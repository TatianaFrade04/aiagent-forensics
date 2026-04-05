"""
rag/indexer.py — Ingestão e indexação de PDFs no ChromaDB.

Fluxo:
  PDF → PDFPlumberLoader → RecursiveCharacterTextSplitter
      → HuggingFaceEmbeddings → Chroma (persisted)
"""

import hashlib
import logging
import os

import chromadb
from langchain_community.document_loaders import PDFPlumberLoader
from langchain_huggingface import HuggingFaceEmbeddings
from langchain_chroma import Chroma
from langchain_text_splitters import RecursiveCharacterTextSplitter

from .config import (
    CHROMA_PERSIST_DIR,
    CHUNK_OVERLAP,
    CHUNK_SIZE,
    COLLECTION_NAME,
    EMBEDDING_MODEL,
)

logger = logging.getLogger(__name__)

# ─── Singleton de embeddings (evita recarregar o modelo em cada chamada) ────────────

_embeddings_instance: HuggingFaceEmbeddings | None = None


def _embeddings() -> HuggingFaceEmbeddings:
    global _embeddings_instance
    if _embeddings_instance is None:
        _embeddings_instance = HuggingFaceEmbeddings(model_name=EMBEDDING_MODEL)
    return _embeddings_instance
# ─── Helpers privados ──────────────────────────────────────────────────────────────────


def _vectorstore() -> Chroma:
    os.makedirs(CHROMA_PERSIST_DIR, exist_ok=True)
    return Chroma(
        collection_name=COLLECTION_NAME,
        embedding_function=_embeddings(),
        persist_directory=CHROMA_PERSIST_DIR,
    )


def _chroma_collection() -> chromadb.Collection:
    """Acesso directo à colecção ChromaDB para operações administrativas."""
    os.makedirs(CHROMA_PERSIST_DIR, exist_ok=True)
    client = chromadb.PersistentClient(path=CHROMA_PERSIST_DIR)
    return client.get_or_create_collection(COLLECTION_NAME)


def _is_already_indexed(doc_id: str) -> bool:
    """Verifica se algum chunk com este doc_id já existe na colecção."""
    try:
        col = _chroma_collection()
        result = col.get(where={"doc_id": {"$eq": doc_id}}, limit=1, include=[])
        return len(result["ids"]) > 0
    except Exception:
        return False


def _purge_stale_entries(filename: str, current_doc_id: str) -> None:
    """Apaga entradas antigas do mesmo ficheiro com doc_ids diferentes."""
    try:
        col = _chroma_collection()
        result = col.get(where={"filename": {"$eq": filename}}, include=["metadatas"])
        stale_ids = [
            eid for eid, meta in zip(result["ids"], result["metadatas"] or [])
            if meta and meta.get("doc_id") != current_doc_id
        ]
        if stale_ids:
            col.delete(ids=stale_ids)
            logger.info(
                "Purged %d stale chunks for filename=%r (old doc_ids removed).",
                len(stale_ids), filename,
            )
    except Exception as exc:
        logger.warning("Could not purge stale entries for %r: %s", filename, exc)

# ─── API pública ──────────────────────────────────────────────────────────────

def _make_doc_id(filename: str) -> str:
    """Gera um doc_id determinístico a partir do nome do ficheiro (MD5[:12])."""
    return hashlib.md5(os.path.basename(filename).encode()).hexdigest()[:12]


def ingest_pdf(filepath: str, doc_id: str | None = None) -> dict:
    """
    Carrega um PDF, divide em chunks e indexa no ChromaDB.

    Args:
        filepath: Caminho absoluto ou relativo para o ficheiro PDF.
        doc_id:   Ignorado — o doc_id é sempre gerado internamente a partir
                  do nome do ficheiro via MD5 para garantir consistência
                  entre sessões.

    Returns:
        Dict com status, doc_id e número de chunks indexados.

    Raises:
        FileNotFoundError: Se o ficheiro não existir.
        ValueError: Se o PDF não tiver texto extraível (ex: scan de imagem).
    """
    if not os.path.isfile(filepath):
        raise FileNotFoundError(f"PDF not found: {filepath!r}")

    # doc_id sempre derivado do nome do ficheiro — ignora argumento externo
    doc_id = _make_doc_id(filepath)
    logger.info("Generated doc_id=%r from filename %r", doc_id, os.path.basename(filepath))

    # ── Limpeza de entradas obsoletas (mesmo ficheiro, doc_id antigo) ─────────
    _purge_stale_entries(os.path.basename(filepath), doc_id)

    # ── Deduplicação ──────────────────────────────────────────────────────────
    if _is_already_indexed(doc_id):
        logger.info("Document %r already indexed — skipping.", doc_id)
        return {"doc_id": doc_id, "status": "already_indexed", "chunks": 0}

    # ── Extracção de texto ────────────────────────────────────────────────────
    logger.info("Loading PDF: %r", filepath)
    loader = PDFPlumberLoader(filepath)
    try:
        docs = loader.load()
    except Exception as exc:
        raise ValueError(f"Failed to load PDF {filepath!r}: {exc}") from exc

    # Rejeita PDFs sem texto (scans de imagem)
    if not docs or all(not d.page_content.strip() for d in docs):
        raise ValueError(
            f"No text extracted from {filepath!r}. "
            "The PDF may be an image-only scan — run OCR first "
            "(e.g. ocrmypdf input.pdf output.pdf)."
        )

    # ── Chunking ──────────────────────────────────────────────────────────────
    splitter = RecursiveCharacterTextSplitter(
        chunk_size=CHUNK_SIZE,
        chunk_overlap=CHUNK_OVERLAP,
    )
    chunks = splitter.split_documents(docs)

    # Enriquecer metadata de cada chunk
    filename = os.path.basename(filepath)
    for chunk in chunks:
        chunk.metadata.update(
            {
                "doc_id": doc_id,
                "filename": filename,
                # PDFPlumberLoader já coloca "page" em chunk.metadata
            }
        )

    # ── Indexação ─────────────────────────────────────────────────────────────
    logger.info("Indexing %d chunks for document %r …", len(chunks), doc_id)
    vs = _vectorstore()
    vs.add_documents(chunks)
    logger.info("Document %r indexed successfully (%d chunks).", doc_id, len(chunks))

    return {"doc_id": doc_id, "status": "indexed", "chunks": len(chunks)}


def list_indexed_documents() -> list[dict]:
    """
    Retorna a lista de documentos únicos presentes na colecção.

    Returns:
        Lista de dicts com {doc_id, filename}.
    """
    col = _chroma_collection()
    result = col.get(include=["metadatas"])

    seen: dict[str, dict] = {}
    for meta in result.get("metadatas") or []:
        if not meta:
            continue
        doc_id = meta.get("doc_id")
        if doc_id and doc_id not in seen:
            seen[doc_id] = {
                "doc_id": doc_id,
                "filename": meta.get("filename", ""),
            }

    return list(seen.values())


def is_document_indexed(filename: str) -> bool:
    """
    [NOVA FUNÇÃO] Verifica se um documento específico está indexado.
    
    Args:
        filename: Nome do ficheiro a verificar.
        
    Returns:
        True se o documento estiver indexado, False caso contrário.
    """
    try:
        col = _chroma_collection()
        result = col.get(where={"filename": {"$eq": filename}}, limit=1, include=[])
        return len(result["ids"]) > 0
    except Exception:
        return False
