"""
rag/indexer.py — Ingestão e indexação de documentos no ChromaDB.

Formatos suportados: PDF, DOCX, CSV, TXT, MD

Fluxo:
  Documento → Loader (por extensão) → RecursiveCharacterTextSplitter
            → HuggingFaceEmbeddings → Chroma (persisted)
"""

import hashlib
import logging
import os

import chromadb
from langchain_community.document_loaders import (
    CSVLoader,
    Docx2txtLoader,
    PDFPlumberLoader,
    TextLoader,
)
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

_embeddings_instance = None


def _embeddings():
    from langchain_huggingface import HuggingFaceEmbeddings
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

# ─── Selecção de loader por extensão ─────────────────────────────────────────

SUPPORTED_EXTENSIONS = {".pdf", ".docx", ".csv", ".txt", ".md"}


def _get_loader(filepath: str):
    ext = os.path.splitext(filepath)[1].lower()
    if ext == ".pdf":
        return PDFPlumberLoader(filepath)
    if ext == ".docx":
        return Docx2txtLoader(filepath)
    if ext == ".csv":
        return CSVLoader(filepath, encoding="utf-8")
    if ext in {".txt", ".md"}:
        return TextLoader(filepath, encoding="utf-8")
    raise ValueError(
        f"Unsupported file type {ext!r}. Supported: {', '.join(sorted(SUPPORTED_EXTENSIONS))}"
    )


# ─── API pública ──────────────────────────────────────────────────────────────

def _make_doc_id(filename: str) -> str:
    """Gera um doc_id determinístico a partir do nome do ficheiro (MD5[:12])."""
    return hashlib.md5(os.path.basename(filename).encode()).hexdigest()[:12]


def ingest_document(filepath: str, doc_id: str | None = None, original_filename: str | None = None) -> dict:
    """
    Carrega um documento (PDF, DOCX, CSV ou TXT), divide em chunks e indexa no ChromaDB.

    Args:
        filepath:          Caminho para o ficheiro a ler (pode ser temporário).
        doc_id:            Ignorado — gerado internamente via MD5 do nome do ficheiro.
        original_filename: Nome canónico do ficheiro (usado para doc_id e metadata
                           quando filepath aponta para um ficheiro temporário).

    Returns:
        Dict com status, doc_id e número de chunks indexados.

    Raises:
        FileNotFoundError: Se o ficheiro não existir.
        ValueError: Se o tipo não for suportado ou sem texto extraível.
    """
    if not os.path.isfile(filepath):
        raise FileNotFoundError(f"File not found: {filepath!r}")

    canonical = original_filename if original_filename else os.path.basename(filepath)
    doc_id = _make_doc_id(canonical)
    logger.info("Generated doc_id=%r from filename %r", doc_id, canonical)

    # ── Limpeza de entradas obsoletas (mesmo ficheiro, doc_id antigo) ─────────
    _purge_stale_entries(canonical, doc_id)

    # ── Deduplicação ──────────────────────────────────────────────────────────
    if _is_already_indexed(doc_id):
        logger.info("Document %r already indexed — skipping.", doc_id)
        return {"doc_id": doc_id, "status": "already_indexed", "chunks": 0}

    # ── Selecção do loader e extracção de texto ───────────────────────────────
    logger.info("Loading document: %r", filepath)
    loader = _get_loader(filepath)
    try:
        docs = loader.load()
    except Exception as exc:
        raise ValueError(f"Failed to load {filepath!r}: {exc}") from exc

    if not docs or all(not d.page_content.strip() for d in docs):
        ext = os.path.splitext(canonical)[1].lower()
        hint = " The PDF may be an image-only scan — run OCR first." if ext == ".pdf" else ""
        raise ValueError(f"No text extracted from {filepath!r}.{hint}")

    # ── Chunking ──────────────────────────────────────────────────────────────
    splitter = RecursiveCharacterTextSplitter(
        chunk_size=CHUNK_SIZE,
        chunk_overlap=CHUNK_OVERLAP,
    )
    chunks = splitter.split_documents(docs)

    for i, chunk in enumerate(chunks):
        page = chunk.metadata.get("page", chunk.metadata.get("page_number", i))
        chunk.metadata.update({"doc_id": doc_id, "filename": canonical, "page": page})

    # ── Indexação ─────────────────────────────────────────────────────────────
    logger.info("Indexing %d chunks for document %r …", len(chunks), doc_id)
    vs = _vectorstore()
    vs.add_documents(chunks)
    logger.info("Document %r indexed successfully (%d chunks).", doc_id, len(chunks))

    return {"doc_id": doc_id, "status": "indexed", "chunks": len(chunks)}


# alias de retrocompatibilidade
ingest_pdf = ingest_document


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


def clear_collection() -> int:
    """Remove todos os documentos indexados. Devolve o numero de chunks removidos."""
    try:
        col = _chroma_collection()
        result = col.get(include=[])
        count = len(result["ids"]) if result["ids"] else 0
        if count:
            col.delete(ids=result["ids"])
        logger.info("Cleared %d chunks from collection.", count)
        return count
    except Exception as e:
        logger.error("Failed to clear collection: %s", e)
        return 0


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