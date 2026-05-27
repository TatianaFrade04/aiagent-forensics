"""
rag/indexer.py — Document ingestion and indexing into ChromaDB.

Supported formats: PDF, DOCX, CSV, TXT, MD

Pipeline:
  Document → Loader (by extension) → RecursiveCharacterTextSplitter
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

# ─── Embeddings singleton ─────────────────────────────────────────────────────

_embeddings_instance = None


def _embeddings():
    from langchain_huggingface import HuggingFaceEmbeddings
    global _embeddings_instance
    if _embeddings_instance is None:
        _embeddings_instance = HuggingFaceEmbeddings(model_name=EMBEDDING_MODEL)
    return _embeddings_instance
# ─── Private helpers ──────────────────────────────────────────────────────────


def _vectorstore() -> Chroma:
    os.makedirs(CHROMA_PERSIST_DIR, exist_ok=True)
    return Chroma(
        collection_name=COLLECTION_NAME,
        embedding_function=_embeddings(),
        persist_directory=CHROMA_PERSIST_DIR,
    )


def _chroma_collection() -> chromadb.Collection:
    """Direct access to the ChromaDB collection for administrative operations."""
    os.makedirs(CHROMA_PERSIST_DIR, exist_ok=True)
    client = chromadb.PersistentClient(path=CHROMA_PERSIST_DIR)
    return client.get_or_create_collection(COLLECTION_NAME)


def _is_already_indexed(doc_id: str) -> bool:
    """Return True if any chunk with this doc_id already exists in the collection."""
    try:
        col = _chroma_collection()
        result = col.get(where={"doc_id": {"$eq": doc_id}}, limit=1, include=[])
        return len(result["ids"]) > 0
    except Exception:
        return False


def _purge_stale_entries(filename: str, current_doc_id: str) -> None:
    """Delete old entries for the same filename that have a different doc_id."""
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

# ─── Loader selection by extension ───────────────────────────────────────────

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


# ─── Public API ───────────────────────────────────────────────────────────────

def _make_doc_id(filename: str) -> str:
    """Generate a deterministic doc_id from the filename (MD5[:12])."""
    return hashlib.md5(os.path.basename(filename).encode()).hexdigest()[:12]


def ingest_document(filepath: str, doc_id: str | None = None, original_filename: str | None = None) -> dict:
    """
    Load a document (PDF, DOCX, CSV or TXT), split into chunks, and index in ChromaDB.

    Args:
        filepath:          Path to the file to read (may be a temporary path).
        doc_id:            Ignored — generated internally from the filename via MD5.
        original_filename: Canonical filename used for doc_id and metadata
                           when filepath points to a temporary file.

    Returns:
        Dict with status, doc_id, and number of chunks indexed.

    Raises:
        FileNotFoundError: If the file does not exist.
        ValueError: If the file type is unsupported or no text could be extracted.
    """
    if not os.path.isfile(filepath):
        raise FileNotFoundError(f"File not found: {filepath!r}")

    canonical = original_filename if original_filename else os.path.basename(filepath)
    doc_id = _make_doc_id(canonical)
    logger.info("Generated doc_id=%r from filename %r", doc_id, canonical)

    _purge_stale_entries(canonical, doc_id)

    if _is_already_indexed(doc_id):
        logger.info("Document %r already indexed — skipping.", doc_id)
        return {"doc_id": doc_id, "status": "already_indexed", "chunks": 0}

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

    splitter = RecursiveCharacterTextSplitter(
        chunk_size=CHUNK_SIZE,
        chunk_overlap=CHUNK_OVERLAP,
    )
    chunks = splitter.split_documents(docs)

    for i, chunk in enumerate(chunks):
        page = chunk.metadata.get("page", chunk.metadata.get("page_number", i))
        chunk.metadata.update({"doc_id": doc_id, "filename": canonical, "page": page})

    logger.info("Indexing %d chunks for document %r …", len(chunks), doc_id)
    vs = _vectorstore()
    vs.add_documents(chunks)
    logger.info("Document %r indexed successfully (%d chunks).", doc_id, len(chunks))

    return {"doc_id": doc_id, "status": "indexed", "chunks": len(chunks)}


ingest_pdf = ingest_document


def list_indexed_documents() -> list[dict]:
    """
    Return the list of unique documents present in the collection.

    Returns:
        List of dicts with {doc_id, filename}.
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
    """Remove all indexed documents. Returns the number of chunks removed."""
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
    Return True if the given filename is indexed in the collection.
    """
    try:
        col = _chroma_collection()
        result = col.get(where={"filename": {"$eq": filename}}, limit=1, include=[])
        return len(result["ids"]) > 0
    except Exception:
        return False