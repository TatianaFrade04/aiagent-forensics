"""
rag/retriever.py — Semantic retrieval of relevant chunks from ChromaDB.
"""

import logging
import os

import chromadb
from langchain_chroma import Chroma
from langchain_core.documents import Document
from langchain_core.vectorstores import VectorStoreRetriever

from .config import (
    CHROMA_PERSIST_DIR,
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

# ─── API pública ──────────────────────────────────────────────────────────────

def retrieve(query: str, top_k: int = 5, filename: str | None = None) -> list[Document]:
    """
    Retrieve the top_k most relevant chunks for a query.

    Args:
        query:    Search query or terms.
        top_k:    Maximum number of chunks to return.
        filename: If specified, filter results to this file only.

    Returns:
        List of Document (page_content + metadata with doc_id, page, filename).
    """
    if filename:
        logger.info("Retrieving top-%d chunks for query: %r (filtered by file: %s)", top_k, query, filename)
    else:
        logger.info("Retrieving top-%d chunks for query: %r (all documents)", top_k, query)

    try:
        vs = _vectorstore()

        if filename:
            docs_with_scores = vs.similarity_search_with_score(
                query,
                k=top_k,
                filter={"filename": {"$eq": filename}}
            )
            docs = [doc for doc, score in docs_with_scores]
        else:
            retriever = vs.as_retriever(search_kwargs={"k": top_k})
            docs = retriever.invoke(query)

        logger.info("Retrieved %d chunks.", len(docs))
        return docs
    except Exception as e:
        logger.error("ChromaDB retrieval failed: %s", e)
        return []


def get_retriever(top_k: int = 5, filename: str | None = None) -> VectorStoreRetriever:
    """
    Return a configured VectorStoreRetriever for use in LangChain chains.

    Args:
        top_k:    Number of documents to retrieve.
        filename: If specified, filter results to this file only.
    """
    search_kwargs = {"k": top_k}
    if filename:
        search_kwargs["filter"] = {"filename": {"$eq": filename}}
    
    return _vectorstore().as_retriever(search_kwargs=search_kwargs)


def _chroma_collection() -> chromadb.Collection:
    os.makedirs(CHROMA_PERSIST_DIR, exist_ok=True)
    client = chromadb.PersistentClient(path=CHROMA_PERSIST_DIR)
    return client.get_or_create_collection(COLLECTION_NAME)


def list_indexed_documents() -> list[str]:
    """
    List all unique document filenames that have been indexed.

    Returns:
        List of unique document filenames in the vector store.
    """
    logger.info("Retrieving list of indexed documents")
    col = _chroma_collection()
    result = col.get(include=["metadatas"])
    filenames = set()
    if result and result["metadatas"]:
        for metadata in result["metadatas"]:
            if metadata and "filename" in metadata:
                filenames.add(metadata["filename"])
    unique_files = sorted(list(filenames))
    logger.info("Found %d unique indexed documents", len(unique_files))
    return unique_files