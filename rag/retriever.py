"""
rag/retriever.py — Recuperação de chunks relevantes do ChromaDB.
"""

import logging
import os

from langchain_huggingface import HuggingFaceEmbeddings
from langchain_chroma import Chroma
from langchain_core.documents import Document
from langchain_core.vectorstores import VectorStoreRetriever

from .config import (
    CHROMA_PERSIST_DIR,
    COLLECTION_NAME,
    EMBEDDING_MODEL,
)

logger = logging.getLogger(__name__)

# ─── Singleton de embeddings ──────────────────────────────────────────────────────────────────

_embeddings_instance: HuggingFaceEmbeddings | None = None


def _embeddings() -> HuggingFaceEmbeddings:
    global _embeddings_instance
    if _embeddings_instance is None:
        _embeddings_instance = HuggingFaceEmbeddings(model_name=EMBEDDING_MODEL)
    return _embeddings_instance

# ─── Helper privado ──────────────────────────────────────────────────────────────────


def _vectorstore() -> Chroma:
    os.makedirs(CHROMA_PERSIST_DIR, exist_ok=True)
    return Chroma(
        collection_name=COLLECTION_NAME,
        embedding_function=_embeddings(),
        persist_directory=CHROMA_PERSIST_DIR,
    )

# ─── API pública ──────────────────────────────────────────────────────────────

def retrieve(query: str, top_k: int = 5) -> list[Document]:
    """
    Recupera os top_k chunks mais relevantes para a query.

    Args:
        query:  Pergunta ou termos de pesquisa.
        top_k:  Número máximo de chunks a devolver.

    Returns:
        Lista de Document (page_content + metadata com doc_id, page, filename).
    """
    logger.info("Retrieving top-%d chunks for query: %r", top_k, query)
    vs = _vectorstore()
    retriever = vs.as_retriever(search_kwargs={"k": top_k})
    docs = retriever.invoke(query)
    logger.info("Retrieved %d chunks.", len(docs))
    return docs


def get_retriever(top_k: int = 5) -> VectorStoreRetriever:
    """
    Devolve um VectorStoreRetriever configurado — para integração em chains
    LangChain (create_retrieval_chain, etc.).
    """
    return _vectorstore().as_retriever(search_kwargs={"k": top_k})
