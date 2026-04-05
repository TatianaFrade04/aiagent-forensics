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

def retrieve(query: str, top_k: int = 5, filename: str | None = None) -> list[Document]:
    """
    Recupera os top_k chunks mais relevantes para a query.

    Args:
        query:    Pergunta ou termos de pesquisa.
        top_k:    Número máximo de chunks a devolver.
        filename: [NOVO] Nome do ficheiro para filtrar os resultados.
                 Se None, busca em todos os documentos indexados.

    Returns:
        Lista de Document (page_content + metadata com doc_id, page, filename).
    """
    if filename:
        logger.info("Retrieving top-%d chunks for query: %r (filtered by file: %s)", top_k, query, filename)
    else:
        logger.info("Retrieving top-%d chunks for query: %r (all documents)", top_k, query)
    
    vs = _vectorstore()
    
    # Se um filename específico foi pedido, aplicar filtro de metadata
    if filename:
        # Usar similarity_search_with_score com filtro de metadata
        docs_with_scores = vs.similarity_search_with_score(
            query,
            k=top_k,
            filter={"filename": {"$eq": filename}}
        )
        docs = [doc for doc, score in docs_with_scores]
    else:
        # Comportamento original - buscar em todos os documentos
        retriever = vs.as_retriever(search_kwargs={"k": top_k})
        docs = retriever.invoke(query)
    
    logger.info("Retrieved %d chunks.", len(docs))
    return docs


def get_retriever(top_k: int = 5, filename: str | None = None) -> VectorStoreRetriever:
    """
    Devolve um VectorStoreRetriever configurado — para integração em chains
    LangChain (create_retrieval_chain, etc.).
    
    Args:
        top_k:    Número de documentos a recuperar.
        filename: [NOVO] Se especificado, filtra apenas por este ficheiro.
    """
    search_kwargs = {"k": top_k}
    
    # Adicionar filtro se filename foi especificado
    if filename:
        search_kwargs["filter"] = {"filename": {"$eq": filename}}
    
    return _vectorstore().as_retriever(search_kwargs=search_kwargs)
