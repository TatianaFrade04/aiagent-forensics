"""
rag/routes.py — FastAPI routes for RAG functionality.
"""

import logging
from typing import Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

from .generator import answer_with_rag
from .retriever import list_indexed_documents

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/rag", tags=["RAG"])


# ─── Request/Response Models ─────────────────────────────────────────────────

class QueryRequest(BaseModel):
    query: str
    top_k: int = 5
    filename: Optional[str] = None


class QueryResponse(BaseModel):
    answer: str
    sources: list[dict]


class DocumentsResponse(BaseModel):
    documents: list[str]


# ─── Routes ──────────────────────────────────────────────────────────────────

@router.post("/query", response_model=QueryResponse)
async def query_documents(request: QueryRequest) -> QueryResponse:
    """
    Query indexed documents using RAG.
    
    Args:
        request: Query request with question, top_k, and optional filename filter
        
    Returns:
        Answer and sources from RAG pipeline
    """
    try:
        result = answer_with_rag(
            query=request.query,
            top_k=request.top_k,
            filename=request.filename
        )
        return QueryResponse(answer=result["answer"], sources=result["sources"])
    except Exception as e:
        logger.error(f"Error during RAG query: {e}")
        raise HTTPException(status_code=500, detail=f"RAG query failed: {str(e)}")


@router.get("/documents", response_model=DocumentsResponse)
async def get_indexed_documents() -> DocumentsResponse:
    """
    List all indexed documents in the vector store.
    
    Returns:
        List of document filenames that have been indexed
    """
    try:
        documents = list_indexed_documents()
        return DocumentsResponse(documents=documents)
    except Exception as e:
        logger.error(f"Error listing documents: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to list documents: {str(e)}")


@router.get("/health")
async def health_check():
    """
    Simple health check endpoint.
    """
    return {"status": "healthy", "service": "RAG"}