"""
rag/routes.py — Endpoints FastAPI para o pipeline RAG forense.

Endpoints:
  POST /rag/ingest      — faz upload de um PDF e indexa-o
  POST /rag/query       — recebe uma query e devolve resposta + fontes
  GET  /rag/documents   — lista documentos já indexados
"""

import logging
import os
import tempfile

from fastapi import APIRouter, File, Form, HTTPException, UploadFile
from pydantic import BaseModel, Field

from .generator import answer_with_rag
from .indexer import ingest_pdf, list_indexed_documents

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/rag", tags=["RAG"])

# ─── Schemas ──────────────────────────────────────────────────────────────────

class QueryRequest(BaseModel):
    query: str = Field(..., min_length=1, description="Pergunta a responder com RAG.")
    top_k: int = Field(default=5, ge=1, le=20, description="Número de chunks a recuperar.")


# ─── Endpoints ────────────────────────────────────────────────────────────────

@router.post(
    "/ingest",
    summary="Indexar PDF",
    description="Faz upload de um PDF e indexa-o no ChromaDB. "
                "Envia o campo `doc_id` como Form field; "
                "se omitido, usa o nome do ficheiro (sem extensão).",
)
async def ingest_endpoint(
    file: UploadFile = File(..., description="Ficheiro PDF a indexar."),
    doc_id: str = Form(default=None, description="Identificador único do documento."),
):
    if not file.filename or not file.filename.lower().endswith(".pdf"):
        raise HTTPException(status_code=400, detail="Only PDF files (.pdf) are accepted.")

    # doc_id opcional — usa o nome do ficheiro como fallback
    effective_doc_id = doc_id.strip() if doc_id and doc_id.strip() else os.path.splitext(file.filename)[0]

    # Guarda temporariamente em disco para o loader
    tmp_path: str | None = None
    try:
        with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as tmp:
            tmp.write(await file.read())
            tmp_path = tmp.name

        result = ingest_pdf(tmp_path, effective_doc_id)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except ValueError as exc:
        # PDF corrompido ou sem texto extraível
        raise HTTPException(status_code=422, detail=str(exc))
    except Exception as exc:
        logger.exception("Unexpected error while ingesting doc_id=%r", effective_doc_id)
        raise HTTPException(status_code=500, detail=f"Ingest failed: {exc}")
    finally:
        if tmp_path and os.path.exists(tmp_path):
            os.unlink(tmp_path)

    return result


@router.post(
    "/query",
    summary="Consultar com RAG",
    description="Recupera chunks relevantes e gera uma resposta usando Claude.",
)
async def query_endpoint(req: QueryRequest):
    try:
        result = answer_with_rag(req.query, top_k=req.top_k)
    except Exception as exc:
        logger.exception("RAG query error for query=%r", req.query)
        raise HTTPException(status_code=500, detail=f"Query failed: {exc}")
    return result


@router.get(
    "/documents",
    summary="Listar documentos indexados",
    description="Devolve a lista de documentos presentes na colecção ChromaDB.",
)
async def documents_endpoint():
    try:
        docs = list_indexed_documents()
    except Exception as exc:
        logger.exception("Error listing indexed documents")
        raise HTTPException(status_code=500, detail=str(exc))
    return {"documents": docs, "total": len(docs)}
