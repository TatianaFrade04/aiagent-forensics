"""
app.py — Ponto de entrada FastAPI para o sistema RAG do AIAgent@forensics.

Arrancar o servidor:
  uvicorn app:app --reload --port 8000

Documentação interactiva:
  http://localhost:8000/docs
"""

import logging

from fastapi import FastAPI

from rag.routes import router as rag_router

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)

app = FastAPI(
    title="AIAgent@forensics — RAG API",
    description=(
        "Pipeline RAG para consulta de relatórios forenses em PDF. "
        "Usa ChromaDB + sentence-transformers (all-MiniLM-L6-v2) + Claude (Anthropic)."
    ),
    version="1.0.0",
)

app.include_router(rag_router)


@app.get("/health", tags=["Health"])
def health():
    """Verifica se o servidor está operacional."""
    return {"status": "ok"}
