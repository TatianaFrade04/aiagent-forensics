"""
rag/config.py — Configuração centralizada do pipeline RAG.
"""

import os

# ─── Caminhos ─────────────────────────────────────────────────────────────────

# Directório raiz do projecto (um nível acima de rag/)
_BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

# ChromaDB persiste aqui em disco (criado automaticamente)
CHROMA_PERSIST_DIR: str = os.path.join(_BASE_DIR, "chroma_store")

# ─── ChromaDB ─────────────────────────────────────────────────────────────────

COLLECTION_NAME: str = "forensic_docs"

# ─── Embeddings ───────────────────────────────────────────────────────────────

EMBEDDING_MODEL: str = "all-MiniLM-L6-v2"

# ─── Chunking ─────────────────────────────────────────────────────────────────

CHUNK_SIZE: int = 500
CHUNK_OVERLAP: int = 50

# ─── LLM (Ollama local) ──────────────────────────────────────────────────────

OLLAMA_MODEL: str = os.getenv("OLLAMA_MODEL", "qwen2.5:7b")
OLLAMA_URL: str   = os.getenv("OLLAMA_URL",   "http://localhost:11434")