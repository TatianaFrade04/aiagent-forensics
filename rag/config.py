"""
rag/config.py — Centralised RAG pipeline configuration.
"""

import os

# ─── Paths ────────────────────────────────────────────────────────────────────

_BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

CHROMA_PERSIST_DIR: str = os.path.join(_BASE_DIR, "chroma_store")

# ─── ChromaDB ─────────────────────────────────────────────────────────────────

COLLECTION_NAME: str = "forensic_docs"

# ─── Embeddings ───────────────────────────────────────────────────────────────

EMBEDDING_MODEL: str = "all-MiniLM-L6-v2"

# ─── Chunking ─────────────────────────────────────────────────────────────────

CHUNK_SIZE: int = 500
CHUNK_OVERLAP: int = 50

# ─── LLM (Ollama local) ──────────────────────────────────────────────────────

OLLAMA_MODEL: str = os.getenv("OLLAMA_MODEL", "gemma4:e4b")
OLLAMA_URL: str   = os.getenv("OLLAMA_URL",   "http://localhost:11434")