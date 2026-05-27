"""
rag/generator.py — RAG answer generation via local Ollama model.

Pipeline (LCEL — LangChain v1.x):
  query → Retriever → top-k chunks → ChatOllama (local model)
        → answer with source citations
"""

import logging

from dotenv import load_dotenv
from langchain_ollama import ChatOllama
from langchain_core.output_parsers import StrOutputParser
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.runnables import RunnablePassthrough

from .config import OLLAMA_MODEL, OLLAMA_URL
from .retriever import get_retriever

load_dotenv()

logger = logging.getLogger(__name__)

# ─── Prompt ───────────────────────────────────────────────────────────────────

_SYSTEM_PROMPT = """\
You are a forensic analyst assistant. Your role is to answer questions \
EXCLUSIVELY based on the document excerpts provided in the context below.

STRICT RULES:
1. Only use information explicitly present in the provided excerpts.
2. For every piece of information you use, cite the source in the format: \
   [doc_id: <doc_id>, page: <page>].
3. If the answer cannot be found in the provided documents, respond with:
   "This information is not available in the indexed documents."
4. Never invent, infer, or extrapolate information not present in the excerpts.
5. Be precise and concise.

Context from indexed documents:
{context}"""

_PROMPT = ChatPromptTemplate.from_messages(
    [
        ("system", _SYSTEM_PROMPT),
        ("human", "{question}"),
    ]
)

# ─── Helpers ──────────────────────────────────────────────────────────────────

def _format_docs(docs) -> str:
    parts = []
    for doc in docs:
        meta = doc.metadata
        header = f"[doc_id: {meta.get('doc_id', '')}, page: {meta.get('page', '')}]"
        parts.append(f"{header}\n{doc.page_content}")
    return "\n\n".join(parts)

# ─── API pública ──────────────────────────────────────────────────────────────

def answer_with_rag(query: str, top_k: int = 5, filename: str | None = None) -> dict:
    """
    Answer a query using the full RAG pipeline (LCEL).

    Args:
        query:    User question.
        top_k:    Number of chunks to retrieve.
        filename: If specified, filter results to this document only.

    Returns:
        Dict with:
          - "answer"  : str — model-generated answer
          - "sources" : list[dict] — [{doc_id, filename, page}, …]
    """
    if filename:
        logger.info("RAG query (top_k=%d, file=%s): %r", top_k, filename, query)
    else:
        logger.info("RAG query (top_k=%d): %r", top_k, query)

    retriever = get_retriever(top_k=top_k, filename=filename)
    llm = ChatOllama(model=OLLAMA_MODEL, base_url=OLLAMA_URL, temperature=0)

    docs = retriever.invoke(query)

    # Return early if no documents found
    if not docs and filename:
        return {
            "answer": f"No information found for '{filename}'. The document may not be indexed or does not contain relevant content for this query.",
            "sources": []
        }
    elif not docs:
        return {
            "answer": "This information is not available in the indexed documents.",
            "sources": []
        }

    rag_chain = (
        {
            "context": lambda _: _format_docs(docs),
            "question": RunnablePassthrough(),
        }
        | _PROMPT
        | llm
        | StrOutputParser()
    )

    try:
        answer = rag_chain.invoke(query)
    except Exception as e:
        return {"answer": f"Error: RAG LLM invocation failed: {e}", "sources": []}

    # Deduplicate sources — cite each page only once
    sources: list[dict] = []
    seen_sources: set[tuple] = set()
    for doc in docs:
        meta = doc.metadata
        key = (meta.get("doc_id", ""), str(meta.get("page", "")))
        if key not in seen_sources:
            seen_sources.add(key)
            sources.append(
                {
                    "doc_id": meta.get("doc_id", ""),
                    "filename": meta.get("filename", ""),
                    "page": meta.get("page", ""),
                }
            )

    logger.info("Answer generated. Sources used: %d unique chunks.", len(sources))
    return {"answer": answer, "sources": sources}