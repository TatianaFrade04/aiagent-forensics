"""
rag/generator.py — Geração de respostas com RAG via modelo Ollama local.

Pipeline (LCEL — LangChain v1.x):
  query → Retriever → top-k chunks → ChatOllama (modelo local)
        → resposta com citação de fontes
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

def answer_with_rag(query: str, top_k: int = 5) -> dict:
    """
    Responde a uma query usando o pipeline RAG completo (LCEL).

    Args:
        query:  Pergunta do utilizador.
        top_k:  Número de chunks a recuperar.

    Returns:
        Dict com:
          - "answer"  : str — resposta gerada pelo Claude
          - "sources" : list[dict] — [{doc_id, filename, page}, …]
    """
    logger.info("RAG query (top_k=%d): %r", top_k, query)

    retriever = get_retriever(top_k=top_k)
    llm = ChatOllama(model=OLLAMA_MODEL, base_url=OLLAMA_URL, temperature=0)

    # Recuperar os docs separadamente para extrair fontes
    docs = retriever.invoke(query)

    # Montar chain LCEL: contexto já formatado + pergunta → LLM → string
    rag_chain = (
        {
            "context": lambda _: _format_docs(docs),
            "question": RunnablePassthrough(),
        }
        | _PROMPT
        | llm
        | StrOutputParser()
    )

    answer = rag_chain.invoke(query)

    # Extrair fontes únicas
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
