"""
main.py — AIAgent@forensics
Agente LLM com paradigma ReAct para investigação forense digital.
Politécnico de Leiria — ESTG | Licenciatura em Engenharia Informática
"""

import argparse
import atexit
import os
import re
import sys

try:
    import readline  # activa setas, histórico e edição no input() — Linux/macOS
except ImportError:
    pass  # Windows sem pyreadline — silencioso

# Add project root to path to enable imports of rag module
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from dotenv import load_dotenv

from langchain_ollama import ChatOllama
from langchain_core.tools import tool
from langchain_core.messages import AIMessage, HumanMessage, SystemMessage, ToolMessage

from langchain.agents import create_agent

from .tools import run_in_sandbox, stop_container, start_container
from .skills import load_skills, select_skills, format_skills_context

# RAG imports
from rag.indexer import ingest_pdf, is_document_indexed
from rag.generator import answer_with_rag

load_dotenv()

# ─── Ferramenta exposta ao agente ─────────────────────────────────────────────

@tool
def run_forensics_command(command: str) -> str:
    """
    Run any bash command inside the forensic Linux container and get back stdout and stderr.

    FILESYSTEM LAYOUT:
      /forensics/  - mounted forensic partitions (READ-ONLY evidence)
      /exports/    - writable directory for saving output files

    NOTES:
      - Paths with spaces MUST use single quotes
      - /forensics is READ-ONLY — never redirect or write there
    """
    return run_in_sandbox(command)


@tool
def ingest_pdf_document(filename: str) -> str:
    """
    Index a PDF document in the RAG vector store for later querying.
    
    Args:
        filename: Path to the PDF file (relative to current directory or absolute path).
        
    Returns:
        Status message indicating success, failure, or if already indexed.
    """
    import os
    import logging
    
    logger = logging.getLogger(__name__)
    
    try:
        # Check if file exists
        if not os.path.isfile(filename):
            return f"Error: PDF file '{filename}' not found."
        
        # Check if already indexed (by filename only)
        basename = os.path.basename(filename)
        if is_document_indexed(basename):
            return f"Document '{basename}' is already indexed. Use query_rag_documents to search it."
        
        # Ingest the document
        result = ingest_pdf(filename)
        
        if result["status"] == "indexed":
            return f"Successfully indexed '{basename}' with doc_id={result['doc_id']} ({result['chunks']} chunks)."
        elif result["status"] == "already_indexed":
            return f"Document '{basename}' was already indexed with doc_id={result['doc_id']}."
        else:
            return f"Unknown status: {result}"
            
    except FileNotFoundError as e:
        return f"Error: {e}"
    except ValueError as e:
        return f"Error: {e}"
    except Exception as e:
        logger.error("Error in ingest_pdf_document: %s", e)
        return f"Error indexing document: {e}"


@tool
def query_rag_documents(query: str, top_k: int = 5, filename: str | None = None) -> str:
    """
    Query the indexed PDF documents using the RAG pipeline.
    
    Args:
        query: Natural language question about the documents.
        top_k: Number of relevant chunks to retrieve (default: 5).
        filename: Optional filename to filter results to a specific document.
                 Agent should auto-detect filename from user messages containing
                 "Com base no ficheiro X" or similar patterns.
        
    Returns:
        Answer based on indexed document content with source citations.
    """
    import logging
    import re
    
    logger = logging.getLogger(__name__)
    
    # Auto-detect filename from query if not provided
    if not filename:
        # Look for patterns like "Com base no ficheiro X" or "ficheiro X"
        filename_patterns = [
            r'(?:com base no|ficheiro|arquivo|documento)\s+([a-zA-Z0-9_\-.]+\.pdf)',
            r'([a-zA-Z0-9_\-.]+\.pdf)',
        ]
        
        for pattern in filename_patterns:
            match = re.search(pattern, query, re.IGNORECASE)
            if match:
                detected_filename = match.group(1)
                logger.info("Auto-detected filename: %s", detected_filename)
                filename = detected_filename
                break
    
    try:
        result = answer_with_rag(query, top_k=top_k, filename=filename)
        
        answer = result["answer"]
        sources = result["sources"]
        
        # Format response with sources
        response_parts = [answer]
        
        if sources:
            response_parts.append("\n\nSources:")
            for i, source in enumerate(sources, 1):
                doc_id = source.get("doc_id", "")
                filename_src = source.get("filename", "")
                page = source.get("page", "")
                response_parts.append(f"{i}. {filename_src} [doc_id: {doc_id}, page: {page}]")
        
        return "\n".join(response_parts)
        
    except Exception as e:
        logger.error("Error in query_rag_documents: %s", e)
        return f"Error querying documents: {e}"


TOOLS = [run_forensics_command, ingest_pdf_document, query_rag_documents]

# ─── System prompt ────────────────────────────────────────────────────────────

_SYSTEM_PROMPT_TEMPLATE = (
    "You are a digital forensics expert agent operating in READ-ONLY forensic mode.\n"
    "Always respond in English, regardless of the language of the user's message.\n"
    "\n"
    "FILESYSTEM LAYOUT:\n"
    "  {evidence}/ — Windows NTFS partition (READ-ONLY evidence)\n"
    "  /exports/           — the ONLY writable directory\n"
    "  NOTE: Windows directory names (Windows, System32, etc.) are case-sensitive\n"
    "  when mounted on Linux. ALWAYS use find with -iname to discover exact paths\n"
    "  before passing them to forensic tools. Never assume casing.\n"
    "\n"
    "REGISTRY HIVES — Windows registry hive files have NO file extension.\n"
    "  The hive files are named: SOFTWARE, SYSTEM, SAM, SECURITY, NTUSER.DAT\n"
    "  Main hives location: {evidence}/Windows/System32/config/\n"
    "  Per-user hive:        {evidence}/USERS/<username>/NTUSER.DAT\n"
    "  NEVER search for *.reg or *.hive — those are not hive files.\n"
    "  ALWAYS resolve hive paths with find in the SAME command string, using this pattern:\n"
    "    HIVE=$(find '{evidence}' -iname 'SOFTWARE' -not -path '*/Users/*'\n"
    "      -not -path '*/diagnostics/*' -not -path '*/RegBack/*' 2>/dev/null | head -1)\n"
    "    ; reglookup -p '/...' \"$HIVE\"\n"
    "  The variable HIVE is defined and used in the SAME command — this is correct.\n"
    "  NEVER use $HIVE or $SOFTWARE_HIVE or $SYSTEM_HIVE across separate commands —\n"
    "  variables do NOT persist between tool calls.\n"
    "  NEVER use inline $(find ...) without assigning to a quoted variable first.\n"
    "  The -not -path '*/diagnostics/*' filter is CRITICAL — omitting it may return\n"
    "  a diagnostics file instead of the real hive, causing 'undefined value' errors.\n"
    "  To find the Windows version: reglookup -p '/Microsoft/Windows NT/CurrentVersion'\n"
    "  on the SOFTWARE hive.\n"
    "\n"
    "TOOL: run_forensics_command(command) — run any bash command inside the forensic container\n"
    "\n"
    "RULES:\n"
    "1. ALWAYS use the run_forensics_command tool to execute commands — never describe them.\n"
    "   WRONG: writing ```bash command``` or code blocks in your reply.\n"
    "   WRONG: saying 'I will run ...' or 'Let me execute ...' without calling the tool.\n"
    "   RIGHT: call run_forensics_command with the bash command as the argument.\n"
    "   Do NOT announce what you are about to do. Do NOT ask for clarification. Just call the tool.\n"
    "2. NEVER invent or hallucinate results — only report what the tool returns.\n"
    "3. CRITICAL — EVERY path under /forensics/ MUST be wrapped in single quotes. No exceptions.\n"
    "   WRONG: stat {evidence}/USERS/<username>/file.txt\n"
    "   WRONG: stat {evidence}/USERS/<username>\\ file.txt\n"
    "   RIGHT: stat '{evidence}/USERS/<username>/file.txt'\n"
    "   RIGHT: find '{evidence}' -name '*.pdf'\n"
    "   RIGHT: exiftool '{evidence}/USERS/<username>/Documents/photo.jpg'\n"
    "4. /forensics is READ-ONLY. NEVER redirect or write there.\n"
    "5. NEVER use: rm, mv, dd, shred, find -delete, sed -i.\n"
    "6. To save output to a file: command > /exports/file.txt\n"
    "   Then verify with: ls -lh /exports/file.txt\n"
    "7. If a tool call returns an error (e.g. wrong path, file not found, command not found),\n"
    "   NEVER conclude failure immediately. Analyse the error, correct the command\n"
    "   (try different paths or case variations) and try again.\n"
    "   Only report failure after at least two distinct attempts.\n"
    "8. Every new question requires a new tool call — no exceptions.\n"
    "   NEVER answer from memory or from results seen earlier in this conversation.\n"
    "   Even if the exact same question was just asked, call run_forensics_command again\n"
    "   to get a fresh result. Reusing cached output is treated the same as hallucination.\n"
    "9. If command output is truncated, use grep, head, or tail to extract the needed\n"
    "   information before answering. NEVER assume or invent content that was cut off.\n"
    "10. When the user provides an absolute path in a command, run it EXACTLY as given.\n"
    "   NEVER modify, rewrite, or prefix it with {evidence}.\n"
    "   WRONG (user said 'cat /etc/hosts'): cat '{evidence}/etc/hosts'\n"
    "   RIGHT: cat /etc/hosts\n"
    "11. To list Windows users on the evidence image, ALWAYS use:\n"
    "   find '{evidence}/USERS' -mindepth 1 -maxdepth 1 -type d\n"
    "   NEVER use registry hives (SAM, regripper, reglookup) for this operation.\n"
)


def build_system_prompt(evidence: str) -> str:
    return _SYSTEM_PROMPT_TEMPLATE.format(evidence=evidence)


# ─── Auto-detecção da partição de evidência ──────────────────────────────────

def auto_detect_evidence() -> str:
    """Detecta automaticamente a partição principal sob /forensics/ (Windows ou Linux).
    Termina o programa se nenhuma partição reconhecível for encontrada."""
    cmd = (
        "find /forensics -mindepth 1 -maxdepth 1 -type d 2>/dev/null | sort | "
        "while read p; do "
        "( find \"$p\" -maxdepth 1 -type d \\( -iname 'USERS' -o -iname 'Windows' -o -iname 'home' \\) "
        "2>/dev/null | grep -q . || [ -f \"$p/etc/passwd\" ] ) && echo \"$p\" && break; "
        "done | head -1"
    )
    result = run_in_sandbox(cmd)
    path = result.strip().splitlines()[0] if result.strip() else ""
    if not path or not path.startswith("/"):
        print("[!] Nenhuma partição reconhecível encontrada em /forensics/.")
        print("    Use --evidence para especificar o caminho manualmente.")
        sys.exit(1)
    return path


# ─── Interface chatbot ────────────────────────────────────────────────────────

BANNER = """
╔══════════════════════════════════════════════════════════╗
║                AIAgent@forensics v1.0                    ║
║             Politécnico de Leiria - ESTG                 ║
║  Agente LLM para Investigação Forense Digital (ReAct)    ║
╠══════════════════════════════════════════════════════════╣
║  Comandos especiais:                                     ║
║    'sair' / 'exit'  -> termina o programa                ║
║    'limpar'         -> limpa o historico de conversa     ║
║    'estrutura'      -> mostra o que esta montado         ║
╚══════════════════════════════════════════════════════════╝
"""


_default_evidence_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "evidence"))


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="AIAgent@forensics — Agente LLM para investigação forense")
    parser.add_argument("--model",    default=os.getenv("OLLAMA_MODEL", "qwen3.5:4b"),
                        help="Modelo Ollama (default: llama3.2:9b)")
    parser.add_argument("--url",      default=os.getenv("OLLAMA_URL", "http://localhost:11434"),
                        help="URL do servidor Ollama (default: http://localhost:11434)")
    parser.add_argument("--ctx",      type=int,   default=32768,
                        help="Tamanho do contexto em tokens (default: 32768)")
    parser.add_argument("--temp",     type=float, default=0.3,
                        help="Temperatura do modelo (default: 0.3)")
    parser.add_argument("--evidence", default=None,
                        help="Directoria da particao forense (default: auto-detectada)")
    parser.add_argument("--max-iter", dest="max_iter", type=int, default=15,
                        help="Máximo de iterações por pergunta (default: 15)")
    parser.add_argument("--dir", default=_default_evidence_dir,
                        help=f"Directoria host com a imagem forense (default: {_default_evidence_dir})")
    parser.add_argument("--think", action="store_true", default=True,
                        help="Activa modo de raciocínio do modelo (reasoning=True)")
    parser.add_argument("--debug", action="store_true", default=False,
                        help="Mostra campos raw do AIMessage para inspecção")
    return parser.parse_args()


def main():
    args = parse_args()
    
    # Register cleanup function only when main program runs
    atexit.register(stop_container)

    print(BANNER)
    print(f"[*] Modelo   : {args.model} via {args.url}")
    print(f"[*] Contexto : {args.ctx} tokens | Temperatura: {args.temp}")
    sys.modules["agent.tools"].FORENSICS_IMAGE_PATH = os.path.abspath(args.dir)
    print(f"[*] Dir. imagem : {sys.modules['agent.tools'].FORENSICS_IMAGE_PATH}")
    start_container()

    if args.evidence:
        check = run_in_sandbox(f"test -d '{args.evidence}' && echo ok")
        if check.strip() == "ok":
            evidence = args.evidence
            print(f"[*] Evidencia: {evidence} (manual)")
        else:
            print(f"[!] Particao '{args.evidence}' nao encontrada. A usar auto-deteccao...")
            evidence = auto_detect_evidence()
            print(f"[*] Evidencia: {evidence} (auto-detectada)")
    else:
        evidence = auto_detect_evidence()
        print(f"[*] Evidencia: {evidence} (auto-detectada)")

    all_skills = load_skills()
    print(f"[*] Skills carregadas: {len(all_skills)} ({', '.join(s.name for s in all_skills)})")

    llm = ChatOllama(
        model=args.model,
        base_url=args.url,
        temperature=args.temp,
        num_ctx=args.ctx,
        reasoning=True,  # Always enabled for better user experience
    )
    agent = create_agent(model=llm, tools=TOOLS)

    system_prompt = build_system_prompt(evidence)
    conversation = [SystemMessage(content=system_prompt)]

    while True:
        try:
            user_input = input("Tu: ").strip()
        except KeyboardInterrupt:
            print("\n[*] Cancelado. Use 'sair' para terminar.")
            continue
        except EOFError:
            print("\n[*] A encerrar...")
            break

        if not user_input:
            continue
        if user_input.lower() in ("sair", "exit", "quit"):
            print("[*] Ate logo!")
            break
        if user_input.lower() == "limpar":
            conversation = [SystemMessage(content=system_prompt)]
            print("[*] Historico limpo.\n")
            continue
        if user_input.lower() == "estrutura":
            print("\n[Estrutura montada]\n" + run_in_sandbox("find /forensics -maxdepth 3 -type d"))
            continue

        # Skills
        selected = select_skills(user_input, all_skills)
        skills_context = format_skills_context(selected, evidence)
        if selected:
            print(f"[*] Skills selecionadas: {', '.join(s.name for s in selected)}")

        conversation[0] = SystemMessage(
            content=system_prompt + (
                "\nThe following commands are installed and available in the container:\n"
                + skills_context + "\n"
                if skills_context else ""
            )
        )
        conversation.append(HumanMessage(content=user_input))

        print()

        tool_call_count = 0
        limit_reached = False
        new_messages = []

        try:
            for chunk in agent.stream(
                {"messages": conversation},
                {"recursion_limit": 999},
            ):
                for node_output in chunk.values():
                    for msg in node_output.get("messages", []):
                        new_messages.append(msg)
                        print(f"\n{'─'*60}")

                        if isinstance(msg, AIMessage):
                            raw = msg.content if isinstance(msg.content, str) else ""
                            if args.debug:
                                print(f"  [DEBUG] additional_kwargs={msg.additional_kwargs}")
                                print(f"  [DEBUG] response_metadata={msg.response_metadata}")
                            # Pensamento via reasoning_content (reasoning=True) ou tags <think> inline
                            thought = (getattr(msg, "additional_kwargs", {}) or {}).get("reasoning_content", "") or ""
                            if not thought:
                                think_match = re.search(r"<think>(.*?)</think>", raw, re.DOTALL)
                                if think_match:
                                    thought = think_match.group(1).strip()
                            if thought:
                                print(f"  [Pensamento]\n{thought}")
                            visible = re.sub(r"<think>.*?</think>", "", raw, flags=re.DOTALL).strip()
                            tool_calls = getattr(msg, "tool_calls", None) or []
                            print(f"  [AIMessage] content={visible!r}")
                            if tool_calls:
                                print(f"  [tool_calls]")
                            for tc in tool_calls:
                                print(f"    → {tc['name']}({tc['args']})")

                        elif isinstance(msg, ToolMessage):
                            out = msg.content[:300] if isinstance(msg.content, str) else str(msg.content)[:300]
                            suffix = "…" if isinstance(msg.content, str) and len(msg.content) > 300 else ""
                            print(f"  [resultado] {out!r}{suffix}")
                            tool_call_count += 1

                        print(f"{'─'*60}", flush=True)

                if tool_call_count >= args.max_iter:
                    limit_reached = True
                    break

            # Actualizar conversation com os novos passos
            conversation.extend(new_messages)

            # Token usage (último AIMessage)
            last_ai = next((m for m in reversed(new_messages) if isinstance(m, AIMessage)), None)
            if last_ai and getattr(last_ai, "usage_metadata", None):
                u = last_ai.usage_metadata
                pct = round(u["total_tokens"] / args.ctx * 100)
                print(f"\n[Contexto: {u['input_tokens']} in + {u['output_tokens']} out = {u['total_tokens']}/{args.ctx} tokens ({pct}%)]")

            if limit_reached:
                print(f"\n[!] Limite de {args.max_iter} iterações atingido. A pedir sumário...")
                conversation.append(HumanMessage(content=(
                    "You have reached the maximum number of tool calls. "
                    "Based on the evidence collected so far, provide a concise summary of your findings. "
                    "Do NOT call any more tools."
                )))
                summary_msgs = []
                for chunk in agent.stream({"messages": conversation}, {"recursion_limit": 5}):
                    for node_output in chunk.values():
                        summary_msgs.extend(node_output.get("messages", []))
                conversation.extend(summary_msgs)
                answer = next(
                    (m for m in reversed(summary_msgs)
                     if isinstance(m, AIMessage) and not (getattr(m, "tool_calls", None) or [])),
                    None,
                )
                if answer:
                    content = answer.content if isinstance(answer.content, str) else str(answer.content)
                    print(f"\n{'='*60}")
                    print(f"Agente (sumário): {content}")
                    print(f"{'='*60}\n")
                else:
                    print("    Sem sumário disponível.\n")
            else:
                # Resposta final — último AIMessage sem tool calls
                answer = next(
                    (m for m in reversed(new_messages)
                     if isinstance(m, AIMessage) and not (getattr(m, "tool_calls", None) or [])),
                    None,
                )
                if answer:
                    content = answer.content if isinstance(answer.content, str) else str(answer.content)
                    print(f"\n{'='*60}")
                    print(f"Agente: {content}")
                    print(f"{'='*60}\n")
                else:
                    print(f"\n{'='*60}")
                    print("Agente: Não foi possível obter uma resposta final.")
                    print(f"{'='*60}\n")

        except KeyboardInterrupt:
            print("\n[!] Agente cancelado. A voltar ao prompt...")
            if conversation and isinstance(conversation[-1], HumanMessage):
                conversation.pop()

        except Exception as e:
            print(f"\n[!] Erro: {str(e)}\n")
            if conversation and isinstance(conversation[-1], HumanMessage):
                conversation.pop()


if __name__ == "__main__":
    main()
