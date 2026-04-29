"""
main.py — AIAgent@forensics
Agente LLM com paradigma ReAct para investigação forense digital.
Politécnico de Leiria — ESTG | Licenciatura em Engenharia Informática
"""

import argparse
import atexit
import base64 as _b64
import os
import re
import sys
from time import time
import time

_ORANGE = "\033[38;5;208m"
_RESET  = "\033[0m"

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
    "   WRONG: saying 'I cannot find / determine / retrieve this information' without first calling the tool.\n"
    "   WRONG: giving up after previous failures without trying a DIFFERENT approach.\n"
    "   RIGHT: call run_forensics_command with the bash command as the argument.\n"
    "   Do NOT announce what you are about to do. Do NOT ask for clarification. Just call the tool.\n"
    "   EVEN IF a previous attempt failed, you MUST try at least one alternative method before reporting failure.\n"
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
    "   Only report failure after at least TWO distinct approaches have been tried and both failed.\n"
    "   If a registry path fails, try the EVENT LOG. If a tool is missing, try an alternative tool.\n"
    "   NEVER repeat an identical failing command — always change something.\n"
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
    "11. To list Windows users on the evidence image, ALWAYS cross-reference TWO sources:\n"
    "   SOURCE 1 — filesystem: find '{evidence}/USERS' -mindepth 1 -maxdepth 1 -type d\n"
    "   SOURCE 2 — SAM registry: reglookup on the SAM hive, path /SAM/Domains/Account/Users/Names\n"
    "     SAM=$(find '{evidence}' -iname 'SAM' -not -path '*/diagnostics/*' -not -path '*/RegBack/*' 2>/dev/null | head -1)\n"
    "     ; reglookup -p '/SAM/Domains/Account/Users/Names' \"$SAM\"\n"
    "   After running both commands, compare the results: report users present in BOTH,\n"
    "   users only in the filesystem (directory exists but no registry account), and\n"
    "   users only in the registry (account exists but no home directory).\n"
    "12. RAG tools (ingest_pdf_document, query_rag_documents) are ONLY for PDF documents\n"
    "   provided EXTERNALLY by the investigator — never for files inside the forensic image.\n"
    "   To read any file inside /forensics/ (.txt, .doc, .csv, etc.), ALWAYS use\n"
    "   run_forensics_command with strings or head (see Rule 14 — never cat).\n"
    "   NEVER use ingest_pdf_document on files found inside /forensics/.\n"
    "13. EVERY finding you report MUST include its exact source so the investigator can verify it.\n"
    "   For filesystem findings: include the full path (e.g. '{evidence}/USERS/<username>/Documents/report.txt').\n"
    "   For registry findings: include the hive file path AND the registry key\n"
    "     (e.g. hive: '{evidence}/Windows/System32/config/SAM', key: '/SAM/Domains/Account/Users/Names/<username>').\n"
    "   For database findings (SQLite, ESE, MDB): include the database file path and the table/query used.\n"
    "   For metadata findings (exiftool, strings): include the exact file path the tool was run on.\n"
    "   NEVER state a fact without saying where it was found. A finding without a source is inadmissible.\n"
    "14. SYSTEM UPTIME — uptime at a specific timestamp is NOT stored in the Windows registry.\n"
    "   NEVER use reglookup, regquery, or ControlSet keys to find uptime. 'regquery' does not exist in Linux.\n"
    "   NEVER assume ControlSet003 — valid names are ControlSet001 and ControlSet002 only.\n"
    "   The correct method:\n"
    "     Step 1: find '{evidence}' -iname 'System.evtx'  (locate the Windows System event log)\n"
    "     Step 2: FIRST check which evtx package is importable:\n"
    "             python3 -c \"import evtx; print('evtx OK')\" 2>&1 || python3 -c \"import Evtx; print('Evtx OK')\" 2>&1\n"
    "     Step 3: parse with whichever module is available:\n"
    "       Option A — 'evtx' module (omerbenamram):\n"
    "             python3 -c \"\n"
    "             import evtx, json\n"
    "             with evtx.PyEvtxParser('<System.evtx path>') as p:\n"
    "               for r in p.records_json():\n"
    "                 d=json.loads(r['data']); eid=d.get('Event',{{}}).get('System',{{}}).get('EventID','')\n"
    "                 if isinstance(eid,dict): eid=eid.get('#text','')\n"
    "                 if str(eid) in ('6005','6006'): print(eid, r.get('timestamp',''))\n"
    "             \" 2>&1 | head -50\n"
    "       Option B — 'Evtx' module (python-evtx/willi-ballenthin):\n"
    "             python3 -c \"\n"
    "             import Evtx.Evtx as evtx\n"
    "             with evtx.Evtx('<System.evtx path>') as log:\n"
    "               for r in log.records():\n"
    "                 xml=r.xml()\n"
    "                 if '>6005<' in xml or '>6006<' in xml: print(xml[:400])\n"
    "             \" 2>&1 | head -100\n"
    "     NEVER use strings on .evtx — timestamps are binary FILETIME, not ASCII.\n"
    "     NEVER use evtx_dump CLI without first running 'which evtx_dump'.\n"
    "     Step 3: identify the LAST boot event (ID 6005) that occurred BEFORE the target timestamp\n"
    "     Step 4: uptime = target_timestamp − boot_timestamp  (calculate in Python)\n"
    "   NEVER report shutdown time (regripper -p shutdown) as boot time — they are different values.\n"
    "\n"
    "15. EMAIL FORENSICS (.eml files) — ALWAYS use grep directly on the file, never strings.\n"
    "   To read email headers: awk '/^$/{{exit}} 1' 'file.eml'\n"
    "   TIMEZONE SEMANTICS — an email passes through multiple SMTP servers, each adding a Received: header:\n"
    "     • 'Date:' header          → sender's timezone (set by the mail client)\n"
    "     • Topmost 'Received:'     → DESTINATION timezone (the inbox/delivery server)\n"
    "     • Bottom-most 'Received:' → closest to the sender/origin\n"
    "   When asked for the DESTINATION timezone, report the offset from the FIRST (topmost) Received: header.\n"
    "   When asked for the SENDER timezone, report the offset from the Date: header.\n"
    "   NEVER report the Date: header offset as the destination timezone.\n"
    "   ALWAYS run: grep -i -E '^(date|received):' 'file.eml'  to capture ALL timezone data.\n"
    "\n"
    "16. This tool returns at most 100 lines of output. Any command producing more than 100 lines is\n"
    "   TRUNCATED — the excess is NOT visible to you and you will silently miss evidence.\n"
    "   NEVER use `cat` on any file — its output will be cut off unpredictably.\n"
    "   ALWAYS read files in controlled chunks:\n"
    "     Count lines first:                 wc -l 'file'\n"
    "     First chunk (lines 1–100):         head -n 100 'file'\n"
    "     Next chunk (lines 101–200):        awk 'NR>=101 && NR<=200' 'file'\n"
    "     Next chunk (lines 201–300):        awk 'NR>=201 && NR<=300' 'file'\n"
    "     Search inside a file:              grep 'keyword' 'file'\n"
    "   For binary files: strings 'file' | head -n 100  (NEVER strings alone)\n"
    "   Continue reading chunks until you have seen all lines relevant to the investigation.\n"
)


def build_system_prompt(evidence: str, allow_network: bool = False) -> str:
    prompt = _SYSTEM_PROMPT_TEMPLATE.format(evidence=evidence)
    if allow_network:
        prompt += (
            "\nNETWORK MODE: Internet access is enabled in this container.\n"
            "The container runs as root — NEVER use sudo.\n"
            "If a command returns 'command not found' or 'not installed', "
            "AUTOMATICALLY install it and then re-run the original command — "
            "do NOT ask the user for permission. Installation order to try:\n"
            "  1. apt-get install -y <package>   (if found in apt repos)\n"
            "  2. pip3 install <package>          (if not in apt, e.g. volatility3)\n"
            "  3. pip3 install --break-system-packages <package>  (if pip3 refuses)\n"
            "Only install tools directly relevant to the investigation. "
            "Do NOT use the network for any other purpose.\n"
        )
    return prompt


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
║    'limpar_rag'     -> limpa documentos RAG indexados    ║
╚══════════════════════════════════════════════════════════╝
"""


_default_evidence_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "evidence"))


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="AIAgent@forensics — Agente LLM para investigação forense")
    parser.add_argument("--model",    default=os.getenv("OLLAMA_MODEL", "gemma4:e4b"),
                        help="Modelo Ollama (default: llama3.2:9b)")
    parser.add_argument("--url",      default=os.getenv("OLLAMA_URL", "http://localhost:11434"),
                        help="URL do servidor Ollama (default: http://localhost:11434)")
    parser.add_argument("--ctx",      type=int,   default=32768,
                        help="Tamanho do contexto em tokens (default: 32768)")
    parser.add_argument("--temp",     type=float, default=0.3,
                        help="Temperatura do modelo (default: 0.3)")
    parser.add_argument("--evidence", default=None,
                        help="Directoria da particao forense (default: auto-detectada)")
    parser.add_argument("--dir", default=_default_evidence_dir,
                        help=f"Directoria host com a imagem forense (default: {_default_evidence_dir})")
    parser.add_argument("--think", action="store_true", default=True,
                        help="Activa modo de raciocínio do modelo (reasoning=True)")
    parser.add_argument("--debug", action="store_true", default=False,
                        help="Mostra campos raw do AIMessage para inspecção")
    parser.add_argument("--no-clear-rag", dest="clear_rag", action="store_false",
                        help="Mantém documentos RAG indexados de sessões anteriores")
    parser.set_defaults(clear_rag=True)
    parser.add_argument("--no-mount", dest="no_mount", action="store_true", default=False,
                        help="Monta a directoria de evidência directamente em /forensics (sem imagem E01/DD)")
    parser.add_argument("--allow-network", dest="allow_network", action="store_true", default=False,
                        help="Activa acesso à internet no container (para sudo apt-get install)")
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
    start_container(no_mount=args.no_mount, allow_network=args.allow_network)

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

    from rag.indexer import clear_collection, list_indexed_documents
    indexed = list_indexed_documents()
    if args.clear_rag and indexed:
        n = clear_collection()
        print(f"[*] RAG: coleccao limpa ({n} chunks removidos). Use --no-clear-rag para manter.")
    elif indexed:
        print(f"[*] RAG: {len(indexed)} documento(s) indexado(s): {', '.join(indexed)}")
    else:
        print("[*] RAG: coleccao vazia.")

    llm = ChatOllama(
        model=args.model,
        base_url=args.url,
        temperature=args.temp,
        num_ctx=args.ctx,
        reasoning=True,  # Always enabled for better user experience
    )
    agent = create_agent(model=llm, tools=TOOLS)

    system_prompt = build_system_prompt(evidence, allow_network=args.allow_network)
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
        if user_input.lower() == "limpar_rag":
            from rag.indexer import clear_collection
            n = clear_collection()
            print(f"[*] RAG: coleccao limpa ({n} chunks removidos).\n")
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

        original_query_msg = conversation[-1]
        ts_query = int(time.time())
        t_start  = time.time()
        out_file = f"/exports/investigation_summary_{ts_query}.txt"
        intermediate_files: list[str] = []
        MAX_COMPRESSIONS = 20
        forced_continuations = 0
        MAX_FORCED = 3

        def _llm_content(resp) -> str:
            c = resp.content if isinstance(resp.content, str) else str(resp.content)
            if not c.strip():
                c = (getattr(resp, "additional_kwargs", {}) or {}).get("reasoning_content", "") or ""
            return c

        def _consolidate() -> str:
            exports_dir = sys.modules["agent.tools"].EXPORTS_PATH
            parts = []
            for f in intermediate_files:
                local = os.path.join(exports_dir, os.path.basename(f))
                try:
                    with open(local, "r", encoding="utf-8", errors="replace") as fp:
                        parts.append(fp.read())
                except Exception:
                    pass
            if parts:
                combined = "\n\n".join(parts)
                prompt = [
                    conversation[0],
                    original_query_msg,
                    HumanMessage(content=(
                        "Based on the following intermediate investigation reports, "
                        "produce a comprehensive final investigation report. "
                        "Consolidate all findings, eliminate duplicates, and provide "
                        "a clear structured conclusion. Do NOT call any tools.\n\n"
                        + combined
                    )),
                ]
            else:
                prompt = conversation + [HumanMessage(content=(
                    "Based on the evidence collected so far, provide a concise final summary "
                    "of your findings. Do NOT call any more tools."
                ))]
            return _llm_content(llm.invoke(prompt))

        agent_active = True
        try:
            while agent_active:
                needs_compress = False
                new_messages = []
                last_usage = None
                pending_tool_calls = 0

                for chunk in agent.stream(
                    {"messages": conversation},
                    {"recursion_limit": 999},
                ):
                    for node_output in chunk.values():
                        for msg in node_output.get("messages", []):
                            new_messages.append(msg)

                            if isinstance(msg, AIMessage):
                                raw = msg.content if isinstance(msg.content, str) else ""

                                if args.debug:
                                    print(f"{_ORANGE}\n{'─'*60}{_RESET}")
                                    print(f"{_ORANGE}  [DEBUG] additional_kwargs={msg.additional_kwargs}{_RESET}")
                                    print(f"{_ORANGE}  [DEBUG] response_metadata={msg.response_metadata}{_RESET}")

                                thought = (getattr(msg, "additional_kwargs", {}) or {}).get("reasoning_content", "") or ""
                                if not thought:
                                    think_match = re.search(r"<think>(.*?)</think>", raw, re.DOTALL)
                                    if think_match:
                                        thought = think_match.group(1).strip()

                                if thought:
                                    if args.debug:
                                        print(f"  [Pensamento]\n{thought}")
                                    else:
                                        lines = [l.strip() for l in thought.strip().splitlines() if l.strip()]
                                        action_lines = [
                                            l for l in lines
                                            if l and not l[0].isdigit() and not l.startswith('-')
                                        ]
                                        for line in action_lines[:2]:
                                            print(f"⟳ ", end="", flush=True)
                                            for word in line.split():
                                                print(word, end=" ", flush=True)
                                                time.sleep(0.03)
                                            print()

                                visible = re.sub(r"<think>.*?</think>", "", raw, flags=re.DOTALL).strip()
                                tool_calls = getattr(msg, "tool_calls", None) or []
                                pending_tool_calls += len(tool_calls)

                                if args.debug:
                                    print(f"{_ORANGE}  [AIMessage] content={visible!r}{_RESET}")
                                    if tool_calls:
                                        print(f"{_ORANGE}  [tool_calls]{_RESET}")
                                    for tc in tool_calls:
                                        print(f"{_ORANGE}    → {tc['name']}({tc['args']}){_RESET}")

                                if getattr(msg, "usage_metadata", None):
                                    last_usage = msg.usage_metadata
                                    ratio = last_usage["total_tokens"] / args.ctx
                                    if ratio >= 0.70:
                                        needs_compress = True

                            elif isinstance(msg, ToolMessage):
                                pending_tool_calls = max(0, pending_tool_calls - 1)
                                if args.debug:
                                    out = msg.content[:300] if isinstance(msg.content, str) else str(msg.content)[:300]
                                    suffix = "…" if isinstance(msg.content, str) and len(msg.content) > 300 else ""
                                    print(f"{_ORANGE}  [resultado] {out!r}{suffix}{_RESET}")

                            if args.debug and isinstance(msg, (AIMessage, ToolMessage)):
                                print(f"{_ORANGE}{'─'*60}{_RESET}", flush=True)

                    over_limit = last_usage is not None and last_usage["total_tokens"] / args.ctx >= 0.85
                    if (needs_compress and pending_tool_calls == 0) or over_limit:
                        break

                conversation.extend(new_messages)

                if last_usage:
                    u = last_usage
                    pct = round(u["total_tokens"] / args.ctx * 100)
                    color, reset = (_ORANGE, _RESET) if args.debug else ("", "")
                    print(f"{color}\n[Contexto: {u['input_tokens']} in + {u['output_tokens']} out = {u['total_tokens']}/{args.ctx} tokens ({pct}%)]{reset}")

                if needs_compress:
                    has_tool_results = any(isinstance(m, ToolMessage) for m in new_messages)

                    if not has_tool_results:
                        conversation = [
                            conversation[0],
                            original_query_msg,
                            HumanMessage(content="Continue the investigation."),
                        ]
                    else:
                        part_n = len(intermediate_files) + 1
                        inter_file = f"/exports/investigation_part_{ts_query}_{part_n:02d}.txt"
                        reason = f"Contexto a {round(last_usage['total_tokens']/args.ctx*100)}%"
                        print(f"\n[*] {reason} — a guardar relatório intermédio {part_n} e continuar...")

                        if len(intermediate_files) >= MAX_COMPRESSIONS:
                            agent_active = False
                            print(f"[!] Limite de {MAX_COMPRESSIONS} compressões atingido. A gerar relatório final...")
                            content = _consolidate()
                            elapsed = time.time() - t_start
                            print(f"\n{'='*60}")
                            print(f"Agente: {content}")
                            print(f"{'='*60}")
                            print(f"[*] Tempo de resposta: {elapsed:.1f}s\n")
                            mins, secs = divmod(int(elapsed), 60)
                            header = (
                                f"=== Relatório Final ===\n"
                                f"Tempo de investigação: {elapsed:.1f}s ({mins}m{secs:02d}s)\n"
                                f"Pergunta: {original_query_msg.content}\n"
                                f"{'='*24}\n\n"
                            )
                            b64 = _b64.b64encode((header + content).encode("utf-8")).decode()
                            run_in_sandbox(f"echo '{b64}' | base64 -d > {out_file}")
                            print(f"[*] Relatório final guardado em: {out_file}\n")
                        else:
                            # Call 1: sumário completo → ficheiro intermédio
                            full_resp = llm.invoke(conversation + [HumanMessage(content=(
                                "Write a comprehensive intermediate investigation report of ALL evidence found so far.\n"
                                "BEGIN IMMEDIATELY with the report content — do NOT explain what you are about to do.\n"
                                "Do NOT use phrases like 'The user is asking me to...', 'Let me review...', 'I should...'.\n"
                                "Do NOT call any tools. Do NOT include bash commands or code blocks.\n"
                                "Structure: users found, key files and their content, suspicious items, registry/system findings, timestamps.\n"
                                "Be thorough and specific — exact file paths, usernames, timestamps, hash values, suspicious content.\n"
                                "For EVERY finding include its exact source: full file path, or registry hive path + key, "
                                "or database file path + table. A finding without a source must not appear in the report.\n"
                                "ONLY report findings from actual tool results already in this conversation.\n"
                                "End with a brief list of areas not yet explored."
                            ))])
                            full_summary = _llm_content(full_resp)
                            header = f"=== Relatório Intermédio {part_n} [{int(time.time())}] ===\n"
                            b64 = _b64.b64encode((header + full_summary).encode("utf-8")).decode()
                            run_in_sandbox(f"echo '{b64}' | base64 -d > {inter_file}")
                            intermediate_files.append(inter_file)
                            print(f"[*] Relatório {part_n} guardado em: {inter_file}")

                            # Call 2: sumário curto → conversa comprimida
                            short_resp = llm.invoke(conversation + [HumanMessage(content=(
                                "Summarise the investigation so far in 3-5 bullet points (maximum 100 words). "
                                "Include only the most important confirmed findings from tool results. "
                                "Do NOT include bash commands or code blocks."
                            ))])
                            short_summary = _llm_content(short_resp)

                            conversation = [
                                conversation[0],
                                original_query_msg,
                                AIMessage(content=(
                                    f"[Investigation part {part_n} saved to {inter_file}]\n\n"
                                    f"Key findings so far:\n{short_summary}"
                                )),
                                HumanMessage(content=(
                                    "Continue the forensic investigation. "
                                    "Do NOT provide a final answer or summary yet — keep running commands.\n"
                                    "Investigate areas NOT yet covered: browser history databases, "
                                    "email content and attachments, encoded/encrypted files (decode them), "
                                    "registry hives (USB history, installed software, user activity), "
                                    "other user profiles, Recycle Bin contents, and any suspicious files.\n"
                                    f"Detailed findings so far are in {inter_file}. "
                                    "Run commands until you have exhausted all leads."
                                )),
                            ]

                else:
                    low_usage = (last_usage is not None and
                                 last_usage["total_tokens"] / args.ctx < 0.25)
                    if low_usage and intermediate_files and forced_continuations < MAX_FORCED:
                        forced_continuations += 1
                        conversation.extend(new_messages)
                        conversation.append(HumanMessage(content=(
                            "You stopped investigating too early. There are still unexplored areas. "
                            "Continue running forensic commands — do NOT summarize yet."
                        )))
                        print(f"[*] Investigação terminou cedo ({round(last_usage['total_tokens']/args.ctx*100)}% ctx) "
                              f"— a forçar continuação ({forced_continuations}/{MAX_FORCED})...")
                    else:
                        agent_active = False
                        answer = next(
                            (m for m in reversed(new_messages)
                             if isinstance(m, AIMessage) and not (getattr(m, "tool_calls", None) or [])),
                            None,
                        )
                        content = ""
                        if answer:
                            content = answer.content if isinstance(answer.content, str) else str(answer.content)
                            if not content.strip():
                                content = (getattr(answer, "additional_kwargs", {}) or {}).get("reasoning_content", "") or ""

                        if intermediate_files:
                            content = _consolidate()
                            elapsed = time.time() - t_start
                            mins, secs = divmod(int(elapsed), 60)
                            header = (
                                f"=== Relatório Final ===\n"
                                f"Tempo de investigação: {elapsed:.1f}s ({mins}m{secs:02d}s)\n"
                                f"Pergunta: {original_query_msg.content}\n"
                                f"{'='*24}\n\n"
                            )
                            b64 = _b64.b64encode((header + content).encode("utf-8")).decode()
                            run_in_sandbox(f"echo '{b64}' | base64 -d > {out_file}")
                            print(f"[*] Relatório final guardado em: {out_file}\n")

                        print(f"\n{'='*60}")
                        print(f"Agente: {content}" if content else "Agente: Não foi possível obter uma resposta final.")
                        print(f"{'='*60}")
                        print(f"[*] Tempo de resposta: {time.time() - t_start:.1f}s\n")

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
