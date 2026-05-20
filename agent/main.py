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

import shlex
import json
import urllib.request

from .tools import run_in_sandbox, stop_container, start_container, EXPORTS_PATH
from .skills import load_skills, select_skills, format_skills_context

load_dotenv()

def _q(path: str) -> str:
    """Shell-quote a path for use inside run_in_sandbox commands."""
    return shlex.quote(path)

# ─── Ferramenta exposta ao agente ─────────────────────────────────────────────

@tool
def run_forensics_command(command: str) -> str:
    """
    Run any bash command inside the forensic Linux container and get back stdout and stderr.

    FILESYSTEM LAYOUT:
      Raw disk image  - EWF images are mounted and exposed as a file named 'ewf1';
                        find it with: find / -maxdepth 6 -name 'ewf1' -type f 2>/dev/null
      Mounted partitions - evidence partitions are mounted as directories (READ-ONLY);
                           find them with: mount | grep -iE 'loop|fuseblk|ntfs'
      /exports/       - writable directory for saving output files

    IMPORTANT: mounted partition directories are NOT disk image files.
      Opening a directory as a binary file always fails with IsADirectoryError.
      For raw disk analysis (GUIDs, schema, cluster size) use the raw image file found above.

    NOTES:
      - Paths with spaces MUST use single quotes
      - Evidence partitions are READ-ONLY — never redirect or write there
    """
    return run_in_sandbox(command)


@tool
def ingest_pdf_document(filename: str) -> str:
    """
    Index a document (PDF, DOCX, CSV or TXT) in the RAG vector store for later querying.

    Accepts paths on the host OR paths inside the forensic container
    (e.g. /forensics/part006/USERS/Jimmy Wilson/Documents/report.pdf).
    Container paths are copied to a temp file on the host before indexing.

    Supported formats: .pdf, .docx, .csv, .txt, .md

    Args:
        filename: Path to the document — either a host path or a container path
                  (starting with /forensics/ or /exports/).

    Returns:
        Status message indicating success, failure, or if already indexed.
    """
    import logging
    from rag.indexer import ingest_document, is_document_indexed

    logger = logging.getLogger(__name__)

    exports_tmp = None
    try:
        basename = os.path.basename(filename)

        # Check if already indexed before doing any file I/O
        if is_document_indexed(basename):
            return f"Document '{basename}' is already indexed. Use query_rag_documents to search it."

        # If the path lives inside the container, copy via /exports/ (shared volume).
        # This handles paths with spaces correctly — docker cp breaks with spaces.
        if filename.startswith("/forensics/"):
            safe_name = re.sub(r"[^\w.\-]", "_", basename)
            exports_tmp_container = f"/exports/_rag_ingest_{safe_name}"
            exports_tmp = os.path.join(EXPORTS_PATH, f"_rag_ingest_{safe_name}")

            result_cp = run_in_sandbox(f"cp {_q(filename)} {_q(exports_tmp_container)}")
            if not os.path.isfile(exports_tmp):
                return (
                    f"Error: could not copy '{basename}' to /exports/ — "
                    f"{result_cp.strip() or 'cp failed inside container'}"
                )
            ingest_path = exports_tmp
        elif filename.startswith("/exports/"):
            ingest_path = os.path.join(EXPORTS_PATH, basename)
            if not os.path.isfile(ingest_path):
                return f"Error: file '{filename}' not found in exports."
        else:
            if not os.path.isfile(filename):
                return f"Error: file '{filename}' not found."
            ingest_path = filename

        result = ingest_document(ingest_path, original_filename=basename)
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
    finally:
        if exports_tmp and os.path.exists(exports_tmp):
            os.unlink(exports_tmp)


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
    from rag.generator import answer_with_rag

    logger = logging.getLogger(__name__)

    # Auto-detect filename from query if not provided
    if not filename:
        _ext = r'(?:pdf|docx?|csv|txt|md)'
        filename_patterns = [
            rf'(?:com base no|ficheiro|arquivo|documento)\s+([a-zA-Z0-9_\-.]+\.{_ext})',
            rf'([a-zA-Z0-9_\-.]+\.{_ext})',
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


_skills_cache: list = []
_evidence_path: str = ""


@tool
def get_forensic_procedure(task: str) -> str:
    """
    Get step-by-step forensic procedures and exact commands for a specific task.

    MANDATORY — call this BEFORE running commands for any of these operations:
      - extracting a file from a VHD or VMDK partition (icat, fls, inode lookup)
      - computing SHA1 or MD5 hash of a file inside a virtual disk image
      - reading jump lists to find when an application was last run
      - finding the last-run timestamp of Windows Mail or any application via jump lists
      - getting disk GUID, partition GUID, or partition schema from a physical disk
      - reading the SAM hive for user accounts, last login times, or password hints
      - getting cluster size or volume label from a partition
      - reading Windows event logs for boot time, shutdown, or system uptime
      - analysing prefetch files or recycle bin contents

    Also call this whenever you are unsure which tool or command to use.

    Returns exact commands and procedures. Pass a short description of the task,
    for example: "extract Card Printers.htm from VHD and compute SHA1",
    "find last run time of Windows Mail from jump lists", "get disk partition GUID".
    """
    global _skills_cache, _evidence_path
    if not _skills_cache:
        _skills_cache = load_skills()
    selected = select_skills(task, _skills_cache, max_skills=2, min_score=0.10)
    if not selected:
        return "No specific procedure found for this task. Use standard forensic tools in the container."
    return format_skills_context(selected, _evidence_path or "{evidence}")


TOOLS = [run_forensics_command, ingest_pdf_document, query_rag_documents, get_forensic_procedure]

# ─── System prompt ────────────────────────────────────────────────────────────

_SYSTEM_PROMPT_TEMPLATE = (
    "You are a digital forensics expert agent operating in READ-ONLY forensic mode.\n"
    "LANGUAGE — ABSOLUTE RULE: ALL your responses MUST be written in English.\n"
    "This applies regardless of the language used in the user's message.\n"
    "NEVER respond in Portuguese, Spanish, French, or any other language.\n"
    "If the user writes in Portuguese, understand it but reply ONLY in English.\n"
    "\n"
    "ANSWER FORMAT:\n"
    "  If the question provides multiple-choice options (e.g. 'a) ... b) ... c) ...'),\n"
    "  reply with ONLY the letter (a, b, c, or d). Never reply with 'true', 'false',\n"
    "  or any other text when a letter is the expected answer format.\n"
    "  CRITICAL — FULL OPTION MATCH: before selecting a letter, read ALL options in full\n"
    "  and verify that the COMPLETE option text matches ALL your findings, not just one\n"
    "  keyword. When an option lists multiple values (e.g. 'Truecrypt/BCTextEncoder'),\n"
    "  EVERY value in that option must match evidence you found. An option containing one\n"
    "  correct keyword but one wrong keyword is WRONG. Never stop at the first option that\n"
    "  contains a matching keyword — read every option before deciding.\n"
    "  If the question asks for True/False, reply with only 'true' or 'false'.\n"
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
    "\n"
    "  reglookup SYNTAX — CRITICAL:\n"
    "    1. reglookup uses FORWARD SLASHES '/' as path separators — NEVER backslashes.\n"
    "    2. Arguments are ALWAYS: reglookup -p '<KEY_PATH>' '<HIVE_FILE>'\n"
    "       -p = the path WITHIN the registry using forward slashes\n"
    "       last arg = the hive FILE path on disk\n"
    "  WRONG: reglookup -p '/forensics/.../NTUSER.DAT' 'Software\\...'  ← args reversed!\n"
    "  WRONG: reglookup -p 'Software\\Microsoft\\Windows\\CurrentVersion\\Run' ...  ← backslashes!\n"
    "  RIGHT: reglookup -p '/Software/Microsoft/Windows/CurrentVersion/Run' '/forensics/.../NTUSER.DAT'\n"
    "\n"
    "  SYSTEM HIVES — resolve path with find in the SAME command string:\n"
    "    HIVE=$(find '{evidence}' -iname 'SOFTWARE' -not -path '*/Users/*'\n"
    "      -not -path '*/diagnostics/*' -not -path '*/RegBack/*' 2>/dev/null | head -1)\n"
    "    ; reglookup -p '/...' \"$HIVE\"\n"
    "  The variable HIVE is defined and used in the SAME command — this is correct.\n"
    "  NEVER use $HIVE or $SOFTWARE_HIVE or $SYSTEM_HIVE across separate commands —\n"
    "  variables do NOT persist between tool calls.\n"
    "  NEVER use inline $(find ...) without assigning to a quoted variable first.\n"
    "  The -not -path '*/diagnostics/*' filter is CRITICAL — omitting it may return\n"
    "  a diagnostics file instead of the real hive, causing 'undefined value' errors.\n"
    "\n"
    "  USER HIVE (NTUSER.DAT) — the path is known directly, no find needed:\n"
    "    reglookup -p '/Software/Microsoft/Windows/CurrentVersion/Run' \\\n"
    "      '{evidence}/USERS/<username>/NTUSER.DAT'\n"
    "  Note: NTUSER.DAT paths use forward slashes and a leading slash, same as system hives.\n"
    "  Note: use single-quoted hive path when the username contains spaces.\n"
    "\n"
    "  USER STARTUP PROGRAMS (Run key in NTUSER.DAT):\n"
    "    reglookup -p '/Software/Microsoft/Windows/CurrentVersion/Run' \\\n"
    "      '{evidence}/USERS/<username>/NTUSER.DAT'\n"
    "  If the above returns an error, check the hive file exists first:\n"
    "    find '{evidence}/USERS/<username>' -iname 'NTUSER.DAT'\n"
    "  Case matters on Linux — the file may be 'NTUSER.DAT' or 'ntuser.dat'.\n"
    "\n"
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
    "2b. EXACT VALUES — Forensic evidence must be compared exactly, character by character.\n"
    "   A timestamp, hash, GUID, or file size that differs by even one character or digit is NOT a match.\n"
    "   Never round, approximate, or assume 'close enough'. If the value found does not match\n"
    "   a given reference exactly, report it as a non-match and state the exact value found.\n"
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
    "8. FORENSIC PROCEDURES — when you need guidance on HOW to perform a specific forensic task\n"
    "   (e.g. extract a file from a VHD, read a disk GUID, parse a registry hive),\n"
    "   call get_forensic_procedure(task) FIRST to get exact commands.\n"
    "   Only call it when you genuinely need procedural guidance, not for every question.\n"
    "8b. MANDATORY TOOL CALL — you MUST call run_forensics_command before answering ANY question.\n"
    "   Answering without first calling the tool is FORBIDDEN, even if you think you know the answer.\n"
    "   Every new question requires a NEW tool call — no exceptions.\n"
    "   NEVER answer from memory or from results seen earlier in this conversation.\n"
    "   Even if the exact same question was just asked, call run_forensics_command again.\n"
    "   Answering without a tool call is treated the same as hallucination — always wrong.\n"
    "9. If command output is truncated, use grep, head, or tail to extract the needed\n"
    "   information before answering. NEVER assume or invent content that was cut off.\n"
    "10. When the user provides an absolute path in a command, run it EXACTLY as given.\n"
    "   NEVER modify, rewrite, or prefix it with {evidence}.\n"
    "   WRONG (user said 'cat /etc/hosts'): cat '{evidence}/etc/hosts'\n"
    "   RIGHT: cat /etc/hosts\n"
    "10b. FILE SCOPE — only search inside /forensics/ when the user explicitly references\n"
    "   the forensic image, container, or a path that starts with /forensics/.\n"
    "   If the user refers to a file by name only (e.g. 'resume file 1.txt', 'read report.csv')\n"
    "   WITHOUT mentioning the image, treat the file as being on the HOST filesystem.\n"
    "   HOST_WORKDIR = {workdir}   (project directory on the host — files provided by the user live here)\n"
    "   Search order for host files — try in this exact sequence:\n"
    "     1. Try ingest_pdf_document('{workdir}/filename') directly.\n"
    "        If it succeeds, follow up with query_rag_documents to answer the user's request.\n"
    "     2. If step 1 fails (file not found), check /exports/:\n"
    "        ls /exports/ | grep -i 'filename'\n"
    "        If found: ingest_pdf_document('/exports/filename') then query_rag_documents.\n"
    "     3. If still not found, reply EXACTLY:\n"
    "        'File not found. Please copy it to /exports/ with:\n"
    "         cp {workdir}/filename /exports/\n"
    "         Then ask me again.'\n"
    "   NEVER run find '/forensics' for a file the user did not place in the forensic image.\n"
    "   NEVER trigger the VHD SEARCH (Rule 17) for host-scope file requests.\n"
    "11. To list Windows users on the evidence image, ALWAYS cross-reference TWO sources:\n"
    "   SOURCE 1 — filesystem: find '{evidence}/USERS' -mindepth 1 -maxdepth 1 -type d\n"
    "   SOURCE 2 — SAM registry: reglookup on the SAM hive, path /SAM/Domains/Account/Users/Names\n"
    "     SAM=$(find '{evidence}' -iname 'SAM' -not -path '*/diagnostics/*' -not -path '*/RegBack/*' 2>/dev/null | head -1)\n"
    "     ; reglookup -p '/SAM/Domains/Account/Users/Names' \"$SAM\"\n"
    "   After running both commands, compare the results: report users present in BOTH,\n"
    "   users only in the filesystem (directory exists but no registry account), and\n"
    "   users only in the registry (account exists but no home directory).\n"
    "12. RAG tools (ingest_pdf_document, query_rag_documents) work for PDF, DOCX, CSV, TXT and MD documents\n"
    "   both EXTERNAL (provided by the investigator) and INSIDE the forensic image.\n"
    "   For documents inside /forensics/ pass the full container path directly to ingest_pdf_document\n"
    "   (e.g. ingest_pdf_document('/forensics/part006/USERS/Jimmy Wilson/Documents/report.pdf')).\n"
    "   The tool copies the file from the container automatically — no manual cp needed.\n"
    "   Supported extensions: .pdf, .docx, .csv, .txt, .md\n"
    "   CRITICAL — when querying a SPECIFIC document, ALWAYS pass filename= explicitly:\n"
    "     query_rag_documents('summarise this document', filename='report.docx')\n"
    "   NEVER call query_rag_documents without filename= when you know which document the user is asking about.\n"
    "   To read other file types inside /forensics/ (.doc, .xls, etc.), ALWAYS use\n"
    "   run_forensics_command with strings or head (see Rule 14 — never cat).\n"
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
    "   ALWAYS run this first to capture ALL Received: and Date: headers:\n"
    "     grep -i -E '^(date|received):' 'file.eml'\n"
    "\n"
    "   RECEIVED HEADER CHAIN — each SMTP hop adds one Received: header at the TOP:\n"
    "     • Topmost 'Received:'     → FINAL DESTINATION server (inbox/delivery)\n"
    "     • Bottom-most 'Received:' → first hop, closest to sender/origin\n"
    "     Each Received: header contains the IP of the server that ACCEPTED the message.\n"
    "\n"
    "   DESTINATION IP ADDRESS:\n"
    "     The 'final destination IP' is the IP in the TOPMOST Received: header.\n"
    "     Extract it with: grep -i '^received:' 'file.eml' | head -1\n"
    "     Look for patterns like: 'from ... [x.x.x.x]' or 'by ... with'\n"
    "     The IP inside [] in the topmost Received: = final destination.\n"
    "\n"
    "   TIMEZONE SEMANTICS:\n"
    "     • 'Date:' header          → sender's timezone (set by the mail client)\n"
    "     • Topmost 'Received:'     → DESTINATION timezone (the inbox/delivery server)\n"
    "     • Bottom-most 'Received:' → closest to the sender/origin\n"
    "   When asked for the DESTINATION timezone, report the offset from the FIRST (topmost) Received: header.\n"
    "   When asked for the SENDER timezone, report the offset from the Date: header.\n"
    "   NEVER report the Date: header offset as the destination timezone.\n"
    "\n"
    "16. SAM HIVE — LOCAL WINDOWS USERS (last login, RID, password hint, account status).\n"
    "   The SAM hive is the ONLY reliable source for last login time, RID, password hint, and account flags.\n"
    "   The Security event log (Event ID 4624) stores the SAM account name (e.g. 'jwilson'), NOT the display\n"
    "   name, and the log may be incomplete or cleared. ALWAYS prefer the SAM hive.\n"
    "   NEVER search Event ID 4624 by display name to find last login.\n"
    "\n"
    "17. EVTX XML ATTRIBUTE PARSING — the correct element format in Windows EVTX XML is:\n"
    "     <Data Name=\"TargetUserName\">jwilson</Data>   (element content, NOT an XML attribute)\n"
    "   WRONG regex: r'TargetUserName=\"([^\"]+)\"'   (looks for XML attribute — will NEVER match)\n"
    "   RIGHT regex: r'<Data Name=\"TargetUserName\">([^<]+)</Data>'\n"
    "   Apply the same pattern for ANY named Data field: SubjectUserName, IpAddress, LogonType, etc.\n"
    "\n"
    "18. This tool returns at most 100 lines of output. Any command producing more than 100 lines is\n"
    "   TRUNCATED — the excess is NOT visible to you and you will silently miss evidence.\n"
    "\n"
    "   `cat` is AUTO-INTERCEPTED at the tool layer:\n"
    "     • binary file  → blocked; you get xxd/strings guidance instead\n"
    "     • text < 10 KB → allowed as-is\n"
    "     • text 10–500 KB → silently transformed to head -n 100\n"
    "     • text > 500 KB → blocked; you get wc -l/grep guidance instead\n"
    "   Auto-interception is a safety net, NOT a strategy. Follow the decision tree below\n"
    "   so you choose the right tool intentionally on the FIRST call.\n"
    "\n"
    "   ALWAYS follow this decision tree before reading any file:\n"
    "\n"
    "   A) DETECT FILE TYPE FIRST — always run this before any read:\n"
    "     file -b --mime-type 'path'\n"
    "     -> 'text/*'                   -> treat as TEXT (go to B)\n"
    "     -> 'application/x-sqlite3'    -> sqlite3 'path' \".tables\" then SELECT query\n"
    "     -> 'application/x-ms-evtx'   -> use python3 evtx parser (see Rule 14)\n"
    "     -> registry hive (no ext.)   -> use reglookup (see REGISTRY HIVES section)\n"
    "     -> anything else              -> treat as unknown binary (go to D)\n"
    "\n"
    "   B) TEXT FILES — check size first:\n"
    "     wc -l 'path'\n"
    "     -> under 100 lines : head -n 100 'path'   (reads everything in one call)\n"
    "     -> 100-5000 lines  : read in overlapping chunks (go to C)\n"
    "     -> over 5000 lines : NEVER read sequentially — use targeted search only:\n"
    "         grep -n -i 'keyword' 'path' | head -n 100\n"
    "         grep -n -A 5 -B 5 'keyword' 'path' | head -n 100\n"
    "\n"
    "   C) OVERLAPPING CHUNKS for text files (100-5000 lines):\n"
    "     Chunk 1:  head -n 100 'path'               (lines 1-100)\n"
    "     Chunk 2:  awk 'NR>=86  && NR<=185' 'path'  (lines 86-185,  overlap 15)\n"
    "     Chunk 3:  awk 'NR>=171 && NR<=270' 'path'  (lines 171-270, overlap 15)\n"
    "     Each chunk advances 85 lines, overlapping 15 with the previous chunk.\n"
    "     NEVER skip lines between chunks — boundary content will be lost.\n"
    "     Continue until all lines relevant to the investigation are covered.\n"
    "\n"
    "   D) UNKNOWN BINARY FILES:\n"
    "     Step 1 — inspect the file header (magic bytes, structure):\n"
    "       xxd 'path' | head -n 32          (256 bytes in hex — identifica formato)\n"
    "     Step 2 — search for known keywords (most efficient for large binaries):\n"
    "       strings -n 8 'path' | grep -i 'keyword' | head -n 100\n"
    "     Step 3 — if no keyword, survey the first printable strings:\n"
    "       strings -n 8 'path' | head -n 100\n"
    "     Step 4 — if the binary is large and full strings output is needed:\n"
    "       strings -n 8 'path' > /exports/strings_out.txt\n"
    "       wc -l /exports/strings_out.txt\n"
    "       Then read /exports/strings_out.txt as a TEXT file (go to B)\n"
    "     NOTE: NEVER use dd or python-magic here — xxd + strings + file -b cover all cases.\n"
    "\n"
    "17. FILE NOT FOUND → VHD SEARCH:\n"
    "   If find returns no output for a specific filename — even after searching /forensics —\n"
    "   DO NOT repeat find with different paths or options. DO NOT use stat directly.\n"
    "   DO NOT check the Recycle Bin. DO NOT try ls or different partitions.\n"
    "   The file is inside a nested VHD/VMDK. Run this EXACT script immediately:\n"
    "     TARGET='filename.txt'\n"
    "     FILE=$(find '/forensics' -iname \"$TARGET\" -type f 2>/dev/null | head -1)\n"
    "     if [ -n \"$FILE\" ]; then\n"
    "       echo \"FOUND: $FILE\"; stat -c \"%s\" \"$FILE\"\n"
    "     else\n"
    "       echo 'Not in mounted partitions — searching VHD...'\n"
    "       VHD=$(find '{evidence}' \\( -iname '*.vhd' -o -iname '*.vmdk' \\) -type f 2>/dev/null | head -1)\n"
    "       echo \"VHD: $VHD\"\n"
    "       mmls \"$VHD\" 2>/dev/null | awk 'NR>5 && $2~/[0-9]/{{print $3}}' | while read start; do\n"
    "         offset=$(( 10#$start ))\n"
    "         result=$(fls -i vhd -r -o \"$offset\" \"$VHD\" 2>/dev/null | grep -i \"$TARGET\")\n"
    "         [ -n \"$result\" ] && echo \"FOUND in VHD offset=$offset: $result\"\n"
    "       done\n"
    "     fi\n"
    "   If FOUND in VHD — extract the file with icat:\n"
    "   CRITICAL: icat takes an INODE NUMBER, NOT a filename. The filename MUST NOT appear in the icat command.\n"
    "   WRONG: icat -i vhd -o $offset \"$VHD\" 12345 Card Printers.htm   ← filename after inode = ERROR\n"
    "   WRONG: icat -i vhd -o $offset \"$VHD\" 'Card Printers.htm'        ← filename instead of inode = ERROR\n"
    "   RIGHT workflow — two steps:\n"
    "     Step 1: get the inode number from fls output:\n"
    "       INODE=$(fls -i vhd -r -o $offset \"$VHD\" 2>/dev/null | grep -i 'Card Printers.htm' | awk '{{print $2}}' | tr -d ':')\n"
    "       echo \"Inode: $INODE\"   # verify it is a number, e.g. 12345\n"
    "     Step 2: extract using ONLY the inode number — NO filename argument:\n"
    "       icat -i vhd -o $offset \"$VHD\" \"$INODE\" > /exports/target_file\n"
    "       stat -c \"%s\" /exports/target_file\n"
    "   For SHA1/MD5 hash: sha1sum /exports/target_file | awk '{{print toupper($1)}}'\n"
    "\n"
    "19. WINDOWS APPLICATION LAST RUN TIME — use UserAssist in NTUSER.DAT, NOT Application.evtx.\n"
    "   Application.evtx is a BINARY file — grep/strings will NEVER find plain-text usernames or\n"
    "   timestamps inside it. NEVER run grep on .evtx files to find application usage.\n"
    "\n"
    "   The correct source is the UserAssist registry key in NTUSER.DAT:\n"
    "     Key: /Software/Microsoft/Windows/CurrentVersion/Explorer/UserAssist/<GUID>/Count\n"
    "     GUID {{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}} — direct executable launches\n"
    "     GUID {{F4E57C4B-2036-45F0-A9AB-443BCFE33D9F}} — shortcut/LNK launches\n"
    "   All entry names are ROT-13 encoded. Decode with: codecs.decode(name, 'rot13')\n"
    "   Examples: 'wlmail.exe' → ROT-13 → 'jyznvy.rkr'  |  'Windows Live Mail.lnk' → 'Jvaqbjf Yvir Znvy.yax'\n"
    "\n"
    "   CRITICAL — python3 -c \"...\" BREAKS for multi-line scripts. ALWAYS use heredoc:\n"
    "     WRONG: python3 -c \"import struct\\n...\"\n"
    "     RIGHT: python3 << 'PYEOF'\\n...\\nPYEOF\n"
    "\n"
    "   STEP 1a — Check whether python-registry is available:\n"
    "     python3 -c 'import Registry; print(\"Registry OK\")' 2>&1 || echo 'NOT AVAILABLE'\n"
    "\n"
    "   STEP 1b — If python-registry available, use heredoc (NEVER python3 -c for multi-line):\n"
    "     python3 << 'PYEOF'\n"
    "     import Registry.Registry as reg, struct, codecs\n"
    "     from datetime import datetime, timedelta, timezone\n"
    "     h = reg.Registry('{evidence}/USERS/<username>/NTUSER.DAT')\n"
    "     epoch = datetime(1601,1,1,tzinfo=timezone.utc)\n"
    "     for guid in ['{{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}}','{{F4E57C4B-2036-45F0-A9AB-443BCFE33D9F}}']:\n"
    "       try:\n"
    "         key = h.open('Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Explorer\\\\UserAssist\\\\'+guid+'\\\\Count')\n"
    "         for v in key.values():\n"
    "           name = codecs.decode(v.name(), 'rot13')\n"
    "           data = v.raw_data()\n"
    "           if len(data) >= 68:\n"
    "             ft = struct.unpack_from('<Q', data, 60)[0]\n"
    "             dt = epoch + timedelta(microseconds=ft//10) if ft else 'never'\n"
    "           else: dt = 'no timestamp'\n"
    "           print(guid[-8:], name, dt)\n"
    "       except Exception as e: print(guid[-8:], 'ERROR', e)\n"
    "     PYEOF\n"
    "\n"
    "   STEP 1c — If python-registry NOT available, use jump lists FILETIME scan (stdlib only):\n"
    "     python3 << 'PYEOF'\n"
    "     import struct, datetime, glob, os\n"
    "     epoch = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)\n"
    "     pattern = '{evidence}/USERS/*/AppData/Roaming/Microsoft/Windows/Recent/AutomaticDestinations/*.automaticDestinations-ms'\n"
    "     for jl in glob.glob(pattern):\n"
    "       with open(jl, 'rb') as f: raw = f.read()\n"
    "       appid = os.path.basename(jl).split('.')[0]\n"
    "       results = []\n"
    "       for i in range(0, len(raw) - 8, 4):\n"
    "         ft = struct.unpack_from('<Q', raw, i)[0]\n"
    "         if 0x01BF000000000000 < ft < 0x01D5000000000000:\n"
    "           results.append(epoch + datetime.timedelta(microseconds=ft // 10))\n"
    "       if results:\n"
    "         print(appid, max(results).strftime('%a, %d %B %Y %H:%M:%S UTC'))\n"
    "     PYEOF\n"
    "\n"
    "   STEP 2 — If no match in UserAssist, check LNK file access timestamps:\n"
    "     find '{evidence}/USERS/<username>/AppData/Roaming/Microsoft/Windows/Recent' \\\n"
    "       -iname '*<appname>*' -o -iname '*<appname>*.lnk' 2>/dev/null | \\\n"
    "       while read f; do python3 -c \"import os; s=os.stat('$f'); print(s.st_atime, '$f')\"; done\n"
    "   Or use python3 with lnkfile/LnkParse3 if available, otherwise stat atime.\n"
    "\n"
    "   STEP 3 — Alternative: check IAM or Mail account key timestamps (Windows Live Mail):\n"
    "     reglookup -p '/Software/Microsoft/IAM/Accounts/Active Directory GC' \\\n"
    "       '{evidence}/USERS/<username>/NTUSER.DAT'\n"
    "     The KEY timestamp shown by reglookup is the last modification = last active use.\n"
    "\n"
    "   NEVER search Application.evtx or any .evtx file for application last run time.\n"
    "   NEVER repeat a failing grep on a binary .evtx file — if a command returns empty, switch to UserAssist.\n"
    "\n"
    "FINAL REMINDER — LANGUAGE: Every word of your response must be in English.\n"
    "Do NOT use Portuguese, Spanish, or any other language, even if the user writes in one.\n"
)


def build_system_prompt(evidence: str, workdir: str = "", allow_network: bool = False) -> str:
    if not workdir:
        workdir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    prompt = _SYSTEM_PROMPT_TEMPLATE.format(evidence=evidence, workdir=workdir)
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
        print("[!] No recognisable partition found under /forensics/.")
        print("    Use --evidence para especificar o caminho manualmente.")
        sys.exit(1)
    return path


# ─── Interface chatbot ────────────────────────────────────────────────────────

BANNER = """
╔══════════════════════════════════════════════════════════╗
║                AIAgent@forensics v1.0                    ║
║             Polytechnic of Leiria - ESTG                 ║
║  LLM Agent for Digital Forensic Investigation (ReAct)    ║
╠══════════════════════════════════════════════════════════╣
║  Special commands:                                       ║
║    /exit            -> terminates the program            ║
║    /clear           -> clears conversation history       ║
║    /structure       -> shows what is mounted             ║
║    /clear_rag       -> clears indexed RAG documents      ║
╚══════════════════════════════════════════════════════════╝
"""


_default_evidence_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "evidence"))


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="AIAgent@forensics — LLM agent for forensic investigation")
    parser.add_argument("--model",    default=os.getenv("OLLAMA_MODEL", "gemma4:26b"),
                        help="Ollama model (default: llama3.2:9b)")
    parser.add_argument("--url",      default=os.getenv("OLLAMA_URL", "http://localhost:11434"),
                        help="Ollama server URL (default: http://localhost:11434)")
    parser.add_argument("--ctx",      type=int,   default=32768,
                        help="Context size in tokens (default: 32768)")
    parser.add_argument("--temp",     type=float, default=0.3,
                        help="Model temperature (default: 0.3)")
    parser.add_argument("--evidence", default=None,
                        help="Forensic partition directory (default: auto-detected)")
    parser.add_argument("--dir", default=_default_evidence_dir,
                        help=f"Host directory containing the forensic image (default: {_default_evidence_dir})")
    parser.add_argument("--think", action="store_true", default=True,
                        help="Enable model reasoning mode (reasoning=True)")
    parser.add_argument("--debug", action="store_true", default=False,
                        help="Show raw AIMessage fields for inspection")
    parser.add_argument("--no-clear-rag", dest="clear_rag", action="store_false",
                        help="Keep RAG documents indexed from previous sessions")
    parser.set_defaults(clear_rag=True)
    parser.add_argument("--no-mount", dest="no_mount", action="store_true", default=False,
                        help="Mount the evidence directory directly at /forensics (no E01/DD image)")
    parser.add_argument("--allow-network", dest="allow_network", action="store_true", default=False,
                        help="Enable internet access in the container (for sudo apt-get install)")
    parser.add_argument("--clear-after-question", dest="limpar_apos_pergunta", action="store_true", default=False,
                        help="Clear context automatically after each question (test mode with clean context)")
    return parser.parse_args()


def get_model_context(base_url: str, model: str, fallback: int = 32768) -> int:
    """Query Ollama /api/show to get the model's actual native context window size."""
    try:
        req = urllib.request.Request(
            f"{base_url}/api/show",
            data=json.dumps({"model": model}).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            info = json.loads(resp.read())
        model_info = info.get("model_info", {})
        for key in ("llama.context_length", "general.context_length", "context_length"):
            if key in model_info:
                return int(model_info[key])
        params = info.get("parameters", "")
        for line in params.splitlines():
            if line.strip().startswith("num_ctx"):
                return int(line.split()[-1])
    except Exception:
        pass
    return fallback


def _url_reachable(url: str, timeout: int = 3) -> bool:
    try:
        urllib.request.urlopen(f"{url}/api/tags", timeout=timeout)
        return True
    except Exception:
        return False


def main():
    args = parse_args()

    # Se o URL configurado não responder, cai para o Ollama direto (mitmweb opcional)
    if args.url != "http://localhost:11434" and not _url_reachable(args.url):
        print(f"[!] {args.url} inacessível — a usar http://localhost:11434 diretamente")
        args.url = "http://localhost:11434"

    # Register cleanup function only when main program runs
    atexit.register(stop_container)

    print(BANNER)
    print(f"[*] Model    : {args.model} via {args.url}")
    print(f"[*] Context  : {args.ctx} tokens | Temperature: {args.temp}")
    sys.modules["agent.tools"].FORENSICS_IMAGE_PATH = os.path.abspath(args.dir)
    print(f"[*] Image dir: {sys.modules['agent.tools'].FORENSICS_IMAGE_PATH}")
    start_container(no_mount=args.no_mount, allow_network=args.allow_network)

    if args.evidence:
        check = run_in_sandbox(f"test -d '{args.evidence}' && echo ok")
        if check.strip() == "ok":
            evidence = args.evidence
            print(f"[*] Evidence : {evidence} (manual)")
        else:
            print(f"[!] Partition '{args.evidence}' not found. Using auto-detection...")
            evidence = auto_detect_evidence()
            print(f"[*] Evidence : {evidence} (auto-detected)")
    else:
        evidence = auto_detect_evidence()
        print(f"[*] Evidence : {evidence} (auto-detected)")

    global _evidence_path, _skills_cache
    _evidence_path = evidence
    _skills_cache = load_skills()
    print(f"[*] Skills loaded: {len(_skills_cache)} ({', '.join(s.name for s in _skills_cache)})")

    from rag.indexer import clear_collection, list_indexed_documents
    indexed = list_indexed_documents()
    if args.clear_rag and indexed:
        n = clear_collection()
        print(f"[*] RAG: collection cleared ({n} chunks removed). Use --no-clear-rag to keep.")
    elif indexed:
        print(f"[*] RAG: {len(indexed)} document(s) indexed: {', '.join(indexed)}")
    else:
        print("[*] RAG: empty collection.")

    llm = ChatOllama(
        model=args.model,
        base_url=args.url,
        temperature=args.temp,
        num_ctx=args.ctx,
        keep_alive=-1,
        reasoning=True,  # Always enabled for better user experience
    )
    effective_ctx = get_model_context(args.url, args.model, fallback=args.ctx)
    if effective_ctx != args.ctx:
        print(f"[*] Native ctx : {effective_ctx} tokens (configured: {args.ctx} — Ollama uses native context)")
    agent = create_agent(model=llm, tools=TOOLS)

    system_prompt = build_system_prompt(evidence, workdir=os.getcwd(), allow_network=args.allow_network)
    conversation = [SystemMessage(content=system_prompt)]

    while True:
        try:
            user_input = input("You: ").strip()
        except KeyboardInterrupt:
            print("\n[*] Cancelled. Use /exit to quit.")
            continue
        except EOFError:
            print("\n[*] Shutting down...")
            break

        if not user_input:
            continue
        if user_input.lower() in ("/exit", "/quit"):
            print("[*] Goodbye!")
            break
        if user_input.lower() == "/clear":
            conversation = [SystemMessage(content=system_prompt)]
            print("[*] Conversation history cleared.\n")
            continue
        if user_input.lower() == "/structure":
            print("\n[Mounted structure]\n" + run_in_sandbox("find /forensics -maxdepth 3 -type d"))
            continue
        if user_input.lower() == "/clear_rag":
            from rag.indexer import clear_collection
            n = clear_collection()
            print(f"[*] RAG: collection cleared ({n} chunks removed).\n")
            continue

        conversation[0] = SystemMessage(content=system_prompt)
        # Detect non-English input and prepend a language reminder
        _ascii_ratio = sum(c.isascii() for c in user_input) / max(len(user_input), 1)
        _looks_non_english = _ascii_ratio < 0.95 or any(
            w in user_input.lower() for w in ("quantos", "quais", "onde", "como", "quando", "porque", "qual")
        )
        _msg_content = (
            "[REMINDER: Reply in English only]\n" + user_input
            if _looks_non_english else user_input
        )
        conversation.append(HumanMessage(content=_msg_content))

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

        last_prompt_eval = 0
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

                                meta = getattr(msg, "response_metadata", {}) or {}
                                pec = meta.get("prompt_eval_count", 0)
                                if pec:
                                    last_prompt_eval = pec

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
                    print(f"{color}\n[Context: {u['input_tokens']} in + {u['output_tokens']} out = {u['total_tokens']}/{args.ctx} tokens ({pct}%)]{reset}")

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
                        reason = f"Context at {round(last_usage['total_tokens']/args.ctx*100)}%"
                        print(f"\n[*] {reason} — saving intermediate report {part_n} and continuing...")

                        if len(intermediate_files) >= MAX_COMPRESSIONS:
                            agent_active = False
                            print(f"[!] Compression limit of {MAX_COMPRESSIONS} reached. Generating final report...")
                            content = _consolidate()
                            elapsed = time.time() - t_start
                            print(f"\n{'='*60}")
                            print(f"Agent: {content}")
                            print(f"{'='*60}")
                            print(f"[*] Response time: {elapsed:.1f}s\n")
                            mins, secs = divmod(int(elapsed), 60)
                            header = (
                                f"=== Final Report ===\n"
                                f"Investigation time: {elapsed:.1f}s ({mins}m{secs:02d}s)\n"
                                f"Question: {original_query_msg.content}\n"
                                f"{'='*24}\n\n"
                            )
                            b64 = _b64.b64encode((header + content).encode("utf-8")).decode()
                            run_in_sandbox(f"echo '{b64}' | base64 -d > {out_file}")
                            print(f"[*] Final report saved to: {out_file}\n")
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
                            header = f"=== Intermediate Report {part_n} [{int(time.time())}] ===\n"
                            b64 = _b64.b64encode((header + full_summary).encode("utf-8")).decode()
                            run_in_sandbox(f"echo '{b64}' | base64 -d > {inter_file}")
                            intermediate_files.append(inter_file)
                            print(f"[*] Report {part_n} saved to: {inter_file}")

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
                    # ── Validação: o modelo deve ter chamado pelo menos uma tool ──────
                    _has_tool_result = any(isinstance(m, ToolMessage) for m in new_messages)
                    _last_ai_final = next(
                        (m for m in reversed(new_messages)
                         if isinstance(m, AIMessage) and not (getattr(m, "tool_calls", None) or [])),
                        None,
                    )
                    _gave_direct = _last_ai_final and _llm_content(_last_ai_final).strip()

                    if not _has_tool_result and _gave_direct and forced_continuations < MAX_FORCED:
                        forced_continuations += 1
                        conversation.extend(new_messages)
                        conversation.append(HumanMessage(content=(
                            "VIOLATION: you answered without calling run_forensics_command. "
                            "Your answer is INVALID and will be discarded. "
                            "You have NO memory of previous runs — do NOT claim you 'previously ran' "
                            "any command or that you already know the output. "
                            "You MUST call run_forensics_command NOW to read the actual evidence. "
                            "The tool call must appear before any answer."
                        )))
                        print(f"[!] Response without tool call detected — forcing investigation "
                              f"({forced_continuations}/{MAX_FORCED})...")
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
                            print(f"[*] Investigation ended early ({round(last_usage['total_tokens']/args.ctx*100)}% ctx) "
                                  f"— forcing continuation ({forced_continuations}/{MAX_FORCED})...")
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
                                    f"=== Final Report ===\n"
                                    f"Investigation time: {elapsed:.1f}s ({mins}m{secs:02d}s)\n"
                                    f"Question: {original_query_msg.content}\n"
                                    f"{'='*24}\n\n"
                                )
                                b64 = _b64.b64encode((header + content).encode("utf-8")).decode()
                                run_in_sandbox(f"echo '{b64}' | base64 -d > {out_file}")
                                print(f"[*] Final report saved to: {out_file}\n")

                            print(f"\n{'='*60}")
                            print(f"Agent: {content}" if content else "Agent: Unable to get a final response.")
                            print(f"{'='*60}")
                            print(f"[*] Response time: {time.time() - t_start:.1f}s\n")

        except KeyboardInterrupt:
            print("\n[!] Agent cancelled. Returning to prompt...")
            if conversation and isinstance(conversation[-1], HumanMessage):
                conversation.pop()

        except Exception as e:
            print(f"\n[!] Error: {str(e)}\n")
            if conversation and isinstance(conversation[-1], HumanMessage):
                conversation.pop()

        # Cross-question context overflow detection (interactive mode)
        if not args.limpar_apos_pergunta and last_prompt_eval > 0:
            ctx_pct = last_prompt_eval / effective_ctx * 100
            if ctx_pct >= 95:
                print(f"\n{'─'*60}")
                print(f"⚠️  Context window is {ctx_pct:.0f}% full ({last_prompt_eval:,}/{effective_ctx:,} tokens).")
                print("    Auto-compressing conversation history to free up context...")
                try:
                    sum_resp = llm.invoke(conversation + [HumanMessage(content=(
                        "Summarize ALL forensic findings from this investigation in 10-15 bullet points. "
                        "Include: users found, key file paths and their content, registry findings, "
                        "timestamps, suspicious items, and confirmed conclusions. "
                        "Be specific — include exact values, paths, and dates. "
                        "Do NOT call any tools. Do NOT include code blocks."
                    ))])
                    summary = _llm_content(sum_resp)
                except Exception:
                    summary = "(Auto-summary failed — key findings visible in conversation above.)"
                conversation[:] = [
                    conversation[0],
                    AIMessage(content=f"[Conversation compressed — summary of prior investigation:]\n\n{summary}"),
                ]
                print("[*] Conversation history compressed. Context freed.")
                print("    Type /clear to fully reset the conversation if responses seem degraded.")
                print(f"{'─'*60}\n")
            elif ctx_pct >= 75:
                print(f"\n⚠️  Context window is {ctx_pct:.0f}% full "
                      f"({last_prompt_eval:,}/{effective_ctx:,} tokens). "
                      f"Type /clear to start a new conversation and avoid degraded responses.")

        # Limpar contexto após pergunta se flag ativada
        if args.limpar_apos_pergunta:
            conversation = [SystemMessage(content=system_prompt)]
            print("[*] Context cleared after response.\n")


if __name__ == "__main__":
    main()
