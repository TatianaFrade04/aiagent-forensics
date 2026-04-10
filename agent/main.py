"""
main.py — AIAgent@forensics
Agente LLM com paradigma ReAct para investigação forense digital.
Politécnico de Leiria — ESTG | Licenciatura em Engenharia Informática
"""

import argparse
import atexit
import os
import sys

from dotenv import load_dotenv

from langchain_ollama import ChatOllama
from langchain_core.tools import tool
from langchain_core.messages import AIMessage, HumanMessage, SystemMessage, ToolMessage

from langchain.agents import create_agent

from tools import run_in_sandbox, stop_container, start_container
from skills import load_skills, select_skills, format_skills_context

load_dotenv()

atexit.register(stop_container)

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


TOOLS = [run_forensics_command]

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
    "   WRONG: stat {evidence}/USERS/Jimmy Wilson/file.txt\n"
    "   WRONG: stat {evidence}/USERS/Jimmy\\ Wilson/file.txt\n"
    "   RIGHT: stat '{evidence}/USERS/Jimmy Wilson/file.txt'\n"
    "   RIGHT: find '{evidence}' -name '*.pdf'\n"
    "   RIGHT: exiftool '{evidence}/USERS/Jimmy Wilson/Documents/photo.jpg'\n"
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
    if not path:
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
    return parser.parse_args()


def main():
    args = parse_args()

    print(BANNER)
    print(f"[*] Modelo   : {args.model} via {args.url}")
    print(f"[*] Contexto : {args.ctx} tokens | Temperatura: {args.temp}")
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
    )
    agent = create_agent(model=llm, tools=TOOLS)

    system_prompt = build_system_prompt(evidence)
    conversation = [SystemMessage(content=system_prompt)]

    while True:
        try:
            user_input = input("Tu: ").strip()
        except (KeyboardInterrupt, EOFError):
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
        try:
            result = agent.invoke(
                {"messages": conversation},
                {"recursion_limit": args.max_iter * 3},
            )

            prev_len = len(conversation)
            conversation = list(result["messages"])
            new_messages = conversation[prev_len:]

            # Debug: intermediate steps
            tool_call_map = {}
            for msg in new_messages:
                if isinstance(msg, AIMessage):
                    for tc in (getattr(msg, "tool_calls", None) or []):
                        tool_call_map[tc["id"]] = tc

            for msg in new_messages:
                print(f"\n{'─'*60}")
                if isinstance(msg, AIMessage):
                    content = msg.content if isinstance(msg.content, str) else ""
                    tool_calls = getattr(msg, "tool_calls", None) or []
                    print(f"  [AIMessage] content={content!r}")
                    for tc in tool_calls:
                        print(f"    tool_call: {tc}")
                elif isinstance(msg, ToolMessage):
                    tc_info = tool_call_map.get(msg.tool_call_id, {})
                    tool_name = tc_info.get("name", "?")
                    tool_args = tc_info.get("args", {})
                    out = msg.content[:200] if isinstance(msg.content, str) else str(msg.content)[:200]
                    ellipsis = "..." if isinstance(msg.content, str) and len(msg.content) > 200 else ""
                    print(f"  [ToolMessage] {tool_name}({tool_args}) => {out!r}{ellipsis}")
                print(f"{'─'*60}")

            # Token usage
            last_ai = next((m for m in reversed(new_messages) if isinstance(m, AIMessage)), None)
            if last_ai and getattr(last_ai, "usage_metadata", None):
                u = last_ai.usage_metadata
                pct = round(u["total_tokens"] / args.ctx * 100)
                print(f"[Contexto: {u['input_tokens']} in + {u['output_tokens']} out = {u['total_tokens']}/{args.ctx} tokens ({pct}%)]")

            # Final answer — last AIMessage without tool calls
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

        except Exception as e:
            from langgraph.errors import GraphRecursionError
            if isinstance(e, GraphRecursionError):
                # Limit reached — show last partial answer if available
                partial = next(
                    (m for m in reversed(conversation)
                     if isinstance(m, AIMessage) and m.content
                     and not (getattr(m, "tool_calls", None) or [])),
                    None,
                )
                print(f"\n[!] Limite de {args.max_iter} iteracoes atingido.")
                if partial:
                    content = partial.content if isinstance(partial.content, str) else str(partial.content)
                    print(f"\n{'='*60}")
                    print(f"Agente (parcial): {content}")
                    print(f"{'='*60}\n")
                else:
                    print("    Sem resposta parcial disponivel. Tente uma pergunta mais especifica.\n")
            else:
                print(f"\n[!] Erro: {str(e)}\n")
                if conversation and isinstance(conversation[-1], HumanMessage):
                    conversation.pop()


if __name__ == "__main__":
    main()
