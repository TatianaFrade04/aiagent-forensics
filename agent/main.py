"""
main.py — AIAgent@forensics
Agente LLM com paradigma ReAct para investigação forense digital.
Politécnico de Leiria — ESTG | Licenciatura em Engenharia Informática
"""

import atexit
import json
import os
from typing import Any

from dotenv import load_dotenv

from langchain_ollama import ChatOllama
from langchain_core.tools import tool
from langchain_core.messages import HumanMessage, SystemMessage, ToolMessage

from tools import run_in_sandbox, stop_container, start_container
from skills import load_skills, select_skills, format_skills_context

# ─── Configuração ─────────────────────────────────────────────────────────────

load_dotenv()

OLLAMA_MODEL   = os.getenv("OLLAMA_MODEL",   "qwen2.5:7b")
OLLAMA_URL     = os.getenv("OLLAMA_URL",     "http://localhost:11434")
MAX_ITERATIONS = int(os.getenv("MAX_ITERATIONS", "15"))

atexit.register(stop_container)

# ─── Ferramenta exposta ao agente ─────────────────────────────────────────────

@tool
def run_forensics_command(command: str) -> str:
    """
    Run any bash command inside the forensic Linux container and get back stdout and stderr.

    FILESYSTEM LAYOUT:
      /forensics/part006/  - Windows NTFS partition (READ-ONLY evidence)
      /exports/            - writable directory for saving output files

    EXAMPLES:
      ls -la /forensics/part006/USERS
      find /forensics/part006 -name "*.pdf"
      grep -ri "keyword" /forensics/part006/USERS/
      cat '/forensics/part006/USERS/Jimmy Wilson/Documents/file.txt'
      cat '/forensics/part006/USERS/Jimmy Wilson/Documents/file.txt' > /exports/file.txt

    NOTES:
      - Paths with spaces MUST use single quotes
      - /forensics is READ-ONLY — never redirect or write there
    """
    return run_in_sandbox(command)


TOOLS = {run_forensics_command.name: run_forensics_command}

# ─── Modelo LLM ───────────────────────────────────────────────────────────────

llm = ChatOllama(
    model=OLLAMA_MODEL,
    base_url=OLLAMA_URL,
    temperature=0.3,
    num_ctx=32768,
).bind_tools(list(TOOLS.values()))

# ─── System prompt ────────────────────────────────────────────────────────────

SYSTEM_PROMPT = (
    "You are a digital forensics expert agent operating in READ-ONLY forensic mode.\n"
    "Always respond in English, regardless of the language of the user's message.\n"
    "\n"
    "FILESYSTEM LAYOUT:\n"
    "  /forensics/part006/ — Windows NTFS partition (READ-ONLY evidence)\n"
    "  /exports/           — the ONLY writable directory\n"
    "  NOTE: Windows directory names (Windows, System32, etc.) are case-sensitive\n"
    "  when mounted on Linux. ALWAYS use find with -iname to discover exact paths\n"
    "  before passing them to forensic tools. Never assume casing.\n"
    "\n"
    "REGISTRY HIVES — Windows registry hive files have NO file extension.\n"
    "  The hive files are named: SOFTWARE, SYSTEM, SAM, SECURITY, NTUSER.DAT\n"
    "  Main hives location: /forensics/part006/Windows/System32/config/\n"
    "  Per-user hive:        /forensics/part006/USERS/<username>/NTUSER.DAT\n"
    "  NEVER search for *.reg or *.hive — those are not hive files.\n"
    "  ALWAYS resolve hive paths with find in the SAME command string:\n"
    "    HIVE=$(find '/forensics/part006' -iname 'SOFTWARE' -not -path '*/Users/*'\n"
    "      -not -path '*/RegBack/*' 2>/dev/null | head -1); reglookup -p '/...' \"$HIVE\"\n"
    "  NEVER use bare shell variables like $SOFTWARE_HIVE or $SYSTEM_HIVE — they are\n"
    "  not defined and will always cause 'No such file or directory' errors.\n"
    "  To find the Windows version: reglookup -p '/Microsoft/Windows NT/CurrentVersion'\n"
    "  on the SOFTWARE hive.\n"
    "\n"
    "TOOL: run_forensics_command(command) — run any bash command inside the forensic container\n"
    "\n"
    "RULES:\n"
    "1. ALWAYS call run_forensics_command immediately — never write commands as text.\n"
    "   WRONG: writing ```bash command``` in your reply without a tool call.\n"
    "   WRONG: saying 'I will run ...' or 'Let me execute ...' without calling the tool.\n"
    "   WRONG: emitting JSON like {\"name\": \"run_forensics_command\", ...} in text.\n"
    "   RIGHT: call run_forensics_command(command) as your very first action, with no preamble.\n"
    "   Your response must contain ONLY a tool call — zero words of introduction or explanation.\n"
    "   Do NOT announce what you are about to do. Do NOT ask for clarification. Just call the tool.\n"
    "2. NEVER invent or hallucinate results — only report what the tool returns.\n"
    "3. CRITICAL — EVERY path under /forensics/ MUST be wrapped in single quotes. No exceptions.\n"
    "   WRONG: stat /forensics/part006/USERS/Jimmy Wilson/file.txt\n"
    "   WRONG: stat /forensics/part006/USERS/Jimmy\\ Wilson/file.txt\n"
    "   RIGHT: stat '/forensics/part006/USERS/Jimmy Wilson/file.txt'\n"
    "   RIGHT: find '/forensics/part006' -name '*.pdf'\n"
    "   RIGHT: exiftool '/forensics/part006/USERS/Jimmy Wilson/Documents/photo.jpg'\n"
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
    "   NEVER modify, rewrite, or prefix it with /forensics/part006/.\n"
    "   WRONG (user said 'cat /etc/hosts'): cat '/forensics/part006/etc/hosts'\n"
    "   RIGHT: cat /etc/hosts\n"
    "11. To list Windows users on the evidence image, ALWAYS use:\n"
    "   find '/forensics/part006/USERS' -mindepth 1 -maxdepth 1 -type d\n"
    "   NEVER use registry hives (SAM, regripper, reglookup) for this operation.\n"
)

# ─── Helpers para extracção de tool calls ─────────────────────────────────────

def _render_message_text(message: Any) -> str:
    content = getattr(message, "content", "")
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for block in content:
            if isinstance(block, str):
                parts.append(block)
            elif isinstance(block, dict) and block.get("type") == "text":
                parts.append(block.get("text", ""))
        return "\n".join(parts)
    return str(content)


def _extract_json_object(text: str) -> dict | None:
    """Tenta extrair um objecto JSON do texto (fallback para modelos sem tool calling nativo)."""
    candidates = []
    for i, ch in enumerate(text):
        if ch == "{":
            depth = 0
            for j, c in enumerate(text[i:], i):
                if c == "{":
                    depth += 1
                elif c == "}":
                    depth -= 1
                    if depth == 0:
                        candidates.append(text[i:j+1])
                        break
    for m in sorted(candidates, key=len, reverse=True):
        try:
            obj = json.loads(m.replace("\\'", "'"))
            if isinstance(obj, dict):
                return obj
        except json.JSONDecodeError:
            pass
    return None


def _extract_tool_calls(message: Any) -> list[dict]:
    """Extrai tool calls da mensagem — tenta structured primeiro, depois fallback JSON."""
    structured = getattr(message, "tool_calls", None)
    if structured:
        return list(structured)
    # Fallback: o modelo escreveu JSON em texto
    payload = _extract_json_object(_render_message_text(message))
    if not payload:
        return []
    name = payload.get("name")
    arguments = payload.get("arguments", {})
    if isinstance(name, str) and isinstance(arguments, dict):
        return [{"id": "text-tool-call", "name": name, "args": arguments}]
    return []

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

def cmd_estrutura():
    result = run_in_sandbox("find /forensics -maxdepth 3 -type d")
    print("\n[Estrutura montada]\n" + result)


def main():
    print(BANNER)
    print(f"[*] Modelo: {OLLAMA_MODEL} via {OLLAMA_URL}")
    start_container()

    # Carregar skills forenses
    all_skills = load_skills()
    print(f"[*] Skills carregadas: {len(all_skills)} ({', '.join(s.name for s in all_skills)})")

    conversation = [SystemMessage(content=SYSTEM_PROMPT)]

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
            conversation = [SystemMessage(content=SYSTEM_PROMPT)]
            print("[*] Historico limpo.\n")
            continue

        if user_input.lower() == "estrutura":
            cmd_estrutura()
            continue

        # Selecionar skills relevantes
        selected = select_skills(user_input, all_skills)
        skills_context = format_skills_context(selected)
        if selected:
            print(f"[*] Skills selecionadas: {', '.join(s.name for s in selected)}")

        # Injetar skills no system prompt (posição 0)
        if skills_context:
            conversation[0] = SystemMessage(
                content=SYSTEM_PROMPT
                + "\nThe following commands are installed and available in the container:\n"
                + skills_context + "\n"
            )
        else:
            conversation[0] = SystemMessage(content=SYSTEM_PROMPT)

        conversation.append(HumanMessage(content=user_input))

        print()
        try:
            last_tool_command = None  # loop detection per turn
            for iteration in range(MAX_ITERATIONS):
                response = llm.invoke(conversation)

                tool_calls = _extract_tool_calls(response)
                content = _render_message_text(response)

                # Se resposta vazia (sem tool calls nem texto), não poluir a conversa
                if not tool_calls and not content.strip():
                    print(f"\n{'─'*60}")
                    print(f"[AVISO — iteração {iteration + 1}: resposta vazia, a tentar de novo]")
                    print(f"{'─'*60}")
                    if iteration < 2:
                        # Nudge: relembrar o modelo do workflow correcto
                        conversation.append(HumanMessage(
                            content=(
                                "Your previous response was empty. You must call run_forensics_command to answer the question.\n"
                                "IMPORTANT: Do NOT guess file paths. Before running any forensic tool, "
                                "always discover the exact path first using find, for example:\n"
                                "  find /forensics/part006 -iname 'SOFTWARE' -not -path '*/Users/*' 2>/dev/null | head -3\n"
                                "Then use the exact path returned by find in your next command."
                            )
                        ))
                        continue
                    # Remover HumanMessages adicionadas (nudges + mensagem original)
                    while len(conversation) > 1 and isinstance(conversation[-1], HumanMessage):
                        conversation.pop()
                    print(f"\n{'='*60}")
                    print("Agente: Não foi possível obter resposta do modelo após várias tentativas. Reformule a pergunta ou verifique se o modelo está a funcionar correctamente.")
                    print(f"{'='*60}\n")
                    break

                conversation.append(response)

                # Debug: output em bruto
                print(f"\n{'─'*60}")
                print(f"[RAW AGENT OUTPUT — iteração {iteration + 1}]")
                print(f"  [{response.__class__.__name__}] content={content!r}")
                if tool_calls:
                    for tc in tool_calls:
                        print(f"    tool_call: {tc}")
                print(f"{'─'*60}")

                if not tool_calls:
                    # Nudge: model wrote text but no tool call, and no tool was used yet this turn
                    last_human_idx = max(
                        (i for i, m in enumerate(conversation) if isinstance(m, HumanMessage)),
                        default=0,
                    )
                    tool_used_this_turn = any(
                        isinstance(m, ToolMessage) for m in conversation[last_human_idx:]
                    )
                    if not tool_used_this_turn and iteration < 2:
                        print(f"\n{'─'*60}")
                        print(f"[AVISO — iteração {iteration + 1}: modelo descreveu comando sem executar, a forçar tool call]")
                        print(f"{'─'*60}")
                        conversation.append(HumanMessage(
                            content=(
                                "You wrote a command in your text response but did NOT call run_forensics_command. "
                                "Writing bash or JSON in text is NOT execution. "
                                "You MUST call run_forensics_command now with the exact command. "
                                "Do not write any text — just call the tool immediately."
                            )
                        ))
                        continue
                    print(f"\n{'='*60}")
                    print(f"Agente: {content}")
                    print(f"{'='*60}\n")
                    break

                loop_detected = False
                for tool_call in tool_calls:
                    tool_name = tool_call.get("name", "")
                    tool_args = tool_call.get("args", {})
                    tool_id   = tool_call.get("id", "tool-call")

                    if tool_name not in TOOLS:
                        tool_output = f"Erro: ferramenta desconhecida '{tool_name}'"
                    else:
                        tool_output = TOOLS[tool_name].invoke(tool_args)

                    print(f"  [ToolMessage] {tool_name}({tool_args}) => {tool_output[:200]!r}{'...' if len(tool_output) > 200 else ''}")

                    conversation.append(ToolMessage(
                        content=json.dumps({"result": tool_output}),
                        tool_call_id=tool_id,
                    ))

                    # Loop detection: same command repeated → inject break-out nudge
                    cmd = tool_args.get("command", "")
                    if cmd and cmd == last_tool_command:
                        loop_detected = True
                        print(f"\n{'─'*60}")
                        print(f"[AVISO — iteração {iteration + 1}: loop detectado, mesmo comando repetido]")
                        print(f"{'─'*60}")
                        conversation.append(HumanMessage(
                            content=(
                                "STOP — you just repeated the exact same command and got the same result. "
                                "Do NOT call this command again.\n"
                                "If a previous find/ls command already returned a list of file paths saved in a temp file, "
                                "those paths ARE the answer. Use 'head -100 <tempfile>' to read them and report to the user.\n"
                                "Do NOT grep for date strings inside a list of file paths — dates are not in the paths.\n"
                                "Try a completely different approach or report the results you already have."
                            )
                        ))
                        break
                    last_tool_command = cmd or last_tool_command

                if loop_detected:
                    continue

        except Exception as e:
            print(f"\n[!] Erro: {str(e)}\n")
            # Remove a HumanMessage que causou o erro
            if conversation and isinstance(conversation[-1], HumanMessage):
                conversation.pop()


if __name__ == "__main__":
    main()