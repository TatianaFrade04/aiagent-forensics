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
    "\n"
    "TOOL: run_forensics_command(command) — run any bash command inside the forensic container\n"
    "\n"
    "RULES:\n"
    "1. Use run_forensics_command to execute bash commands in the forensic container\n"
    "   whenever you need to inspect the filesystem, search files, or run any shell operation.\n"
    "   Do NOT ask for clarification before running a command — just run it.\n"
    "2. NEVER invent or hallucinate results — only report what the tool returns.\n"
    "3. Paths with spaces MUST use single quotes:\n"
    "     ls '/forensics/part006/USERS/Jimmy Wilson/Desktop'\n"
    "4. /forensics is READ-ONLY. NEVER redirect or write there.\n"
    "5. NEVER use: rm, mv, dd, shred, find -delete, sed -i.\n"
    "6. To save output to a file: command > /exports/file.txt\n"
    "   Then verify with: ls -lh /exports/file.txt\n"
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
    for m in reversed(candidates):
        try:
            obj = json.loads(m)
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

        conversation.append(HumanMessage(content=user_input))

        print()
        try:
            for iteration in range(MAX_ITERATIONS):
                response = llm.invoke(conversation)
                conversation.append(response)

                tool_calls = _extract_tool_calls(response)
                content = _render_message_text(response)

                # Debug: output em bruto
                print(f"\n{'─'*60}")
                print(f"[RAW AGENT OUTPUT — iteração {iteration + 1}]")
                print(f"  [{response.__class__.__name__}] content={content!r}")
                if tool_calls:
                    for tc in tool_calls:
                        print(f"    tool_call: {tc}")
                print(f"{'─'*60}")

                if not tool_calls:
                    print(f"\n{'='*60}")
                    print(f"Agente: {content}")
                    print(f"{'='*60}\n")
                    break

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

        except Exception as e:
            print(f"\n[!] Erro: {str(e)}\n")
            # Remove a HumanMessage que causou o erro
            if conversation and isinstance(conversation[-1], HumanMessage):
                conversation.pop()


if __name__ == "__main__":
    main()