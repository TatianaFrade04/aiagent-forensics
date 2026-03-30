"""
main.py — AIAgent@forensics
Agente LLM com paradigma ReAct para investigação forense digital.
Politécnico de Leiria — ESTG | Licenciatura em Engenharia Informática
"""

import atexit
import json
import os
import re
from typing import Any

from dotenv import load_dotenv

from langchain_ollama import ChatOllama
from langchain_core.messages import HumanMessage, SystemMessage, ToolMessage

from tools import run_in_sandbox, stop_container, start_container, bash

# ─── Configuração ─────────────────────────────────────────────────────────────

load_dotenv()

OLLAMA_MODEL   = os.getenv("OLLAMA_MODEL",   "llama3.1:8b")
OLLAMA_URL     = os.getenv("OLLAMA_URL",     "http://localhost:11434")

atexit.register(stop_container)

SYSTEM_PROMPT = (
    "You are a digital forensics expert agent operating in READ-ONLY forensic mode.\n"
    "\n"
    "FILESYSTEM LAYOUT:\n"
    "  /forensics/part006/ — Windows NTFS partition (READ-ONLY evidence)\n"
    "  /exports/           — the ONLY writable directory\n"
    "\n"
    "TOOL: bash(command) — run any bash command inside the forensic container\n"
    "\n"
    "RULES:\n"
    "1. When asked to run a command, ALWAYS call bash immediately with that exact command.\n"
    "   NEVER ask for clarification. NEVER refuse. Just run it and show the output.\n"
    "2. After receiving an Observation with the tool result, write your final answer.\n"
    "   Do NOT call bash again — the Observation IS the result.\n"
    "3. NEVER invent or hallucinate results — only report what the tool returns.\n"
    "4. Paths with spaces MUST use single quotes:\n"
    "     ls '/forensics/part006/USERS/Jimmy Wilson/Desktop'\n"
    "5. /forensics is READ-ONLY. NEVER redirect or write there.\n"
    "6. NEVER use: rm, mv, dd, shred, find -delete, sed -i.\n"
    "7. To save output to a file: command > /exports/file.txt\n"
    "   Then verify with: ls -lh /exports/file.txt\n"
    "\n"
    "OUTPUT FORMAT:\n"
    "When presenting tool results, always respond exactly like this:\n"
    "\n"
    "Ok, running the command.\n"
    "\n"
    "Here is the output:\n"
    "\n"
    "```\n"
    "<exact stdout here, unmodified>\n"
    "```\n"
    "\n"
    "If there is stderr, show it in a separate block labeled 'stderr:'.\n"
    "NEVER summarize, interpret, truncate, or paraphrase the output.\n"
    "NEVER replace output with a description.\n"
    "Only explain if the user explicitly asks.\n"
)

# ─── Modelo LLM ───────────────────────────────────────────────────────────────

llm = ChatOllama(
    model=OLLAMA_MODEL,
    base_url=OLLAMA_URL,
    temperature=0.5,
    num_ctx=8192,
).bind_tools([bash])

TOOLS: dict[str, Any] = {bash.name: bash}

# ─── Parsing de tool calls (3-tier fallback) ──────────────────────────────────

def _render_message_text(message: object) -> str:
    text = getattr(message, "text", "")
    if isinstance(text, str) and text:
        return text
    content = getattr(message, "content", "")
    if isinstance(content, str):
        return content
    return str(content)


def _extract_json_object(text: str) -> dict[str, Any] | None:
    text = text.strip()
    if not text:
        return None
    candidates = [text]
    fenced_match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
    if fenced_match:
        candidates.append(fenced_match.group(1))
    start = text.find("{")
    end = text.rfind("}")
    if start != -1 and end != -1 and start < end:
        candidates.append(text[start : end + 1])
    for candidate in candidates:
        try:
            data = json.loads(candidate)
        except json.JSONDecodeError:
            continue
        if isinstance(data, dict):
            return data
    return None


def _extract_tool_calls(message: object) -> list[dict[str, Any]]:
    structured = getattr(message, "tool_calls", None)
    if structured:
        return list(structured)
    payload = _extract_json_object(_render_message_text(message))
    if not payload:
        return []
    name = payload.get("name")
    arguments = payload.get("arguments", {})
    if isinstance(name, str) and isinstance(arguments, dict):
        return [{"id": "text-tool-call", "name": name, "args": arguments}]
    return []

# ─── Extração e formatação de comandos literais ──────────────────────────────

# Padrões reconhecidos (PT e EN):
#   "Corre o comando ls -la"
#   "Corre exatamente o comando: ls -la"
#   "Executa o comando: ls -la"
#   "Run the command ls -la"
#   "Execute exactly: ls -la"
_CMD_PATTERNS = re.compile(
    r"(?:"
    r"corre\s+(?:exatamente\s+)?o\s+comando\s*:?\s*"
    r"|executa\s+(?:exatamente\s+)?o\s+comando\s*:?\s*"
    r"|run\s+(?:exactly\s+)?the\s+command\s*:?\s*"
    r"|execute\s+(?:exactly\s*:?\s*|the\s+command\s*:?\s*)?"
    r")(.*)",
    re.IGNORECASE | re.DOTALL,
)


def _extract_literal_command(text: str) -> str | None:
    """Devolve o comando literal se o input corresponde a um padrão de execução directa."""
    m = _CMD_PATTERNS.match(text.strip())
    if m:
        cmd = m.group(1).strip()
        # Remove aspas externas opcionais: "ls -la" -> ls -la
        if len(cmd) >= 2 and cmd[0] in ('"', "'") and cmd[-1] == cmd[0]:
            cmd = cmd[1:-1]
        return cmd if cmd else None
    return None


def _format_command_output(command: str, output: str) -> str:
    """Formata stdout/stderr para apresentação sem intervenção do modelo."""
    # run_in_sandbox retorna stdout + stderr combinados ou mensagens de erro
    lines = output.splitlines()

    # Tenta separar stderr (marcado pelo próprio run_in_sandbox com [stderr])
    stderr_marker = "[stderr]"
    if stderr_marker in lines:
        idx = lines.index(stderr_marker)
        stdout_lines = lines[:idx]
        stderr_lines = lines[idx + 1 :]
    else:
        stdout_lines = lines
        stderr_lines = []

    stdout_text = "\n".join(stdout_lines).strip()
    stderr_text = "\n".join(stderr_lines).strip()

    parts = [f"Ok, running `{command}`.\n"]

    if stdout_text:
        parts.append(f"```\n{stdout_text}\n```")
    else:
        parts.append("```\n(no output)\n```")

    if stderr_text:
        parts.append(f"\nstderr:\n```\n{stderr_text}\n```")

    return "\n".join(parts)


BANNER = """
╔══════════════════════════════════════════════════════════╗
║              AIAgent@forensics v1.0                      ║
║       Politécnico de Leiria - ESTG                       ║
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

    messages: list[Any] = [SystemMessage(content=SYSTEM_PROMPT)]

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
            messages = [SystemMessage(content=SYSTEM_PROMPT)]
            print("[*] Historico limpo.\n")
            continue

        if user_input.lower() == "estrutura":
            cmd_estrutura()
            continue

        # ── Bypass do modelo para comandos literais ──────────────────────────
        literal_cmd = _extract_literal_command(user_input)
        if literal_cmd:
            print(f"  [direct exec] bash('{literal_cmd}')")
            output = run_in_sandbox(literal_cmd)
            print()
            print(_format_command_output(literal_cmd, output))
            print()
            # Regista no histórico para manter contexto
            messages.append(HumanMessage(content=user_input))
            messages.append(HumanMessage(
                content=f"[Executed `{literal_cmd}`]\nObservation:\n{output}"
            ))
            continue
        # ─────────────────────────────────────────────────────────────────────

        messages.append(HumanMessage(content=user_input))

        print()
        try:
            tool_call_count = 0
            while True:
                if tool_call_count >= 10:
                    print("\n[!] Limite de tool calls atingido.")
                    break

                response = llm.invoke(messages)
                tool_calls = _extract_tool_calls(response)

                if not tool_calls:
                    messages.append(response)
                    print(f"\n{'='*60}")
                    print(f"Agente: {_render_message_text(response)}")
                    print(f"{'='*60}\n")
                    break

                messages.append(response)
                tool_call_count += len(tool_calls)

                # Detecta se o modelo usou tool calling nativo (structured) ou texto
                is_native = bool(getattr(response, "tool_calls", None))

                for tc in tool_calls:
                    tool_name = tc["name"]
                    tool_impl = TOOLS.get(tool_name)
                    print(f"  [tool call] {tool_name}({tc.get('args', {})})")
                    if tool_impl is None:
                        tool_output = f"Ferramenta desconhecida: {tool_name}"
                    else:
                        tool_output = tool_impl.invoke(tc.get("args", {}))

                    if is_native:
                        # Tool calling nativo: ToolMessage com o ID correto
                        messages.append(
                            ToolMessage(
                                content=str(tool_output),
                                tool_call_id=tc["id"],
                            )
                        )
                    else:
                        # Tool call em texto: ToolMessage órfã quebra o protocolo.
                        # "Observation:" é o prefixo que o modelo reconhece como resultado da tool.
                        messages.append(
                            HumanMessage(content=f"Observation:\n{tool_output}")
                        )

        except Exception as e:
            print(f"\n[!] Erro: {str(e)}\n")
            if messages and isinstance(messages[-1], HumanMessage):
                messages.pop()


if __name__ == "__main__":
    main()