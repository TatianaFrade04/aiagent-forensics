"""
main.py — AIAgent@forensics
Agente LLM com paradigma ReAct para investigação forense digital.
Politécnico de Leiria — ESTG | Licenciatura em Engenharia Informática
"""

import atexit
import os
import json
import re
from dotenv import load_dotenv

from langchain_ollama import ChatOllama
from langchain_core.tools import tool
from langgraph.prebuilt import create_react_agent

from tools import run_in_sandbox, stop_container

# ─── Configuração ─────────────────────────────────────────────────────────────

load_dotenv()

OLLAMA_MODEL   = os.getenv("OLLAMA_MODEL",   "llama3.1:8b")
OLLAMA_URL     = os.getenv("OLLAMA_URL",     "http://localhost:11434")
MAX_ITERATIONS = int(os.getenv("MAX_ITERATIONS", "15"))

atexit.register(stop_container)

# ─── Ferramenta exposta ao agente ─────────────────────────────────────────────

@tool
def run_forensics_command(command: str) -> str:
    """
    Executa comandos forenses dentro de um container Linux seguro e isolado.
    A imagem forense esta montada em read-only e os ficheiros estao acessiveis em /forensics/partN/

    MOUNTED STRUCTURE (Windows system):
      /forensics/part006/                                      - main Windows partition (NTFS mounted)
      /forensics/part006/USERS/                                - user home directories
      /forensics/part006/Windows/System32/config/SAM           - user accounts database
      /forensics/part006/Windows/System32/config/SYSTEM        - system configuration
      /forensics/part006/Windows/System32/winevt/Logs/         - event logs (.evtx)

    AVAILABLE COMMANDS:
      ls, find, stat, file, grep, strings, cat, xxd, hexdump,
      md5sum, sha1sum, sha256sum, chntpw, mmls, fsstat, fls, icat, evtx_dump

    EXAMPLES (use /forensics/part006 directly):
      ls /forensics/part006/USERS
      find /forensics/part006 -name "*.pdf"
      grep -ri "keyword" /forensics/part006/USERS/
      md5sum "/forensics/part006/USERS/Jimmy Wilson/Documents/file.pdf"
      chntpw -l /forensics/part006/Windows/System32/config/SAM
      evtx_dump /forensics/part006/Windows/System32/winevt/Logs/System.evtx
      cat /forensics_info.txt

    NOTES:
      - The main partition is MOUNTED at /forensics/part006/
      - Use ls and find directly on /forensics/part006/
      - Always execute one command at a time
    """
    return run_in_sandbox(command)


# ─── Modelo LLM ───────────────────────────────────────────────────────────────

llm = ChatOllama(
    model=OLLAMA_MODEL,
    base_url=OLLAMA_URL,
    temperature=0.5,
)

# ─── Agente ReAct ─────────────────────────────────────────────────────────────

agent = create_react_agent(
    model=llm,
    tools=[run_forensics_command],
    prompt=(
    "You are a digital forensics expert agent. "
    "You have ONE tool: run_forensics_command(command='...'). "
    "CRITICAL: Paths with spaces MUST use single quotes: cat '/forensics/part006/USERS/Jimmy Wilson/Desktop/file.txt'. "
    "NEVER write: cat /forensics/part006/USERS/Jimmy Wilson/... (unquoted spaces break the command). "
    "ALWAYS write: cat '/forensics/part006/USERS/Jimmy Wilson/...' (single-quoted). "
    "NEVER output JSON. ALWAYS call run_forensics_command directly.\n"
    "RULES:\n"
    "1. Every answer requires calling run_forensics_command first to get real data.\n"
    "2. ALL files are under /forensics/part006/.\n"
    "3. Execute one command at a time and wait for the result.\n"
    "4. Never invent results. If unsure, use find to search.\n"
    ),
)

# ─── Interface chatbot ────────────────────────────────────────────────────────

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
    print("[*] A verificar container...\n")

    messages = []

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
            messages.clear()
            print("[*] Historico limpo.\n")
            continue

        if user_input.lower() == "estrutura":
            cmd_estrutura()
            continue

        messages.append({"role": "user", "content": user_input})

        print()
        try:
            result = agent.invoke({"messages": messages})
            messages = result.get("messages", messages)

            resposta = ""
            for msg in reversed(messages):
                if msg.__class__.__name__ == "AIMessage" and msg.content:
                    resposta = msg.content
                    break

            if not resposta:
                resposta = "(sem resposta)"

            # Fallback 1: detecta tool calls em texto (JSON ou Python-like)
            cmd = None
            for pattern in [
                r'"command"\s*:\s*"([^"]+)"',                        # JSON: "command": "..."
                r"run_forensics_command\(command='([^']+)'",          # Python single-quote
                r'run_forensics_command\(command="([^"]+)"',          # Python double-quote
            ]:
                m = re.search(pattern, resposta)
                if m:
                    cmd = m.group(1)
                    break

            # Fallback 1b: formato {"name": "ls", "parameters": {"path": "..."}}
            if not cmd:
                name_m = re.search(r'"name"\s*:\s*"(\w+)"', resposta)
                path_m = re.search(r'"path"\s*:\s*"([^"]+)"', resposta)
                if name_m and path_m:
                    cmd = f"{name_m.group(1)} '{path_m.group(1)}'"
            if cmd:
                output = run_in_sandbox(cmd)
                resposta = f"$ {cmd}\n{output}"

            # Fallback 2: verifica se alguma ferramenta foi chamada
            # Se não foi, o modelo alucionou — executa find com o nome do ficheiro
            elif not any(msg.__class__.__name__ == "ToolMessage" for msg in messages):
                # Extrai possível nome de ficheiro da pergunta do utilizador
                file_match = re.search(r'"([^"]+\.\w+)"', user_input)
                if file_match:
                    filename = file_match.group(1)
                    find_cmd = f"find /forensics/part006 -iname '{filename}'"
                    output = run_in_sandbox(find_cmd)
                    resposta = f"[Nenhuma ferramenta chamada — a executar find automaticamente]\n$ {find_cmd}\n{output}"

            print(f"\n{'='*60}")
            print(f"Agente: {resposta}")
            print(f"{'='*60}\n")

        except Exception as e:
            print(f"\n[!] Erro: {str(e)}\n")
            if messages and messages[-1].get("role") == "user":
                messages.pop()


if __name__ == "__main__":
    main()