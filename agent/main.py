"""
main.py — AIAgent@forensics
Agente LLM com paradigma ReAct para investigação forense digital.
Politécnico de Leiria — ESTG | Licenciatura em Engenharia Informática
"""

import atexit
import os
from dotenv import load_dotenv

from langchain_ollama import ChatOllama
from langchain_core.tools import tool
from langgraph.prebuilt import create_react_agent

from tools import run_in_sandbox, stop_container, ensure_container_running

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
    "You are a digital forensics expert. Use run_forensics_command to execute shell commands inside the forensic container.\n"
    "RULES:\n"
    "1. ALWAYS call run_forensics_command before answering — never invent results.\n"
    "2. ALL files are under /forensics/part006/.\n"
    "3. Paths with spaces need single quotes: ls '/forensics/part006/USERS/Jimmy Wilson/Desktop'\n"
    "4. If unsure of a path, use find first: find /forensics/part006 -iname 'filename'\n"
    "5. One command at a time.\n"
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
    ensure_container_running()

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
            n_before = len(messages)
            result = agent.invoke({"messages": messages})
            messages = result.get("messages", messages)
            new_msgs = messages[n_before:]  # apenas mensagens do turno actual

            # Output em bruto do agente (todas as mensagens do turno actual)
            print(f"\n{'─'*60}")
            print("[RAW AGENT OUTPUT]")
            for msg in new_msgs:
                cls = msg.__class__.__name__
                content = msg.content if hasattr(msg, "content") else ""
                tool_calls = getattr(msg, "tool_calls", [])
                print(f"  [{cls}] content={content!r}")
                if tool_calls:
                    for tc in tool_calls:
                        print(f"    tool_call: {tc}")
            print(f"{'─'*60}\n")

            resposta = ""
            for msg in reversed(messages):
                if msg.__class__.__name__ == "AIMessage" and msg.content:
                    resposta = msg.content
                    break

            if not resposta:
                resposta = "(sem resposta)"

            print(f"\n{'='*60}")
            print(f"Agente: {resposta}")
            print(f"{'='*60}\n")

        except Exception as e:
            print(f"\n[!] Erro: {str(e)}\n")
            if messages and messages[-1].get("role") == "user":
                messages.pop()


if __name__ == "__main__":
    main()