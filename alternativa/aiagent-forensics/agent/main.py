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
    "IMPORTANT: ALWAYS use the run_forensics_command tool to execute commands. "
    "NEVER say 'I will execute' without actually calling the tool. "
    "Every time you need information, call run_forensics_command immediately.\n"
    "MANDATORY RULES - ALWAYS FOLLOW THESE:\n"
    "1. NEVER respond without using run_forensics_command first.\n"
    "2. ALL evidence is inside /forensics/. Always search and look for files under /forensics/.\n"
    "3. NEVER use fls/icat unless ls/find do not work.\n"
    "5. ALWAYS execute one command at a time and analyse the result before continuing.\n"
    "6. NEVER invent paths or results. If unsure, use find to search.\n"
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

    history = []

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
            history.clear()
            print("[*] Historico limpo.\n")
            continue

        if user_input.lower() == "estrutura":
            cmd_estrutura()
            continue

        history.append({"role": "user", "content": user_input})

        print()
        try:
            result = agent.invoke({"messages": history})
            messages = result.get("messages", [])

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

            history.append({"role": "assistant", "content": resposta})

        except Exception as e:
            print(f"\n[!] Erro: {str(e)}\n")
            if history and history[-1]["role"] == "user":
                history.pop()


if __name__ == "__main__":
    main()