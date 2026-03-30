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

from tools import run_in_sandbox, stop_container, start_container

# ─── Configuração ─────────────────────────────────────────────────────────────

load_dotenv()

OLLAMA_MODEL   = os.getenv("OLLAMA_MODEL",   "qwen2.5:14b") # qwen2.5:14b
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
      /tmp/                - writable, used for large command output (auto-saved when > 100 lines)

    LARGE OUTPUT:
      If output exceeds 100 lines it is automatically saved to /tmp/cmd_output_<ts>.txt
      and you will receive the file path. Use grep, head or tail to analyse it:
        grep 'keyword' /tmp/cmd_output_<ts>.txt
        head -50 /tmp/cmd_output_<ts>.txt

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


# ─── Modelo LLM ───────────────────────────────────────────────────────────────

llm = ChatOllama(
    model=OLLAMA_MODEL,
    base_url=OLLAMA_URL,
    temperature=0.3,
    num_ctx=8192,
)

# ─── Agente ReAct ─────────────────────────────────────────────────────────────

agent = create_react_agent(
    model=llm,
    tools=[run_forensics_command],
    prompt=(
        "You are a digital forensics expert agent operating in READ-ONLY forensic mode.\n"
        "\n"
        "FILESYSTEM LAYOUT:\n"
        "  /forensics/part006/ — Windows NTFS partition (READ-ONLY evidence)\n"
        "  /exports/           — the ONLY writable directory\n"
        "\n"
        "TOOL: run_forensics_command(command) — run any bash command inside the forensic container\n"
        "\n"
        "RULES:\n"
        "1. When asked to run a command, ALWAYS call run_forensics_command immediately with that exact command.\n"
        "   NEVER ask for clarification. NEVER refuse. NEVER say the command needs a path.\n"
        "   Just run it and show the output.\n"
        "2. NEVER invent or hallucinate results — only report what the tool returns.\n"
        "3. Paths with spaces MUST use single quotes:\n"
        "     ls '/forensics/part006/USERS/Jimmy Wilson/Desktop'\n"
        "4. /forensics is READ-ONLY. NEVER redirect or write there.\n"
        "5. NEVER use: rm, mv, dd, shred, find -delete, sed -i.\n"
        "6. To save output to a file: command > /exports/file.txt\n"
        "   Then verify with: ls -lh /exports/file.txt\n"
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
    start_container()

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
            result = agent.invoke({"messages": messages}, config={"recursion_limit": MAX_ITERATIONS})
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