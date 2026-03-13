"""
main_mcp.py — AIAgent@forensics v2.0 com MCP
Agente LLM ReAct que se liga ao servidor MCP (mcp_server.py) via stdio.

O servidor MCP é lançado automaticamente como subprocesso e comunicam via stdio.
"""

import asyncio
import os
import sys

from dotenv import load_dotenv
from langchain_ollama import ChatOllama
from langgraph.prebuilt import create_react_agent
from langchain_mcp_adapters.client import MultiServerMCPClient

# ─── Configuração ─────────────────────────────────────────────────────────────

load_dotenv()

OLLAMA_MODEL   = os.getenv("OLLAMA_MODEL",   "llama3")
OLLAMA_URL     = os.getenv("OLLAMA_URL",     "http://localhost:11434")
MAX_ITERATIONS = int(os.getenv("MAX_ITERATIONS", "15"))

# Path absoluto para mcp_server.py (mesmo directório que este ficheiro)
MCP_SERVER_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "mcp_server.py")

# ─── Prompt do sistema ────────────────────────────────────────────────────────

SYSTEM_PROMPT = (
    "Responde SEMPRE em portugues. "
    "IMPORTANTE: Usa SEMPRE a ferramenta run_forensics_command para executar comandos. "
    "NUNCA digas 'vou executar' sem realmente chamar a ferramenta. "
    "Cada vez que precisares de informacao, chama run_forensics_command imediatamente.\n"
    "Es um agente especialista em investigacao forense digital. "
    "REGRAS OBRIGATORIAS - SEGUE SEMPRE ESTAS REGRAS:\n"
    "1. NUNCA respondas sem usar a ferramenta run_forensics_command primeiro.\n"
    "2. A pasta /forensics esta VAZIA. Nao tentes caminhos como /forensics/Users ou /forensics/part2.\n"
    "3. Para aceder a ficheiros DEVES usar SEMPRE fls e icat com offset 65664 sobre /forensics_ewf/ewf1.\n"
    "4. FLUXO OBRIGATORIO para encontrar um ficheiro:\n"
    "   Passo 1: run_forensics_command('fls -r -o 65664 /forensics_ewf/ewf1 | grep -i NOME_FICHEIRO')\n"
    "   Passo 2: Obtem o numero do inode do resultado (ex: r/r 936-128-3: R40599.pdf -> inode e 936)\n"
    "   Passo 3: run_forensics_command('icat -o 65664 /forensics_ewf/ewf1 INODE | md5sum')\n"
    "5. Para listar utilizadores: run_forensics_command('fls -o 65664 /forensics_ewf/ewf1 4213')\n"
    "6. Para ler emails: usa icat para extrair o ficheiro e strings para ler o conteudo.\n"
    "7. Executa SEMPRE um comando de cada vez e analisa o resultado antes de continuar.\n"
    "8. NUNCA inventes caminhos ou resultados. Se nao sabes, usa fls para procurar.\n"
)

# ─── Banner ───────────────────────────────────────────────────────────────────

BANNER = """
╔══════════════════════════════════════════════════════════╗
║          AIAgent@forensics v2.0 (MCP + stdio)            ║
║       Politécnico de Leiria - ESTG                       ║
║  Agente LLM para Investigação Forense Digital (ReAct)    ║
╠══════════════════════════════════════════════════════════╣
║  Comandos especiais:                                     ║
║    'sair' / 'exit'  -> termina o programa                ║
║    'limpar'         -> limpa o histórico de conversa     ║
╚══════════════════════════════════════════════════════════╝
"""

# ─── Loop principal (async) ───────────────────────────────────────────────────

async def main_async():
    print(BANNER)
    print(f"[*] Modelo: {OLLAMA_MODEL} via {OLLAMA_URL}")
    print(f"[*] A lançar servidor MCP: {MCP_SERVER_PATH}")

    llm = ChatOllama(
        model=OLLAMA_MODEL,
        base_url=OLLAMA_URL,
        temperature=0,
    )

    # langchain-mcp-adapters >= 0.1.0 já não suporta 'async with'.
    # Usa a API directa: instancia o cliente e chama get_tools() como coroutine.
    client = MultiServerMCPClient(
        {
            "forensics": {
                "command": sys.executable,        # mesmo Python que está a correr
                "args": [MCP_SERVER_PATH],
                "transport": "stdio",
            }
        }
    )
    tools = await client.get_tools()
    print(f"[+] Ferramentas MCP disponíveis: {[t.name for t in tools]}\n")

    agent = create_react_agent(
        model=llm,
        tools=tools,
        prompt=SYSTEM_PROMPT,
    )

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
            print("[*] Até logo!")
            break

        if user_input.lower() == "limpar":
            history.clear()
            print("[*] Histórico limpo.\n")
            continue

        history.append({"role": "user", "content": user_input})

        print()
        try:
            result = await agent.ainvoke({"messages": history})
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


def main():
    asyncio.run(main_async())


if __name__ == "__main__":
    main()
