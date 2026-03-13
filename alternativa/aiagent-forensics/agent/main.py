"""
main.py — AIAgent@forensics v3.0
Agente LLM ReAct para investigação forense digital.
Politécnico de Leiria — ESTG | Licenciatura em Engenharia Informática

Modos de execução (controlados pelo .env):
  USE_MCP=false  → modo directo: agente sync com run_forensics_command genérico
  USE_MCP=true   → modo MCP: agente async com 12 ferramentas forenses especializadas

LLM (controlado pelo .env):
  USE_GEMINI=false → Ollama local (OLLAMA_MODEL, OLLAMA_URL)
  USE_GEMINI=true  → Gemini API (GEMINI_MODEL, GEMINI_API_KEY)
"""

import asyncio
import atexit
import os
import sys

from dotenv import load_dotenv
from langchain_core.tools import tool
from langgraph.prebuilt import create_react_agent

from tools import run_in_sandbox, stop_container

# ─── Configuração ─────────────────────────────────────────────────────────────

load_dotenv()

OLLAMA_MODEL   = os.getenv("OLLAMA_MODEL",   "qwen2.5:14b")
OLLAMA_URL     = os.getenv("OLLAMA_URL",     "http://localhost:11434")
GEMINI_MODEL   = os.getenv("GEMINI_MODEL",   "gemini-2.0-flash")
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
MAX_ITERATIONS = int(os.getenv("MAX_ITERATIONS", "15"))
USE_MCP        = os.getenv("USE_MCP",    "false").lower() == "true"
USE_GEMINI     = os.getenv("USE_GEMINI", "false").lower() == "true"

MCP_SERVER_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "mcp_server.py")

# ─── Utilitário ───────────────────────────────────────────────────────────────

def _to_str(content) -> str:
    """Normaliza content (str ou list MCP) para string."""
    if isinstance(content, list):
        return " ".join(
            item.get("text", str(item)) if isinstance(item, dict) else str(item)
            for item in content
        )
    return str(content) if content else ""

# ─── Banner ───────────────────────────────────────────────────────────────────

def _banner():
    modo = "MCP + 12 ferramentas" if USE_MCP else "Directo"
    llm  = f"Gemini ({GEMINI_MODEL})" if USE_GEMINI else f"Ollama ({OLLAMA_MODEL})"
    print(f"""
╔══════════════════════════════════════════════════════════╗
║              AIAgent@forensics v3.0                      ║
║       Politécnico de Leiria - ESTG                       ║
║  Agente LLM para Investigação Forense Digital (ReAct)    ║
╠══════════════════════════════════════════════════════════╣
║  Modo : {modo:<49}║
║  LLM  : {llm:<49}║
╠══════════════════════════════════════════════════════════╣
║  Comandos especiais:                                     ║
║    'sair' / 'exit'  -> termina o programa                ║
║    'limpar'         -> limpa o histórico de conversa     ║
║    'estrutura'      -> mostra o que está montado         ║
╚══════════════════════════════════════════════════════════╝""")

# ─── Construção do LLM ────────────────────────────────────────────────────────

def _build_llm():
    if USE_GEMINI:
        from langchain_google_genai import ChatGoogleGenerativeAI
        return ChatGoogleGenerativeAI(
            model=GEMINI_MODEL,
            google_api_key=GEMINI_API_KEY,
            temperature=0,
        )
    from langchain_ollama import ChatOllama
    return ChatOllama(model=OLLAMA_MODEL, base_url=OLLAMA_URL, temperature=0)

# ─── Prompts ──────────────────────────────────────────────────────────────────

_PROMPT_DIRECTO = (
    "Responde SEMPRE em portugues. "
    "IMPORTANTE: Usa SEMPRE a ferramenta run_forensics_command para executar comandos. "
    "NUNCA digas 'vou executar' sem realmente chamar a ferramenta. "
    "Cada vez que precisares de informacao, chama run_forensics_command imediatamente.\n"
    "Es um agente especialista em investigacao forense digital. "
    "REGRAS OBRIGATORIAS:\n"
    "1. NUNCA respondas sem usar a ferramenta run_forensics_command primeiro.\n"
    "2. A pasta /forensics esta VAZIA. Nao tentes caminhos directos.\n"
    "3. Para aceder a ficheiros DEVES usar SEMPRE fls e icat com offset 65664 sobre /forensics_ewf/ewf1.\n"
    "4. FLUXO para encontrar ficheiro:\n"
    "   Passo 1: run_forensics_command('fls -r -o 65664 /forensics_ewf/ewf1 | grep -i NOME')\n"
    "   Passo 2: obtem inode do resultado (ex: r/r 936-128-3: R40599.pdf -> inode 936)\n"
    "   Passo 3: run_forensics_command('icat -o 65664 /forensics_ewf/ewf1 INODE | md5sum')\n"
    "5. Para listar utilizadores: run_forensics_command('fls -o 65664 /forensics_ewf/ewf1 4213')\n"
    "6. Executa SEMPRE um comando de cada vez e analisa o resultado antes de continuar.\n"
)

_PROMPT_MCP = (
    "Responde SEMPRE em portugues. "
    "Es um agente especialista em investigacao forense digital.\n\n"
    "REGRAS OBRIGATORIAS:\n"
    "1. Chama SEMPRE uma ferramenta antes de responder — nunca respondas sem dados reais.\n"
    "2. Age directamente: NUNCA describes o que vais fazer, executa imediatamente.\n"
    "3. Usa run_forensics_command apenas como fallback se nenhuma ferramenta especializada servir.\n"
    "4. NUNCA termines a investigacao a meio — continua a chamar ferramentas ate teres a resposta FINAL completa.\n"
    "5. NUNCA digas 'vou procurar' ou 'primeiro vamos' — simplesmente chama a ferramenta.\n"
    "6. NUNCA digas 'nao consigo' — tens sempre ferramentas disponiveis.\n\n"
    "AO INICIAR QUALQUER INVESTIGACAO:\n"
    "  Usa get_filesystem_info() para perceber o tipo de imagem (NTFS, ext, etc.).\n\n"
    "PERGUNTAS SOBRE UTILIZADORES:\n"
    "  Se o utilizador nao for especificado, chama list_users() primeiro.\n"
    "  Apresenta os utilizadores encontrados e pergunta qual o pretendido.\n"
    "  So depois de confirmado, continua com list_directory(inode).\n\n"
    "FLUXO PARA MD5:\n"
    "  find_file('nome') -> inode (numero antes de ':') -> get_file_md5(inode)\n\n"
    "FLUXO PARA PASTA DE UM UTILIZADOR:\n"
    "  1. list_users() -> utilizadores e inodes\n"
    "  2. Pergunta qual o pretendido (se nao especificado)\n"
    "  3. list_directory(inode_user) -> subpastas (Desktop, Documents, etc.)\n"
    "  4. list_directory(inode_subpasta) -> lista conteudo\n"
)

# ═══════════════════════════════════════════════════════════════════════════════
# MODO DIRECTO (USE_MCP=false) — sync, ferramenta genérica
# ═══════════════════════════════════════════════════════════════════════════════

@tool
def run_forensics_command(command: str) -> str:
    """
    Executa comandos forenses dentro de um container Linux seguro e isolado.
    A imagem forense está montada em read-only.

    COMANDOS DISPONÍVEIS:
      ls, find, stat, file, grep, strings, cat, xxd, hexdump,
      md5sum, sha1sum, sha256sum, chntpw, mmls, fsstat, fls, icat, ffind, evtx_dump

    EXEMPLOS VIA SLEUTH KIT:
      fls -r -o 65664 /forensics_ewf/ewf1                  -- lista todos os ficheiros
      fls -r -o 65664 /forensics_ewf/ewf1 | grep -i pdf    -- procura PDFs
      fls -o 65664 /forensics_ewf/ewf1 4213                -- lista utilizadores
      icat -o 65664 /forensics_ewf/ewf1 <INODE>            -- le ficheiro pelo inode
      icat -o 65664 /forensics_ewf/ewf1 <INODE> | md5sum   -- calcula MD5
      mmls /forensics_ewf/ewf1                             -- tabela de particoes
    """
    return run_in_sandbox(command)


def _run_direct_loop():
    """Loop chatbot em modo directo (sync)."""
    atexit.register(stop_container)

    llm   = _build_llm()
    agent = create_react_agent(
        model=llm,
        tools=[run_forensics_command],
        prompt=_PROMPT_DIRECTO,
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
        if user_input.lower() == "estrutura":
            print("\n[Estrutura montada]\n" + run_in_sandbox("find /forensics -maxdepth 3 -type d"))
            continue

        history.append({"role": "user", "content": user_input})
        print()
        try:
            resposta = ""
            for chunk in agent.stream({"messages": history}):
                if "agent" in chunk:
                    for msg in chunk["agent"]["messages"]:
                        if hasattr(msg, "tool_calls") and msg.tool_calls:
                            for tc in msg.tool_calls:
                                args = ", ".join(f"{k}={v!r}" for k, v in tc["args"].items())
                                print(f"  [→ {tc['name']}({args})]", flush=True)
                        if hasattr(msg, "content") and msg.content:
                            resposta = _to_str(msg.content)
                elif "tools" in chunk:
                    for msg in chunk["tools"]["messages"]:
                        raw = _to_str(msg.content)
                        preview = raw[:120].replace("\n", " ")
                        print(f"  [✓ resultado: {preview}{'...' if len(raw) > 120 else ''}]",
                              flush=True)
            print(f"\n{'='*60}\nAgente: {resposta}\n{'='*60}\n")
            history.append({"role": "assistant", "content": resposta})
        except Exception as e:
            print(f"\n[!] Erro: {e}\n")
            if history and history[-1]["role"] == "user":
                history.pop()


# ═══════════════════════════════════════════════════════════════════════════════
# MODO MCP (USE_MCP=true) — async, 15 ferramentas especializadas
# ═══════════════════════════════════════════════════════════════════════════════

async def _run_mcp_loop():
    """Loop chatbot em modo MCP (async)."""
    from langchain_mcp_adapters.client import MultiServerMCPClient

    print(f"[*] A lançar servidor MCP: {MCP_SERVER_PATH}")

    client = MultiServerMCPClient({
        "forensics": {
            "command": sys.executable,
            "args": [MCP_SERVER_PATH],
            "transport": "stdio",
        }
    })
    tools = await client.get_tools()
    print(f"[+] Ferramentas MCP disponíveis ({len(tools)}): {[t.name for t in tools]}\n")

    llm   = _build_llm()
    agent = create_react_agent(
        model=llm,
        tools=tools,
        prompt=_PROMPT_MCP,
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
        if user_input.lower() == "estrutura":
            print("[!] Comando 'estrutura' não disponível em modo MCP.")
            continue

        history.append({"role": "user", "content": user_input})
        print()
        try:
            resposta = ""
            async for chunk in agent.astream({"messages": history}):
                if "agent" in chunk:
                    for msg in chunk["agent"]["messages"]:
                        if hasattr(msg, "tool_calls") and msg.tool_calls:
                            for tc in msg.tool_calls:
                                args = ", ".join(f"{k}={v!r}" for k, v in tc["args"].items())
                                print(f"  [→ {tc['name']}({args})]", flush=True)
                        if hasattr(msg, "content") and msg.content:
                            resposta = _to_str(msg.content)
                elif "tools" in chunk:
                    for msg in chunk["tools"]["messages"]:
                        raw = _to_str(msg.content)
                        preview = raw[:120].replace("\n", " ")
                        print(f"  [✓ resultado: {preview}{'...' if len(raw) > 120 else ''}]",
                              flush=True)
            print(f"\n{'='*60}\nAgente: {resposta}\n{'='*60}\n")
            history.append({"role": "assistant", "content": resposta})
        except Exception as e:
            print(f"\n[!] Erro: {e}\n")
            if history and history[-1]["role"] == "user":
                history.pop()


# ─── Ponto de entrada ─────────────────────────────────────────────────────────

def main():
    _banner()
    llm_desc = f"Gemini ({GEMINI_MODEL})" if USE_GEMINI else f"Ollama ({OLLAMA_MODEL}) via {OLLAMA_URL}"
    print(f"[*] LLM: {llm_desc}")

    if USE_MCP:
        asyncio.run(_run_mcp_loop())
    else:
        print("[*] A verificar container...\n")
        _run_direct_loop()


if __name__ == "__main__":
    main()
