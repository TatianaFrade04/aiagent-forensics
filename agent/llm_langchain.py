import os
import subprocess

from langchain.agents import create_agent
from langchain_ollama import ChatOllama

from tools.commands import bash_cmd


# =========================
# Config
# =========================

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_EVIDENCE_DIR = os.path.join(_PROJECT_ROOT, "evidence")

_DOCKER_IMAGE = os.getenv("FORENSICS_IMAGE") or "forensics"
_DOCKER_CONTAINER = os.getenv("FORENSICS_CONTAINER") or "forensics"

OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL") or "http://localhost:11434"
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL") or "llama3.1"


# =========================
# Helpers
# =========================

def shorten_text(text: str, max_len: int = 1800) -> str:
    if text is None:
        return ""
    text = str(text)
    if len(text) <= max_len:
        return text
    return text[:max_len] + "\n...[output truncado]..."


def is_error_text(text: str) -> bool:
    if not text:
        return False
    lowered = text.lower()
    return (
        "error invoking tool" in lowered
        or "erro bash" in lowered
        or "field required" in lowered
        or "input should be a valid string" in lowered
    )


# =========================
# Tool list
# =========================

TOOLS = [
    bash_cmd,
]


# =========================
# Prompt
# =========================

SYSTEM_PROMPT = """
És um assistente forense especializado em análise de imagens de disco.

Tens acesso a estas tools:

1. bash_cmd(command)
    Executa texto bash ad-hoc diretamente no container.
    - command: comando bash (ex: "ls -la /evidence", "fls -i ewf -o 65664 /evidence/2020JimmyWilson.E01").
    - timeout: opcional, em segundos.

Regras:
- Usa esta tool para executar comandos e depois responde com base no output.
- Quando uma pergunta exigir vários passos, encadeia numa única chamada com `&&`, `;` e pipes `|`.
- Quando precisares separar outputs por etapa, usa `echo` entre comandos para marcar secções.
- Em pipelines, nunca uses `grep -r`; usa `grep` simples para filtrar o output do comando anterior.
- Exemplo correto para raiz da partição: `fls -i ewf -o <offset> <e01>` (sem grep) ou `fls ... | grep '^d/'`.
- Se for necessário, aumenta `timeout` para comandos mais longos.
- `/evidence` é uma pasta montada com ficheiros de evidência, não um device block.
- Para perguntas sobre partições de uma evidência, usa este fluxo:
    1) listar ficheiros em `/evidence` para encontrar `.E01`
    2) correr `mmls -i ewf /evidence/<ficheiro>.E01`
- Se a pergunta for sobre partições forenses, nunca uses `lsblk`, `fdisk` ou `parted` para inferir a resposta.
- Só usa `lsblk`, `fdisk` ou `parted` quando o utilizador pedir explicitamente dispositivos do sistema (`/dev/*`).
- Para perguntas sobre utilizadores na imagem ("quais users", "quantos users"), segue OBRIGATORIAMENTE este fluxo:
    1) encontrar o ficheiro `.E01` em `/evidence`
    2) obter offset principal com `mmls -i ewf`
    3) listar recursivamente com `fls -r -i ewf -o <offset> <e01>` e extrair nomes de perfis em `/Users/...`
- Nunca uses `getent passwd`, `/etc/passwd` ou equivalentes para responder sobre utilizadores da imagem.
- Quando responderes "quantos", indica também os nomes encontrados (ou diz explicitamente que não encontrou nenhum).
- Baseia-te APENAS no output das tools para responder.
- Não respondas com JSON.
"""


# =========================
# Docker
# =========================

def ensure_container():
    running = subprocess.run(
        ["docker", "ps", "-q", "--filter", f"name=^{_DOCKER_CONTAINER}$"],
        capture_output=True,
        text=True,
    ).stdout.strip()

    if running:
        print(f"[docker] Container '{_DOCKER_CONTAINER}' já está a correr.")
        return

    subprocess.run(
        ["docker", "rm", "-f", _DOCKER_CONTAINER],
        capture_output=True,
        text=True,
    )

    print(f"[docker] A arrancar container '{_DOCKER_CONTAINER}' com imagem '{_DOCKER_IMAGE}'...")

    result = subprocess.run(
        [
            "docker",
            "run",
            "-d",
            "--name",
            _DOCKER_CONTAINER,
            "--network",
            "none",
            "-v",
            f"{_EVIDENCE_DIR}:/evidence:ro",
            _DOCKER_IMAGE,
        ],
        capture_output=True,
        text=True,
    )

    if result.returncode != 0:
        raise RuntimeError(f"Falha ao arrancar o container:\n{result.stderr}")

    print("[docker] Container pronto.\n")


# =========================
# Agent
# =========================

def build_agent():
    if not OLLAMA_MODEL:
        raise ValueError("OLLAMA_MODEL está vazio.")

    print(f"[ollama] base_url={OLLAMA_BASE_URL}")
    print(f"[ollama] model={OLLAMA_MODEL}")

    llm = ChatOllama(
        model=OLLAMA_MODEL,
        base_url=OLLAMA_BASE_URL,
        temperature=0,
        validate_model_on_init=False,
    )

    return create_agent(
        model=llm,
        tools=TOOLS,
        system_prompt=SYSTEM_PROMPT,
    )


# =========================
# Pretty terminal output
# =========================

def print_step(text: str):
    print(f"\n[passo] {text}")


def print_tool_call(tool_name: str, args: dict):
    if tool_name == "bash_cmd":
        print_step("A executar comando bash no container...")
    else:
        print_step(f"A executar tool: {tool_name}")

    print(f"[decisão] {tool_name}")
    print(f"[args] {args}")


def print_tool_result(tool_name: str, content: str):
    text = str(content).strip()

    if is_error_text(text):
        print(f"\n[aviso:{tool_name}] tentativa falhou, a corrigir...")
        print(shorten_text(text, max_len=600))
        return

    print(f"\n[resultado:{tool_name}]")
    print(shorten_text(text))


def print_final_answer(text: str):
    text = (text or "").strip()
    if text:
        print("\n[resposta final]")
        print(text)


def print_stream_chunk(chunk: dict):
    """
    Interpreta os chunks devolvidos por agent.stream(..., stream_mode='updates').
    """
    if not isinstance(chunk, dict):
        return

    for _, node_data in chunk.items():
        if not isinstance(node_data, dict):
            continue

        messages = node_data.get("messages", [])
        if not messages:
            continue

        for msg in messages:
            tool_calls = getattr(msg, "tool_calls", None)
            if tool_calls:
                for tc in tool_calls:
                    tool_name = tc.get("name", "tool")
                    args = tc.get("args", {})
                    print_tool_call(tool_name, args)
                continue

            tool_name = getattr(msg, "name", None)
            if tool_name:
                content = getattr(msg, "content", "")
                print_tool_result(tool_name, content)
                continue

            content = getattr(msg, "content", None)
            if isinstance(content, str) and content.strip():
                print_final_answer(content)


# =========================
# Main
# =========================

def main():
    ensure_container()
    agent = build_agent()

    while True:
        query = input("\nPergunta (ou 'sair'): ").strip()

        if query.lower() in ("sair", "exit", "quit"):
            break

        try:
            for chunk in agent.stream(
                {"messages": [{"role": "user", "content": query}]},
                stream_mode="updates",
            ):
                print_stream_chunk(chunk)

            print()

        except Exception as e:
            print(f"\n[erro] {e}")


if __name__ == "__main__":
    main()