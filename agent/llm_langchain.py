import os
import subprocess

from langchain.agents import create_agent
from langchain.tools import tool
from langchain_ollama import ChatOllama

from tools.commands import list_dir, mmls_partitions
from tools.runner import run_cmd


# =========================
# Config
# =========================

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_EVIDENCE_DIR = os.path.join(_PROJECT_ROOT, "evidence")

_DOCKER_IMAGE = os.getenv("FORENSICS_IMAGE") or "forensics"
_DOCKER_CONTAINER = os.getenv("FORENSICS_CONTAINER") or "forensics"

E01_DEFAULT = "/evidence/2020JimmyWilson.E01"

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
        or "erro fls" in lowered
        or "invalid image offset" in lowered
        or "field required" in lowered
        or "input should be a valid string" in lowered
    )


def extract_main_partition_offset(mmls_output: str) -> str:
    """
    Extrai o start sector da maior 'Basic data partition' do output do mmls.
    """

    candidates = []

    for raw_line in mmls_output.splitlines():
        line = raw_line.strip()
        if not line:
            continue

        # Exemplo:
        # 006:  001  0000065664  0001736831  0001671168  Basic data partition
        if "Basic data partition" not in line:
            continue

        parts = line.split()
        if len(parts) < 6:
            continue

        try:
            start = parts[2]
            length = int(parts[4])
            candidates.append(
                {
                    "start": start,
                    "length": length,
                    "line": raw_line,
                }
            )
        except (ValueError, IndexError):
            continue

    if not candidates:
        raise ValueError(
            "Não foi encontrada nenhuma 'Basic data partition' no output do mmls."
        )

    best = max(candidates, key=lambda item: item["length"])
    return str(best["start"])


# =========================
# Tools
# =========================

def _fls_raw(e01_path: str, offset: str, inode: str = "") -> str:
    argv = ["fls", "-i", "ewf", "-o", offset, e01_path]
    if inode:
        argv.append(inode)
    r = run_cmd(argv)
    if r["returncode"] != 0:
        return f"ERRO fls\n{r['stderr']}"
    return r["stdout"]


def _parse_inode(fls_output: str, name: str) -> str:
    """Devolve o inode da entrada com o nome dado, ou None se não encontrar."""
    for line in fls_output.splitlines():
        parts = line.split("\t", 1)
        if len(parts) == 2 and parts[1].strip().lower() == name.lower():
            # formato: 'd/d 4214-144-5:' ou 'r/r 7-128-1:'
            inode_part = parts[0].split()[-1].rstrip(":")
            return inode_part
    return None


@tool
def explore_disk(e01_path: str = E01_DEFAULT, path: str = "/") -> str:
    """Explora o conteúdo de uma imagem de disco forense.
    e01_path: caminho do ficheiro .E01 dentro do container.
    path: caminho a explorar dentro da imagem.
           Usa "/" ou "" para a raiz.
           Para subpastas usa o nome: "Windows", "USERS", "USERS/JimmyWilson".
    Usa esta tool para QUALQUER pergunta sobre ficheiros ou pastas dentro da imagem.
    """
    # Passo 1 — offset
    print("\n[passo] A descobrir o offset da partição principal...")
    print("[decisão] mmls_partitions")
    print(f"[args] {{'e01_path': '{e01_path}'}}")
    raw_mmls = mmls_partitions.invoke({"e01_path": e01_path})
    print("\n[resultado:mmls_partitions]")
    print(shorten_text(raw_mmls))
    offset = extract_main_partition_offset(raw_mmls)
    print(f"\n[passo] Offset da partição principal: {offset}")

    # Componentes do caminho (vazio = raiz)
    components = [p for p in path.strip("/").split("/") if p]

    # Passo 2 — listar raiz
    print("\n[passo] A listar a raiz da partição...")
    print("[decisão] fls (raiz)")
    print(f"[args] {{'e01_path': '{e01_path}', 'offset': '{offset}'}}")
    current_output = _fls_raw(e01_path, offset)
    print("\n[resultado:fls (raiz)]")
    print(shorten_text(current_output))

    if not components:
        return current_output

    # Passo 3 — navegar pelas subpastas
    for component in components:
        inode = _parse_inode(current_output, component)
        if not inode:
            return f"Não foi encontrada a entrada '{component}'. Conteúdo atual:\n{current_output}"
        print(f"\n[passo] A entrar na pasta '{component}' (inode: {inode})...")
        print("[decisão] fls")
        print(f"[args] {{'e01_path': '{e01_path}', 'offset': '{offset}', 'inode': '{inode}'}}")
        current_output = _fls_raw(e01_path, offset, inode)
        print(f"\n[resultado:fls '{component}']")
        print(shorten_text(current_output))

    return current_output


# =========================
# Tool list
# =========================

TOOLS = [
    list_dir,
    explore_disk,
]


# =========================
# Prompt
# =========================

SYSTEM_PROMPT = f"""
És um assistente forense especializado em análise de imagens de disco.

Tens acesso a estas tools:

1. list_dir(path)
   Usa quando o utilizador perguntar sobre o container ou a pasta /evidence do sistema de ficheiros do container.
   Exemplos: "o que existe em /evidence", "que ficheiros de imagem tens", "lista /evidence".

2. explore_disk(e01_path, path)
   Usa quando o utilizador perguntar sobre o INTERIOR de uma imagem de disco (.E01).
   Exemplos: "que ficheiros existem na raiz da imagem", "o que existe na pasta Windows", "lista USERS".
   - e01_path: usa {E01_DEFAULT} se o utilizador não indicar outro.
   - path: "/" para a raiz da imagem; "Windows", "USERS", "USERS/JimmyWilson" para subpastas.

Regras:
- Não uses explore_disk para perguntas sobre o container.
- Não uses list_dir para explorar o interior de uma imagem.
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
    if tool_name == "explore_disk":
        # os passos são impressos dentro da própria tool
        return
    elif tool_name == "list_dir":
        print_step(f"A listar '{args.get('path', '/evidence')}' no container...")
    else:
        print_step(f"A executar tool: {tool_name}")

    print(f"[decisão] {tool_name}")
    print(f"[args] {args}")


def print_tool_result(tool_name: str, content: str):
    text = str(content).strip()

    if is_error_text(text):
        print(f"\n[aviso:{tool_name}] tentativa falhou, a corrigir...")
        return

    # explore_disk já imprimiu tudo internamente — não repetir
    if tool_name == "explore_disk":
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