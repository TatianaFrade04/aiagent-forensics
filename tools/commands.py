import os
from datetime import datetime
import subprocess

from langchain_core.tools import tool

from tools.runner import run_cmd

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_EVIDENCE_DIR = os.path.join(_PROJECT_ROOT, "evidence")


@tool
def list_dir(path: str = "/evidence") -> str:
    """Lista ficheiros e pastas numa diretoria.
    Usa /evidence para ver os ficheiros de evidência dentro do container."""
    # paths Linux (ex: /evidence) → correr dentro do container
    if path.startswith("/"):
        r = run_cmd(["ls", "-la", path])
        if r["returncode"] != 0:
            return f"ERRO a listar {path}\n{r['stderr']}"
        return r["stdout"]

    # paths Windows → listar localmente
    try:
        entries = os.listdir(path)
        lines = []
        for name in sorted(entries):
            full = os.path.join(path, name)
            st = os.stat(full)
            size = st.st_size
            mtime = datetime.fromtimestamp(st.st_mtime).strftime("%Y-%m-%d %H:%M")
            kind = "d" if os.path.isdir(full) else "-"
            lines.append(f"{kind} {size:>12}  {mtime}  {name}")
        return f"total {len(entries)}\n" + "\n".join(lines)
    except Exception as e:
        return f"ERRO a listar {path}\n{e}"


@tool
def mmls_partitions(e01_path: str) -> str:
    """Lista as partições de um ficheiro de imagem forense (.E01).
    Usa o path do ficheiro dentro do container (ex: /evidence/imagem.E01)."""
    r = run_cmd(["mmls", "-i", "ewf", e01_path])
    if r["returncode"] != 0:
        return f"ERRO mmls\n{r['stderr']}"
    return r["stdout"]


@tool
def fls_list(e01_path: str, offset: str, directory_inode: str = "") -> str:
    """
    Lista ficheiros de um filesystem usando fls.

    Argumentos:
    - e01_path: caminho para a imagem E01
    - offset: start sector real da partição
    - directory_inode: inode opcional de uma diretoria específica

    Regras:
    - o offset deve ser um número em string
    - o offset deve vir de get_main_partition_offset ou mmls_partitions
    - não usar partition number, slot ou nomes de tools
    """
    if not isinstance(offset, str) or not offset.strip().isdigit():
        return "ERRO fls\nOffset inválido. Usa primeiro get_main_partition_offset e passa o valor devolvido em offset."

    cmd = ["fls", "-o", offset, e01_path]
    if directory_inode and str(directory_inode).strip():
        cmd.extend(["-d", str(directory_inode).strip()])

    result = subprocess.run(cmd, capture_output=True, text=True)

    if result.returncode != 0:
        return f"ERRO fls\n{result.stderr.strip()}"

    return result.stdout.strip()

def find_on_mounted(path: str = None) -> str:
    """
    Encontra ficheiros recursivamente numa pasta local.
    """
    if path is None:
        path = _EVIDENCE_DIR
    try:
        result_lines = []
        for root, dirs, files in os.walk(path):
            result_lines.append(root)
            for f in files:
                result_lines.append(os.path.join(root, f))
        return "\n".join(result_lines) if result_lines else "(pasta vazia)"
    except Exception as e:
        return f"ERRO find\n{e}"


def grep_recursive(pattern: str, path: str = None) -> str:
    """
    Procura texto recursivamente em ficheiros de texto.
    """
    if path is None:
        path = os.path.join(_PROJECT_ROOT, "agent")
    try:
        matches = []
        for root, dirs, files in os.walk(path):
            for fname in files:
                fpath = os.path.join(root, fname)
                try:
                    with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                        for i, line in enumerate(f, 1):
                            if pattern in line:
                                matches.append(f"{fpath}:{i}: {line.rstrip()}")
                except Exception:
                    pass
        return "\n".join(matches) if matches else "(sem resultados)"
    except Exception as e:
        return f"ERRO grep\n{e}"