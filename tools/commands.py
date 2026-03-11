import os
from datetime import datetime

from tools.runner import run_cmd

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_EVIDENCE_DIR = os.path.join(_PROJECT_ROOT, "evidence")


def list_dir(path: str = None) -> str:
    # paths Linux (ex: /evidence) → correr dentro do container
    if path is not None and path.startswith("/"):
        r = run_cmd(["ls", "-la", path])
        if r["returncode"] != 0:
            return f"ERRO a listar {path}\n{r['stderr']}"
        return r["stdout"]

    # paths Windows → listar localmente
    if path is None:
        path = _EVIDENCE_DIR
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


def mmls_partitions(e01_path: str) -> str:
    r = run_cmd(["mmls", "-i", "ewf", e01_path])
    if r["returncode"] != 0:
        return f"ERRO mmls\n{r['stderr']}"
    return r["stdout"]


def fls_list(e01_path: str, offset: str, directory_inode: str = "") -> str:
    """
    Lista ficheiros via fls usando EWF + offset.
    directory_inode é opcional; se vazio lista a raiz.
    """
    argv = ["fls", "-i", "ewf", "-o", str(offset), e01_path]
    if directory_inode:
        argv.append(directory_inode)

    r = run_cmd(argv)
    if r["returncode"] != 0:
        return f"ERRO fls\n{r['stderr']}"
    return r["stdout"]


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