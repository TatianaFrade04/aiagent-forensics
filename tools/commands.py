from tools.runner import run_cmd


def list_dir(path: str = "/evidence") -> str:
    r = run_cmd(["ls", "-la", path])
    if r["returncode"] != 0:
        return f"ERRO a listar {path}\n{r['stderr']}"
    return r["stdout"]


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


def find_on_mounted(path: str = "/evidence") -> str:
    """
    Só encontra ficheiros no filesystem do container (ex: o ficheiro .E01).
    NÃO lista conteúdo dentro do E01.
    """
    r = run_cmd(["find", path])
    if r["returncode"] != 0:
        return f"ERRO find\n{r['stderr']}"
    return r["stdout"]


def grep_recursive(pattern: str, path: str = "/app") -> str:
    """
    Procura texto recursivamente em ficheiros reais do container (/app, /tmp, etc).
    Para E01, precisas primeiro extrair ficheiros (fase futura).
    """
    r = run_cmd(["grep", "-R", "-n", pattern, path])
    if r["returncode"] not in (0, 1):  # 1 = não encontrou
        return f"ERRO grep\n{r['stderr']}"
    return r["stdout"] or "(sem resultados)"