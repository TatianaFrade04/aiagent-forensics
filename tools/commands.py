from langchain_core.tools import tool

from tools.runner import run_cmd


@tool
def bash_cmd(command: str, timeout: int = 120) -> str:
    """Executa comandos bash no container forense.
    Aceita comandos simples ou encadeados (&&, ;, |) e corre com `bash -lc`.
    timeout: limite em segundos para a execução."""
    if not isinstance(command, str) or not command.strip():
        return "ERRO bash\nComando vazio."
    if not isinstance(timeout, int) or timeout <= 0:
        return "ERRO bash\nTimeout inválido."

    lower_cmd = command.lower()
    uses_block_tools = any(k in lower_cmd for k in ("lsblk", "fdisk", "parted"))
    references_device = "/dev/" in lower_cmd
    uses_host_user_enum = any(
        k in lower_cmd
        for k in (
            "getent passwd",
            "cat /etc/passwd",
            "awk -f:",
            "cut -d: -f1",
        )
    ) and "icat" not in lower_cmd

    if uses_block_tools and not references_device:
        return (
            "ERRO bash\n"
            "Comandos de partições do host (lsblk/fdisk/parted) não devem ser usados para responder sobre evidência forense. "
            "Para partições, usa: ls -la /evidence e depois mmls -i ewf /evidence/<imagem>.E01"
        )

    if uses_host_user_enum:
        return (
            "ERRO bash\n"
            "Esse comando lista utilizadores do sistema do container, não da imagem forense. "
            "Para utilizadores da imagem, usa: ls -la /evidence; mmls -i ewf /evidence/<imagem>.E01; "
            "e analisa com fls -i ewf -o <offset> ..."
        )

    if "|" in lower_cmd and "grep -r" in lower_cmd:
        return (
            "ERRO bash\n"
            "Não uses `grep -r` em output vindo de pipe. O `-r` faz busca recursiva no filesystem e pode causar erros. "
            "Usa `grep` simples no pipeline (ex.: fls ... | grep '^d/' )."
        )

    # pipefail garante falha correta em pipelines encadeados.
    chained_command = f"set -o pipefail; {command.strip()}"
    r = run_cmd(["bash", "-lc", chained_command], timeout=timeout)
    if r["returncode"] != 0:
        stdout = (r.get("stdout") or "").strip()
        stderr = (r.get("stderr") or "").strip()
        if "binary file matches" in stderr.lower() and "grep" in lower_cmd:
            return (
                "ERRO bash\n"
                "O comando de filtro tentou ler ficheiros/binários no filesystem. "
                "Se estás a filtrar output de outro comando, remove `-r` do grep e usa apenas pipe."
            )
        # Alguns comandos de filtro (ex.: grep sem matches) podem devolver código != 0
        # mesmo quando o output já contém a resposta útil (ex.: "0").
        if stdout and not stderr:
            return stdout
        return f"ERRO bash\n{stderr or 'comando falhou'}"

    return (r.get("stdout") or "").strip()