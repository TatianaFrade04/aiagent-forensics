"""
tools.py — Ferramentas do agente forense
Executa comandos dentro do container Docker de forma segura e controlada.
"""

import subprocess
import shlex
import os
import re
import time

# ─── Configuração ─────────────────────────────────────────────────────────────

CONTAINER_NAME = "forensics"

# Carrega o .env manualmente para evitar problemas com backslashes
def _load_env_path():
    env_file = os.path.join(os.path.dirname(__file__), ".env")
    if os.path.exists(env_file):
        with open(env_file, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line.startswith("FORENSICS_IMAGE_PATH="):
                    return line.split("=", 1)[1].strip()
    # Default: pasta evidence/ relativa a este ficheiro (../evidence)
    default = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "evidence"))
    return os.getenv("FORENSICS_IMAGE_PATH", default)

FORENSICS_IMAGE_PATH = _load_env_path()

# Pasta de exportações — dentro do container é sempre /exports (bind mount).
# No host usa ./exports/ relativo à raiz do projecto.
EXPORTS_PATH = os.getenv(
    "EXPORTS_PATH",
    os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "exports"))
)
os.makedirs(EXPORTS_PATH, exist_ok=True)

# Comandos permitidos (whitelist de segurança)
ALLOWED_COMMANDS = [
    "ls", "find", "stat", "file",
    "grep", "strings", "cat", "xxd", "hexdump",
    "md5sum", "sha1sum", "sha256sum",
    "chntpw",
    "mmls", "fsstat", "fls", "icat", "ffind",
    "evtx_dump",
]

# ─── Gestão do container ──────────────────────────────────────────────────────

def start_container() -> bool:
    """Destrói qualquer container existente e cria um novo de raiz."""
    rm_result = subprocess.run(["docker", "rm", "-f", CONTAINER_NAME], capture_output=True, text=True)
    if rm_result.returncode != 0 and rm_result.stderr.strip():
        print(f"[!] Aviso rm: {rm_result.stderr.strip()}")
    for _ in range(5):
        check = subprocess.run(["docker", "inspect", CONTAINER_NAME], capture_output=True)
        if check.returncode != 0:
            break
        time.sleep(1)
    print("[*] A iniciar container forense...")
    try:
        docker_run_args = [
            "docker", "run", "-d",
            "--name", CONTAINER_NAME,
            "--cap-add", "SYS_ADMIN",
            "--network", "none",
            "--memory", "512m",
            "--cpus", "1.0",
            "--security-opt", "seccomp=unconfined",
            "--security-opt", "apparmor=unconfined",
            "--device", "/dev/loop-control",
            "--device", "/dev/fuse",
            "-v", f"{FORENSICS_IMAGE_PATH}:/forensics_raw:ro",
            "-v", f"{EXPORTS_PATH}:/exports",
        ]
        docker_run_args += ["forensics-sandbox", "sleep", "infinity"]
        subprocess.run(docker_run_args, check=True, capture_output=True)

        print("[*] A aguardar montagem da imagem forense...")
        time.sleep(10)

        check = subprocess.run(
            ["docker", "exec", CONTAINER_NAME, "ls", "/forensics_ewf"],
            capture_output=True, text=True
        )
        if "ewf1" in check.stdout:
            print("[+] Container iniciado e imagem E01 montada com sucesso!")
        else:
            print("[!] Container iniciado mas ewf1 nao encontrado.")
            print(f"[!] Verifica com: docker logs {CONTAINER_NAME}")

        return True

    except subprocess.CalledProcessError as e:
        print(f"[!] Erro ao iniciar container: {e.stderr.decode()}")
        return False


def ensure_container_running() -> bool:
    """Verifica se o container está activo. Se não, inicia-o."""
    try:
        result = subprocess.run(
            ["docker", "inspect", "-f", "{{.State.Running}}", CONTAINER_NAME],
            capture_output=True, text=True
        )
        if result.stdout.strip() == "true":
            return True
    except Exception:
        pass

    return start_container()


def stop_container():
    """Para e remove o container (chamado no fecho do programa)."""
    print("\n[*] A parar container...")
    # Desmonta os filesystems antes de parar o container.
    # Sem esta etapa, os mounts FUSE(nivel 2) (ewfmount) e NTFS(nivel3) (losetup+mount) ficam
    # activos no kernel, impedindo o SIGKILL de terminar o container — deixando-o
    # em estado zombie e impossível de remover na próxima execução.
    # -l (lazy): desliga o mount do directório imediatamente, sem forçar processos.
    subprocess.run(
        ["docker", "exec", CONTAINER_NAME, "bash", "-c",
         "umount -l /forensics/part* 2>/dev/null; losetup -D 2>/dev/null; umount -l /forensics_ewf 2>/dev/null; true"],
        capture_output=True, timeout=15
    )
    subprocess.run(["docker", "stop", CONTAINER_NAME], capture_output=True)
    subprocess.run(["docker", "rm",   CONTAINER_NAME], capture_output=True)
    print("[+] Container removido.")


# ─── Execução de comandos ─────────────────────────────────────────────────────

def run_in_sandbox(command: str) -> str:
    """Executa um comando forense dentro do container Docker."""
    command = command.strip()

    # Remove blocos markdown se o LLM os incluir
    if command.startswith("```"):
        lines = command.split("\n")
        command = "\n".join(l for l in lines if not l.startswith("```")).strip()

    try:
        parts = shlex.split(command)
    except ValueError as e:
        return f"Erro ao interpretar comando: {e}"

    if not parts:
        return "Erro: comando vazio."

    # Heurística: se parece que o path /forensics foi partido por espaços não-escapados,
    # rejunta os fragmentos (ex: ["cat", "/forensics/.../Jimmy", "Wilson/file"] → ["cat", "/forensics/.../Jimmy Wilson/file"])
    if len(parts) > 2 and parts[1].startswith("/forensics") and not parts[2].startswith("-"):
        parts = [parts[0], " ".join(parts[1:])]

    # Remove backslash-escapes dos argumentos (ex: O\ Death.txt → O Death.txt)
    parts = [parts[0]] + [re.sub(r'\\(.)', r'\1', p) for p in parts[1:]]

    base_cmd = parts[0]
    if base_cmd not in ALLOWED_COMMANDS:
        return (
            f"Erro: comando '{base_cmd}' nao permitido.\n"
            f"Comandos disponiveis: {', '.join(ALLOWED_COMMANDS)}"
        )

    if not ensure_container_running():
        return "Erro: nao foi possivel iniciar o container."

    # Reconstrói o comando com quoting correcto para preservar espaços em paths
    safe_cmd = " ".join(shlex.quote(p) for p in parts)
    docker_cmd = ["docker", "exec", CONTAINER_NAME, "bash", "-c", safe_cmd]

    for attempt in range(2):
        try:
            result = subprocess.run(
                docker_cmd,
                capture_output=True,
                text=True,
                timeout=60
            )
            output = result.stdout + result.stderr

            # Detecta erro setns (Docker Desktop perde exec após mounts FUSE+loop)
            #setns = set namespace — é uma syscall do Linux kernel.
            if "setns" in output and attempt == 0:
                print("[!] Erro setns detectado — a reiniciar container...")
                stop_container()
                time.sleep(2)
                if not ensure_container_running():
                    return "Erro: nao foi possivel reiniciar o container."
                continue

            # Auto-recovery: se cat falha com "No such file", tenta find + cat
            if base_cmd == "cat" and "No such file or directory" in output and len(parts) >= 2:
                filename = os.path.basename(parts[-1])
                if filename and os.path.splitext(filename)[1]:
                    find_result = subprocess.run(
                        ["docker", "exec", CONTAINER_NAME, "bash", "-c",
                         f"find /forensics/part006 -iname {shlex.quote(filename)} 2>/dev/null | head -1"],
                        capture_output=True, text=True, timeout=30
                    ).stdout.strip()
                    if find_result:
                        cat_result = subprocess.run(
                            ["docker", "exec", CONTAINER_NAME, "bash", "-c",
                             f"cat {shlex.quote(find_result)}"],
                            capture_output=True, text=True, timeout=30
                        )
                        out = cat_result.stdout + cat_result.stderr
                        if out.strip():
                            return f"[{find_result}]\n{out}"

            MAX_CHARS = 4000
            if len(output) > MAX_CHARS:
                output = output[:MAX_CHARS] + "\n\n[... output truncado ...]"

            return output if output.strip() else "(comando executado sem output)"

        except subprocess.TimeoutExpired:
            return "Erro: timeout — o comando demorou mais de 60 segundos."
        except Exception as e:
            return f"Erro inesperado: {str(e)}"

    return "Erro: nao foi possivel executar o comando apos reiniciar o container."


# ─── Funções forenses estruturadas ───────────────────────────────────────────

def list_directory_names(dir_path: str, export_filename: str = "listagem.txt") -> str:
    """
    Lista apenas os nomes (sem metadados) dos ficheiros e pastas imediatamente
    dentro de dir_path, um nome por linha, e guarda em EXPORTS_PATH/<export_filename>.

    Usa: find <dir_path> -maxdepth 1 -mindepth 1 -printf '%f\\n'
    O output é escrito directamente em Python no host via o bind mount —
    nunca através de redirection gerada pelo agente.
    """
    # Validações de segurança
    dir_path = dir_path.rstrip("/")
    if not dir_path.startswith("/forensics"):
        return "[!] BLOCKED: dir_path must be under /forensics."
    export_filename = os.path.basename(export_filename)  # impede path traversal
    if not export_filename:
        return "[!] export_filename must not be empty."

    if not ensure_container_running():
        return "[!] Erro: nao foi possivel iniciar o container."

    # Verifica que o path existe e é uma directoria
    kind_result = subprocess.run(
        ["docker", "exec", CONTAINER_NAME, "bash", "-c",
         f"if [ -d {shlex.quote(dir_path)} ]; then echo dir; "
         f"elif [ -e {shlex.quote(dir_path)} ]; then echo file; "
         f"else echo missing; fi"],
        capture_output=True, text=True, timeout=10,
    )
    kind = kind_result.stdout.strip()
    if kind == "missing":
        return f"[!] ERROR: '{dir_path}' does not exist inside the container."
    if kind == "file":
        return (
            f"[!] ERROR: '{dir_path}' is a file, not a directory. "
            "Provide a directory path."
        )

    # Executa find dentro do container com -printf '%f\n' → apenas nome base
    find_result = subprocess.run(
        ["docker", "exec", CONTAINER_NAME, "bash", "-c",
         f"find {shlex.quote(dir_path)} -maxdepth 1 -mindepth 1 -printf '%f\\n' "
         f"| sort 2>/dev/null"],
        capture_output=True, text=True, timeout=30,
    )
    names = find_result.stdout.strip()

    if not names:
        stderr = find_result.stderr.strip()
        return (
            f"[!] No entries found in '{dir_path}'."
            + (f"\nstderr: {stderr}" if stderr else "")
        )

    # Valida que o output não contém metadados (permissões, datas, tamanhos)
    suspicious = [
        line for line in names.splitlines()
        if re.match(r'^[-drwx]{9}\s', line)   # ls -l style permissions
        or re.match(r'^\d{4}-\d{2}-\d{2}', line)  # timestamps
        or line.startswith("/")               # caminhos absolutos
    ]
    if suspicious:
        return (
            "[!] VALIDATION FAILED: output contains metadata or absolute paths.\n"
            f"  Unexpected lines: {suspicious[:3]}\n"
            "  This is a bug — report it instead of saving the file."
        )

    # Escreve directamente em Python no host (sem shell redirection)
    dest = os.path.join(EXPORTS_PATH, export_filename)
    try:
        with open(dest, "w", encoding="utf-8") as fh:
            fh.write(names + "\n")
    except OSError as e:
        return f"[!] Erro ao escrever ficheiro de exportação: {e}"

    # Verificação final
    size = os.path.getsize(dest)
    line_count = names.count("\n") + 1
    return (
        f"[\u2713] Export verified: '/exports/{export_filename}' "
        f"({size} bytes, {line_count} entries).\n"
        f"First entries:\n"
        + "\n".join(names.splitlines()[:10])
        + ("\n[...]" if line_count > 10 else "")
    )


def export_file_content(file_path: str, export_filename: str) -> str:
    """
    Reads the content of a single file from inside the container and writes
    it to EXPORTS_PATH/<export_filename> on the host via the bind mount.
    """
    file_path = file_path.rstrip("/")
    if not file_path.startswith("/forensics"):
        return "[!] BLOCKED: file_path must be under /forensics."
    export_filename = os.path.basename(export_filename)  # impede path traversal
    if not export_filename:
        return "[!] export_filename must not be empty."

    if not ensure_container_running():
        return "[!] Erro: nao foi possivel iniciar o container."

    # Verifica que o path existe e é um ficheiro
    kind_result = subprocess.run(
        ["docker", "exec", CONTAINER_NAME, "bash", "-c",
         f"if [ -f {shlex.quote(file_path)} ]; then echo file; "
         f"elif [ -e {shlex.quote(file_path)} ]; then echo other; "
         f"else echo missing; fi"],
        capture_output=True, text=True, timeout=10,
    )
    kind = kind_result.stdout.strip()
    if kind == "missing":
        return f"[!] ERROR: '{file_path}' does not exist inside the container."
    if kind == "other":
        return f"[!] ERROR: '{file_path}' is not a regular file."

    # Lê o conteúdo do ficheiro via docker exec (binário-safe via base64)
    read_result = subprocess.run(
        ["docker", "exec", CONTAINER_NAME, "bash", "-c",
         f"cat {shlex.quote(file_path)} | base64"],
        capture_output=True, timeout=60,
    )
    if read_result.returncode != 0:
        err = read_result.stderr.decode(errors="replace").strip()
        return f"[!] ERROR reading file: {err}"

    import base64
    try:
        raw_bytes = base64.b64decode(read_result.stdout)
    except Exception as e:
        return f"[!] ERROR decoding file content: {e}"

    dest = os.path.join(EXPORTS_PATH, export_filename)
    try:
        with open(dest, "wb") as fh:
            fh.write(raw_bytes)
    except OSError as e:
        return f"[!] Erro ao escrever ficheiro de exportação: {e}"

    size = os.path.getsize(dest)
    return (
        f"[\u2713] Export verified: '/exports/{export_filename}' ({size} bytes).\n"
        f"Source: {file_path}"
    )
