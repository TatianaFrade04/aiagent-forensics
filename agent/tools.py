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

CONTAINER_NAME = "forensics_sandbox"

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
            "--privileged",
            "--network", "none",
            "--memory", "512m",
            "--cpus", "1.0",
            "--security-opt", "seccomp=unconfined",
            "--security-opt", "apparmor=unconfined",
            "-v", f"{FORENSICS_IMAGE_PATH}:/forensics_raw:ro",
        ]
        # No Linux o FUSE( Filesystem in Userspace) precisa de acesso explícito ao dispositivo /dev/fuse.
        # No Windows (Docker Desktop) este dispositivo não existe no host — ignorar.
        if os.path.exists("/dev/fuse"):
            docker_run_args += ["--device", "/dev/fuse"]
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
