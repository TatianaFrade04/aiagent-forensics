"""
tools.py — Ferramentas do agente forense
Executa comandos bash arbitrários dentro do container Docker.
"""

import subprocess
import os
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
    default = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "evidence"))
    return os.getenv("FORENSICS_IMAGE_PATH", default)

FORENSICS_IMAGE_PATH = _load_env_path()

EXPORTS_PATH = os.getenv(
    "EXPORTS_PATH",
    os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "exports"))
)
os.makedirs(EXPORTS_PATH, exist_ok=True)

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
            "--cap-add", "MKNOD",
            "--device", "/dev/loop-control",
            "--device", "/dev/fuse",
            "--device-cgroup-rule", "b 7:* rmw",
            "--network", "none",
            "--memory", "512m",
            "--cpus", "1.0",
            "--security-opt", "seccomp=unconfined",
            "--security-opt", "apparmor=unconfined",
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
    subprocess.run(
        ["docker", "exec", CONTAINER_NAME, "bash", "-c",
         "umount -l /forensics/part* 2>/dev/null; losetup -D 2>/dev/null; umount -l /forensics_ewf 2>/dev/null; true"],
        capture_output=True, timeout=15
    )
    subprocess.run(["docker", "stop", CONTAINER_NAME], capture_output=True)
    subprocess.run(["docker", "rm",   CONTAINER_NAME], capture_output=True)
    print("[+] Container removido.")


# ─── Execução de comandos ─────────────────────────────────────────────────────

MAX_LINES = 100  # Linhas acima deste limite → guarda em ficheiro no container

def run_in_sandbox(command: str) -> str:
    """Executa um comando bash arbitrário dentro do container Docker."""
    command = command.strip()

    # Remove blocos markdown se o LLM os incluir
    if command.startswith("```"):
        lines = command.split("\n")
        command = "\n".join(l for l in lines if not l.startswith("```")).strip()

    if not command:
        return "Erro: comando vazio."

    if not ensure_container_running():
        return "Erro: nao foi possivel iniciar o container."

    docker_cmd = ["docker", "exec", CONTAINER_NAME, "bash", "-c", command]

    for attempt in range(2):
        try:
            result = subprocess.run(
                docker_cmd,
                capture_output=True,
                text=True,
                timeout=60
            )
            stdout = result.stdout
            stderr = result.stderr

            # Detecta erro setns (Docker perde exec após mounts FUSE+loop)
            if "setns" in (stdout + stderr) and attempt == 0:
                print("[!] Erro setns detectado — a reiniciar container...")
                stop_container()
                time.sleep(2)
                if not ensure_container_running():
                    return "Erro: nao foi possivel reiniciar o container."
                continue

            # Constrói output combinado
            output = stdout
            if stderr.strip():
                output += f"\n[stderr]\n{stderr}" if stdout.strip() else stderr

            if not output.strip():
                return "(comando executado sem output)"

            # Output grande: guarda em ficheiro dentro do container
            lines = output.splitlines()
            if len(lines) > MAX_LINES:
                ts = int(time.time())
                out_file = f"/tmp/cmd_output_{ts}.txt"
                subprocess.run(
                    ["docker", "exec", "-i", CONTAINER_NAME, "bash", "-c", f"cat > {out_file}"],
                    input=output,
                    capture_output=True, text=True, timeout=15
                )
                return (
                    f"[Output grande: {len(lines)} linhas — guardado em {out_file}]\n"
                    f"Usa grep, head ou tail para analisar:\n"
                    f"  grep 'keyword' {out_file}\n"
                    f"  head -50 {out_file}\n\n"
                    f"Primeiras {MAX_LINES} linhas:\n" + "\n".join(lines[:MAX_LINES])
                )

            return output

        except subprocess.TimeoutExpired:
            return "Erro: timeout — o comando demorou mais de 60 segundos."
        except Exception as e:
            return f"Erro inesperado: {str(e)}"

    return "Erro: nao foi possivel executar o comando apos reiniciar o container."
