"""
tools.py — Ferramentas do agente forense
Executa comandos dentro do container Docker de forma segura e controlada.
"""

import subprocess
import shlex
import os
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
    return os.getenv("FORENSICS_IMAGE_PATH", r"C:\\forensics-agent\\forensics_image")
FORENSICS_IMAGE_PATH = _load_env_path() or os.getenv(
    "FORENSICS_IMAGE_PATH",
    r"C:\forensics-agent\forensics_image"
)

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

def ensure_container_running() -> bool:
    """Garante que o container está activo com a imagem montada."""
    try:
        result = subprocess.run(
            ["docker", "inspect", "-f", "{{.State.Running}}", CONTAINER_NAME],
            capture_output=True, text=True
        )
        if result.stdout.strip() == "true":
            return True
    except Exception:
        pass

    print("[*] A iniciar container forense...")
    try:
        # O entrypoint.sh corre automaticamente e faz ewfmount
        # "sleep infinity" é o CMD que mantém o container vivo depois do entrypoint
        subprocess.run([
            "docker", "run", "-d",
            "--name", CONTAINER_NAME,
            "--privileged",
            "--network", "none",
            "--memory", "512m",
            "--cpus", "1.0",
            "-v", f"{FORENSICS_IMAGE_PATH}:/forensics_raw:ro",
            "forensics-sandbox",
            "sleep", "infinity"
        ], check=True, capture_output=True)

        # Aguarda o entrypoint terminar (ewfmount pode demorar alguns segundos)
        print("[*] A aguardar montagem da imagem forense...")
        time.sleep(10)

        # Confirma que o ewfmount correu
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


def stop_container():
    """Para e remove o container (chamado no fecho do programa)."""
    print("\n[*] A parar container...")
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

    base_cmd = parts[0]
    if base_cmd not in ALLOWED_COMMANDS:
        return (
            f"Erro: comando '{base_cmd}' nao permitido.\n"
            f"Comandos disponiveis: {', '.join(ALLOWED_COMMANDS)}"
        )

    if not ensure_container_running():
        return "Erro: nao foi possivel iniciar o container."

    docker_cmd = ["docker", "exec", CONTAINER_NAME] + parts

    try:
        result = subprocess.run(
            docker_cmd,
            capture_output=True,
            text=True,
            timeout=60
        )
        output = result.stdout + result.stderr

        MAX_CHARS = 4000
        if len(output) > MAX_CHARS:
            output = output[:MAX_CHARS] + f"\n\n[... output truncado ...]"

        return output if output.strip() else "(comando executado sem output)"

    except subprocess.TimeoutExpired:
        return "Erro: timeout — o comando demorou mais de 60 segundos."
    except Exception as e:
        return f"Erro inesperado: {str(e)}"
