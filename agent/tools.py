"""
tools.py — Ferramentas do agente forense
Executa comandos bash arbitrários dentro do container Docker.
"""

import hashlib
import re
import shlex
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

# Calcula um hash dos ficheiros Docker (Dockerfile + entrypoint.sh)
def _compute_dockerfile_hash() -> str:
    docker_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "docker"))
    h = hashlib.sha256()
    for fname in ("Dockerfile", "entrypoint.sh"):
        fpath = os.path.join(docker_dir, fname)
        if os.path.exists(fpath):
            with open(fpath, "rb") as f:
                h.update(f.read())
    return h.hexdigest()[:16] #16 chars

_HASH_FILE = os.path.join(os.path.dirname(__file__), ".docker_image_hash")
# Localização: agent/.docker_image_hash

# Lê o hash guardado do ficheiro
def _get_stored_hash() -> str:
    if os.path.exists(_HASH_FILE):
        with open(_HASH_FILE) as f:
            return f.read().strip()
    return ""

# Guarda o novo hash em ficheiro
def _store_hash(value: str):
    with open(_HASH_FILE, "w") as f:
        f.write(value)


def start_container(no_mount: bool = False, allow_network: bool = False) -> bool:
    """Destrói qualquer container existente e cria um novo de raiz."""
    rm_result = subprocess.run(["docker", "rm", "-f", CONTAINER_NAME], capture_output=True, text=True)
    if rm_result.returncode != 0 and rm_result.stderr.strip():
        print(f"[!] Warning rm: {rm_result.stderr.strip()}")
    for _ in range(5):
        check = subprocess.run(["docker", "inspect", CONTAINER_NAME], capture_output=True)
        if check.returncode != 0:
            break
        time.sleep(1)
    local_hash = _compute_dockerfile_hash()
    dockerfile_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "docker"))

    img_check = subprocess.run(
        ["docker", "image", "inspect", "forensics-sandbox"],
        capture_output=True
    )
    needs_build = img_check.returncode != 0

    if not needs_build and local_hash != _get_stored_hash():
        print("[!] Docker image outdated — rebuilding automatically...")
        subprocess.run(["docker", "rmi", "forensics-sandbox"], capture_output=True)
        needs_build = True

    if needs_build:
        print("[*] Building 'forensics-sandbox' image...")
        try:
            subprocess.run(
                ["docker", "build", "-t", "forensics-sandbox", dockerfile_dir],
                check=True
            )
            _store_hash(local_hash)
            print("[+] Build complete.")
        except FileNotFoundError:
            print("[!] Docker not found. Check if it is installed.")
            return False
        except subprocess.CalledProcessError as e:
            print(f"[!] Image build error: {e}")
            return False

    if no_mount:
        volume_arg = f"{FORENSICS_IMAGE_PATH}:/forensics:ro"
        print("[*] Direct mode — no forensic image mounting.")
    else:
        volume_arg = f"{FORENSICS_IMAGE_PATH}:/forensics_raw:ro"

    print("[*] Starting forensic container...")
    try:
        if allow_network:
            print("[!] WARNING: container with internet access enabled.")

        docker_run_args = [
            "docker", "run", "-d",
            "--name", CONTAINER_NAME,
            "--cap-add", "SYS_ADMIN",
            "--cap-add", "MKNOD",
            "--device", "/dev/loop-control",
            "--device", "/dev/fuse",
            "--device-cgroup-rule", "b 7:* rmw",
            "--memory", "2g",
            "--cpus", "1.0",
            "--security-opt", "seccomp=unconfined",
            "--security-opt", "apparmor=unconfined",
            "-v", volume_arg,
            "-v", f"{EXPORTS_PATH}:/exports",
        ]
        if not allow_network:
            docker_run_args += ["--network", "none"]
        docker_run_args += ["forensics-sandbox", "sleep", "infinity"]
        subprocess.run(docker_run_args, check=True, capture_output=True)

        if no_mount:
            print("[+] Container started in direct mode!")
        else:
            print("[*] Waiting for forensic image to mount...")
            time.sleep(10)

            check = subprocess.run(
                ["docker", "exec", CONTAINER_NAME, "ls", "/forensics_ewf"],
                capture_output=True, text=True
            )
            if "ewf1" in check.stdout:
                print("[+] Container started and E01 image mounted successfully!")
            else:
                print("[!] Container started but ewf1 not found.")
                print(f"[!] Check with: docker logs {CONTAINER_NAME}")

        return True

    except FileNotFoundError:
        print("[!] Error starting container: Docker not found. Check if it is installed.")
        return False
    except subprocess.CalledProcessError as e:
        print(f"[!] Error starting container: {e.stderr.decode()}")
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
    print("\n[*] Stopping container...")
    subprocess.run(
        ["docker", "exec", CONTAINER_NAME, "bash", "-c",
         "umount -l /forensics/part* 2>/dev/null; losetup -D 2>/dev/null; umount -l /forensics_ewf 2>/dev/null; true"],
        capture_output=True, timeout=15
    )
    subprocess.run(["docker", "stop", CONTAINER_NAME], capture_output=True)
    subprocess.run(["docker", "rm",   CONTAINER_NAME], capture_output=True)
    print("[+] Container removed.")


# ─── Execução de comandos ─────────────────────────────────────────────────────

MAX_LINES = 100  # Linhas acima deste limite → guarda em ficheiro no container

# Apanha: cat [flags] 'path'  /  cat [flags] "path"  /  cat [flags] path
# Apenas um ficheiro, path começa com / ou .
_CAT_PATTERN = re.compile(
    r"""^\s*cat\s+(?:-[A-Za-z]+\s+)*(?:'([^']+)'|"([^"]+)"|(/\S+|\./\S+))\s*$"""
)


def _get_file_meta(path: str) -> tuple[int, str]:
    """Devolve (size_bytes, mime_type) do ficheiro dentro do container."""
    meta_cmd = (
        f"stat -c '%s' {shlex.quote(path)} 2>/dev/null; "
        f"file -b --mime-type {shlex.quote(path)} 2>/dev/null"
    )
    r = subprocess.run(
        ["docker", "exec", CONTAINER_NAME, "bash", "-c", meta_cmd],
        capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=10,
    )
    lines = r.stdout.strip().splitlines()
    try:
        size = int(lines[0].strip())
    except (ValueError, IndexError):
        size = -1
    mime = lines[1].strip() if len(lines) > 1 else "unknown"
    return size, mime


def _intercept_cat(command: str) -> "tuple[str, str] | str | None":
    """
    Interceta comandos `cat path`.

    Retorna:
      (novo_comando, metadata_prefix)  — transforma e continua
      str                              — bloqueia e devolve mensagem directamente
      None                             — não é cat, passa em frente
    """
    m = _CAT_PATTERN.match(command)
    if not m:
        return None

    path = m.group(1) or m.group(2) or m.group(3)
    size, mime = _get_file_meta(path)

    fmt_size = (
        f"{size:,} bytes ({size / 1024:.0f} KB)" if size >= 0 else "tamanho desconhecido"
    )
    meta_note = f"[AUTO-METADATA] path={path} | size={fmt_size} | type={mime}\n"

    # Ficheiro binário — cat bloqueado e redireciona para strings
    if not mime.startswith("text/"):
        return (
            f"{meta_note}"
            f"cat bloqueado — ficheiro binário ({mime}).\n"
            f"Para inspecionar usa:\n"
            f"  xxd {shlex.quote(path)} | head -n 32\n"
            f"  strings -n 8 {shlex.quote(path)} | head -n 100"
        )

    # Texto pequeno (< 10 KB ou tamanho desconhecido) — permite cat
    if size < 0 or size < 10_240:
        return (command, meta_note)

    # Texto médio (10 KB – 500 KB) — transforma em head
    if size < 512_000:
        new_cmd = f"head -n 100 {shlex.quote(path)}"
        note = meta_note + f"[cat → head -n 100: ficheiro tem {size / 1024:.0f} KB]\n"
        return (new_cmd, note)

    # Texto grande (≥ 500 KB) — bloqueia, guia para wc -l / grep
    return (
        f"{meta_note}"
        f"cat bloqueado — ficheiro demasiado grande ({size / 1024 / 1024:.1f} MB).\n"
        f"Verifica primeiro com:\n"
        f"  wc -l {shlex.quote(path)}\n"
        f"  grep -n 'keyword' {shlex.quote(path)} | head -n 100"
    )


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

    # ── Intercepção de cat ────────────────────────────────────────────────────
    intercept = _intercept_cat(command)
    if intercept is not None:
        if isinstance(intercept, str):
            return intercept                      # bloqueado — devolve guia directamente
        command, _meta_prefix = intercept
    else:
        _meta_prefix = ""

    docker_cmd = ["docker", "exec", CONTAINER_NAME, "bash", "-c", command]

    for attempt in range(2):
        try:
            result = subprocess.run(
                docker_cmd,
                capture_output=True,
                text=True,
                encoding='utf-8',
                errors='replace',
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
                return _meta_prefix + "(comando executado sem output)"

            # Output grande: guarda em ficheiro dentro do container
            lines = output.splitlines()
            if len(lines) > MAX_LINES:
                ts = int(time.time())
                out_file = f"/tmp/cmd_output_{ts}.txt"
                save_result = subprocess.run(
                    ["docker", "exec", "-i", CONTAINER_NAME, "bash", "-c", f"cat > {out_file}"],
                    input=output,
                    capture_output=True, text=True, encoding='utf-8',
                    errors='replace', timeout=15
                )
                if save_result.returncode != 0:
                    return (
                        _meta_prefix
                        + f"[Output grande: {len(lines)} linhas — truncado a {MAX_LINES}]\n"
                        + "\n".join(lines[:MAX_LINES])
                    )
                return (
                    _meta_prefix
                    + f"[Output grande: {len(lines)} linhas — guardado em {out_file}]\n"
                    f"Usa grep, head ou tail para analisar:\n"
                    f"  grep 'keyword' {out_file}\n"
                    f"  head -50 {out_file}\n\n"
                    f"Primeiras {MAX_LINES} linhas:\n" + "\n".join(lines[:MAX_LINES])
                )

            return _meta_prefix + output

        except subprocess.TimeoutExpired:
            return "Erro: timeout — o comando demorou mais de 60 segundos."
        except Exception as e:
            return f"Erro inesperado: {str(e)}"

    return "Erro: nao foi possivel executar o comando apos reiniciar o container."
