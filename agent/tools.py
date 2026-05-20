"""
tools.py — Forensic agent tools
Executes arbitrary bash commands inside the Docker container.
"""

import hashlib
import re
import shlex
import subprocess
import os
import time

# ─── Configuration ────────────────────────────────────────────────────────────

CONTAINER_NAME = "forensics"

# Load .env manually to avoid issues with backslashes
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

# ─── Container management ─────────────────────────────────────────────────────

# Hash of Docker files (Dockerfile + entrypoint.sh) to detect image changes
def _compute_dockerfile_hash() -> str:
    docker_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "docker"))
    h = hashlib.sha256()
    for fname in ("Dockerfile", "entrypoint.sh"):
        fpath = os.path.join(docker_dir, fname)
        if os.path.exists(fpath):
            with open(fpath, "rb") as f:
                h.update(f.read())
    return h.hexdigest()[:16]

_HASH_FILE = os.path.join(os.path.dirname(__file__), ".docker_image_hash")

def _get_stored_hash() -> str:
    if os.path.exists(_HASH_FILE):
        with open(_HASH_FILE) as f:
            return f.read().strip()
    return ""

def _store_hash(value: str):
    with open(_HASH_FILE, "w") as f:
        f.write(value)


def start_container(no_mount: bool = False, allow_network: bool = False) -> bool:
    """Destroy any existing container and create a fresh one."""
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
                # Verify that at least one partition was mounted
                parts_check = subprocess.run(
                    ["docker", "exec", CONTAINER_NAME, "ls", "/forensics/"],
                    capture_output=True, text=True
                )
                if not parts_check.stdout.strip():
                    print("[!] Warning: no partition mounted in /forensics/ — showing entrypoint log:")
                    logs = subprocess.run(
                        ["docker", "logs", CONTAINER_NAME],
                        capture_output=True, text=True
                    )
                    output = (logs.stdout or "") + (logs.stderr or "")
                    print(output[-3000:] if len(output) > 3000 else output)
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
    """Check if the container is running. If not, start it."""
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
    """Stop and remove the container."""
    print("\n[*] Stopping container...")
    subprocess.run(
        ["docker", "exec", CONTAINER_NAME, "bash", "-c",
         "umount -l /forensics/part* 2>/dev/null; losetup -D 2>/dev/null; umount -l /forensics_ewf 2>/dev/null; true"],
        capture_output=True, timeout=15
    )
    subprocess.run(["docker", "stop", CONTAINER_NAME], capture_output=True)
    subprocess.run(["docker", "rm",   CONTAINER_NAME], capture_output=True)
    print("[+] Container removed.")


# ─── Command execution ────────────────────────────────────────────────────────

MAX_LINES = 100   # Lines above this limit → save to file inside container
MAX_CHARS = 20_000  # Characters — long lines (SQLite, cache) can exceed MAX_LINES

# Matches: cat [flags] 'path' / cat [flags] "path" / cat [flags] path
# Single file only, path starts with / or .
_CAT_PATTERN = re.compile(
    r"""^\s*cat\s+(?:-[A-Za-z]+\s+)*(?:'([^']+)'|"([^"]+)"|(/\S+|\./\S+))\s*$"""
)


def _get_file_meta(path: str) -> tuple[int, str]:
    """Return (size_bytes, mime_type) for a file inside the container."""
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
    Intercept `cat path` commands.

    Returns:
      (new_command, metadata_prefix)  — transform and continue
      str                             — block and return message directly
      None                            — not a cat command, pass through
    """
    m = _CAT_PATTERN.match(command)
    if not m:
        return None

    path = m.group(1) or m.group(2) or m.group(3)
    size, mime = _get_file_meta(path)

    fmt_size = (
        f"{size:,} bytes ({size / 1024:.0f} KB)" if size >= 0 else "unknown size"
    )
    meta_note = f"[AUTO-METADATA] path={path} | size={fmt_size} | type={mime}\n"

    # Binary file — block cat and redirect to strings
    if not mime.startswith("text/"):
        return (
            f"{meta_note}"
            f"cat blocked — binary file ({mime}).\n"
            f"To inspect use:\n"
            f"  xxd {shlex.quote(path)} | head -n 32\n"
            f"  strings -n 8 {shlex.quote(path)} | head -n 100"
        )

    # Small text (< 10 KB or unknown size) — allow cat
    if size < 0 or size < 10_240:
        return (command, meta_note)

    # Medium text (10 KB – 500 KB) — transform to head
    if size < 512_000:
        new_cmd = f"head -n 100 {shlex.quote(path)}"
        note = meta_note + f"[cat → head -n 100: file is {size / 1024:.0f} KB]\n"
        return (new_cmd, note)

    # Large text (≥ 500 KB) — block, guide to wc -l / grep
    return (
        f"{meta_note}"
        f"cat blocked — file too large ({size / 1024 / 1024:.1f} MB).\n"
        f"Check first with:\n"
        f"  wc -l {shlex.quote(path)}\n"
        f"  grep -n 'keyword' {shlex.quote(path)} | head -n 100"
    )


def run_in_sandbox(command: str) -> str:
    """Execute an arbitrary bash command inside the Docker container."""
    command = command.strip()

    # Strip markdown code blocks if the LLM includes them
    if command.startswith("```"):
        lines = command.split("\n")
        command = "\n".join(l for l in lines if not l.startswith("```")).strip()

    if not command:
        return "Error: empty command."

    if not ensure_container_running():
        return "Error: could not start container."

    # ── cat interception ──────────────────────────────────────────────────────
    intercept = _intercept_cat(command)
    if intercept is not None:
        if isinstance(intercept, str):
            return intercept
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

            # Detect setns error (Docker loses exec after FUSE+loop mounts)
            if "setns" in (stdout + stderr) and attempt == 0:
                print("[!] setns error detected — restarting container...")
                stop_container()
                time.sleep(2)
                if not ensure_container_running():
                    return "Error: could not restart container."
                continue

            # Build combined output
            output = stdout
            if stderr.strip():
                output += f"\n[stderr]\n{stderr}" if stdout.strip() else stderr

            if not output.strip():
                return _meta_prefix + "(command executed with no output)"

            # Large output: save to file inside container
            lines = output.splitlines()
            if len(lines) > MAX_LINES or len(output) > MAX_CHARS:
                ts = int(time.time())
                out_file = f"/tmp/cmd_output_{ts}.txt"
                save_result = subprocess.run(
                    ["docker", "exec", "-i", CONTAINER_NAME, "bash", "-c", f"cat > {out_file}"],
                    input=output,
                    capture_output=True, text=True, encoding='utf-8',
                    errors='replace', timeout=15
                )
                # Preview: first MAX_LINES lines, capped at MAX_CHARS total
                preview_lines = lines[:MAX_LINES]
                preview = "\n".join(preview_lines)
                if len(preview) > MAX_CHARS:
                    preview = preview[:MAX_CHARS] + "\n[... truncated — use the file above]"
                size_info = f"{len(lines)} lines / {len(output):,} chars"
                if save_result.returncode != 0:
                    return (
                        _meta_prefix
                        + f"[Large output: {size_info} — truncated]\n"
                        + preview
                    )
                return (
                    _meta_prefix
                    + f"[Large output: {size_info} — saved to {out_file}]\n"
                    f"Use grep, head or tail to analyse:\n"
                    f"  grep 'keyword' {out_file}\n"
                    f"  head -50 {out_file}\n\n"
                    f"First lines:\n" + preview
                )

            return _meta_prefix + output

        except subprocess.TimeoutExpired:
            return "Error: timeout — command took more than 60 seconds."
        except Exception as e:
            return f"Unexpected error: {str(e)}"

    return "Error: could not execute command after restarting container."
