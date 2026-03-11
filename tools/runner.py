import os
import subprocess
from typing import List, Optional, Dict, Any

# Binários e comandos que só existem no container Linux
_DOCKER_CONTAINER = "forensics"
_FORENSIC_BINARIES = {"mmls", "fls", "fsstat", "icat", "ils", "ls"}

# Pasta de evidências: Windows → container
_EVIDENCE_WIN = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "evidence")
_EVIDENCE_CONTAINER = "/evidence"


def _translate_path(arg: str) -> str:
    """Converte um path Windows da pasta evidence para o path equivalente no container."""
    if arg.lower().startswith(_EVIDENCE_WIN.lower()):
        relative = arg[len(_EVIDENCE_WIN):].replace("\\", "/").lstrip("/")
        return f"{_EVIDENCE_CONTAINER}/{relative}" if relative else _EVIDENCE_CONTAINER
    # fallback: usa apenas o nome do ficheiro
    return f"{_EVIDENCE_CONTAINER}/{arg.replace(chr(92), '/').split('/')[-1]}"


def run_cmd(argv: List[str], timeout: int = 120, env: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    """
    Executa um comando de forma segura (sem shell=True).
    - Se o binário for uma ferramenta forense (SleuthKit), envia para o container
      Docker via 'docker exec'.
    - Caso contrário, corre localmente no Windows.
    Devolve um dicionário com stdout/stderr/returncode.
    """
    if argv and argv[0] in _FORENSIC_BINARIES:
        translated = []
        for arg in argv:
            if isinstance(arg, str) and (":\\" in arg or arg.startswith("C:/")):
                arg = _translate_path(arg)
            translated.append(arg)
        final_argv = ["docker", "exec", _DOCKER_CONTAINER] + translated
    else:
        final_argv = argv

    result = subprocess.run(
        final_argv,
        capture_output=True,
        text=True,
        timeout=timeout,
        env=env
    )
    return {
        "argv": final_argv,
        "returncode": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr
    }