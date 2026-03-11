import subprocess
from typing import List, Optional, Dict, Any

# Binários e comandos que só existem no container Linux
_DOCKER_CONTAINER = "forensics"
_FORENSIC_BINARIES = {"mmls", "fls", "fsstat", "icat", "ils", "ls"}


def run_cmd(argv: List[str], timeout: int = 120, env: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    """
    Executa um comando de forma segura (sem shell=True).
    - Se o binário for uma ferramenta forense (SleuthKit), envia para o container
      Docker via 'docker exec'.
    - Caso contrário, corre localmente no Windows.
    Devolve um dicionário com stdout/stderr/returncode.
    """
    if argv and argv[0] in _FORENSIC_BINARIES:
        # O ficheiro .E01 no Windows está montado em /evidence no container,
        # por isso substituímos o path Windows pelo path Linux equivalente
        translated = []
        for arg in argv:
            if isinstance(arg, str) and (":\\" in arg or arg.startswith("C:/")):
                # converte C:\AIAgentForensics\evidence\foo.E01 -> /evidence/foo.E01
                fname = arg.replace("\\", "/").split("/")[-1]
                arg = f"/evidence/{fname}"
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