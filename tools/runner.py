import subprocess
from typing import List, Optional, Dict, Any


def run_cmd(argv: List[str], timeout: int = 120, env: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    """
    Executa um comando Linux de forma segura (sem shell=True).
    Devolve um dicionário com stdout/stderr/returncode.
    """
    result = subprocess.run(
        argv,
        capture_output=True,
        text=True,
        timeout=timeout,
        env=env
    )
    return {
        "argv": argv,
        "returncode": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr
    }