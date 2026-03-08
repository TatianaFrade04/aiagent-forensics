import subprocess #modulo python para executar comandos
from typing import List, Optional, Dict, Any


def run_cmd(argv: List[str], timeout: int = 120, env: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    """
    Função reutilizavel para executar um comando Linux 
    Executa um comando Linux de forma segura (sem shell=True).
    Devolve um dicionário com stdout/stderr/returncode (resultado estruturado))
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