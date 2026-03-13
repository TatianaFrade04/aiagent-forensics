"""
mcp_server.py — Servidor MCP para AIAgent@forensics
Expõe 12 ferramentas forenses especializadas via Model Context Protocol (stdio).

Execução directa:  python mcp_server.py
(normalmente lançado como subprocesso pelo agente em main.py quando USE_MCP=true)
"""

import sys
import os
import atexit
import re
import subprocess

# Garante que o módulo tools é encontrado (mesmo directório)
sys.path.insert(0, os.path.dirname(__file__))

from mcp.server.fastmcp import FastMCP
from tools import run_in_sandbox, ensure_container_running, CONTAINER_NAME

# ─── Limpeza silenciosa ao terminar ───────────────────────────────────────────

def _silent_stop_container():
    """Para o container silenciosamente (stdout pode estar fechado via stdio)."""
    subprocess.run(["docker", "stop", CONTAINER_NAME], capture_output=True)
    subprocess.run(["docker", "rm",   CONTAINER_NAME], capture_output=True)

atexit.register(_silent_stop_container)

# ─── Helper interno para comandos com pipes ───────────────────────────────────

IMAGE = "/forensics_ewf/ewf1"

_discovered_offset: str | None = None

def _get_offset() -> str:
    """Descobre o offset da partição principal (maior partição de dados) via mmls.
    Lazy com cache — corre uma vez e reutiliza. Fallback para FORENSICS_OFFSET ou 65664."""
    global _discovered_offset
    if _discovered_offset is not None:
        return _discovered_offset
    ensure_container_running()
    try:
        result = subprocess.run(
            ["docker", "exec", CONTAINER_NAME, "sh", "-c", f"mmls {IMAGE}"],
            capture_output=True, text=True, timeout=30
        )
        best_start, best_len = None, 0
        for line in result.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 5:
                try:
                    start  = int(parts[2])
                    length = int(parts[4])
                    if length > best_len:
                        best_start, best_len = str(start), length
                except ValueError:
                    pass
        if best_start:
            _discovered_offset = best_start
            return _discovered_offset
    except Exception:
        pass
    _discovered_offset = os.getenv("FORENSICS_OFFSET", "65664")
    return _discovered_offset


def _exec_shell(shell_cmd: str) -> str:
    """Executa um comando shell complexo no container via 'sh -c'.
    Usado internamente para comandos com pipes — não exposto ao LLM."""
    if not ensure_container_running():
        return "Erro: não foi possível iniciar o container."
    try:
        result = subprocess.run(
            ["docker", "exec", CONTAINER_NAME, "sh", "-c", shell_cmd],
            capture_output=True, text=True, timeout=60
        )
        output = result.stdout + result.stderr
        if len(output) > 4000:
            output = output[:4000] + "\n\n[... output truncado ...]"
        return output if output.strip() else "(comando executado sem output)"
    except subprocess.TimeoutExpired:
        return "Erro: timeout — o comando demorou mais de 60 segundos."
    except Exception as e:
        return f"Erro inesperado: {str(e)}"

def _parse_inode(inode_input) -> tuple:
    """Extrai o número de inode do formato NTFS (ex: '36-144-6' -> '36', ou '936').
    Retorna (inode_str, error_msg). error_msg é None se válido."""
    s = str(inode_input).strip()
    numeric = s.split('-')[0]  # Pega só a parte antes do primeiro '-'
    try:
        val = int(numeric)
        if val <= 0:
            return None, f"Erro: inode inválido ({inode_input}). Deve ser positivo."
        return str(val), None
    except ValueError:
        return None, f"Erro: inode inválido ({inode_input}). Formato esperado: número ou 'número-seq-atrib' (ex: 36 ou 36-144-6)."

def _validate_inode(inode: int) -> str | None:
    """Compatibilidade — usa _parse_inode internamente."""
    _, err = _parse_inode(inode)
    return err

def _sanitize_name(name: str) -> str | None:
    """Sanitiza nome de ficheiro para uso em shell. Retorna None se inválido."""
    if not re.match(r'^[\w\-. ]+$', name, re.UNICODE):
        return None
    return name

# ─── Servidor MCP ─────────────────────────────────────────────────────────────

mcp = FastMCP(
    "forensics-server",
    instructions=(
        "Servidor MCP forense para imagens de disco (Windows NTFS, Linux ext2/3/4). "
        "Imagem montada via ewfmount em /forensics_ewf/ewf1. "
        "O offset da partição principal é descoberto automaticamente via mmls. "
        "Usa as ferramentas especializadas — só usa run_forensics_command como fallback."
    ),
)

# ─── Ferramentas especializadas ────────────────────────────────────────────────

@mcp.tool()
def list_users() -> str:
    """
    Lista os utilizadores do sistema encontrados na imagem forense.
    Funciona com Windows (NTFS) e Linux (ext2/3/4).
    - Windows: descobre e lista a pasta Users dinamicamente
    - Linux: lê /etc/passwd e lista contas com UID >= 1000

    Retorna: lista de utilizadores com os respectivos inodes (Windows)
             ou nomes/home (Linux).
    """
    offset = _get_offset()
    fs_info = _exec_shell(f"fsstat -o {offset} {IMAGE} 2>&1 | head -5")

    if "NTFS" in fs_info:
        # Windows: raiz NTFS = inode 5, procura pasta Users
        root = _exec_shell(f"fls -o {offset} {IMAGE} 5 | grep -i 'Users'")
        m = re.search(r'd/d\s+(\d+)', root)
        if not m:
            return ("Pasta Users não encontrada na raiz.\n"
                    "Listagem da raiz:\n" +
                    _exec_shell(f"fls -o {offset} {IMAGE} 5"))
        users_inode = m.group(1)
        return _exec_shell(f"fls -o {offset} {IMAGE} {users_inode}")
    else:
        # Linux: tenta /etc/passwd primeiro
        passwd_entry = _exec_shell(f"fls -r -o {offset} {IMAGE} 2 | grep -i 'passwd$'")
        m = re.search(r'r/r\s+(\d+)', passwd_entry)
        if m:
            return _exec_shell(
                f"icat -o {offset} {IMAGE} {m.group(1)} | "
                f"awk -F: '$3 >= 1000 && $3 < 65534 {{print $1 \" (uid=\" $3 \", home=\" $6 \")\"}}'")
        # Fallback: lista /home
        home = _exec_shell(f"fls -o {offset} {IMAGE} 2 | grep -i 'home'")
        m = re.search(r'd/d\s+(\d+)', home)
        if m:
            return _exec_shell(f"fls -o {offset} {IMAGE} {m.group(1)}")
        return ("Não foi possível encontrar utilizadores automaticamente.\n"
                "Usa get_filesystem_info() para explorar a estrutura da imagem.")


@mcp.tool()
def list_directory(inode: str) -> str:
    """
    Lista o conteúdo de uma pasta pelo seu inode.

    Parâmetros:
      inode: inode da pasta — aceita formato completo NTFS (ex: '36-144-6') ou só o número ('36')

    Retorna: conteúdo da pasta com tipos (d/ = pasta, r/r = ficheiro regular).
             Formato de cada linha: tipo inode: nome
    """
    inode_num, err = _parse_inode(inode)
    if err:
        return err
    return run_in_sandbox(f"fls -o {_get_offset()} {IMAGE} {inode_num}")


@mcp.tool()
def find_file(name: str) -> str:
    """
    Procura um ficheiro na imagem forense por nome (case-insensitive).

    Parâmetros:
      name: nome ou parte do nome do ficheiro a procurar (ex: "pdf", "R40599", "SAM")

    Retorna: linhas com caminho e inode dos ficheiros encontrados.
             O inode é o número antes do ':' (ex: 'r/r 936-128-3: R40599.pdf' -> inode 936).
    """
    clean = _sanitize_name(name)
    if clean is None:
        return f"Erro: nome '{name}' contém caracteres não permitidos."
    return _exec_shell(f"fls -r -o {_get_offset()} {IMAGE} | grep -i '{clean}'")


@mcp.tool()
def get_file_md5(inode: str) -> str:
    """
    Calcula o hash MD5 de um ficheiro pelo seu inode.

    Parâmetros:
      inode: inode do ficheiro — aceita formato NTFS completo (ex: '936-128-3') ou só o número ('936')

    Retorna: hash MD5 do ficheiro.
    """
    inode_num, err = _parse_inode(inode)
    if err:
        return err
    return _exec_shell(f"icat -o {_get_offset()} {IMAGE} {inode_num} | md5sum")


@mcp.tool()
def get_file_sha1(inode: str) -> str:
    """
    Calcula o hash SHA1 de um ficheiro pelo seu inode.

    Parâmetros:
      inode: inode do ficheiro — aceita formato NTFS completo (ex: '936-128-3') ou só o número ('936')

    Retorna: hash SHA1 do ficheiro (40 caracteres hexadecimais).
    """
    inode_num, err = _parse_inode(inode)
    if err:
        return err
    return _exec_shell(f"icat -o {_get_offset()} {IMAGE} {inode_num} | sha1sum")


@mcp.tool()
def get_file_sha256(inode: str) -> str:
    """
    Calcula o hash SHA256 de um ficheiro pelo seu inode.

    Parâmetros:
      inode: inode do ficheiro — aceita formato NTFS completo (ex: '936-128-3') ou só o número ('936')

    Retorna: hash SHA256 do ficheiro (64 caracteres hexadecimais).
    """
    inode_num, err = _parse_inode(inode)
    if err:
        return err
    return _exec_shell(f"icat -o {_get_offset()} {IMAGE} {inode_num} | sha256sum")


@mcp.tool()
def read_file(inode: str) -> str:
    """
    Lê o conteúdo textual de um ficheiro pelo seu inode (extrai strings legíveis).
    Adequado para ficheiros de texto, documentos, emails, scripts.

    Parâmetros:
      inode: inode do ficheiro — aceita formato NTFS completo (ex: '936-128-3') ou só o número ('936')

    Retorna: conteúdo textual (strings) do ficheiro, truncado a 4000 caracteres.
    """
    inode_num, err = _parse_inode(inode)
    if err:
        return err
    return _exec_shell(f"icat -o {_get_offset()} {IMAGE} {inode_num} | strings")


@mcp.tool()
def get_partitions() -> str:
    """
    Mostra a tabela de partições da imagem forense.
    Usa mmls para listar todas as partições com offsets e tamanhos.

    Retorna: tabela de partições (tipo, offset em sectores, tamanho).
    """
    return run_in_sandbox(f"mmls {IMAGE}")


@mcp.tool()
def get_filesystem_info() -> str:
    """
    Mostra informação detalhada do sistema de ficheiros da partição principal.
    Usa fsstat para identificar o tipo (NTFS, ext2/3/4, FAT, etc.) e metadados.

    Retorna: tipo de filesystem, tamanho de cluster, datas, versão, etc.
    """
    return run_in_sandbox(f"fsstat -o {_get_offset()} {IMAGE}")


@mcp.tool()
def get_file_metadata(inode: str) -> str:
    """
    Obtém metadados completos de um ficheiro: timestamps, tamanho, atributos NTFS.
    Inclui datas de criação, modificação, acesso e alteração de metadados (MACE).

    Parâmetros:
      inode: inode do ficheiro — aceita formato NTFS completo (ex: '936-128-3') ou só o número ('936')

    Retorna: timestamps MACE, tamanho, tipo, atributos, sectores alocados.
    """
    inode_num, err = _parse_inode(inode)
    if err:
        return err
    return _exec_shell(f"istat -o {_get_offset()} {IMAGE} {inode_num}")


@mcp.tool()
def read_email(inode: str) -> str:
    """
    Lê o conteúdo de um ficheiro de email (.eml, .msg, .pst) pelo inode.
    Extrai strings legíveis incluindo cabeçalhos (From, To, Subject, Date),
    timezone, endereços IP e corpo da mensagem.

    Parâmetros:
      inode: inode do ficheiro — aceita formato NTFS completo (ex: '936-128-3') ou só o número ('936')

    Retorna: cabeçalhos e corpo do email (primeiras 150 linhas de strings).
    """
    inode_num, err = _parse_inode(inode)
    if err:
        return err
    return _exec_shell(f"icat -o {_get_offset()} {IMAGE} {inode_num} | strings | head -150")


@mcp.tool()
def list_registry_users(inode: str) -> str:
    """
    Lista os utilizadores no registo Windows (ficheiro SAM) pelo inode.
    Extrai usernames, flags de conta e informação de password (hash NTLM).

    Parâmetros:
      inode: inode do ficheiro SAM — aceita formato NTFS completo ou só o número
             (normalmente em Windows/System32/config/ — usa find_file("SAM") para o obter)

    Retorna: lista de utilizadores do registo com detalhes de conta.
    """
    inode_num, err = _parse_inode(inode)
    if err:
        return err
    return _exec_shell(
        f"icat -o {_get_offset()} {IMAGE} {inode_num} > /tmp/_forensics_SAM && "
        f"chntpw -l /tmp/_forensics_SAM ; "
        f"rm -f /tmp/_forensics_SAM"
    )


@mcp.tool()
def read_event_logs(inode: str) -> str:
    """
    Lê logs de eventos Windows (.evtx) pelo inode do ficheiro de log.

    Parâmetros:
      inode: inode do ficheiro .evtx — aceita formato NTFS completo ou só o número
             (ex: usa find_file("Security.evtx") para obter o inode)

    Retorna: primeiros 200 eventos do log em formato texto.
    """
    inode_num, err = _parse_inode(inode)
    if err:
        return err
    return _exec_shell(
        f"icat -o {_get_offset()} {IMAGE} {inode_num} > /tmp/_forensics_evt.evtx && "
        f"evtx_dump /tmp/_forensics_evt.evtx | head -200 ; "
        f"rm -f /tmp/_forensics_evt.evtx"
    )


@mcp.tool()
def read_registry_key(hive_inode: str, key_path: str) -> str:
    """
    Lê chaves e valores do registo Windows de um ficheiro hive pelo inode.
    Usa hivex para acesso estruturado. Funciona com qualquer hive Windows.

    Parâmetros:
      hive_inode: inode do ficheiro hive (obtém-se com find_file)
      key_path:   caminho da chave no registo (usa \\ como separador)
                  Use "" para listar a raiz do hive.

    Hives comuns e localização (em Windows/System32/config/):
      SAM        -> utilizadores, passwords, última ligação, RIDs
      SYSTEM     -> timezone, serviços, configuração do sistema
      SOFTWARE   -> programas instalados, configurações globais
      SECURITY   -> políticas de segurança, auditoria
      NTUSER.DAT -> por utilizador (em Users/NomeUtilizador/) — preferências,
                    MRU, Run keys, histórico de pesquisa, programas usados

    Exemplos de key_path úteis:
      SAM:        "SAM\\Domains\\Account\\Users\\Names"  -> lista utilizadores
      SYSTEM:     "ControlSet001\\Control\\TimeZoneInformation" -> timezone
      SOFTWARE:   "Microsoft\\Windows\\CurrentVersion\\Uninstall" -> instalados
      NTUSER.DAT: "Software\\Microsoft\\Windows\\CurrentVersion\\Run" -> autorun
      NTUSER.DAT: "Software\\Microsoft\\Internet Explorer\\TypedURLs"  -> URLs

    Retorna: subchaves e valores da chave especificada.
    """
    hive_num, err = _parse_inode(hive_inode)
    if err:
        return err
    if not re.match(r'^[\w\\ \-\.]*$', key_path, re.UNICODE):
        return f"Erro: key_path '{key_path}' contém caracteres não permitidos."

    tmp = "/tmp/_forensics_hive"
    if key_path.strip() == "":
        # Listar raiz
        cmd = (f"icat -o {_get_offset()} {IMAGE} {hive_num} > {tmp} && "
               f"hivexls {tmp} \\ ; rm -f {tmp}")
    else:
        # Listar subchaves da chave especificada
        cmd = (f"icat -o {_get_offset()} {IMAGE} {hive_num} > {tmp} && "
               f"hivexls {tmp} '{key_path}' 2>/dev/null ; "
               f"echo '--- valores ---' ; "
               f"hivexget {tmp} '{key_path}' 2>/dev/null || true ; "
               f"rm -f {tmp}")
    return _exec_shell(cmd)


@mcp.tool()
def run_forensics_command(command: str) -> str:
    """
    Fallback genérico — executa qualquer comando forense no container Docker.
    Usa esta ferramenta apenas quando as ferramentas especializadas não chegarem.

    Comandos disponíveis (whitelist):
      ls, find, stat, file, grep, strings, cat, xxd, hexdump,
      md5sum, sha1sum, sha256sum, chntpw,
      mmls, fsstat, fls, icat, ffind, evtx_dump

    Exemplos:
      fls -r -o OFFSET /forensics_ewf/ewf1         -- lista todos os ficheiros
      icat -o OFFSET /forensics_ewf/ewf1 INODE     -- lê ficheiro pelo inode
      mmls /forensics_ewf/ewf1                     -- tabela de partições
    """
    return run_in_sandbox(command)


# ─── Ponto de entrada ─────────────────────────────────────────────────────────

if __name__ == "__main__":
    mcp.run(transport="stdio")
