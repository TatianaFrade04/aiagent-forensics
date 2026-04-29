"""
run_tests.py — Automação de testes para AIAgent@forensics
Corre um guião completo de perguntas em vários modelos e sessões.
Coloca este ficheiro na raiz do projecto (ao lado de pyproject.toml).

Uso:
    python run_tests.py
    python run_tests.py --modelos llama3.2 mistral
    python run_tests.py --sessoes 2
    python run_tests.py --modelos qwen2.5:7b --sessoes 1 --debug
"""

import argparse
import json
import os
import socket
import subprocess
import sys
import time
from datetime import datetime

# ─── Gestão do container Docker ──────────────────────────────────────────────

def container_esta_ativo() -> bool:
    r = subprocess.run(
        ["docker", "inspect", "-f", "{{.State.Running}}", "forensics"],
        capture_output=True, text=True
    )
    return r.stdout.strip() == "true"

def parar_container():
    subprocess.run(["docker", "stop", "forensics"], capture_output=True, timeout=30)
    subprocess.run(["docker", "rm",   "forensics"], capture_output=True, timeout=30)
    # Aguarda até o container desaparecer de facto
    for _ in range(20):
        r = subprocess.run(["docker", "inspect", "forensics"], capture_output=True)
        if r.returncode != 0:
            break
        time.sleep(1)

def garantir_container_ativo():
    """Verifica se o container está activo; se não, aguarda até 60s que arranque."""
    for _ in range(60):
        if container_esta_ativo():
            return True
        time.sleep(1)
    return False

# ─── Modelos a testar ─────────────────────────────────────────────────────────

MODELOS_DEFAULT = [
   # "qwen2.5:7b",
    "llama3.2",
    "llama3.1:8b",
    "deepseek-r1:8b",
    "gemma3:4b",
]

SESSOES_DEFAULT = 3

# Contexto máximo seguro por modelo para 12 GB VRAM (Q4 quantization)
# Pesos do modelo + KV cache não devem exceder ~11.5 GB (margem de segurança)
MODEL_CTX_12GB: dict[str, int] = {
    "gemma4:e4b":      131072,  # 4B, GQA com poucos KV heads — KV cache muito eficiente
    "gemma3:4b":        65536,  # 4B standard
    "gemma3:12b":       16384,  # 12B — pesos ~8 GB, pouco espaço para KV cache
    "qwen3.5:4b":       65536,  # 4B
    "qwen2.5:7b":       32768,  # 7B — pesos ~4.5 GB
    "qwen2.5:14b":      16384,  # 14B — pesos ~9 GB
    "llama3.2":         65536,  # 3B (default tag)
    "llama3.2:3b":      65536,  # 3B explícito
    "llama3.1:8b":      32768,  # 8B — pesos ~5 GB
    "llama3.3:70b":      4096,  # 70B quantizado — apenas cabe com ctx mínimo
    "deepseek-r1:8b":   32768,  # 8B reasoning — usa mais memória em inferência
    "mistral":          32768,  # 7B
    "mistral:7b":       32768,  # 7B explícito
}


def ctx_para_modelo(modelo: str) -> int:
    """Devolve o contexto máximo seguro para 12 GB VRAM. Fallback: 32768."""
    return MODEL_CTX_12GB.get(modelo, 32768)

# ─── Guião de perguntas ───────────────────────────────────────────────────────

PERGUNTAS = [
    # Chunk A — Básicas / Factuais
    ("A1", "What is the hostname of the machine?"),
    ("A2", "What version of Windows is installed?"),
    ("A3", "What user accounts exist on the system?"),
    ("A4", "What is the configured timezone of the system?"),
    ("A5", "What was the date and time of the last system boot?"),
    ("A6", "What filesystem is used on the main partition?"),
    ("A7", "What is the IP address and MAC address of the machine?"),
    ("A8", "What antivirus software is or was installed?"),
    # Chunk B — Análise / Investigação
    ("B1", "Which users have or had active sessions on the system?"),
    ("B2", "Are there recently deleted files that can be recovered?"),
    ("B3", "What applications were installed and when?"),
    ("B4", "Is there evidence of suspicious network connections or remote access?"),
    ("B5", "Are there files in unusual locations such as Temp or AppData?"),
    ("B6", "What scheduled tasks exist on the system?"),
    ("B7", "Is there evidence of PowerShell or CMD script execution?"),
    # Chunk C — Pergunta complexa
    ("C1", (
        "Do a complete analysis of user Jimmy Wilson's activity: "
        "what files did he modify recently, what programs did he run, "
        "what is his browsing history, and what USB devices did he use?"
    )),
]

# ─── Helpers ──────────────────────────────────────────────────────────────────

SEPARADOR = "=" * 60   # o teu agente imprime este separador no fim de cada resposta


def modelo_safe(modelo: str) -> str:
    """Converte nome do modelo em string segura para ficheiros."""
    return modelo.replace(":", "-").replace("/", "-")


def extrair_metricas_do_log(texto_resposta: str) -> dict:
    """
    Extrai métricas do bloco [DEBUG] response_metadata que o agente imprime
    quando corre com --debug. Se não houver debug activo, devolve zeros.
    """
    import re
    metricas = {
        "total_duration_ns": 0,
        "prompt_eval_count": 0,
        "eval_count": 0,
        "tool_calls": 0,
    }
    # total_duration
    m = re.search(r"'total_duration':\s*(\d+)", texto_resposta)
    if m:
        metricas["total_duration_ns"] = int(m.group(1))

    # tokens
    m = re.search(r"'prompt_eval_count':\s*(\d+)", texto_resposta)
    if m:
        metricas["prompt_eval_count"] = int(m.group(1))
    m = re.search(r"'eval_count':\s*(\d+)", texto_resposta)
    if m:
        metricas["eval_count"] = int(m.group(1))

    # número de tool calls
    metricas["tool_calls"] = texto_resposta.count("run_forensics_command(")

    return metricas


# ─── Core ─────────────────────────────────────────────────────────────────────

def correr_sessao(modelo: str, sessao: int, ctx: int, debug: bool = False) -> dict:
    """Lança o agente UMA VEZ e envia todas as perguntas em sequência via Popen."""
    print(f"\n{'='*60}")
    print(f"  MODELO: {modelo}  |  CTX: {ctx}  |  SESSÃO: {sessao}/{SESSOES_DEFAULT}")
    print(f"{'='*60}")

    timestamp_inicio = datetime.now().isoformat()
    resultados = []

    env = os.environ.copy()
    env["PYTHONIOENCODING"] = "utf-8"
    env["PYTHONUTF8"] = "1"

    cmd = ["uv", "run", "forensics", "--model", modelo, "--ctx", str(ctx)]
    if debug:
        cmd.append("--debug")

    proc = subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=env,
    )

    # Aguarda arranque
    print("  A arrancar agente...", end="", flush=True)
    deadline = time.time() + 90
    arrancou = False
    while time.time() < deadline:
        linha = proc.stdout.readline()
        if not linha:
            break
        if "Skills" in linha or "Tu:" in linha:
            arrancou = True
            break
        print(".", end="", flush=True)

    if not arrancou:
        proc.kill()
        for id_q, texto_q in PERGUNTAS:
            resultados.append({"id": id_q, "chunk": id_q[0], "pergunta": texto_q,
                "resposta_final": "ERRO: agente nao arrancou", "resposta_raw": "",
                "tempo_segundos": 0.0,
                "metricas_ollama": {"total_duration_ns":0,"prompt_eval_count":0,"eval_count":0,"tool_calls":0}})
        return {"modelo": modelo, "sessao": sessao, "timestamp_inicio": timestamp_inicio,
                "timestamp_fim": datetime.now().isoformat(), "perguntas": resultados,
                "resumo": {"total_perguntas": len(resultados), "tempo_total_segundos": 0,
                           "tempo_medio_segundos": 0, "total_tool_calls": 0}}
    print(" OK")

    for id_q, texto_q in PERGUNTAS:
        print(f"\n  [{id_q}] {texto_q[:70]}{'...' if len(texto_q) > 70 else ''}")
        print(f"  Aguardando resposta...", end="", flush=True)

        inicio = time.time()
        try:
            proc.stdin.write(texto_q + "\n")
            proc.stdin.flush()
        except Exception as e:
            resultados.append({"id": id_q, "chunk": id_q[0], "pergunta": texto_q,
                "resposta_final": f"ERRO: {e}", "resposta_raw": f"ERRO: {e}",
                "tempo_segundos": 0.0,
                "metricas_ollama": {"total_duration_ns":0,"prompt_eval_count":0,"eval_count":0,"tool_calls":0}})
            continue

        # Lê resposta: sep1 -> "Agente: ..." -> sep2
        linhas = []
        resposta_final = ""
        deadline_r = time.time() + 120
        sep_count = 0

        while time.time() < deadline_r:
            linha = proc.stdout.readline()
            if not linha:
                break
            linhas.append(linha.rstrip())
            if linha.startswith("=" * 10):
                sep_count += 1
            if sep_count >= 1 and linha.startswith("Agente:"):
                resposta_final = linha[len("Agente:"):].strip()
            if sep_count >= 2 and resposta_final:
                break

        tempo = time.time() - inicio
        metricas = extrair_metricas_do_log("\n".join(linhas))

        if not resposta_final:
            linhas_uteis = [l for l in linhas if l.strip() and not l.startswith("=") and not l.startswith("[")]
            resposta_final = linhas_uteis[-1] if linhas_uteis else "ERRO: sem resposta"

        perguntas_feitas = len(resultados)
        perguntas_total_sessao = len(PERGUNTAS)
        if perguntas_feitas > 0:
            tempo_medio_ate_agora = sum(r["tempo_segundos"] for r in resultados) / perguntas_feitas
            restantes_sessao = perguntas_total_sessao - perguntas_feitas
            eta_sessao = restantes_sessao * tempo_medio_ate_agora
            print(f" {tempo:.1f}s  |  tool_calls: {metricas['tool_calls']}  |  ETA sessão: ~{int(eta_sessao)}s")
        else:
            print(f" {tempo:.1f}s  |  tool_calls: {metricas['tool_calls']}")

        resultados.append({
            "id": id_q, "chunk": id_q[0], "pergunta": texto_q,
            "resposta_final": resposta_final,
            "resposta_raw": "\n".join(linhas),
            "tempo_segundos": round(tempo, 2),
            "metricas_ollama": metricas,
        })

        # Guarda progresso após cada pergunta (evita perder dados se interrompido)
        tempo_total_parcial = sum(r["tempo_segundos"] for r in resultados)
        guardar_log({
            "modelo": modelo,
            "sessao": sessao,
            "timestamp_inicio": timestamp_inicio,
            "timestamp_fim": datetime.now().isoformat(),
            "perguntas": resultados,
            "resumo": {
                "total_perguntas": len(resultados),
                "tempo_total_segundos": round(tempo_total_parcial, 2),
                "tempo_medio_segundos": round(tempo_total_parcial / len(resultados), 2),
                "total_tool_calls": sum(r["metricas_ollama"]["tool_calls"] for r in resultados),
            },
        })

    # Termina o agente
    try:
        proc.stdin.write("exit\n")
        proc.stdin.flush()
        proc.wait(timeout=30)
    except Exception:
        proc.kill()

def guardar_log(dados: dict, pasta: str = "logs_testes"):
    """Guarda JSON estruturado — inclui hostname do PC na pasta."""
    hostname = socket.gethostname()
    pasta_pc = os.path.join(pasta, hostname)
    os.makedirs(pasta_pc, exist_ok=True)
    ms = modelo_safe(dados["modelo"])
    caminho = f"{pasta_pc}/{ms}_sessao{dados['sessao']}.json"

    with open(caminho, "w", encoding="utf-8") as f:
        json.dump(dados, f, ensure_ascii=False, indent=2)

    print(f"  → Guardado: {caminho}")


# ─── Main ─────────────────────────────────────────────────────────────────────

def parse_args():
    p = argparse.ArgumentParser(description="Automação de testes — AIAgent@forensics")
    p.add_argument("--modelos", nargs="+", default=MODELOS_DEFAULT,
                   help="Lista de modelos a testar")
    p.add_argument("--sessoes", type=int, default=SESSOES_DEFAULT,
                   help=f"Número de sessões por modelo (default: {SESSOES_DEFAULT})")
    p.add_argument("--pasta", default="logs_testes",
                   help="Pasta onde guardar os logs (default: logs_testes/)")
    p.add_argument("--debug", action="store_true",
                   help="Lança o agente em modo debug (mais métricas nos logs)")
    p.add_argument("--apenas-modelo", metavar="MODELO",
                   help="Corre apenas um modelo específico (útil para testes rápidos)")
    p.add_argument("--ctx", type=int, default=None,
                   help="Contexto em tokens (default: auto-detectado por modelo para 12 GB VRAM)")
    return p.parse_args()


def main():
    args = parse_args()

    modelos = [args.apenas_modelo] if args.apenas_modelo else args.modelos
    global SESSOES_DEFAULT
    SESSOES_DEFAULT = args.sessoes

    total = len(modelos) * args.sessoes
    print(f"\n🔬 Bateria de testes — AIAgent@forensics")
    print(f"   Modelos  : {', '.join(modelos)}")
    print(f"   Sessões  : {args.sessoes} por modelo")
    print(f"   Perguntas: {len(PERGUNTAS)} por sessão")
    print(f"   Total    : {total} sessões  ({total * len(PERGUNTAS)} respostas)")
    if args.ctx:
        print(f"   Contexto : {args.ctx} (manual)\n")
    else:
        print(f"   Contexto : auto (12 GB VRAM)\n")

    # Limpar container Docker residual antes de começar
    print("  Limpando container Docker residual...")
    subprocess.run(["docker", "rm", "-f", "forensics"],
                   capture_output=True, text=True)
    print("  OK\n")

    inicio_global = time.time()

    for modelo in modelos:
        ctx = args.ctx if args.ctx else ctx_para_modelo(modelo)
        for sessao in range(1, args.sessoes + 1):
            try:
                dados = correr_sessao(modelo, sessao, ctx=ctx, debug=args.debug)
                guardar_log(dados, pasta=args.pasta)
            except KeyboardInterrupt:
                print("\n[!] Interrompido pelo utilizador.")
                sys.exit(0)
            except Exception as e:
                print(f"\n[ERRO] Modelo {modelo} sessão {sessao}: {e}")
                continue

    duracao = round(time.time() - inicio_global, 1)
    print(f"\n✅ Testes concluídos em {duracao}s")
    print(f"   Logs em: {args.pasta}/")
    print(f"\n   Próximo passo: traz os JSONs ao Claude para gerar gráficos e tabelas.\n")


if __name__ == "__main__":
    main()
