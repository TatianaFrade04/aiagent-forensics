"""
run_ctf.py — Testes CTF com scoring automático para AIAgent@forensics
Usa as 25 perguntas do Case Study com respostas conhecidas (ground truth).
Corre na raiz do projecto: python run_ctf.py

Uso:
    python run_ctf.py
    python run_ctf.py --modelos qwen3.5:4b mistral
    python run_ctf.py --apenas-modelo qwen3.5:4b
"""

import argparse
import atexit
import json
import os
import signal
import subprocess
import sys
import time
import threading
from datetime import datetime

# ─── Cleanup garantido (Ctrl+C, SIGTERM, SSH drop) ────────────────────────────

_current_proc = None

def _cleanup():
    global _current_proc
    if _current_proc and _current_proc.poll() is None:
        _current_proc.kill()
    subprocess.run(["docker", "rm", "-f", "forensics"], capture_output=True)

atexit.register(_cleanup)
signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
signal.signal(signal.SIGINT,  lambda *_: sys.exit(0))
if hasattr(signal, "SIGHUP"):
    signal.signal(signal.SIGHUP, lambda *_: sys.exit(0))

# ─── Modelos a testar ─────────────────────────────────────────────────────────

MODELOS_DEFAULT = [
    "gemma4:e4b",
    "qwen3.5:4b",
    "qwen2.5:7b",
    "llama3.1:8b",
]

SESSOES_DEFAULT = 3

# ─── Perguntas CTF com ground truth ──────────────────────────────────────────
# Formato: (id, pergunta_para_agente, resposta_correta, tipo)
# tipo: "mc" = múltipla escolha, "tf" = verdadeiro/falso
# Para múltipla escolha a resposta_correta é a letra (a/b/c/...)
# Para verdadeiro/falso é "true" ou "false"

PERGUNTAS_CTF = [
    (
        "Q1",
        'What is the destination time zone offset in the first Received header of the email file 447018D5-00000006.eml? Choose from: a) +04:00  b) -07:00  c) -08:00  d) -05:00  e) -09:00. Reply with only the letter.',
        "c",
        "mc",
    ),
    (
        "Q2",
        'True or False: The total capacity in bytes of the "J. Wilson" partition in System.vhd is 734,003,200. Reply with only "true" or "false".',
        "true",
        "tf",
    ),
    (
        "Q3",
        'What was the date and time the email "447018D5-00000006.eml" received by Jimmy Wilson was originally sent? Choose from: a) Sun, 16 February 2014 10:55:09 -05:00  b) Sun, 16 February 2014 07:55:09 -05:00  c) Sun, 16 February 2014 12:55:09 -05:00  d) Sun, 16 February 2014 11:55:09 -05:00  e) Sun, 16 February 2014 13:55:09 -05:00. Reply with only the letter.',
        "c",
        "mc",
    ),
    (
        "Q6",
        'True or False: On February 20, 2014 at 17:02:35 UTC, the system uptime in seconds was 9,634. Reply with only "true" or "false".',
        "true",
        "tf",
    ),
    (
        "Q7",
        'True or False: The MD5 hash value of the pdf.pdf file is C1F95108A34228535A9262085E784D7C3E27FC68. Reply with only "true" or "false".',
        "false",
        "tf",
    ),
    (
        "Q8",
        'True or False: The user account Jimmy Wilson has his logon password enabled and the password hint is "safeone". Reply with only "true" or "false".',
        "true",
        "tf",
    ),
    (
        "Q10",
        'True or False: The final destination IP address for the email "447018D5-00000006.eml" received by Jimmy Wilson is 10.221.48.196. Reply with only "true" or "false".',
        "true",
        "tf",
    ),
    (
        "Q12",
        "What is the logical size in bytes (decimal) of the pdf.pdf file? Choose from: a) 444,332  b) 433,994  c) 395,232  d) 253,283. Reply with only the letter.",
        "b",
        "mc",
    ),
    (
        "Q13",
        'True or False: The user account BillyBob sent the following files to the $recyclebin: "New Price List.txt" and "New Price List Encoded". Reply with only "true" or "false".',
        "true",
        "tf",
    ),
    (
        "Q14",
        "What is the logical file size in bytes (decimal) of the PLEAS.txt file? Choose from: a) 110,592  b) 122,336  c) 122,880  d) 108,227. Reply with only the letter.",
        "b",
        "mc",
    ),
    (
        "Q15",
        "What is the full name of the user that has the RID number 0x3EB? Choose from: a) Administrator  b) Betty Boop  c) Joe T. Nameless  d) BillyBob  e) Guest. Reply with only the letter.",
        "c",
        "mc",
    ),
    (
        "Q16",
        'When was the last login date and time for the user "Jimmy Wilson"? Choose from: a) February 18, 2014 12:38:16 UTC  b) January 19, 2014 06:22:12 UTC  c) March 03, 2014 11:11:11 UTC  d) None of these times are correct  e) February 19, 2014 13:30:58 UTC  f) April 01, 2014 00:00:01 UTC  g) February 17, 2014 17:38:22 UTC. Reply with only the letter.',
        "d",
        "mc",
    ),
    (
        "Q17",
        'True or False: jose.Badguy@hushmail.com and robert.ripoff@gmx.com sent emails to the user Jimmy Wilson. Reply with only "true" or "false".',
        "true",
        "tf",
    ),
    (
        "Q18",
        "What program did the user Jimmy Wilson have set to run when he logged on to the computer? Choose from: a) None of the other answers are correct  b) Notepad.exe  c) StinkyNot.exe  d) MSAccess.exe  e) MSWord.exe. Reply with only the letter.",
        "c",
        "mc",
    ),
    (
        "Q19",
        'True or False: The SHA1 hash value for the AISB08.pdf file is BDEBF09E8B2D404D1C483C3EBFB8AD37C780D909. Reply with only "true" or "false".',
        "true",
        "tf",
    ),
    (
        "Q20",
        "What encryption programs were used on this computer? Choose from: a) Veracrypt/BitLocker  b) BitLocker/Veracrypt  c) File Vault/Truecrypt  d) BCTextEncoder/Veracrypt  e) No encryption programs were used  f) Truecrypt/BCTextEncoder. Reply with only the letter.",
        "d",
        "mc",
    ),
    (
        "Q22",
        'True or False: The SHA1 hash value for the Card Printers.htm file is F6CF04DB3D1BA828E375BBFE988876CE06164126. Reply with only "true" or "false".',
        "true",
        "tf",
    ),
    (
        "Q23",
        'What search engine did the user "Jimmy Wilson" use to search for "how to steal identities"? Choose from: a) Yahoo  b) Bing  c) DuckDuckGo  d) Dogpile  e) Google. Reply with only the letter.',
        "b",
        "mc",
    ),
    (
        "Q24",
        'What is the last date and time the user "Jimmy Wilson" ran the Windows Mail Application? Choose from: a) Sat, 25 January 2014 15:27:51 UTC  b) Sat, 25 January 2014 19:27:51 UTC  c) Sat, 25 January 2014 18:27:51 UTC  d) Sat, 25 January 2014 17:27:51 UTC  e) Sat, 25 January 2014 16:27:51 UTC. Reply with only the letter.',
        "c",
        "mc",
    ),
]

# ─── Helpers ──────────────────────────────────────────────────────────────────

def modelo_safe(modelo: str) -> str:
    return modelo.replace(":", "-").replace("/", "-")


def extrair_resposta_modelo(texto: str, tipo: str) -> str:
    """Extrai a resposta do modelo (letra ou true/false) do texto de resposta."""
    import re

    # Procura na linha "Agente: ..."
    for linha in texto.splitlines():
        if linha.startswith("Agente:"):
            texto = linha[len("Agente:"):].strip()
            break

    texto_lower = texto.lower().strip()

    if tipo == "tf":
        if texto_lower.startswith("true"):
            return "true"
        if texto_lower.startswith("false"):
            return "false"
        if "true" in texto_lower[:50]:
            return "true"
        if "false" in texto_lower[:50]:
            return "false"
        return texto_lower[:20]

    if tipo == "mc":
        # Tenta extrair letra simples no início
        m = re.match(r"^\s*([a-g])\b", texto_lower)
        if m:
            return m.group(1)
        # Tenta "the answer is X" ou "answer: X"
        m = re.search(r"(?:answer is|answer:|correct answer is|correct:)\s*([a-g])\b", texto_lower)
        if m:
            return m.group(1)
        # Última tentativa: primeira letra isolada
        m = re.search(r"\b([a-g])\b", texto_lower[:100])
        if m:
            return m.group(1)
        return texto_lower[:10]

    return texto_lower[:20]


def avaliar_resposta(resposta_modelo: str, resposta_correta: str, tipo: str) -> bool:
    extraida = extrair_resposta_modelo(resposta_modelo, tipo)
    return extraida.strip().lower() == resposta_correta.strip().lower()


def extrair_metricas_do_log(texto: str) -> dict:
    import re
    metricas = {"total_duration_ns": 0, "prompt_eval_count": 0, "eval_count": 0, "tool_calls": 0}
    m = re.search(r"'total_duration':\s*(\d+)", texto)
    if m:
        metricas["total_duration_ns"] = int(m.group(1))
    m = re.search(r"'prompt_eval_count':\s*(\d+)", texto)
    if m:
        metricas["prompt_eval_count"] = int(m.group(1))
    m = re.search(r"'eval_count':\s*(\d+)", texto)
    if m:
        metricas["eval_count"] = int(m.group(1))
    metricas["tool_calls"] = texto.count("run_forensics_command(")
    return metricas


def guardar_log(dados: dict, pasta: str = "logs_ctf"):
    os.makedirs(pasta, exist_ok=True)
    ms = modelo_safe(dados["modelo"])
    caminho = f"{pasta}/{ms}_sessao{dados['sessao']}.json"
    with open(caminho, "w", encoding="utf-8") as f:
        json.dump(dados, f, ensure_ascii=False, indent=2)
    print(f"  → Guardado: {caminho}")


# ─── Core ─────────────────────────────────────────────────────────────────────

def correr_sessao_ctf(modelo: str, sessao: int, debug: bool = False) -> dict:
    """Lança o agente uma vez e envia todas as perguntas CTF em sequência."""
    print(f"\n{'='*60}")
    print(f"  MODELO: {modelo}  |  SESSÃO: {sessao}/{SESSOES_DEFAULT}")
    print(f"{'='*60}")

    timestamp_inicio = datetime.now().isoformat()
    resultados = []

    env = os.environ.copy()
    env["PYTHONIOENCODING"] = "utf-8"
    env["PYTHONUTF8"] = "1"

    cmd = ["uv", "run", "forensics", "--model", modelo]
    if debug:
        cmd.append("--debug")

    global _current_proc
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
    _current_proc = proc

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
        for id_q, pergunta, correta, tipo in PERGUNTAS_CTF:
            resultados.append({
                "id": id_q, "pergunta": pergunta, "resposta_correta": correta,
                "tipo": tipo, "resposta_modelo_raw": "ERRO: agente nao arrancou",
                "resposta_extraida": "", "correto": False,
                "tempo_segundos": 0.0, "metricas_ollama": {"total_duration_ns":0,"prompt_eval_count":0,"eval_count":0,"tool_calls":0}
            })
        return _resumo(modelo, sessao, timestamp_inicio, resultados)
    print(" OK")

    for idx, (id_q, pergunta, correta, tipo) in enumerate(PERGUNTAS_CTF):
        print(f"\n  [{id_q}] {pergunta[:65]}...")
        print(f"  Aguardando resposta...", end="", flush=True)

        inicio = time.time()
        try:
            proc.stdin.write(pergunta + "\n")
            proc.stdin.flush()
        except Exception as e:
            resultados.append({
                "id": id_q, "pergunta": pergunta, "resposta_correta": correta,
                "tipo": tipo, "resposta_modelo_raw": f"ERRO: {e}",
                "resposta_extraida": "", "correto": False,
                "tempo_segundos": 0.0, "metricas_ollama": {"total_duration_ns":0,"prompt_eval_count":0,"eval_count":0,"tool_calls":0}
            })
            continue

        # Lê stdout em thread separada para não perder nada
        linhas = []
        ultima_agente_ref = [""]
        fim_evento = threading.Event()

        def ler_stdout():
            sep_count = 0
            ultima_agente = ""
            try:
                for linha in proc.stdout:
                    linhas.append(linha.rstrip())
                    if linha.startswith("=" * 10):
                        sep_count += 1
                    if linha.startswith("Agente:"):
                        ultima_agente = linha
                        ultima_agente_ref[0] = linha
                    # Detecta fim: separador depois de termos visto Agente:
                    if sep_count >= 1 and ultima_agente and linha.startswith("=" * 10):
                        fim_evento.set()
                        return
            except Exception:
                pass
            fim_evento.set()

        t = threading.Thread(target=ler_stdout, daemon=True)
        t.start()
        fim_evento.wait(timeout=600)  # 10 min máximo
        agente_linha = ultima_agente_ref[0]

        tempo = time.time() - inicio
        resposta_raw = "\n".join(linhas)
        metricas = extrair_metricas_do_log(resposta_raw)

        resposta_extraida = extrair_resposta_modelo(agente_linha or resposta_raw, tipo)
        correto = avaliar_resposta(agente_linha or resposta_raw, correta, tipo)

        # Calcula ETA
        perguntas_feitas = idx + 1
        tempo_medio = sum(r["tempo_segundos"] for r in resultados) / max(len(resultados), 1)
        restantes = len(PERGUNTAS_CTF) - perguntas_feitas
        eta = int(restantes * tempo_medio) if resultados else 0

        status = "✅" if correto else "❌"
        print(f" {tempo:.1f}s  |  {status} (extraído: '{resposta_extraida}', correcto: '{correta}')  |  ETA: ~{eta}s")

        resultados.append({
            "id": id_q,
            "pergunta": pergunta,
            "resposta_correta": correta,
            "tipo": tipo,
            "resposta_modelo_raw": agente_linha,
            "resposta_extraida": resposta_extraida,
            "correto": correto,
            "tempo_segundos": round(tempo, 2),
            "metricas_ollama": metricas,
        })

        # Guarda progresso após cada pergunta
        guardar_log(_resumo(modelo, sessao, timestamp_inicio, resultados))

    # Termina agente
    try:
        proc.stdin.write("exit\n")
        proc.stdin.flush()
        proc.wait(timeout=30)
    except Exception:
        proc.kill()

    return _resumo(modelo, sessao, timestamp_inicio, resultados)


def _resumo(modelo, sessao, timestamp_inicio, resultados):
    corretas = sum(1 for r in resultados if r.get("correto", False))
    total = len(resultados)
    tempo_total = sum(r["tempo_segundos"] for r in resultados)
    return {
        "modelo": modelo,
        "sessao": sessao,
        "timestamp_inicio": timestamp_inicio,
        "timestamp_fim": datetime.now().isoformat(),
        "perguntas": resultados,
        "resumo": {
            "total_perguntas": total,
            "corretas": corretas,
            "incorretas": total - corretas,
            "score_percentagem": round(corretas / total * 100, 1) if total else 0,
            "tempo_total_segundos": round(tempo_total, 2),
            "tempo_medio_segundos": round(tempo_total / total, 2) if total else 0,
            "total_tool_calls": sum(r["metricas_ollama"]["tool_calls"] for r in resultados),
        },
    }


# ─── Main ─────────────────────────────────────────────────────────────────────

def parse_args():
    p = argparse.ArgumentParser(description="CTF scoring — AIAgent@forensics")
    p.add_argument("--modelos", nargs="+", default=MODELOS_DEFAULT)
    p.add_argument("--sessoes", type=int, default=SESSOES_DEFAULT)
    p.add_argument("--pasta", default="logs_ctf")
    p.add_argument("--debug", action="store_true")
    p.add_argument("--apenas-modelo", metavar="MODELO")
    return p.parse_args()


def main():
    args = parse_args()
    modelos = [args.apenas_modelo] if args.apenas_modelo else args.modelos
    sessoes = args.sessoes

    total = len(modelos) * sessoes
    print(f"\n🔬 CTF Scoring — AIAgent@forensics")
    print(f"   Modelos  : {', '.join(modelos)}")
    print(f"   Sessões  : {sessoes} por modelo")
    print(f"   Perguntas: {len(PERGUNTAS_CTF)} (com ground truth)")
    print(f"   Total    : {total} sessões\n")

    # Limpar container residual
    print("  Limpando container Docker residual...")
    subprocess.run(["docker", "rm", "-f", "forensics"], capture_output=True, text=True)
    print("  OK\n")

    inicio_global = time.time()
    todos_resultados = []

    for modelo in modelos:
        for sessao in range(1, sessoes + 1):
            try:
                dados = correr_sessao_ctf(modelo, sessao, debug=args.debug)
                guardar_log(dados, pasta=args.pasta)
                todos_resultados.append(dados)

                r = dados["resumo"]
                print(f"\n  📊 {modelo} sessão {sessao}: {r['corretas']}/{r['total_perguntas']} ({r['score_percentagem']}%)")

            except KeyboardInterrupt:
                print("\n[!] Interrompido.")
                sys.exit(0)
            except Exception as e:
                print(f"\n[ERRO] {modelo} sessão {sessao}: {e}")
                continue

    # Tabela final
    duracao = round(time.time() - inicio_global, 1)
    print(f"\n{'='*60}")
    print(f"  RESULTADOS FINAIS")
    print(f"{'='*60}")
    print(f"  {'Modelo':<20} {'Score':>8} {'Corretas':>10} {'Tempo médio':>12}")
    print(f"  {'-'*52}")
    for d in todos_resultados:
        r = d["resumo"]
        print(f"  {d['modelo']:<20} {r['score_percentagem']:>7}%  {r['corretas']:>4}/{r['total_perguntas']:<4}  {r['tempo_medio_segundos']:>8.1f}s")
    print(f"\n✅ Concluído em {duracao}s  |  Logs em: {args.pasta}/\n")


if __name__ == "__main__":
    main()
