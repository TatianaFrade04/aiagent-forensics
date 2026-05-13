"""
run_ctf_temperaturas.py — Testes CTF com scoring automático variando temperature

Uso:
    python run_ctf_temperaturas.py
    python run_ctf_temperaturas.py --modelo gemma4:26b --temperaturas 0.0 0.1 0.3 0.7 1.0
    python run_ctf_temperaturas.py --modelo qwen3.5:4b --sessoes 3 --limpar-contexto
"""

import argparse
import atexit
import json
import os
import re
import signal
import subprocess
import sys
import time
from datetime import datetime

_project_root = os.path.abspath(os.path.dirname(__file__))
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

from langchain_ollama import ChatOllama
from langchain_core.messages import AIMessage, HumanMessage, SystemMessage, ToolMessage
from langchain.agents import create_agent

from agent.tools import start_container
from agent.main import auto_detect_evidence, build_system_prompt, TOOLS
from agent.skills import load_skills, select_skills, format_skills_context


def _cleanup_orphan_loops():
    try:
        result = subprocess.run(["losetup", "-a"], capture_output=True, text=True, timeout=5)
        for line in result.stdout.splitlines():
            if "ewf1" in line and line.split(":")[1].strip().startswith("[]:"):
                dev = line.split(":")[0].strip()
                subprocess.run(["sudo", "losetup", "-d", dev], capture_output=True)
    except Exception:
        pass


def _cleanup_container():
    subprocess.run(
        [
            "docker", "exec", "forensics", "bash", "-c",
            "umount -l /forensics/part* 2>/dev/null; "
            "losetup -D 2>/dev/null; "
            "umount -l /forensics_ewf 2>/dev/null; true",
        ],
        capture_output=True,
        timeout=15,
    )
    subprocess.run(["docker", "stop", "--time", "10", "forensics"], capture_output=True)
    subprocess.run(["docker", "rm", "-f", "forensics"], capture_output=True)

    for _ in range(10):
        check = subprocess.run(["docker", "inspect", "forensics"], capture_output=True)
        if check.returncode != 0:
            break
        time.sleep(1)

    _cleanup_orphan_loops()


def _cleanup():
    _cleanup_container()


atexit.register(_cleanup)
signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
signal.signal(signal.SIGINT, lambda *_: sys.exit(0))
if hasattr(signal, "SIGHUP"):
    signal.signal(signal.SIGHUP, lambda *_: sys.exit(0))


MODELO_DEFAULT = "gemma4:26b"

TEMPERATURAS_DEFAULT = [
    0.0,
    0.1,
    0.2,
    0.3,
    0.5,
    0.7,
    1.0,
]

SESSOES_DEFAULT = 3

MODEL_CTX_12GB: dict[str, int] = {
    "gemma4:e4b": 131072,
    "gemma3:4b": 65536,
    "gemma3:12b": 16384,
    "qwen3.5:4b": 65536,
    "qwen2.5:7b": 32768,
    "qwen2.5:14b": 16384,
    "qwen3:8b": 65536,
    "llama3.2": 65536,
    "llama3.2:3b": 65536,
    "llama3.1:8b": 32768,
    "llama3.3:70b": 4096,
    "deepseek-r1:8b": 32768,
    "mistral": 32768,
    "mistral:7b": 32768,
    "gemma4:26b": 8192,
    "gemma4:27b": 8192,
}

MODELOS_COM_THINKING = {
    "gemma4:e4b", "gemma4:12b", "gemma4:26b", "gemma4:27b",
    "qwen3.5:4b", "qwen3:4b", "qwen3:8b", "qwen3:14b",
    "deepseek-r1:8b", "deepseek-r1:14b", "deepseek-r1:32b",
}


PERGUNTAS_CTF = [
    ("Q1", 'What is the destination time zone offset in the first Received header of the email file 447018D5-00000006.eml? Choose from: a) +04:00  b) -07:00  c) -08:00  d) -05:00  e) -09:00. Reply with only the letter.', "c", "mc"),
    ("Q2", 'True or False: The total capacity in bytes of the "J. Wilson" partition in System.vhd is 734,003,200. Reply with only "true" or "false".', "true", "tf"),
    ("Q3", 'What was the date and time the email "447018D5-00000006.eml" received by Jimmy Wilson was originally sent? Choose from: a) Sun, 16 February 2014 10:55:09 -05:00  b) Sun, 16 February 2014 07:55:09 -05:00  c) Sun, 16 February 2014 12:55:09 -05:00  d) Sun, 16 February 2014 11:55:09 -05:00  e) Sun, 16 February 2014 13:55:09 -05:00. Reply with only the letter.', "c", "mc"),
    ("Q6", 'True or False: On February 20, 2014 at 17:02:35 UTC, the system uptime in seconds was 9,634. Reply with only "true" or "false".', "true", "tf"),
    ("Q7", 'True or False: The MD5 hash value of the pdf.pdf file is C1F95108A34228535A9262085E784D7C3E27FC68. Reply with only "true" or "false".', "false", "tf"),
    ("Q8", 'True or False: The user account Jimmy Wilson has his logon password enabled and the password hint is "safeone". Reply with only "true" or "false".', "true", "tf"),
    ("Q10", 'True or False: The final destination IP address for the email "447018D5-00000006.eml" received by Jimmy Wilson is 10.221.48.196. Reply with only "true" or "false".', "true", "tf"),
    ("Q12", "What is the logical size in bytes (decimal) of the pdf.pdf file? Choose from: a) 444,332  b) 433,994  c) 395,232  d) 253,283. Reply with only the letter.", "b", "mc"),
    ("Q13", 'True or False: The user account BillyBob sent the following files to the $recyclebin: "New Price List.txt" and "New Price List Encoded". Reply with only "true" or "false".', "true", "tf"),
    ("Q14", "What is the logical file size in bytes (decimal) of the PLEAS.txt file? Choose from: a) 110,592  b) 122,336  c) 122,880  d) 108,227. Reply with only the letter.", "b", "mc"),
    ("Q15", "What is the full name of the user that has the RID number 0x3EB? Choose from: a) Administrator  b) Betty Boop  c) Joe T. Nameless  d) BillyBob  e) Guest. Reply with only the letter.", "c", "mc"),
    ("Q16", 'When was the last login date and time for the user "Jimmy Wilson"? Choose from: a) February 18, 2014 12:38:16 UTC  b) January 19, 2014 06:22:12 UTC  c) March 03, 2014 11:11:11 UTC  d) None of these times are correct  e) February 19, 2014 13:30:58 UTC  f) April 01, 2014 00:00:01 UTC  g) February 17, 2014 17:38:22 UTC. Reply with only the letter.', "d", "mc"),
    ("Q17", 'True or False: jose.Badguy@hushmail.com and robert.ripoff@gmx.com sent emails to the user Jimmy Wilson. Reply with only "true" or "false".', "true", "tf"),
    ("Q18", "What program did the user Jimmy Wilson have set to run when he logged on to the computer? Choose from: a) None of the other answers are correct  b) Notepad.exe  c) StinkyNot.exe  d) MSAccess.exe  e) MSWord.exe. Reply with only the letter.", "c", "mc"),
    ("Q19", 'True or False: The SHA1 hash value for the AISB08.pdf file is BDEBF09E8B2D404D1C483C3EBFB8AD37C780D909. Reply with only "true" or "false".', "true", "tf"),
    ("Q20", "What encryption programs were used on this computer? Choose from: a) Veracrypt/BitLocker  b) BitLocker/Veracrypt  c) File Vault/Truecrypt  d) BCTextEncoder/Veracrypt  e) No encryption programs were used  f) Truecrypt/BCTextEncoder. Reply with only the letter, read all options before reply.", "f", "mc"),
    ("Q22", 'True or False: The SHA1 hash value for the Card Printers.htm file is F6CF04DB3D1BA828E375BBFE988876CE06164126. Reply with only "true" or "false".', "true", "tf"),
    ("Q23", 'What search engine did the user "Jimmy Wilson" use to search for "how to steal identities"? Choose from: a) Yahoo  b) Bing  c) DuckDuckGo  d) Dogpile  e) Google. Reply with only the letter.', "b", "mc"),
    ("Q24", 'What is the last date and time the user "Jimmy Wilson" ran the Windows Mail Application? Choose from: a) Sat, 25 January 2014 15:27:51 UTC  b) Sat, 25 January 2014 19:27:51 UTC  c) Sat, 25 January 2014 18:27:51 UTC  d) Sat, 25 January 2014 17:27:51 UTC  e) Sat, 25 January 2014 16:27:51 UTC. Reply with only the letter.', "c", "mc"),
]


def ctx_para_modelo(modelo: str) -> int:
    return MODEL_CTX_12GB.get(modelo, 32768)


def suporta_thinking(modelo: str) -> bool:
    return modelo in MODELOS_COM_THINKING


def modelo_safe(modelo: str) -> str:
    return modelo.replace(":", "-").replace("/", "-")


def temp_safe(temperatura: float) -> str:
    return str(temperatura).replace(".", "p").replace("-", "m")


def extrair_resposta_modelo(texto: str, tipo: str) -> str:
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
        m = re.match(r"^\s*([a-g])\b", texto_lower)
        if m:
            return m.group(1)
        m = re.search(r"(?:answer is|answer:|correct answer is|correct:)\s*([a-g])\b", texto_lower)
        if m:
            return m.group(1)
        m = re.search(r"\b([a-g])\b", texto_lower[:100])
        if m:
            return m.group(1)
        return texto_lower[:10]

    return texto_lower[:20]


def avaliar_resposta(resposta_modelo: str, resposta_correta: str, tipo: str) -> bool:
    extraida = extrair_resposta_modelo(resposta_modelo, tipo)
    return extraida.strip().lower() == resposta_correta.strip().lower()


def _extrair_metricas_msgs(msgs: list) -> dict:
    metricas = {
        "total_duration_ns": 0,
        "prompt_eval_count": 0,
        "eval_count": 0,
        "tool_calls": 0,
    }

    for msg in msgs:
        if isinstance(msg, AIMessage):
            meta = getattr(msg, "response_metadata", {}) or {}
            metricas["total_duration_ns"] += meta.get("total_duration", 0)
            metricas["prompt_eval_count"] += meta.get("prompt_eval_count", 0)
            metricas["eval_count"] += meta.get("eval_count", 0)
            metricas["tool_calls"] += len(getattr(msg, "tool_calls", None) or [])

    return metricas


def guardar_log(dados: dict, pasta: str = "logs_ctf_temperaturas", run_ts: str = ""):
    os.makedirs(pasta, exist_ok=True)

    ms = modelo_safe(dados["modelo"])
    temp = temp_safe(dados.get("temperatura", 0.0))
    ts = f"_{run_ts}" if run_ts else ""
    limpo = "_contexto_limpo" if dados.get("limpar_contexto") else ""

    caminho = f"{pasta}/{ms}_temp{temp}_sessao{dados['sessao']}{limpo}{ts}.json"

    with open(caminho, "w", encoding="utf-8") as f:
        json.dump(dados, f, ensure_ascii=False, indent=2)

    print(f"  → Guardado: {caminho}")


def _llm_content(msg) -> str:
    if not msg:
        return ""

    c = msg.content if isinstance(msg.content, str) else str(msg.content)

    if not c.strip():
        c = (getattr(msg, "additional_kwargs", {}) or {}).get("reasoning_content", "") or ""

    return c


def _invocar_agente(agent, conversation: list, debug: bool = False) -> list:
    new_messages = []

    try:
        for chunk in agent.stream({"messages": conversation}, {"recursion_limit": 999}):
            for node_output in chunk.values():
                for msg in node_output.get("messages", []):
                    new_messages.append(msg)

                    if debug:
                        if isinstance(msg, AIMessage):
                            raw = msg.content if isinstance(msg.content, str) else ""
                            visible = re.sub(r"<think>.*?</think>", "", raw, flags=re.DOTALL).strip()
                            tool_calls = getattr(msg, "tool_calls", None) or []

                            print(f"  [AIMessage] {visible[:300]!r}")

                            for tc in tool_calls:
                                print(f"    → {tc['name']}({tc['args']})")

                        elif isinstance(msg, ToolMessage):
                            out = msg.content[:300] if isinstance(msg.content, str) else str(msg.content)[:300]
                            print(f"  [ToolMessage] {out!r}")

    except Exception as e:
        print(f"\n  [!] Erro no agente: {e}")

    return new_messages


def _resumo(
    modelo: str,
    temperatura: float,
    sessao: int,
    timestamp_inicio: str,
    resultados: list,
    ctx: int = 0,
    limpar_contexto: bool = False,
):
    corretas = sum(1 for r in resultados if r.get("correto", False))
    total = len(resultados)
    tempo_total = sum(r["tempo_segundos"] for r in resultados)

    return {
        "modelo": modelo,
        "temperatura": temperatura,
        "ctx": ctx,
        "limpar_contexto": limpar_contexto,
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


def correr_sessao_ctf(
    modelo: str,
    temperatura: float,
    sessao: int,
    ctx: int,
    debug: bool = False,
    run_ts: str = "",
    limpar_contexto: bool = False,
    pasta: str = "logs_ctf_temperaturas",
) -> dict:
    print(f"\n{'=' * 70}")
    print(f"  MODELO: {modelo}  |  TEMP: {temperatura}  |  CTX: {ctx}  |  SESSÃO: {sessao}")
    modo_str = "contexto limpo entre perguntas" if limpar_contexto else "contexto normal"
    print(f"  MODO: {modo_str}")
    print(f"{'=' * 70}")

    timestamp_inicio = datetime.now().isoformat()
    t_wall_inicio = time.time()
    resultados = []

    print("  A iniciar container...", end="", flush=True)
    start_container()
    print(" OK")

    print("  A detectar partição de evidência...", end="", flush=True)
    evidence = auto_detect_evidence()
    print(f" {evidence}")

    system_prompt = build_system_prompt(evidence)
    all_skills = load_skills()

    llm = ChatOllama(
        model=modelo,
        temperature=temperatura,
        num_ctx=ctx,
        reasoning=suporta_thinking(modelo),
    )

    agent = create_agent(model=llm, tools=TOOLS)

    conversation = [SystemMessage(content=system_prompt)]

    for idx, (id_q, pergunta, correta, tipo) in enumerate(PERGUNTAS_CTF):
        print(f"\n  [{id_q}] {pergunta[:65]}...")

        if limpar_contexto:
            conversation = [SystemMessage(content=system_prompt)]

        selected = select_skills(pergunta, all_skills, max_skills=2)
        skills_context = format_skills_context(selected, evidence)

        if selected and debug:
            print(f"  [Skills: {', '.join(s.name for s in selected)}]")

        conversation[0] = SystemMessage(
            content=system_prompt + (
                "\nMANDATORY FORENSIC PROCEDURES — copy these scripts EXACTLY into run_forensics_command when the task matches. "
                "Do NOT write your own commands when a procedure is provided:\n"
                + skills_context
                + "\n"
                if skills_context
                else ""
            )
        )

        conversation.append(HumanMessage(content=pergunta))

        print("  A aguardar resposta...", end="", flush=True)
        inicio = time.time()

        new_messages = _invocar_agente(agent, conversation, debug=debug)
        conversation.extend(new_messages)

        tempo = time.time() - inicio

        answer = next(
            (
                m for m in reversed(new_messages)
                if isinstance(m, AIMessage) and not (getattr(m, "tool_calls", None) or [])
            ),
            None,
        )

        content = _llm_content(answer)
        metricas = _extrair_metricas_msgs(new_messages)

        resposta_extraida = extrair_resposta_modelo(content, tipo)
        correto = avaliar_resposta(content, correta, tipo)

        perguntas_feitas = idx + 1
        tempo_medio = sum(r["tempo_segundos"] for r in resultados) / max(len(resultados), 1)
        restantes = len(PERGUNTAS_CTF) - perguntas_feitas
        eta = int(restantes * tempo_medio) if resultados else 0

        status = "✅" if correto else "❌"

        print(
            f" {tempo:.1f}s  |  {status} "
            f"(extraído: '{resposta_extraida}', correcto: '{correta}')  |  ETA: ~{eta}s"
        )

        resultados.append({
            "id": id_q,
            "pergunta": pergunta,
            "resposta_correta": correta,
            "tipo": tipo,
            "resposta_modelo_raw": content,
            "resposta_extraida": resposta_extraida,
            "correto": correto,
            "tempo_segundos": round(tempo, 2),
            "metricas_ollama": metricas,
        })

        guardar_log(
            _resumo(
                modelo=modelo,
                temperatura=temperatura,
                sessao=sessao,
                timestamp_inicio=timestamp_inicio,
                resultados=resultados,
                ctx=ctx,
                limpar_contexto=limpar_contexto,
            ),
            pasta=pasta,
            run_ts=run_ts,
        )

    _cleanup_container()

    res = _resumo(
        modelo=modelo,
        temperatura=temperatura,
        sessao=sessao,
        timestamp_inicio=timestamp_inicio,
        resultados=resultados,
        ctx=ctx,
        limpar_contexto=limpar_contexto,
    )

    res["duracao_wall_segundos"] = round(time.time() - t_wall_inicio, 1)
    return res


def _formatar_duracao(seg: float) -> str:
    s = int(seg)
    h, rem = divmod(s, 3600)
    m, s = divmod(rem, 60)

    if h:
        return f"{h}h {m:02d}m {s:02d}s"
    if m:
        return f"{m}m {s:02d}s"
    return f"{s}s"


def parse_args():
    p = argparse.ArgumentParser(description="CTF scoring por temperature — AIAgent@forensics")

    p.add_argument("--modelo", default=MODELO_DEFAULT)
    p.add_argument("--temperaturas", nargs="+", type=float, default=TEMPERATURAS_DEFAULT)
    p.add_argument("--sessoes", type=int, default=SESSOES_DEFAULT)
    p.add_argument("--pasta", default="logs_ctf_temperaturas")
    p.add_argument("--debug", action="store_true")
    p.add_argument(
        "--ctx",
        type=int,
        default=None,
        help="Contexto em tokens. Default: auto-detectado por modelo para 12 GB VRAM.",
    )
    p.add_argument(
        "--limpar-contexto",
        action="store_true",
        default=False,
        help="Limpa o contexto da conversa entre perguntas.",
    )

    return p.parse_args()


def main():
    args = parse_args()

    modelo = args.modelo
    temperaturas = args.temperaturas
    sessoes = args.sessoes
    ctx = args.ctx if args.ctx else ctx_para_modelo(modelo)

    total = len(temperaturas) * sessoes
    modo_label = "contexto limpo entre perguntas" if args.limpar_contexto else "contexto normal"

    print("\n🔬 CTF Scoring — Teste por temperature")
    print(f"   Modelo      : {modelo}")
    print(f"   Contexto    : {ctx:,} tokens")
    print(f"   Temperaturas: {temperaturas}")
    print(f"   Modo        : {modo_label}")
    print(f"   Sessões     : {sessoes} por temperatura")
    print(f"   Perguntas   : {len(PERGUNTAS_CTF)}")
    print(f"   Total       : {total} sessões\n")

    print("  Limpando container Docker residual e loop devices órfãos...")
    subprocess.run(["docker", "rm", "-f", "forensics"], capture_output=True, text=True)
    _cleanup_orphan_loops()
    print("  OK\n")

    run_ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    inicio_global = time.time()

    todos_resultados = []
    sessoes_concluidas = 0
    tempos_sessoes: list[float] = []

    for temperatura in temperaturas:
        for sessao in range(1, sessoes + 1):
            try:
                dados = correr_sessao_ctf(
                    modelo=modelo,
                    temperatura=temperatura,
                    sessao=sessao,
                    ctx=ctx,
                    debug=args.debug,
                    run_ts=run_ts,
                    limpar_contexto=args.limpar_contexto,
                    pasta=args.pasta,
                )

                guardar_log(dados, pasta=args.pasta, run_ts=run_ts)
                todos_resultados.append(dados)

                dur_sessao = dados.get("duracao_wall_segundos", 0.0)
                tempos_sessoes.append(dur_sessao)
                sessoes_concluidas += 1

                r = dados["resumo"]
                restantes = total - sessoes_concluidas

                if restantes > 0:
                    media = sum(tempos_sessoes) / len(tempos_sessoes)
                    eta_str = f"  |  ETA restante: ~{_formatar_duracao(restantes * media)}"
                else:
                    eta_str = "  |  Última sessão concluída"

                print(
                    f"\n  📊 temp={temperatura} sessão {sessao}: "
                    f"{r['corretas']}/{r['total_perguntas']} "
                    f"({r['score_percentagem']}%)  |  "
                    f"duração: {_formatar_duracao(dur_sessao)}{eta_str}"
                )

            except KeyboardInterrupt:
                print("\n[!] Interrompido.")
                sys.exit(0)

            except Exception as e:
                print(f"\n[ERRO] temp={temperatura} sessão {sessao}: {e}")
                continue

    duracao = round(time.time() - inicio_global, 1)

    print(f"\n{'=' * 100}")
    print("  RESULTADOS FINAIS POR TEMPERATURE")
    print(f"{'=' * 100}")
    print(
        f"  {'Modelo':<20} {'Temp':>6} {'Contexto':>10} {'Sessão':>7} "
        f"{'Score':>8} {'Corretas':>10} {'Duração':>14} {'T.médio/Q':>11}"
    )
    print(f"  {'-' * 96}")

    for d in todos_resultados:
        r = d["resumo"]
        ctx_str = f"{d.get('ctx', 0):,}"
        dur = _formatar_duracao(d.get("duracao_wall_segundos", r["tempo_total_segundos"]))

        print(
            f"  {d['modelo']:<20} "
            f"{d.get('temperatura', 0):>6} "
            f"{ctx_str:>10} "
            f"{d['sessao']:>7} "
            f"{r['score_percentagem']:>7}%  "
            f"{r['corretas']:>4}/{r['total_perguntas']:<4}  "
            f"{dur:>14}  "
            f"{r['tempo_medio_segundos']:>8.1f}s"
        )

    print(f"\n✅ Concluído em {_formatar_duracao(duracao)} ({duracao}s)")
    print(f"   Logs em: {args.pasta}/\n")


if __name__ == "__main__":
    main()