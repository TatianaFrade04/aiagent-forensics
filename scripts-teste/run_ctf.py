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
import logging
import os
import re
import signal
import subprocess
import sys
import time
import traceback
from datetime import datetime

# ─── Imports do agente ────────────────────────────────────────────────────────

_project_root = os.path.abspath(os.path.dirname(__file__))
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

from langchain_ollama import ChatOllama
from langchain_core.messages import AIMessage, HumanMessage, SystemMessage, ToolMessage
from langchain.agents import create_agent

from agent.tools import start_container, stop_container, run_in_sandbox
from agent.main import auto_detect_evidence, build_system_prompt, TOOLS
from agent.skills import load_skills, select_skills, format_skills_context

# ─── Logging ──────────────────────────────────────────────────────────────────

_log_path = os.path.join(os.path.dirname(__file__), "run_ctf_errors.log")
logging.basicConfig(
    level=logging.WARNING,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.FileHandler(_log_path, encoding="utf-8"),
        logging.StreamHandler(sys.stderr),
    ],
)
_logger = logging.getLogger("run_ctf")

# ─── Timing logger (tail -f run_ctf_timing.log) ───────────────────────────────

_timing_log_path = os.path.join(os.path.dirname(__file__), "run_ctf_timing.log")
_timing_logger = logging.getLogger("run_ctf.timing")
_timing_logger.setLevel(logging.INFO)
_th = logging.FileHandler(_timing_log_path, encoding="utf-8")
_th.setFormatter(logging.Formatter("%(message)s"))
_timing_logger.addHandler(_th)
_timing_logger.propagate = False


# ─── Callback de timing ───────────────────────────────────────────────────────

from langchain_core.callbacks import BaseCallbackHandler


class TimingCallback(BaseCallbackHandler):
    """Loga para stdout e run_ctf_timing.log o timing de cada passo do agente."""

    def __init__(self, id_q: str):
        super().__init__()
        self.id_q = id_q
        self._llm_t0: float | None = None
        self._first_token_t: float | None = None
        self._tool_t0: float | None = None
        self._tool_name: str = "?"

    def _ts(self) -> str:
        return datetime.now().strftime("%H:%M:%S.%f")[:12]

    def _log(self, msg: str) -> None:
        line = f"[{self._ts()}] {self.id_q} → {msg}"
        print(f"  {line}", flush=True)
        _timing_logger.info(line)

    def on_llm_start(self, serialized, messages, **kwargs):
        self._llm_t0 = time.time()
        self._first_token_t = None
        chars = sum(len(str(m)) for batch in messages for m in (batch if isinstance(batch, list) else [batch]))
        self._log(f"LLM START  (~{chars // 4:,} tokens estimados no prompt)")

    def on_llm_new_token(self, token: str, **kwargs):
        if self._first_token_t is None and token.strip():
            self._first_token_t = time.time()
            elapsed = self._first_token_t - (self._llm_t0 or self._first_token_t)
            self._log(f"FIRST TOKEN  (prompt eval: {elapsed:.1f}s)")

    def on_llm_end(self, response, **kwargs):
        elapsed = time.time() - (self._llm_t0 or time.time())
        gen_tokens, prompt_tokens = 0, 0
        for gen_list in (response.generations or []):
            for gen in gen_list:
                info = getattr(gen, "generation_info", {}) or {}
                gen_tokens += info.get("eval_count", 0)
                prompt_tokens = max(prompt_tokens, info.get("prompt_eval_count", 0))
        token_info = f" | prompt={prompt_tokens:,} | gerados={gen_tokens}" if prompt_tokens else ""
        self._log(f"LLM END    ({elapsed:.1f}s total{token_info})")

    def on_tool_start(self, serialized, input_str: str, **kwargs):
        self._tool_t0 = time.time()
        self._tool_name = serialized.get("name", "?")
        short = str(input_str)[:80].replace("\n", "↵")
        self._log(f"TOOL START  {self._tool_name}({short}…)")

    def on_tool_end(self, output: str, **kwargs):
        elapsed = time.time() - (self._tool_t0 or time.time())
        preview = str(output)[:60].replace("\n", "↵")
        self._log(f"TOOL END    {self._tool_name}  ({elapsed:.1f}s) → {preview!r}")

# ─── Cleanup garantido (Ctrl+C, SIGTERM, SSH drop) ────────────────────────────

def _cleanup_orphan_loops():
    """Remove loop devices orphans no host que apontam para ficheiros ewf1."""
    try:
        result = subprocess.run(
            ["losetup", "-a"],
            capture_output=True, text=True, timeout=5
        )
        for line in result.stdout.splitlines():
            if "ewf1" in line and line.split(":")[1].strip().startswith("[]:"):
                dev = line.split(":")[0].strip()
                subprocess.run(["sudo", "losetup", "-d", dev], capture_output=True)
    except Exception:
        pass


def _cleanup_container():
    """Para e remove o container com sequência segura, depois limpa loop devices órfãos."""
    # 1. Desmontar partições e loop devices dentro do container
    subprocess.run(
        ["docker", "exec", "forensics", "bash", "-c",
         "umount -l /forensics/part* 2>/dev/null; "
         "losetup -D 2>/dev/null; "
         "umount -l /forensics_ewf 2>/dev/null; true"],
        capture_output=True, timeout=15
    )
    # 2. Parar container com timeout explícito de 10s
    subprocess.run(["docker", "stop", "--time", "10", "forensics"], capture_output=True)
    # 3. Forçar remoção
    subprocess.run(["docker", "rm", "-f", "forensics"], capture_output=True)
    # 4. Polling até confirmar que o container não existe (máximo 10s)
    for _ in range(10):
        check = subprocess.run(["docker", "inspect", "forensics"], capture_output=True)
        if check.returncode != 0:
            break
        time.sleep(1)
    # 5. Só agora limpar loop devices órfãos no host
    _cleanup_orphan_loops()


def _cleanup():
    _cleanup_container()


atexit.register(_cleanup)
signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
signal.signal(signal.SIGINT,  lambda *_: sys.exit(0))
if hasattr(signal, "SIGHUP"):
    signal.signal(signal.SIGHUP, lambda *_: sys.exit(0))

# ─── Timeout por pergunta ─────────────────────────────────────────────────────

TIMEOUT_PER_QUESTION = 600  # seconds — override with --timeout

# Questions that require slow operations (icat file extraction, binary disk reads,
# jump list parsing) get extra time on top of the base timeout.
TIMEOUT_EXTRA: dict[str, int] = {
    "Q4":  300,  # disk GUID — binary GPT header read
    "Q6":  600,  # uptime — evtx parsing with multiple boot events
    "Q11": 300,  # partition GUID — binary GPT entry array read
    "Q22": 600,  # SHA1 of Card Printers.htm — icat extraction + hash
    "Q24": 600,  # Windows Mail last run — jump list parsing
}


class _QuestionTimeout(Exception):
    pass


def _sigalrm_handler(signum, frame):
    raise _QuestionTimeout()

# ─── Modelos a testar ─────────────────────────────────────────────────────────

MODELOS_DEFAULT = [
    #"gemma4:e4b",
    "gemma4:26b",
    "qwen3.5:4b",
]

TEMPERATURAS_DEFAULT = [
    #0.0,
    #0.1,
    0.2,
    0.3,
    0.5,
    0.7,
    1.0,
]

SESSOES_DEFAULT = 6

# Contexto máximo seguro por modelo para 12 GB VRAM (Q4 quantization)
# Pesos do modelo + KV cache não devem exceder ~11.5 GB (margem de segurança)
MODEL_CTX_12GB: dict[str, int] = {
    "gemma4:e4b":      32768,  # 4B, GQA com poucos KV heads — KV cache muito eficiente
    #"gemma4:26b":       32768,  # 26B — pesos ~8 GB, pouco espaço para KV cache
    "qwen3.5:4b":       32768,  # 4B
}


MODELOS_COM_THINKING = {
    "gemma4:e4b", "gemma4:12b", "gemma4:27b",
    "qwen3.5:4b", "qwen3:4b", "qwen3:8b", "qwen3:14b",
    "deepseek-r1:8b", "deepseek-r1:14b", "deepseek-r1:32b",
}


def ctx_para_modelo(modelo: str) -> int:
    """Devolve o contexto máximo seguro para 12 GB VRAM. Fallback: 32768."""
    return MODEL_CTX_12GB.get(modelo, 32768)


def suporta_thinking(modelo: str) -> bool:
    """Retorna True se o modelo suporta o parâmetro reasoning=True do Ollama."""
    return modelo in MODELOS_COM_THINKING

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
         "Q4",
          'The disk GUID (in hex) of the physical disk is: 6FAE8D386C441743AE3298C4BDE04830. Reply with only "true" or "false".',
          "true",
          "tf",
     ),
      (
          "Q5",
          'True or False: The cluster size in bytes within the second partition of the physical disk is 512. Reply with only "true" or "false".',
          "false",
          "tf",
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
         "Q9",
         'What is the partitioning format (Schema) of the physical disk? Choose from: a) None of the other answers are correct  b) GPT  c) The Physical disk is not partitioned  d) MBE. Reply with only the letter. ',
         "b",
         "mc",
     ),
     (
         "Q10",
         'True or False: The final destination IP address for the email "447018D5-00000006.eml" received by Jimmy Wilson is 10.221.48.196. Reply with only "true" or "false".',
         "true",
         "tf",
     ),
     (
         "Q11",
         'The 2nd partitions unique GUID (in hex) of the physical disk is: 423FDC8AA701EE46AF5A70C06738E819. Reply with only "true" or "false".',
         "false",
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
          "false",
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
          "What encryption programs were used on this computer? Choose from: a) Veracrypt/BitLocker  b) BitLocker/Veracrypt  c) File Vault/Truecrypt  d) BCTextEncoder/Veracrypt  e) No encryption programs were used  f) Truecrypt/BCTextEncoder. Reply with only the letter, read all options before reply.",
          "f",
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

# Prefixes that indicate the model described its plan instead of answering
_PLANNING_PREFIXES = (
    "the user is asking",
    "i need to",
    "let me run",
    "let me check",
    "i should",
    "i will run",
    "i'll run",
    "i am going to",
    "to answer this",
    "to find this",
    "to verify this",
)


def _is_planning_text(content: str) -> bool:
    """Returns True if content is reasoning/planning text, not a real answer."""
    c = content.lower().strip()
    return any(c.startswith(p) for p in _PLANNING_PREFIXES)


def modelo_safe(modelo: str) -> str:
    return modelo.replace(":", "-").replace("/", "-")


def extrair_resposta_modelo(texto: str, tipo: str) -> str:
    """Extrai a resposta do modelo (letra ou true/false) do texto de resposta."""
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
        # "the answer is false", "therefore false", "answer: false", etc.
        m = re.search(r"\b(?:answer(?:\s+is)?|therefore)[:\s]+(true|false)\b", texto_lower)
        if m:
            return m.group(1)
        # last word-boundary occurrence anywhere in text (DOTALL so .* crosses newlines)
        m = re.search(r"\b(false|true)\b(?![\s\S]*\b(?:false|true)\b)", texto_lower)
        if m:
            return m.group(1)
        return texto_lower[:20]

    if tipo == "mc":
        m = re.match(r"^\s*([a-g])\b", texto_lower)
        if m:
            return m.group(1)
        # "answer is: **b**", "answer: b)", "the answer is b", etc. — allow markdown/punct around letter
        m = re.search(r"(?:answer(?:\s+is)?|correct(?:\s+answer)?)[:\s*]+\**([a-g])\b", texto_lower)
        if m:
            return m.group(1)
        # Last non-empty line that is just a standalone answer letter (models often end with lone letter)
        for line in reversed(texto_lower.splitlines()):
            stripped = line.strip()
            if not stripped:
                continue
            m = re.match(r"^([a-g])[).\s]*$", stripped)
            if m:
                return m.group(1)
            break
        m = re.search(r"\b([a-g])\b", texto_lower[:100])
        if m:
            return m.group(1)
        # Last standalone letter in full text — use DOTALL so .* crosses newlines
        m = re.search(r"\b([a-g])\b(?![\s\S]*\b[a-g]\b)", texto_lower)
        if m:
            return m.group(1)
        return texto_lower[:10]

    return texto_lower[:20]


def avaliar_resposta(resposta_modelo: str, resposta_correta: str, tipo: str) -> bool:
    extraida = extrair_resposta_modelo(resposta_modelo, tipo)
    return extraida.strip().lower() == resposta_correta.strip().lower()


def _resposta_valida(extraida: str, tipo: str) -> bool:
    if tipo == "tf":
        return extraida in {"true", "false"}
    if tipo == "mc":
        return extraida in set("abcdefg")
    return True


def _extrair_metricas_msgs(msgs: list) -> dict:
    """Extrai métricas directamente das mensagens do agente."""
    metricas = {"total_duration_ns": 0, "prompt_eval_count": 0, "eval_count": 0, "tool_calls": 0}
    for msg in msgs:
        if isinstance(msg, AIMessage):
            meta = getattr(msg, "response_metadata", {}) or {}
            metricas["total_duration_ns"] += meta.get("total_duration", 0)
            metricas["prompt_eval_count"] += meta.get("prompt_eval_count", 0)
            metricas["eval_count"] += meta.get("eval_count", 0)
            metricas["tool_calls"] += len(getattr(msg, "tool_calls", None) or [])
    return metricas


def guardar_log(dados: dict, pasta: str = "logs_ctf_sem_limpeza_1505_limpeza", run_ts: str = ""):
    os.makedirs(pasta, exist_ok=True)
    ms = modelo_safe(dados["modelo"])
    ts = f"_{run_ts}" if run_ts else ""
    limpo = "_contexto_limpo" if dados.get("limpar_contexto") else ""
    temp = dados.get("temperatura")
    temp_str = f"_temp{str(temp).replace('.', 'p')}" if temp is not None else ""
    caminho = f"{pasta}/{ms}{temp_str}_sessao{dados['sessao']}{limpo}{ts}.json"
    with open(caminho, "w", encoding="utf-8") as f:
        json.dump(dados, f, ensure_ascii=False, indent=2)
    print(f"  → Guardado: {caminho}")



# ─── Core ─────────────────────────────────────────────────────────────────────

def _llm_content(msg) -> str:
    """Extrai o conteúdo textual visível de uma mensagem AI (sem tags de raciocínio)."""
    c = msg.content if isinstance(msg.content, str) else str(msg.content)
    if not c.strip():
        c = (getattr(msg, "additional_kwargs", {}) or {}).get("reasoning_content", "") or ""
    # Strip <think>...</think> reasoning blocks — only keep the visible answer
    c = re.sub(r"<think>.*?</think>", "", c, flags=re.DOTALL).strip()
    return c


def _ollama_online(base_url: str, timeout: int = 5) -> bool:
    """Verifica se o Ollama aceita inferência (não só /api/tags)."""
    import urllib.request, urllib.error
    try:
        req = urllib.request.Request(
            f"{base_url}/api/generate",
            data=b'{"model":"_ping_","prompt":"","stream":false}',
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            urllib.request.urlopen(req, timeout=timeout)
        except urllib.error.HTTPError as e:
            # 404 = Ollama respondeu mas modelo não existe → servidor está up
            if e.code == 404:
                return True
            # 400/500 também significa que o servidor está a responder
            if e.code in (400, 500):
                return True
        return True
    except Exception:
        return False


def _unload_all_models(base_url: str) -> None:
    """Força o Ollama a descarregar todos os modelos carregados."""
    import urllib.request, json
    try:
        resp = urllib.request.urlopen(f"{base_url}/api/tags", timeout=5)
        data = json.loads(resp.read())
        for m in data.get("models", []):
            name = m.get("name", "")
            if not name:
                continue
            req = urllib.request.Request(
                f"{base_url}/api/generate",
                data=json.dumps({"model": name, "keep_alive": 0}).encode(),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            try:
                urllib.request.urlopen(req, timeout=5)
            except Exception:
                pass
    except Exception:
        pass


def _invocar_agente(agent, conversation: list, debug: bool = False, id_q: str = "",
                    timeout_s: int = TIMEOUT_PER_QUESTION) -> list:
    """Corre agent.stream() e devolve a lista de novas mensagens."""
    from langgraph.errors import GraphRecursionError
    ollama_url = os.getenv("OLLAMA_URL", "http://localhost:11434")
    new_messages = []
    callback = TimingCallback(id_q)
    old_handler = signal.signal(signal.SIGALRM, _sigalrm_handler)
    signal.alarm(timeout_s)
    try:
        for chunk in agent.stream(
            {"messages": conversation},
            {"recursion_limit": 60, "callbacks": [callback]},
        ):
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
    except GraphRecursionError:
        print(f"\n  [!] [{id_q}] Recursion limit hit — forcing final answer...")
        _logger.warning("[%s] GraphRecursionError — retrying with stop instruction.", id_q)
        signal.alarm(0)
        try:
            stop_msg = HumanMessage(content=(
                "STOP exploring. Based on what you have found so far, "
                "give your FINAL answer now. "
                "Reply with ONLY the answer letter (for multiple choice) "
                "or ONLY 'true' or 'false' (for true/false). No explanation."
            ))
            signal.signal(signal.SIGALRM, _sigalrm_handler)
            signal.alarm(min(timeout_s, 120))
            for chunk in agent.stream(
                {"messages": conversation + new_messages + [stop_msg]},
                {"recursion_limit": 10, "callbacks": [callback]},
            ):
                for node_output in chunk.values():
                    for msg in node_output.get("messages", []):
                        new_messages.append(msg)
        except Exception as e2:
            _logger.warning("[%s] Stop-instruction retry also failed: %s", id_q, e2)
    except _QuestionTimeout:
        print(f"\n  [!] [{id_q}] Timeout after {timeout_s}s — question marked as wrong.")
        _logger.warning("[%s] timeout after %ds — question unanswered.", id_q, timeout_s)
    except Exception as e:
        err_str = str(e).lower()
        is_connect_err = (
            "connection refused" in err_str
            or "connecterror" in err_str
            or "errno 111" in err_str
            or "server disconnected" in err_str
            or "remoteprotocolerror" in err_str
        )
        if is_connect_err and not new_messages:
            # Ollama caiu — espera até 120s e tenta uma vez mais
            print(f"\n  [!] [{id_q}] Ollama unreachable — waiting up to 120s and retrying...")
            _logger.warning("[%s] ConnectError — waiting for Ollama...", id_q)
            signal.alarm(0)
            for wait in [10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10]:
                time.sleep(wait)
                if _ollama_online(ollama_url):
                    break
            else:
                _logger.error("[%s] Ollama did not come back online after 120s.", id_q)
                signal.signal(signal.SIGALRM, old_handler)
                return new_messages
            print(f"  [*] [{id_q}] Ollama online — a reintentar pergunta...")
            signal.signal(signal.SIGALRM, old_handler)
            return _invocar_agente(agent, conversation, debug=debug, id_q=id_q + "(retry)", timeout_s=timeout_s)
        tb = traceback.format_exc()
        print(f"\n  [!] Erro no agente: {e}")
        _logger.error("Exception in _invocar_agente (msgs collected: %d):\n%s", len(new_messages), tb)
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, old_handler)
    return new_messages


def correr_sessao_ctf(modelo: str, sessao: int, ctx: int, debug: bool = False, run_ts: str = "", limpar_contexto: bool = False, pasta: str = "logs_ctf_sem_limpeza_1505_limpeza", timeout_s: int = TIMEOUT_PER_QUESTION, temperatura: float | None = None) -> dict:
    """Runs the agent directly and sends all CTF questions in sequence."""
    print(f"\n{'='*60}")
    print(f"  MODEL: {modelo}  |  CTX: {ctx}  |  SESSION: {sessao}/{SESSOES_DEFAULT}")
    modo_str = "clean context between questions" if limpar_contexto else "accumulated context"
    print(f"  MODE: {modo_str}")
    print(f"{'='*60}")

    timestamp_inicio = datetime.now().isoformat()
    t_wall_inicio = time.time()
    resultados = []

    print("  Starting container...", end="", flush=True)
    start_container()
    print(" OK")

    print("  Detecting evidence partition...", end="", flush=True)
    evidence = auto_detect_evidence()
    print(f" {evidence}")

    system_prompt = build_system_prompt(evidence) + (
        "\nCTF ANSWER FORMAT:\n"
        "   For TRUE/FALSE questions: if the value you find differs from the reference, answer 'false'.\n"
        "   For MULTIPLE CHOICE questions: compare the value you found against every listed option.\n"
        "     If the value matches one option → select that letter.\n"
        "     If the value matches NONE of the options AND there is a 'None of these' / 'None of the above'\n"
        "     option → select THAT option. NEVER leave the answer blank because nothing matches.\n"
        "   Planning/reasoning text is INTERNAL ONLY — your FINAL response must be the actual answer letter or true/false.\n"
        "   For multiple-choice questions: your FINAL response MUST be EXACTLY one letter (a/b/c/d/e/f/g).\n"
        "   For true/false questions: your FINAL response MUST be EXACTLY 'true' or 'false'.\n"
        "MULTIPLE CHOICE ANSWERING PROCEDURE — when the question says 'Choose from: a) ... b) ... Reply with only the letter':\n"
        "   Step 1 — run the forensic command(s) to find the actual value from the evidence.\n"
        "   Step 2 — read ALL options listed (a, b, c, d, e, f, g) before deciding.\n"
        "   Step 3 — compare your finding to each option exactly, character by character.\n"
        "   Step 4 — select the letter of the matching option.\n"
        "             If NO option matches and 'None of these' / 'None of the above' exists → select that letter.\n"
        "   Step 5 — output EXACTLY ONE LETTER and nothing else. No explanation, no punctuation, no prefix.\n"
        "   WRONG final responses: 'The answer is b', 'b)', 'b.', 'Based on evidence: b', 'b - GPT'\n"
        "   RIGHT final response:  b\n"
        "   NEVER skip reading an option. NEVER answer before calling the tool. NEVER output more than one letter.\n"
    )

    import agent.main as _agent_main
    _agent_main._evidence_path = evidence
    if not _agent_main._skills_cache:
        _agent_main._skills_cache = load_skills()

    ollama_url = os.getenv("OLLAMA_URL", "http://localhost:11434")
    llm = ChatOllama(
        model=modelo,
        temperature=temperatura if temperatura is not None else 0.3,
        num_ctx=ctx,
        keep_alive=-1,
        reasoning=suporta_thinking(modelo),
        base_url=ollama_url,
    )
    agent = create_agent(model=llm, tools=TOOLS)

    conversation = [SystemMessage(content=system_prompt)]
    last_prompt_tokens = 0  # updated after each question

    for idx, (id_q, pergunta, correta, tipo) in enumerate(PERGUNTAS_CTF):
        print(f"\n  [{id_q}] {pergunta[:65]}...")

        if limpar_contexto:
            conversation = [SystemMessage(content=system_prompt)]
            last_prompt_tokens = 0

        conversation[0] = SystemMessage(content=system_prompt)

        # Compress BEFORE the question if context is already ≥ 85 % full
        if not limpar_contexto and ctx > 0 and last_prompt_tokens > 0:
            ctx_pct_before = last_prompt_tokens / ctx * 100
            if ctx_pct_before >= 85:
                print(f"\n  ⚠  Context {ctx_pct_before:.0f}% full before [{id_q}] — compressing...")
                try:
                    sum_resp = llm.invoke(conversation + [HumanMessage(content=(
                        "Summarize ALL forensic findings from this investigation in 10-15 bullet points. "
                        "Include: users found, key file paths and their content, registry findings, "
                        "timestamps, suspicious items, and confirmed conclusions. "
                        "Be specific — include exact values, paths, and dates. "
                        "Do NOT call any tools. Do NOT include code blocks."
                    ))])
                    summary = _llm_content(sum_resp)
                except Exception:
                    summary = "(Auto-summary failed.)"
                conversation[:] = [
                    conversation[0],
                    AIMessage(content=f"[Conversation compressed — summary of prior investigation:]\n\n{summary}"),
                ]
                last_prompt_tokens = 0
                print(f"  Conversation compressed. Context freed.")

        conversation.append(HumanMessage(content=pergunta))

        q_timeout = timeout_s + TIMEOUT_EXTRA.get(id_q, 0)
        print(f"  Waiting for response...", end="", flush=True)
        inicio = time.time()

        new_messages = _invocar_agente(agent, conversation, debug=debug, id_q=id_q, timeout_s=q_timeout)
        conversation.extend(new_messages)

        tempo = time.time() - inicio

        answer = next(
            (m for m in reversed(new_messages)
             if isinstance(m, AIMessage) and not (getattr(m, "tool_calls", None) or [])),
            None,
        )
        content = _llm_content(answer) if answer else ""

        if not new_messages:
            _logger.error("[%s] agent returned 0 messages — possible silent crash.", id_q)
        elif not content.strip():
            _logger.warning("[%s] resposta final vazia (tool_calls=%d, msgs=%d).",
                            id_q,
                            sum(len(getattr(m, "tool_calls", None) or []) for m in new_messages),
                            len(new_messages))

        metricas = _extrair_metricas_msgs(new_messages)
        resposta_extraida = extrair_resposta_modelo(content, tipo)
        correto = avaliar_resposta(content, correta, tipo)

        # Retry nível 1 — planning text: re-invocar o agente (tem acesso a ferramentas)
        if _is_planning_text(content):
            _logger.warning("[%s] planning text detected — re-invoking agent with force instruction.", id_q)
            # Use different message depending on whether evidence commands were already run
            _evidence_calls = sum(
                1
                for _m in new_messages
                if isinstance(_m, AIMessage)
                for _tc in (getattr(_m, "tool_calls", None) or [])
                if _tc.get("name") == "run_forensics_command"
            )
            if _evidence_calls > 0:
                _force_text = (
                    "You already ran the forensic command and have the result in front of you.\n"
                    "Stop reasoning. Give your FINAL answer RIGHT NOW.\n"
                    "Reply with ONLY "
                    + ("'true' or 'false'." if tipo == "tf" else "one letter (a/b/c/d/e/f/g). No explanation.")
                )
            else:
                _force_text = (
                    "Stop. You described your plan but did NOT run any forensic command yet.\n"
                    "Call run_forensics_command RIGHT NOW with the appropriate bash command.\n"
                    "After seeing the result, reply with ONLY the answer "
                    + ("('true' or 'false')." if tipo == "tf" else "(single letter: a/b/c/d/e/f/g).")
                )
            force_msg = HumanMessage(content=_force_text)
            try:
                retry_timeout = max(60, q_timeout // 2)
                new_msgs2 = _invocar_agente(
                    agent, conversation + [force_msg],
                    debug=debug, id_q=id_q + "(force)", timeout_s=retry_timeout,
                )
                if new_msgs2:
                    conversation.extend(new_msgs2)
                    answer2 = next(
                        (m for m in reversed(new_msgs2)
                         if isinstance(m, AIMessage) and not (getattr(m, "tool_calls", None) or [])),
                        None,
                    )
                    content2 = _llm_content(answer2) if answer2 else ""
                    if content2.strip() and not _is_planning_text(content2):
                        content = content2
                        metricas["tool_calls"] += _extrair_metricas_msgs(new_msgs2)["tool_calls"]
                        _logger.info("[%s] force retry result: %r", id_q, content[:120])
            except Exception:
                pass
            resposta_extraida = extrair_resposta_modelo(content, tipo)
            correto = avaliar_resposta(content, correta, tipo)

        # Retry nível 2 — resposta vazia ou formato inválido: prompt directo ao LLM
        if not content.strip() or not _resposta_valida(resposta_extraida, tipo):
            retry_msg = (
                "Reply with ONLY 'true' or 'false'. No explanation, no punctuation."
                if tipo == "tf" else
                "Reply with ONLY the letter of your answer (a, b, c, d, e, f, or g). No explanation, no punctuation."
            )
            try:
                retry_resp = llm.invoke(conversation + [HumanMessage(content=retry_msg)])
                retry_content = _llm_content(retry_resp)
                if retry_content.strip():
                    content = retry_content
                    resposta_extraida = extrair_resposta_modelo(content, tipo)
                    correto = avaliar_resposta(content, correta, tipo)
                    _logger.info("[%s] format retry (was empty=%s) — extracted: %r",
                                 id_q, not content.strip(), resposta_extraida)
            except Exception:
                pass

        perguntas_feitas = idx + 1
        tempo_medio = sum(r["tempo_segundos"] for r in resultados) / max(len(resultados), 1)
        restantes = len(PERGUNTAS_CTF) - perguntas_feitas
        eta = int(restantes * tempo_medio) if resultados else 0

        status = "✅" if correto else "❌"
        print(f" {tempo:.1f}s  |  {status} (extracted: '{resposta_extraida}', correct: '{correta}')  |  ETA: ~{eta}s")

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

        guardar_log(_resumo(modelo, sessao, timestamp_inicio, resultados, ctx, limpar_contexto, temperatura), pasta=pasta, run_ts=run_ts)

        # Actualizar last_prompt_tokens para a próxima iteração
        if not limpar_contexto and ctx > 0:
            _q_prompt_tokens = max(
                (msg.response_metadata.get("prompt_eval_count", 0)
                 for msg in new_messages
                 if isinstance(msg, AIMessage) and hasattr(msg, "response_metadata")),
                default=0,
            )
            if _q_prompt_tokens > 0:
                last_prompt_tokens = _q_prompt_tokens
                ctx_pct = last_prompt_tokens / ctx * 100
                if ctx_pct >= 75:
                    print(f"\n  ⚠  Context {ctx_pct:.0f}% full ({last_prompt_tokens:,}/{ctx:,} tokens).")

    _cleanup_container()
    res = _resumo(modelo, sessao, timestamp_inicio, resultados, ctx, limpar_contexto, temperatura)
    res["duracao_wall_segundos"] = round(time.time() - t_wall_inicio, 1)
    return res


def _resumo(modelo, sessao, timestamp_inicio, resultados, ctx: int = 0, limpar_contexto: bool = False, temperatura: float | None = None):
    corretas = sum(1 for r in resultados if r.get("correto", False))
    total = len(resultados)
    tempo_total = sum(r["tempo_segundos"] for r in resultados)
    d = {
        "modelo": modelo,
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
    if temperatura is not None:
        d["temperatura"] = temperatura
    return d


# ─── Helpers de apresentação ──────────────────────────────────────────────────

def _imprimir_tabela_contextos(modelos: list, ctx_manual: int | None):
    print(f"   {'Model':<22} {'Context (tokens)':>18}  Source")
    print(f"   {'-'*22} {'-'*18}  {'-'*7}")
    for m in modelos:
        if ctx_manual:
            ctx = ctx_manual
            fonte = "manual"
        else:
            ctx = MODEL_CTX_12GB.get(m, 32768)
            fonte = "table" if m in MODEL_CTX_12GB else "default"
        print(f"   {m:<22} {ctx:>18,}  {fonte}")
    print()


def _formatar_duracao(seg: float) -> str:
    s = int(seg)
    h, rem = divmod(s, 3600)
    m, s = divmod(rem, 60)
    if h:
        return f"{h}h {m:02d}m {s:02d}s"
    if m:
        return f"{m}m {s:02d}s"
    return f"{s}s"


# ─── Main ─────────────────────────────────────────────────────────────────────

def parse_args():
    p = argparse.ArgumentParser(description="CTF scoring — AIAgent@forensics")
    p.add_argument("--models",         nargs="+", default=MODELOS_DEFAULT,
                   help="Models to evaluate (default: MODELOS_DEFAULT)")
    p.add_argument("--sessions",       type=int, default=SESSOES_DEFAULT,
                   help=f"Number of sessions per model (default: {SESSOES_DEFAULT})")
    p.add_argument("--output-dir",     default="logs_ctf_sem_limpeza_1505_limpeza",
                   help="Output directory for logs (default: logs_ctf_sem_limpeza_1505_limpeza)")
    p.add_argument("--debug",          action="store_true",
                   help="Show raw AIMessage fields for inspection")
    p.add_argument("--only-model",     metavar="MODEL",
                   help="Run only this model (overrides --models)")
    p.add_argument("--ctx",            type=int, default=None,
                   help="Context size in tokens (default: auto-detected per model for 12 GB VRAM)")
    p.add_argument("--clear-context",  action="store_true", default=False,
                   help="Clear conversation context between questions (each question is independent)")
    p.add_argument("--timeout",        type=int, default=TIMEOUT_PER_QUESTION,
                   help=f"Timeout per question in seconds (default: {TIMEOUT_PER_QUESTION})")
    p.add_argument("--temperatures",   nargs="+", type=float, default=None,
                   help="Temperatures to evaluate (default: TEMPERATURAS_DEFAULT). "
                        "Pass --temperatures 0.3 to run a single temperature.")
    return p.parse_args()


def main():
    args = parse_args()
    modelos = [args.only_model] if args.only_model else args.models
    sessoes = args.sessions
    temperaturas = args.temperatures if args.temperatures is not None else TEMPERATURAS_DEFAULT

    total = len(modelos) * sessoes * (len(temperaturas) if temperaturas else 1)
    modo_label = "clean context between questions" if args.clear_context else "accumulated context"
    print(f"\n🔬 CTF Scoring — AIAgent@forensics")
    print(f"   Mode        : {modo_label}")
    print(f"   Sessions    : {sessoes} per model" + (f" × {len(temperaturas)} temperatures" if temperaturas else ""))
    print(f"   Temperatures: {temperaturas if temperaturas else '[default 0.3]'}")
    print(f"   Questions   : {len(PERGUNTAS_CTF)} (with ground truth)")
    print(f"   Total       : {total} sessions\n")
    print(f"   Models and max context (12 GB VRAM):")
    _imprimir_tabela_contextos(modelos, args.ctx)

    print("  Cleaning up residual Docker container and orphan loop devices...")
    subprocess.run(["docker", "rm", "-f", "forensics"], capture_output=True, text=True)
    _cleanup_orphan_loops()
    print("  OK\n")

    ollama_url = os.getenv("OLLAMA_URL", "http://localhost:11434")
    if ollama_url != "http://localhost:11434" and not _ollama_online(ollama_url, timeout=3):
        print(f"  [!] {ollama_url} unreachable — falling back to http://localhost:11434")
        ollama_url = "http://localhost:11434"
        os.environ["OLLAMA_URL"] = ollama_url

    print("  Unloading residual Ollama models...", end="", flush=True)
    _unload_all_models(ollama_url)
    print(" OK")

    run_ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    inicio_global = time.time()
    todos_resultados = []
    sessoes_concluidas = 0
    tempos_sessoes: list[float] = []

    for modelo in modelos:
        ctx = args.ctx if args.ctx else ctx_para_modelo(modelo)

        # Pre-warm: carrega o modelo uma única vez antes das sessões
        ollama_url = os.getenv("OLLAMA_URL", "http://localhost:11434")
        _llm_warm = ChatOllama(model=modelo, num_ctx=ctx, keep_alive=-1,
                               reasoning=suporta_thinking(modelo), base_url=ollama_url)
        print(f"\n  Loading {modelo} (ctx={ctx})...", end="", flush=True)
        for _pw in range(24):  # até 240s
            try:
                _llm_warm.invoke([HumanMessage(content="ok")])
                print(" OK")
                break
            except Exception:
                if _pw == 0:
                    print(" waiting...", end="", flush=True)
                time.sleep(10)
        else:
            print(" FAILED — continuing anyway")

        temp_list = temperaturas
        for temperatura in temp_list:
            temp_label = f"  temp={temperatura}" if temperatura is not None else ""
            for sessao in range(1, sessoes + 1):
                try:
                    dados = correr_sessao_ctf(modelo, sessao, ctx=ctx, debug=args.debug, run_ts=run_ts, limpar_contexto=args.clear_context, pasta=args.output_dir, timeout_s=args.timeout, temperatura=temperatura)
                    guardar_log(dados, pasta=args.output_dir, run_ts=run_ts)
                    todos_resultados.append(dados)

                    dur_sessao = dados.get("duracao_wall_segundos", 0.0)
                    tempos_sessoes.append(dur_sessao)
                    sessoes_concluidas += 1

                    r = dados["resumo"]
                    restantes = total - sessoes_concluidas
                    if restantes > 0:
                        media = sum(tempos_sessoes) / len(tempos_sessoes)
                        eta_str = f"  |  ETA remaining: ~{_formatar_duracao(restantes * media)}"
                    else:
                        eta_str = "  |  Last session done"
                    print(f"\n  📊 {modelo}{temp_label} session {sessao}: {r['corretas']}/{r['total_perguntas']} ({r['score_percentagem']}%)  |  duration: {_formatar_duracao(dur_sessao)}{eta_str}")

                except KeyboardInterrupt:
                    print("\n[!] Interrupted.")
                    sys.exit(0)
                except Exception as e:
                    print(f"\n[ERROR] {modelo}{temp_label} session {sessao}: {e}")
                    continue

    duracao = round(time.time() - inicio_global, 1)
    print(f"\n{'='*90}")
    print(f"  FINAL RESULTS")
    print(f"{'='*90}")
    print(f"  {'Model':<20} {'Context':>10} {'Session':>7} {'Score':>8} {'Correct':>10} {'Session duration':>16} {'Avg/Q':>11}")
    print(f"  {'-'*86}")
    for d in todos_resultados:
        r = d["resumo"]
        ctx_str = f"{d.get('ctx', 0):,}"
        dur = _formatar_duracao(d.get("duracao_wall_segundos", r["tempo_total_segundos"]))
        print(f"  {d['modelo']:<20} {ctx_str:>10} {d['sessao']:>7} {r['score_percentagem']:>7}%  {r['corretas']:>4}/{r['total_perguntas']:<4}  {dur:>14}  {r['tempo_medio_segundos']:>8.1f}s")
    print(f"\n✅ Done in {_formatar_duracao(duracao)} ({duracao}s)  |  Logs: {args.output_dir}/\n")


if __name__ == "__main__":
    main()
