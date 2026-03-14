import base64
import json
import os
import re
import subprocess
from typing import List, Literal, Optional

from langchain_core.messages import HumanMessage
from langchain_ollama import ChatOllama
from pydantic import BaseModel, Field

from mcp_local import LocalMCPClient, create_default_server


# =========================
# Config
# =========================

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_EVIDENCE_DIR = os.path.join(_PROJECT_ROOT, "evidence")

_DOCKER_IMAGE = os.getenv("FORENSICS_IMAGE") or "forensics"
_DOCKER_CONTAINER = os.getenv("FORENSICS_CONTAINER") or "forensics"

OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL") or "http://localhost:11434"
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL") or "llama3.1"


# =========================
# Structured decision model
# 
VISUAL_INTENTS = [
    "general_description",
    "object_presence",
    "object_location",
    "forensic_trace_detection",
    "scene_relationships",
]

ARTIFACT_INTENTS = [
    "directory_listing",
    "image_partition_inspection",
    "partition_root_listing",
    "user_enumeration",
    "path_lookup",
    "file_search",
    "timeline_lookup",
    "artifact_lookup",
    "file_hash_lookup",
    "file_size_lookup",
    "file_content_inspection",
    "filesystem_stats",
    "disk_metadata",
    "registry_lookup",
    "event_log_lookup",
    "insufficient_evidence",
    "unsafe_inference",
]

ALLOWED_DOMAINS = ["visual", "artifact"]
ALLOWED_INTENTS = VISUAL_INTENTS + ARTIFACT_INTENTS


class DecisionEntities(BaseModel):
    user: Optional[str] = None
    application: Optional[str] = None
    target_path: Optional[str] = None
    action: Optional[str] = None
    path_scope: Optional[Literal["host_filesystem", "forensic_image", "user_profile", "unknown"]] = None
    artifact_type: Optional[str] = None
    timestamp_target: Optional[str] = None
    operation: Optional[Literal["list", "find", "inspect", "inspect_partitions", "enumerate_users", "query_last_used", "query_timestamp", "compute"]] = None
    reference_source: Optional[str] = None
    algorithm: Optional[str] = None


class ConversationState(BaseModel):
    last_path: Optional[str] = None
    last_artifact: Optional[str] = None
    last_artifact_type: Optional[str] = None
    last_user: Optional[str] = None


class OrchestrationDecision(BaseModel):
    domain: Literal["visual", "artifact"]
    intent: Literal[
        "general_description",
        "object_presence",
        "object_location",
        "forensic_trace_detection",
        "scene_relationships",
        "directory_listing",
        "image_partition_inspection",
        "partition_root_listing",
        "user_enumeration",
        "path_lookup",
        "file_search",
        "timeline_lookup",
        "artifact_lookup",
        "file_hash_lookup",
        "file_size_lookup",
        "file_content_inspection",
        "filesystem_stats",
        "disk_metadata",
        "registry_lookup",
        "event_log_lookup",
        "insufficient_evidence",
        "unsafe_inference",
    ]
    rewritten_question: str
    entities: DecisionEntities = Field(default_factory=DecisionEntities)
    constraints: List[str] = Field(default_factory=list)
    tool_plan: List[str] = Field(default_factory=list)
    needs_image: bool = Field(default=False)


ALLOWED_TEMPLATE_NAMES = set(ALLOWED_INTENTS + ["safe_generic_visual_analysis"])
RESULT_OK = "ok"


# =========================
# Helpers
# =========================

def shorten_text(text: str, max_len: int = 1800) -> str:
    if text is None:
        return ""
    text = str(text)
    if len(text) <= max_len:
        return text
    return text[:max_len] + "\n...[truncated]..."


def is_error_text(text: str) -> bool:
    if not text:
        return False
    lowered = text.lower()
    return (
        "error invoking tool" in lowered
        or "erro bash" in lowered
        or "field required" in lowered
        or "input should be a valid string" in lowered
    )


def _read_image_as_data_url(image_path: str) -> str:
    with open(image_path, "rb") as image_file:
        encoded = base64.b64encode(image_file.read()).decode("ascii")

    ext = os.path.splitext(image_path)[1].lower()
    mime = {
        ".jpg": "image/jpeg",
        ".jpeg": "image/jpeg",
        ".png": "image/png",
        ".webp": "image/webp",
        ".bmp": "image/bmp",
    }.get(ext, "application/octet-stream")
    return f"data:{mime};base64,{encoded}"


def _history_to_text(history: List[str], max_turns: int = 8) -> str:
    if not history:
        return ""
    return "\n".join(history[-max_turns:])


def _normalize_template_name(template_name: str) -> str:
    raw = (template_name or "").strip().lower().replace(" ", "_")
    aliases = {
        "insufficient_visual_evidence": "insufficient_evidence",
        "directory_navigation": "directory_listing",
        "evidence_inventory": "artifact_lookup",
    }
    normalized = aliases.get(raw, raw)
    return normalized if normalized in ALLOWED_TEMPLATE_NAMES else "safe_generic_visual_analysis"


def _intent_to_template(intent: str) -> str:
    candidate = _normalize_template_name(intent)
    return candidate if candidate in ALLOWED_TEMPLATE_NAMES else "safe_generic_visual_analysis"


def _find_default_forensic_image_path() -> Optional[str]:
    try:
        if not os.path.isdir(_EVIDENCE_DIR):
            return None
        candidates = []
        for root, _, files in os.walk(_EVIDENCE_DIR):
            for filename in files:
                if filename.lower().endswith((".e01", ".dd", ".img", ".raw", ".001")):
                    full = os.path.join(root, filename)
                    rel = os.path.relpath(full, _PROJECT_ROOT).replace("\\", "/")
                    candidates.append("/" + rel)
        if not candidates:
            return None
        candidates.sort()
        return candidates[0]
    except Exception:
        return None


# =========================
# Classification prompt
# =========================

CLASSIFIER_PROMPT = """
You are the orchestration agent for a forensic analysis system.

There are two domains:
1) visual questions about the current image
2) artifact questions about directories, files, application usage, and timelines

For each user question:
1) classify domain as either visual or artifact
2) classify intent using the allowed intents
3) extract entities
4) produce a tool_plan
5) set needs_image

Allowed intents:
- general_description
- object_presence
- object_location
- forensic_trace_detection
- scene_relationships
- directory_listing
- image_partition_inspection
- partition_root_listing
- user_enumeration
- path_lookup
- file_search
- timeline_lookup
- artifact_lookup
- file_hash_lookup
- file_size_lookup
- file_content_inspection
- filesystem_stats
- disk_metadata
- registry_lookup
- insufficient_evidence
- unsafe_inference

Return structured fields:
- domain
- intent
- rewritten_question
- entities: user, application, target_path, path_scope, action, artifact_type, timestamp_target, operation
- constraints
- tool_plan
- needs_image

Critical classification rules:
- If query refers to Desktop, Downloads, Documents, or folders, map to target_path (never application).
- For literal paths (/evidence, /tmp, ./output, ../data), set path_scope=host_filesystem and keep application=null.
- If query asks to list files in a folder, use intent=directory_listing and operation=list.
- For follow-up partition questions ("que particoes existem?", "what partitions are there?") with an implicit prior forensic image reference, use intent=image_partition_inspection and operation=inspect_partitions.
- For questions about files in the root of the primary partition ("ficheiros na raiz da particao principal", "files in the root of the primary partition"), use intent=partition_root_listing.
- For user profile inventory questions ("quais os users que existem?", "which users exist?", "list users", "show user profiles"), use intent=user_enumeration and operation=enumerate_users.
- If query asks when an app was last opened, use intent=timeline_lookup and operation=query_last_used.
- Questions about a user's Desktop, Downloads, Documents, Pictures, or Music folder (e.g. 'what is in the desktop of user X', 'o que esta no desktop do user Y') MUST use domain=artifact and intent=directory_listing — NEVER domain=visual or intent=insufficient_evidence, regardless of the word 'desktop'.
- Questions asking for MD5/SHA1/SHA256 hash of a file → domain=artifact, intent=file_hash_lookup, operation=compute; put the file path in target_path and the algorithm name (md5/sha1/sha256) in action.
- Questions about logical file size, how big a file is, tamanho do ficheiro → domain=artifact, intent=file_size_lookup, operation=compute; put the file path in target_path.
- Questions to read, show, or extract the content of a specific file → domain=artifact, intent=file_content_inspection, operation=inspect; put the file path in target_path.
- Questions about cluster size, block size, sector size, or filesystem type → domain=artifact, intent=filesystem_stats, operation=inspect.
- Questions about partition schema (GPT/MBR), disk GUID, partition GUID, disk serial number → domain=artifact, intent=disk_metadata, operation=inspect_partitions.
- Questions about SAM registry, RID numbers, last login time, password hint, startup programs, installed encryption software, UserAssist, or any Windows registry key → domain=artifact, intent=registry_lookup, operation=inspect; put the hive name (sam/ntuser/software/system) in artifact_type and the specific key target in action.
- Questions about system uptime, system boot time, shutdown time, Windows event log, Event ID, evtx, or "what was the uptime at [timestamp]" → domain=artifact, intent=event_log_lookup, operation=inspect; put the log name (system/application/security) in artifact_type and the specific timestamp or event_id in action.
- Artifact queries must use needs_image=false.
- Visual queries must use needs_image=true.
- For artifact queries, tool_plan must include specific MCP tools and not only generic reasoning.
"""


SAFE_GENERIC_TEMPLATE = (
    "Analyze only visible evidence in the image. "
    "If uncertainty exists, state it explicitly. "
    "Do not infer intent, identity, chronology, or hidden facts."
)


# =========================
# Docker
# =========================

def ensure_container():
    try:
        running = subprocess.run(
            ["docker", "ps", "-q", "--filter", f"name=^{_DOCKER_CONTAINER}$"],
            capture_output=True,
            text=True,
        ).stdout.strip()
    except FileNotFoundError:
        print("[docker] Warning: Docker is unavailable. Continuing without container startup.")
        return

    if running:
        print(f"[docker] Container '{_DOCKER_CONTAINER}' is already running.")
        return

    subprocess.run(["docker", "rm", "-f", _DOCKER_CONTAINER], capture_output=True, text=True)
    print(f"[docker] Starting container '{_DOCKER_CONTAINER}' from image '{_DOCKER_IMAGE}'...")

    result = subprocess.run(
        [
            "docker",
            "run",
            "-d",
            "--name",
            _DOCKER_CONTAINER,
            "--network",
            "none",
            "-v",
            f"{_EVIDENCE_DIR}:/evidence:ro",
            _DOCKER_IMAGE,
        ],
        capture_output=True,
        text=True,
    )

    if result.returncode != 0:
        print(f"[docker] Warning: failed to start container: {result.stderr.strip()}")
        print("[docker] Continuing application startup.")
        return

    print("[docker] Container ready.\n")


# =========================
# Decision normalization
# =========================

def _normalize_decision(raw_plan: dict) -> OrchestrationDecision:
    payload = dict(raw_plan or {})

    domain = str(payload.get("domain") or "").strip().lower()
    if domain not in ALLOWED_DOMAINS:
        domain = "artifact"

    intent = str(payload.get("intent") or "").strip()
    if intent not in ALLOWED_INTENTS:
        intent = "insufficient_evidence"

    rewritten_question = str(payload.get("rewritten_question") or "").strip()
    if not rewritten_question:
        rewritten_question = "Find the requested evidence safely."

    entities_payload = payload.get("entities")
    if not isinstance(entities_payload, dict):
        entities_payload = {}

    constraints = payload.get("constraints")
    if not isinstance(constraints, list):
        constraints = []
    constraints = [str(item).strip() for item in constraints if str(item).strip()]

    tool_plan = payload.get("tool_plan")
    if not isinstance(tool_plan, list):
        tool_plan = []
    tool_plan = [str(item).strip() for item in tool_plan if str(item).strip()]

    needs_image = bool(payload.get("needs_image", domain == "visual"))

    return OrchestrationDecision(
        domain=domain,
        intent=intent,
        rewritten_question=rewritten_question,
        entities=DecisionEntities.model_validate(entities_payload),
        constraints=constraints,
        tool_plan=tool_plan,
        needs_image=needs_image,
    )


def _apply_artifact_entity_rules(decision: OrchestrationDecision, question: str) -> OrchestrationDecision:
    lowered_q = (question or "").lower()
    folder_tokens = ["desktop", "downloads", "documents", "documentos", "music", "pictures", "videos"]
    special_folders = {"desktop", "downloads", "documents", "documentos", "music", "pictures", "videos"}
    file_words = ["ficheiro", "ficheiros", "file", "files"]
    folder_words = ["pasta", "pastas", "folder", "folders", "diretoria", "diretório", "directory"]

    literal_path = _extract_literal_path(question)

    if decision.entities.user and decision.entities.user.strip().lower() in {"unknown", "none", "null", "n/a"}:
        decision.entities.user = None

    # Never treat folder names as application entities.
    if decision.entities.application and decision.entities.application.lower() in folder_tokens:
        if not decision.entities.target_path:
            decision.entities.target_path = decision.entities.application
        decision.entities.application = None

    for token in folder_tokens:
        if token in lowered_q and not decision.entities.target_path:
            decision.entities.target_path = token.capitalize()

    if any(word in lowered_q for word in file_words) and not any(word in lowered_q for word in folder_words):
        decision.entities.artifact_type = "file"
    elif any(word in lowered_q for word in folder_words):
        decision.entities.artifact_type = "folder"

    if literal_path:
        decision.entities.target_path = literal_path
        decision.entities.path_scope = "host_filesystem"
        decision.entities.application = None
        # Keep user if this is actually a user-profile folder request like '/Desktop do Jimmy Wilson'.
        if not decision.entities.user:
            decision.entities.user = None
        if decision.entities.operation is None:
            decision.entities.operation = "list"
        if decision.entities.artifact_type is None:
            decision.entities.artifact_type = "filesystem_entry"

    # If a user is present and folder target is a known user profile folder, force forensic user-profile scope.
    # Also check the last segment of a full fake path like /home/user/Desktop.
    normalized_target = (decision.entities.target_path or "").strip().lstrip("/").lower()
    normalized_target_last = normalized_target.replace("\\", "/").split("/")[-1] if normalized_target else ""
    folder_key = normalized_target if normalized_target in special_folders else (
        normalized_target_last if normalized_target_last in special_folders else None
    )
    if decision.domain == "artifact" and decision.entities.user and folder_key:
        canonical_folder = "Documents" if folder_key == "documentos" else folder_key.capitalize()
        decision.entities.target_path = canonical_folder
        decision.entities.path_scope = "user_profile"
        decision.entities.artifact_type = decision.entities.artifact_type or "folder"
        decision.entities.operation = "list"
        decision.intent = "directory_listing"
        decision.needs_image = False

    # Domain correction: questions about files/documents in the forensic image are artifact queries.
    artifact_image_markers = ["imagem de evid", "forensic image", "nesta imagem", "this image"]
    artifact_file_markers = ["document", "ficheiro", "file", "personal", "pessoal", "users", "parti"]
    if decision.domain == "visual":
        if any(marker in lowered_q for marker in artifact_image_markers) and any(
            marker in lowered_q for marker in artifact_file_markers
        ):
            decision.domain = "artifact"
            decision.intent = "artifact_lookup"
            decision.needs_image = False
            if not decision.entities.operation:
                decision.entities.operation = "find"
            if not decision.entities.path_scope:
                decision.entities.path_scope = "forensic_image"

    # Belt-and-suspenders guard: user + folder word must NEVER route to host filesystem.
    # Covers both domain=visual misclassification and domain=artifact with host path.
    if decision.entities.user and any(token in lowered_q for token in folder_tokens):
        if decision.domain == "visual" or (
            decision.domain == "artifact" and decision.entities.path_scope == "host_filesystem"
        ):
            canonical_folder = None
            for token in folder_tokens:
                if token in lowered_q:
                    canonical_folder = "Documents" if token == "documentos" else token.capitalize()
                    break
            decision.domain = "artifact"
            decision.intent = "directory_listing"
            decision.needs_image = False
            decision.entities.path_scope = "user_profile"
            decision.entities.operation = "list"
            if canonical_folder:
                decision.entities.target_path = canonical_folder

    # For forensic-image artifact questions, keep target_path anchored to the current image by default.
    if decision.domain == "artifact" and decision.entities.path_scope == "forensic_image":
        existing_target = (decision.entities.target_path or "").strip()
        if existing_target and not _is_forensic_image_path(existing_target):
            if not decision.entities.action:
                decision.entities.action = existing_target
            existing_target = ""

        if not existing_target or existing_target in {"/", ".", "./"}:
            default_image = _find_default_forensic_image_path()
            if default_image:
                decision.entities.target_path = default_image

    if decision.domain == "artifact":
        decision.needs_image = False

    # Filesystem stats guard: cluster/sector/block size questions must always route to filesystem_stats.
    if decision.domain == "artifact" and _is_filesystem_stats_question(question):
        decision.intent = "filesystem_stats"
        if not decision.entities.operation:
            decision.entities.operation = "inspect"

    # Event log guard: uptime/boot time/event log questions must always route to event_log_lookup.
    if _is_event_log_question(question):
        decision.domain = "artifact"
        decision.intent = "event_log_lookup"
        decision.needs_image = False
        if not decision.entities.artifact_type:
            decision.entities.artifact_type = "system"
        if not decision.entities.operation:
            decision.entities.operation = "inspect"
        # Extract timestamp from the question if not already set
        if not decision.entities.timestamp_target:
            extracted_ts = _extract_timestamp_from_question(question)
            if extracted_ts:
                decision.entities.timestamp_target = extracted_ts

    # Intent refinements for artifact branch.
    _protected_intents = {
        "filesystem_stats", "disk_metadata", "file_hash_lookup", "file_size_lookup",
        "file_content_inspection", "registry_lookup", "event_log_lookup",
    }
    if decision.domain == "artifact":
        if decision.entities.path_scope == "host_filesystem" and decision.intent not in _protected_intents:
            decision.intent = "directory_listing"
        # Clear stale host_filesystem scope from protected intents — these tools work on the forensic image directly.
        if decision.entities.path_scope == "host_filesystem" and decision.intent in _protected_intents:
            decision.entities.path_scope = "forensic_image"

        if any(token in lowered_q for token in ["parti", "partition", "/evidence", "evidence"]):
            if not decision.entities.user and decision.intent not in _protected_intents | {"partition_root_listing"} \
                    and not _is_filesystem_stats_question(question):
                decision.intent = "artifact_lookup"
                if not decision.entities.operation:
                    decision.entities.operation = "inspect"

        if decision.entities.path_scope == "host_filesystem" and decision.intent not in _protected_intents:
            decision.intent = "directory_listing"
            decision.entities.operation = "list"

        if decision.entities.operation == "list" or "lista" in lowered_q or "list" in lowered_q:
            if decision.entities.target_path:
                decision.intent = "directory_listing"
        if decision.entities.operation == "query_last_used" or "ultima vez" in lowered_q or "last time" in lowered_q:
            decision.intent = "timeline_lookup"
        if decision.entities.operation == "find" and decision.intent not in ("timeline_lookup", "directory_listing"):
            decision.intent = "file_search"

    # File-type keyword guard: if the question is about a file type (email, pdf, exe...)
    # it must never be classified as user_enumeration, even if the LLM made that mistake.
    _FILE_SEARCH_TOKENS = [
        "email", "e-mail", "emails", "eml", "mail", "mails", "correio", "mensagem", "mensagens",
        "pdf", "pdfs", "documento", "documentos",
        "photo", "foto", "fotos", "imagem", "image",
        "video", "vídeo", "audio", "mp3", "mp4",
        "executable", "exe", "programa", "programas",
        "zip", "rar", "arquivo", "comprimido",
    ]
    _USER_ENUM_TOKENS = ["users", "user profiles", "utilizadores", "profiles", "usuarios", "usuários"]

    def _flip_to_file_search() -> None:
        decision.intent = "file_search"
        decision.entities.artifact_type = "file"
        decision.entities.user = None
        decision.entities.operation = "find"
        decision.entities.path_scope = "forensic_image"
        decision.rewritten_question = question

    if decision.intent == "user_enumeration" and any(kw in lowered_q for kw in _FILE_SEARCH_TOKENS):
        if not any(t in lowered_q for t in _USER_ENUM_TOKENS):
            _flip_to_file_search()

    # Also fix directory_listing with no user when the question is really a file-type search.
    # e.g. "list the .pdf files" or "diz os .pdf da pasta Documents" (no user specified)
    if decision.intent == "directory_listing" and not decision.entities.user:
        if any(kw in lowered_q for kw in _FILE_SEARCH_TOKENS):
            _flip_to_file_search()

    # Computer-activity guard: questions about whether/when the COMPUTER was on/active
    # should not carry a hallucinated user from conversation context.
    # e.g. "o computador esteve ligado no dia X?" / "quais dias o computador foi ligado?"
    _COMPUTER_ACTIVITY_TOKENS = [
        "computador esteve", "computer was", "computer on", "was the computer",
        "esteve ligado", "estava ligado", "ligado no dia", "active on", "used on",
        "activity on", "atividade no dia", "atividade em",
        "quais dias", "quais foram os dias", "which days", "dias que o computador",
        "days the computer", "days was", "dias foi ligado", "dias ligado",
    ]
    _is_computer_activity_q = any(tok in lowered_q for tok in _COMPUTER_ACTIVITY_TOKENS)
    _has_explicit_user = any(name_tok in lowered_q for name_tok in ["jimmy", "wilson", "admin", "user"])

    if (
        _is_computer_activity_q
        and not _has_explicit_user
        and decision.intent in ("timeline_lookup", "event_log_lookup", "insufficient_evidence", "artifact_lookup")
    ):
        decision.domain = "artifact"
        decision.intent = "timeline_lookup"
        decision.needs_image = False
        decision.entities.user = None  # clear hallucinated user

    # Validate timestamp_target: must look like a real date (YYYY-MM-DD or YYYY-MM-DD HH:MM:SS).
    # Clear it if the LLM put a word like "days", "today", "all", etc.
    if decision.entities.timestamp_target:
        import re as _re
        _ts = decision.entities.timestamp_target.strip()
        if not _re.match(r"\d{4}-\d{2}-\d{2}", _ts):
            decision.entities.timestamp_target = None

    return decision


def _is_partition_question(question: str) -> bool:
    lowered = (question or "").lower()
    return any(token in lowered for token in ["partition", "parti", "parti\u00e7", "particao", "parti\u00e7\u00e3o", "volumes", "layout"])


_FS_STAT_TOKENS = [
    "cluster size", "block size", "sector size", "filesystem type", "file system type",
    "tamanho do cluster", "tamanho de cluster", "tamanho do bloco", "cluster size in bytes",
    "bytes per cluster", "bytes per sector",
]

def _is_filesystem_stats_question(question: str) -> bool:
    lowered = (question or "").lower()
    return any(token in lowered for token in _FS_STAT_TOKENS)


_EVENT_LOG_TOKENS = [
    "uptime", "up time", "system up time", "system uptime",
    "boot time", "shutdown time", "event log", "event id",
    "evtx", "windows log", "system log",
    "tempo de actividade", "tempo de atividade",
]

def _is_event_log_question(question: str) -> bool:
    lowered = (question or "").lower()
    return any(token in lowered for token in _EVENT_LOG_TOKENS)


def _extract_timestamp_from_question(question: str) -> Optional[str]:
    """Try to extract and normalize a date/datetime string from a natural language question.
    Returns a string compatible with python-evtx timestamp format (YYYY-MM-DD HH:MM:SS or YYYY-MM-DD).
    """
    import re
    from datetime import datetime

    # Pattern 1: ISO datetime already formatted
    m = re.search(r"(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2}:\d{2})", question)
    if m:
        return f"{m.group(1)} {m.group(2)}"

    # Pattern 2: ISO date only
    m = re.search(r"\d{4}-\d{2}-\d{2}", question)
    if m:
        return m.group(0)

    # Pattern 3: "February 20, 2014 @ 17:02:35" / "February 20, 2014 17:02:35"
    month_names = (
        "january february march april may june "
        "july august september october november december"
    ).split()
    month_map = {name: i + 1 for i, name in enumerate(month_names)}
    pat3 = re.search(
        r"(january|february|march|april|may|june|july|august|september|october|november|december)"
        r"\s+(\d{1,2}),?\s+(\d{4})[^0-9]*(\d{2}):(\d{2}):(\d{2})",
        question,
        re.IGNORECASE,
    )
    if pat3:
        month = month_map[pat3.group(1).lower()]
        day = int(pat3.group(2))
        year = int(pat3.group(3))
        hh, mm, ss = pat3.group(4), pat3.group(5), pat3.group(6)
        return f"{year:04d}-{month:02d}-{day:02d} {hh}:{mm}:{ss}"

    # Pattern 4: "February 20, 2014" without time
    pat4 = re.search(
        r"(january|february|march|april|may|june|july|august|september|october|november|december)"
        r"\s+(\d{1,2}),?\s+(\d{4})",
        question,
        re.IGNORECASE,
    )
    if pat4:
        month = month_map[pat4.group(1).lower()]
        day = int(pat4.group(2))
        year = int(pat4.group(3))
        return f"{year:04d}-{month:02d}-{day:02d}"

    return None


def _is_partition_root_listing_question(question: str) -> bool:
    lowered = (question or "").lower()
    partition_markers = ["partition", "parti", "parti\u00e7", "particao", "parti\u00e7\u00e3o", "particao principal", "parti\u00e7\u00e3o principal"]
    root_markers = ["root", "raiz"]
    file_markers = ["files", "ficheiros", "file", "entries", "conte\u00fado", "conteudo"]
    return (
        any(marker in lowered for marker in partition_markers)
        and any(marker in lowered for marker in root_markers)
        and any(marker in lowered for marker in file_markers)
    )


def _is_user_enumeration_question(question: str) -> bool:
    lowered = (question or "").lower()
    user_tokens = ["users", "user profiles", "user profile", "profiles", "usuarios", "utilizadores", "usu\u00e1rios", "users que existem"]
    if any(token in lowered for token in user_tokens):
        return True
    return bool(re.search(r"\b(which|quais|listar|list|show)\b.*\b(users?|profiles?)\b", lowered))


def _is_forensic_image_path(path: Optional[str]) -> bool:
    if not path:
        return False
    lowered = path.lower()
    return lowered.endswith((".e01", ".dd", ".img", ".raw", ".001"))


def _apply_conversation_reference_rules(
    decision: OrchestrationDecision,
    question: str,
    conversation_state: Optional[ConversationState],
) -> OrchestrationDecision:
    if decision.domain != "artifact":
        return decision

    if not conversation_state:
        return decision

    if _is_partition_root_listing_question(question):
        resolved_target = decision.entities.target_path
        reference_source = None

        if resolved_target and not _is_forensic_image_path(resolved_target):
            resolved_target = None

        if (
            not resolved_target
            and conversation_state.last_artifact_type == "forensic_image"
            and _is_forensic_image_path(conversation_state.last_artifact)
        ):
            resolved_target = conversation_state.last_artifact
            reference_source = "conversation_context"

        if not resolved_target:
            default_image = _find_default_forensic_image_path()
            if default_image:
                resolved_target = default_image
                reference_source = reference_source or "case_context"

        if resolved_target:
            decision.intent = "partition_root_listing"
            decision.entities.target_path = resolved_target
            decision.entities.path_scope = "forensic_image"
            decision.entities.artifact_type = "filesystem_entry"
            decision.entities.operation = "list"
            decision.entities.application = None
            decision.entities.reference_source = reference_source
            if "use the most recent forensic image referenced in the conversation" not in decision.constraints:
                decision.constraints.append("use the most recent forensic image referenced in the conversation")
            if "return root entries from the primary partition only" not in decision.constraints:
                decision.constraints.append("return root entries from the primary partition only")
            decision.rewritten_question = (
                f"List root directory entries from the primary partition in forensic image {resolved_target}."
            )

    elif _is_partition_question(question) and not _is_filesystem_stats_question(question) and decision.intent not in (
        "filesystem_stats", "disk_metadata", "file_hash_lookup", "file_size_lookup",
        "file_content_inspection", "registry_lookup",
    ):
        resolved_target = decision.entities.target_path
        reference_source = None

        # Partition inspection requires an image file, never a directory path.
        if resolved_target and not _is_forensic_image_path(resolved_target):
            resolved_target = None

        if (
            not resolved_target
            and conversation_state.last_artifact_type == "forensic_image"
            and _is_forensic_image_path(conversation_state.last_artifact)
        ):
            resolved_target = conversation_state.last_artifact
            reference_source = "conversation_context"

        if not resolved_target:
            default_image = _find_default_forensic_image_path()
            if default_image:
                resolved_target = default_image
                reference_source = reference_source or "case_context"

        if resolved_target and (
            _is_forensic_image_path(resolved_target)
            or conversation_state.last_artifact == resolved_target
            or conversation_state.last_artifact_type == "forensic_image"
        ):
            decision.intent = "image_partition_inspection"
            decision.entities.target_path = resolved_target
            decision.entities.path_scope = "host_filesystem"
            decision.entities.artifact_type = "forensic_image"
            decision.entities.operation = "inspect_partitions"
            decision.entities.application = None
            if conversation_state.last_user and not decision.entities.user:
                decision.entities.user = conversation_state.last_user
            if reference_source:
                decision.entities.reference_source = reference_source

            if reference_source and "use the most recent forensic image referenced in the conversation" not in decision.constraints:
                decision.constraints.append("use the most recent forensic image referenced in the conversation")
            if "return partition information only" not in decision.constraints:
                decision.constraints.append("return partition information only")
            decision.rewritten_question = (
                f"List the partitions contained in the forensic image {resolved_target}."
            )

    if _is_user_enumeration_question(question):
        decision.intent = "user_enumeration"
        decision.entities.user = None
        decision.entities.application = None
        decision.entities.path_scope = "forensic_image"
        decision.entities.artifact_type = "user_profile"
        decision.entities.operation = "enumerate_users"

        if conversation_state.last_artifact_type == "forensic_image" and conversation_state.last_artifact:
            decision.entities.target_path = conversation_state.last_artifact
            decision.entities.reference_source = "conversation_context"
        else:
            decision.entities.target_path = _find_default_forensic_image_path()
            if decision.entities.target_path:
                decision.entities.reference_source = "case_context"

        if "use the current forensic image or case context" not in decision.constraints:
            decision.constraints.append("use the current forensic image or case context")
        if "return only identified user profiles" not in decision.constraints:
            decision.constraints.append("return only identified user profiles")

        decision.rewritten_question = "List the user profiles present in the current forensic image or case evidence."

    return decision


def _derive_artifact_tool_plan(decision: OrchestrationDecision) -> List[str]:
    entities = decision.entities

    if decision.intent == "image_partition_inspection":
        return ["inspect_image_partitions"]
    if decision.intent == "partition_root_listing":
        return ["list_primary_partition_root"]
    if decision.intent == "user_enumeration":
        return ["list_users"]

    if entities.path_scope == "host_filesystem":
        if decision.intent in ("path_lookup",):
            return ["stat_path"]
        return ["list_directory"]

    if decision.intent == "directory_listing":
        if not entities.user:
            return ["get_case_context", "query_evidence"]
        return ["resolve_user_profile", "get_special_folder", "list_user_directory"]
    if decision.intent == "path_lookup":
        if not entities.user:
            return ["get_case_context", "query_evidence"]
        return ["resolve_user_profile", "get_special_folder"]
    if decision.intent == "file_search":
        if not entities.user:
            return ["get_case_context", "query_evidence"]
        return ["resolve_user_profile", "search_user_files"]
    if decision.intent == "timeline_lookup":
        if not entities.user:
            return ["query_timeline"]
        if entities.application:
            return ["resolve_user_profile", "get_last_app_execution"]
        return ["resolve_user_profile", "query_timeline"]
    if decision.intent == "artifact_lookup":
        if not entities.user:
            return ["get_case_context", "query_evidence"]
        if entities.target_path:
            return ["resolve_user_profile", "get_special_folder", "list_user_directory"]
        if entities.application:
            return ["resolve_user_profile", "get_last_app_execution"]
        return ["resolve_user_profile", "query_timeline"]
    if decision.intent == "file_hash_lookup":
        return ["get_file_hash"]
    if decision.intent == "file_size_lookup":
        return ["get_file_size"]
    if decision.intent == "file_content_inspection":
        return ["extract_file_content"]
    if decision.intent == "filesystem_stats":
        return ["get_filesystem_stats"]
    if decision.intent == "disk_metadata":
        return ["get_disk_metadata"]
    if decision.intent == "registry_lookup":
        return ["query_registry"]
    if decision.intent == "event_log_lookup":
        return ["query_event_log"]

    if not entities.user:
        return ["get_case_context", "query_evidence"]
    return ["resolve_user_profile", "query_timeline"]


def _apply_tool_plan_rules(decision: OrchestrationDecision) -> OrchestrationDecision:
    if decision.domain == "artifact":
        if decision.intent in {
            "image_partition_inspection", "partition_root_listing", "user_enumeration",
            "file_hash_lookup", "file_size_lookup", "file_content_inspection",
            "filesystem_stats", "disk_metadata", "registry_lookup", "event_log_lookup",
            "file_search", "artifact_lookup",
        }:
            decision.tool_plan = _derive_artifact_tool_plan(decision)
            return decision

        if decision.entities.path_scope == "user_profile":
            decision.tool_plan = _derive_artifact_tool_plan(decision)
            return decision

        user_specific = {
            "resolve_user_profile",
            "get_special_folder",
            "list_user_directory",
            "search_user_files",
            "get_last_app_execution",
        }
        specific = {
            "get_case_context",
            "query_evidence",
            "stat_path",
            "list_directory",
            "inspect_image_partitions",
            "list_primary_partition_root",
            "list_users",
            "resolve_user_profile",
            "get_special_folder",
            "list_user_directory",
            "search_user_files",
            "get_last_app_execution",
            "query_timeline",
            "get_file_hash",
            "get_file_size",
            "extract_file_content",
            "get_filesystem_stats",
            "get_disk_metadata",
            "query_registry",
        }
        has_specific = any(tool in specific for tool in decision.tool_plan)
        if not has_specific:
            decision.tool_plan = _derive_artifact_tool_plan(decision)
        else:
            # Keep only known artifact tools if planner mixes generic placeholders.
            cleaned = [tool for tool in decision.tool_plan if tool in specific]
            if not decision.entities.user and any(tool in user_specific for tool in cleaned):
                decision.tool_plan = _derive_artifact_tool_plan(decision)
            else:
                decision.tool_plan = cleaned or _derive_artifact_tool_plan(decision)

        if decision.entities.path_scope == "host_filesystem" and decision.intent != "image_partition_inspection":
            decision.tool_plan = _derive_artifact_tool_plan(decision)

    if decision.domain == "visual":
        decision.needs_image = True
        if "get_current_image" not in decision.tool_plan:
            decision.tool_plan = ["get_current_image"]

    return decision


def _build_classifier(llm: ChatOllama):
    classifier_llm = llm.with_structured_output(OrchestrationDecision)

    def classify_question(question: str, history: str):
        prompt = (
            f"{CLASSIFIER_PROMPT}\n\n"
            f"Conversation history:\n{history or '(empty)'}\n\n"
            f"User question:\n{question}"
        )
        plan = classifier_llm.invoke(prompt)
        return plan.model_dump()

    return classify_question


# =========================
# Build pipeline
# =========================

def build_pipeline():
    if not OLLAMA_MODEL:
        raise ValueError("OLLAMA_MODEL is empty.")

    print(f"[ollama] base_url={OLLAMA_BASE_URL}")
    print(f"[ollama] model={OLLAMA_MODEL}")

    llm = ChatOllama(
        model=OLLAMA_MODEL,
        base_url=OLLAMA_BASE_URL,
        temperature=0,
        validate_model_on_init=False,
    )

    classify_question = _build_classifier(llm)
    mcp_server = create_default_server(
        evidence_dir=_EVIDENCE_DIR,
        classify_question=classify_question,
    )
    mcp_client = LocalMCPClient(mcp_server)
    return llm, mcp_client


# =========================
# Artifact execution
# =========================

def _execute_artifact_tool(
    mcp_client: LocalMCPClient,
    tool_name: str,
    entities: DecisionEntities,
    rewritten_question: str,
) -> dict:
    user = entities.user or ""
    target_path = entities.target_path or "Desktop"

    if tool_name == "stat_path":
        return mcp_client.stat_path(target_path)
    if tool_name == "list_directory":
        include_dirs = entities.artifact_type != "file"
        return mcp_client.list_directory(
            target_path,
            recursive=False,
            include_dirs=bool(include_dirs),
        )
    if tool_name == "inspect_image_partitions":
        return mcp_client.inspect_image_partitions(target_path)
    if tool_name == "list_primary_partition_root":
        image_path = target_path if _is_forensic_image_path(target_path) else None
        return mcp_client.list_primary_partition_root(image_path=image_path)
    if tool_name == "list_users":
        image_path = target_path if _is_forensic_image_path(target_path) else None
        return mcp_client.list_users(image_path=image_path)

    if tool_name == "resolve_user_profile":
        if hasattr(mcp_client, "resolve_user_profile"):
            return mcp_client.resolve_user_profile(user)
        return {
            "status": "ok",
            "message": "Fallback artifact query executed for profile resolution.",
            "data": {"output": mcp_client.query_evidence(rewritten_question)},
        }
    if tool_name == "get_special_folder":
        if hasattr(mcp_client, "get_special_folder"):
            return mcp_client.get_special_folder(user=user, folder_name=target_path)
        return {
            "status": "ok",
            "message": "Fallback artifact query executed for folder resolution.",
            "data": {"output": mcp_client.query_evidence(rewritten_question)},
        }
    if tool_name == "list_user_directory":
        include_dirs = entities.artifact_type in (None, "directory", "folder")
        if hasattr(mcp_client, "list_user_directory"):
            return mcp_client.list_user_directory(
                user=user,
                folder_name=target_path,
                include_dirs=bool(include_dirs),
                recursive=False,
            )
        return {
            "status": "ok",
            "message": "Fallback artifact query executed for directory listing.",
            "data": {"output": mcp_client.query_evidence(rewritten_question)},
        }
    if tool_name == "search_user_files":
        pattern = entities.action if entities.action and "." in entities.action else None
        if hasattr(mcp_client, "search_user_files"):
            return mcp_client.search_user_files(user=user, path=entities.target_path, pattern=pattern)
        return {
            "status": "ok",
            "message": "Fallback artifact query executed for file search.",
            "data": {"output": mcp_client.query_evidence(rewritten_question)},
        }
    if tool_name == "get_last_app_execution":
        if hasattr(mcp_client, "get_last_app_execution"):
            return mcp_client.get_last_app_execution(user=user, app_name=entities.application or "")
        return {
            "status": "ok",
            "message": "Fallback artifact query executed for app execution lookup.",
            "data": {"output": mcp_client.query_evidence(rewritten_question)},
        }
    if tool_name == "query_timeline":
        return mcp_client.query_timeline(user=entities.user, timestamp=entities.timestamp_target)
    if tool_name == "get_case_context":
        return {
            "status": "ok",
            "message": "Case context retrieved.",
            "data": {"context": mcp_client.get_case_context()},
        }
    if tool_name == "query_evidence":
        return {
            "status": "ok",
            "message": "Evidence query executed.",
            "data": {"output": mcp_client.query_evidence(rewritten_question)},
        }

    if tool_name == "get_file_hash":
        algorithm = (entities.action or entities.algorithm or "md5").lower()
        if algorithm not in ("md5", "sha1", "sha256"):
            algorithm = "md5"
        file_path = entities.target_path or ""
        return mcp_client.get_file_hash(file_path=file_path, algorithm=algorithm)

    if tool_name == "get_file_size":
        return mcp_client.get_file_size(file_path=entities.target_path or "")

    if tool_name == "extract_file_content":
        return mcp_client.extract_file_content(file_path=entities.target_path or "")

    if tool_name == "get_filesystem_stats":
        image_path = entities.target_path if _is_forensic_image_path(entities.target_path or "") else None
        return mcp_client.get_filesystem_stats(image_path=image_path)

    if tool_name == "get_disk_metadata":
        image_path = entities.target_path if _is_forensic_image_path(entities.target_path or "") else None
        return mcp_client.get_disk_metadata(image_path=image_path)

    if tool_name == "query_registry":
        hive = (entities.artifact_type or "sam").lower()
        key_path = entities.action or None
        image_path = entities.target_path if _is_forensic_image_path(entities.target_path or "") else None
        return mcp_client.query_registry(hive=hive, key_path=key_path, user=entities.user, image_path=image_path)

    if tool_name == "query_event_log":
        log_name = (entities.artifact_type or "system").lower()
        if log_name not in ("system", "application", "security"):
            log_name = "system"
        # action may contain event IDs (e.g. "6013") or timestamp filter
        action = (entities.action or "").strip()
        event_ids = None
        timestamp_filter = None
        if action.isdigit():
            event_ids = [int(action)]
        elif action:
            timestamp_filter = action
        # Also parse timestamp_target if set
        if entities.timestamp_target:
            timestamp_filter = entities.timestamp_target
        image_path = entities.target_path if _is_forensic_image_path(entities.target_path or "") else None
        return mcp_client.query_event_log(
            log_name=log_name, event_ids=event_ids, timestamp=timestamp_filter, image_path=image_path
        )

    return {
        "status": "tool_error",
        "message": f"Unknown artifact tool '{tool_name}'.",
        "data": {},
    }


def _artifact_failure_message(status: str, message: str) -> str:
    mapping = {
        "user_not_found": "The requested user profile was not found in the evidence image.",
        "path_not_resolved": "The requested folder or path could not be resolved for that user.",
        "directory_empty": "The target directory exists but no entries matched the requested filters.",
        "artifact_not_found": "The artifact was not found in the indexed evidence set.",
        "insufficient_index_data": "Evidence indexes are insufficient to answer this query reliably.",
        "tool_error": "The forensic toolchain failed while processing the query.",
    }
    base = mapping.get(status, "No relevant evidence was found for this artifact query.")
    if message:
        return f"{base} Details: {message}"
    return base


def _run_artifact_flow(
    llm: ChatOllama,
    mcp_client: LocalMCPClient,
    decision: OrchestrationDecision,
    conversation_state: Optional[ConversationState] = None,
    original_question: str = "",
) -> tuple[OrchestrationDecision, str]:
    if decision.intent == "image_partition_inspection":
        return _run_image_partition_inspection_flow(mcp_client, decision, conversation_state)
    if decision.intent == "partition_root_listing":
        return _run_partition_root_listing_flow(mcp_client, decision, conversation_state)
    if decision.intent == "user_enumeration":
        return _run_user_enumeration_flow(mcp_client, decision, conversation_state)

    _flow_protected_intents = {
        "file_content_inspection", "file_hash_lookup", "file_size_lookup",
        "filesystem_stats", "disk_metadata", "registry_lookup", "event_log_lookup",
    }
    if decision.entities.path_scope == "host_filesystem" and decision.intent not in _flow_protected_intents:
        # Literal filesystem operations must not be mixed with case context or forensic-image expansion.
        return _run_literal_path_flow(mcp_client, decision, conversation_state)

    case_context = mcp_client.get_case_context()
    template_payload = mcp_client.get_prompt_template(intent=_intent_to_template(decision.intent))
    template_text = template_payload.get("template") if isinstance(template_payload, dict) else SAFE_GENERIC_TEMPLATE
    template_name = _normalize_template_name(
        template_payload.get("name") if isinstance(template_payload, dict) else decision.intent
    )

    tool_results = []
    for tool_name in decision.tool_plan:
        result = _execute_artifact_tool(
            mcp_client,
            tool_name,
            decision.entities,
            decision.rewritten_question,
        )
        tool_results.append({"tool": tool_name, "result": result})

    ok_results = [item for item in tool_results if item["result"].get("status") == RESULT_OK]
    if not ok_results:
        first = tool_results[0]["result"] if tool_results else {"status": "artifact_not_found", "message": "No tool result."}
        return decision, _artifact_failure_message(first.get("status", "artifact_not_found"), first.get("message", ""))

    if decision.intent == "directory_listing":
        direct_answer = _build_directory_listing_answer(tool_results, decision)
        if direct_answer:
            return decision, direct_answer

    if decision.intent == "timeline_lookup":
        direct_answer = _build_timeline_answer(tool_results, decision)
        if direct_answer:
            return decision, direct_answer

    final_instruction = (
        "You are a forensic artifact analysis assistant.\n"
        "Task: answer only from MCP tool outputs.\n\n"
        f"Prompt template ({template_name}): {template_text}\n\n"
        f"Case context:\n{shorten_text(case_context, max_len=1400)}\n\n"
        + (
            f"Original user question (use this to determine answer format — "
            f"if it asks for a count/quantity reply with a number; "
            f"if it asks for names/list/what files reply with the actual file names): {original_question}\n\n"
            if original_question else ""
        )
        + f"Rewritten question:\n{decision.rewritten_question}\n\n"
        "Tool results (JSON):\n"
        f"{json.dumps(tool_results, ensure_ascii=False, indent=2)}\n\n"
        "Response policy:\n"
        "- Never invent timestamps, paths, or events.\n"
        "- If status is not ok, explain the exact failure reason from status/message.\n"
        "- Distinguish: user_not_found, path_not_resolved, directory_empty, artifact_not_found, insufficient_index_data, tool_error."
    )
    response = llm.invoke([HumanMessage(content=[{"type": "text", "text": final_instruction}])])
    answer = (response.content if hasattr(response, "content") else str(response)).strip()
    _update_conversation_state(conversation_state, decision, tool_results)
    return decision, answer


def _build_directory_listing_answer(tool_results: List[dict], decision: OrchestrationDecision) -> Optional[str]:
    for item in reversed(tool_results):
        result = item.get("result") or {}
        if result.get("status") != "ok":
            continue
        entries = result.get("entries")
        if not isinstance(entries, list):
            continue

        if not entries:
            return "Directory exists but is empty."

        include_files = decision.entities.artifact_type != "folder"
        include_dirs = decision.entities.artifact_type != "file"

        filtered = []
        for entry in entries:
            etype = entry.get("type")
            if etype == "file" and include_files:
                filtered.append(entry)
            elif etype == "dir" and include_dirs:
                filtered.append(entry)

        if not filtered:
            kind = "files" if decision.entities.artifact_type == "file" else "directories"
            return f"No {kind} were found in the requested location."

        lines = [f"- {entry.get('name')} ({entry.get('type')})" for entry in filtered]
        return "\n".join(lines)

    return None


def _build_timeline_answer(
    tool_results: List[dict], decision: OrchestrationDecision
) -> Optional[str]:
    """Build a direct answer for timeline_lookup when the result has unique_active_dates."""
    for item in tool_results:
        result = item.get("result") or {}
        if result.get("status") != "ok":
            continue
        dates = result.get("unique_active_dates")
        if not isinstance(dates, list) or not dates:
            continue
        user = result.get("user")
        who = f" for user **{user}**" if user else ""
        ts_filter = result.get("timestamp_filter")
        last = (result.get("last_event") or {}).get("timestamp", "")
        first = (result.get("first_event") or {}).get("timestamp", "")

        if ts_filter:
            # Date-filtered query: was computer on that day?
            return (
                f"Activity found on {ts_filter}{who}: {len(dates)} logon event(s).\n"
                f"First: {first}  Last: {last}"
            )

        # All-dates query
        date_lines = "\n".join(f"  {d}" for d in dates)
        total = result.get("total_events", len(dates))
        return (
            f"The computer was used on **{len(dates)} day(s)**{who} "
            f"({total} logon/logoff events total):\n{date_lines}\n\n"
            f"First activity: {first}\nLast activity:  {last}"
        )

    return None


def _run_literal_path_flow(
    mcp_client: LocalMCPClient,
    decision: OrchestrationDecision,
    conversation_state: Optional[ConversationState] = None,
) -> tuple[OrchestrationDecision, str]:
    results = []
    for tool_name in decision.tool_plan:
        result = _execute_artifact_tool(
            mcp_client,
            tool_name,
            decision.entities,
            decision.rewritten_question,
        )
        results.append({"tool": tool_name, "result": result})

    _update_conversation_state(conversation_state, decision, results)

    if not results:
        return decision, "No filesystem tool was executed."

    final = results[-1]["result"]
    status = final.get("status")
    if status == "ok":
        if "entries" in final:
            entries = final.get("entries", [])
            if not entries:
                return decision, "Directory exists but is empty."
            lines = []
            for entry in entries:
                lines.append(f"- {entry.get('name')} ({entry.get('type')})")
            return decision, "\n".join(lines)
        if final.get("is_dir") is not None:
            return decision, json.dumps(final, ensure_ascii=False, indent=2)

    if status == "path_not_resolved":
        return decision, f"Path not resolved: {final.get('message', 'Path does not exist.')}"
    if status == "directory_empty":
        return decision, "Directory exists but is empty."

    return decision, f"Filesystem operation failed: {final.get('message', 'unknown error')}"


def _run_image_partition_inspection_flow(
    mcp_client: LocalMCPClient,
    decision: OrchestrationDecision,
    conversation_state: Optional[ConversationState] = None,
) -> tuple[OrchestrationDecision, str]:
    results = []
    for tool_name in decision.tool_plan:
        result = _execute_artifact_tool(
            mcp_client,
            tool_name,
            decision.entities,
            decision.rewritten_question,
        )
        results.append({"tool": tool_name, "result": result})

    _update_conversation_state(conversation_state, decision, results)

    if not results:
        return decision, "No partition inspection tool was executed."

    final = results[-1]["result"]
    status = final.get("status")
    if status != "ok":
        return decision, _artifact_failure_message(status, final.get("message", ""))

    partitions = final.get("partitions", [])
    if not partitions:
        return decision, "No partitions were reported for the forensic image."

    lines = []
    for part in partitions:
        lines.append(
            "- slot {slot}: start={start} end={end} length={length} desc={desc}".format(
                slot=part.get("slot"),
                start=part.get("start_sector"),
                end=part.get("end_sector"),
                length=part.get("length_sectors"),
                desc=part.get("description"),
            )
        )
    return decision, "\n".join(lines)


def _run_user_enumeration_flow(
    mcp_client: LocalMCPClient,
    decision: OrchestrationDecision,
    conversation_state: Optional[ConversationState] = None,
) -> tuple[OrchestrationDecision, str]:
    results = []
    for tool_name in decision.tool_plan:
        result = _execute_artifact_tool(
            mcp_client,
            tool_name,
            decision.entities,
            decision.rewritten_question,
        )
        results.append({"tool": tool_name, "result": result})

    _update_conversation_state(conversation_state, decision, results)

    if not results:
        return decision, "No user-enumeration tool was executed."

    final = results[-1]["result"]
    status = final.get("status")
    if status != "ok":
        return decision, _artifact_failure_message(status, final.get("message", ""))

    users = final.get("users", [])
    if not users:
        return decision, "No user profiles were identified in the selected evidence source."

    lines = [f"- {name}" for name in users]
    return decision, "\n".join(lines)


def _run_partition_root_listing_flow(
    mcp_client: LocalMCPClient,
    decision: OrchestrationDecision,
    conversation_state: Optional[ConversationState] = None,
) -> tuple[OrchestrationDecision, str]:
    results = []
    for tool_name in decision.tool_plan:
        result = _execute_artifact_tool(
            mcp_client,
            tool_name,
            decision.entities,
            decision.rewritten_question,
        )
        results.append({"tool": tool_name, "result": result})

    _update_conversation_state(conversation_state, decision, results)

    if not results:
        return decision, "No partition root listing tool was executed."

    final = results[-1]["result"]
    status = final.get("status")
    if status != "ok":
        return decision, _artifact_failure_message(status, final.get("message", ""))

    entries = final.get("entries", [])
    if not entries:
        return decision, "No entries were found in the root of the primary partition."

    lines = [f"- {entry.get('name')} ({entry.get('type')})" for entry in entries]
    return decision, "\n".join(lines)


def _update_conversation_state(
    conversation_state: Optional[ConversationState],
    decision: OrchestrationDecision,
    tool_results: List[dict],
) -> None:
    if not conversation_state:
        return

    if decision.entities.target_path:
        conversation_state.last_path = decision.entities.target_path
    if decision.entities.user:
        conversation_state.last_user = decision.entities.user

    if decision.intent == "image_partition_inspection" and _is_forensic_image_path(decision.entities.target_path):
        conversation_state.last_artifact = decision.entities.target_path
        conversation_state.last_artifact_type = "forensic_image"

    for item in tool_results:
        tool_name = item.get("tool")
        result = item.get("result") or {}
        if result.get("status") != "ok":
            continue

        if tool_name == "inspect_image_partitions":
            image_path = result.get("image_path") or decision.entities.target_path
            if image_path:
                conversation_state.last_artifact = image_path
                conversation_state.last_artifact_type = "forensic_image"
                conversation_state.last_path = image_path

        if tool_name == "list_directory":
            base_path = result.get("path") or decision.entities.target_path
            entries = result.get("entries") or []
            for entry in entries:
                if entry.get("type") != "file":
                    continue
                name = str(entry.get("name") or "")
                if _is_forensic_image_path(name):
                    artifact_path = _join_paths(base_path, name)
                    conversation_state.last_artifact = artifact_path
                    conversation_state.last_artifact_type = "forensic_image"
                    break


def _join_paths(base_path: Optional[str], name: str) -> str:
    base = (base_path or "").replace("\\", "/").rstrip("/")
    if not base:
        return name
    if base == ".":
        return f"./{name}"
    return f"{base}/{name}"


def _extract_literal_path(question: str) -> Optional[str]:
    text = question or ""
    # Supports /evidence, ./out, ../data and Windows absolute paths.
    match = re.search(r"(?<!\w)(/[\w\-./]+|\.{1,2}/[\w\-./]+|[A-Za-z]:\\[^\s]+)", text)
    if not match:
        return None
    token = match.group(1).rstrip("?.!,;:")
    return token


# =========================
# Main query flow
# =========================

def _safe_no_evidence_response(reason: str) -> str:
    return (
        "Insufficient visual evidence to answer safely. "
        f"Reason: {reason}. "
        "Please provide a relevant image to continue."
    )


def run_forensic_visual_flow(
    llm: ChatOllama,
    mcp_client: LocalMCPClient,
    question: str,
    history: List[str],
    conversation_state: Optional[ConversationState] = None,
):
    history_text = _history_to_text(history)
    raw_plan = mcp_client.classify_question(question=question, history=history_text)
    decision = _normalize_decision(raw_plan)
    decision = _apply_artifact_entity_rules(decision, question)
    decision = _apply_conversation_reference_rules(decision, question, conversation_state)
    decision = _apply_tool_plan_rules(decision)

    if decision.intent == "unsafe_inference":
        return decision, (
            "I cannot help with speculative or unsafe inference requests. "
            "I can only describe directly supported evidence."
        )

    if decision.domain == "artifact":
        # Artifact policy: always execute planned MCP tools before final answer.
        return _run_artifact_flow(llm, mcp_client, decision, conversation_state, original_question=question)

    case_context = mcp_client.get_case_context()
    image_path = mcp_client.get_current_image()
    if not image_path:
        decision.intent = "insufficient_evidence"
        return decision, _safe_no_evidence_response("no image found in evidence directory")

    template_payload = mcp_client.get_prompt_template(intent=_intent_to_template(decision.intent))
    template_text = template_payload.get("template") if isinstance(template_payload, dict) else None
    template_name = template_payload.get("name") if isinstance(template_payload, dict) else None

    if not template_text:
        template_text = SAFE_GENERIC_TEMPLATE
    resolved_template_name = _normalize_template_name(template_name or decision.intent)

    constraints_text = "\n".join(f"- {c}" for c in (decision.constraints or []))
    if not constraints_text:
        constraints_text = "- Use only visible evidence from the provided image."

    final_instruction = (
        "You are a forensic visual analysis assistant.\n"
        "Task: answer only from visible evidence.\n\n"
        f"Prompt template ({resolved_template_name}): {template_text}\n\n"
        f"Case context:\n{shorten_text(case_context, max_len=1600)}\n\n"
        f"Rewritten question:\n{decision.rewritten_question}\n\n"
        f"Constraints:\n{constraints_text}\n\n"
        "Response policy:\n"
        "- If evidence is insufficient, explicitly say so.\n"
        "- Do not infer identity, intent, timeline, or hidden causes.\n"
        "- Keep the answer grounded in what is directly visible."
    )

    content = [{"type": "text", "text": final_instruction}]
    content.append(
        {
            "type": "image_url",
            "image_url": {"url": _read_image_as_data_url(image_path)},
        }
    )

    response = llm.invoke([HumanMessage(content=content)])
    answer = (response.content if hasattr(response, "content") else str(response)).strip()
    return decision, answer


# =========================
# Pretty terminal output
# =========================

def print_step(text: str):
    print(f"\n[passo] {text}")


def print_tool_call(tool_name: str, args: dict):
    print_step(f"A executar tool: {tool_name}")
    print(f"[decisao] {tool_name}")
    print(f"[args] {args}")


def print_tool_result(tool_name: str, content: str):
    text = str(content).strip()

    if is_error_text(text):
        print(f"\n[aviso:{tool_name}] tentativa falhou, a corrigir...")
        print(shorten_text(text, max_len=600))
        return

    print(f"\n[resultado:{tool_name}]")
    print(shorten_text(text))


def print_final_answer(text: str):
    text = (text or "").strip()
    if text:
        print("\n[resposta final]")
        print(text)


def print_plan(plan: OrchestrationDecision):
    payload = plan.model_dump()
    print_step("Plano estruturado (classificacao)")
    print(json.dumps(payload, indent=2, ensure_ascii=False))


# =========================
# Main
# =========================

def main():
    ensure_container()
    llm, mcp_client = build_pipeline()
    history: List[str] = []
    conversation_state = ConversationState()

    while True:
        query = input("\nPergunta (ou 'sair'): ").strip()

        if query.lower() in ("sair", "exit", "quit"):
            break

        try:
            plan, answer = run_forensic_visual_flow(
                llm=llm,
                mcp_client=mcp_client,
                question=query,
                history=history,
                conversation_state=conversation_state,
            )

            print_plan(plan)
            print_final_answer(answer)

            history.append(f"user: {query}")
            history.append(f"assistant: {shorten_text(answer, max_len=500)}")

            print()

        except Exception as e:
            print(f"\n[erro] {e}")


if __name__ == "__main__":
    main()