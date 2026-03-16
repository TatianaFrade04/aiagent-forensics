"""
Normalization and validation layer.

All functions here are deterministic — no LLM calls.

WHY THIS IS BETTER THAN LLM-GENERATED TOOL PLANNING:
  Edge-case handling (folder aliases, hash variants, image fallback) lives in
  one place with explicit mappings rather than scattered prompt rules that the
  LLM may or may not follow.
"""
from __future__ import annotations

import os
from typing import Any, Optional

from agent.capabilities import Capability, get_capability

# ---------------------------------------------------------------------------
# Alias maps
# ---------------------------------------------------------------------------

_FOLDER_ALIASES: dict[str, str] = {
    "desktop": "Desktop",
    "downloads": "Downloads",
    "documents": "Documents",
    "documentos": "Documents",
    "docs": "Documents",
    "pictures": "Pictures",
    "photos": "Pictures",
    "images": "Pictures",
    "fotos": "Pictures",
    "music": "Music",
    "musica": "Music",
    "música": "Music",
    "videos": "Videos",
    "video": "Videos",
    "vídeos": "Videos",
    "appdata": "AppData",
    "app data": "AppData",
}

_HASH_ALIASES: dict[str, str] = {
    "md5": "md5",
    "sha1": "sha1",
    "sha-1": "sha1",
    "sha 1": "sha1",
    "sha256": "sha256",
    "sha-256": "sha256",
    "sha 256": "sha256",
    "sha2": "sha256",
}

_HIVE_ALIASES: dict[str, str] = {
    "sam": "sam",
    "ntuser": "ntuser",
    "ntuser.dat": "ntuser",
    "software": "software",
    "system": "system",
    "security": "security",
}

_LOG_ALIASES: dict[str, str] = {
    "system": "system",
    "sys": "system",
    "application": "application",
    "app": "application",
    "security": "security",
    "sec": "security",
}

# Maps natural-language query qualifiers to canonical values understood by the
# responder's timeline formatter ("all", "first", "last").
_TIMELINE_QUERY_ALIASES: dict[str, str] = {
    "all": "all",
    "all_dates": "all",
    "dates": "all",
    "days": "all",
    "first": "first",
    "first_use": "first",
    "earliest": "first",
    "first_time": "first",
    "last": "last",
    "last_use": "last",
    "latest": "last",
    "most_recent": "last",
    "recently": "last",
}

_VALID_ALGORITHMS = {"md5", "sha1", "sha256"}
_VALID_HIVES = {"sam", "ntuser", "software", "system", "security"}
_VALID_LOG_NAMES = {"system", "application", "security"}


# ---------------------------------------------------------------------------
# Individual normalizers
# ---------------------------------------------------------------------------

def normalize_folder(folder: str) -> str:
    """Map a folder alias to its canonical Windows spelling."""
    return _FOLDER_ALIASES.get((folder or "").strip().lower(), (folder or "Desktop").strip())


def normalize_algorithm(algorithm: str) -> str:
    """Map a hash-algorithm alias to md5 / sha1 / sha256.  Falls back to 'md5'."""
    return _HASH_ALIASES.get((algorithm or "").strip().lower(), "md5")


def normalize_hive(hive: str) -> str:
    """Map a registry-hive alias to its canonical name.  Falls back to 'sam'."""
    return _HIVE_ALIASES.get((hive or "").strip().lower(), "sam")


def normalize_log_name(log_name: str) -> str:
    """Map an event-log alias to system / application / security.  Falls back to 'system'."""
    return _LOG_ALIASES.get((log_name or "").strip().lower(), "system")


def normalize_timeline_query(query: str) -> str:
    """Map a timeline query qualifier to 'all', 'first', or 'last'.  Falls back to 'all'."""
    return _TIMELINE_QUERY_ALIASES.get((query or "").strip().lower(), "all")


_EMAIL_QUERY_TYPE_ALIASES: dict[str, str] = {
    "accounts": "accounts",
    "account": "accounts",
    "conta": "accounts",
    "contas": "accounts",
    "count": "count",
    "counting": "count",
    "how many": "count",
    "quantos": "count",
    "quantas": "count",
    "total": "count",
    "número": "count",
    "numero": "count",
}


def normalize_email_query_type(query_type: str) -> str:
    """Map an email query type alias to 'accounts' or 'count'.  Falls back to 'accounts'."""
    return _EMAIL_QUERY_TYPE_ALIASES.get((query_type or "").strip().lower(), "accounts")


def _strip_file_path_quotes(path: str) -> str:
    """
    Strip a single layer of surrounding quote characters from a file path.

    Handles:
      - ASCII straight double quotes:  "file.txt"  ->  file.txt
      - ASCII straight single quotes:  'file.txt'  ->  file.txt
      - Unicode LEFT/RIGHT DOUBLE QUOTATION MARKS (U+201C / U+201D):
        \u201cfile.txt\u201d  ->  file.txt
      - Unicode LEFT/RIGHT SINGLE QUOTATION MARKS (U+2018 / U+2019):
        \u2018file.txt\u2019  ->  file.txt

    The LLM parser echoes the user's quotation marks verbatim; these prevent
    the fls substring / exact-basename match from finding the file.
    """
    p = (path or "").strip()
    if len(p) < 2:
        return p
    OPEN_TO_CLOSE = {
        '"': '"',    # ASCII double
        "'":  "'",   # ASCII single
        '\u201c': '\u201d',  # LEFT/RIGHT DOUBLE QUOTATION MARK
        '\u2018': '\u2019',  # LEFT/RIGHT SINGLE QUOTATION MARK
    }
    expected_close = OPEN_TO_CLOSE.get(p[0])
    if expected_close and p[-1] == expected_close:
        return p[1:-1].strip()
    return p


def _strip_evidence_prefix(path: str) -> str:
    """
    Strip a leading /evidence/ prefix from a file path used for forensic image
    searches (get_file_size, compute_file_hash, read_file_content).

    These tools search inside the forensic image partition using fls output paths
    like 'users/jimmy/desktop/notes.txt'.  A path like '/evidence/notes.txt'
    would NEVER match those lines because the fls output never contains
    '/evidence/'.  Stripping the prefix turns it into a bare filename that
    is found via substring match.

    The stripping only applies when the part after /evidence/ contains no
    further path separators, meaning it is a simple filename the LLM wrongly
    anchored to /evidence/.  If the user specifies a deep path such as
    '/evidence/Users/Alice/doc.txt', the full path is preserved (it may
    refer to a known in-image path where the leading slash is stripped by
    the server function already).
    """
    normalized = (path or "").strip()
    prefix = "/evidence/"
    if normalized.lower().startswith(prefix):
        remainder = normalized[len(prefix):]
        if "/" not in remainder:
            return remainder
    return normalized


# ---------------------------------------------------------------------------
# Image path discovery
# ---------------------------------------------------------------------------

def find_default_forensic_image(evidence_dir: str) -> Optional[str]:
    """
    Scan *evidence_dir* recursively for the first forensic image found.
    Returns a /evidence/... style path compatible with MCP tool calls.
    """
    if not os.path.isdir(evidence_dir):
        return None
    candidates: list[str] = []
    project_root = os.path.dirname(evidence_dir)
    for root, _, files in os.walk(evidence_dir):
        for filename in files:
            if filename.lower().endswith((".e01", ".dd", ".img", ".raw", ".001")):
                full = os.path.join(root, filename)
                rel = os.path.relpath(full, project_root).replace("\\", "/")
                candidates.append("/" + rel)
    if not candidates:
        return None
    candidates.sort()
    return candidates[0]


# ---------------------------------------------------------------------------
# Per-capability parameter normalization
# ---------------------------------------------------------------------------

def normalize_parameters(capability_name: str, params: dict[str, Any]) -> dict[str, Any]:
    """
    Apply deterministic alias normalization to *params* for the given capability.
    Always returns a new dict; never mutates the input.
    """
    p = dict(params)

    if capability_name == "list_user_folder":
        if "folder" in p:
            p["folder"] = normalize_folder(p["folder"])

    if capability_name == "compute_file_hash":
        # Always ensure algorithm is present; normalizer is the single authority.
        p["algorithm"] = normalize_algorithm(p.get("algorithm", "md5"))

    # Normalise file_path: strip surrounding quotes THEN strip /evidence/ prefix.
    # Quote-stripping must come first: the LLM may emit '"filename.txt"' which
    # _strip_evidence_prefix would not recognise as starting with /evidence/.
    if capability_name in ("get_file_size", "compute_file_hash", "read_file_content"):
        if p.get("file_path"):
            p["file_path"] = _strip_evidence_prefix(_strip_file_path_quotes(p["file_path"]))
        # Strip surrounding quotes from bare filenames too (LLM echoes the user's
        # quotation marks verbatim, e.g. '\u201cThe Width Of A Circle.txt\u201d').
        if p.get("filename"):
            p["filename"] = _strip_file_path_quotes(p["filename"])

    if capability_name == "inspect_registry":
        p["hive"] = normalize_hive(p.get("hive", "sam"))

    if capability_name == "inspect_event_logs":
        p["log_name"] = normalize_log_name(p.get("log_name", "system"))

    if capability_name == "inspect_timeline":
        # Normalize the optional query qualifier so the responder can use it.
        p["query"] = normalize_timeline_query(p.get("query", "all"))

    if capability_name == "inspect_filesystem":
        # Normalize partition_index to int when the parser returns it as a string.
        if p.get("partition_index") is not None:
            try:
                p["partition_index"] = int(p["partition_index"])
            except (ValueError, TypeError):
                p.pop("partition_index", None)

    if capability_name == "inspect_email_accounts":
        p["query_type"] = normalize_email_query_type(p.get("query_type", "accounts"))

    return p


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

# Configurable confidence threshold (override via env var).
CONFIDENCE_THRESHOLD: float = float(os.getenv("PARSER_CONFIDENCE_THRESHOLD", "0.65"))


class ValidationError(Exception):
    """Raised when a parsed request fails validation before execution."""

    def __init__(self, error_code: str, message: str) -> None:
        super().__init__(message)
        self.error_code = error_code


def validate_parsed_request(
    capability_name: str,
    confidence: float,
    parameters: dict[str, Any],
    evidence_dir: Optional[str] = None,
    last_known_image_path: Optional[str] = None,
    last_known_file_path: Optional[str] = None,
) -> dict[str, Any]:
    """
    Validate a parsed request and return an enriched parameters dict.

    Checks performed (in order):
      1. Reject the 'unsupported_request' sentinel.
      2. Reject unknown capability names.
      3. Enforce the confidence threshold.
      4. Inject a default image_path when the capability can use one but none was given.
      5. Inject last_known_file_path for read_file_content / get_file_size when the
         user refers to a file from conversation context without re-specifying it.
      6. Verify all required parameters are present.

    Raises ValidationError with a structured error_code on any failure.
    Out-of-scope requests never reach MCP tool execution.
    """
    # 1. Sentinel.
    if capability_name == "unsupported_request":
        raise ValidationError(
            "unsupported_request",
            "This question is outside the supported forensic capability set.",
        )

    # 2. Unknown capability.
    capability: Optional[Capability] = get_capability(capability_name)
    if capability is None:
        raise ValidationError(
            "unsupported_request",
            f"Unknown capability '{capability_name}'.",
        )

    # 3. Confidence threshold.
    if confidence < CONFIDENCE_THRESHOLD:
        raise ValidationError(
            "low_confidence",
            (
                f"Parser confidence {confidence:.2f} is below the required "
                f"threshold {CONFIDENCE_THRESHOLD:.2f}. "
                "Please rephrase the question or provide more context."
            ),
        )

    # 4. Image path fallback: inject if the capability can use one but none was given.
    all_params = set(capability.required_params + capability.optional_params)
    params = dict(parameters)
    if "image_path" in all_params and not params.get("image_path"):
        if last_known_image_path:
            params["image_path"] = last_known_image_path
        elif evidence_dir:
            default_image = find_default_forensic_image(evidence_dir)
            if default_image:
                params["image_path"] = default_image

    # 5. File path fallback: inject for file-centric capabilities when the user
    #    references the file from conversation context without re-specifying it
    #    (e.g. "show the content of that email" after a prior file listing).
    #    Skip injection when 'filename' is already present — the executor will
    #    route that to find_file_by_name instead of calling get_file_size directly.
    if "file_path" in all_params and not params.get("file_path") and not params.get("filename"):
        if last_known_file_path:
            params["file_path"] = last_known_file_path

    # 6. Required parameters.
    for req in capability.required_params:
        if not params.get(req):
            raise ValidationError(
                "missing_required_parameter",
                f"Required parameter '{req}' is missing for capability '{capability_name}'.",
            )

    return params
