"""
Final answer composition for the capability-based forensic assistant.

All answers are grounded strictly in MCP tool outputs.
The LLM is used only for capabilities whose output is rich/semi-structured
(file content, registry, event logs, email accounts, filesystem/disk metadata).
"""
from __future__ import annotations

import json
from typing import Any, Callable, List, Optional

from langchain_core.messages import HumanMessage
from langchain_ollama import ChatOllama

# ---------------------------------------------------------------------------
# Error catalogue
# ---------------------------------------------------------------------------

_ERROR_MESSAGES: dict[str, str] = {
    "unsupported_request": (
        "This question is outside the supported forensic capability set. "
        "Please ask a question about partitions, users, files, registry, "
        "event logs, timeline, or email accounts."
    ),
    "low_confidence": (
        "The question could not be mapped to a supported forensic capability "
        "with sufficient confidence. Please rephrase or provide more context."
    ),
    "missing_required_parameter": (
        "A required parameter for this capability was not provided or could "
        "not be inferred. Please specify the missing information."
    ),
    "artifact_not_found": (
        "The requested artifact was not found in the evidence source."
    ),
    "user_not_found": (
        "The requested user profile was not found in the forensic image."
    ),
    "path_not_resolved": (
        "The requested path could not be resolved in the evidence source."
    ),
    "tool_error": (
        "The forensic toolchain encountered an error while processing the request."
    ),
    "container_not_running": (
        "The forensic container is not running. The system will attempt to "
        "restart it automatically on the next request. If the problem persists, "
        "please ensure Docker Desktop is running."
    ),
    "docker_daemon_down": (
        "Docker daemon is not reachable. Please start Docker Desktop and try again."
    ),
    "directory_empty": (
        "The target directory exists but contains no entries."
    ),
    "insufficient_index_data": (
        "Evidence indexes are insufficient to answer this query reliably."
    ),
    "multiple_matches": (
        "Multiple files with that name were found. "
        "Please re-ask with the full path from the list below."
    ),
}


def error_response(error_code: str, detail: str = "") -> str:
    """Return a user-facing error message for *error_code*."""
    # Upgrade raw Docker errors to specific error codes.
    if error_code == "tool_error" and detail:
        lower_detail = detail.lower()
        if "is not running" in lower_detail or "container" in lower_detail and "not running" in lower_detail:
            error_code = "container_not_running"
        elif "daemon" in lower_detail or "pipe" in lower_detail or "cannot connect" in lower_detail:
            error_code = "docker_daemon_down"

    base = _ERROR_MESSAGES.get(error_code, f"Unexpected error ({error_code}).")
    return f"{base}\nDetail: {detail}" if detail else base


# ---------------------------------------------------------------------------
# Direct (non-LLM) formatters for fully structured outputs
# ---------------------------------------------------------------------------

def _fmt_partition_listing(result: dict) -> str:
    partitions = result.get("partitions") or []
    if not partitions:
        return "No partitions were found in the forensic image."
    lines = [
        f"  Slot {p.get('slot')}: "
        f"start={p.get('start_sector')}  "
        f"end={p.get('end_sector')}  "
        f"length={p.get('length_sectors')}  "
        f"-- {p.get('description')}"
        for p in partitions
    ]
    return f"{len(partitions)} partition(s) found:\n" + "\n".join(lines)


def _fmt_user_listing(result: dict) -> str:
    users = result.get("users") or []
    if not users:
        return "No user profiles found in the evidence image."
    lines = [f"  - {u}" for u in users]
    return f"{len(users)} user(s) found:\n" + "\n".join(lines)


def _fmt_directory_entries(result: dict) -> str:
    entries = result.get("entries") or []
    if not entries:
        return "Directory exists but is empty."
    lines = [f"  - {e.get('name')}  ({e.get('type')})" for e in entries]
    return f"{len(entries)} entr(ies):\n" + "\n".join(lines)


def _fmt_file_hash(result: dict) -> str:
    algo = (result.get("algorithm") or "").upper()
    value = (
        result.get("hash")
        or result.get("value")
        or result.get("digest")
        or "N/A"
    )
    path = result.get("file_path") or result.get("path") or ""
    return f"{algo} hash of '{path}':  {value}"


def _fmt_file_size(result: dict) -> str:
    size = (
        result.get("size_bytes")
        or result.get("size")
        or result.get("logical_size")
    )
    path = result.get("file_path") or result.get("path") or ""
    if size is None:
        return f"Size of '{path}': unavailable."
    base = f"Size of '{path}':  {size:,} bytes"
    note = result.get("fuzzy_note")
    return f"{base}\n  ({note})" if note else base


def _fmt_timeline(result: dict) -> str:
    dates = result.get("unique_active_dates") or []
    user = result.get("user")
    who = f" for user '{user}'" if user else ""
    ts_filter = result.get("timestamp_filter")
    first_ts = (result.get("first_event") or {}).get("timestamp", "")
    last_ts = (result.get("last_event") or {}).get("timestamp", "")

    if ts_filter:
        return (
            f"Activity found on {ts_filter}{who}: {len(dates)} logon event(s).\n"
            f"  First: {first_ts}   Last: {last_ts}"
        )
    if not dates:
        return f"No activity recorded{who}."

    total = result.get("total_events", len(dates))
    date_block = "\n".join(f"    {d}" for d in dates)
    return (
        f"Active on {len(dates)} day(s){who} ({total} events total):\n"
        f"{date_block}\n"
        f"  First: {first_ts}   Last: {last_ts}"
    )


# Capabilities whose tool output is fully structured -> direct formatter.
_DIRECT_FORMATTERS: dict[str, Callable[[list[dict]], str]] = {
    "list_partitions":             lambda rs: _fmt_partition_listing(rs[-1]["result"]),
    "list_users":                  lambda rs: _fmt_user_listing(rs[-1]["result"]),
    "list_primary_partition_root": lambda rs: _fmt_directory_entries(rs[-1]["result"]),
    "list_user_folder":            lambda rs: _fmt_directory_entries(rs[-1]["result"]),
    "list_directory":              lambda rs: _fmt_directory_entries(rs[-1]["result"]),
    "compute_file_hash":           lambda rs: _fmt_file_hash(rs[-1]["result"]),
    "get_file_size":               lambda rs: _fmt_file_size(rs[-1]["result"]),
    # inspect_timeline intentionally excluded: the LLM-grounded path handles
    # targeted questions ("first use", "last use", "which days") more naturally
    # than a fixed formatter, while still being grounded only in tool output.
}

# Capabilities with rich/semi-structured output -> LLM-grounded narration.
_LLM_GROUNDED_CAPABILITIES = {
    "read_file_content",
    "inspect_filesystem",
    "inspect_disk_metadata",
    "inspect_registry",
    "inspect_event_logs",
    "inspect_email_accounts",
    "inspect_timeline",   # moved here so first/last/count questions get a direct answer
}


# ---------------------------------------------------------------------------
# LLM-grounded composition
# ---------------------------------------------------------------------------

def _compose_with_llm(
    llm: ChatOllama,
    capability_name: str,
    original_question: str,
    tool_results: List[dict],
    parameters: Optional[dict] = None,
) -> str:
    """
    Produce an answer grounded solely in *tool_results*.
    The LLM must not invent any fact not present in the tool output.
    """
    # Build a targeted instruction line when the user asked for a specific
    # timeline qualifier so the LLM doesn't just dump the full date list.
    query_hint = ""
    if parameters and capability_name == "inspect_timeline":
        q = (parameters.get("query") or "all").lower()
        if q == "first":
            query_hint = (
                "\nThe user is asking specifically for the FIRST / EARLIEST activity. "
                "Respond with just that timestamp from 'first_event' in the tool output.\n"
            )
        elif q == "last":
            query_hint = (
                "\nThe user is asking specifically for the LAST / MOST RECENT activity. "
                "Respond with just that timestamp from 'last_event' in the tool output.\n"
            )
        elif q == "all":
            query_hint = (
                "\nThe user is asking for ALL active days. "
                "List every date from 'unique_active_dates' and include the total count.\n"
            )

    if parameters and capability_name == "inspect_email_accounts":
        qt = (parameters.get("query_type") or "accounts").lower()
        if qt == "count":
            query_hint = (
                "\nThe user is asking for the TOTAL COUNT of email messages. "
                "Report eml_message_count, the sum of message_count across thunderbird_mbox_folders "
                "and generic_mbox_files, and the overall total_message_count. "
                "Do not focus on account configuration names.\n"
            )
        else:
            query_hint = (
                "\nThe user is asking for EMAIL ACCOUNT CONFIGURATION (address, username). "
                "Report account names and email addresses found in windows_live_mail_accounts, "
                "thunderbird_profiles, and outlook_files. Ignore message counts. "
                "If thunderbird_mbox_folders or eml_paths are non-empty, list the paths "
                "and tell the user they can read individual emails by asking: "
                "'mostra o conteudo do email <path>' with the exact path shown.\n"
            )

    prompt = (
        "You are a forensic artifact analysis assistant.\n"
        "Answer the user question using ONLY the MCP tool outputs shown below.\n"
        "Never invent paths, timestamps, hashes, usernames, or values absent from "
        "the tool output.\n"
        "If the result shows an error or missing data, report that plainly.\n"
        f"{query_hint}\n"
        f"Capability executed: {capability_name}\n"
        f"Original question: {original_question}\n\n"
        "Tool outputs (JSON):\n"
        f"{json.dumps(tool_results, ensure_ascii=False, indent=2)}\n\n"
        "Provide a concise, evidence-grounded forensic answer."
    )
    response = llm.invoke([HumanMessage(content=[{"type": "text", "text": prompt}])])
    return (response.content if hasattr(response, "content") else str(response)).strip()


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def compose_answer(
    llm: ChatOllama,
    capability_name: str,
    parameters: dict[str, Any],
    tool_results: List[dict],
    original_question: str = "",
) -> str:
    """
    Build the final user-facing answer from MCP *tool_results*.

    Strategy:
      1. If *tool_results* is empty -> generic tool error.
      2. If the last result carries a non-ok status -> structured error message.
      3. If a direct formatter exists -> use it (fully deterministic, no LLM).
      4. If capability is in the LLM-grounded set -> compose with LLM, strictly
         grounded in tool output.
      5. Fallback: pretty-print the raw JSON.
    """
    if not tool_results:
        return error_response("tool_error", "No tool was executed.")

    last_result = tool_results[-1]["result"]
    status = last_result.get("status", "")

    if status and status != "ok":
        return error_response(status, last_result.get("message", ""))

    formatter = _DIRECT_FORMATTERS.get(capability_name)
    if formatter is not None:
        return formatter(tool_results)

    if capability_name in _LLM_GROUNDED_CAPABILITIES:
        return _compose_with_llm(llm, capability_name, original_question, tool_results, parameters)

    # Fallback: raw structured output.
    return json.dumps(last_result, ensure_ascii=False, indent=2)
