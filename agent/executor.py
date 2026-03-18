"""
Deterministic execution layer.

execute_capability() maps each capability to exactly the right MCP tool calls.
Zero LLM involvement — routing is a deterministic Python branch, testable and
extendable without touching any prompt.
"""
from __future__ import annotations

from typing import Any, Optional


# ---------------------------------------------------------------------------
# Conversation state
# ---------------------------------------------------------------------------

class CapabilityState:
    """
    Minimal mutable state preserved across conversation turns.

    Only stores useful defaults for future capability calls:
      - last forensic image path
      - last active user
      - last accessed folder
    """

    def __init__(self) -> None:
        self.last_image_path: Optional[str] = None
        self.last_user: Optional[str] = None
        self.last_folder: Optional[str] = None
        # Tracks the last file path successfully read or sized, so follow-up
        # questions like 'show the content of that file' can resolve file_path
        # from conversation context instead of requiring re-specification.
        self.last_file_path: Optional[str] = None

    def update(self, capability_name: str, parameters: dict[str, Any], result: dict) -> None:
        """Update state from a successful tool result."""
        if (result or {}).get("status") != "ok":
            return

        if parameters.get("user"):
            self.last_user = parameters["user"]

        if parameters.get("folder"):
            self.last_folder = parameters["folder"]

        # Track the last successfully accessed file path for conversation follow-ups.
        file_path = (
            parameters.get("file_path")
            or result.get("file_path")
            or result.get("path")
        )
        if file_path and not _is_forensic_image_path(str(file_path)):
            self.last_file_path = file_path

        # Promote any image path we learn about.
        for candidate in (
            parameters.get("image_path"),
            result.get("image_path"),
            result.get("resolved_path"),
        ):
            if candidate and _is_forensic_image_path(str(candidate)):
                self.last_image_path = candidate
                break


def _is_forensic_image_path(path: str) -> bool:
    return (path or "").lower().endswith((".e01", ".dd", ".img", ".raw", ".001"))


# ---------------------------------------------------------------------------
# Individual capability executors
# ---------------------------------------------------------------------------

def _exec_list_partitions(client: Any, params: dict) -> list[dict]:
    return [
        {
            "tool": "inspect_image_partitions",
            "result": client.inspect_image_partitions(params["image_path"]),
        }
    ]


def _exec_list_users(client: Any, params: dict) -> list[dict]:
    return [
        {
            "tool": "list_users",
            "result": client.list_users(image_path=params.get("image_path")),
        }
    ]


def _exec_list_primary_partition_root(client: Any, params: dict) -> list[dict]:
    return [
        {
            "tool": "list_primary_partition_root",
            "result": client.list_primary_partition_root(image_path=params.get("image_path")),
        }
    ]


def _exec_list_user_folder(client: Any, params: dict) -> list[dict]:
    """
    Three chained MCP calls: resolve_user_profile -> get_special_folder -> list_user_directory.
    Execution stops on the first failure to avoid misleading partial results.
    """
    user = params["user"]
    folder = params["folder"]
    image_path = params.get("image_path")
    results: list[dict] = []

    profile_result = client.resolve_user_profile(user=user, image_path=image_path)
    results.append({"tool": "resolve_user_profile", "result": profile_result})
    if profile_result.get("status") != "ok":
        return results

    folder_result = client.get_special_folder(
        user=user, folder_name=folder, image_path=image_path
    )
    results.append({"tool": "get_special_folder", "result": folder_result})
    if folder_result.get("status") != "ok":
        return results

    dir_result = client.list_user_directory(
        user=user,
        folder_name=folder,
        include_dirs=True,
        recursive=False,
        image_path=image_path,
    )
    results.append({"tool": "list_user_directory", "result": dir_result})
    return results


def _exec_list_directory(client: Any, params: dict) -> list[dict]:
    return [
        {
            "tool": "list_directory",
            "result": client.list_directory(params["path"], recursive=False, include_dirs=True),
        }
    ]


def _exec_compute_file_hash(client: Any, params: dict) -> list[dict]:
    return [
        {
            "tool": "get_file_hash",
            "result": client.get_file_hash(
                file_path=params["file_path"],
                algorithm=params["algorithm"],
            ),
        }
    ]


def _exec_get_file_size(client: Any, params: dict) -> list[dict]:
    filename = params.get("filename")
    file_path = params.get("file_path")

    if not filename and not file_path:
        return [
            {
                "tool": "get_file_size",
                "result": {
                    "status": "path_not_resolved",
                    "message": (
                        "No file path or filename provided. "
                        "Please specify the file name or path explicitly."
                    ),
                },
            }
        ]

    if filename and not file_path:
        # Bare filename: search the entire image for exactly this basename.
        # find_file_by_name returns the same status structure as get_file_size
        # (ok / multiple_matches / path_not_resolved), so the responder works
        # unchanged for both paths.
        result = client.find_file_by_name(filename=filename)
        return [{"tool": "get_file_size", "result": result}]

    # Explicit path (contains path separator): call get_file_size directly.
    return [
        {
            "tool": "get_file_size",
            "result": client.get_file_size(file_path=file_path),
        }
    ]


def _exec_read_file_content(client: Any, params: dict) -> list[dict]:
    file_path = params.get("file_path")
    if not file_path:
        return [{
            "tool": "extract_file_content",
            "result": {
                "status": "path_not_resolved",
                "message": (
                    "No file path provided. Please specify the file path explicitly, "
                    "for example: 'show the content of /Users/Jimmy/Desktop/email.eml'."
                ),
            },
        }]
    return [
        {
            "tool": "extract_file_content",
            "result": client.extract_file_content(file_path=file_path),
        }
    ]


def _exec_inspect_filesystem(client: Any, params: dict) -> list[dict]:
    # partition_index is forwarded to the MCP tool as a keyword hint so that the
    # server can select the correct partition offset when the user asks about a
    # specific partition (e.g. "cluster size in the second partition").
    kwargs: dict[str, Any] = {"image_path": params.get("image_path")}
    if params.get("partition_index") is not None:
        kwargs["partition_index"] = params["partition_index"]
    return [
        {
            "tool": "get_filesystem_stats",
            "result": client.get_filesystem_stats(**kwargs),
        }
    ]


def _exec_inspect_disk_metadata(client: Any, params: dict) -> list[dict]:
    return [
        {
            "tool": "get_disk_metadata",
            "result": client.get_disk_metadata(image_path=params.get("image_path")),
        }
    ]


def _exec_inspect_registry(client: Any, params: dict) -> list[dict]:
    return [
        {
            "tool": "query_registry",
            "result": client.query_registry(
                hive=params["hive"],
                key_path=params.get("key_path"),
                user=params.get("user"),
                image_path=params.get("image_path"),
            ),
        }
    ]


def _exec_inspect_event_logs(client: Any, params: dict) -> list[dict]:
    return [
        {
            "tool": "query_event_log",
            "result": client.query_event_log(
                log_name=params["log_name"],
                event_ids=params.get("event_ids"),
                timestamp=params.get("timestamp"),
                image_path=params.get("image_path"),
                username=params.get("username"),
            ),
        }
    ]


def _exec_inspect_timeline(client: Any, params: dict) -> list[dict]:
    return [
        {
            "tool": "query_timeline",
            "result": client.query_timeline(
                user=params.get("user"),
                timestamp=params.get("timestamp"),
                image_path=params.get("image_path"),
            ),
        }
    ]


def _exec_inspect_email_accounts(client: Any, params: dict) -> list[dict]:
    return [
        {
            "tool": "get_email_accounts",
            "result": client.get_email_accounts(
                user=params.get("user"),
                image_path=params.get("image_path"),
                query_type=params.get("query_type", "accounts"),
            ),
        }
    ]


# ---------------------------------------------------------------------------
# Dispatcher  (single source of truth for capability -> executor mapping)
# ---------------------------------------------------------------------------

_EXECUTORS: dict[str, Any] = {
    "list_partitions": _exec_list_partitions,
    "list_users": _exec_list_users,
    "list_primary_partition_root": _exec_list_primary_partition_root,
    "list_user_folder": _exec_list_user_folder,
    "list_directory": _exec_list_directory,
    "compute_file_hash": _exec_compute_file_hash,
    "get_file_size": _exec_get_file_size,
    "read_file_content": _exec_read_file_content,
    "inspect_filesystem": _exec_inspect_filesystem,
    "inspect_disk_metadata": _exec_inspect_disk_metadata,
    "inspect_registry": _exec_inspect_registry,
    "inspect_event_logs": _exec_inspect_event_logs,
    "inspect_timeline": _exec_inspect_timeline,
    "inspect_email_accounts": _exec_inspect_email_accounts,
}


def execute_capability(
    client: Any,
    capability_name: str,
    parameters: dict[str, Any],
    state: Optional[CapabilityState] = None,
) -> list[dict]:
    """
    Deterministically execute *capability_name* via MCP tool calls.

    Returns a list of ``{"tool": str, "result": dict}`` records.
    Raises ``ValueError`` for unregistered capability names (impossible after
    ``validate_parsed_request`` succeeds, but kept as a hard guard).
    """
    executor = _EXECUTORS.get(capability_name)
    if executor is None:
        raise ValueError(f"No executor registered for capability '{capability_name}'.")

    # For read_file_content: if no file_path was parsed, fall back to the last
    # known file path from conversation state (handles a follow-up like
    # "show the content of that file" after a get_file_size or email listing).
    if (
        capability_name == "read_file_content"
        and not parameters.get("file_path")
        and state is not None
        and state.last_file_path
    ):
        parameters = dict(parameters)
        parameters["file_path"] = state.last_file_path

    tool_results = executor(client, parameters)

    # Update conversation state from the last successful result.
    if state is not None:
        last_ok = next(
            (
                item["result"]
                for item in reversed(tool_results)
                if (item["result"] or {}).get("status") == "ok"
            ),
            None,
        )
        if last_ok is not None:
            state.update(capability_name, parameters, last_ok)

    return tool_results
