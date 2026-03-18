"""
Closed capability registry for the forensic assistant.

The LLM only handles language understanding. All routing is a deterministic
dict lookup — to add a capability, add one registry entry and one executor branch.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional


@dataclass(frozen=True)
class Capability:
    """Declares a single supported forensic capability."""

    name: str
    description: str
    required_params: List[str]
    optional_params: List[str]
    mcp_tools: List[str]  # ordered list of MCP tools this capability executes


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

CAPABILITY_REGISTRY: dict[str, Capability] = {
    "list_partitions": Capability(
        name="list_partitions",
        description="List the partition table of a forensic disk image.",
        required_params=[],
        optional_params=["image_path"],
        mcp_tools=["inspect_image_partitions"],
    ),
    "list_users": Capability(
        name="list_users",
        description="Enumerate user profiles present in the forensic image.",
        required_params=[],
        optional_params=["image_path"],
        mcp_tools=["list_users"],
    ),
    "list_primary_partition_root": Capability(
        name="list_primary_partition_root",
        description="List root directory entries from the primary partition.",
        required_params=[],
        optional_params=["image_path"],
        mcp_tools=["list_primary_partition_root"],
    ),
    "list_user_folder": Capability(
        name="list_user_folder",
        description=(
            "List the contents of a user profile folder "
            "(Desktop, Documents, Downloads, Pictures, Music, AppData, …)."
        ),
        required_params=["user", "folder"],
        optional_params=["image_path"],
        mcp_tools=["resolve_user_profile", "get_special_folder", "list_user_directory"],
    ),
    "list_directory": Capability(
        name="list_directory",
        description="List contents of a literal host or evidence filesystem path.",
        required_params=["path"],
        optional_params=[],
        mcp_tools=["list_directory"],
    ),
    "compute_file_hash": Capability(
        name="compute_file_hash",
        description="Compute the cryptographic hash (MD5/SHA1/SHA256) of a file.",
        # algorithm is optional because normalizer always injects a default of 'md5'.
        required_params=["file_path"],
        optional_params=["algorithm"],
        mcp_tools=["get_file_hash"],
    ),
    "get_file_size": Capability(
        name="get_file_size",
        description="Return the logical size in bytes of a file in the forensic image.",
        # file_path: explicit partial/full path (contains /).  filename: bare name
        # (no path separator) that the executor resolves via find_file_by_name.
        # Neither is strictly required; the executor returns a graceful error when
        # both are absent.
        required_params=[],
        optional_params=["file_path", "filename"],
        mcp_tools=["get_file_size"],
    ),
    "read_file_content": Capability(
        name="read_file_content",
        description="Extract and return the text content of a file from the forensic image.",
        # file_path is optional so that conversation-state fallback can supply it
        # (e.g. 'show the content of that email' after a previous email listing).
        required_params=[],
        optional_params=["file_path"],
        mcp_tools=["extract_file_content"],
    ),
    "inspect_filesystem": Capability(
        name="inspect_filesystem",
        description="Return filesystem statistics: type, cluster size, sector size, block size.",
        # partition_index: 1-based index when the user specifies a specific partition
        # (e.g. 'cluster size in the second partition' → partition_index=2).
        required_params=[],
        optional_params=["image_path", "partition_index"],
        mcp_tools=["get_filesystem_stats"],
    ),
    "inspect_disk_metadata": Capability(
        name="inspect_disk_metadata",
        description=(
            "Return disk metadata: partition schema (GPT/MBR), "
            "disk GUID, partition GUIDs, disk serial number."
        ),
        required_params=[],
        optional_params=["image_path"],
        mcp_tools=["get_disk_metadata"],
    ),
    "inspect_registry": Capability(
        name="inspect_registry",
        description=(
            "Query a Windows registry hive (SAM, NTUSER, SOFTWARE, SYSTEM) "
            "for RIDs, last login, password hints, startup programs, UserAssist, etc."
        ),
        required_params=["hive"],
        optional_params=["key_path", "user", "image_path"],
        mcp_tools=["query_registry"],
    ),
    "inspect_event_logs": Capability(
        name="inspect_event_logs",
        description=(
            "Query Windows event logs (System / Application / Security) "
            "by event ID, timestamp, or username."
        ),
        required_params=["log_name"],
        optional_params=["event_ids", "timestamp", "username", "image_path"],
        mcp_tools=["query_event_log"],
    ),
    "inspect_timeline": Capability(
        name="inspect_timeline",
        description=(
            "Query the forensic activity timeline for logon/logoff events, "
            "optionally filtered by user or date."
        ),
        # query: 'all' (default), 'first' (earliest event), 'last' (most recent event).
        # The responder uses this to give a targeted answer instead of a full date list.
        required_params=[],
        optional_params=["user", "timestamp", "query", "image_path"],
        mcp_tools=["query_timeline"],
    ),
    "inspect_email_accounts": Capability(
        name="inspect_email_accounts",
        description="Retrieve email account information for a user from the forensic image.",
        required_params=[],
        optional_params=["user", "image_path", "query_type"],
        mcp_tools=["get_email_accounts"],
    ),
    # Sentinel returned when the question is outside supported forensic scope.
    "unsupported_request": Capability(
        name="unsupported_request",
        description="The question is outside the supported forensic capability set.",
        required_params=[],
        optional_params=[],
        mcp_tools=[],
    ),
}


def get_capability(name: str) -> Optional[Capability]:
    """Return the Capability for *name*, or None if not registered."""
    return CAPABILITY_REGISTRY.get(name)


def capability_names() -> List[str]:
    """Return all registered capability names (including the sentinel)."""
    return list(CAPABILITY_REGISTRY.keys())


def supported_capability_names() -> List[str]:
    """Return all capability names excluding the sentinel."""
    return [n for n in CAPABILITY_REGISTRY if n != "unsupported_request"]
