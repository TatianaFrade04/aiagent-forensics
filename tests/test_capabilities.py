"""
Regression test suite for the capability-based forensic assistant.

Each test case defines:
  - question       : natural-language input exactly as a user would type it
  - capability     : expected capability name after parsing + normalization
  - params_subset  : dict of parameters that MUST appear in the normalized output
                     (other params such as image_path injected by the validator
                     are not required to be present in the subset check)
  - mcp_tools      : ordered list of MCP tools expected to be executed
  - result_type    : "direct" (no LLM) | "llm_grounded" | "error"

Run with:
    pytest tests/test_capabilities.py -v

Structure:
  - Unit tests check normalization and validation only (no LLM, no MCP calls).
  - Integration constants list what a live run should produce (human-reviewable).
"""
from __future__ import annotations

import pytest
from agent.normalizer import (
    normalize_parameters,
    normalize_timeline_query,
    normalize_folder,
    normalize_algorithm,
    normalize_hive,
    normalize_log_name,
    _strip_evidence_prefix,
)
from agent.capabilities import get_capability, CAPABILITY_REGISTRY


# ---------------------------------------------------------------------------
# Regression table
# Each row is a dict consumed by parametrized tests below.
# ---------------------------------------------------------------------------

REGRESSION_CASES = [
    # ---- Timeline --------------------------------------------------------
    {
        "question": "Quais dias o computador foi ligado?",
        "capability": "inspect_timeline",
        "params_subset": {"query": "all"},
        "mcp_tools": ["query_timeline"],
        "result_type": "llm_grounded",
    },
    {
        "question": "Quando o pc foi ligado pela primeira vez?",
        "capability": "inspect_timeline",
        "params_subset": {"query": "first"},
        "mcp_tools": ["query_timeline"],
        "result_type": "llm_grounded",
    },
    {
        "question": "Quando o pc foi usado pela ultima vez?",
        "capability": "inspect_timeline",
        "params_subset": {"query": "last"},
        "mcp_tools": ["query_timeline"],
        "result_type": "llm_grounded",
    },
    {
        "question": "When was the computer first used?",
        "capability": "inspect_timeline",
        "params_subset": {"query": "first"},
        "mcp_tools": ["query_timeline"],
        "result_type": "llm_grounded",
    },
    {
        "question": "When was the last time the computer was active?",
        "capability": "inspect_timeline",
        "params_subset": {"query": "last"},
        "mcp_tools": ["query_timeline"],
        "result_type": "llm_grounded",
    },
    # ---- Email accounts --------------------------------------------------
    {
        "question": "Qual a conta de email?",
        "capability": "inspect_email_accounts",
        "params_subset": {},
        "mcp_tools": ["get_email_accounts"],
        "result_type": "llm_grounded",
    },
    {
        "question": "Quantos emails existem?",
        "capability": "inspect_email_accounts",
        "params_subset": {},
        "mcp_tools": ["get_email_accounts"],
        "result_type": "llm_grounded",
    },
    # ---- Email content (conversation follow-up) --------------------------
    {
        "question": "mostra o conteúdo do email /evidence/emails/msg1.eml",
        "capability": "read_file_content",
        "params_subset": {"file_path": "/evidence/emails/msg1.eml"},
        "mcp_tools": ["extract_file_content"],
        "result_type": "llm_grounded",
    },
    # ---- Disk metadata ---------------------------------------------------
    {
        "question": "Qual é o GUID (in hex) do disco físico?",
        "capability": "inspect_disk_metadata",
        "params_subset": {},
        "mcp_tools": ["get_disk_metadata"],
        "result_type": "llm_grounded",
    },
    {
        "question": "What is the disk GUID in hex?",
        "capability": "inspect_disk_metadata",
        "params_subset": {},
        "mcp_tools": ["get_disk_metadata"],
        "result_type": "llm_grounded",
    },
    # ---- File size -------------------------------------------------------
    {
        "question": "Qual é o tamanho do ficheiro \"The Widht Of a Circle.txt\"?",
        "capability": "get_file_size",
        "params_subset": {"file_path": "The Widht Of a Circle.txt"},
        "mcp_tools": ["get_file_size"],
        "result_type": "direct",
    },
    # ---- Filesystem stats ------------------------------------------------
    {
        "question": "What is the cluster size in bytes within the second partition of the physical disk?",
        "capability": "inspect_filesystem",
        "params_subset": {"partition_index": 2},
        "mcp_tools": ["get_filesystem_stats"],
        "result_type": "llm_grounded",
    },
    {
        "question": "What is the cluster size in bytes within the second partition?",
        "capability": "inspect_filesystem",
        "params_subset": {"partition_index": 2},
        "mcp_tools": ["get_filesystem_stats"],
        "result_type": "llm_grounded",
    },
    # ---- Partition listing -----------------------------------------------
    {
        "question": "What partitions does the disk image have?",
        "capability": "list_partitions",
        "params_subset": {},
        "mcp_tools": ["inspect_image_partitions"],
        "result_type": "direct",
    },
    # ---- User listing ----------------------------------------------------
    {
        "question": "Quais users existem na imagem?",
        "capability": "list_users",
        "params_subset": {},
        "mcp_tools": ["list_users"],
        "result_type": "direct",
    },
    # ---- User folder listing ---------------------------------------------
    {
        "question": "List the files on Jimmy Wilson's Desktop",
        "capability": "list_user_folder",
        "params_subset": {"user": "Jimmy Wilson", "folder": "Desktop"},
        "mcp_tools": ["resolve_user_profile", "get_special_folder", "list_user_directory"],
        "result_type": "direct",
    },
    {
        "question": "O que está nos documentos do Jimmy Wilson?",
        "capability": "list_user_folder",
        "params_subset": {"user": "Jimmy Wilson", "folder": "Documents"},
        "mcp_tools": ["resolve_user_profile", "get_special_folder", "list_user_directory"],
        "result_type": "direct",
    },
    # ---- File hash -------------------------------------------------------
    {
        "question": "What is the MD5 hash of /evidence/notes.txt?",
        "capability": "compute_file_hash",
        "params_subset": {"file_path": "/evidence/notes.txt", "algorithm": "md5"},
        "mcp_tools": ["get_file_hash"],
        "result_type": "direct",
    },
    {
        "question": "Give me the SHA-256 of /evidence/report.pdf",
        "capability": "compute_file_hash",
        "params_subset": {"file_path": "/evidence/report.pdf", "algorithm": "sha256"},
        "mcp_tools": ["get_file_hash"],
        "result_type": "direct",
    },
    # ---- Registry --------------------------------------------------------
    {
        "question": "Show me the SAM registry for RID numbers",
        "capability": "inspect_registry",
        "params_subset": {"hive": "sam"},
        "mcp_tools": ["query_registry"],
        "result_type": "llm_grounded",
    },
    # ---- Event logs ------------------------------------------------------
    {
        "question": "When was the system last booted? Check the System event log.",
        "capability": "inspect_event_logs",
        "params_subset": {"log_name": "system"},
        "mcp_tools": ["query_event_log"],
        "result_type": "llm_grounded",
    },
    # ---- Partition root --------------------------------------------------
    {
        "question": "List the root of the primary partition",
        "capability": "list_primary_partition_root",
        "params_subset": {},
        "mcp_tools": ["list_primary_partition_root"],
        "result_type": "direct",
    },
]


# ---------------------------------------------------------------------------
# Unit tests — normalization layer (no LLM, no MCP)
# ---------------------------------------------------------------------------

class TestFolderAliases:
    @pytest.mark.parametrize("alias,expected", [
        ("desktop", "Desktop"),
        ("DESKTOP", "Desktop"),
        ("documentos", "Documents"),
        ("docs", "Documents"),
        ("fotos", "Pictures"),
        ("musica", "Music"),
        ("música", "Music"),
        ("appdata", "AppData"),
        ("app data", "AppData"),
        ("downloads", "Downloads"),
        ("vídeos", "Videos"),
    ])
    def test_folder_alias(self, alias: str, expected: str):
        assert normalize_folder(alias) == expected


class TestHashAliases:
    @pytest.mark.parametrize("alias,expected", [
        ("md5", "md5"),
        ("MD5", "md5"),
        ("sha1", "sha1"),
        ("sha-1", "sha1"),
        ("sha 1", "sha1"),
        ("sha256", "sha256"),
        ("sha-256", "sha256"),
        ("sha 256", "sha256"),
        ("sha2", "sha256"),
        ("", "md5"),   # fallback
    ])
    def test_hash_alias(self, alias: str, expected: str):
        assert normalize_algorithm(alias) == expected


class TestHiveAliases:
    @pytest.mark.parametrize("alias,expected", [
        ("sam", "sam"),
        ("SAM", "sam"),
        ("ntuser", "ntuser"),
        ("ntuser.dat", "ntuser"),
        ("software", "software"),
        ("system", "system"),
        ("security", "security"),
        ("", "sam"),   # fallback
    ])
    def test_hive_alias(self, alias: str, expected: str):
        assert normalize_hive(alias) == expected


class TestLogAliases:
    @pytest.mark.parametrize("alias,expected", [
        ("system", "system"),
        ("sys", "system"),
        ("application", "application"),
        ("app", "application"),
        ("security", "security"),
        ("sec", "security"),
        ("", "system"),   # fallback
    ])
    def test_log_alias(self, alias: str, expected: str):
        assert normalize_log_name(alias) == expected


class TestTimelineQueryAliases:
    @pytest.mark.parametrize("alias,expected", [
        ("first", "first"),
        ("first_use", "first"),
        ("earliest", "first"),
        ("first_time", "first"),
        ("last", "last"),
        ("last_use", "last"),
        ("latest", "last"),
        ("most_recent", "last"),
        ("recently", "last"),
        ("all", "all"),
        ("all_dates", "all"),
        ("days", "all"),
        ("", "all"),   # default
        ("unknown_value", "all"),   # fallback
    ])
    def test_timeline_query_alias(self, alias: str, expected: str):
        assert normalize_timeline_query(alias) == expected


class TestNormalizeParameters:
    def test_timeline_query_injected(self):
        params = normalize_parameters("inspect_timeline", {})
        assert params["query"] == "all"

    def test_timeline_query_first_preserved(self):
        params = normalize_parameters("inspect_timeline", {"query": "first"})
        assert params["query"] == "first"

    def test_timeline_query_alias_normalized(self):
        params = normalize_parameters("inspect_timeline", {"query": "earliest"})
        assert params["query"] == "first"

    def test_compute_hash_algorithm_default(self):
        params = normalize_parameters("compute_file_hash", {"file_path": "/f.txt"})
        assert params["algorithm"] == "md5"

    def test_compute_hash_algorithm_alias(self):
        params = normalize_parameters("compute_file_hash", {"file_path": "/f.txt", "algorithm": "sha-256"})
        assert params["algorithm"] == "sha256"

    def test_filesystem_partition_index_int(self):
        params = normalize_parameters("inspect_filesystem", {"partition_index": "2"})
        assert params["partition_index"] == 2

    def test_filesystem_partition_index_invalid_removed(self):
        params = normalize_parameters("inspect_filesystem", {"partition_index": "abc"})
        assert "partition_index" not in params

    def test_folder_alias_applied(self):
        params = normalize_parameters("list_user_folder", {"user": "Alice", "folder": "documentos"})
        assert params["folder"] == "Documents"

    def test_hive_alias_applied(self):
        params = normalize_parameters("inspect_registry", {"hive": "SAM"})
        assert params["hive"] == "sam"

    def test_log_alias_applied(self):
        params = normalize_parameters("inspect_event_logs", {"log_name": "sys"})
        assert params["log_name"] == "system"

    # --- CASE 7 regression: /evidence/ prefix stripping ---

    def test_get_file_size_strips_evidence_prefix(self):
        """Case 7: /evidence/<filename> → <filename> so fls substring search works."""
        params = normalize_parameters("get_file_size", {"file_path": "/evidence/The Widht Of a Circle.txt"})
        assert params["file_path"] == "The Widht Of a Circle.txt"

    def test_compute_file_hash_strips_evidence_prefix(self):
        params = normalize_parameters("compute_file_hash", {"file_path": "/evidence/report.pdf"})
        assert params["file_path"] == "report.pdf"

    def test_read_file_content_strips_evidence_prefix(self):
        params = normalize_parameters("read_file_content", {"file_path": "/evidence/readme.txt"})
        assert params["file_path"] == "readme.txt"

    def test_deep_path_not_stripped(self):
        """Paths with nested segments after /evidence/ must NOT be stripped."""
        params = normalize_parameters("get_file_size", {"file_path": "/evidence/Users/Alice/notes.txt"})
        assert params["file_path"] == "/evidence/Users/Alice/notes.txt"

    def test_non_evidence_path_unchanged(self):
        """Paths that don't start with /evidence/ are left alone."""
        params = normalize_parameters("get_file_size", {"file_path": "Users/jimmy/desktop/file.txt"})
        assert params["file_path"] == "Users/jimmy/desktop/file.txt"


class TestCapabilityRegistry:
    def test_all_capabilities_have_executors(self):
        """Every non-sentinel capability must be in the executor dispatch table."""
        from agent.executor import _EXECUTORS
        from agent.capabilities import supported_capability_names
        for name in supported_capability_names():
            assert name in _EXECUTORS, f"No executor registered for capability '{name}'"

    @pytest.mark.parametrize("name,expected_tools", [
        ("list_partitions",             ["inspect_image_partitions"]),
        ("list_users",                  ["list_users"]),
        ("list_primary_partition_root", ["list_primary_partition_root"]),
        ("list_user_folder",            ["resolve_user_profile", "get_special_folder", "list_user_directory"]),
        ("list_directory",              ["list_directory"]),
        ("compute_file_hash",           ["get_file_hash"]),
        ("get_file_size",               ["get_file_size"]),
        ("read_file_content",           ["extract_file_content"]),
        ("inspect_filesystem",          ["get_filesystem_stats"]),
        ("inspect_disk_metadata",       ["get_disk_metadata"]),
        ("inspect_registry",            ["query_registry"]),
        ("inspect_event_logs",          ["query_event_log"]),
        ("inspect_timeline",            ["query_timeline"]),
        ("inspect_email_accounts",      ["get_email_accounts"]),
    ])
    def test_mcp_tools_match_registry(self, name: str, expected_tools: list):
        cap = get_capability(name)
        assert cap is not None
        assert cap.mcp_tools == expected_tools

    def test_read_file_content_file_path_optional(self):
        """file_path moved to optional so conversation state can supply it."""
        cap = get_capability("read_file_content")
        assert "file_path" not in cap.required_params
        assert "file_path" in cap.optional_params

    def test_list_partitions_image_path_optional(self):
        """image_path moved to optional so validator injects it from evidence dir."""
        cap = get_capability("list_partitions")
        assert "image_path" not in cap.required_params
        assert "image_path" in cap.optional_params

    def test_compute_file_hash_algorithm_optional(self):
        """algorithm moved to optional; normalizer always injects a default."""
        cap = get_capability("compute_file_hash")
        assert "algorithm" not in cap.required_params
        assert "algorithm" in cap.optional_params

    def test_inspect_timeline_query_optional(self):
        cap = get_capability("inspect_timeline")
        assert "query" in cap.optional_params

    def test_inspect_filesystem_partition_index_optional(self):
        cap = get_capability("inspect_filesystem")
        assert "partition_index" in cap.optional_params


# ---------------------------------------------------------------------------
# Unit tests — _strip_evidence_prefix (case 7 regression)
# ---------------------------------------------------------------------------

class TestStripEvidencePrefix:
    @pytest.mark.parametrize("raw,expected", [
        # simple filename with /evidence/ prefix → stripped
        ("/evidence/The Widht Of a Circle.txt", "The Widht Of a Circle.txt"),
        ("/evidence/report.pdf",                "report.pdf"),
        ("/evidence/readme.TXT",                "readme.TXT"),
        # deep path → NOT stripped (may be a real in-image path)
        ("/evidence/Users/Alice/notes.txt",     "/evidence/Users/Alice/notes.txt"),
        # no /evidence/ prefix → unchanged
        ("Users/jimmy/desktop/file.txt",        "Users/jimmy/desktop/file.txt"),
        ("file.txt",                            "file.txt"),
        # empty string → unchanged
        ("",                                    ""),
    ])
    def test_strip(self, raw: str, expected: str):
        assert _strip_evidence_prefix(raw) == expected


# ---------------------------------------------------------------------------
# Unit tests — _extract_partition_offsets_all (case 8 regression)
# ---------------------------------------------------------------------------

class TestExtractPartitionOffsetsAll:
    """Verify that the helper correctly enumerates real filesystem partitions."""

    _SAMPLE_MMLS = """\
GUID Partition Table (EFI)
Offset Sector: 0
Units are in 512-byte sectors

      Slot      Start        End          Length       Description
000:  Meta      0000000000   0000000000   0000000001   Safety Table
001:  -------   0000000000   0000000033   0000000034   Unallocated
002:  Meta      0000000001   0000000001   0000000001   GPT Header
003:  Meta      0000000001   0000000001   0000000001   GPT Footer
004:  000       0000000034   0000032767   0000032734   Microsoft Recovery
005:  001       0000032768   0000034815   0000002048   EFI System Partition
006:  002       0000034816   0000124927   0000090112   Basic Data Partition
"""

    def test_returns_only_real_partitions(self):
        from mcp_local.server import _extract_partition_offsets_all
        offsets = _extract_partition_offsets_all(self._SAMPLE_MMLS)
        # Slots 000/001/002/003 are Meta/Unallocated → excluded
        # Slots 004/005/006 (values "000","001","002") are real → included
        assert len(offsets) == 3

    def test_first_partition_offset(self):
        from mcp_local.server import _extract_partition_offsets_all
        offsets = _extract_partition_offsets_all(self._SAMPLE_MMLS)
        assert offsets[0] == "0000000034"    # slot 004 start sector

    def test_second_partition_offset(self):
        from mcp_local.server import _extract_partition_offsets_all
        offsets = _extract_partition_offsets_all(self._SAMPLE_MMLS)
        assert offsets[1] == "0000032768"  # slot 005 start sector

    def test_empty_mmls(self):
        from mcp_local.server import _extract_partition_offsets_all
        assert _extract_partition_offsets_all("") == []


# ---------------------------------------------------------------------------
# Unit tests — MCP client signature (case 8 regression)
# ---------------------------------------------------------------------------

class TestMCPClientSignature:
    def test_get_filesystem_stats_accepts_partition_index(self):
        """LocalMCPClient.get_filesystem_stats must accept partition_index kwarg."""
        import inspect
        from mcp_local.client import LocalMCPClient
        sig = inspect.signature(LocalMCPClient.get_filesystem_stats)
        assert "partition_index" in sig.parameters, (
            "LocalMCPClient.get_filesystem_stats is missing partition_index parameter — "
            "this caused the TypeError in case 8."
        )

    def test_get_email_accounts_accepts_query_type(self):
        """LocalMCPClient.get_email_accounts must accept query_type kwarg."""
        import inspect
        from mcp_local.client import LocalMCPClient
        sig = inspect.signature(LocalMCPClient.get_email_accounts)
        assert "query_type" in sig.parameters, (
            "LocalMCPClient.get_email_accounts is missing query_type parameter."
        )


class TestEmailQueryType:
    """Verify the inspect_email_accounts capability and normalizer handle query_type."""

    def test_capability_has_query_type_optional(self):
        from agent.capabilities import CAPABILITY_REGISTRY
        cap = CAPABILITY_REGISTRY["inspect_email_accounts"]
        assert "query_type" in cap.optional_params

    def test_executor_passes_query_type(self):
        """_exec_inspect_email_accounts must forward query_type from params."""
        import inspect
        from agent.executor import _exec_inspect_email_accounts
        source = inspect.getsource(_exec_inspect_email_accounts)
        assert "query_type" in source

    def test_normalize_parameters_injects_default_query_type(self):
        from agent.normalizer import normalize_parameters
        p = normalize_parameters("inspect_email_accounts", {})
        assert p["query_type"] == "accounts"

    def test_normalize_parameters_count_preserved(self):
        from agent.normalizer import normalize_parameters
        p = normalize_parameters("inspect_email_accounts", {"query_type": "count"})
        assert p["query_type"] == "count"

    def test_normalize_parameters_alias_quantos(self):
        from agent.normalizer import normalize_parameters
        p = normalize_parameters("inspect_email_accounts", {"query_type": "quantos"})
        assert p["query_type"] == "count"


class TestNormalizeEmailQueryType:
    """Unit tests for normalize_email_query_type alias map."""

    def test_accounts_passthrough(self):
        from agent.normalizer import normalize_email_query_type
        assert normalize_email_query_type("accounts") == "accounts"

    def test_count_passthrough(self):
        from agent.normalizer import normalize_email_query_type
        assert normalize_email_query_type("count") == "count"

    def test_how_many_alias(self):
        from agent.normalizer import normalize_email_query_type
        assert normalize_email_query_type("how many") == "count"

    def test_quantos_alias(self):
        from agent.normalizer import normalize_email_query_type
        assert normalize_email_query_type("quantos") == "count"

    def test_quantas_alias(self):
        from agent.normalizer import normalize_email_query_type
        assert normalize_email_query_type("quantas") == "count"

    def test_total_alias(self):
        from agent.normalizer import normalize_email_query_type
        assert normalize_email_query_type("total") == "count"

    def test_conta_alias(self):
        from agent.normalizer import normalize_email_query_type
        assert normalize_email_query_type("conta") == "accounts"

    def test_unknown_defaults_to_accounts(self):
        from agent.normalizer import normalize_email_query_type
        assert normalize_email_query_type("whatever") == "accounts"

    def test_none_defaults_to_accounts(self):
        from agent.normalizer import normalize_email_query_type
        assert normalize_email_query_type(None) == "accounts"  # type: ignore[arg-type]

    def test_case_insensitive(self):
        from agent.normalizer import normalize_email_query_type
        assert normalize_email_query_type("COUNT") == "count"
        assert normalize_email_query_type("ACCOUNTS") == "accounts"


class TestTimelineMultiSource:
    """Verify timeline multi-source constants and helper are present in server.py."""

    def test_boot_shutdown_event_ids_defined(self):
        from mcp_local.server import _BOOT_SHUTDOWN_EVENT_IDS
        assert set(_BOOT_SHUTDOWN_EVENT_IDS) == {6005, 6006, 6008, 6009}

    def test_logon_event_ids_defined(self):
        from mcp_local.server import _LOGON_EVENT_IDS
        assert 4624 in _LOGON_EVENT_IDS

    def test_build_timeline_result_structure(self):
        from mcp_local.server import _build_timeline_result
        result = _build_timeline_result(
            events=[{"timestamp": "2020-01-01T10:00:00", "user": "alice", "event_id": 4624}],
            user="alice",
            timestamp=None,
            source="security_event_log",
        )
        assert result["status"] == "ok"
        assert "source" in result
        assert result["source"] == "security_event_log"
        assert "unique_active_dates" in result
        assert "first_event" in result
        assert "last_event" in result


# ---------------------------------------------------------------------------
# Case 4 regression: quote-stripping for quoted filenames
# ---------------------------------------------------------------------------

class TestStripFilePathQuotes:
    """norm._strip_file_path_quotes must remove surrounding quote characters."""

    def test_double_quoted(self):
        from agent.normalizer import _strip_file_path_quotes
        assert _strip_file_path_quotes('"The Widht Of a Circle.txt"') == "The Widht Of a Circle.txt"

    def test_single_quoted(self):
        from agent.normalizer import _strip_file_path_quotes
        assert _strip_file_path_quotes("'notes.txt'") == "notes.txt"

    def test_unquoted_unchanged(self):
        from agent.normalizer import _strip_file_path_quotes
        assert _strip_file_path_quotes("notes.txt") == "notes.txt"

    def test_empty_unchanged(self):
        from agent.normalizer import _strip_file_path_quotes
        assert _strip_file_path_quotes("") == ""

    def test_path_with_slash_double_quoted(self):
        from agent.normalizer import _strip_file_path_quotes
        assert _strip_file_path_quotes('"Users/Jimmy/Desktop/f.txt"') == "Users/Jimmy/Desktop/f.txt"

    def test_normalize_parameters_strips_quotes_get_file_size(self):
        """Case 4 regression: quoted filename must be stripped before fls lookup."""
        from agent.normalizer import normalize_parameters
        p = normalize_parameters("get_file_size", {"file_path": '"The Widht Of a Circle.txt"'})
        assert p["file_path"] == "The Widht Of a Circle.txt"

    def test_normalize_parameters_strips_quotes_compute_file_hash(self):
        from agent.normalizer import normalize_parameters
        p = normalize_parameters("compute_file_hash", {"file_path": "'report.pdf'"})
        assert p["file_path"] == "report.pdf"

    def test_normalize_parameters_strips_quotes_read_file_content(self):
        from agent.normalizer import normalize_parameters
        p = normalize_parameters("read_file_content", {"file_path": '"readme.txt"'})
        assert p["file_path"] == "readme.txt"

    def test_quote_then_evidence_prefix_stripped(self):
        """Quote stripping must happen BEFORE evidence prefix stripping."""
        from agent.normalizer import normalize_parameters
        # Parser could emit '"/evidence/notes.txt"' — strip quotes first, then prefix.
        p = normalize_parameters("get_file_size", {"file_path": '"/evidence/notes.txt"'})
        assert p["file_path"] == "notes.txt"


# ---------------------------------------------------------------------------
# Case 3 regression: read_file_content executor + state fallback
# ---------------------------------------------------------------------------

class TestReadFileContentExecutor:
    """_exec_read_file_content must not KeyError on missing file_path."""

    def test_missing_file_path_returns_path_not_resolved(self):
        from agent.executor import _exec_read_file_content

        class FakeClient:
            pass

        results = _exec_read_file_content(FakeClient(), {})
        assert len(results) == 1
        assert results[0]["result"]["status"] == "path_not_resolved"

    def test_explicit_file_path_forwarded(self):
        from agent.executor import _exec_read_file_content

        received = {}

        class FakeClient:
            def extract_file_content(self, file_path):
                received["file_path"] = file_path
                return {"status": "ok", "content": "hello"}

        results = _exec_read_file_content(FakeClient(), {"file_path": "notes.txt"})
        assert received["file_path"] == "notes.txt"
        assert results[0]["result"]["status"] == "ok"

    def test_state_fallback_injects_last_file_path(self):
        """execute_capability must use state.last_file_path when file_path absent."""
        from agent.executor import execute_capability, CapabilityState

        received = {}

        class FakeClient:
            def extract_file_content(self, file_path):
                received["file_path"] = file_path
                return {"status": "ok", "content": "data"}

        state = CapabilityState()
        state.last_file_path = "Users/Jimmy/Desktop/report.txt"

        execute_capability(FakeClient(), "read_file_content", {}, state=state)
        assert received.get("file_path") == "Users/Jimmy/Desktop/report.txt"

    def test_no_state_no_file_path_returns_error(self):
        """With no state and no file_path, a descriptive error is returned."""
        from agent.executor import execute_capability

        class FakeClient:
            pass

        results = execute_capability(FakeClient(), "read_file_content", {}, state=None)
        assert results[0]["result"]["status"] == "path_not_resolved"


# ---------------------------------------------------------------------------
# Cases 1 & 2 regression: email fls parsing uses -p flag + filename suffix check
# ---------------------------------------------------------------------------

class TestEmailFlsParsing:
    """_default_get_email_accounts must use fls -p and check suffix on filename,
    not on the trailing bytes of the full tab-separated fls -l line."""

    def test_fls_command_includes_p_flag(self):
        """Regression: fls must include -p so path_token contains full \
directory path (e.g. *Thunderbird* appears for TB files)."""
        import inspect
        from mcp_local import server
        source = inspect.getsource(server._default_get_email_accounts)
        # Check that the fls invocation has the -p flag in it.
        assert '"-p"' in source or "'-p'" in source, (
            "fls call in _default_get_email_accounts is missing the -p (full-path) flag. "
            "Without -p, Thunderbird detection and suffix matching both fail."
        )

    def test_suffix_not_checked_on_whole_line(self):
        """Regression: the old code used line_lower.rstrip().endswith(sfx) which
        tests the END of the full tab-separated line (ends with uid/gid numbers,
        NOT the filename extension).  After the fix the check must be on the
        filename portion (name_lower)."""
        import inspect
        from mcp_local import server
        source = inspect.getsource(server._default_get_email_accounts)
        # The fixed code must NOT contain the old broken pattern.
        assert "line_lower.rstrip().endswith" not in source, (
            "Found old broken suffix check 'line_lower.rstrip().endswith(sfx)'. "
            "This checks the end of the full tab-line not the filename."
        )

    def test_eml_paths_in_result_schema(self):
        """ok result must include eml_paths list for Case 3 follow-up reads."""
        # We can only verify the return-value key is present by inspecting the
        # function source (a live run needs the Docker container).
        import inspect
        from mcp_local import server
        source = inspect.getsource(server._default_get_email_accounts)
        assert '"eml_paths"' in source, (
            "_default_get_email_accounts does not return 'eml_paths' list. "
            "Users need these paths to copy into a read_file_content follow-up."
        )


# ---------------------------------------------------------------------------
# Case 1 (new): Unicode curly-quote stripping
# ---------------------------------------------------------------------------

class TestUnicodeCurlyQuoteStripping:
    """_strip_file_path_quotes must strip Unicode LEFT/RIGHT smart-quote pairs."""

    def test_left_right_double_quotation_marks(self):
        """U+201C / U+201D — the most common curly double quotes."""
        from agent.normalizer import _strip_file_path_quotes
        assert _strip_file_path_quotes('\u201cThe Widht Of a Circle.txt\u201d') == "The Widht Of a Circle.txt"

    def test_left_right_single_quotation_marks(self):
        """U+2018 / U+2019 — curly single quotes."""
        from agent.normalizer import _strip_file_path_quotes
        assert _strip_file_path_quotes('\u2018notes.txt\u2019') == "notes.txt"

    def test_mismatched_curly_quotes_not_stripped(self):
        """Opening left double + closing left double (same) are NOT a valid pair."""
        from agent.normalizer import _strip_file_path_quotes
        # \u201c ... \u201c — both opening, no strip expected
        assert _strip_file_path_quotes('\u201cfile.txt\u201c') == '\u201cfile.txt\u201c'

    def test_normalize_parameters_strips_unicode_double_quotes(self):
        """End-to-end: normalize_parameters must strip curly double quotes from file_path."""
        from agent.normalizer import normalize_parameters
        p = normalize_parameters("get_file_size", {
            "file_path": '\u201cThe Widht Of a Circle.txt\u201d'
        })
        assert p["file_path"] == "The Widht Of a Circle.txt"

    def test_normalize_parameters_strips_unicode_single_quotes(self):
        from agent.normalizer import normalize_parameters
        p = normalize_parameters("get_file_size", {"file_path": '\u2018report.pdf\u2019'})
        assert p["file_path"] == "report.pdf"

    def test_ascii_quotes_still_stripped(self):
        """Existing ASCII quote stripping must continue to work."""
        from agent.normalizer import _strip_file_path_quotes
        assert _strip_file_path_quotes('"file.txt"') == "file.txt"
        assert _strip_file_path_quotes("'file.txt'") == "file.txt"


# ---------------------------------------------------------------------------
# Case 1 (new): File size — exact basename matching and 0/1/many handling
# ---------------------------------------------------------------------------

class TestFileSizeLookup:
    """_default_get_file_size must use exact basename matching and return
    multiple_matches when more than one file has the same name."""

    def _make_fls_line(self, path: str, size: int, inode: str = "1234-128-1") -> str:
        """Produce a minimal fls -l -p line for testing."""
        return f"r/r {inode}:\t{path}\t0\t0\t0\t0\t{size}\t0\t0"

    def test_exact_basename_match(self):
        """Basename matching logic lives in _find_file_in_fls_output (extracted
        helper) which performs an exact last-component comparison (not substring)."""
        import inspect
        from mcp_local import server
        source = inspect.getsource(server._find_file_in_fls_output)
        # The helper must extract the last path component and compare it.
        assert "split" in source and "lower" in source, (
            "_find_file_in_fls_output is missing basename extraction/matching logic."
        )

    def test_multiple_matches_status(self):
        """_default_find_file_by_name must return 'multiple_matches' when >1 file
        shares the same basename."""
        import inspect
        from mcp_local import server
        source = inspect.getsource(server._default_find_file_by_name)
        assert '"multiple_matches"' in source, (
            "_default_find_file_by_name does not return multiple_matches status."
        )

    def test_result_file_path_is_resolved_full_path(self):
        """On a successful single match the result file_path must be the
        RESOLVED full path from fls (not the user's bare filename input).
        The resolved path is set in _build_match_result."""
        import inspect
        from mcp_local import server
        source = inspect.getsource(server._build_match_result)
        assert 'matches[0][0]' in source, (
            "_build_match_result ok result does not use the resolved full path from fls."
        )

    def test_multiple_matches_in_error_catalogue(self):
        """'multiple_matches' must be in the responder error catalogue so
        compose_answer can produce a user-friendly message."""
        from agent.responder import _ERROR_MESSAGES
        assert "multiple_matches" in _ERROR_MESSAGES


# ---------------------------------------------------------------------------
# Case 2 (new): mbox detection in extract_file_content
# ---------------------------------------------------------------------------

class TestMboxDetection:
    """_default_extract_file_content must detect mbox format and return
    the first message as readable content rather than raw mbox bytes."""

    def test_mbox_detection_in_source(self):
        """The function must contain mbox-format detection logic."""
        import inspect
        from mcp_local import server
        source = inspect.getsource(server._default_extract_file_content)
        assert "mbox" in source.lower(), (
            "_default_extract_file_content has no mbox detection. "
            "Thunderbird folders (mbox files) would return raw binary blobs."
        )

    def test_mbox_format_field_in_result(self):
        """Source must produce a result with format='mbox' for mbox content."""
        import inspect
        from mcp_local import server
        source = inspect.getsource(server._default_extract_file_content)
        assert '"format": "mbox"' in source or '"mbox"' in source, (
            "_default_extract_file_content does not tag mbox results with format='mbox'."
        )

    def test_mbox_first_message_extraction_logic(self):
        """The mbox split logic must skip the envelope 'From user@host date' line
        and return the RFC 2822 headers + body of the first message."""
        import inspect
        from mcp_local import server
        source = inspect.getsource(server._default_extract_file_content)
        # The split on mbox boundaries is implemented via re.split.
        assert "re.split" in source or "split" in source, (
            "_default_extract_file_content is missing message-boundary split logic for mbox."
        )

    def test_mbox_note_field_present(self):
        """Result for mbox must include a mbox_note explaining it's message 1 of N."""
        import inspect
        from mcp_local import server
        source = inspect.getsource(server._default_extract_file_content)
        assert "mbox_note" in source, (
            "_default_extract_file_content is missing 'mbox_note' field for mbox results."
        )


# ---------------------------------------------------------------------------
# Phase 5b (new): filename vs file_path schema split
# ---------------------------------------------------------------------------

class TestFilenameParameter:
    """The parser emits 'filename' for bare quoted file names and 'file_path'
    for explicit paths (containing at least one '/').  The executor routes
    'filename' to find_file_by_name (basename search) and 'file_path' to
    get_file_size (direct full-path lookup).  Both return the same status
    structure so the responder requires no changes."""

    def test_get_file_size_has_filename_optional(self):
        """'filename' must be an optional parameter on get_file_size."""
        from agent.capabilities import CAPABILITY_REGISTRY
        cap = CAPABILITY_REGISTRY["get_file_size"]
        assert "filename" in cap.optional_params, (
            "get_file_size capability is missing 'filename' in optional_params."
        )

    def test_get_file_size_file_path_not_required(self):
        """file_path must NOT be in required_params so filename-only requests pass validation."""
        from agent.capabilities import CAPABILITY_REGISTRY
        cap = CAPABILITY_REGISTRY["get_file_size"]
        assert "file_path" not in cap.required_params, (
            "get_file_size still lists file_path as required; must be optional "
            "to allow 'filename'-only requests."
        )

    def test_client_has_find_file_by_name(self):
        """LocalMCPClient must expose find_file_by_name for bare-filename resolution."""
        import inspect
        from mcp_local.client import LocalMCPClient
        sig = inspect.signature(LocalMCPClient.find_file_by_name)
        assert "filename" in sig.parameters, (
            "LocalMCPClient.find_file_by_name is missing 'filename' parameter."
        )

    def test_server_has_find_file_by_name(self):
        """_default_find_file_by_name must exist in server.py."""
        from mcp_local import server
        assert hasattr(server, "_default_find_file_by_name"), (
            "server.py is missing _default_find_file_by_name function."
        )

    def test_executor_routes_filename_to_find_file_by_name(self):
        """_exec_get_file_size must call find_file_by_name when 'filename' is present."""
        import inspect
        from agent.executor import _exec_get_file_size
        source = inspect.getsource(_exec_get_file_size)
        assert "find_file_by_name" in source, (
            "_exec_get_file_size does not call find_file_by_name for bare filenames."
        )

    def test_executor_routes_file_path_to_get_file_size(self):
        """_exec_get_file_size must call get_file_size when 'file_path' is present."""
        import inspect
        from agent.executor import _exec_get_file_size
        source = inspect.getsource(_exec_get_file_size)
        assert "get_file_size" in source, (
            "_exec_get_file_size does not call get_file_size for explicit paths."
        )

    def test_normalizer_strips_quotes_from_filename(self):
        """normalize_parameters must strip ASCII double quotes from 'filename'."""
        from agent.normalizer import normalize_parameters
        params = normalize_parameters("get_file_size", {"filename": '"The Width Of A Circle.txt"'})
        assert params["filename"] == "The Width Of A Circle.txt", (
            "normalize_parameters does not strip ASCII double quotes from 'filename'."
        )

    def test_normalizer_strips_unicode_quotes_from_filename(self):
        """normalize_parameters must strip Unicode LEFT/RIGHT DOUBLE QUOTATION MARKs from filename."""
        from agent.normalizer import normalize_parameters
        params = normalize_parameters("get_file_size", {
            "filename": "\u201cThe Width Of A Circle.txt\u201d"
        })
        assert params["filename"] == "The Width Of A Circle.txt", (
            "normalize_parameters does not strip Unicode curly quotes from 'filename'."
        )

    def test_validate_does_not_inject_file_path_when_filename_present(self):
        """validate_parsed_request must NOT inject last_known_file_path when filename is given."""
        from agent.normalizer import validate_parsed_request
        params = validate_parsed_request(
            "get_file_size",
            confidence=0.93,
            parameters={"filename": "notes.txt"},
            last_known_file_path="/some/old/path.txt",
        )
        # file_path must NOT be injected when filename is already present.
        assert not params.get("file_path"), (
            "validate_parsed_request injected last_known_file_path even though "
            "'filename' was already present in the parameters."
        )
        assert params.get("filename") == "notes.txt"

    def test_get_file_size_safety_fallback_delegates_bare_name(self):
        """_default_get_file_size must delegate bare filenames (no '/') to
        _default_find_file_by_name rather than failing silently."""
        import inspect
        from mcp_local import server
        source = inspect.getsource(server._default_get_file_size)
        assert "_default_find_file_by_name" in source, (
            "_default_get_file_size is missing the safety fallback to "
            "_default_find_file_by_name for bare filenames."
        )

    def test_parser_prompt_has_filename_rule(self):
        """The parser prompt template must describe the 'filename' parameter."""
        from agent.parser import _PARSER_PROMPT_TEMPLATE
        assert "filename" in _PARSER_PROMPT_TEMPLATE, (
            "Parser prompt is missing the 'filename' parameter extraction rule."
        )


# ---------------------------------------------------------------------------
# Phase 5c (new): fuzzy filename matching in _find_file_in_fls_output
# ---------------------------------------------------------------------------

class TestFindFileInFlsOutput:
    """Pure unit tests for _find_file_in_fls_output.

    All tests use synthetic fls -l -p lines — no Docker or forensic image
    required.  This covers the four cases required by the spec:
      - exact filename match
      - typo in filename (single-character transposition)
      - multiple similar filenames (ambiguity)
      - no match
    Plus regression guards for the extraction helpers.
    """

    def _line(self, path: str, size: int, inode: str = "100-128-1") -> str:
        """Produce one minimal fls -l -p TSV line."""
        return f"r/r {inode}:\t{path}\t0\t0\t0\t0\t{size}\t0\t0"

    # --- helpers exist ---

    def test_find_file_in_fls_output_exists(self):
        from mcp_local import server
        assert hasattr(server, "_find_file_in_fls_output"), (
            "server.py is missing _find_file_in_fls_output helper."
        )

    def test_build_match_result_exists(self):
        from mcp_local import server
        assert hasattr(server, "_build_match_result"), (
            "server.py is missing _build_match_result helper."
        )

    # --- Case 1: exact filename match ---

    def test_exact_filename_match_returns_ok(self):
        """Querying the exact filename (same case) must return status='ok'."""
        from mcp_local.server import _find_file_in_fls_output
        fls = self._line("USERS/Jimmy Wilson/Documents/The Width Of A Circle.txt", 1783)
        result = _find_file_in_fls_output(fls, "The Width Of A Circle.txt")
        assert result["status"] == "ok"
        assert result["size_bytes"] == 1783
        assert result["file_path"] == "USERS/Jimmy Wilson/Documents/The Width Of A Circle.txt"

    def test_exact_match_case_insensitive(self):
        """Exact match is case-insensitive: 'notes.TXT' finds 'Notes.txt'."""
        from mcp_local.server import _find_file_in_fls_output
        fls = self._line("USERS/Alice/Documents/Notes.txt", 512)
        result = _find_file_in_fls_output(fls, "notes.TXT")
        assert result["status"] == "ok"
        assert result["size_bytes"] == 512

    def test_exact_match_has_no_fuzzy_note(self):
        """An exact match must NOT include fuzzy_note — it was found directly."""
        from mcp_local.server import _find_file_in_fls_output
        fls = self._line("USERS/Jimmy/report.pdf", 2048)
        result = _find_file_in_fls_output(fls, "report.pdf")
        assert result["status"] == "ok"
        assert "fuzzy_note" not in result

    # --- Case 2: typo in filename ---

    def test_typo_transposition_widht_vs_width(self):
        """Single-character transposition 'Widht' for 'Width' must fuzzy-match."""
        from mcp_local.server import _find_file_in_fls_output
        fls = self._line("USERS/Jimmy Wilson/Documents/The Width Of A Circle.txt", 1783)
        result = _find_file_in_fls_output(fls, "The Widht Of a Circle.txt")
        assert result["status"] == "ok", (
            f"Expected status='ok' for typo query, got: {result}"
        )
        assert result["size_bytes"] == 1783
        assert "The Width Of A Circle.txt" in result["file_path"]

    def test_typo_match_has_fuzzy_note(self):
        """A fuzzy match must include a fuzzy_note field to inform the user."""
        from mcp_local.server import _find_file_in_fls_output
        fls = self._line("USERS/Jimmy Wilson/Documents/The Width Of A Circle.txt", 1783)
        result = _find_file_in_fls_output(fls, "The Widht Of a Circle.txt")
        assert result.get("fuzzy_note"), (
            "Fuzzy match result is missing 'fuzzy_note' field."
        )
        assert "The Width Of A Circle.txt" in result["fuzzy_note"], (
            "fuzzy_note does not mention the actual matched filename."
        )

    def test_single_char_deletion_typo(self):
        """Missing a character ('report.pd' for 'report.pdf') must fuzzy-match."""
        from mcp_local.server import _find_file_in_fls_output
        fls = self._line("USERS/Alice/report.pdf", 4096)
        result = _find_file_in_fls_output(fls, "report.pd")
        assert result["status"] == "ok"
        assert "fuzzy_note" in result

    # --- Case 3: multiple similar filenames (ambiguity) ---

    def test_multiple_exact_basenames_returns_multiple_matches(self):
        """When two files share the same basename, return multiple_matches."""
        from mcp_local.server import _find_file_in_fls_output
        fls = "\n".join([
            self._line("USERS/Alice/docs/report.pdf", 100, "101-128-1"),
            self._line("USERS/Bob/docs/report.pdf", 200, "202-128-1"),
        ])
        result = _find_file_in_fls_output(fls, "report.pdf")
        assert result["status"] == "multiple_matches"
        assert len(result["matches"]) == 2

    def test_multiple_fuzzy_candidates_returns_multiple_matches(self):
        """When several files are similarly-named, return multiple_matches
        rather than picking one arbitrarily."""
        from mcp_local.server import _find_file_in_fls_output
        fls = "\n".join([
            self._line("USERS/Alice/docs/report_2020.pdf", 100, "101-128-1"),
            self._line("USERS/Alice/docs/report_2021.pdf", 200, "202-128-1"),
        ])
        # Query is close to both (differs by one digit).
        result = _find_file_in_fls_output(fls, "report_2022.pdf")
        # Both are similar — must not silently pick one.
        assert result["status"] in ("multiple_matches", "path_not_resolved"), (
            "Expected ambiguity or not-found for a query equidistant between two files, "
            f"but got: {result}"
        )

    # --- Case 4: no match ---

    def test_no_match_returns_path_not_resolved(self):
        """A filename with no similar candidate must return path_not_resolved."""
        from mcp_local.server import _find_file_in_fls_output
        fls = self._line("USERS/Jimmy/zzz_completely_unrelated_file.dat", 999)
        result = _find_file_in_fls_output(fls, "nonexistent_file.txt")
        assert result["status"] == "path_not_resolved"

    def test_empty_fls_output_returns_path_not_resolved(self):
        """Empty fls output must return path_not_resolved, not raise."""
        from mcp_local.server import _find_file_in_fls_output
        result = _find_file_in_fls_output("", "any_file.txt")
        assert result["status"] == "path_not_resolved"

    # --- regression: exact beats fuzzy when both exist ---

    def test_exact_match_wins_over_fuzzy_candidate(self):
        """When there is both an exact match and a similar-but-different file,
        the exact match is returned (no fuzzy_note)."""
        from mcp_local.server import _find_file_in_fls_output
        fls = "\n".join([
            self._line("USERS/Alice/notes.txt", 111, "101-128-1"),
            self._line("USERS/Bob/notes_.txt", 222, "202-128-1"),  # similar but not exact
        ])
        result = _find_file_in_fls_output(fls, "notes.txt")
        assert result["status"] == "ok"
        assert result["size_bytes"] == 111          # exact match, not the similar one
        assert "fuzzy_note" not in result

    # --- responder integration: fuzzy_note is surfaced ---

    def test_fmt_file_size_includes_fuzzy_note(self):
        """_fmt_file_size must include fuzzy_note text when the result contains it."""
        from agent.responder import _fmt_file_size
        result = {
            "status": "ok",
            "file_path": "USERS/Jimmy/The Width Of A Circle.txt",
            "size_bytes": 1783,
            "fuzzy_note": "No exact match for 'The Widht Of a Circle.txt'. Closest match: 'The Width Of A Circle.txt'.",
        }
        formatted = _fmt_file_size(result)
        assert "The Width Of A Circle.txt" in formatted
        assert "1,783" in formatted
        assert "Closest match" in formatted

    def test_fmt_file_size_no_note_when_exact(self):
        """_fmt_file_size must NOT add fuzzy-match text for an exact (clean) match."""
        from agent.responder import _fmt_file_size
        result = {
            "status": "ok",
            "file_path": "USERS/Jimmy/exact_file.txt",
            "size_bytes": 512,
        }
        formatted = _fmt_file_size(result)
        assert "512" in formatted
        # fuzzy_note text is only added when fuzzy_note field is present.
        assert "Closest match" not in formatted

