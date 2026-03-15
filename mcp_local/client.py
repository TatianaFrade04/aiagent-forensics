from __future__ import annotations

from typing import Any
from typing import Optional

from .server import LocalMCPServer


class LocalMCPClient:
    """Thin client wrapper so orchestration uses MCP-like method calls."""

    def __init__(self, server: LocalMCPServer):
        self._server = server

    def classify_question(self, question: str, history: str) -> Any:
        return self._server.call_tool("classify_question", question=question, history=history)

    def get_current_image(self) -> Any:
        return self._server.call_tool("get_current_image")

    def get_case_context(self) -> Any:
        return self._server.call_tool("get_case_context")

    def get_prompt_template(self, intent: str) -> Any:
        return self._server.call_tool("get_prompt_template", intent=intent)

    def query_evidence(self, question: str) -> Any:
        return self._server.call_tool("query_evidence", question=question)

    def stat_path(self, path: str) -> Any:
        return self._server.call_tool("stat_path", path=path)

    def list_directory(
        self,
        path: str,
        recursive: bool = False,
        include_dirs: bool = True,
    ) -> Any:
        return self._server.call_tool(
            "list_directory",
            path=path,
            recursive=recursive,
            include_dirs=include_dirs,
        )

    def inspect_image_partitions(self, image_path: str) -> Any:
        return self._server.call_tool("inspect_image_partitions", image_path=image_path)

    def list_users(self, image_path: Optional[str] = None) -> Any:
        return self._server.call_tool("list_users", image_path=image_path)

    def list_primary_partition_root(self, image_path: Optional[str] = None) -> Any:
        return self._server.call_tool("list_primary_partition_root", image_path=image_path)

    def resolve_user_profile(self, user: str, image_path: Optional[str] = None) -> Any:
        return self._server.call_tool("resolve_user_profile", user=user, image_path=image_path)

    def get_special_folder(self, user: str, folder_name: str, image_path: Optional[str] = None) -> Any:
        return self._server.call_tool(
            "get_special_folder",
            user=user,
            folder_name=folder_name,
            image_path=image_path,
        )

    def list_user_directory(
        self,
        user: str,
        folder_name: str,
        include_dirs: bool = True,
        recursive: bool = False,
        image_path: Optional[str] = None,
    ) -> Any:
        return self._server.call_tool(
            "list_user_directory",
            user=user,
            folder_name=folder_name,
            include_dirs=include_dirs,
            recursive=recursive,
            image_path=image_path,
        )

    def get_file_hash(self, file_path: str, algorithm: str = "md5") -> Any:
        return self._server.call_tool("get_file_hash", file_path=file_path, algorithm=algorithm)

    def get_file_size(self, file_path: str) -> Any:
        return self._server.call_tool("get_file_size", file_path=file_path)

    def extract_file_content(self, file_path: str, max_bytes: int = 8192) -> Any:
        return self._server.call_tool("extract_file_content", file_path=file_path, max_bytes=max_bytes)

    def get_filesystem_stats(self, image_path: Optional[str] = None) -> Any:
        return self._server.call_tool("get_filesystem_stats", image_path=image_path)

    def get_disk_metadata(self, image_path: Optional[str] = None) -> Any:
        return self._server.call_tool("get_disk_metadata", image_path=image_path)

    def query_registry(
        self,
        hive: str,
        key_path: Optional[str] = None,
        user: Optional[str] = None,
        image_path: Optional[str] = None,
    ) -> Any:
        return self._server.call_tool(
            "query_registry",
            hive=hive,
            key_path=key_path,
            user=user,
            image_path=image_path,
        )

    def query_event_log(
        self,
        log_name: str = "system",
        event_ids: Optional[list] = None,
        timestamp: Optional[str] = None,
        image_path: Optional[str] = None,
        username: Optional[str] = None,
    ) -> Any:
        return self._server.call_tool(
            "query_event_log",
            log_name=log_name,
            event_ids=event_ids,
            timestamp=timestamp,
            image_path=image_path,
            username=username,
        )

    def query_timeline(
        self,
        user: Optional[str] = None,
        timestamp: Optional[str] = None,
        image_path: Optional[str] = None,
    ) -> Any:
        return self._server.call_tool("query_timeline", user=user, timestamp=timestamp, image_path=image_path)

    def get_email_accounts(
        self,
        user: Optional[str] = None,
        image_path: Optional[str] = None,
    ) -> Any:
        return self._server.call_tool("get_email_accounts", user=user, image_path=image_path)

    def find_flag(self, image_path: Optional[str] = None) -> Any:
        return self._server.call_tool("find_flag", image_path=image_path)

    def find_deleted_files(self, path_filter: Optional[str] = None, image_path: Optional[str] = None) -> Any:
        return self._server.call_tool("find_deleted_files", path_filter=path_filter, image_path=image_path)
