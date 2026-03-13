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
