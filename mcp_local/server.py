from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

from tools.runner import run_cmd

_EVIDENCE_CONTAINER = "/evidence"

ToolHandler = Callable[..., Any]


def _to_container_path(host_path: str, evidence_dir: str) -> str:
    """Translate a Windows host evidence path to its equivalent container path.

    The evidence directory is mounted at /evidence inside the container.
    Using this before embedding paths in bash -c strings prevents run_cmd's
    path-translation logic from corrupting the entire bash command string.
    """
    norm_host = os.path.normpath(host_path)
    norm_ev = os.path.normpath(evidence_dir)
    if norm_host.lower().startswith(norm_ev.lower()):
        relative = norm_host[len(norm_ev):].replace("\\", "/").lstrip("/")
        return f"{_EVIDENCE_CONTAINER}/{relative}" if relative else _EVIDENCE_CONTAINER
    return f"{_EVIDENCE_CONTAINER}/{os.path.basename(host_path)}"


def _resolve_host_path(evidence_dir: str, raw_path: str) -> str:
    """Resolve user-provided literal path into a host filesystem path.

    `/evidence` paths are mapped to the local mounted evidence directory.
    Relative paths are resolved from project root.
    """
    path = (raw_path or "").strip()
    if not path:
        return ""

    project_root = os.path.dirname(evidence_dir)
    normalized = path.replace("\\", "/")

    if normalized == "/evidence":
        return evidence_dir
    if normalized.startswith("/evidence/"):
        suffix = normalized[len("/evidence/"):]
        return os.path.normpath(os.path.join(evidence_dir, suffix))

    if normalized.startswith("./") or normalized.startswith("../"):
        return os.path.normpath(os.path.join(project_root, normalized))

    if os.path.isabs(path):
        return os.path.normpath(path)

    return os.path.normpath(os.path.join(project_root, path))


def _default_stat_path(evidence_dir: str, path: str) -> Dict[str, Any]:
    resolved = _resolve_host_path(evidence_dir, path)
    if not resolved:
        return {
            "status": "path_not_resolved",
            "path": path,
            "resolved_path": resolved,
            "message": "Path was not provided.",
        }

    if not os.path.exists(resolved):
        return {
            "status": "path_not_resolved",
            "path": path,
            "resolved_path": resolved,
            "message": "Path does not exist.",
        }

    is_dir = os.path.isdir(resolved)
    is_file = os.path.isfile(resolved)
    size = os.path.getsize(resolved) if is_file else None
    return {
        "status": "ok",
        "path": path,
        "resolved_path": resolved,
        "is_dir": is_dir,
        "is_file": is_file,
        "size_bytes": size,
    }


def _default_list_directory(
    evidence_dir: str,
    path: str,
    recursive: bool = False,
    include_dirs: bool = True,
) -> Dict[str, Any]:
    stat = _default_stat_path(evidence_dir, path)
    if stat.get("status") != "ok":
        return stat
    if not stat.get("is_dir"):
        return {
            "status": "path_not_resolved",
            "path": path,
            "resolved_path": stat.get("resolved_path"),
            "message": "Path exists but is not a directory.",
        }

    resolved = stat["resolved_path"]
    entries: List[Dict[str, Any]] = []

    if recursive:
        for root, dirs, files in os.walk(resolved):
            rel_root = os.path.relpath(root, resolved)
            if include_dirs:
                for d in dirs:
                    rel = os.path.normpath(os.path.join(rel_root, d))
                    entries.append({"type": "dir", "name": d, "relative_path": rel})
            for f in files:
                rel = os.path.normpath(os.path.join(rel_root, f))
                entries.append({"type": "file", "name": f, "relative_path": rel})
    else:
        for name in sorted(os.listdir(resolved)):
            full = os.path.join(resolved, name)
            if os.path.isdir(full):
                if include_dirs:
                    entries.append({"type": "dir", "name": name, "relative_path": name})
            else:
                entries.append({"type": "file", "name": name, "relative_path": name})

    if not entries:
        return {
            "status": "directory_empty",
            "path": path,
            "resolved_path": resolved,
            "entries": [],
            "count": 0,
        }

    return {
        "status": "ok",
        "path": path,
        "resolved_path": resolved,
        "entries": entries,
        "count": len(entries),
        "recursive": bool(recursive),
        "include_dirs": bool(include_dirs),
    }


def _default_inspect_image_partitions(evidence_dir: str, image_path: str) -> Dict[str, Any]:
    resolved = _resolve_host_path(evidence_dir, image_path)
    if not resolved:
        return {
            "status": "path_not_resolved",
            "image_path": image_path,
            "resolved_path": resolved,
            "message": "Image path was not provided.",
        }

    if not os.path.exists(resolved):
        return {
            "status": "path_not_resolved",
            "image_path": image_path,
            "resolved_path": resolved,
            "message": "Image path does not exist.",
        }

    if not os.path.isfile(resolved):
        return {
            "status": "path_not_resolved",
            "image_path": image_path,
            "resolved_path": resolved,
            "message": "Path exists but is not a file.",
        }

    result = run_cmd(["mmls", "-i", "ewf", resolved], timeout=120)
    if result["returncode"] != 0:
        stderr = (result.get("stderr") or "").strip() or "mmls command failed"
        return {
            "status": "tool_error",
            "image_path": image_path,
            "resolved_path": resolved,
            "message": stderr,
        }

    output = (result.get("stdout") or "").strip()
    partitions = []
    for line in output.splitlines():
        stripped = line.strip()
        if not stripped or ":" not in stripped:
            continue

        right_side = stripped.split(":", 1)[1].strip()
        parts = right_side.split()
        if len(parts) < 5:
            continue

        slot = parts[0]
        start_sector = parts[1]
        end_sector = parts[2]
        length_sector = parts[3]
        description = " ".join(parts[4:])

        if not start_sector.isdigit() or not end_sector.isdigit() or not length_sector.isdigit():
            continue

        partitions.append(
            {
                "slot": slot,
                "start_sector": int(start_sector),
                "end_sector": int(end_sector),
                "length_sectors": int(length_sector),
                "description": description,
            }
        )

    return {
        "status": "ok",
        "image_path": image_path,
        "resolved_path": resolved,
        "partition_count": len(partitions),
        "partitions": partitions,
        "raw_mmls": output,
    }


def _default_list_users(evidence_dir: str, image_path: Optional[str] = None) -> Dict[str, Any]:
    resolved_image: Optional[str] = None
    primary_offset: Optional[str] = None

    if image_path:
        resolved_image = _resolve_host_path(evidence_dir, image_path)
        if not resolved_image or not os.path.exists(resolved_image) or not os.path.isfile(resolved_image):
            return {
                "status": "path_not_resolved",
                "image_path": image_path,
                "resolved_path": resolved_image,
                "message": "Image path does not exist or is not a file.",
            }

        mmls_result = run_cmd(["mmls", "-i", "ewf", resolved_image], timeout=120)
        if mmls_result["returncode"] != 0:
            stderr = (mmls_result.get("stderr") or "").strip() or "mmls command failed"
            return {
                "status": "tool_error",
                "image_path": image_path,
                "resolved_path": resolved_image,
                "message": stderr,
            }

        primary_offset = _extract_primary_partition_offset((mmls_result.get("stdout") or ""))
        if not primary_offset:
            return {
                "status": "insufficient_index_data",
                "image_path": image_path,
                "resolved_path": resolved_image,
                "message": "Could not detect primary partition offset.",
            }
    else:
        resolved_image, primary_offset, error = _resolve_primary_image_and_offset(evidence_dir)
        if not resolved_image:
            return {
                "status": "artifact_not_found",
                "image_path": image_path,
                "resolved_path": resolved_image,
                "message": error or "No forensic image available.",
            }
        if not primary_offset:
            return {
                "status": "insufficient_index_data",
                "image_path": image_path,
                "resolved_path": resolved_image,
                "message": error or "Primary partition offset unavailable.",
            }

    root_result = run_cmd(["fls", "-i", "ewf", "-o", primary_offset, resolved_image], timeout=120)
    if root_result["returncode"] != 0:
        stderr = (root_result.get("stderr") or "").strip() or "fls command failed"
        return {
            "status": "tool_error",
            "image_path": image_path,
            "resolved_path": resolved_image,
            "message": stderr,
        }

    root_output = (root_result.get("stdout") or "").strip()
    users = _extract_user_profiles_from_root_listing(resolved_image, primary_offset, root_output)
    if not users:
        return {
            "status": "artifact_not_found",
            "image_path": image_path,
            "resolved_path": resolved_image,
            "users": [],
            "count": 0,
            "message": "No user profiles found in the selected forensic image.",
        }

    return {
        "status": "ok",
        "image_path": image_path,
        "resolved_path": resolved_image,
        "users": users,
        "count": len(users),
    }


def _default_list_primary_partition_root(evidence_dir: str, image_path: Optional[str] = None) -> Dict[str, Any]:
    resolved_image: Optional[str] = None
    primary_offset: Optional[str] = None

    if image_path:
        resolved_image = _resolve_host_path(evidence_dir, image_path)
        if not resolved_image or not os.path.exists(resolved_image) or not os.path.isfile(resolved_image):
            return {
                "status": "path_not_resolved",
                "image_path": image_path,
                "resolved_path": resolved_image,
                "message": "Image path does not exist or is not a file.",
            }

        mmls_result = run_cmd(["mmls", "-i", "ewf", resolved_image], timeout=120)
        if mmls_result["returncode"] != 0:
            stderr = (mmls_result.get("stderr") or "").strip() or "mmls command failed"
            return {
                "status": "tool_error",
                "image_path": image_path,
                "resolved_path": resolved_image,
                "message": stderr,
            }
        primary_offset = _extract_primary_partition_offset((mmls_result.get("stdout") or ""))
        if not primary_offset:
            return {
                "status": "insufficient_index_data",
                "image_path": image_path,
                "resolved_path": resolved_image,
                "message": "Could not detect primary partition offset.",
            }
    else:
        resolved_image, primary_offset, error = _resolve_primary_image_and_offset(evidence_dir)
        if not resolved_image:
            return {
                "status": "artifact_not_found",
                "image_path": image_path,
                "resolved_path": resolved_image,
                "message": error or "No forensic image available.",
            }
        if not primary_offset:
            return {
                "status": "insufficient_index_data",
                "image_path": image_path,
                "resolved_path": resolved_image,
                "message": error or "Primary partition offset unavailable.",
            }

    fls_result = run_cmd(["fls", "-i", "ewf", "-o", primary_offset, resolved_image], timeout=120)
    if fls_result["returncode"] != 0:
        stderr = (fls_result.get("stderr") or "").strip() or "fls command failed"
        return {
            "status": "tool_error",
            "image_path": image_path,
            "resolved_path": resolved_image,
            "message": stderr,
        }

    output = (fls_result.get("stdout") or "").strip()
    entries: List[Dict[str, Any]] = []
    entry_regex = re.compile(r"^([drv])/([drv])\s+\d+-\d+-\d+:\s*(.+)$", re.IGNORECASE)
    for line in output.splitlines():
        match = entry_regex.match(line.strip())
        if not match:
            continue
        entry_type = match.group(1).lower()
        name = match.group(3).strip()
        if not name:
            continue
        if name in (".", ".."):
            continue
        entries.append(
            {
                "type": "dir" if entry_type == "d" else "file",
                "name": name,
                "raw": line.strip(),
            }
        )

    if not entries:
        return {
            "status": "directory_empty",
            "image_path": image_path,
            "resolved_path": resolved_image,
            "entries": [],
            "count": 0,
            "primary_offset": primary_offset,
        }

    return {
        "status": "ok",
        "image_path": image_path,
        "resolved_path": resolved_image,
        "entries": entries,
        "count": len(entries),
        "primary_offset": primary_offset,
    }


def _resolve_image_and_offset(evidence_dir: str, image_path: Optional[str] = None) -> Tuple[Optional[str], Optional[str], str]:
    if image_path:
        resolved_image = _resolve_host_path(evidence_dir, image_path)
        if not resolved_image or not os.path.exists(resolved_image) or not os.path.isfile(resolved_image):
            return None, None, "Image path does not exist or is not a file."

        mmls_result = run_cmd(["mmls", "-i", "ewf", resolved_image], timeout=120)
        if mmls_result["returncode"] != 0:
            stderr = (mmls_result.get("stderr") or "").strip() or "mmls command failed"
            return resolved_image, None, stderr

        primary_offset = _extract_primary_partition_offset((mmls_result.get("stdout") or ""))
        if not primary_offset:
            return resolved_image, None, "Could not detect primary partition offset."

        return resolved_image, primary_offset, ""

    return _resolve_primary_image_and_offset(evidence_dir)


def _normalize_folder_name(folder_name: str) -> str:
    normalized = (folder_name or "").strip().strip("/")
    mapping = {
        "desktop": "Desktop",
        "documents": "Documents",
        "documentos": "Documents",
        "downloads": "Downloads",
        "pictures": "Pictures",
        "music": "Music",
        "videos": "Videos",
        "appdata": "AppData",
    }
    return mapping.get(normalized.lower(), normalized or "Desktop")


def _default_resolve_user_profile(evidence_dir: str, user: str, image_path: Optional[str] = None) -> Dict[str, Any]:
    requested = (user or "").strip()
    if not requested:
        return {"status": "user_not_found", "message": "User was not provided."}

    users_result = _default_list_users(evidence_dir, image_path=image_path)
    if users_result.get("status") != "ok":
        return users_result

    users = users_result.get("users", [])
    requested_lower = requested.lower()

    exact = next((name for name in users if name.lower() == requested_lower), None)
    if not exact:
        exact = next((name for name in users if requested_lower in name.lower()), None)

    if not exact:
        return {
            "status": "user_not_found",
            "requested_user": requested,
            "available_users": users,
            "message": "User profile not found in forensic image.",
        }

    return {
        "status": "ok",
        "requested_user": requested,
        "resolved_user": exact,
        "available_users": users,
        "image_path": users_result.get("image_path"),
        "resolved_path": users_result.get("resolved_path"),
    }


def _default_get_special_folder(
    evidence_dir: str,
    user: str,
    folder_name: str,
    image_path: Optional[str] = None,
) -> Dict[str, Any]:
    user_result = _default_resolve_user_profile(evidence_dir, user, image_path=image_path)
    if user_result.get("status") != "ok":
        return user_result

    folder = _normalize_folder_name(folder_name)
    resolved_user = user_result.get("resolved_user")
    folder_path = f"/Users/{resolved_user}/{folder}"
    return {
        "status": "ok",
        "resolved_user": resolved_user,
        "folder_name": folder,
        "folder_path": folder_path,
        "image_path": user_result.get("image_path"),
        "resolved_path": user_result.get("resolved_path"),
    }


def _default_list_user_directory(
    evidence_dir: str,
    user: str,
    folder_name: str,
    include_dirs: bool = True,
    recursive: bool = False,
    image_path: Optional[str] = None,
) -> Dict[str, Any]:
    user_result = _default_resolve_user_profile(evidence_dir, user, image_path=image_path)
    if user_result.get("status") != "ok":
        return user_result

    resolved_image, primary_offset, error = _resolve_image_and_offset(evidence_dir, image_path=image_path)
    if not resolved_image:
        return {"status": "artifact_not_found", "message": error or "No forensic image available."}
    if not primary_offset:
        return {"status": "insufficient_index_data", "message": error or "Primary partition offset unavailable."}

    folder = _normalize_folder_name(folder_name)
    resolved_user = user_result.get("resolved_user")
    folder_prefix = f"users/{resolved_user.lower()}/{folder.lower()}"

    fls_result = run_cmd(
        ["fls", "-r", "-p", "-i", "ewf", "-o", primary_offset, resolved_image],
        timeout=300,
    )
    output = (fls_result.get("stdout") or "").strip()
    if fls_result["returncode"] != 0 and not output:
        stderr = (fls_result.get("stderr") or "").strip() or "fls command failed"
        return {"status": "tool_error", "message": stderr}

    entry_regex = re.compile(r"^([drv])/([drv])\s+\d+-\d+-\d+:\s*(.+)$", re.IGNORECASE)
    entries: List[Dict[str, Any]] = []
    saw_folder_prefix = False

    for line in output.splitlines():
        match = entry_regex.match(line.strip())
        if not match:
            continue
        entry_type = match.group(1).lower()
        path_value = match.group(3).strip()
        path_lower = path_value.lstrip("/").lower()

        if path_lower == folder_prefix:
            saw_folder_prefix = True
            continue
        if not path_lower.startswith(folder_prefix + "/"):
            continue

        saw_folder_prefix = True
        relative = path_value[len(folder_prefix):].lstrip("/")
        if not relative:
            continue
        if not recursive and "/" in relative:
            continue

        is_dir = entry_type == "d"
        if is_dir and not include_dirs:
            continue

        name = relative.split("/")[-1]
        entries.append(
            {
                "type": "dir" if is_dir else "file",
                "name": name,
                "relative_path": relative,
                "path": path_value,
            }
        )

    if not saw_folder_prefix:
        return {
            "status": "path_not_resolved",
            "resolved_user": resolved_user,
            "folder_name": folder,
            "message": "Requested user folder was not found in forensic image.",
        }

    if not entries:
        return {
            "status": "directory_empty",
            "resolved_user": resolved_user,
            "folder_name": folder,
            "entries": [],
            "count": 0,
        }

    return {
        "status": "ok",
        "resolved_user": resolved_user,
        "folder_name": folder,
        "entries": entries,
        "count": len(entries),
        "recursive": bool(recursive),
        "include_dirs": bool(include_dirs),
    }


@dataclass
class LocalMCPServer:
    """Minimal in-process MCP-style server with named tool handlers."""

    tools: Dict[str, ToolHandler] = field(default_factory=dict)

    def register_tool(self, name: str, handler: ToolHandler) -> None:
        self.tools[name] = handler

    def call_tool(self, name: str, **kwargs: Any) -> Any:
        if name not in self.tools:
            raise KeyError(f"MCP tool '{name}' is not registered")
        return self.tools[name](**kwargs)


def _default_get_current_image(evidence_dir: str) -> Optional[str]:
    image_ext = {".jpg", ".jpeg", ".png", ".webp", ".bmp"}
    for root, _, files in os.walk(evidence_dir):
        for filename in files:
            ext = os.path.splitext(filename)[1].lower()
            if ext in image_ext:
                return os.path.join(root, filename)
    return None


def _default_get_case_context(evidence_dir: str) -> str:
    if not os.path.isdir(evidence_dir):
        return "No evidence directory found."

    evidence_files = []
    for root, _, files in os.walk(evidence_dir):
        for filename in files:
            full_path = os.path.join(root, filename)
            evidence_files.append(os.path.relpath(full_path, evidence_dir))

    if not evidence_files:
        return "Evidence directory is empty."

    evidence_files.sort()
    preview = "\n".join(f"- {p}" for p in evidence_files[:30])
    suffix = "\n- ..." if len(evidence_files) > 30 else ""

    sections = [f"Evidence files under /evidence:\n{preview}{suffix}"]

    # Try to enrich case context with partition metadata from the first E01 image.
    e01_paths = [
        os.path.join(evidence_dir, rel_path)
        for rel_path in evidence_files
        if rel_path.lower().endswith(".e01")
    ]
    if not e01_paths:
        return "\n\n".join(sections)

    primary_image = e01_paths[0]
    primary_name = os.path.relpath(primary_image, evidence_dir)
    sections.append(f"Primary forensic image: {primary_name}")

    mmls_result = run_cmd(["mmls", "-i", "ewf", primary_image], timeout=120)
    if mmls_result["returncode"] != 0:
        stderr = (mmls_result.get("stderr") or "").strip() or "mmls command failed"
        sections.append(f"Partition table analysis unavailable: {stderr}")
        return "\n\n".join(sections)

    mmls_output = (mmls_result.get("stdout") or "").strip()
    sections.append("Partition table (mmls):\n" + (mmls_output or "(empty output)"))

    primary_offset = _extract_primary_partition_offset(mmls_output)
    if primary_offset is None:
        sections.append("Primary partition root listing unavailable: could not detect a primary partition offset.")
        return "\n\n".join(sections)

    fls_result = run_cmd(["fls", "-i", "ewf", "-o", primary_offset, primary_image], timeout=120)
    if fls_result["returncode"] != 0:
        stderr = (fls_result.get("stderr") or "").strip() or "fls command failed"
        sections.append(f"Primary partition root listing unavailable: {stderr}")
        return "\n\n".join(sections)

    fls_output = (fls_result.get("stdout") or "").strip()
    fls_lines = fls_output.splitlines()
    preview_lines = fls_lines[:120]
    preview_suffix = "\n..." if len(fls_lines) > 120 else ""
    sections.append(
        "Primary partition root entries (fls):\n"
        + ("\n".join(preview_lines) if preview_lines else "(no entries)")
        + preview_suffix
    )

    user_profiles = _extract_user_profiles_from_root_listing(
        image_path=primary_image,
        primary_offset=primary_offset,
        root_listing=fls_output,
    )
    if user_profiles:
        users_text = "\n".join(f"- {name}" for name in user_profiles)
        sections.append(f"Detected user profiles:\n{users_text}")
    else:
        sections.append("Detected user profiles:\n- none found")

    return "\n\n".join(sections)


def _extract_primary_partition_offset(mmls_output: str) -> Optional[str]:
    candidates = []
    for line in (mmls_output or "").splitlines():
        stripped = line.strip()
        if not stripped or ":" not in stripped:
            continue

        right_side = stripped.split(":", 1)[1].strip()
        parts = right_side.split()
        # Expected columns after ':' are: slot start end length description...
        if len(parts) < 5:
            continue

        slot = parts[0]
        start_sector = parts[1]
        length_sector = parts[3]
        description = " ".join(parts[4:]).lower()

        if (
            "unallocated" in description
            or "metadata" in description
            or "reserved" in description
            or "safety table" in description
            or "header" in description
            or "partition table" in description
        ):
            continue

        if not start_sector.isdigit() or not length_sector.isdigit():
            continue

        # Prefer known filesystem partitions and sizeable data partitions.
        score = 0
        if any(fs in description for fs in ("ntfs", "fat", "ext", "hfs", "apfs", "linux")):
            score += 3
        if "basic data partition" in description:
            score += 2
        if slot.isdigit():
            score += 1

        candidates.append((score, int(length_sector), start_sector))

    if not candidates:
        return None

    candidates.sort(key=lambda item: (item[0], item[1]), reverse=True)
    return candidates[0][2]


def _extract_user_profiles_from_root_listing(
    image_path: str,
    primary_offset: str,
    root_listing: str,
) -> List[str]:
    users_inodes = []
    inode_regex = re.compile(r"^d/d\s+(\d+)-\d+-\d+:\s*(USERS|Users)\s*$")

    for line in (root_listing or "").splitlines():
        match = inode_regex.match(line.strip())
        if match:
            users_inodes.append(match.group(1))

    profiles = set()
    entry_regex = re.compile(r"^[drv]/[drv]\s+\d+-\d+-\d+:\s*(.+)$", re.IGNORECASE)

    for inode in users_inodes:
        users_dir_result = run_cmd(
            ["fls", "-i", "ewf", "-o", primary_offset, image_path, inode],
            timeout=120,
        )
        if users_dir_result["returncode"] != 0:
            continue

        users_output = (users_dir_result.get("stdout") or "").strip()
        for line in users_output.splitlines():
            match = entry_regex.match(line.strip())
            if not match:
                continue

            name = match.group(1).strip()
            if not name or name in (".", ".."):
                continue

            lowered = name.lower()
            if lowered in ("all users", "default", "default user", "public"):
                continue

            profiles.add(name)

    return sorted(profiles)


def _resolve_primary_image_and_offset(evidence_dir: str) -> Tuple[Optional[str], Optional[str], str]:
    if not os.path.isdir(evidence_dir):
        return None, None, "No evidence directory found."

    evidence_files = []
    for root, _, files in os.walk(evidence_dir):
        for filename in files:
            full_path = os.path.join(root, filename)
            evidence_files.append(os.path.relpath(full_path, evidence_dir))

    e01_paths = [
        os.path.join(evidence_dir, rel_path)
        for rel_path in sorted(evidence_files)
        if rel_path.lower().endswith(".e01")
    ]
    if not e01_paths:
        return None, None, "No .E01 evidence image found."

    primary_image = e01_paths[0]
    mmls_result = run_cmd(["mmls", "-i", "ewf", primary_image], timeout=120)
    if mmls_result["returncode"] != 0:
        stderr = (mmls_result.get("stderr") or "").strip() or "mmls command failed"
        return primary_image, None, f"Partition analysis unavailable: {stderr}"

    primary_offset = _extract_primary_partition_offset((mmls_result.get("stdout") or ""))
    if not primary_offset:
        return primary_image, None, "Could not detect primary partition offset."

    return primary_image, primary_offset, ""


def _extract_query_user_name(question: str) -> Optional[str]:
    text = question or ""
    patterns = [
        r"(?:user|utilizador|usu[aá]rio)\s+([A-Za-z][A-Za-z\s\.-]{1,60})",
        r"(?:desktop|ambiente de trabalho|work environment)\s+(?:do|da|de|of)\s+([A-Za-z][A-Za-z\s\.-]{1,60})",
    ]
    for pattern in patterns:
        match = re.search(pattern, text, flags=re.IGNORECASE)
        if match:
            return re.sub(r"\s+", " ", match.group(1)).strip(" .")
    return None


def _extract_query_filename(question: str) -> Optional[str]:
    match = re.search(r"([A-Za-z0-9_\-]+\.[A-Za-z0-9]{1,8})", question or "")
    return match.group(1) if match else None


def _extract_query_folder_name(question: str) -> Optional[str]:
    text = question or ""

    # Prefer explicit NTFS metadata references (e.g. $Extend, $MFT, $LogFile).
    m = re.search(r"(\$[A-Za-z0-9_\-.$]+)", text)
    if m:
        return m.group(1)

    # Generic "folder X" / "pasta X" extraction.
    m = re.search(
        r"(?:folder|directory|pasta|diret[óo]rio)\s+([A-Za-z0-9_\-./$\\]+)",
        text,
        flags=re.IGNORECASE,
    )
    if m:
        return m.group(1).strip().strip("?.!,;:")

    return None


def _default_query_evidence(evidence_dir: str, question: str) -> str:
    lowered = (question or "").lower()
    image_path, primary_offset, error = _resolve_primary_image_and_offset(evidence_dir)
    if not image_path:
        return error
    if not primary_offset:
        return error

    if any(term in lowered for term in ["parti", "partition"]):
        result = run_cmd(["mmls", "-i", "ewf", image_path], timeout=120)
        if result["returncode"] != 0:
            stderr = (result.get("stderr") or "").strip() or "mmls command failed"
            return f"Partition query failed: {stderr}"
        return "Partition table (mmls):\n" + ((result.get("stdout") or "").strip() or "(empty output)")

    folder_name = _extract_query_folder_name(question)
    if folder_name:
        result = run_cmd(
            ["fls", "-r", "-p", "-i", "ewf", "-o", primary_offset, image_path],
            timeout=300,
        )
        stdout = (result.get("stdout") or "").strip()
        if result["returncode"] != 0 and not stdout:
            stderr = (result.get("stderr") or "").strip() or "fls command failed"
            return f"Directory query failed: {stderr}"

        target = folder_name.strip().replace("\\", "/").strip("/").lower()
        entry_regex = re.compile(r"^([drv])/([drv])\s+\d+-\d+-\d+:\s*(.+)$", re.IGNORECASE)
        entries: List[Dict[str, str]] = []
        seen = set()
        saw_target = False

        for line in stdout.splitlines():
            match = entry_regex.match(line.strip())
            if not match:
                continue

            entry_type = match.group(1).lower()
            path_value = match.group(3).strip().lstrip("/")
            path_lower = path_value.lower()

            if path_lower == target:
                saw_target = True
                continue
            if not path_lower.startswith(target + "/"):
                continue

            saw_target = True
            relative = path_value[len(target):].lstrip("/")
            if not relative or "/" in relative:
                continue

            key = (relative.lower(), entry_type)
            if key in seen:
                continue
            seen.add(key)
            entries.append(
                {
                    "type": "dir" if entry_type == "d" else "file",
                    "name": relative,
                    "path": path_value,
                }
            )

        if not saw_target:
            return f"Directory '{folder_name}' was not found in the forensic image."
        if not entries:
            return f"Directory '{folder_name}' exists but has no direct entries."

        entries.sort(key=lambda item: (item["type"], item["name"].lower()))
        lines = [f"- {item['name']} ({item['type']})" for item in entries]
        return f"Entries in {folder_name}:\n" + "\n".join(lines)

    user_name = _extract_query_user_name(question)
    if user_name and any(term in lowered for term in ["desktop", "ambiente de trabalho", "work environment"]):
        result = run_cmd(
            ["fls", "-r", "-p", "-i", "ewf", "-o", primary_offset, image_path],
            timeout=240,
        )
        stdout = (result.get("stdout") or "").strip()
        if result["returncode"] != 0 and not stdout:
            stderr = (result.get("stderr") or "").strip() or "fls command failed"
            return f"Desktop query failed: {stderr}"

        user_path = f"/users/{user_name.lower()}/desktop"
        lines = [line for line in stdout.splitlines() if user_path in line.lower()]
        preview = "\n".join(lines[:80]) if lines else "(no entries found)"
        return (
            f"Desktop entries for {user_name} (fls -r -p):\n"
            + preview
        )

    if any(term in lowered for term in ["users", "utilizadores", "usu[aá]rios", "quais os users"]):
        root_result = run_cmd(["fls", "-i", "ewf", "-o", primary_offset, image_path], timeout=120)
        root_output = (root_result.get("stdout") or "").strip()
        profiles = _extract_user_profiles_from_root_listing(image_path, primary_offset, root_output)
        if not profiles:
            return "No user profiles found in the primary partition."
        return "Detected user profiles:\n" + "\n".join(f"- {name}" for name in profiles)

    file_name = _extract_query_filename(question)
    if file_name and any(term in lowered for term in ["tamanho", "size"]):
        result = run_cmd(
            ["fls", "-r", "-l", "-p", "-i", "ewf", "-o", primary_offset, image_path],
            timeout=240,
        )
        stdout = (result.get("stdout") or "").strip()
        if result["returncode"] != 0 and not stdout:
            stderr = (result.get("stderr") or "").strip() or "fls command failed"
            return f"File size query failed: {stderr}"

        matches = [line for line in stdout.splitlines() if file_name.lower() in line.lower()]
        if not matches:
            return f"No entries found for '{file_name}' in primary partition listing."
        return f"Matching entries for {file_name} (fls -r -l -p):\n" + "\n".join(matches[:40])

    if any(term in lowered for term in ["shutdown", "deslig", "encerramento"]):
        result = run_cmd(
            ["fls", "-r", "-p", "-i", "ewf", "-o", primary_offset, image_path],
            timeout=240,
        )
        stdout = (result.get("stdout") or "").strip()
        candidates = []
        for line in stdout.splitlines():
            lowered_line = line.lower()
            if any(
                marker in lowered_line
                for marker in ["windows/system32/config/system", "system.evtx", "winevt/logs/system"]
            ):
                candidates.append(line)

        return (
            "Potential shutdown-related artifacts (path-level only):\n"
            + ("\n".join(candidates[:60]) if candidates else "(no obvious artifacts found)")
            + "\nNote: precise last shutdown time needs registry/event-log parsing."
        )

    if any(term in lowered for term in ["last run", "ultima vez", "quando foi", "last used", "last opened", "last time", "last access", "ultimo acesso"]):
        return (
            "Timeline analysis (last run / last access times) requires registry or event-log parsing "
            "which is not yet implemented. "
            f"Available evidence image: {os.path.basename(image_path)}"
        )

    # Email / document type search: detect requests for files by type and search recursively.
    _EXTENSION_QUERIES: List[tuple] = [
        (["email", "e-mail", "eml", "mail", "correio", "mensagem", "inbox", "windows live mail"], [".eml", ".msg", ".pst", ".ost", ".mbox"]),
        (["pdf"], [".pdf"]),
        (["imagem", "photo", "foto", "image", "jpg", "jpeg", "png", "bmp"], [".jpg", ".jpeg", ".png", ".bmp", ".gif", ".webp"]),
        (["video", "vídeo", "mp4", "avi", "mkv"], [".mp4", ".avi", ".mkv", ".mov", ".wmv"]),
        (["audio", "mp3", "música", "musica"], [".mp3", ".wav", ".flac", ".aac", ".ogg"]),
        (["documento", "document", "docx", "xlsx", "word", "excel"], [".doc", ".docx", ".xls", ".xlsx", ".odt", ".ods"]),
        (["executavel", "executável", "executable", "exe", "binario", "binário", "programa", "program"], [".exe", ".dll", ".bat", ".cmd", ".ps1"]),
        (["zip", "comprimido", "compressed", "archive", "rar", "7z"], [".zip", ".rar", ".7z", ".tar", ".gz"]),
        (["encrypt", "encriptado", "encrypted", "bcrypt", "bitlocker"], [".bfe", ".pfx", ".p12", ".cer"]),
    ]
    matched_extensions: List[str] = []
    for keywords, exts in _EXTENSION_QUERIES:
        if any(kw in lowered for kw in keywords):
            matched_extensions = exts
            break

    if matched_extensions:
        result = run_cmd(
            ["fls", "-r", "-p", "-i", "ewf", "-o", primary_offset, image_path],
            timeout=300,
        )
        stdout = (result.get("stdout") or "").strip()
        if result["returncode"] != 0 and not stdout:
            stderr = (result.get("stderr") or "").strip() or "fls command failed"
            return f"File search failed: {stderr}"

        ext_lower = [e.lower() for e in matched_extensions]
        matches = []
        for line in stdout.splitlines():
            ll = line.lower()
            if any(ll.endswith(ext) or (ext + "\t") in ll or (ext + " ") in ll for ext in ext_lower):
                matches.append(line)

        if not matches:
            return f"No files with extensions {matched_extensions} found in the forensic image."

        preview = "\n".join(matches[:60])
        suffix = f"\n... ({len(matches) - 60} more)" if len(matches) > 60 else ""
        return (
            f"Files matching {matched_extensions} found in forensic image ({len(matches)} total):\n"
            + preview + suffix
        )

    # Generic fallback for other inventory-style forensic questions.
    result = run_cmd(["fls", "-i", "ewf", "-o", primary_offset, image_path], timeout=120)
    if result["returncode"] != 0:
        stderr = (result.get("stderr") or "").strip() or "fls command failed"
        return f"Root listing query failed: {stderr}"

    lines = ((result.get("stdout") or "").strip()).splitlines()
    preview = "\n".join(lines[:120]) if lines else "(no entries)"
    suffix = "\n..." if len(lines) > 120 else ""
    return "Primary partition root entries (fls):\n" + preview + suffix


def _default_get_prompt_template(intent: str) -> Dict[str, str]:
    templates = {
        "general_description": {
            "name": "general_description",
            "template": (
                "Describe only what is visually present in the image. "
                "Avoid assumptions and keep language precise."
            ),
        },
        "object_presence": {
            "name": "object_presence",
            "template": (
                "Determine whether the requested object or attribute is visible. "
                "If uncertain, say it is not clearly visible."
            ),
        },
        "object_location": {
            "name": "object_location",
            "template": (
                "Locate requested objects using relative regions (top-left, center, foreground, background). "
                "Do not infer beyond the visible frame."
            ),
        },
        "forensic_trace_detection": {
            "name": "forensic_trace_detection",
            "template": (
                "Look for visible forensic traces (damage, residues, disturbances, markings). "
                "Report only directly observable indicators."
            ),
        },
        "scene_relationships": {
            "name": "scene_relationships",
            "template": (
                "Describe visible spatial relationships between relevant entities. "
                "Do not infer timeline, intent, or causality."
            ),
        },
        "evidence_inventory": {
            "name": "evidence_inventory",
            "template": (
                "Summarize available evidence entries from case context. "
                "List factual file or folder names only and avoid speculation about unseen contents."
            ),
        },
        "insufficient_visual_evidence": {
            "name": "insufficient_visual_evidence",
            "template": (
                "State that available visual evidence is insufficient and explain what is missing."
            ),
        },
        "unsafe_inference": {
            "name": "unsafe_inference",
            "template": (
                "Refuse speculative or sensitive inference requests and redirect to observable facts only."
            ),
        },
    }

    default_template = {
        "name": "safe_generic_visual_analysis",
        "template": (
            "Analyze only visible evidence in the image. "
            "If certainty is low, state uncertainty explicitly and avoid speculation."
        ),
    }

    return templates.get(intent, default_template)


# =========================
# File hash / size / content
# =========================

def _find_inode_for_path(image_path: str, primary_offset: str, file_path: str) -> Optional[str]:
    """Return the inode string (e.g. '12345-128-1') for a file path inside the forensic image.
    Falls back to basename-only matching to handle LLM-hallucinated paths like /path/to/file.ext.
    """
    fls_result = run_cmd(
        ["fls", "-r", "-p", "-i", "ewf", "-o", primary_offset, image_path],
        timeout=300,
    )
    output = (fls_result.get("stdout") or "").strip()
    if not output:
        return None

    inode_regex = re.compile(r"^[drv]/[drv]\s+(\S+):\s*(.+)$", re.IGNORECASE)
    lines_parsed = []
    for line in output.splitlines():
        match = inode_regex.match(line.strip())
        if match:
            lines_parsed.append((match.group(1), match.group(2).strip().lstrip("/").lower()))

    # First pass: full suffix match
    target_lower = file_path.strip().lstrip("/").lower()
    for inode, path_val in lines_parsed:
        if path_val == target_lower or path_val.endswith("/" + target_lower) or path_val.endswith(target_lower):
            return inode

    # Second pass: basename-only match (handles hallucinated paths like /path/to/file.ext)
    basename_lower = os.path.basename(file_path.replace("\\", "/")).lower()
    if basename_lower and basename_lower != target_lower:
        for inode, path_val in lines_parsed:
            if path_val == basename_lower or path_val.endswith("/" + basename_lower):
                return inode

    return None


def _default_get_file_hash(evidence_dir: str, file_path: str, algorithm: str = "md5") -> Dict[str, Any]:
    if not file_path:
        return {"status": "path_not_resolved", "file_path": file_path, "message": "File path was not provided."}

    algorithm = algorithm.lower() if algorithm else "md5"
    if algorithm not in ("md5", "sha1", "sha256"):
        algorithm = "md5"
    hash_cmd = {"md5": "md5sum", "sha1": "sha1sum", "sha256": "sha256sum"}[algorithm]

    resolved_image, primary_offset, error = _resolve_primary_image_and_offset(evidence_dir)
    if not resolved_image:
        return {"status": "artifact_not_found", "file_path": file_path, "message": error or "No forensic image available."}
    if not primary_offset:
        return {"status": "insufficient_index_data", "file_path": file_path, "message": error or "Primary partition offset unavailable."}

    inode = _find_inode_for_path(resolved_image, primary_offset, file_path)
    if not inode:
        return {"status": "path_not_resolved", "file_path": file_path, "message": f"File '{file_path}' not found in forensic image."}

    container_image = _to_container_path(resolved_image, evidence_dir)
    cmd = f"icat -i ewf -o {primary_offset} {container_image} {inode} | {hash_cmd}"
    result = run_cmd(["bash", "-lc", cmd], timeout=300)
    stdout = (result.get("stdout") or "").strip()
    if result["returncode"] != 0 and not stdout:
        stderr = (result.get("stderr") or "").strip() or "hash command failed"
        return {"status": "tool_error", "file_path": file_path, "message": stderr}

    hash_value = stdout.split()[0] if stdout else ""
    if not hash_value:
        return {"status": "tool_error", "file_path": file_path, "message": "Hash command produced no output."}

    return {
        "status": "ok",
        "file_path": file_path,
        "algorithm": algorithm,
        "hash": hash_value.upper(),
        "inode": inode,
    }


def _build_match_result(
    original_filename: str,
    matches: List[Tuple[str, int]],
) -> Dict[str, Any]:
    """Build a status dict from a (resolved_path, size_bytes) match list.

    Returns 'ok' for a single unique match, 'multiple_matches' for several.
    Never mutates *matches*.
    """
    if len(matches) == 1:
        return {
            "status": "ok",
            "file_path": matches[0][0],   # resolved full path from fls
            "size_bytes": matches[0][1],
        }
    paths_str = "\n".join(
        f"  - {p} ({s:,} bytes)" for (p, s) in matches[:10]
    )
    return {
        "status": "multiple_matches",
        "file_path": original_filename,
        "message": (
            f"Found {len(matches)} file(s) for '{original_filename}'. "
            f"Please specify the full path:\n{paths_str}"
        ),
        "matches": [{"path": p, "size_bytes": s} for (p, s) in matches[:10]],
    }


def _find_file_in_fls_output(output: str, filename: str) -> Dict[str, Any]:
    """Pure matching logic: locate *filename* inside fls -l -p stdout.

    Search strategy (applied in order; halts at first success):

      Pass 1 — Exact case-insensitive basename match.
               Handles identical names regardless of case ("notes.TXT" for "notes.txt").

      Pass 2 — Fuzzy basename match via difflib.get_close_matches (cutoff 0.75).
               Catches single-character typos, transpositions, and minor capitalisation
               differences.  When a single fuzzy candidate is found the result has
               status 'ok' *plus* a 'fuzzy_note' field describing what was matched,
               so the caller/responder can inform the user.

    Returns the same structure as _build_match_result:
      - "ok"               : one match; file_path (resolved) + size_bytes [+ fuzzy_note].
      - "multiple_matches" : more than one file equally (or similarly) named.
      - "path_not_resolved": nothing found at either pass.
    """
    import difflib

    target_lower = filename.strip().lower()

    # Parse every fls -l -p line into (full_path, basename_lower, size_bytes).
    # fls -l -p TSV: <type inode:>\t<full-path>\t<mtime>\t<atime>\t<ctime>\t<crtime>\t<size>\t<uid>\t<gid>
    all_entries: List[Tuple[str, str, int]] = []
    for line in output.splitlines():
        tab_parts = line.split("\t")
        if len(tab_parts) < 2:
            continue
        path_token = tab_parts[1].strip()
        if not path_token:
            continue
        basename = path_token.split("/")[-1].lower()
        size_bytes: Optional[int] = None
        if len(tab_parts) >= 7 and tab_parts[6].strip().isdigit():
            size_bytes = int(tab_parts[6].strip())
        else:
            # Fallback: last purely-numeric token that is plausibly a byte count.
            tokens = line.split()
            numeric = [t for t in tokens if t.isdigit() and len(t) <= 12]
            if numeric:
                size_bytes = int(numeric[-1])
        if size_bytes is not None:
            all_entries.append((path_token, basename, size_bytes))

    # --- Pass 1: exact case-insensitive basename match ---
    exact: List[Tuple[str, int]] = [
        (p, s) for (p, bn, s) in all_entries if bn == target_lower
    ]
    if exact:
        return _build_match_result(filename, exact)

    # --- Pass 2: fuzzy basename match (difflib, cutoff 0.75) ---
    all_basenames = [bn for (_, bn, _) in all_entries]
    close_names = set(
        difflib.get_close_matches(target_lower, all_basenames, n=5, cutoff=0.75)
    )
    if close_names:
        fuzzy_raw: List[Tuple[str, int]] = [
            (p, s) for (p, bn, s) in all_entries if bn in close_names
        ]
        # Deduplicate paths (allocated + unallocated fls entries for the same file).
        seen: set = set()
        fuzzy: List[Tuple[str, int]] = []
        for p, s in fuzzy_raw:
            if p.lower() not in seen:
                seen.add(p.lower())
                fuzzy.append((p, s))
        if fuzzy:
            result = _build_match_result(filename, fuzzy)
            if result["status"] == "ok":
                actual_name = fuzzy[0][0].split("/")[-1]
                result["fuzzy_note"] = (
                    f"No exact match for '{filename}'. "
                    f"Closest match: '{actual_name}'."
                )
            return result

    return {
        "status": "path_not_resolved",
        "file_path": filename,
        "message": f"File '{filename}' not found in forensic image listing.",
    }


def _default_find_file_by_name(evidence_dir: str, filename: str) -> Dict[str, Any]:
    """Search the forensic image for a file by bare basename.

    Delegates all matching to _find_file_in_fls_output (exact then fuzzy).
    Returns the same status structure as get_file_size so the responder handles
    results from both entry points uniformly:
      - "ok"               : one match; file_path (resolved) + size_bytes [+ fuzzy_note].
      - "multiple_matches" : more than one file matches by name or close similarity.
      - "path_not_resolved": no file found at any level of matching.
    """
    if not filename:
        return {"status": "path_not_resolved", "file_path": filename, "message": "Filename was not provided."}

    resolved_image, primary_offset, error = _resolve_primary_image_and_offset(evidence_dir)
    if not resolved_image:
        return {"status": "artifact_not_found", "file_path": filename, "message": error or "No forensic image available."}
    if not primary_offset:
        return {"status": "insufficient_index_data", "file_path": filename, "message": error or "Primary partition offset unavailable."}

    result = run_cmd(
        ["fls", "-r", "-l", "-p", "-i", "ewf", "-o", primary_offset, resolved_image],
        timeout=300,
    )
    output = (result.get("stdout") or "").strip()
    if result["returncode"] != 0 and not output:
        stderr = (result.get("stderr") or "").strip() or "fls command failed"
        return {"status": "tool_error", "file_path": filename, "message": stderr}

    return _find_file_in_fls_output(output, filename)


def _default_get_file_size(evidence_dir: str, file_path: str) -> Dict[str, Any]:
    """Return the size in bytes of a file at an explicit path in the forensic image.

    *file_path* should contain at least one path separator ('/').  For bare
    filenames (no separator), the executor should call _default_find_file_by_name
    via client.find_file_by_name instead.  As a safety fallback, bare names
    received here are delegated to _default_find_file_by_name automatically.
    """
    if not file_path:
        return {"status": "path_not_resolved", "file_path": file_path, "message": "File path was not provided."}

    # Safety fallback: bare filename (no '/') → basename search.
    if "/" not in file_path.strip().lstrip("/"):
        return _default_find_file_by_name(evidence_dir, file_path)

    resolved_image, primary_offset, error = _resolve_primary_image_and_offset(evidence_dir)
    if not resolved_image:
        return {"status": "artifact_not_found", "file_path": file_path, "message": error or "No forensic image available."}
    if not primary_offset:
        return {"status": "insufficient_index_data", "file_path": file_path, "message": error or "Primary partition offset unavailable."}

    result = run_cmd(
        ["fls", "-r", "-l", "-p", "-i", "ewf", "-o", primary_offset, resolved_image],
        timeout=300,
    )
    output = (result.get("stdout") or "").strip()
    if result["returncode"] != 0 and not output:
        stderr = (result.get("stderr") or "").strip() or "fls command failed"
        return {"status": "tool_error", "file_path": file_path, "message": stderr}

    # fls -l -p TSV: <type inode:>\t<full-path>\t<mtime>\t<atime>\t<ctime>\t<crtime>\t<size>\t<uid>\t<gid>
    target = file_path.strip().lstrip("/")
    target_lower = target.lower()
    for line in output.splitlines():
        tab_parts = line.split("\t")
        if len(tab_parts) < 2:
            continue
        path_token = tab_parts[1].strip()
        if not path_token:
            continue
        path_lower = path_token.lower()
        if path_lower == target_lower or path_lower.endswith("/" + target_lower):
            size_bytes = None
            if len(tab_parts) >= 7 and tab_parts[6].strip().isdigit():
                size_bytes = int(tab_parts[6].strip())
            else:
                tokens = line.split()
                numeric = [t for t in tokens if t.isdigit() and len(t) <= 12]
                if numeric:
                    size_bytes = int(numeric[-1])
            if size_bytes is not None:
                return {
                    "status": "ok",
                    "file_path": path_token,
                    "size_bytes": size_bytes,
                }

    return {
        "status": "path_not_resolved",
        "file_path": file_path,
        "message": f"File at path '{file_path}' not found in forensic image listing.",
    }


def _default_extract_file_content(evidence_dir: str, file_path: str, max_bytes: int = 8192) -> Dict[str, Any]:
    if not file_path:
        return {"status": "path_not_resolved", "file_path": file_path, "message": "File path was not provided."}

    resolved_image, primary_offset, error = _resolve_primary_image_and_offset(evidence_dir)
    if not resolved_image:
        return {"status": "artifact_not_found", "file_path": file_path, "message": error or "No forensic image available."}
    if not primary_offset:
        return {"status": "insufficient_index_data", "file_path": file_path, "message": error or "Primary partition offset unavailable."}

    inode = _find_inode_for_path(resolved_image, primary_offset, file_path)
    if not inode:
        return {"status": "path_not_resolved", "file_path": file_path, "message": f"File '{file_path}' not found in forensic image."}

    result = run_cmd(
        ["icat", "-i", "ewf", "-o", primary_offset, resolved_image, inode],
        timeout=120,
    )
    raw = result.get("stdout") or ""
    if result["returncode"] != 0 and not raw:
        stderr = (result.get("stderr") or "").strip() or "icat command failed"
        return {"status": "tool_error", "file_path": file_path, "message": stderr}

    if isinstance(raw, bytes):
        content = raw.decode("utf-8", errors="replace")
    else:
        content = raw

    truncated = len(content) > max_bytes
    snippet = content[:max_bytes]

    # Detect mbox format: the first line starts with "From " followed by a sender
    # address and a date stamp (standard POSIX mbox envelope-sender line).
    # Thunderbird stores each mail folder (INBOX, Sent, Drafts …) as a single mbox
    # file.  Without mbox-aware parsing `extract_file_content` would return raw mbox
    # bytes that the LLM cannot present as a readable email.
    first_line = snippet.split("\n", 1)[0]
    if re.match(r"^From \S", first_line):
        # Split on mbox message boundaries: a line starting with "From " that
        # is preceded by a blank line (or at the very start of the file).
        # re.split on \n\nFrom preserves the separator in subsequent parts.
        parts = re.split(r"\n(?=From \S)", snippet)
        # parts[0] is the first message (including its "From " envelope line).
        # Skip the envelope line; the RFC 2822 headers + body start on line 2.
        first_msg_lines = parts[0].split("\n")[1:]  # drop "From user@host date" line
        first_message = "\n".join(first_msg_lines).strip()
        total_messages = len(parts)
        return {
            "status": "ok",
            "file_path": file_path,
            "inode": inode,
            "format": "mbox",
            "content": first_message,
            "truncated": truncated,
            "mbox_note": (
                f"This is message 1 of {total_messages} in a Thunderbird mbox folder. "
                "To read another message, the file contains multiple 'From ' delimited messages."
            ),
        }

    return {
        "status": "ok",
        "file_path": file_path,
        "inode": inode,
        "content": snippet,
        "truncated": truncated,
    }


# =========================
# Filesystem stats
# =========================

def _extract_partition_offsets_all(mmls_output: str) -> List[str]:
    """
    Return start-sector offsets for all real (non-meta, non-unallocated) partitions
    from mmls output, sorted by start sector ascending.  Index is 1-based.

    Filters out entries whose slot field is non-numeric ("Meta", "-------", etc.).
    """
    results = []
    for line in (mmls_output or "").splitlines():
        stripped = line.strip()
        if not stripped or ":" not in stripped:
            continue
        right_side = stripped.split(":", 1)[1].strip()
        parts = right_side.split()
        if len(parts) < 5:
            continue
        slot = parts[0]
        start_sector = parts[1]
        length_sector = parts[3]
        if not start_sector.isdigit() or not length_sector.isdigit():
            continue
        if not slot.isdigit():
            continue
        results.append((int(start_sector), start_sector))
    results.sort(key=lambda x: x[0])
    return [r[1] for r in results]


def _default_get_filesystem_stats(
    evidence_dir: str,
    image_path: Optional[str] = None,
    partition_index: Optional[int] = None,
) -> Dict[str, Any]:
    resolved_image, primary_offset, error = _resolve_image_and_offset(evidence_dir, image_path)
    if not resolved_image:
        return {"status": "artifact_not_found", "image_path": image_path, "message": error or "No forensic image available."}
    if not primary_offset:
        return {"status": "insufficient_index_data", "image_path": image_path, "message": error or "Primary partition offset unavailable."}

    # When the caller requests a specific partition, override the auto-detected offset.
    if partition_index is not None:
        mmls_result = run_cmd(["mmls", "-i", "ewf", resolved_image], timeout=120)
        all_offsets = _extract_partition_offsets_all((mmls_result.get("stdout") or ""))
        if partition_index < 1 or partition_index > len(all_offsets):
            return {
                "status": "artifact_not_found",
                "image_path": image_path,
                "partition_index": partition_index,
                "message": (
                    f"Partition index {partition_index} is out of range. "
                    f"Found {len(all_offsets)} real (non-meta) partition(s)."
                ),
            }
        primary_offset = all_offsets[partition_index - 1]

    result = run_cmd(["fsstat", "-i", "ewf", "-o", primary_offset, resolved_image], timeout=120)
    output = (result.get("stdout") or "").strip()
    if result["returncode"] != 0 and not output:
        stderr = (result.get("stderr") or "").strip() or "fsstat command failed"
        return {"status": "tool_error", "image_path": image_path, "message": stderr}

    def _parse_fsstat_field(text: str, *keys: str) -> Optional[str]:
        for key in keys:
            for line in text.splitlines():
                if key.lower() in line.lower() and ":" in line:
                    val = line.split(":", 1)[1].strip()
                    if val:
                        return val
        return None

    cluster_size = _parse_fsstat_field(output, "Cluster Size", "Block Size", "bytes per cluster")
    sector_size = _parse_fsstat_field(output, "Sector Size", "bytes per sector")
    fs_type = _parse_fsstat_field(output, "File System Type", "File system type")

    return {
        "status": "ok",
        "image_path": image_path,
        "resolved_path": resolved_image,
        "primary_offset": primary_offset,
        "filesystem_type": fs_type,
        "cluster_size": cluster_size,
        "sector_size": sector_size,
        "raw_fsstat": output,
    }


# =========================
# Disk metadata (GPT/MBR, GUIDs)
# =========================

def _default_get_disk_metadata(evidence_dir: str, image_path: Optional[str] = None) -> Dict[str, Any]:
    resolved_image = _resolve_host_path(evidence_dir, image_path) if image_path else None
    if not resolved_image:
        # Auto-detect first E01
        e01_result = _resolve_primary_image_and_offset(evidence_dir)
        resolved_image = e01_result[0]
        if not resolved_image:
            return {"status": "artifact_not_found", "image_path": image_path, "message": "No forensic image available."}

    result = run_cmd(["mmls", "-i", "ewf", resolved_image], timeout=120)
    output = (result.get("stdout") or "").strip()
    if result["returncode"] != 0 and not output:
        stderr = (result.get("stderr") or "").strip() or "mmls command failed"
        return {"status": "tool_error", "image_path": image_path, "message": stderr}

    # Determine partition scheme from header
    scheme = "unknown"
    disk_guid: Optional[str] = None
    gpt_header_slot: Optional[str] = None
    header_lines = output.splitlines()[:10]
    for line in header_lines:
        ll = line.lower()
        if "guid partition table" in ll or "gpt" in ll:
            scheme = "GPT"
        elif "dos partition table" in ll or "mbr" in ll:
            scheme = "MBR"

    # Find the GPT Header slot number from the mmls table (for GUID extraction)
    if scheme == "GPT":
        for line in output.splitlines():
            if "GPT Header" in line and ":" in line:
                slot_part = line.split(":")[0].strip()
                if slot_part.isdigit():
                    gpt_header_slot = slot_part
                    break

    # Extract disk GUID by hex-dumping the raw GPT header sector with od.
    # Using od avoids any dependency on python3 being present in the container's PATH.
    if scheme == "GPT" and gpt_header_slot:
        container_image = _to_container_path(resolved_image, evidence_dir)
        bash_cmd = (
            f"mmcat -i ewf {container_image} {gpt_header_slot} 2>/dev/null "
            f"| od -A n -v -t x1 | tr -dc '0-9a-fA-F'"
        )
        hex_result = run_cmd(["bash", "-c", bash_cmd], timeout=30)
        raw_hex = (hex_result.get("stdout") or "").strip()
        # GPT signature "EFI PART" = 4546492050415254 (8 bytes = 16 hex chars)
        # Disk GUID is at byte offset 56 (hex offset 112) and is 16 bytes (32 hex chars).
        if len(raw_hex) >= 144 and raw_hex[:16].upper() == "4546492050415254":
            try:
                import struct as _struct
                guid_bytes = bytes.fromhex(raw_hex[112:144])
                p1, p2, p3 = _struct.unpack_from("<IHH", guid_bytes, 0)
                p4 = guid_bytes[8:10].hex().upper()
                p5 = guid_bytes[10:16].hex().upper()
                disk_guid = f"{p1:08X}-{p2:04X}-{p3:04X}-{p4}-{p5}"
            except Exception:
                disk_guid = None

    # Parse partitions (reuse existing logic) and capture per-partition GUIDs
    partitions = []
    entry_regex = re.compile(r"^\d+:\s*(.+)$")
    for line in output.splitlines():
        stripped = line.strip()
        if not stripped or ":" not in stripped:
            continue
        right_side = stripped.split(":", 1)[1].strip()
        parts = right_side.split()
        if len(parts) < 5:
            continue
        slot, start_sector, end_sector, length_sector = parts[0], parts[1], parts[2], parts[3]
        description = " ".join(parts[4:])
        if not start_sector.isdigit() or not end_sector.isdigit() or not length_sector.isdigit():
            continue
        part_guid_match = re.search(r"\{?([0-9A-Fa-f]{8}[0-9A-Fa-f\-]{23,})\}?", description)
        part_guid = part_guid_match.group(1).upper().replace("-", "") if part_guid_match else None
        partitions.append({
            "slot": slot,
            "start_sector": int(start_sector),
            "end_sector": int(end_sector),
            "length_sectors": int(length_sector),
            "description": description,
            "guid": part_guid,
        })

    return {
        "status": "ok",
        "image_path": image_path,
        "resolved_path": resolved_image,
        "scheme": scheme,
        "disk_guid": disk_guid,
        "partition_count": len(partitions),
        "partitions": partitions,
        "raw_mmls": output,
    }


# =========================
# Registry query
# =========================

_HIVE_PATHS = {
    "sam": "Windows/System32/config/SAM",
    "system": "Windows/System32/config/SYSTEM",
    "software": "Windows/System32/config/SOFTWARE",
    "security": "Windows/System32/config/SECURITY",
}

_REGISTRY_QUERY_SCRIPT = r"""
import sys, json
from Registry import Registry

hive_path = sys.argv[1]
key_path = sys.argv[2] if len(sys.argv) > 2 else None

try:
    reg = Registry.Registry(hive_path)
    if key_path:
        key = reg.open(key_path)
        result = {"key": key_path, "values": {}}
        for v in key.values():
            try:
                result["values"][v.name()] = str(v.value())
            except Exception:
                result["values"][v.name()] = "<unreadable>"
        subkeys = [sk.name() for sk in key.subkeys()]
        result["subkeys"] = subkeys
    else:
        root = reg.root()
        result = {"root": root.name(), "subkeys": [sk.name() for sk in root.subkeys()]}
    print(json.dumps(result, ensure_ascii=False))
except Exception as e:
    print(json.dumps({"error": str(e)}))
"""


def _default_query_registry(
    evidence_dir: str,
    hive: str,
    key_path: Optional[str] = None,
    user: Optional[str] = None,
    image_path: Optional[str] = None,
) -> Dict[str, Any]:
    hive = (hive or "sam").lower()

    resolved_image, primary_offset, error = _resolve_image_and_offset(evidence_dir, image_path)
    if not resolved_image:
        return {"status": "artifact_not_found", "hive": hive, "message": error or "No forensic image available."}
    if not primary_offset:
        return {"status": "insufficient_index_data", "hive": hive, "message": error or "Primary partition offset unavailable."}

    # Determine hive path inside the image
    if hive == "ntuser":
        if not user:
            return {"status": "user_not_found", "hive": hive, "message": "User must be specified for NTUSER.DAT queries."}
        hive_image_path = f"Users/{user}/NTUSER.DAT"
    else:
        hive_image_path = _HIVE_PATHS.get(hive)
        if not hive_image_path:
            return {"status": "tool_error", "hive": hive, "message": f"Unknown hive '{hive}'. Supported: sam, system, software, security, ntuser."}

    inode = _find_inode_for_path(resolved_image, primary_offset, hive_image_path)
    if not inode:
        return {"status": "path_not_resolved", "hive": hive, "message": f"Hive '{hive_image_path}' not found in forensic image."}

    import time
    container_image = _to_container_path(resolved_image, evidence_dir)
    tmp_path = f"/tmp/hive_{hive}_{int(time.time())}"
    extract_cmd = f"icat -i ewf -o {primary_offset} {container_image} {inode} > {tmp_path}"
    extract_result = run_cmd(["bash", "-lc", extract_cmd], timeout=120)
    if extract_result["returncode"] != 0:
        stderr = (extract_result.get("stderr") or "").strip() or "icat extraction failed"
        return {"status": "tool_error", "hive": hive, "message": stderr}

    # Write the Python query script to a temp file and run it
    script_path = f"/tmp/regquery_{int(time.time())}.py"
    write_script_cmd = f"cat > {script_path} << 'PYEOF'\n{_REGISTRY_QUERY_SCRIPT.strip()}\nPYEOF"
    run_cmd(["bash", "-lc", write_script_cmd], timeout=30)

    key_arg = key_path or ""
    # Invoke python3 directly via docker exec to avoid PATH issues in bash login shells.
    parse_argv = ["python3", script_path, tmp_path]
    if key_arg:
        parse_argv.append(key_arg)
    parse_result = run_cmd(parse_argv, timeout=60)
    stdout = (parse_result.get("stdout") or "").strip()
    stderr = (parse_result.get("stderr") or "").strip()

    # Cleanup temp files
    run_cmd(["bash", "-lc", f"rm -f {tmp_path} {script_path}"], timeout=10)

    if not stdout:
        return {"status": "tool_error", "hive": hive, "message": stderr or "Registry parsing produced no output."}

    try:
        import json as _json
        parsed = _json.loads(stdout)
        if "error" in parsed:
            return {"status": "tool_error", "hive": hive, "key_path": key_path, "message": parsed["error"]}
        return {"status": "ok", "hive": hive, "key_path": key_path, "output": parsed}
    except Exception:
        return {"status": "ok", "hive": hive, "key_path": key_path, "output": stdout}


# =========================
# Event log query (evtx)
# =========================

_EVTX_PATHS = {
    "system": "Windows/System32/winevt/Logs/System.evtx",
    "application": "Windows/System32/winevt/Logs/Application.evtx",
    "security": "Windows/System32/winevt/Logs/Security.evtx",
}

_EVTX_PARSE_SCRIPT = """
import sys, json, re as _re
from xml.etree import ElementTree as ET

try:
    import Evtx.Evtx as evtx
except ImportError:
    print(json.dumps({"error": "python-evtx not installed"}))
    sys.exit(0)

log_path = sys.argv[1]
target_event_ids = [int(x) for x in sys.argv[2].split(",")] if sys.argv[2] else []
target_ts_str = sys.argv[3] if len(sys.argv) > 3 else ""
target_user = sys.argv[4].lower().strip() if len(sys.argv) > 4 and sys.argv[4].strip() else ""


def _parse_data_text(raw):
    raw = (raw or "").strip()
    if not raw:
        return ""
    try:
        inner = ET.fromstring("<root>" + raw + "</root>")
        parts = [c.text.strip() for c in inner if c.text and c.text.strip()]
        if parts:
            return " ".join(parts)
    except Exception:
        pass
    return _re.sub(r"<[^>]+>", " ", raw).strip()


results = []
try:
    with evtx.Evtx(log_path) as log:
        for record in log.records():
            try:
                xml_str = record.xml()
                root = ET.fromstring(xml_str)
                ns = {"w": "http://schemas.microsoft.com/win/2004/08/events/event"}
                system = root.find("w:System", ns)
                if system is None:
                    continue
                eid_el = system.find("w:EventID", ns)
                if eid_el is None:
                    continue
                eid = int(eid_el.text)
                if target_event_ids and eid not in target_event_ids:
                    continue
                time_el = system.find("w:TimeCreated", ns)
                ts_str = time_el.get("SystemTime", "") if time_el is not None else ""
                if target_ts_str and target_ts_str not in ts_str:
                    continue
                evt_data = root.find("w:EventData", ns)
                data_values = []
                data_named = {}
                if evt_data is not None:
                    for data_el in evt_data:
                        val = _parse_data_text(data_el.text)
                        name = data_el.get("Name")
                        if name:
                            data_named[name] = val
                        elif val:
                            data_values.append(val)
                if target_user:
                    all_vals = list(data_named.values()) + data_values
                    if not any(target_user in v.lower() for v in all_vals):
                        continue
                computer_el = system.find("w:Computer", ns)
                computer = computer_el.text if computer_el is not None else ""
                results.append({
                    "event_id": eid,
                    "timestamp": ts_str,
                    "computer": computer,
                    "data": data_values,
                    "data_named": data_named,
                })
            except Exception:
                pass
    print(json.dumps(results, ensure_ascii=False))
except Exception as e:
    print(json.dumps({"error": str(e)}))
"""


def _default_query_event_log(
    evidence_dir: str,
    log_name: str = "system",
    event_ids: Optional[List[int]] = None,
    timestamp: Optional[str] = None,
    image_path: Optional[str] = None,
    username: Optional[str] = None,
) -> Dict[str, Any]:
    resolved_image, primary_offset, error = _resolve_image_and_offset(evidence_dir, image_path)
    if not resolved_image:
        return {"status": "artifact_not_found", "log": log_name, "message": error or "No forensic image available."}
    if not primary_offset:
        return {"status": "insufficient_index_data", "log": log_name, "message": error or "Primary partition offset unavailable."}

    evtx_path = _EVTX_PATHS.get((log_name or "system").lower())
    if not evtx_path:
        return {"status": "tool_error", "log": log_name, "message": f"Unknown log '{log_name}'. Supported: system, application, security."}

    inode = _find_inode_for_path(resolved_image, primary_offset, evtx_path)
    if not inode:
        return {"status": "path_not_resolved", "log": log_name, "message": f"Event log '{evtx_path}' not found in forensic image."}

    import time
    container_image = _to_container_path(resolved_image, evidence_dir)
    tmp_evtx = f"/tmp/evtx_{log_name}_{int(time.time())}.evtx"
    script_path = f"/tmp/evtx_parse_{int(time.time())}.py"

    extract_cmd = f"icat -i ewf -o {primary_offset} {container_image} {inode} > {tmp_evtx}"
    extract_result = run_cmd(["bash", "-lc", extract_cmd], timeout=120)
    if extract_result["returncode"] != 0:
        return {"status": "tool_error", "log": log_name, "message": (extract_result.get("stderr") or "").strip() or "icat failed"}

    write_script_cmd = f"cat > {script_path} << 'PYEOF'\n{_EVTX_PARSE_SCRIPT.strip()}\nPYEOF"
    run_cmd(["bash", "-lc", write_script_cmd], timeout=30)

    event_ids_arg = ",".join(str(e) for e in (event_ids or []))
    ts_arg = (timestamp or "").strip()
    user_arg = (username or "").strip().replace("'", "")
    # Invoke python3 directly via docker exec to avoid PATH issues in bash login shells.
    parse_result = run_cmd(
        ["python3", script_path, tmp_evtx, event_ids_arg, ts_arg, user_arg],
        timeout=120,
    )
    stdout = (parse_result.get("stdout") or "").strip()

    run_cmd(["bash", "-lc", f"rm -f {tmp_evtx} {script_path}"], timeout=10)

    if not stdout:
        return {"status": "tool_error", "log": log_name, "message": (parse_result.get("stderr") or "").strip() or "No output from parser"}

    try:
        import json as _json
        parsed = _json.loads(stdout)
        if isinstance(parsed, dict) and "error" in parsed:
            return {"status": "tool_error", "log": log_name, "message": parsed["error"]}
        return {"status": "ok", "log": log_name, "event_ids": event_ids, "timestamp_filter": timestamp, "events": parsed}
    except Exception:
        return {"status": "ok", "log": log_name, "raw_output": stdout}


_LOGON_EVENT_IDS = [4624, 4647, 4634, 4648]

# System event log IDs used as fallback when Security log has no logon events.
# 6005 = EventLog service started (OS boot),  6006 = EventLog service stopped (clean shutdown)
# 6008 = unexpected shutdown,  6009 = OS version logged at boot
_BOOT_SHUTDOWN_EVENT_IDS = [6005, 6006, 6008, 6009]


def _build_timeline_result(
    events: list,
    user: Optional[str],
    timestamp: Optional[str],
    source: str,
) -> Dict[str, Any]:
    """Shared helper: extract dates and first/last from an event list."""
    events_sorted = sorted(events, key=lambda e: str(e.get("timestamp", "")))
    unique_dates: list = sorted({
        str(e.get("timestamp", ""))[:10]
        for e in events_sorted
        if len(str(e.get("timestamp", ""))) >= 10
    })
    return {
        "status": "ok",
        "source": source,
        "user": user,
        "timestamp_filter": timestamp,
        "first_event": events_sorted[0],
        "last_event": events_sorted[-1],
        "total_events": len(events),
        "unique_active_dates": unique_dates,
    }


def _default_query_timeline(
    evidence_dir: str,
    user: Optional[str] = None,
    timestamp: Optional[str] = None,
    image_path: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Multi-source timeline query:

    Layer 1 — Security event log (logon/logoff IDs 4624/4647/4634/4648).
              Best source: captures interactive and remote logons per user.
    Layer 2 — System event log (boot/shutdown IDs 6005/6006/6008/6009).
              Fallback: present even when auditing is disabled.
    Layer 3 — fls timestamp scan of the primary partition root.
              Last resort: works from filesystem metadata when no EVTX is available.

    The 'source' field in the result indicates which layer succeeded.
    """
    # --- Layer 1: Security log ---
    sec_result = _default_query_event_log(
        evidence_dir,
        log_name="security",
        event_ids=_LOGON_EVENT_IDS,
        timestamp=timestamp,
        username=user,
        image_path=image_path,
    )
    if sec_result.get("status") == "ok":
        events = sec_result.get("events") or []
        if events:
            return _build_timeline_result(events, user, timestamp, source="security_event_log")

    # Collect the error context from Layer 1 so we can report it if all layers fail.
    layer1_status = sec_result.get("status", "tool_error")
    layer1_msg = sec_result.get("message", "")

    # --- Layer 2: System log (boot/shutdown events) ---
    sys_result = _default_query_event_log(
        evidence_dir,
        log_name="system",
        event_ids=_BOOT_SHUTDOWN_EVENT_IDS,
        timestamp=timestamp,
        username=None,   # boot events have no user field
        image_path=image_path,
    )
    if sys_result.get("status") == "ok":
        events = sys_result.get("events") or []
        if events:
            return _build_timeline_result(events, user, timestamp, source="system_event_log")

    # --- Layer 3: fls timestamp scan ---
    resolved_image, primary_offset, err = _resolve_image_and_offset(evidence_dir, image_path)
    if resolved_image and primary_offset:
        fls_result = run_cmd(
            ["fls", "-r", "-m", "/", "-i", "ewf", "-o", primary_offset, resolved_image],
            timeout=360,
        )
        fls_out = (fls_result.get("stdout") or "").strip()
        # mactime body file: col 9 is mtime Unix timestamp.  Collect unique YYYY-MM-DD.
        dates_from_fls: set = set()
        import time as _time
        for line in fls_out.splitlines():
            parts = line.split("|")
            if len(parts) < 11:
                continue
            try:
                mtime = int(parts[8])
                if mtime > 0:
                    dates_from_fls.add(
                        _time.strftime("%Y-%m-%d", _time.gmtime(mtime))
                    )
            except (ValueError, IndexError):
                continue
        if dates_from_fls:
            sorted_dates = sorted(dates_from_fls)
            first_date = sorted_dates[0]
            last_date = sorted_dates[-1]
            return {
                "status": "ok",
                "source": "filesystem_timestamps",
                "user": user,
                "timestamp_filter": timestamp,
                "first_event": {"timestamp": first_date, "source": "fls_mtime"},
                "last_event": {"timestamp": last_date, "source": "fls_mtime"},
                "total_events": len(dates_from_fls),
                "unique_active_dates": sorted_dates,
            }

    # All layers exhausted.
    who = f"user '{user}'" if user else "any user"
    when = f" on {timestamp}" if timestamp else ""
    return {
        "status": "artifact_not_found",
        "user": user,
        "timestamp_filter": timestamp,
        "message": (
            f"No timeline events found for {who}{when}. "
            f"Security log status: {layer1_status} ({layer1_msg}). "
            "System log and filesystem timestamps also yielded no data."
        ),
    }


# Reads from the file path given in sys.argv[1] so it can be invoked directly
# via docker exec (run_cmd(["python3", script_path, temp_file])) rather than
# via a bash pipe, which fails when python3 is not on the container's login PATH.
_OEACCOUNT_PARSE_SCRIPT = (
    'import sys,re,json;'
    'src=open(sys.argv[1],"rb").read() if len(sys.argv)>1 else sys.stdin.buffer.read();'
    r'text=src.decode("utf-16",errors="ignore") if src[:2] in (b"\xff\xfe",b"\xfe\xff") else src.decode("utf-8",errors="ignore");'
    r'acct=re.search(r"<Account_Name[^>]*>([^<]+)</Account_Name>",text);'
    r'imap=re.search(r"<IMAP_User_Name[^>]*>([^<]+)</IMAP_User_Name>",text);'
    r'smtp=re.search(r"<SMTP_Email_Address[^>]*>([^<]+)</SMTP_Email_Address>",text);'
    'print(json.dumps({"account":acct.group(1).strip() if acct else None,"email":smtp.group(1).strip() if smtp else (imap.group(1).strip() if imap else None)}))'
)

# Email artifact suffixes to search for in the forensic image listing.
_EMAIL_ARTIFACT_SUFFIXES = (".oeaccount", ".pst", ".ost", ".eml", ".nws", ".dbx", ".mbox")

# Thunderbird profile marker files / directories used to detect TB installations.
_THUNDERBIRD_MARKERS = ("prefs.js", "localfolders", "imap.sbd", "smtp")

# Maximum number of lines to scan of a Thunderbird INBOX to count messages.
_MBOX_SCAN_LIMIT = 50_000


def _count_mbox_messages(evidence_dir: str, container_image: str, offset: str, inode: str) -> int:
    """
    Count messages in a Unix mbox file (Thunderbird INBOX / Sent / Drafts).
    Each message starts with a 'From ' line at the start of a line.
    Uses `icat` to stream the file and counts those lines in the container.
    Returns the count, or 0 on failure.
    """
    import time as _time
    tmp = f"/tmp/mbox_{inode}_{int(_time.time())}"
    extract_cmd = f"icat -i ewf -o {offset} {container_image} {inode} > {tmp}"
    run_cmd(["bash", "-c", extract_cmd], timeout=60)

    # Count lines matching '^From ' using grep -c (POSIX, always present in container).
    count_result = run_cmd(["bash", "-c", f"grep -c '^From ' {tmp} 2>/dev/null || echo 0"], timeout=30)
    run_cmd(["bash", "-c", f"rm -f {tmp}"], timeout=10)

    raw = (count_result.get("stdout") or "0").strip()
    try:
        return int(raw.split()[0])
    except (ValueError, IndexError):
        return 0


def _default_get_email_accounts(
    evidence_dir: str,
    user: Optional[str] = None,
    image_path: Optional[str] = None,
    query_type: str = "accounts",
) -> Dict[str, Any]:
    """
    Search the forensic image for email artifacts across multiple email clients.

    query_type:
      "accounts" (default) — focus on account/configuration discovery.
      "count"              — focus on message counts per mailbox.

    Clients supported:
      - Windows Live Mail  : *.oeaccount (parse for email address)
      - Outlook            : *.pst / *.ost (path + size)
      - Individual messages: *.eml / *.nws (count)
      - Outlook Express    : *.dbx (path + size)
      - Thunderbird        : prefs.js (detects presence); INBOX-style mbox files (count)
      - Generic mbox       : *.mbox (count via 'From ' lines)

    Always returns all found artifact types; the caller (LLM responder) decides
    how to present them based on query_type.
    """
    img, offset, error = _resolve_image_and_offset(evidence_dir, image_path)
    if not img:
        return {"status": "artifact_not_found", "message": error or "No forensic image available."}
    if not offset:
        return {"status": "insufficient_index_data", "message": error or "Primary partition offset unavailable."}

    container_image = _to_container_path(img, evidence_dir)

    # Bug fix: add -p so tab_parts[1] contains the full path (e.g.
    # /Users/Jimmy/AppData/Roaming/Thunderbird/Profiles/xxx/INBOX) rather than
    # just the bare filename.  Without -p, "thunderbird" never appears in the
    # line and all TB-profile detection fails.  Also, suffix matching must be
    # done on the FILENAME portion (tab_parts[1] basename), NOT on the end of
    # the whole tab-separated line (which ends with uid/gid numbers, not
    # the extension).
    fls_result = run_cmd(["fls", "-r", "-l", "-p", "-i", "ewf", "-o", str(offset), container_image])
    fls_out = (fls_result.get("stdout") or "").strip()
    if not fls_out:
        return {"status": "tool_error", "message": "fls returned no output."}

    user_tokens = [t for t in (user or "").lower().split() if len(t) > 2]

    accounts: List[Dict[str, Any]] = []       # Windows Live Mail parsed accounts
    outlook_files: List[Dict[str, Any]] = []  # PST / OST artifacts
    dbx_files: List[Dict[str, Any]] = []      # Outlook Express DBX files
    eml_count = 0
    eml_paths: List[str] = []                 # up to 20 .eml paths (for read_file_content follow-ups)
    mbox_entries: List[Dict[str, Any]] = []   # Thunderbird / generic mbox
    thunderbird_profiles: List[str] = []      # Thunderbird profile paths

    import time as _time
    script_path = f"/tmp/oeacct_parse_{int(_time.time())}.py"
    script_written = False

    # ---- Single-pass scan over fls -l -p output ----
    # fls -l -p line format (tab-separated):
    #   <type> <inode>:\t<full-path>\t<mtime>\t<atime>\t<ctime>\t<crtime>\t<size>\t<uid>\t<gid>
    for line in fls_out.splitlines():
        tab_parts = line.split("\t")
        if len(tab_parts) < 2:
            continue
        path_token = tab_parts[1].strip()
        if not path_token:
            continue
        path_lower = path_token.lower()
        # Filename is the last path component.
        name = path_token.split("/")[-1] if "/" in path_token else path_token
        name_lower = name.lower()

        # ------ Thunderbird prefs.js (profile detector) ------
        # With -p, lines for TB prefs.js look like:
        #   r/r 1234-128-3:  /Users/Jimmy/.../Thunderbird/Profiles/xxx.default/prefs.js  ...
        if "thunderbird" in path_lower and name_lower == "prefs.js":
            profile_dir = "/".join(path_token.rstrip("/").split("/")[:-1])
            if profile_dir and profile_dir not in thunderbird_profiles:
                thunderbird_profiles.append(profile_dir)
            continue

        # ------ Thunderbird mbox folders (extensionless files inside TB profile) ------
        # INBOX, Sent, Drafts, Trash, etc. are extensionless mbox files.
        # Only match files that are BOTH inside a Thunderbird profile directory AND
        # have no file extension.  Files WITH an extension (e.g. .eml) inside a
        # Thunderbird folder fall through to the suffix-based checks below.
        if "thunderbird" in path_lower and "profiles" in path_lower and "." not in name:
            m = re.search(r"r/r\s+(\d+)-", line)
            if m:
                size = int(tab_parts[6].strip()) if len(tab_parts) >= 7 and tab_parts[6].strip().isdigit() else 0
                if size > 512 and (
                    query_type == "count"
                    or not user_tokens
                    or any(tok in path_lower for tok in user_tokens)
                ):
                    msg_count = _count_mbox_messages(evidence_dir, container_image, offset, m.group(1))
                    if msg_count > 0:
                        mbox_entries.append({
                            "type": "thunderbird_mbox",
                            "path": path_token,
                            "size_bytes": size,
                            "message_count": msg_count,
                        })
            continue  # extensionless TB-profile file: done, skip suffix processing

        # Suffix-based matching — checked against the FILENAME only (name_lower),
        # not the full line, because fls -l lines end with timestamps/uid/gid.
        if not any(name_lower.endswith(sfx) for sfx in _EMAIL_ARTIFACT_SUFFIXES):
            continue

        # ------ individual email messages (.eml / .nws) ------
        if name_lower.endswith(".eml") or name_lower.endswith(".nws"):
            if not user_tokens or any(tok in path_lower for tok in user_tokens):
                eml_count += 1
                if len(eml_paths) < 20:
                    eml_paths.append(path_token)
            continue

        # ------ Outlook data files (.pst / .ost) ------
        if name_lower.endswith(".pst") or name_lower.endswith(".ost"):
            size_token = tab_parts[6].strip() if len(tab_parts) >= 7 and tab_parts[6].strip().isdigit() else ""
            ext = ".pst" if name_lower.endswith(".pst") else ".ost"
            entry: Dict[str, Any] = {"type": "outlook", "format": ext, "path": path_token}
            if size_token:
                entry["size_bytes"] = int(size_token)
            if user_tokens and not any(tok in path_lower for tok in user_tokens):
                continue
            outlook_files.append(entry)
            continue

        # ------ Outlook Express (.dbx) ------
        if name_lower.endswith(".dbx"):
            size_token = tab_parts[6].strip() if len(tab_parts) >= 7 and tab_parts[6].strip().isdigit() else ""
            entry = {"type": "outlook_express", "format": ".dbx", "path": path_token}
            if size_token:
                entry["size_bytes"] = int(size_token)
            if user_tokens and not any(tok in path_lower for tok in user_tokens):
                continue
            dbx_files.append(entry)
            continue

        # ------ Generic mbox files (.mbox) ------
        if name_lower.endswith(".mbox"):
            m = re.search(r"r/r\s+(\d+)-", line)
            if m:
                size_token = tab_parts[6].strip() if len(tab_parts) >= 7 and tab_parts[6].strip().isdigit() else ""
                size = int(size_token) if size_token.isdigit() else 0
                if user_tokens and not any(tok in path_lower for tok in user_tokens):
                    continue
                msg_count = _count_mbox_messages(evidence_dir, container_image, offset, m.group(1)) if size > 512 else 0
                mbox_entries.append({
                    "type": "mbox",
                    "format": ".mbox",
                    "path": path_token,
                    "size_bytes": size,
                    "message_count": msg_count,
                })
            continue

        # ------ Windows Live Mail (.oeaccount) ------
        if not name_lower.endswith(".oeaccount"):
            continue
        m = re.search(r"r/r\s+(\d+)-", line)
        if not m:
            continue
        inode = m.group(1)

        if not script_written:
            write_cmd = f"cat > {script_path} << 'PYEOF'\n{_OEACCOUNT_PARSE_SCRIPT.strip()}\nPYEOF"
            run_cmd(["bash", "-lc", write_cmd], timeout=30)
            script_written = True

        tmp_acct = f"/tmp/oeacct_{inode}_{int(_time.time())}"
        extract_cmd = f"icat -i ewf -o {offset} {container_image} {inode} > {tmp_acct}"
        run_cmd(["bash", "-c", extract_cmd], timeout=30)
        out_result = run_cmd(["python3", script_path, tmp_acct], timeout=30)
        run_cmd(["bash", "-c", f"rm -f {tmp_acct}"], timeout=10)

        raw_out = (out_result.get("stdout") or "").strip()
        if not raw_out:
            continue
        try:
            import json as _json
            parsed = _json.loads(raw_out)
            if not parsed.get("email"):
                continue
            if user_tokens:
                acct_lower = (parsed.get("account") or "").lower() + " " + (parsed.get("email") or "").lower()
                if not any(tok in acct_lower for tok in user_tokens):
                    continue
            accounts.append({"type": "windows_live_mail", **parsed})
        except Exception:
            pass

    if script_written:
        run_cmd(["bash", "-c", f"rm -f {script_path}"], timeout=10)

    total_message_count = (
        eml_count
        + sum(e.get("message_count", 0) for e in mbox_entries)
    )
    has_any = bool(accounts or outlook_files or dbx_files or eml_count or mbox_entries or thunderbird_profiles)

    if not has_any:
        return {
            "status": "artifact_not_found",
            "query_type": query_type,
            "message": (
                "No email artifacts (.oeaccount, .pst, .ost, .eml, .dbx, .mbox, Thunderbird) found"
                + (f" for user '{user}'" if user else "") + "."
            ),
        }

    return {
        "status": "ok",
        "query_type": query_type,
        "thunderbird_profiles": thunderbird_profiles,
        "thunderbird_mbox_folders": mbox_entries,
        "windows_live_mail_accounts": accounts,
        "wlm_count": len(accounts),
        "outlook_files": outlook_files,
        "outlook_count": len(outlook_files),
        "dbx_files": dbx_files,
        "dbx_count": len(dbx_files),
        "eml_message_count": eml_count,
        # eml_paths: up to 20 paths the user can paste into a read_file_content query.
        "eml_paths": eml_paths,
        "generic_mbox_files": [e for e in mbox_entries if e.get("type") == "mbox"],
        "total_message_count": total_message_count,
        "total_artifacts": len(accounts) + len(outlook_files) + len(dbx_files) + eml_count + len(mbox_entries),
    }


def create_default_server(
    *,
    evidence_dir: str,
    classify_question: ToolHandler,
    get_current_image: Optional[ToolHandler] = None,
    get_case_context: Optional[ToolHandler] = None,
    get_prompt_template: Optional[ToolHandler] = None,
    query_evidence: Optional[ToolHandler] = None,
    stat_path: Optional[ToolHandler] = None,
    list_directory: Optional[ToolHandler] = None,
    inspect_image_partitions: Optional[ToolHandler] = None,
    list_users: Optional[ToolHandler] = None,
    list_primary_partition_root: Optional[ToolHandler] = None,
    resolve_user_profile: Optional[ToolHandler] = None,
    get_special_folder: Optional[ToolHandler] = None,
    list_user_directory: Optional[ToolHandler] = None,
) -> LocalMCPServer:
    server = LocalMCPServer()
    server.register_tool("classify_question", classify_question)
    server.register_tool(
        "get_current_image", get_current_image or (lambda: _default_get_current_image(evidence_dir))
    )
    server.register_tool(
        "get_case_context", get_case_context or (lambda: _default_get_case_context(evidence_dir))
    )
    server.register_tool(
        "get_prompt_template", get_prompt_template or _default_get_prompt_template
    )
    server.register_tool(
        "query_evidence", query_evidence or (lambda question: _default_query_evidence(evidence_dir, question))
    )
    server.register_tool(
        "stat_path", stat_path or (lambda path: _default_stat_path(evidence_dir, path))
    )
    server.register_tool(
        "list_directory",
        list_directory
        or (
            lambda path, recursive=False, include_dirs=True: _default_list_directory(
                evidence_dir,
                path,
                bool(recursive),
                bool(include_dirs),
            )
        ),
    )
    server.register_tool(
        "inspect_image_partitions",
        inspect_image_partitions
        or (lambda image_path: _default_inspect_image_partitions(evidence_dir, image_path)),
    )
    server.register_tool(
        "list_users",
        list_users or (lambda image_path=None: _default_list_users(evidence_dir, image_path)),
    )
    server.register_tool(
        "list_primary_partition_root",
        list_primary_partition_root
        or (lambda image_path=None: _default_list_primary_partition_root(evidence_dir, image_path)),
    )
    server.register_tool(
        "resolve_user_profile",
        resolve_user_profile or (lambda user, image_path=None: _default_resolve_user_profile(evidence_dir, user, image_path)),
    )
    server.register_tool(
        "get_special_folder",
        get_special_folder
        or (lambda user, folder_name, image_path=None: _default_get_special_folder(evidence_dir, user, folder_name, image_path)),
    )
    server.register_tool(
        "list_user_directory",
        list_user_directory
        or (
            lambda user, folder_name, include_dirs=True, recursive=False, image_path=None: _default_list_user_directory(
                evidence_dir,
                user,
                folder_name,
                bool(include_dirs),
                bool(recursive),
                image_path,
            )
        ),
    )
    server.register_tool(
        "get_file_hash",
        lambda file_path, algorithm="md5": _default_get_file_hash(evidence_dir, file_path, algorithm),
    )
    server.register_tool(
        "get_file_size",
        lambda file_path: _default_get_file_size(evidence_dir, file_path),
    )
    server.register_tool(
        "find_file_by_name",
        lambda filename: _default_find_file_by_name(evidence_dir, filename),
    )
    server.register_tool(
        "extract_file_content",
        lambda file_path, max_bytes=8192: _default_extract_file_content(evidence_dir, file_path, max_bytes),
    )
    server.register_tool(
        "get_filesystem_stats",
        lambda image_path=None, partition_index=None: _default_get_filesystem_stats(
            evidence_dir, image_path, partition_index=partition_index
        ),
    )
    server.register_tool(
        "get_disk_metadata",
        lambda image_path=None: _default_get_disk_metadata(evidence_dir, image_path),
    )
    server.register_tool(
        "query_registry",
        lambda hive, key_path=None, user=None, image_path=None: _default_query_registry(
            evidence_dir, hive, key_path, user, image_path
        ),
    )
    server.register_tool(
        "query_event_log",
        lambda log_name="system", event_ids=None, timestamp=None, image_path=None, username=None: _default_query_event_log(
            evidence_dir, log_name, event_ids, timestamp, image_path, username
        ),
    )
    server.register_tool(
        "query_timeline",
        lambda user=None, timestamp=None, image_path=None: _default_query_timeline(
            evidence_dir, user, timestamp, image_path
        ),
    )
    server.register_tool(
        "get_email_accounts",
        lambda user=None, image_path=None, query_type="accounts": _default_get_email_accounts(
            evidence_dir, user, image_path, query_type
        ),
    )
    return server
