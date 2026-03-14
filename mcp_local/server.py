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


def _default_get_file_size(evidence_dir: str, file_path: str) -> Dict[str, Any]:
    if not file_path:
        return {"status": "path_not_resolved", "file_path": file_path, "message": "File path was not provided."}

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

    target_lower = file_path.strip().lstrip("/").lower()
    for line in output.splitlines():
        if target_lower not in line.lower():
            continue
        # fls -l output is tab-separated:
        # r/r <inode>:\t<path>\t<mtime>\t<atime>\t<ctime>\t<crtime>\t<size>\t<uid>\t<gid>
        tab_parts = line.split("\t")
        if len(tab_parts) >= 7:
            size_field = tab_parts[6].strip()
            if size_field.isdigit():
                return {
                    "status": "ok",
                    "file_path": file_path,
                    "size_bytes": int(size_field),
                    "raw_line": line.strip(),
                }
        # Fallback: last purely-numeric token (guards against timestamps like "2015-05-26")
        tokens = line.split()
        numeric = [p for p in tokens if p.isdigit() and len(p) <= 12]
        if numeric:
            return {
                "status": "ok",
                "file_path": file_path,
                "size_bytes": int(numeric[-1]),
                "raw_line": line.strip(),
            }

    return {"status": "path_not_resolved", "file_path": file_path, "message": f"File '{file_path}' not found in forensic image listing."}


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
    return {
        "status": "ok",
        "file_path": file_path,
        "inode": inode,
        "content": content[:max_bytes],
        "truncated": truncated,
    }


# =========================
# Filesystem stats
# =========================

def _default_get_filesystem_stats(evidence_dir: str, image_path: Optional[str] = None) -> Dict[str, Any]:
    resolved_image, primary_offset, error = _resolve_image_and_offset(evidence_dir, image_path)
    if not resolved_image:
        return {"status": "artifact_not_found", "image_path": image_path, "message": error or "No forensic image available."}
    if not primary_offset:
        return {"status": "insufficient_index_data", "image_path": image_path, "message": error or "Primary partition offset unavailable."}

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

    # Extract disk GUID by reading the raw GPT header sector via mmcat | python3
    if scheme == "GPT" and gpt_header_slot:
        container_image = _to_container_path(resolved_image, evidence_dir)
        py_script = (
            "import sys,struct;"
            "data=sys.stdin.buffer.read();"
            "r=data[56:72] if data[:8]==b'EFI PART' else b'';"
            "p1,p2,p3=struct.unpack_from('<IHH',r) if len(r)==16 else (0,0,0);"
            "p4=r[8:10].hex().upper() if len(r)==16 else '';"
            "p5=r[10:16].hex().upper() if len(r)==16 else '';"
            "print('%08X-%04X-%04X-%s-%s'%(p1,p2,p3,p4,p5)) if len(r)==16 else None"
        )
        bash_cmd = f"mmcat -i ewf {container_image} {gpt_header_slot} | python3 -c \"{py_script}\""
        guid_result = run_cmd(["bash", "-c", bash_cmd], timeout=30)
        raw_guid = (guid_result.get("stdout") or "").strip()
        if guid_result["returncode"] == 0 and re.match(
            r"[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}", raw_guid
        ):
            disk_guid = raw_guid

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
    parse_cmd = f"python3 {script_path} {tmp_path} {key_arg}" if key_arg else f"python3 {script_path} {tmp_path}"
    parse_result = run_cmd(["bash", "-lc", parse_cmd], timeout=60)
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
import sys, json
from xml.etree import ElementTree as ET
from datetime import datetime, timezone

try:
    import Evtx.Evtx as evtx
except ImportError:
    print(json.dumps({"error": "python-evtx not installed"}))
    sys.exit(0)

log_path = sys.argv[1]
target_event_ids = [int(x) for x in sys.argv[2].split(",")] if sys.argv[2] else []
target_ts_str = sys.argv[3] if len(sys.argv) > 3 else ""

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
                # Filter by timestamp prefix if requested
                if target_ts_str and target_ts_str not in ts_str:
                    continue
                # Extract EventData strings
                evt_data = root.find("w:EventData", ns)
                data_values = []
                if evt_data is not None:
                    import re as _re
                    for data_el in evt_data:
                        raw = (data_el.text or "").strip()
                        if not raw:
                            continue
                        # python-evtx returns inner XML fragments like <string>9634</string>
                        # Try to parse them; fall back to stripping tags with regex
                        try:
                            inner = ET.fromstring(f"<root>{raw}</root>")
                            parts = [child.text.strip() for child in inner if child.text and child.text.strip()]
                            if parts:
                                data_values.extend(parts)
                                continue
                        except Exception:
                            pass
                        # Fallback: strip any XML tags with regex
                        cleaned = _re.sub(r"<[^>]+>", " ", raw).strip()
                        if cleaned:
                            data_values.append(cleaned)
                computer_el = system.find("w:Computer", ns)
                computer = computer_el.text if computer_el is not None else ""
                results.append({
                    "event_id": eid,
                    "timestamp": ts_str,
                    "computer": computer,
                    "data": data_values,
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
    parse_cmd = f"python3 {script_path} {tmp_evtx} '{event_ids_arg}' '{ts_arg}'"
    parse_result = run_cmd(["bash", "-lc", parse_cmd], timeout=120)
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
        "extract_file_content",
        lambda file_path, max_bytes=8192: _default_extract_file_content(evidence_dir, file_path, max_bytes),
    )
    server.register_tool(
        "get_filesystem_stats",
        lambda image_path=None: _default_get_filesystem_stats(evidence_dir, image_path),
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
        lambda log_name="system", event_ids=None, timestamp=None, image_path=None: _default_query_event_log(
            evidence_dir, log_name, event_ids, timestamp, image_path
        ),
    )
    return server
