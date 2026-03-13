from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

from tools.runner import run_cmd


ToolHandler = Callable[..., Any]


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
    return server
