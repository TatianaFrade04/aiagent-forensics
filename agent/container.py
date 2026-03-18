"""
Centralised Docker container lifecycle manager.

Provides ``get_or_create()`` / ``ensure_running()`` so that every ``docker exec``
in the codebase is preceded by a reliable state check.  Handles:

- container created but main process exited immediately
- exec called on a stopped / dead container
- stale container ID from a previous session
- race between create → start → exec
- automatic restart or full recreate when the container is not running
"""
from __future__ import annotations

import logging
import os
import subprocess
import threading
import time
from dataclasses import dataclass
from enum import Enum
from typing import Optional

log = logging.getLogger("forensics.container")

# ---------------------------------------------------------------------------
# Config — single source of truth
# ---------------------------------------------------------------------------

DOCKER_IMAGE: str = os.getenv("FORENSICS_IMAGE") or "forensics"
DOCKER_CONTAINER: str = os.getenv("FORENSICS_CONTAINER") or "forensics"
EVIDENCE_DIR: str = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "evidence"
)

# ---------------------------------------------------------------------------
# Error types
# ---------------------------------------------------------------------------


class ContainerStatus(Enum):
    RUNNING = "running"
    STOPPED = "exited"
    DEAD = "dead"
    CREATED = "created"
    MISSING = "missing"
    DAEMON_DOWN = "daemon_down"


@dataclass
class ContainerError(Exception):
    """Structured error carrying diagnostics."""
    status: ContainerStatus
    detail: str

    def __str__(self) -> str:
        return f"[container:{self.status.value}] {self.detail}"


# ---------------------------------------------------------------------------
# Manager
# ---------------------------------------------------------------------------


class ContainerManager:
    """Thread-safe singleton-style manager for the forensics container."""

    def __init__(
        self,
        container_name: str = DOCKER_CONTAINER,
        image_name: str = DOCKER_IMAGE,
        evidence_dir: str = EVIDENCE_DIR,
    ) -> None:
        self.container_name = container_name
        self.image_name = image_name
        self.evidence_dir = evidence_dir
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def ensure_running(self) -> None:
        """Guarantee the container is running *right now*.

        Called before every ``docker exec``.  Fast-path: a single
        ``docker inspect`` round-trip (~20 ms).  Slow-path: restart or
        full recreate (<2 s typically).
        """
        with self._lock:
            status = self._inspect_status()

            if status == ContainerStatus.RUNNING:
                return

            if status == ContainerStatus.DAEMON_DOWN:
                raise ContainerError(
                    status=ContainerStatus.DAEMON_DOWN,
                    detail=(
                        "Docker daemon is not reachable. "
                        "Please start Docker Desktop and try again."
                    ),
                )

            if status in (ContainerStatus.STOPPED, ContainerStatus.DEAD, ContainerStatus.CREATED):
                log.warning(
                    "Container '%s' exists but is %s — attempting restart.",
                    self.container_name,
                    status.value,
                )
                if self._try_start():
                    return
                # Start failed — fall through to full recreate.
                log.warning("Restart failed; will recreate container.")

            # MISSING or restart-failed → full recreate
            self._recreate()

    def get_exec_prefix(self) -> list[str]:
        """Return the ``docker exec <name>`` argv prefix.

        Callers append their own command after this list.
        """
        return ["docker", "exec", self.container_name]

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _inspect_status(self) -> ContainerStatus:
        """Lightweight status probe via ``docker inspect``."""
        try:
            result = subprocess.run(
                [
                    "docker", "inspect",
                    "-f", "{{.State.Status}}",
                    self.container_name,
                ],
                capture_output=True,
                text=True,
                timeout=10,
            )
        except FileNotFoundError:
            return ContainerStatus.DAEMON_DOWN
        except subprocess.TimeoutExpired:
            return ContainerStatus.DAEMON_DOWN

        if result.returncode != 0:
            stderr = (result.stderr or "").lower()
            if "no such object" in stderr or "not found" in stderr:
                log.info("Container '%s' does not exist.", self.container_name)
                return ContainerStatus.MISSING
            if "cannot connect" in stderr or "pipe" in stderr or "daemon" in stderr:
                return ContainerStatus.DAEMON_DOWN
            # Unknown inspect failure — treat as missing to trigger recreate.
            log.warning(
                "docker inspect failed unexpectedly: %s", result.stderr.strip()
            )
            return ContainerStatus.MISSING

        raw = result.stdout.strip().lower()
        if raw == "running":
            return ContainerStatus.RUNNING
        if raw == "exited":
            return ContainerStatus.STOPPED
        if raw == "dead":
            return ContainerStatus.DEAD
        if raw == "created":
            return ContainerStatus.CREATED
        log.warning("Unknown container status: %s", raw)
        return ContainerStatus.STOPPED  # conservative fallback

    def _try_start(self) -> bool:
        """Try ``docker start`` on an existing-but-stopped container."""
        result = subprocess.run(
            ["docker", "start", self.container_name],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode != 0:
            log.warning("docker start failed: %s", result.stderr.strip())
            return False

        # Brief settle time, then verify
        time.sleep(0.3)
        return self._inspect_status() == ContainerStatus.RUNNING

    def _recreate(self) -> None:
        """Remove any leftover container and create a fresh one."""
        log.info(
            "Recreating container '%s' from image '%s'.",
            self.container_name,
            self.image_name,
        )

        # Remove old container (ignore errors if it doesn't exist)
        subprocess.run(
            ["docker", "rm", "-f", self.container_name],
            capture_output=True,
            text=True,
            timeout=15,
        )

        result = subprocess.run(
            [
                "docker", "run", "-d",
                "--name", self.container_name,
                "--network", "none",
                "-v", f"{self.evidence_dir}:/evidence:ro",
                self.image_name,
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )

        if result.returncode != 0:
            raise ContainerError(
                status=ContainerStatus.MISSING,
                detail=f"Failed to create container: {result.stderr.strip()}",
            )

        # Verify it actually started
        time.sleep(0.3)
        status = self._inspect_status()
        if status != ContainerStatus.RUNNING:
            raise ContainerError(
                status=status,
                detail=(
                    f"Container was created but is '{status.value}' instead of "
                    f"'running'. Check 'docker logs {self.container_name}' for details."
                ),
            )

        log.info("Container '%s' is running.", self.container_name)


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_manager: Optional[ContainerManager] = None
_manager_lock = threading.Lock()


def get_manager() -> ContainerManager:
    """Return (or create) the module-level ContainerManager singleton."""
    global _manager
    if _manager is None:
        with _manager_lock:
            if _manager is None:
                _manager = ContainerManager()
    return _manager
