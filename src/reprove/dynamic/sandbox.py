"""Sandbox: boot an app from a repo, in isolation, on an ephemeral port.

MVP uses a process sandbox with its own process group and a throwaway port;
Docker-based isolation (network-none, read-only FS) is a later milestone —
the interface (`start` / `base_url` / `stop`) stays identical so nothing
downstream changes.

Safety: this boots *the user's own code* locally. Only point reprove at
repositories you own or are authorized to test.
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from ..util import HttpClient, free_port, run_process, wait_for_http

HEALTH_PATHS = ("/healthz", "/health", "/api/health", "/api/healthz", "/")


@dataclass
class RunningApp:
    base_url: str
    port: int
    command: list[str]
    log_path: Optional[Path]

    def stop(self):
        """Handled by the context manager; present for API symmetry."""


def detect_start_command(repo: Path) -> Optional[list[str]]:
    """Best-effort start command for common vibe-coded stacks."""
    pkg = repo / "package.json"
    if pkg.exists():
        try:
            data = json.loads(pkg.read_text(encoding="utf-8", errors="replace"))
        except Exception:
            data = {}
        scripts = data.get("scripts") or {}
        for key in ("start", "dev"):
            if key in scripts and isinstance(scripts[key], str):
                # npm run dev often needs node_modules; prefer plain node entry when present
                if (repo / "node_modules").exists():
                    return ["npm", "run", key, "--silent"]
        for entry in ("server.js", "index.js", "app.js", "main.js", "src/server.js", "src/index.js"):
            if (repo / entry).exists():
                return ["node", entry]
    for entry, cmd in (("main.py", ["python3", "main.py"]), ("app.py", ["python3", "app.py"])):
        if (repo / entry).exists():
            return cmd
    return None


class AppSandbox:
    """Context manager: boots the repo's app on a free port; always tears it down."""

    def __init__(self, repo: Path, command: Optional[list[str]] = None, boot_timeout: float = 15.0):
        self.repo = repo
        self.command = command or detect_start_command(repo)
        self.boot_timeout = boot_timeout
        self.base_url = ""
        self.port = 0
        self._ctx = None
        self._proc = None
        self.log_path: Optional[Path] = None
        self.error: Optional[str] = None

    def __enter__(self) -> "AppSandbox":
        if not self.command:
            self.error = "no start command detected"
            return self
        self.port = free_port()
        self.base_url = f"http://127.0.0.1:{self.port}"
        self.log_path = self.repo / ".reprove-sandbox.log"
        env = {
            "PORT": str(self.port),
            "NODE_ENV": "production",
            # keep anything the app might need neutral; app secrets come from its own config
        }
        self._ctx = run_process(self.command, cwd=self.repo, env=env, log_path=self.log_path)
        self._proc = self._ctx.__enter__()

        http = HttpClient(timeout=2.0)
        deadline = time.time() + self.boot_timeout
        healthy = False
        while time.time() < deadline:
            if self._proc.poll() is not None:
                self.error = f"process exited early (code {self._proc.returncode}); see {self.log_path.name}"
                break
            for path in HEALTH_PATHS:
                r = http.request("GET", self.base_url + path)
                if r.status and r.status < 500:
                    healthy = True
                    break
            if healthy:
                break
            time.sleep(0.3)
        if not healthy and not self.error:
            self.error = f"app did not become healthy within {self.boot_timeout}s; see {self.log_path.name if self.log_path else 'logs'}"
        return self

    @property
    def healthy(self) -> bool:
        return not self.error

    def stop(self):
        if self._ctx is not None:
            self._ctx.__exit__(None, None, None)
            self._ctx = None

    def __exit__(self, *exc):
        self.stop()
        # remove sandbox log so scans don't leave artifacts behind
        if self.log_path and self.log_path.exists():
            try:
                self.log_path.unlink()
            except OSError:
                pass
        return False
