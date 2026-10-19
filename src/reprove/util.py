"""Shared utilities: file walking, entropy, HTTP, process control."""

from __future__ import annotations

import base64
import contextlib
import difflib
import json
import math
import os
import re
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Iterator, Optional

SKIP_DIRS = {
    ".git", "node_modules", ".venv", "venv", "__pycache__", ".next", ".turbo",
    ".cache", ".idea", ".vscode", "vendor", ".reprove", "coverage", ".pytest_cache",
    ".mypy_cache", "dist-cache",
}

# Directories that hold *built* client artifacts — we scan these for leaked secrets,
# because env vars are inlined into the bundle at build time.
BUILT_DIRS = {"dist", "build", "out", ".output", ".svelte-kit"}

TEXT_EXTS = {
    ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".vue", ".svelte", ".html",
    ".py", ".rb", ".go", ".rs", ".java", ".kt", ".php", ".sql", ".json", ".yaml",
    ".yml", ".toml", ".ini", ".cfg", ".conf", ".env", ".sh", ".bash", ".zsh",
    ".md", ".txt", ".lock", ".css", ".graphql", ".gql", ".astro",
}

MAX_FILE_BYTES = 1_500_000


def walk_files(root: Path, include_built: bool = True) -> Iterator[Path]:
    """Yield candidate text files under root, pruning noise directories."""
    for dirpath, dirnames, filenames in os.walk(root):
        d = Path(dirpath)
        rel_parts = d.relative_to(root).parts if d != root else ()
        pruned = []
        for name in dirnames:
            if name in SKIP_DIRS:
                continue
            if name in BUILT_DIRS and not include_built:
                continue
            # prune built dirs from traversal when they are huge? keep — we want them
            pruned.append(name)
        dirnames[:] = pruned
        for fn in filenames:
            p = d / fn
            try:
                if p.stat().st_size > MAX_FILE_BYTES:
                    continue
            except OSError:
                continue
            if (p.suffix.lower() in TEXT_EXTS or fn in {"Dockerfile", ".env", ".env.local",
                                                        ".env.production", ".gitignore"}):
                yield p


def read_text(path: Path) -> Optional[str]:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def rel(root: Path, p: Path) -> str:
    try:
        return str(p.relative_to(root))
    except ValueError:
        return str(p)


def line_of(text: str, index: int) -> int:
    return text.count("\n", 0, index) + 1


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts: dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def looks_like_secret(s: str) -> bool:
    """High-entropy candidate heuristic, tuned to keep false positives low."""
    if len(s) < 24 or len(s) > 200:
        return False
    if s.lower().startswith(("http", "data:", "sha", "md5")):
        return False
    if re.fullmatch(r"[0-9a-fA-F]+", s):  # pure hex is usually a hash/id — skip
        return False
    if not re.search(r"[A-Za-z]", s):
        return False
    has_digit = bool(re.search(r"\d", s))
    has_symbol = bool(re.search(r"[-_.+/=]", s))
    if not (has_digit and has_symbol):
        return False
    if re.fullmatch(r"[\w.-]+@[\w.-]+", s):
        return False
    return shannon_entropy(s) >= 4.1


def decode_jwt_payload(token: str) -> Optional[dict]:
    """Decode the payload of a JWT without verifying — for classification only."""
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        payload = parts[1] + "=" * (-len(parts[1]) % 4)
        data = base64.urlsafe_b64decode(payload.encode())
        return json.loads(data.decode("utf-8", errors="replace"))
    except Exception:
        return None


def unified_diff(old: str, new: str, path: str) -> str:
    if old == new:
        return ""
    return "".join(
        difflib.unified_diff(
            old.splitlines(keepends=True), new.splitlines(keepends=True),
            fromfile=f"a/{path}", tofile=f"b/{path}",
        )
    )


@dataclass
class HttpResult:
    status: int
    headers: dict
    body: str
    error: Optional[str] = None

    def json(self) -> Optional[dict]:
        try:
            return json.loads(self.body)
        except Exception:
            return None

    def snippet(self, n: int = 400) -> str:
        return self.body[:n]


class HttpClient:
    """Tiny stdlib HTTP client with timeouts; no external deps."""

    def __init__(self, timeout: float = 6.0):
        self.timeout = timeout

    def request(
        self,
        method: str,
        url: str,
        json_body: Optional[dict] = None,
        headers: Optional[dict] = None,
        data: Optional[bytes] = None,
    ) -> HttpResult:
        hdrs = {"User-Agent": "reprove/0.1 (security scanner)", "Accept": "*/*"}
        if headers:
            hdrs.update(headers)
        body = data
        if json_body is not None:
            body = json.dumps(json_body).encode()
            hdrs["Content-Type"] = "application/json"
        req = urllib.request.Request(url, data=body, headers=hdrs, method=method.upper())
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                raw = resp.read().decode("utf-8", errors="replace")
                return HttpResult(resp.status, dict(resp.headers), raw)
        except urllib.error.HTTPError as e:
            raw = e.read().decode("utf-8", errors="replace") if e.fp else ""
            return HttpResult(e.code, dict(e.headers or {}), raw)
        except Exception as e:  # connection refused, timeout, DNS...
            return HttpResult(0, {}, "", error=str(e))


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def wait_for_http(url: str, timeout: float = 12.0, http: Optional[HttpClient] = None) -> bool:
    client = http or HttpClient(timeout=2.0)
    deadline = time.time() + timeout
    while time.time() < deadline:
        r = client.request("GET", url)
        if r.status and r.status < 500:
            return True
        time.sleep(0.25)
    return False


@contextlib.contextmanager
def run_process(cmd: list[str], cwd: Path, env: Optional[dict] = None, log_path: Optional[Path] = None):
    """Run a process; always terminate it on exit. Yields the Popen object."""
    full_env = dict(os.environ)
    if env:
        full_env.update(env)
    logf = open(log_path, "wb") if log_path else subprocess.DEVNULL
    proc = subprocess.Popen(
        cmd, cwd=str(cwd), env=full_env,
        stdout=logf, stderr=subprocess.STDOUT,
        start_new_session=True,
    )
    try:
        yield proc
    finally:
        with contextlib.suppress(Exception):
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
        if logf is not subprocess.DEVNULL:
            logf.close()


def run_command(cmd: list[str], cwd: Path, timeout: float = 300.0) -> tuple[int, str]:
    """Run to completion with timeout. Returns (returncode, combined output tail)."""
    try:
        p = subprocess.run(
            cmd, cwd=str(cwd), capture_output=True, text=True, timeout=timeout,
        )
        out = (p.stdout or "") + (p.stderr or "")
        return p.returncode, out[-4000:]
    except FileNotFoundError as e:
        return 127, str(e)
    except subprocess.TimeoutExpired:
        return 124, f"timed out after {timeout}s"


def which(name: str) -> Optional[str]:
    from shutil import which as _which
    return _which(name)


def is_probably_minified(text: str) -> bool:
    """Detect minified bundles (long lines, few newlines)."""
    if not text:
        return False
    lines = text.count("\n")
    return len(text) > 5000 and (lines == 0 or len(text) / max(lines, 1) > 2000)
