"""Scan context: the repo snapshot every analyzer works against, plus the
analyzer registry that makes Reprove horizontally extensible.

Each analyzer is a pure function `(ScanContext) -> list[Finding]` registered
with @register. They run independently and in parallel — the exact same
interface a distributed worker pool would use later (see docs/SCALING.md).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional

from .models import Finding
from .util import walk_files, read_text, rel


@dataclass
class ScanFile:
    path: Path
    relpath: str
    text: str
    is_built: bool = False          # lives in dist/build/out — client artifacts


@dataclass
class ScanContext:
    root: Path
    files: list[ScanFile] = field(default_factory=list)
    options: dict = field(default_factory=dict)

    # ---- convenience accessors -------------------------------------------------

    def iter_files(self, exts: Optional[set[str]] = None, names: Optional[set[str]] = None,
                   exclude_built: bool = False) -> list[ScanFile]:
        out = []
        for f in self.files:
            if exclude_built and f.is_built:
                continue
            if exts is not None and f.path.suffix.lower() not in exts:
                continue
            if names is not None and f.path.name not in names:
                continue
            out.append(f)
        return out

    def by_name(self, *names: str) -> list[ScanFile]:
        wanted = set(names)
        return [f for f in self.files if f.path.name in wanted]

    def find_package_json(self) -> Optional[ScanFile]:
        pkgs = self.by_name("package.json")
        # prefer the shallowest one
        pkgs.sort(key=lambda f: len(f.relpath.split("/")))
        return pkgs[0] if pkgs else None

    def has_file(self, relpath: str) -> bool:
        return any(f.relpath == relpath for f in self.files)

    def offline(self) -> bool:
        return bool(self.options.get("offline", False))

    def app_url(self) -> Optional[str]:
        return self.options.get("app_url")

    def start_command(self) -> Optional[list[str]]:
        return self.options.get("start_command")


def load_context(root: Path, options: dict | None = None) -> ScanContext:
    from .util import BUILT_DIRS
    root = root.expanduser().resolve()
    files: list[ScanFile] = []
    for p in walk_files(root, include_built=True):
        text = read_text(p)
        if text is None:
            continue
        relpath = rel(root, p)
        is_built = any(part in BUILT_DIRS for part in Path(relpath).parts)
        files.append(ScanFile(path=p, relpath=relpath, text=text, is_built=is_built))
    return ScanContext(root=root, files=files, options=options or {})


# ---- analyzer registry ---------------------------------------------------------

_REGISTRY: dict[str, Callable[[ScanContext], list[Finding]]] = {}


def register(name: str):
    def deco(fn: Callable[[ScanContext], list[Finding]]):
        _REGISTRY[name] = fn
        return fn
    return deco


def registered() -> dict[str, Callable[[ScanContext], list[Finding]]]:
    return dict(_REGISTRY)
