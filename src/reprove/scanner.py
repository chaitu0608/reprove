"""Scanner orchestrator.

Pipeline:  load snapshot -> run analyzers in a worker pool -> dynamic probes -> triage.

The analyzer interface is deliberately stateless and pure so the same code
runs in-process (now) or sharded across workers behind a queue (later).
"""

from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Optional

from .context import ScanContext, load_context, registered
from .models import Confidence, ScanReport
from .triage import triage

# Importing the analyzer modules registers them.
from . import analyzers  # noqa: F401  (side-effect: registration)


def scan_repo(
    target: str | Path,
    offline: bool = True,
    dynamic: bool = True,
    workers: int = 4,
    options: dict | None = None,
    progress=None,
) -> ScanReport:
    t0 = time.time()
    root = Path(target)
    if not root.exists():
        raise FileNotFoundError(f"target not found: {root}")

    opts = {"offline": offline}
    if options:
        opts.update(options)
    ctx = load_context(root, opts)

    def emit(msg: str):
        if progress:
            progress(msg)

    emit(f"snapshot: {len(ctx.files)} text files")

    # ---- static analyzers, in parallel workers --------------------------------
    findings = []
    names = registered()
    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        futs = {pool.submit(fn, ctx): name for name, fn in names.items()}
        for fut in as_completed(futs):
            name = futs[fut]
            try:
                res = fut.result()
                findings.extend(res)
                if res:
                    emit(f"static[{name}]: {len(res)} finding(s)")
            except Exception as e:  # an analyzer must never kill the scan
                emit(f"static[{name}]: ERROR {e!r}")

    # ---- dynamic pass ----------------------------------------------------------
    meta: dict = {}
    if dynamic:
        try:
            from .dynamic.probe import dynamic_pass
            dyn_findings, dyn_meta = dynamic_pass(ctx, progress=emit)
            findings.extend(dyn_findings)
            meta["dynamic"] = dyn_meta
        except Exception as e:
            emit(f"dynamic: ERROR {e!r}")
            meta["dynamic"] = {"ran": False, "error": repr(e)}

    merged = triage(findings)
    meta.update({
        "files_scanned": len(ctx.files),
        "duration_s": round(time.time() - t0, 2),
        "offline": offline,
        "analyzers": sorted(names.keys()),
    })
    return ScanReport(target=str(root), findings=merged, meta=meta)
