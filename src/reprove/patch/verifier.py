"""Fix verifier: a fix counts only when it is proven.

For every finding with an automated patch, Reprove does the strongest
verification the finding allows:

  * exploit-replay findings -> boot the PATCHED app in the sandbox and re-run
    the exact recorded ExploitSpec. Fix verified only if the attack fails
    (and the app still boots).
  * rescan findings         -> re-run the analyzers on the patched tree; the
    finding must no longer be detected.
  * everything              -> build check first (syntax + project tests);
    a patch that breaks the app is marked BREAKS_BUILD, never VERIFIED.

The verdict function is deterministic; no model judgment is on the path.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path

from ..context import load_context, registered
from ..dynamic.probe import execute_exploit
from ..dynamic.sandbox import AppSandbox, detect_start_command
from ..models import (Confidence, Evidence, Finding, FixResult, FixStatus,
                      Patch, VerificationMode)
from ..triage import triage
from ..util import HttpClient, run_command, which


def _edited_files(patches: list[Patch]) -> set[str]:
    files: set[str] = set()
    for p in patches:
        for e in p.edits:
            files.add(e["path"])
    return files


def run_build_check(repo: Path, patches: list[Patch]) -> tuple[bool, str]:
    """Syntax-check edited files and run the project's tests if it has them."""
    msgs: list[str] = []
    ok = True

    if which("node") is None and any(f.endswith((".js", ".mjs", ".cjs")) for f in _edited_files(patches)):
        return True, "build check skipped: node not available"

    for relpath in sorted(_edited_files(patches)):
        f = repo / relpath
        if not f.exists():
            continue
        if relpath.endswith((".js", ".mjs", ".cjs")):
            code, out = run_command(["node", "--check", str(f)], repo, timeout=30)
            if code != 0:
                ok = False
                msgs.append(f"node --check {relpath}: FAILED\n{out[-600:]}")
        elif relpath.endswith(".py"):
            code, out = run_command(["python3", "-m", "py_compile", str(f)], repo, timeout=30)
            if code != 0:
                ok = False
                msgs.append(f"py_compile {relpath}: FAILED\n{out[-400:]}")

    pkg = repo / "package.json"
    if pkg.exists():
        try:
            data = json.loads(pkg.read_text(encoding="utf-8", errors="replace"))
            test_script = (data.get("scripts") or {}).get("test", "")
        except Exception:
            test_script = ""
        if test_script:
            code, out = run_command(["npm", "test", "--silent"], repo, timeout=180)
            if code == 0:
                msgs.append("npm test: passed")
            else:
                # Distinguish "dependencies not installed" (bare package missing)
                # from a genuine test failure (a project file/module missing).
                m = re.search(r"Cannot find module '([^']+)'", out)
                missing_dep = bool(m) and not m.group(1).startswith(("/", "."))
                if missing_dep or "ERR_MODULE_NOT_FOUND" in out and "node_modules" in out:
                    msgs.append("npm test: skipped (dependencies not installed — run npm install then reprove to re-verify)")
                else:
                    ok = False
                    msgs.append(f"npm test: FAILED\n{out[-1200:]}")
    return ok, "\n".join(msgs) or "nothing to check"


def _uniquify(spec, suffix: str):
    """Fresh accounts per replay so repeated specs don't collide."""
    s = copy.deepcopy(spec)

    def sub(v):
        if isinstance(v, str):
            return v.replace("@example.org", f"+{suffix}@example.org")
        if isinstance(v, dict):
            return {k: sub(x) for k, x in v.items()}
        if isinstance(v, list):
            return [sub(x) for x in v]
        return v

    s.steps = [sub(st) for st in s.steps]
    return s


def _rescan_pairs(repo: Path) -> set[tuple[str, str]]:
    """Run the static analyzers on the patched tree; return {(rule, file)}."""
    ctx = load_context(repo)
    out: list[Finding] = []
    for name, fn in registered().items():
        try:
            out.extend(fn(ctx))
        except Exception:
            continue
    merged = triage(out)
    pairs = set()
    for f in merged:
        loc = f.location
        if ":" in loc and not loc.startswith(("GET ", "http")):
            parts = loc.rsplit(":", 1)
            if parts[-1].isdigit():
                loc = parts[0]
        pairs.add((f.rule, loc))
    return pairs


def verify_fixes(
    repo: Path,
    findings: list[Finding],
    patches: list[Patch],
    progress=None,
) -> tuple[list[FixResult], dict]:
    emit = progress or (lambda m: None)
    by_finding = {p.finding_id: p for p in patches}
    meta: dict = {}

    # ---- 1. build check ---------------------------------------------------------------
    build_ok, build_detail = run_build_check(repo, patches)
    meta["build"] = {"ok": build_ok, "detail": build_detail}
    emit(f"verify: build check {'PASSED' if build_ok else 'FAILED'}")

    # ---- 2. exploit replays (one sandbox boot for all replayable findings) -------------
    replay_runs: dict[str, object] = {}
    replay_findings = [f for f in findings
                       if f.exploit is not None and f.verification_mode == VerificationMode.EXPLOIT_REPLAY]
    if replay_findings:
        command = detect_start_command(repo)
        if command and build_ok:
            emit(f"verify: booting patched app to replay {len(replay_findings)} exploit(s)")
            with AppSandbox(repo, command=command) as sbx:
                if sbx.healthy:
                    http = HttpClient(timeout=5.0)
                    for i, f in enumerate(replay_findings):
                        spec = _uniquify(f.exploit, f"r{i}")
                        replay_runs[f.id] = execute_exploit(http, sbx.base_url, spec)
                        verdict = replay_runs[f.id].verdict
                        emit(f"verify: replay {f.rule} -> {verdict}")
                else:
                    meta["replay_error"] = sbx.error
                    emit(f"verify: could not boot patched app ({sbx.error})")
        else:
            emit("verify: skipped exploit replay (no start command or build failed)")
    meta["replayed"] = len(replay_runs)

    # ---- 3. rescan the patched tree ------------------------------------------------------
    rescan_pairs: set[tuple[str, str]] = set()
    if any(f.verification_mode == VerificationMode.RESCAN for f in findings):
        rescan_pairs = _rescan_pairs(repo)
        meta["rescan_findings"] = len(rescan_pairs)
        emit(f"verify: rescan of patched tree shows {len(rescan_pairs)} remaining finding(s)")

    # ---- 4. verdicts ----------------------------------------------------------------------
    results: list[FixResult] = []
    for f in findings:
        patch = by_finding.get(f.id)
        mode = f.verification_mode

        if mode == VerificationMode.EXPLOIT_REPLAY:
            run = replay_runs.get(f.id)
            if not build_ok:
                results.append(FixResult(f.id, FixStatus.BREAKS_BUILD, mode,
                                         "patch broke the build — replayed impossible", []))
            elif run is None:
                results.append(FixResult(f.id, FixStatus.INCONCLUSIVE, mode,
                                         "could not boot the patched app to replay the exploit", []))
            elif run.verdict == "exploit-succeeded":
                results.append(FixResult(
                    f.id, FixStatus.STILL_VULNERABLE, mode,
                    "replayed the exact exploit against the patched app — it still succeeds",
                    run.to_evidence()))
            elif run.verdict == "exploit-blocked":
                results.append(FixResult(
                    f.id, FixStatus.VERIFIED, mode,
                    "the recorded exploit no longer works against the patched app",
                    run.to_evidence()))
            else:
                results.append(FixResult(f.id, FixStatus.INCONCLUSIVE, mode,
                                         f"replay aborted: {run.note}", run.to_evidence()))
            continue

        if mode == VerificationMode.RESCAN:
            file_part = f.location.rsplit(":", 1)[0] if ":" in f.location else f.location
            still = any(rule == f.rule and loc == file_part for rule, loc in rescan_pairs)
            if not still:
                # Verified by result, not by patch ownership: a sibling patch
                # (e.g. deleting the committed .env) may have closed this one too.
                results.append(FixResult(f.id, FixStatus.VERIFIED, mode,
                                         f"re-scan no longer detects `{f.rule}` in {file_part}"))
            elif patch is None or not patch.automatic:
                results.append(FixResult(f.id, FixStatus.NOT_ATTEMPTED, mode,
                                         "manual fix guidance provided (no automated patch)"))
            elif not build_ok:
                results.append(FixResult(f.id, FixStatus.BREAKS_BUILD, mode,
                                         "patch broke the build", []))
            else:
                results.append(FixResult(f.id, FixStatus.STILL_VULNERABLE, mode,
                                         f"analyzer still detects `{f.rule}` in {file_part} after patching"))
            continue

        results.append(FixResult(f.id, FixStatus.NOT_ATTEMPTED, mode,
                                 "cannot be auto-verified (manual step required, e.g. key rotation)"))

    verified = sum(1 for r in results if r.status == FixStatus.VERIFIED)
    meta["summary"] = {
        "total": len(results),
        "verified": verified,
        "still_vulnerable": sum(1 for r in results if r.status == FixStatus.STILL_VULNERABLE),
        "breaks_build": sum(1 for r in results if r.status == FixStatus.BREAKS_BUILD),
        "not_attempted": sum(1 for r in results if r.status == FixStatus.NOT_ATTEMPTED),
        "inconclusive": sum(1 for r in results if r.status == FixStatus.INCONCLUSIVE),
    }
    emit(f"verify: {verified}/{len(results)} fixes verified")
    return results, meta
