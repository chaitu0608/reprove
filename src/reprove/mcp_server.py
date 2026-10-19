"""Reprove MCP server — the agent-native face.

Exposes the fix-and-prove loop as MCP tools so a coding agent (Claude, OpenCode,
or any MCP client) can audit and heal an app it just generated, in-loop:

  scan_project    -> findings (with proof where available)
  list_findings   -> the stored findings for a project
  explain_finding -> plain-language explanation, builder-friendly
  propose_patch   -> the minimal diff that fixes a finding
  apply_patch     -> apply it (requires confirm=True)
  verify_fix      -> boot and replay the exploit; the fix counts only if it fails
  full_audit      -> scan + propose (+ apply + verify) in one call

Run:  reprove mcp        (stdio transport)
"""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Optional

from .context import load_context
from .dynamic.probe import execute_exploit
from .dynamic.sandbox import AppSandbox, detect_start_command
from .models import Finding, VerificationMode
from .patch.generator import apply_patch as _apply_patch_fs
from .patch.generator import propose_all, propose_patch
from .patch.verifier import verify_fixes, _uniquify
from .scanner import scan_repo
from .util import HttpClient

_STATE: dict[str, dict] = {}  # path -> {"report": ScanReport, "findings": {id: Finding}}


def _finding(path: str, finding_id: str) -> Finding:
    st = _STATE.get(path)
    if not st:
        raise ValueError(f"no scan stored for {path!r} — run scan_project first")
    f = st["findings"].get(finding_id)
    if not f:
        raise ValueError(f"finding {finding_id!r} not found for {path!r}")
    return f


def tool_scan_project(path: str, dynamic: bool = True, offline: bool = True) -> dict:
    report = scan_repo(path, offline=offline, dynamic=dynamic)
    _STATE[str(Path(path).expanduser().resolve())] = {
        "report": report,
        "findings": {f.id: f for f in report.findings},
    }
    return report.to_dict()


def tool_list_findings(path: str) -> list[dict]:
    st = _STATE.get(str(Path(path).expanduser().resolve()))
    if not st:
        return [{"error": "no scan stored — call scan_project first"}]
    return [
        {k: v for k, v in f.to_dict().items() if k not in ("description", "remediation")}
        for f in st["report"].findings
    ]


def tool_explain_finding(path: str, finding_id: str) -> dict:
    f = _finding(str(Path(path).expanduser().resolve()), finding_id)
    return {
        "id": f.id,
        "title": f.title,
        "severity": f.severity.value,
        "confidence": f.confidence.value,
        "proven": f.confidence.value == "confirmed",
        "location": f.location,
        "what_you_shipped": f.description,
        "why_dangerous": f.description,
        "what_a_senior_would_do": f.remediation,
        "evidence": [e.to_dict() for e in f.evidence],
        "exploit_steps": (f.exploit.steps if f.exploit else None),
        "verification": f.verification_mode.value,
    }


def tool_propose_patch(path: str, finding_id: str) -> dict:
    root = str(Path(path).expanduser().resolve())
    f = _finding(root, finding_id)
    ctx = load_context(Path(root))
    patch = propose_patch(ctx, f)
    if patch is None:
        return {"error": "no patch proposable"}
    _STATE[root].setdefault("patches", {})[finding_id] = patch
    return patch.to_dict()


def tool_apply_patch(path: str, finding_id: str, confirm: bool = False) -> dict:
    if not confirm:
        return {"error": "refusing to edit files without confirm=True",
                "hint": "show the user the proposed diff first, then call again with confirm=True"}
    root = Path(path).expanduser().resolve()
    st = _STATE.get(str(root))
    if not st or finding_id not in st.get("patches", {}):
        return {"error": "propose_patch must be called before apply_patch"}
    patch = st["patches"][finding_id]
    if not patch.automatic:
        return {"error": "this finding needs a manual fix", "guidance": patch.note}
    notes = _apply_patch_fs(root, patch)
    st.setdefault("applied", set()).add(finding_id)
    return {"applied": notes, "next": "call verify_fix to prove the fix"}


def tool_verify_fix(path: str, finding_id: str) -> dict:
    root = Path(path).expanduser().resolve()
    f = _finding(str(root), finding_id)

    if f.verification_mode == VerificationMode.EXPLOIT_REPLAY and f.exploit:
        command = detect_start_command(root)
        if not command:
            return {"status": "inconclusive", "reason": "no start command detected"}
        with AppSandbox(root, command=command) as sbx:
            if not sbx.healthy:
                return {"status": "inconclusive", "reason": sbx.error}
            spec = _uniquify(f.exploit, "mcp")
            run = execute_exploit(HttpClient(timeout=5.0), sbx.base_url, spec)
        status = {"exploit-blocked": "verified", "exploit-succeeded": "still-vulnerable",
                  "setup-failed": "inconclusive"}[run.verdict]
        return {"status": status, "verdict": run.verdict,
                "steps": [s.__dict__ for s in run.steps],
                "final_status": run.final_status, "body_excerpt": run.final_body[:400]}

    # rescan-based verification
    st = _STATE[str(root)]
    patches = list(st.get("patches", {}).values())
    fixes, _meta = verify_fixes(root, [f], patches)
    r = fixes[0]
    return {"status": r.status.value, "detail": r.detail}


def tool_full_audit(path: str, apply: bool = False, dynamic: bool = True) -> dict:
    scan = tool_scan_project(path, dynamic=dynamic)
    root = str(Path(path).expanduser().resolve())
    ctx = load_context(Path(root))
    findings = list(_STATE[root]["findings"].values())
    patches = propose_all(ctx, findings)
    _STATE[root]["patches"] = {p.finding_id: p for p in patches}

    applied = []
    if apply:
        for p in patches:
            if p.automatic:
                applied.extend(_apply_patch_fs(Path(root), p))
        fixes, vmeta = verify_fixes(Path(root), findings, patches)
        return {"scan": scan, "patches": [p.to_dict() for p in patches],
                "applied": applied, "fixes": [f.to_dict() for f in fixes], "verify_meta": vmeta}
    return {"scan": scan, "patches": [p.to_dict() for p in patches],
            "note": "call apply_patch per finding (confirm=True), then verify_fix"}


def build_server():
    try:
        from mcp.server.fastmcp import FastMCP
    except ImportError as e:  # pragma: no cover
        raise ImportError("MCP SDK not installed — pip install 'reprove-security[mcp]'") from e

    mcp = FastMCP(
        "reprove",
        instructions=(
            "Security that proves itself: scan an app for vibe-code security flaws, PROVE each one with a "
            "real exploit against a sandboxed local copy, apply the minimal patch, then RE-PROVE the fix by "
            "replaying the exploit. A fix counts only when its exploit fails. All probing happens against "
            "the user's own local code — never point this at third-party systems."
        ),
    )

    @mcp.tool()
    def scan_project(path: str, dynamic: bool = True, offline: bool = True) -> dict:
        """Scan a project directory for security flaws (secrets, RLS, IDOR, injection, deps, config, AI-feature). dynamic=True boots the app locally and runs a two-user exploit probe."""
        return tool_scan_project(path, dynamic, offline)

    @mcp.tool()
    def list_findings(path: str) -> list:
        """List findings from the last scan of `path`."""
        return tool_list_findings(path)

    @mcp.tool()
    def explain_finding(path: str, finding_id: str) -> dict:
        """Explain one finding in plain language: what was shipped, why it's dangerous, what a senior engineer would do."""
        return tool_explain_finding(path, finding_id)

    @mcp.tool()
    def propose_patch(path: str, finding_id: str) -> dict:
        """Generate the minimal patch (diff) that fixes a finding."""
        return tool_propose_patch(path, finding_id)

    @mcp.tool()
    def apply_patch(path: str, finding_id: str, confirm: bool = False) -> dict:
        """Apply the proposed patch to the local project. Requires confirm=True after showing the diff to the user."""
        return tool_apply_patch(path, finding_id, confirm)

    @mcp.tool()
    def verify_fix(path: str, finding_id: str) -> dict:
        """Prove the fix: boot the app and replay the exact exploit. verified = attack no longer works."""
        return tool_verify_fix(path, finding_id)

    @mcp.tool()
    def full_audit(path: str, apply: bool = False, dynamic: bool = True) -> dict:
        """One-shot: scan, propose patches for everything, optionally apply all automated fixes and verify each one by exploit replay."""
        return tool_full_audit(path, apply, dynamic)

    return mcp


def main() -> int:
    server = build_server()
    server.run()  # stdio transport
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
