"""Report rendering: human-first markdown + machine JSON.

Every finding answers three questions in the report, in plain language:
  1. What did you ship?        (description, with the evidence)
  2. Why is it dangerous?      (impact in real-world terms)
  3. What would a senior engineer have done? (remediation)
"""

from __future__ import annotations

from .models import AuditReport, FixStatus, ScanReport

BADGE = {"critical": "CRIT", "high": "HIGH", "medium": "MED ", "low": "LOW ", "info": "INFO"}
SYM = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "⚪", "info": "·"}
CONF = {"confirmed": "PROVEN", "likely": "LIKELY", "possible": "POSSIBLE"}
FIX_SYM = {
    FixStatus.VERIFIED: "✅ verified",
    FixStatus.STILL_VULNERABLE: "❌ still vulnerable",
    FixStatus.BREAKS_BUILD: "💥 breaks build",
    FixStatus.NOT_ATTEMPTED: "✋ manual",
    FixStatus.INCONCLUSIVE: "❓ inconclusive",
}


def render_scan(report: ScanReport, verbose: bool = True) -> str:
    lines = []
    summary = report.by_severity()
    counts = " · ".join(f"{SYM[s]} {n} {s}" for s, n in sorted(summary.items(), key=lambda kv: kv[1]) if n)
    lines.append(f"Reprove scan: {report.target}")
    lines.append(f"files: {report.meta.get('files_scanned', '?')} · duration: {report.meta.get('duration_s', '?')}s"
                 + (f" · {counts}" if counts else " · no findings"))
    dyn = report.meta.get("dynamic") or {}
    if dyn.get("ran") is False:
        lines.append(f"dynamic pass: skipped ({dyn.get('reason', 'n/a')})")
    elif dyn.get("ran"):
        lines.append(f"dynamic pass: two-user probe on live app · {len(dyn.get('notes', []))} note(s)")
    lines.append("")

    for f in report.findings:
        lines.extend(_render_finding(f, verbose=verbose))
    if not report.findings:
        lines.append("No findings. (Controls: this genuinely happens — see corpus/clean-node-api.)")
    return "\n".join(lines)


def _render_finding(f, verbose: bool = True) -> list[str]:
    lines = [f"{SYM[f.severity.value]} [{BADGE[f.severity.value]}] {f.title}  ({CONF[f.confidence.value]})",
             f"   rule: {f.rule} · at: {f.location}"]
    lines.append(f"   what you shipped: {f.description}")
    lines.append(f"   senior fix:       {f.remediation}")
    if verbose and f.evidence:
        ev = f.evidence[0]
        lines.append(f"   evidence:         [{ev.kind}] {ev.detail[:300]}")
    if f.exploit:
        lines.append(f"   exploit:          reproducible ({len(f.exploit.steps)} steps): {f.exploit.description}")
    lines.append("")
    return lines


def render_audit(audit: AuditReport) -> str:
    scan = audit.scan
    lines = ["=" * 72,
             f"REPROVE AUDIT — {scan.target}",
             "=" * 72, ""]
    lines.append(render_scan(scan, verbose=True))

    fixes_by_id = {r.finding_id: r for r in audit.fixes}
    if audit.patches:
        lines.append("-" * 72)
        lines.append("PATCHES PROPOSED")
        lines.append("-" * 72)
        for p in audit.patches:
            kind = "auto" if p.automatic else "manual"
            lines.append(f"  [{kind}] {p.summary}")
            if p.note:
                for nl in p.note.splitlines():
                    lines.append(f"        {nl}")
        lines.append("")

    if audit.fixes:
        lines.append("-" * 72)
        lines.append("VERIFICATION — a fix counts only when it is proven")
        lines.append("-" * 72)
        for r in audit.fixes:
            f = next((x for x in scan.findings if x.id == r.finding_id), None)
            title = f.title if f else r.finding_id
            lines.append(f"  {FIX_SYM[r.status]:<20} {title}")
            if r.detail:
                lines.append(f"      {r.detail}")
            for ev in r.evidence[:2]:
                lines.append(f"      proof: {ev.detail[:220]}")
        s = audit.meta.get("verify", {}).get("summary", {})
        if s:
            lines.append("")
            lines.append(f"  fixes: {s.get('verified', 0)} verified · {s.get('still_vulnerable', 0)} still vulnerable · "
                         f"{s.get('breaks_build', 0)} broke build · {s.get('not_attempted', 0)} manual · "
                         f"{s.get('inconclusive', 0)} inconclusive")
    lines.append("")
    lines.append("Tip: `reprove audit <path> --apply` copies the repo, applies automated patches,")
    lines.append("boots the patched app, replays every exploit, and reports only proven fixes.")
    return "\n".join(lines)
