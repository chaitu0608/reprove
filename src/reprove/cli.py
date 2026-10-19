"""Reprove CLI.

Commands:
  reprove scan  <path>            static + dynamic scan, findings with proof
  reprove audit <path> [--apply]  scan -> patch -> verify (the full loop)
  reprove demo                    run the full loop on the bundled vulnerable corpus app
  reprove mcp                     run the MCP server (stdio) for agent integration
  reprove rules                   list every rule Reprove can detect

Exit codes (CI-friendly):
  0 clean / all fixes verified · 1 scan error · 2 confirmed high+ findings remain
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
import tempfile
from pathlib import Path

from . import __version__
from .context import load_context
from .models import AuditReport, Confidence, FixStatus, Severity
from .patch.generator import apply_patch, propose_all
from .patch.verifier import verify_fixes
from .report import render_audit, render_scan
from .scanner import scan_repo
from .util import SKIP_DIRS

OUT_DIR_NAME = "reprove-out"


def _progress(msg: str):
    print(f"  · {msg}", file=sys.stderr)


def _add_common(p: argparse.ArgumentParser):
    p.add_argument("--offline", action="store_true", default=True,
                   help="skip network checks (registry/OSV); default ON")
    p.add_argument("--online", dest="offline", action="store_false",
                   help="enable registry + OSV network checks")
    p.add_argument("--no-dynamic", action="store_true",
                   help="skip the live two-user exploit probe")
    p.add_argument("--workers", type=int, default=4, help="analyzer worker pool size")
    p.add_argument("--json", action="store_true", help="machine-readable output to stdout")


def cmd_scan(args) -> int:
    report = scan_repo(args.path, offline=args.offline, dynamic=not args.no_dynamic,
                       workers=args.workers, progress=_progress if not args.json else None)
    if args.json:
        print(report.to_json())
    else:
        print(render_scan(report))
    if args.output:
        Path(args.output).write_text(report.to_json(), encoding="utf-8")
        print(f"report written to {args.output}", file=sys.stderr)
    bad = [f for f in report.findings
           if f.severity in (Severity.CRITICAL, Severity.HIGH) and f.confidence == Confidence.CONFIRMED]
    return 2 if bad else 0


def _copy_for_audit(target: Path) -> Path:
    work = Path(tempfile.mkdtemp(prefix="reprove-audit-"))
    dest = work / target.name
    shutil.copytree(target, dest, ignore=shutil.ignore_patterns(*SKIP_DIRS, ".reprove-sandbox.log"),
                    dirs_exist_ok=False)
    return dest


def cmd_audit(args) -> int:
    target = Path(args.path).expanduser().resolve()
    if not target.exists():
        print(f"target not found: {target}", file=sys.stderr)
        return 1

    print(f"Reprove audit: {target}", file=sys.stderr)
    report = scan_repo(target, offline=args.offline, dynamic=not args.no_dynamic,
                       workers=args.workers, progress=_progress)

    ctx = load_context(target, {"offline": args.offline})
    patches = propose_all(ctx, report.findings)
    auto = [p for p in patches if p.automatic]

    if not args.apply:
        audit = AuditReport(target=str(target), scan=report, patches=patches,
                            meta={"applied": False})
        text = render_audit(audit)
        if args.json:
            print(json.dumps(audit.to_dict(), indent=2))
        else:
            print(text)
            print(f"\nDry run: {len(auto)} automated patch(es) ready. Re-run with --apply to fix-and-prove.")
        _write_outputs(target, audit)
        return 2 if any(f.severity.rank <= 1 and f.confidence == Confidence.CONFIRMED
                        for f in report.findings) else 0

    # ---- apply + verify (on a working copy by default) ------------------------------
    if args.in_place:
        work = target
        print("  ⚠ applying patches IN PLACE", file=sys.stderr)
    else:
        work = _copy_for_audit(target)
        print(f"  · working copy: {work}", file=sys.stderr)

    applied_notes: list[str] = []
    for p in auto:
        notes = apply_patch(work, p)
        applied_notes.extend(f"{p.summary}: {n}" for n in notes)

    fixes, verify_meta = verify_fixes(work, report.findings, patches,
                                      progress=_progress if not args.json else None)
    audit = AuditReport(target=str(target), scan=report, patches=patches, fixes=fixes,
                        meta={"applied": True, "verification_target": str(work),
                              "applied_notes": applied_notes, "verify": verify_meta})

    _write_outputs(target, audit)
    if args.json:
        print(json.dumps(audit.to_dict(), indent=2))
    else:
        print(render_audit(audit))
        if not args.in_place:
            print(f"\nPatched working copy kept at: {audit.meta['verification_target']}")
            print("Review, then either rsync it over your project or re-run with --in-place.")

    remaining = [r for r in fixes if r.status in (FixStatus.STILL_VULNERABLE,)]
    broke = [r for r in fixes if r.status == FixStatus.BREAKS_BUILD]
    if broke or remaining:
        return 2
    return 0


def _write_outputs(target: Path, audit: AuditReport):
    out = Path.cwd() / OUT_DIR_NAME
    out.mkdir(exist_ok=True)
    (out / "audit.json").write_text(json.dumps(audit.to_dict(), indent=2), encoding="utf-8")
    md = render_audit(audit)
    (out / "REPORT.md").write_text(md, encoding="utf-8")
    diff_text = "\n\n".join(p.diff for p in audit.patches if p.diff)
    if diff_text:
        (out / "fixes.diff").write_text(diff_text, encoding="utf-8")
    print(f"  · outputs: {out}/audit.json, REPORT.md, fixes.diff", file=sys.stderr)


def cmd_rules(args) -> int:
    from .scanner import registered
    import importlib
    importlib.import_module("reprove.analyzers")
    for name in sorted(registered()):
        mod = sys.modules.get(f"reprove.analyzers.{name}")
        doc = (mod.__doc__ or "").strip().splitlines()[0] if mod else ""
        print(f"{name:<12} {doc}")
    return 0


def cmd_demo(args) -> int:
    repo_root = Path(__file__).resolve().parents[2]
    corpus = repo_root / "corpus" / "vuln-node-api"
    if not corpus.exists():
        print("demo corpus not found — the demo requires running from the source checkout "
              "(corpus/ ships with the repo).", file=sys.stderr)
        return 1
    print("Running the full loop on the bundled vulnerable app (corpus/vuln-node-api):\n"
          "  1) scan  2) prove exploits  3) patch  4) re-prove\n", file=sys.stderr)
    args.path = str(corpus)
    args.apply = True
    args.in_place = False
    return cmd_audit(args)


def cmd_mcp(args) -> int:
    try:
        from .mcp_server import main as mcp_main
    except ImportError as e:
        print(f"MCP server needs the mcp SDK: pip install 'reprove-security[mcp]' ({e})", file=sys.stderr)
        return 1
    return mcp_main()


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="reprove",
                                     description="Prove the exploit. Fix the app. Re-prove it.")
    parser.add_argument("--version", action="version", version=f"reprove {__version__}")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_scan = sub.add_parser("scan", help="scan a project (static + live exploit proof)")
    p_scan.add_argument("path")
    p_scan.add_argument("--output", help="write JSON report to this file")
    _add_common(p_scan)
    p_scan.set_defaults(fn=cmd_scan)

    p_audit = sub.add_parser("audit", help="scan -> propose patches -> apply to a copy -> verify")
    p_audit.add_argument("path")
    p_audit.add_argument("--apply", action="store_true", help="apply automated patches and verify")
    p_audit.add_argument("--in-place", action="store_true",
                         help="apply patches to the target itself (default: safe working copy)")
    _add_common(p_audit)
    p_audit.set_defaults(fn=cmd_audit)

    p_demo = sub.add_parser("demo", help="run the full fix-and-prove loop on the bundled corpus app")
    _add_common(p_demo)
    p_demo.set_defaults(fn=cmd_demo, output=None, in_place=False, apply=True)

    p_mcp = sub.add_parser("mcp", help="run the MCP server (stdio) for agent integration")
    p_mcp.set_defaults(fn=cmd_mcp)

    p_rules = sub.add_parser("rules", help="list analyzers")
    p_rules.set_defaults(fn=cmd_rules)

    args = parser.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    raise SystemExit(main())
