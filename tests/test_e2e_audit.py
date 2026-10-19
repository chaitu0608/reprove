"""THE loop test: scan -> prove -> patch -> re-prove.

This is the test that defines reprove: on the vulnerable corpus app, every
automated patch must VERIFY — exploits replayed against the patched app must
fail, the re-scan must come back clean, and the app's own test suite must
still pass.
"""

import shutil

import pytest

from reprove.context import load_context
from reprove.models import FixStatus
from reprove.patch.generator import apply_patch, propose_all
from reprove.patch.verifier import verify_fixes
from reprove.scanner import scan_repo

pytestmark = pytest.mark.skipif(shutil.which("node") is None, reason="node not available")


def test_full_loop_vuln_app(vuln_app):
    # ---- 1. scan + prove ----------------------------------------------------------
    report = scan_repo(vuln_app, offline=True, dynamic=True)
    assert report.meta["dynamic"]["ran"] is True

    # ---- 2. propose patches --------------------------------------------------------
    ctx = load_context(vuln_app)
    patches = propose_all(ctx, report.findings)
    auto = [p for p in patches if p.automatic]
    assert auto, "no automated patches were proposed"

    # ---- 3. apply -------------------------------------------------------------------
    applied = []
    for p in auto:
        applied.extend(apply_patch(vuln_app, p))
    assert applied

    # ---- 4. verify --------------------------------------------------------------------
    fixes, meta = verify_fixes(vuln_app, report.findings, patches)

    assert meta["build"]["ok"] is True, f"patched app broke the build:\n{meta['build']['detail']}"

    by_id = {r.finding_id: r for r in fixes}

    def status_of(rule: str):
        f = next((x for x in report.findings if x.rule == rule), None)
        assert f is not None, f"finding {rule} missing from scan"
        return by_id[f.id].status

    # exploit-replay verdicts — the heart of this tool
    assert status_of("access-control/idor-confirmed") == FixStatus.VERIFIED
    assert status_of("access-control/admin-endpoint-open") == FixStatus.VERIFIED

    # rescan-verified fixes
    assert status_of("secrets/committed-env") == FixStatus.VERIFIED
    assert status_of("secrets/supabase-service-role") == FixStatus.VERIFIED
    assert status_of("secrets/openai-key") == FixStatus.VERIFIED
    assert status_of("rls/table-without-rls") == FixStatus.VERIFIED
    assert status_of("rls/permissive-policy") == FixStatus.VERIFIED
    assert status_of("authz/node-admin-route-no-auth") == FixStatus.VERIFIED
    assert status_of("idor/in-memory-find-by-id") == FixStatus.VERIFIED
    assert status_of("injection/sql-string-concat") == FixStatus.VERIFIED
    assert status_of("config/cors-wildcard") == FixStatus.VERIFIED

    # nothing should be broken
    assert not any(r.status == FixStatus.BREAKS_BUILD for r in fixes)

    # ---- 5. the patched app still works (tests ran during build check) ----------------
    assert "npm test: passed" in meta["build"]["detail"]


def test_loop_rerun_on_patched_is_clean(vuln_app):
    """After the full loop, a fresh scan of the patched tree should not
    re-confirm any exploit."""
    report = scan_repo(vuln_app, offline=True, dynamic=True)
    ctx = load_context(vuln_app)
    patches = propose_all(ctx, report.findings)
    for p in patches:
        if p.automatic:
            apply_patch(vuln_app, p)

    fresh = scan_repo(vuln_app, offline=True, dynamic=True)
    exploitable = [f for f in fresh.findings if f.exploit is not None]
    assert exploitable == [], f"exploits still demonstrable after patching: {[f.rule for f in exploitable]}"
