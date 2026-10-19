"""Dynamic probe tests: the two-user probe must PROVE the seeded IDOR and the
open admin endpoint on the vulnerable corpus app, with reproducible exploits."""

import shutil

import pytest

from reprove.scanner import scan_repo

pytestmark = pytest.mark.skipif(shutil.which("node") is None, reason="node not available")


def test_two_user_probe_confirms_exploits(vuln_app):
    report = scan_repo(vuln_app, offline=True, dynamic=True)
    dyn = report.meta.get("dynamic", {})
    assert dyn.get("ran") is True, f"dynamic pass did not run: {dyn}"

    by_rule = {f.rule: f for f in report.findings}

    idor = by_rule.get("access-control/idor-confirmed")
    assert idor is not None, "IDOR was not proven — probe failed to demonstrate user B reading user A's order"
    assert idor.exploit is not None
    assert len(idor.exploit.steps) >= 4  # signup a, signup b, create, steal
    ev = idor.evidence[0]
    assert ev.response and ev.response["status"] == 200

    admin = by_rule.get("access-control/admin-endpoint-open")
    assert admin is not None, "open admin endpoint was not confirmed"
    assert admin.exploit is not None


def test_clean_app_probe_finds_nothing(clean_app):
    report = scan_repo(clean_app, offline=True, dynamic=True)
    exploitable = [f for f in report.findings if f.exploit is not None]
    assert exploitable == [], f"control app must not be exploitable, got: {[f.rule for f in exploitable]}"
