"""Static analyzer tests: every seeded vulnerability class must be detected,
and the hardened control app must stay (nearly) clean."""

from reprove.models import Confidence, Severity
from reprove.scanner import scan_repo


def rules(report):
    return {f.rule for f in report.findings}


def test_vuln_node_api_static(vuln_app):
    report = scan_repo(vuln_app, offline=True, dynamic=False)
    found = rules(report)

    # secrets
    assert "secrets/committed-env" in found
    assert "secrets/supabase-service-role" in found
    assert "secrets/openai-key" in found
    assert "secrets/stripe-secret" in found

    # access control / rls
    assert "rls/table-without-rls" in found
    assert "rls/permissive-policy" in found
    assert "authz/node-admin-route-no-auth" in found
    assert "idor/in-memory-find-by-id" in found

    # injection
    assert "injection/sql-string-concat" in found

    # config
    assert "config/cors-wildcard" in found

    # client-exposed secret lands at CRITICAL
    svc = [f for f in report.findings if f.rule == "secrets/supabase-service-role"]
    assert any(f.severity == Severity.CRITICAL for f in svc)
    assert any(f.confidence == Confidence.CONFIRMED for f in svc)


def test_vuln_nextlike_static(nextlike_app):
    report = scan_repo(nextlike_app, offline=True, dynamic=False)
    found = rules(report)

    assert "authz/next-route-no-auth" in found
    assert "idor/supabase-fetch-by-id" in found
    assert "xss/unsafe-html-sink" in found
    assert "config/stack-trace-to-client" in found
    assert "ai/llm-called-from-client" in found
    assert "ai/prompt-injection-surface" in found
    assert "ai/unsafe-tool-execution" in found


def test_clean_app_has_no_high_findings(clean_app):
    report = scan_repo(clean_app, offline=True, dynamic=False)
    bad = [f for f in report.findings if f.severity.rank <= 1]  # critical/high
    assert bad == [], f"control app must stay clean, got: {[(f.rule, f.severity.value) for f in bad]}"


def test_deps_typosquat_offline(vuln_app):
    report = scan_repo(vuln_app, offline=True, dynamic=False)
    typos = [f for f in report.findings if f.rule == "deps/typosquat-suspicion"]
    assert any("expres" in f.title for f in typos)


def test_deps_clean_lodash_not_flagged(clean_app):
    report = scan_repo(clean_app, offline=True, dynamic=False)
    assert not any("lodash" in f.title.lower() for f in report.findings)
