"""MCP tool-function tests (no SDK required — the tool layer is plain functions)."""

import json

from reprove import mcp_server


def test_mcp_tools_end_to_end(nextlike_app):
    scan = mcp_server.tool_scan_project(str(nextlike_app), dynamic=False, offline=True)
    assert scan["findings"], "expected findings on the nextlike fixture"
    ids = [f["id"] for f in scan["findings"]]
    assert ids

    listing = mcp_server.tool_list_findings(str(nextlike_app))
    assert len(listing) == len(ids)

    fid = next(f["id"] for f in scan["findings"] if f["rule"] == "authz/next-route-no-auth")
    explain = mcp_server.tool_explain_finding(str(nextlike_app), fid)
    assert explain["proven"] in (True, False)
    assert explain["what_a_senior_would_do"]

    patch = mcp_server.tool_propose_patch(str(nextlike_app), fid)
    # patch is either automated (has diff/edits) or explicit manual guidance
    assert "summary" in patch

    # JSON-serializable throughout (MCP requirement)
    json.dumps(patch)
    json.dumps(explain)
