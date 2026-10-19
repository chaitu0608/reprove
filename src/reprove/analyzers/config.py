"""Configuration analyzer: the sloppy defaults AI builders ship.

  * CORS wildcard (with credentials: worse)
  * no security headers on server responses
  * verbose error leaking stack traces to clients
  * no rate limiting on a JSON API
"""

from __future__ import annotations

import re

from ..context import ScanContext, ScanFile, register
from ..models import Category, Confidence, Evidence, Finding, Severity, VerificationMode
from ..util import line_of

CORS_WILDCARD = re.compile(r"""(?:Access-Control-Allow-Origin['"]?\s*[,:]\s*['"]\*['"]|origin\s*:\s*['"]\*['"]|origin\s*:\s*true|cors\(\s*\))""", re.I)
CORS_CREDENTIALS = re.compile(r"credentials\s*:\s*true|Access-Control-Allow-Credentials['\"]?\s*[,:]\s*['\"]true", re.I)

STACK_LEAK = re.compile(r"res(?:ponse)?\s*\.\s*(?:send|json|end|write)\s*\(\s*[^)]*(?:err|error|e)\.stack", re.I | re.S)

SERVER_ENTRY = re.compile(r"(?:createServer\s*\(|express\s*\(\s*\)|new\s+Hono|fastify\s*\()")
SECURITY_HEADER = re.compile(r"helmet|Content-Security-Policy|X-Content-Type-Options|Strict-Transport-Security", re.I)
BODY_LIMIT = re.compile(r"(?:express\.json|bodyParser\.json)\s*\(\s*\)")
RATE_LIMIT = re.compile(r"rateLimit|rate-limit|express-rate-limit|@fastify/rate-limit|throttle", re.I)
API_ROUTE = re.compile(r"app\.(?:get|post|put|patch|delete)\s*\(")


@register("config")
def analyze_config(ctx: ScanContext) -> list[Finding]:
    out: list[Finding] = []
    for f in ctx.files:
        if f.is_built or f.path.suffix.lower() not in (".js", ".ts", ".mjs", ".cjs", ".tsx", ".jsx"):
            continue
        out.extend(_cors(f))
        out.extend(_stack_leak(f))
        out.extend(_server_hygiene(f, ctx))
    return out


def _cors(f: ScanFile) -> list[Finding]:
    out = []
    for m in CORS_WILDCARD.finditer(f.text):
        window = f.text[max(0, m.start() - 120): m.end() + 220]
        with_creds = bool(CORS_CREDENTIALS.search(window))
        line = line_of(f.text, m.start())
        sev = Severity.HIGH if with_creds else Severity.MEDIUM
        out.append(Finding(
            rule="config/cors-wildcard",
            category=Category.CONFIG,
            title="CORS allows any origin" + (" — with credentials" if with_creds else ""),
            severity=sev,
            confidence=Confidence.LIKELY,
            description=(
                f"At `{f.relpath}:{line}` the server accepts requests from every origin (wildcard CORS"
                + (", and credentials are enabled — the worst combination" if with_creds else "")
                + "). Any website a logged-in user visits can silently call this API with their cookies/tokens."
            ),
            remediation=("Allowlist your real frontend origin(s) from an environment variable, e.g. "
                         "`origin: process.env.ALLOWED_ORIGIN`. Never combine a wildcard with credentials."),
            location=f"{f.relpath}:{line}",
            evidence=[Evidence(kind="code", detail=f"CORS wildcard: {m.group(0)[:120]}", location=f"{f.relpath}:{line}")],
            verification_mode=VerificationMode.RESCAN,
            tags=["config", "cors"],
        ))
    return out


def _stack_leak(f: ScanFile) -> list[Finding]:
    out = []
    for m in STACK_LEAK.finditer(f.text):
        line = line_of(f.text, m.start())
        out.append(Finding(
            rule="config/stack-trace-to-client",
            category=Category.CONFIG,
            title="Error stack trace sent to the client",
            severity=Severity.LOW,
            confidence=Confidence.LIKELY,
            description=(
                f"`{f.relpath}:{line}` returns `err.stack` to the caller. Stack traces expose file paths, "
                "dependency versions, and internal logic — free reconnaissance for an attacker."
            ),
            remediation="Log the stack server-side; return a generic error payload (code + safe message) to the client.",
            location=f"{f.relpath}:{line}",
            evidence=[Evidence(kind="code", detail="exception stack serialized into the HTTP response",
                               location=f"{f.relpath}:{line}")],
            verification_mode=VerificationMode.RESCAN,
            tags=["config"],
        ))
    return out


def _server_hygiene(f: ScanFile, ctx: ScanContext) -> list[Finding]:
    out = []
    if not SERVER_ENTRY.search(f.text) or f.path.name.endswith((".test.js", ".spec.js")):
        return out
    # one aggregated hygiene finding per server entry file
    missing = []
    if not SECURITY_HEADER.search(ctx_text_of(ctx, f)):
        missing.append("security headers (helmet / Content-Security-Policy)")
    if not RATE_LIMIT.search(ctx_text_of(ctx, f)):
        missing.append("rate limiting on the API")
    if missing:
        first = f.text[:400]
        line = line_of(f.text, SERVER_ENTRY.search(first).start()) if SERVER_ENTRY.search(first) else 1
        out.append(Finding(
            rule="config/server-hygiene-gaps",
            category=Category.CONFIG,
            title="Server entry point lacks basic hardening",
            severity=Severity.LOW,
            confidence=Confidence.LIKELY,
            description=(
                f"`{f.relpath}` starts an HTTP API but has no sign of: {', '.join(missing)}. "
                "Individually minor; together they are the difference between a rough day and a breach."
            ),
            remediation=("Add `helmet()` (or set CSP/nosniff/HSTS headers), and rate-limit auth + LLM "
                         "endpoints (`express-rate-limit`, 5–20 req/min per IP)."),
            location=f"{f.relpath}:{line}",
            evidence=[Evidence(kind="code", detail=f"missing: {', '.join(missing)}", location=f.relpath)],
            verification_mode=VerificationMode.RESCAN,
            tags=["config"],
        ))
    return out


def ctx_text_of(ctx: ScanContext, f: ScanFile) -> str:
    """Search file + immediate sibling config files so a helmet() in app.js counts for server.js."""
    parts = [f.text]
    for sib in ctx.files:
        if sib is f:
            continue
        if sib.relpath.split("/")[0] == f.relpath.split("/")[0] and sib.path.suffix.lower() in (".js", ".ts"):
            parts.append(sib.text)
    return "\n".join(parts)
