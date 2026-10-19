"""Authorization analyzer.

Finds endpoints with no server-side auth check — the "auth only in the UI"
mistake. Hidden buttons and route guards are decoration; the API is the
front door. Rules:

  * Next.js App Router route handlers (app/**/route.ts) with no session check
  * Express routes registered without auth middleware
  * raw Node http blocks under /api/admin* with no auth call nearby
"""

from __future__ import annotations

import re

from ..context import ScanContext, ScanFile, register
from ..models import (Category, Confidence, Evidence, Finding, Severity,
                      VerificationMode)
from ..util import line_of

PUBLIC_SEGMENTS = ("auth", "login", "signup", "register", "webhook", "webhooks", "hooks",
                   "health", "healthz", "public", "oauth", "callback", "stripe", "billing",
                   "cron", "preview", "status", "ping", "docs", "openapi")

AUTH_SIGNALS = re.compile(
    r"getServerSession|getToken|withAuth|requireAuth|requireUser|isAuthenticated|"
    r"\bauth\(\)|currentUser|clerkMiddleware|verifySession|verifyToken|authenticate|"
    r"supabase\.auth\.getUser|getUser\(\)|jwt\.verify|checkAuth|ensureAuth|session\b|"
    r"Authorization\b|req\.user\b|ctx\.user\b",
    re.I,
)

NEXT_HANDLER = re.compile(r"export\s+(?:async\s+)?function\s+(?P<method>GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s*\(")
NEXT_HANDLER_CONST = re.compile(r"export\s+const\s+(?P<method>GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s*=\s*(?:async\s*)?\(")

MIDDLEWARE_SIGNAL = re.compile(
    r"(require|auth|authenticated|verify|verifyToken|jwt|passport|guard|protect|ensureLoggedIn|isLoggedIn)",
    re.I,
)


@register("authz")
def analyze_authz(ctx: ScanContext) -> list[Finding]:
    findings: list[Finding] = []
    for f in ctx.files:
        rp = f.relpath
        parts = rp.split("/")
        if rp.endswith(("route.ts", "route.js", "route.tsx", "route.jsx")) and "app" in parts:
            findings.extend(_next_route(f))
        elif re.match(r"pages/api/.*\.(ts|js|tsx|jsx)$", rp):
            findings.extend(_next_pages_api(f))
        elif f.path.suffix.lower() in (".js", ".ts", ".mjs", ".cjs"):
            findings.extend(_express_routes(f))
            findings.extend(_node_raw_admin(f))
    return findings


def _is_public_path(relpath: str) -> bool:
    segs = [s.lower() for s in relpath.split("/")]
    return any(seg in PUBLIC_SEGMENTS or seg.startswith("[") and len(seg) < 6 for seg in segs)


def _next_route(f: ScanFile) -> list[Finding]:
    findings: list[Finding] = []
    if _is_public_path(f.relpath):
        return findings
    text = f.text
    handlers = [(m.group("method"), m.start()) for m in NEXT_HANDLER.finditer(text)]
    handlers += [(m.group("method"), m.start()) for m in NEXT_HANDLER_CONST.finditer(text)]
    for method, start in handlers:
        # body: from handler start to the next exported handler or EOF
        next_starts = [s for m in NEXT_HANDLER.finditer(text) for s in [m.start()] if s > start]
        next_starts += [s for m in NEXT_HANDLER_CONST.finditer(text) for s in [m.start()] if s > start]
        end = min(next_starts) if next_starts else len(text)
        body = text[start:end]
        if not AUTH_SIGNALS.search(body):
            line = line_of(text, start)
            findings.append(Finding(
                rule="authz/next-route-no-auth",
                category=Category.ACCESS_CONTROL,
                title=f"API route {method} {_route_path(f.relpath)} has no server-side auth",
                severity=Severity.HIGH,
                confidence=Confidence.LIKELY,
                description=(
                    f"The `{method}` handler in `{f.relpath}:{line}` never checks a session, token, or user. "
                    "Any anonymous caller who finds the URL can invoke it. Hiding UI elements does not "
                    "protect an endpoint — the API is the front door."
                ),
                remediation=(
                    "At the top of the handler, resolve the caller server-side — e.g. "
                    "`const { data: { user } } = await supabase.auth.getUser();` or "
                    "`const session = await getServerSession(authOptions);` — and return 401 when absent. "
                    "If the route is intentionally public, add a `reprove:ignore authz` comment."
                ),
                location=f"{f.relpath}:{line}",
                evidence=[Evidence(kind="code",
                                   detail=f"exported {method} handler with no auth signal (getServerSession/auth()/getUser/verifyToken…)",
                                   location=f"{f.relpath}:{line}")],
                verification_mode=VerificationMode.RESCAN,
                tags=["authz", "nextjs"],
                metadata={"method": method, "file": f.relpath},
            ))
    return findings


def _route_path(relpath: str) -> str:
    return "/" + re.sub(r"(^|/)app/|(^|/)route\.(ts|js|tsx|jsx)$", "", relpath).strip("/")


def _next_pages_api(f: ScanFile) -> list[Finding]:
    if _is_public_path(f.relpath):
        return []
    if AUTH_SIGNALS.search(f.text):
        return []
    return [Finding(
        rule="authz/pages-api-no-auth",
        category=Category.ACCESS_CONTROL,
        title=f"API route {_route_path(f.relpath)} has no server-side auth",
        severity=Severity.HIGH,
        confidence=Confidence.POSSIBLE,
        description=(f"`{f.relpath}` has no session/token check. Any anonymous caller reaching this "
                     "endpoint gets it executed."),
        remediation=("Resolve the session server-side (getServerSession/auth) and return 401 when absent, "
                     "or mark the route public with a `reprove:ignore authz` comment."),
        location=f.relpath,
        evidence=[Evidence(kind="code", detail="no auth signal found in file", location=f.relpath)],
        verification_mode=VerificationMode.RESCAN,
        tags=["authz", "nextjs"],
    )]


EXPRESS_ROUTE = re.compile(
    r"""app\s*\.\s*(?P<method>get|post|put|patch|delete|all)\s*\(\s*(?P<quote>['"`])(?P<path>.*?)(?P=quote)\s*,""",
    re.I,
)


def _express_routes(f: ScanFile) -> list[Finding]:
    findings: list[Finding] = []
    text = f.text
    for m in EXPRESS_ROUTE.finditer(text):
        path = m.group("path")
        segs = [s for s in path.split("/") if s]
        if any(seg.lower() in PUBLIC_SEGMENTS for seg in segs):
            continue
        # the remainder of the registration line: middleware chain before the handler
        line_end = text.find("\n", m.end())
        rest = text[m.end(): line_end if line_end != -1 else len(text)]
        if MIDDLEWARE_SIGNAL.search(rest) or AUTH_SIGNALS.search(rest):
            continue
        # sometimes middleware sits on the next line of a multi-line call
        window = text[m.end(): m.end() + 400]
        first_arg_zone = window.split("=>")[0].split("function")[0]
        if MIDDLEWARE_SIGNAL.search(first_arg_zone):
            continue
        line = line_of(text, m.start())
        findings.append(Finding(
            rule="authz/express-route-no-middleware",
            category=Category.ACCESS_CONTROL,
            title=f"Express route {m.group('method').upper()} {path} has no auth middleware",
            severity=Severity.HIGH,
            confidence=Confidence.POSSIBLE,
            description=(
                f"`app.{m.group('method')}('{path}', …)` at `{f.relpath}:{line}` is registered without an "
                "auth-looking middleware (e.g. requireAuth, isAuthenticated, passport). If the handler "
                "itself does not check the session, the route is open to anonymous callers."
            ),
            remediation=("Add auth middleware to the chain (`app.get(path, requireAuth, handler)`) or "
                         "verify the caller inside the handler; mark intentionally public routes with "
                         "`reprove:ignore authz`."),
            location=f"{f.relpath}:{line}",
            evidence=[Evidence(kind="code",
                               detail=f"route registration: app.{m.group('method')}('{path}', …) with no auth middleware detected",
                               location=f"{f.relpath}:{line}")],
            verification_mode=VerificationMode.RESCAN,
            tags=["authz", "express"],
        ))
    return findings


NODE_ADMIN_BLOCK = re.compile(r"""req\.url\s*(?:\.startsWith)?\s*\(?\s*['"`](?P<path>/api/(?:admin|internal)[^'"`]*)['"`]""")


def _balanced_block(text: str, start: int, max_len: int = 3000) -> str:
    """Return the { ... } block starting at the first '{' at/after `start`,
    honoring nesting, so we never scan into a neighbouring handler."""
    i = text.find("{", start)
    if i == -1:
        return text[start:start + max_len]
    depth = 0
    for j in range(i, min(len(text), i + max_len)):
        c = text[j]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return text[i:j + 1]
    return text[i:min(len(text), i + max_len)]


def _node_raw_admin(f: ScanFile) -> list[Finding]:
    """Raw node http servers: look for /api/admin* handling with no auth call nearby."""
    findings: list[Finding] = []
    text = f.text
    for m in NODE_ADMIN_BLOCK.finditer(text):
        block = _balanced_block(text, m.end())
        if AUTH_SIGNALS.search(block) or re.search(r"auth\s*\(\s*req|checkAuth|requireAuth", block):
            continue
        line = line_of(text, m.start())
        findings.append(Finding(
            rule="authz/node-admin-route-no-auth",
            category=Category.ACCESS_CONTROL,
            title=f"Admin endpoint {m.group('path')} handled without an auth check",
            severity=Severity.CRITICAL,
            confidence=Confidence.LIKELY,
            description=(
                f"The block handling `{m.group('path')}` at `{f.relpath}:{line}` has no auth call in its "
                "first lines. Admin surfaces are the highest-value target in any app — an unauthenticated "
                "one is usually the whole breach."
            ),
            remediation=("Check the caller before doing any work: resolve the session token, 401 when absent, "
                         "and verify an admin role — not just presence of a session."),
            location=f"{f.relpath}:{line}",
            evidence=[Evidence(kind="code",
                               detail=f"req.url block for {m.group('path')} with no auth call within the handler preamble",
                               location=f"{f.relpath}:{line}")],
            verification_mode=VerificationMode.RESCAN,
            tags=["authz"],
        ))
    return findings
