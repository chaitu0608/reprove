"""Secret exposure analyzer.

Catches the #1 vibe-coding disaster: secrets that reach the client (or the
repo). Key insight beyond regex matching: *where* a secret lives determines
severity. A service-role key inside a client bundle is game over; the same
string in a server-side .env is normal.

Exposure model (deliberately conservative — false CRITICALs destroy trust):
  client        — provably browser-reachable (public/, dist/, built bundle,
                  client env prefix, "use client" directive)
  repo          — committed to source control (bad, rotate; not necessarily public)
  server        — server-side location (informational only)
"""

from __future__ import annotations

import re
from typing import Optional

from ..context import ScanContext, ScanFile, register
from ..models import (Category, Confidence, Evidence, Finding, Severity,
                      VerificationMode)
from ..util import decode_jwt_payload, is_probably_minified, line_of, looks_like_secret, shannon_entropy

SECRET_PATTERNS: list[tuple[str, str, re.Pattern]] = [
    ("openai-key", "OpenAI API key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{32,}\b")),
    ("anthropic-key", "Anthropic API key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{24,}\b")),
    ("stripe-secret", "Stripe secret key", re.compile(r"\bsk_live_[A-Za-z0-9]{16,}\b")),
    ("aws-access-key", "AWS access key id", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("github-token", "GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("slack-token", "Slack token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("google-api-key", "Google API key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("jwt", "JWT / Supabase key", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")),
]

CLIENT_ENV_PREFIXES = ("NEXT_PUBLIC_", "VITE_", "REACT_APP_", "PUBLIC_", "EXPO_PUBLIC_", "NUXT_PUBLIC_", "GATSBY_")
CLIENT_DIRS = {"public", "static", "assets", "out", "dist", "build", ".output"}
SERVER_DIRS = {"api", "server", "backend", "functions", "scripts", "prisma", "drizzle", "migrations", "supabase"}
FAKE_MARKERS = ("example", "fake", "dummy", "placeholder", "your-", "your_", "xxx", "changeme", "changeme", "test_key", "sample", "redacted")


def _is_fake(s: str) -> bool:
    low = s.lower()
    return any(m in low for m in FAKE_MARKERS)


def _line_text(text: str, idx: int) -> str:
    start = text.rfind("\n", 0, idx) + 1
    end = text.find("\n", idx)
    return text[start:end if end != -1 else len(text)]


def classify_exposure(f: ScanFile, idx: int, literal: str) -> tuple[str, str]:
    """Return (exposure, rationale). exposure in {client, repo, server}."""
    parts = set(f.relpath.split("/"))
    line = _line_text(f.text, idx)

    # 1. built artifacts — inlined by the bundler, shipped to every visitor
    if parts & CLIENT_DIRS and f.is_built:
        if is_probably_minified(f.text):
            return "client", f"embedded in a built client bundle ({f.relpath}) — served to every visitor"
        return "client", f"lies inside a built/public output directory ({f.relpath})"

    # 2. client-exposed env prefixes — bundlers inline these into the browser payload
    for pref in CLIENT_ENV_PREFIXES:
        if re.search(re.escape(pref) + r"[A-Z0-9_]*\s*[:=]", line, re.I) or pref in line.upper():
            return "client", f"referenced through a client-exposed env var on {f.relpath}:{line_of(f.text, idx)}"

    # 3. explicit client directives / purely-client file types in client dirs
    if "'use client'" in f.text or '"use client"' in f.text:
        return "client", f"file is a client component ({f.relpath})"
    if parts & {"public", "static"}:
        return "client", f"file is served statically from {f.relpath}"

    # 4. server-side locations — informational
    if parts & SERVER_DIRS:
        return "server", f"server-side location ({f.relpath})"

    # 5. everything else: committed to the repo
    return "repo", f"committed in the repository ({f.relpath})"


@register("secrets")
def analyze_secrets(ctx: ScanContext) -> list[Finding]:
    findings: list[Finding] = []
    for f in ctx.files:
        text = f.text
        seen: set[str] = set()  # per-file: the same secret in .env AND public/config.js are different (severity) findings

        # 1. known key shapes -----------------------------------------------------
        for rule_name, label, pattern in SECRET_PATTERNS:
            for m in pattern.finditer(text):
                literal = m.group(0)
                if literal in seen or _is_fake(literal):
                    continue
                if rule_name == "jwt":
                    payload = decode_jwt_payload(literal)
                    if not payload:
                        continue
                    seen.add(literal)
                    if payload.get("role") == "service_role":
                        findings.append(_service_role_finding(f, literal, m.start()))
                    continue
                seen.add(literal)
                findings.append(_secret_finding(f, label, rule_name, literal, m.start()))

        # 2. committed .env --------------------------------------------------------
        if f.path.name.startswith(".env") and not f.path.name.endswith((".example", ".sample", ".template")):
            keys = _env_keys(text)
            findings.append(Finding(
                rule="secrets/committed-env",
                category=Category.SECRETS,
                title=f"Environment file committed to the repository: {f.relpath}",
                severity=Severity.HIGH,
                confidence=Confidence.CONFIRMED,
                description=(
                    f"`{f.relpath}` is checked into version control with {len(keys)} variable(s): "
                    f"{', '.join(keys[:6])}{'…' if len(keys) > 6 else ''}. Everything in it is available to "
                    "anyone with repo access — and git history keeps it even after deletion."
                ),
                remediation=(
                    "Delete the file, purge it from git history (git filter-repo or BFG), add `.env` to "
                    ".gitignore, commit a `.env.example` with blank values instead, and ROTATE every "
                    "credential that was in the file — deletion does not un-leak anything."
                ),
                location=f.relpath,
                evidence=[Evidence(kind="code",
                                   detail=f"committed env file; keys: {', '.join(keys[:8])}",
                                   location=f.relpath)],
                verification_mode=VerificationMode.RESCAN,
                tags=["secrets", "git"],
            ))

        # 3. high-entropy values assigned to suspicious names ----------------------
        if not f.is_built:
            for m in re.finditer(r"""(?P<name>[A-Za-z_][A-Za-z0-9_]{2,40})\s*[:=]\s*["'`](?P<val>[^"'`\s]{24,200})["'`]""", text):
                name, val = m.group("name"), m.group("val")
                if val in seen or _is_fake(val):
                    continue
                if val.startswith("eyJ") and decode_jwt_payload(val) is not None:
                    continue  # JWTs are handled (and classified) by the jwt branch above
                upper = name.upper()
                if not any(k in upper for k in ("KEY", "SECRET", "TOKEN", "PASSWORD", "PASSWD", "CREDENTIAL")):
                    continue
                line_txt = _line_text(text, m.start())
                if any(pref in line_txt.upper() for pref in CLIENT_ENV_PREFIXES):
                    continue  # covered by env handling; value itself may be benign
                if not looks_like_secret(val):
                    continue
                seen.add(val)
                exposure, rationale = classify_exposure(f, m.start("val"), val)
                if exposure == "server":
                    continue  # server-side random-looking secret: noise
                masked = val[:6] + "…" + val[-4:]
                line = line_of(text, m.start("val"))
                findings.append(Finding(
                    rule="secrets/high-entropy",
                    category=Category.SECRETS,
                    title=f"Possible hardcoded secret in `{name}`",
                    severity=Severity.MEDIUM if exposure == "repo" else Severity.HIGH,
                    confidence=Confidence.POSSIBLE,
                    description=(
                        f"`{name}` at `{f.relpath}:{line}` holds a high-entropy value ({rationale}). "
                        f"Detected value (masked): `{masked}`. Random-looking values assigned to "
                        "key/token/secret-style names usually are credentials."
                    ),
                    remediation=(
                        "If this is a real credential: move it to a server-only environment variable and rotate it. "
                        "If it is test data or a public identifier, add a `# reprove:ignore` comment and it will be skipped."
                    ),
                    location=f"{f.relpath}:{line}",
                    evidence=[Evidence(kind="code", detail=f"entropy={shannon_entropy(val):.2f}; exposure={exposure}",
                                       location=f"{f.relpath}:{line}")],
                    verification_mode=VerificationMode.RESCAN,
                    tags=["secrets", exposure],
                ))

    return findings


def _env_keys(text: str) -> list[str]:
    return re.findall(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=", text, re.M)


def _secret_finding(f: ScanFile, label: str, rule_name: str, literal: str, idx: int) -> Finding:
    line = line_of(f.text, idx)
    exposure, rationale = classify_exposure(f, idx, literal)
    masked = literal[:8] + "…" + literal[-4:] if len(literal) > 16 else "…"
    is_client = exposure == "client"
    severity = Severity.CRITICAL if is_client else Severity.HIGH
    confidence = Confidence.CONFIRMED if exposure == "client" else Confidence.LIKELY

    desc = (
        f"A {label} is hardcoded at `{f.relpath}:{line}` ({rationale}). "
        + ("This value ships to every visitor's browser — anyone can open devtools and use it. "
           if is_client else
           "It is stored in source control, where it lives in git history forever. ")
        + f"Detected value (masked): `{masked}`"
    )
    return Finding(
        rule=f"secrets/{rule_name}",
        category=Category.SECRETS,
        title=f"{label} exposed ({exposure})",
        severity=severity,
        confidence=confidence,
        description=desc,
        remediation=(
            "Move the usage behind a server-side endpoint (API route, edge function, or backend handler), "
            "reference it via a server-only environment variable, and ROTATE the credential immediately — "
            "removing the string does not un-expose it. If this powered an LLM call from the browser, "
            "proxy the call through your server so the key never ships."
        ),
        location=f"{f.relpath}:{line}",
        evidence=[Evidence(kind="bundle" if "bundle" in rationale else "code",
                           detail=f"{label}; exposure={exposure}; {rationale}",
                           location=f"{f.relpath}:{line}")],
        verification_mode=VerificationMode.RESCAN,
        tags=["secrets", exposure],
        metadata={"exposure": exposure, "literal_len": len(literal)},
    )


def _service_role_finding(f: ScanFile, literal: str, idx: int) -> Finding:
    line = line_of(f.text, idx)
    exposure, rationale = classify_exposure(f, idx, literal)
    is_client = exposure == "client"
    return Finding(
        rule="secrets/supabase-service-role",
        category=Category.SECRETS,
        title="Supabase service_role key exposed",
        severity=Severity.CRITICAL,
        confidence=Confidence.CONFIRMED,
        description=(
            f"A Supabase `service_role` JWT is present at `{f.relpath}:{line}` ({rationale}). "
            "This key BYPASSES ROW LEVEL SECURITY ENTIRELY — even if your policies are perfect, anyone "
            "holding it can read, modify, and delete every row in every table. "
            + ("It is exposed to every visitor of the deployed app. " if is_client else "")
        ),
        remediation=(
            "Remove the key from the code, rotate it in Supabase → Project Settings → API (rotation "
            "invalidates the leaked key), and keep service-role usage exclusively inside trusted "
            "server/edge functions behind authentication."
        ),
        location=f"{f.relpath}:{line}",
        evidence=[Evidence(kind="code",
                           detail=f"JWT payload contains \"role\": \"service_role\"; exposure={exposure}",
                           location=f"{f.relpath}:{line}")],
        verification_mode=VerificationMode.RESCAN,
        tags=["secrets", "supabase", exposure],
        metadata={"exposure": exposure},
    )
