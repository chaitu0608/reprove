"""Injection & XSS analyzer (pattern + data-flow shaped).

Rules:
  * SQL built by string concatenation / template interpolation
  * shell execution with interpolated input
  * XSS sinks: dangerouslySetInnerHTML, innerHTML=, document.write, v-html
  * eval / new Function
"""

from __future__ import annotations

import re

from ..context import ScanContext, ScanFile, register
from ..models import Category, Confidence, Evidence, Finding, Severity, VerificationMode
from ..util import line_of

SQL_START = re.compile(r"\b(select|insert\s+into|update|delete\s+from)\b", re.I)
SQL_CONCAT = re.compile(
    r'(?P<expr>"[^"\n]{0,300}"\s*\+\s*[A-Za-z_$][\w.\[\]]*'
    r"|'[^'\n]{0,300}'\s*\+\s*[A-Za-z_$][\w.\[\]]*"
    r"|`[^`\n]{0,300}\$\{[^}]+\}[^`\n]{0,300}`)"
)
SQL_CALL = re.compile(r"(?:query|execute|raw|exec|prepare)\s*\(")

SHELL_EXEC = re.compile(r"""\b(exec|execSync|spawn|spawnSync|system|popen)\s*\(\s*(?P<expr>[^)]{0,200})\)""")
INTERPOLATION = re.compile(r"""\+\s*[A-Za-z_$]|\$\{|\+\s*req\.|`\s*\+""")

XSS_SINKS = [
    ("dangerouslySetInnerHTML", re.compile(r"dangerouslySetInnerHTML"), Severity.HIGH),
    ("innerHTML assignment", re.compile(r"\.innerHTML\s*="), Severity.HIGH),
    ("document.write", re.compile(r"document\.write\s*\("), Severity.MEDIUM),
    ("v-html", re.compile(r"v-html\s*="), Severity.MEDIUM),
    ("eval()", re.compile(r"(?<![\w.])eval\s*\("), Severity.HIGH),
    ("new Function()", re.compile(r"new\s+Function\s*\("), Severity.HIGH),
]

USER_INPUT_HINTS = re.compile(
    r"req\.(body|query|params)|request\.(json|formData|text)|searchParams|"
    r"props\.|useState|input|message|prompt|content|comment|bio|name\b",
    re.I,
)


def _finding(f: ScanFile, line: int, rule: str, title: str, severity: Severity,
             confidence: Confidence, desc: str, remed: str, evidence: str,
             kind: str = "code", cwe: str = "") -> Finding:
    return Finding(
        rule=rule,
        category=Category.XSS if "xss" in rule or "html" in rule else Category.INJECTION,
        title=title,
        severity=severity,
        confidence=confidence,
        description=desc,
        remediation=remed,
        location=f"{f.relpath}:{line}",
        evidence=[Evidence(kind=kind, detail=evidence, location=f"{f.relpath}:{line}")],
        verification_mode=VerificationMode.RESCAN,
        tags=["injection"] + ([cwe] if cwe else []),
    )


@register("injection")
def analyze_injection(ctx: ScanContext) -> list[Finding]:
    out: list[Finding] = []
    for f in ctx.files:
        if f.is_built or f.path.suffix.lower() not in (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".vue", ".py", ".rb", ".php"):
            continue
        out.extend(_sql_concat(f))
        out.extend(_shell(f))
        out.extend(_xss(f))
    return out


def _sql_concat(f: ScanFile) -> list[Finding]:
    out = []
    text = f.text
    for m in SQL_CONCAT.finditer(text):
        expr = m.group("expr")
        if not SQL_START.search(expr):
            continue
        # must be near a query call to count (avoid random string building)
        window = text[max(0, m.start() - 200): m.end() + 300]
        if not SQL_CALL.search(window):
            continue
        has_user_input = bool(re.search(r"req\.|params|query|input|search|\bq\b", window))
        line = line_of(text, m.start())
        out.append(_finding(
            f, line, "injection/sql-string-concat",
            "SQL built by string concatenation",
            Severity.HIGH,
            Confidence.LIKELY if has_user_input else Confidence.POSSIBLE,
            f"At `{f.relpath}:{line}` a SQL statement is assembled from string pieces"
            + (" that include request-provided input" if has_user_input else "") + ". "
            "An attacker controls the query: `' OR 1=1 --` reads every row; stacked queries and UNIONs do worse. "
            f"Excerpt: `{expr.strip()[:160]}`",
            "Use parameterized queries: pass values separately (`db.query('… WHERE name = $1', [name])`) so "
            "the driver escapes them. Never interpolate input into SQL text. Reprove's fixer rewrites simple "
            "concat shapes to parameterized form.",
            f"concatenated SQL expression: {expr.strip()[:200]}",
            cwe="cwe-89",
        ))
    return out


def _shell(f: ScanFile) -> list[Finding]:
    out = []
    for m in SHELL_EXEC.finditer(f.text):
        expr = m.group("expr")
        if not INTERPOLATION.search(expr):
            continue
        line = line_of(f.text, m.start())
        out.append(_finding(
            f, line, "injection/command-exec-interpolation",
            f"Shell command built with interpolated input ({m.group(1)})",
            Severity.HIGH,
            Confidence.POSSIBLE,
            f"`{m.group(1)}(…)` at `{f.relpath}:{line}` interpolates dynamic values into a shell command. "
            "If any part is attacker-influenced, this is remote code execution.",
            "Avoid the shell: use array-form exec (`execFile('git', ['log', userRef])` without shell) and "
            "validate/allowlist inputs.",
            f"expression: {expr.strip()[:200]}",
            kind="code",
        ))
    return out


def _xss(f: ScanFile) -> list[Finding]:
    out = []
    for label, pattern, severity in XSS_SINKS:
        for m in pattern.finditer(f.text):
            line = line_of(f.text, m.start())
            window = f.text[max(0, m.start() - 300): m.end() + 300]
            fed_by_user = bool(USER_INPUT_HINTS.search(window))
            conf = Confidence.LIKELY if fed_by_user else Confidence.POSSIBLE
            rule = "xss/unsafe-html-sink" if "html" in label.lower() or "innerHTML" in label else "injection/dangerous-sink"
            out.append(_finding(
                f, line, rule,
                f"Unsafe HTML/JS sink: {label}",
                severity,
                conf,
                f"`{label}` at `{f.relpath}:{line}` renders or executes content directly as HTML/JS"
                + (" and the surrounding code touches user-controlled values — this is the XSS shape"
                   if fed_by_user else "") + ". If any attacker-controlled text reaches this sink, "
                "they run script in your users' sessions (steal tokens, act as the user).",
                "Render untrusted data as text (React does this by default), or sanitize with DOMPurify "
                "before the sink; never eval user input.",
                f"sink: {label}; user-input signals nearby: {fed_by_user}",
                cwe="cwe-79",
            ))
    return out
