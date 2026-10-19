"""Supabase / Postgres RLS analyzer.

Parses SQL migrations and reasons about which tables are protected:

  1. tables that never get `ENABLE ROW LEVEL SECURITY`
  2. policies that are permissive (`USING (true)` / no predicate)
  3. user-data tables without a `user_id`-style ownership column

This is the flaw that turns "leaked anon key" (harmless by design) into
"anyone can read every row" (the breach you read about).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from ..context import ScanContext, register
from ..models import (Category, Confidence, Evidence, Finding, Severity,
                      VerificationMode)
from ..util import line_of

CREATE_TABLE = re.compile(
    r"create\s+table\s+(?:if\s+not\s+exists\s+)?(?P<name>[\w.\"]+)\s*\((?P<body>.*?)\)\s*;",
    re.I | re.S,
)
ENABLE_RLS = re.compile(r"alter\s+table\s+(?:only\s+)?(?P<name>[\w.\"]+)\s+enable\s+row\s+level\s+security", re.I)
DISABLE_RLS = re.compile(r"alter\s+table\s+(?:only\s+)?(?P<name>[\w.\"]+)\s+disable\s+row\s+level\s+security", re.I)
CREATE_POLICY = re.compile(
    r"create\s+policy\s+(?:\"(?P<qname>[^\"]+)\"|(?P<name>\S+))\s+on\s+(?P<table>[\w.\"]+)"
    r"(?P<rest>.*?);",
    re.I | re.S,
)
DROP_POLICY = re.compile(r"drop\s+policy\s+(?:if\s+exists\s+)?(?:\"(?P<qname>[^\"]+)\"|(?P<name>\S+))\s+on\s+(?P<table>[\w.\"]+)", re.I)
PERMISSIVE = re.compile(r"using\s*\(\s*(true|1\s*=\s*1)\s*\)", re.I)
HAS_PREDICATE = re.compile(r"using\s*\(|with\s+check\s*\(", re.I)
AUTH_UID = re.compile(r"auth\.uid\(\)|auth\.jwt\(\)|current_setting\s*\(", re.I)

OWNER_COLS = ("user_id", "owner_id", "created_by", "author_id", "account_id", "profile_id", "uid", "customer_id")
IGNORED_TABLES = {"schema_migrations", "supabase_migrations", "migrations", "spatial_ref_sys"}


@dataclass
class Table:
    name: str
    file: str
    line: int
    columns: list[str] = field(default_factory=list)
    rls_enabled: bool = False
    rls_disabled_explicitly: bool = False
    policies: list[dict] = field(default_factory=list)
    dropped_policies: set = field(default_factory=set)

    @property
    def short(self) -> str:
        return self.name.split(".")[-1].strip('"')


def _norm(name: str) -> str:
    return name.strip('"').lower()


def _strip_sql_comments(text: str) -> str:
    """Remove -- line comments and /* */ blocks so commented-out security
    statements cannot fool the parser (a real pattern in AI-generated SQL)."""
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    return re.sub(r"--[^\n]*", "", text)


def parse_migrations(ctx: ScanContext) -> dict[str, Table]:
    """Two-pass parse (order-independent across files): creates first, then state changes."""
    tables: dict[str, Table] = {}
    sql_files = [f for f in ctx.files if f.path.suffix.lower() == ".sql"]
    migration_files = [(f, _strip_sql_comments(f.text)) for f in sql_files
                       if "migration" in f.relpath.lower() or "supabase" in f.relpath.lower()]

    # pass 1: table definitions
    for f, text in migration_files:
        for m in CREATE_TABLE.finditer(text):
            name = _norm(m.group("name"))
            if name.split(".")[-1] in IGNORED_TABLES:
                continue
            body = m.group("body")
            cols = [c.lower() for c in re.findall(r"^\s*([A-Za-z_][\w]*)\s+[a-zA-Z]", body, re.M)]
            t = tables.get(name)
            if t is None:
                tables[name] = Table(name=name, file=f.relpath, line=line_of(f.text, m.start()), columns=cols)
            else:
                t.columns.extend(cols)

    # pass 2: RLS state + policies
    for f, text in migration_files:
        for m in ENABLE_RLS.finditer(text):
            if t := tables.get(_norm(m.group("name"))):
                t.rls_enabled = True
        for m in DISABLE_RLS.finditer(text):
            if t := tables.get(_norm(m.group("name"))):
                t.rls_disabled_explicitly = True
        for m in DROP_POLICY.finditer(text):
            if t := tables.get(_norm(m.group("table"))):
                t.dropped_policies.add((m.group("qname") or m.group("name") or "").lower())
        for m in CREATE_POLICY.finditer(text):
            t = tables.get(_norm(m.group("table")))
            if t:
                t.policies.append({
                    "name": m.group("qname") or m.group("name"),
                    "rest": m.group("rest"),
                    "file": f.relpath,
                    "line": line_of(text, m.start()),
                })
    return tables


def _has_owner_column(t: Table) -> bool:
    return any(oc in t.columns for oc in OWNER_COLS)


@register("rls")
def analyze_rls(ctx: ScanContext) -> list[Finding]:
    findings: list[Finding] = []
    tables = parse_migrations(ctx)

    for t in tables.values():
        if not t.rls_enabled:
            owner = _has_owner_column(t)
            findings.append(Finding(
                rule="rls/table-without-rls",
                category=Category.ACCESS_CONTROL,
                title=f"Supabase table `{t.short}` has RLS disabled",
                severity=Severity.CRITICAL,
                confidence=Confidence.LIKELY,
                description=(
                    f"`{t.name}` is defined at `{t.file}:{t.line}` and never gets "
                    "`ENABLE ROW LEVEL SECURITY`. With RLS off, Supabase's public (anon) key — which is "
                    "designed to be public and ships in every frontend — can read and modify this table "
                    "through the auto-generated REST API. If this table stores anything user-specific, "
                    "it is world-readable right now."
                ),
                remediation=(
                    "Add a migration enabling RLS and scoped policies: "
                    f"`ALTER TABLE {t.name} ENABLE ROW LEVEL SECURITY;` then "
                    + (f"`CREATE POLICY \"{t.short}_own\" ON {t.name} FOR ALL "
                       "USING (auth.uid() = user_id) WITH CHECK (auth.uid() = user_id);`"
                       if owner else
                       f"add a `user_id uuid REFERENCES auth.users(id)` column to {t.short} first, "
                       "then policies scoped to auth.uid(). "
                       "Reprove's RLS fixer generates this migration automatically.")
                ),
                location=f"{t.file}:{t.line}",
                evidence=[Evidence(kind="sql",
                                   detail=f"CREATE TABLE {t.name} with no matching ENABLE ROW LEVEL SECURITY; "
                                          f"columns: {', '.join(t.columns[:10])}",
                                   location=f"{t.file}:{t.line}")],
                verification_mode=VerificationMode.RESCAN,
                tags=["supabase", "rls"],
                metadata={"table": t.name, "has_owner_column": owner},
            ))

        for pol in t.policies:
            if pol["name"].lower() in t.dropped_policies:
                continue
            permissive = bool(PERMISSIVE.search(pol["rest"])) or not HAS_PREDICATE.search(pol["rest"])
            scoped = bool(AUTH_UID.search(pol["rest"]))
            if permissive and not scoped:
                findings.append(Finding(
                    rule="rls/permissive-policy",
                    category=Category.ACCESS_CONTROL,
                    title=f"RLS policy `{pol['name']}` on `{t.short}` allows everyone",
                    severity=Severity.HIGH,
                    confidence=Confidence.LIKELY,
                    description=(
                        f"Policy `{pol['name']}` on `{t.name}` ({pol['file']}:{pol['line']}) is permissive: "
                        "it matches every row for every caller (`USING (true)` or no predicate). RLS is "
                        "technically enabled, but this policy punches a hole straight through it."
                    ),
                    remediation=(
                        f"Scope the policy to the owner: `DROP POLICY IF EXISTS \"{pol['name']}\" ON {t.name};` "
                        f"then `CREATE POLICY \"{pol['name']}_scoped\" ON {t.name} FOR ALL "
                        "USING (auth.uid() = user_id) WITH CHECK (auth.uid() = user_id);`"
                        + ("" if _has_owner_column(t) else " — this table needs a user_id column first.")
                    ),
                    location=f"{pol['file']}:{pol['line']}",
                    evidence=[Evidence(kind="sql", detail=f"policy expression: {pol['rest'].strip()[:200]}",
                                       location=f"{pol['file']}:{pol['line']}")],
                    verification_mode=VerificationMode.RESCAN,
                    tags=["supabase", "rls"],
                    metadata={"table": t.name, "policy": pol["name"]},
                ))

    return findings
