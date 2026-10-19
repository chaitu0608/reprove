"""IDOR (Insecure Direct Object Reference) analyzer — static heuristics.

IDOR is the most common *confirmed* breach class in vibe-coded apps:
`/api/orders/123` returns any user's order if the handler fetches by id
without scoping to the caller. Static heuristics here raise suspicion;
the dynamic two-user probe (dynamic/probe.py) turns suspicion into proof.

Patterns covered:
  * supabase-js:  .from('t').select(…).eq('id', …)  without .eq('user_id', …)
  * Next.js:      handler using params.id / searchParams id without ownership scoping
  * node/express: .find(x => x.id === id) / findOne({ _id: id }) without a user filter
  * SQL:          WHERE id = ? with no AND user_id = ? in the same query
"""

from __future__ import annotations

import re

from ..context import ScanContext, ScanFile, register
from ..models import (Category, Confidence, Evidence, Finding, Severity,
                      VerificationMode)
from ..util import line_of

OWNERSHIP_SIGNALS = re.compile(
    r"user_id|userId|owner_?id|ownerId|created_by|createdBy|auth\.uid\(\)|"
    r"currentUser|\buser\b|session\.user|account_id|accountId|\.id\s*===\s*user",
    re.I,
)
ID_PARAM = re.compile(r"(?:req\.params\.id|params\.id|context\.params\.id|searchParams\.get\(['\"]id['\"]\)|req\.query\.id)")

SUPABASE_QUERY = re.compile(
    r"\.from\(\s*['\"`](?P<table>[\w]+)['\"`]\s*\)(?P<chain>[\s\S]{0,400}?)(?=;|\n\s*\n|$)",
)

def _finding(f: ScanFile, line: int, rule: str, title: str, desc: str, remed: str,
             evidence_detail: str, sev: Severity = Severity.HIGH,
             conf: Confidence = Confidence.LIKELY, meta: dict | None = None) -> Finding:
    return Finding(
        rule=rule,
        category=Category.ACCESS_CONTROL,
        title=title,
        severity=sev,
        confidence=conf,
        description=desc,
        remediation=remed,
        location=f"{f.relpath}:{line}",
        evidence=[Evidence(kind="code", detail=evidence_detail, location=f"{f.relpath}:{line}")],
        verification_mode=VerificationMode.RESCAN,
        tags=["idor", "access-control"],
        metadata=meta or {},
    )


@register("idor")
def analyze_idor(ctx: ScanContext) -> list[Finding]:
    findings: list[Finding] = []
    for f in ctx.files:
        if f.is_built or f.path.suffix.lower() not in (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".vue"):
            continue
        findings.extend(_supabase_idor(f))
        findings.extend(_next_handler_idor(f))
        findings.extend(_find_by_id(f))
        findings.extend(_sql_id_lookup(f))
    return findings


def _supabase_idor(f: ScanFile) -> list[Finding]:
    out = []
    for m in SUPABASE_QUERY.finditer(f.text):
        chain = m.group("chain")
        if not re.search(r"\.eq\(\s*['\"`]id['\"`]", chain):
            continue
        if OWNERSHIP_SIGNALS.search(chain):
            continue
        line = line_of(f.text, m.start())
        out.append(_finding(
            f, line, "idor/supabase-fetch-by-id",
            f"Supabase query on `{m.group('table')}` fetches by id without ownership scoping",
            f"The query at `{f.relpath}:{line}` fetches a `{m.group('table')}` row by its id only. "
            "Ids are guessable/enumerable; without a `user_id = <caller>` filter, any authenticated "
            "(or even anonymous) caller can read another user's row.",
            "Scope the query to the caller: `.eq('id', id).eq('user_id', user.id)` — or better, rely on "
            "RLS with a policy `USING (auth.uid() = user_id)` so the database enforces it even if the "
            "query forgets. Reprove's IDOR fixer applies the `.eq('user_id', …)` scoping.",
            f".from('{m.group('table')}').…eq('id', …) chain has no user_id/user/owner condition",
        ))
    return out


def _next_handler_idor(f: ScanFile) -> list[Finding]:
    if not (f.relpath.endswith(("route.ts", "route.js")) and "app" in f.relpath.split("/")):
        return []
    if not ID_PARAM.search(f.text):
        return []
    # If the whole file scopes by an ownership signal near the id usage, skip.
    for m in ID_PARAM.finditer(f.text):
        window = f.text[max(0, m.start() - 500): m.end() + 700]
        if not OWNERSHIP_SIGNALS.search(window):
            line = line_of(f.text, m.start())
            return [_finding(
                f, line, "idor/route-fetch-by-id",
                "Route fetches a resource by id without checking the caller owns it",
                f"The handler at `{f.relpath}:{line}` reads an `id` from the request and fetches the "
                "resource without any ownership condition in scope. That is the classic IDOR shape: change "
                "the id, read someone else's data.",
                "After fetching, verify the row belongs to the caller (`row.user_id === user.id`) and "
                "return 404 otherwise; or push the constraint into the query / RLS policy. Reprove's "
                "dynamic probe confirms this the moment it is runnable.",
                f"params.id usage with no user_id/user/owner reference within the handler window",
            )]
    return []


FIND_BY_ID = re.compile(
    r"""(?P<coll>\w+)\.find\(\s*(?:function\s*)?\(?\s*(?P<el>\w+)\s*\)?\s*=>?\s*(?:\{\s*return\s+)?\2?\.id\s*===\s*(?P<id>[\w.]+)""",
    re.I,
)
FIND_ONE = re.compile(r"findOne\s*\(\s*\{\s*(?:_?id)\s*:\s*(?P<id>[\w.]+)\s*\}\s*\)")


def _find_by_id(f: ScanFile) -> list[Finding]:
    out = []
    for m in FIND_BY_ID.finditer(f.text):
        window = f.text[m.start(): m.end() + 200]
        if OWNERSHIP_SIGNALS.search(window):
            continue
        line = line_of(f.text, m.start())
        out.append(_finding(
            f, line, "idor/in-memory-find-by-id",
            f"`{m.group('coll')}.find(...)` looks up by id only",
            f"At `{f.relpath}:{line}` a record is looked up by id with no ownership clause "
            "(`&& row.userId === user.id`). Whoever supplies the id gets the row.",
            "Add the ownership clause to the lookup or check ownership right after fetching and 404 on "
            "mismatch. Reprove's IDOR fixer appends the ownership condition when it can identify the user variable.",
            f"lookup: {m.group(0)[:160]}",
        ))
    for m in FIND_ONE.finditer(f.text):
        window = f.text[max(0, m.start() - 200): m.end() + 200]
        if OWNERSHIP_SIGNALS.search(window):
            continue
        line = line_of(f.text, m.start())
        out.append(_finding(
            f, line, "idor/findone-by-id",
            "Database findOne by id without ownership scope",
            f"`findOne({{ _id: … }})` at `{f.relpath}:{line}` matches purely on id.",
            "Filter by both id and owner, or verify ownership after the fetch and return 404 on mismatch.",
            f"lookup: {m.group(0)[:160]}",
        ))
    return out


SQL_ID_LOOKUP = re.compile(
    r"""(?:query|execute|raw)\s*\(\s*[`'"](?P<sql>[^`'"]*(?:where|WHERE)[^`'"]*\bid\s*=[\s\S]{0,120}?)[`'"]""",
)


def _sql_id_lookup(f: ScanFile) -> list[Finding]:
    out = []
    for m in SQL_ID_LOOKUP.finditer(f.text):
        sql = m.group("sql")
        if re.search(r"user_id|owner", sql, re.I):
            continue
        line = line_of(f.text, m.start())
        out.append(_finding(
            f, line, "idor/sql-id-lookup",
            "SQL fetches a row by id with no owner constraint",
            f"The query at `{f.relpath}:{line}` selects by `id` without an owner condition. A caller who "
            "changes the id reads another user's row.",
            "Extend the WHERE clause: `SELECT … WHERE id = $1 AND user_id = $2` with the caller's id bound "
            "as a parameter.",
            f"query: {sql.strip()[:160]}",
            conf=Confidence.POSSIBLE,
        ))
    return out
