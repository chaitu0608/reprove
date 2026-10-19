"""Dynamic exploit probes — the "prove it" layer.

Two-user probe: create identity A and identity B, give A a resource, then
try to read A's resource as B (and as anonymous). If it works, that is not
a suspicious pattern anymore — it is a demonstrated breach with a
reproducible request, recorded as an ExploitSpec.

The same ExploitSpec is later replayed by patch/verifier.py against the
patched app. One executor (`execute_exploit`) drives both, so verification
exercises exactly the attack that was discovered.
"""

from __future__ import annotations

import re
import time
import uuid
from dataclasses import dataclass, field
from typing import Optional

from ..context import ScanContext
from ..models import (Category, Confidence, Evidence, ExploitSpec, Finding,
                      Severity)
from ..util import HttpClient
from .sandbox import AppSandbox, detect_start_command

# ---- route mining -----------------------------------------------------------------

PATH_LITERAL = re.compile(r"""['"`](?P<path>/(?:api|graphql|v\d+|search|users|orders|items|posts|todos|admin|internal)[\w\-/:.\[\]]*)['"`]""")
NEXT_ROUTE_FILE = re.compile(r"(?:^|/)app/(?P<path>.*?)/route\.(?:ts|js|tsx|jsx)$")


def mine_routes(ctx: ScanContext) -> list[str]:
    routes: set[str] = set()
    for f in ctx.files:
        if f.is_built:
            continue
        if f.path.suffix.lower() in (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".py"):
            for m in PATH_LITERAL.finditer(f.text):
                p = m.group("path").rstrip("'\"`")
                p = p.split("?")[0].rstrip("/,")
                if p and not p.endswith((".js", ".css", ".png", ".svg", ".ico")):
                    routes.add(p)
        nm = NEXT_ROUTE_FILE.search(f.relpath)
        if nm:
            segs = [s for s in nm.group("path").split("/") if s]
            segs = [f":{s[1:-1]}" if s.startswith("[") and s.endswith("]") else s for s in segs]
            if segs:
                routes.add("/api/" + "/".join(segs))
    return sorted(routes)


# ---- exploit spec execution (shared with verifier) ---------------------------------

_TEMPLATE = re.compile(r"\{\{\s*([\w.]+)\s*\}\}")


def _sub(value, captures: dict):
    if isinstance(value, str):
        def rep(m):
            return str(captures.get(m.group(1), m.group(0)))
        return _TEMPLATE.sub(rep, value)
    if isinstance(value, dict):
        return {k: _sub(v, captures) for k, v in value.items()}
    if isinstance(value, list):
        return [_sub(v, captures) for v in value]
    return value


def _extract(body, dotted: str):
    cur = body
    for part in dotted.lstrip("$.").split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        elif isinstance(cur, list) and part.isdigit() and int(part) < len(cur):
            cur = cur[int(part)]
        else:
            return None
    return cur


@dataclass
class StepResult:
    name: str
    status: int
    detail: str


@dataclass
class ExploitRun:
    verdict: str                 # "exploit-succeeded" | "exploit-blocked" | "setup-failed"
    steps: list[StepResult] = field(default_factory=list)
    note: str = ""
    final_status: int = 0
    final_body: str = ""

    def to_evidence(self) -> list[Evidence]:
        ev = []
        for s in self.steps:
            ev.append(Evidence(kind="http-exchange", detail=f"{s.name}: {s.detail}",
                               location=f"probe step {s.name}"))
        if self.final_body:
            ev.append(Evidence(kind="http-exchange",
                               detail=f"final response body: {self.final_body[:500]}",
                               location="probe"))
        return ev


def execute_exploit(http: HttpClient, base_url: str, spec: ExploitSpec) -> ExploitRun:
    """Run the exploit steps. Returns whether the attack still succeeds."""
    captures: dict[str, str] = {"base": base_url}
    results: list[StepResult] = []
    final_status = 0
    final_body = ""

    for i, step in enumerate(spec.steps):
        name = step.get("name", f"step-{i}")
        method = step.get("method", "GET")
        url = _sub(step.get("url", ""), captures)
        if not url.startswith("http"):
            url = base_url + url
        headers = _sub(step.get("headers", {}), captures)
        json_body = _sub(step.get("json"), captures)
        expect = step.get("expect_status")

        r = http.request(method, url, json_body=json_body, headers=headers)
        detail = f"{method} {url} → {r.status}" + (f" (error: {r.error})" if r.error else "")
        results.append(StepResult(name=name, status=r.status, detail=detail))

        if r.error:
            return ExploitRun("setup-failed", results, note=f"request error on '{name}': {r.error}")

        for key, path in (step.get("capture") or {}).items():
            parsed = r.json()
            if parsed is not None:
                val = _extract(parsed, path)
                if val is not None:
                    captures[key] = str(val)

        is_final = bool(step.get("final")) or i == len(spec.steps) - 1
        if is_final:
            final_status, final_body = r.status, r.body
            break
        if expect and r.status not in expect:
            return ExploitRun("setup-failed", results,
                              note=f"setup step '{name}' expected {expect}, got {r.status}")

    success = _check_success(spec.success_if, final_status, final_body, captures)
    return ExploitRun("exploit-succeeded" if success else "exploit-blocked",
                      results, final_status=final_status, final_body=final_body)


def _check_success(cond: dict, status: int, body: str, captures: dict) -> bool:
    if not cond:
        return False
    statuses = cond.get("status_in") or []
    if statuses and status not in statuses:
        return False
    needle = cond.get("body_contains")
    if needle is not None:
        resolved = _sub(needle, captures)
        if resolved not in body:
            return False
    any_of = cond.get("body_contains_any") or []
    if any_of:
        resolved = [_sub(x, captures) for x in any_of]
        if not any(x in body for x in resolved):
            return False
    return True


# ---- the probe engine --------------------------------------------------------------

TOKEN_PATHS = ("$.token", "$.access_token", "$.jwt", "$.data.token", "$.data.access_token",
               "$.session.access_token", "$.session.token", "$.user.token", "$.accessToken")
ID_PATHS = ("$.id", "$._id", "$.data.id", "$.data._id", "$.order.id", "$.orderId",
            "$.data.orderId", "$.item.id", "$.data.item.id")


@dataclass
class _Identity:
    name: str
    email: str
    token: Optional[str] = None


class TwoUserProbe:
    def __init__(self, base_url: str, routes: list[str], progress=None, budget_s: float = 90.0):
        self.base_url = base_url
        self.routes = routes
        self.http = HttpClient(timeout=5.0)
        self.progress = progress or (lambda m: None)
        self.deadline = time.time() + budget_s
        self.marker = "RP-" + uuid.uuid4().hex[:10]
        self.notes: list[str] = []
        self.token_path = "$.token"
        self.id_path = "$.id"
        self.signup_ep: Optional[str] = None
        self.collection_ep: Optional[str] = None
        self._identities: tuple[Optional[_Identity], Optional[_Identity], list[str]] = (None, None, [])

    # -- low-level helpers -------------------------------------------------------------

    def _get(self, path: str, token: Optional[str] = None):
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        return self.http.request("GET", self.base_url + path, headers=headers)

    def _post(self, path: str, body: dict, token: Optional[str] = None):
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        return self.http.request("POST", self.base_url + path, json_body=body, headers=headers)

    def _find_token(self, resp) -> Optional[str]:
        parsed = resp.json()
        if parsed is None:
            return None
        for p in TOKEN_PATHS:
            v = _extract(parsed, p)
            if isinstance(v, str) and len(v) > 8:
                self.token_path = p
                return v
        return None

    def _find_id(self, resp) -> Optional[str]:
        parsed = resp.json()
        if parsed is None:
            return None
        for p in ID_PATHS:
            v = _extract(parsed, p)
            if v is not None and str(v):
                self.id_path = p
                return str(v)
        return None

    # -- phases --------------------------------------------------------------------------

    def run(self) -> tuple[list[Finding], dict]:
        findings: list[Finding] = []
        meta: dict = {"ran": True, "marker": self.marker, "routes_mined": len(self.routes),
                      "users": {}, "notes": self.notes}

        self._signup()
        a, b, _eps = self._identities
        meta["users"] = {"a": getattr(a, "email", None), "b": getattr(b, "email", None)}
        if not (a and a.token and b and b.token):
            self.notes.append("could not obtain two authenticated identities — skipping IDOR probe")
            findings.extend(self._anonymous_sweep())
            return findings, meta

        self.progress(f"probe: two identities live ({a.email}, {b.email})")

        created = self._create_resource(a)
        if created:
            collection, resource_id = created
            self.collection_ep = collection
            meta["resource"] = {"route": collection, "id": resource_id}
            findings.extend(self._idor_check(collection, resource_id))
        else:
            self.notes.append("no writable collection discovered — skipping IDOR probe")

        findings.extend(self._anonymous_sweep())
        return findings, meta

    def _signup(self):
        eps = [r for r in self.routes if ("signup" in r or "register" in r) and "login" not in r]
        eps += [r for r in self.routes if "login" in r]
        seen: set[str] = set()
        eps = [e for e in eps if not (e in seen or seen.add(e))]
        if not eps:
            self.notes.append("no signup/login route mined — cannot create identities")
            return

        identities: list[_Identity] = []
        for label in ("a", "b"):
            email = f"reprove.{label}.{self.marker.lower()}@example.org"
            ident = _Identity(name=label, email=email)
            for ep in eps:
                r = self._post(ep, {"email": email, "password": "Reprove!Test123",
                                    "username": email.split("@")[0]})
                if r.status in (200, 201, 204):
                    ident.token = self._find_token(r)
                    if ident.token:
                        self.signup_ep = ep
                        break
                    alt = ep.replace("signup", "login").replace("register", "login")
                    if alt != ep:
                        lr = self._post(alt, {"email": email, "password": "Reprove!Test123"})
                        if lr.status in (200, 201):
                            t = self._find_token(lr)
                            if t:
                                ident.token = t
                                self.signup_ep = ep
                                break
            identities.append(ident)
        self._identities = (identities[0], identities[1], eps)

    def _create_resource(self, a: _Identity) -> Optional[tuple[str, str]]:
        banned = ("auth", "login", "signup", "register", "health", "admin", "internal", "search")
        candidates = [r for r in self.routes
                      if r.count("/") >= 2 and not any(b in r.lower() for b in banned) and ":" not in r]
        body = {"item": self.marker, "name": self.marker, "title": self.marker,
                "content": self.marker, "text": self.marker, "body": self.marker}
        for route in candidates:
            if time.time() > self.deadline:
                break
            r = self._post(route, body, token=a.token)
            if r.status in (200, 201):
                rid = self._find_id(r)
                if rid:
                    self.progress(f"probe: identity A created resource {rid} via {route}")
                    return route, rid
        return None

    def _detail_candidates(self, collection: str, rid: str) -> list[str]:
        cands = []
        for r in self.routes:
            if ":" in r or (r.endswith("/") and len(r.split("/")) >= 3 and "auth" not in r):
                patched = re.sub(r":[A-Za-z_]\w*", rid, r)
                if patched.endswith("/"):
                    patched += rid
                cands.append(patched)
        cands.append(f"{collection.rstrip('/')}/{rid}")
        seen: set[str] = set()
        return [c for c in cands if not (c in seen or seen.add(c))]

    def _idor_check(self, collection: str, rid: str) -> list[Finding]:
        b = self._identities[1]
        findings = []
        for detail in self._detail_candidates(collection, rid):
            r_b = self._get(detail, token=b.token)
            stole = r_b.status == 200 and (self.marker in r_b.body or rid in r_b.body)
            r_anon = self._get(detail)
            anon_read = r_anon.status == 200 and (self.marker in r_anon.body or rid in r_anon.body)

            if anon_read:
                findings.append(self._anon_read_finding(detail, r_anon))
            if stole and not anon_read:
                findings.append(self._idor_finding(detail, r_b))
            if stole or anon_read:
                break
        return findings

    # -- finding builders -------------------------------------------------------------------

    def _spec_base_steps(self) -> list[dict]:
        steps = [
            {"name": "signup_a", "method": "POST", "url": self.signup_ep,
             "json": {"email": f"reprove.a.{self.marker.lower()}@example.org",
                      "password": "Reprove!Test123",
                      "username": f"reprove.a.{self.marker.lower()}"},
             "capture": {"token_a": self.token_path},
             "expect_status": [200, 201, 204]},
            {"name": "signup_b", "method": "POST", "url": self.signup_ep,
             "json": {"email": f"reprove.b.{self.marker.lower()}@example.org",
                      "password": "Reprove!Test123",
                      "username": f"reprove.b.{self.marker.lower()}"},
             "capture": {"token_b": self.token_path},
             "expect_status": [200, 201, 204]},
            {"name": "create_resource_as_a", "method": "POST", "url": self.collection_ep,
             "headers": {"Authorization": "Bearer {{token_a}}"},
             "json": {"item": self.marker, "name": self.marker, "title": self.marker},
             "capture": {"resource_id": self.id_path},
             "expect_status": [200, 201]},
        ]
        return steps

    def _idor_finding(self, detail: str, r_b) -> Finding:
        steps = self._spec_base_steps()
        steps.append({"name": "read_other_users_resource", "method": "GET",
                      "url": detail, "headers": {"Authorization": "Bearer {{token_b}}"},
                      "final": True})
        spec = ExploitSpec(
            steps=steps,
            success_if={"status_in": [200], "body_contains_any": ["{{resource_id}}", self.marker]},
            description=f"User B reads user A's resource at {detail}",
        )
        return Finding(
            rule="access-control/idor-confirmed",
            category=Category.ACCESS_CONTROL,
            title=f"IDOR confirmed: user B can read user A's data via GET {detail}",
            severity=Severity.CRITICAL,
            confidence=Confidence.CONFIRMED,
            description=(
                "Reprove created account A, stored a marker resource, then signed in as a different account B "
                f"and fetched A's resource by its id: HTTP {r_b.status} with A's data in the body. The handler "
                "fetches by id without verifying ownership — the classic IDOR that leaks every user's data to "
                "every other user."
            ),
            remediation=(
                "Scope the fetch to the caller: append an ownership filter (`AND user_id = :current_user` / "
                "`.eq('user_id', user.id)`) and return 404 on mismatch. Add an RLS policy "
                "`USING (auth.uid() = user_id)` as a database-level backstop so a future query mistake cannot "
                "re-open the hole."
            ),
            location=f"GET {detail}",
            evidence=[Evidence(kind="http-exchange",
                               detail=f"user B GET {detail} → {r_b.status}; body excerpt: {r_b.body[:200]}",
                               location=detail,
                               request={"method": "GET", "url": detail,
                                        "headers": {"Authorization": "Bearer <user B token>"}},
                               response={"status": r_b.status, "body": r_b.body[:500]})],
            exploit=spec,
        )

    def _anon_read_finding(self, detail: str, r_anon) -> Finding:
        steps = self._spec_base_steps()
        steps.append({"name": "read_resource_anonymously", "method": "GET", "url": detail, "final": True})
        spec = ExploitSpec(
            steps=steps,
            success_if={"status_in": [200], "body_contains_any": ["{{resource_id}}", self.marker]},
            description=f"Anonymous caller reads a user resource at {detail}",
        )
        return Finding(
            rule="access-control/resource-readable-anonymously",
            category=Category.ACCESS_CONTROL,
            title=f"Anyone (no login) can read {detail}",
            severity=Severity.CRITICAL,
            confidence=Confidence.CONFIRMED,
            description=(
                f"GET {detail} returned another user's resource to an anonymous caller — no token, no session. "
                f"Captured live: HTTP {r_anon.status}. This is one `curl` away for anyone on the internet."
            ),
            remediation=("Require authentication on this route, scope the query to the caller "
                         "(`WHERE id = ? AND user_id = ?`), and add an RLS policy as a backstop."),
            location=f"GET {detail}",
            evidence=[Evidence(kind="http-exchange",
                               detail=f"anonymous GET {detail} → {r_anon.status}; body excerpt: {r_anon.body[:200]}",
                               location=detail,
                               request={"method": "GET", "url": detail},
                               response={"status": r_anon.status, "body": r_anon.body[:500]})],
            exploit=spec,
        )

    def _anonymous_sweep(self) -> list[Finding]:
        findings = []
        sensitive = ("admin", "internal", "private", "manage", "dashboard")
        for route in self.routes:
            if any(ch in route for ch in (":", "{", "[")):
                continue
            low = route.lower()
            if not (any(s in low for s in sensitive) or re.search(r"/(users|accounts|profiles)$", low)):
                continue
            r = self._get(route)
            if r.status == 200:
                spec = ExploitSpec(
                    steps=[{"name": "anonymous_access", "method": "GET", "url": route, "final": True}],
                    success_if={"status_in": [200]},
                    description=f"Anonymous GET {route} succeeds",
                )
                findings.append(Finding(
                    rule="access-control/admin-endpoint-open",
                    category=Category.ACCESS_CONTROL,
                    title=f"`{route}` responds to anonymous callers",
                    severity=Severity.CRITICAL,
                    confidence=Confidence.CONFIRMED,
                    description=(
                        f"GET {route} with no token returned HTTP 200. The path looks administrative, so either "
                        "it leaks data to anyone who guesses it or performs privileged actions anonymously. "
                        "The live response is captured as evidence."
                    ),
                    remediation=("Require authentication server-side AND an explicit admin/role check — "
                                 "authentication alone is not authorization. Test every admin route as an "
                                 "anonymous caller in CI."),
                    location=f"GET {route}",
                    evidence=[Evidence(kind="http-exchange",
                                       detail=f"anonymous GET {route} → {r.status}; body excerpt: {r.body[:200]}",
                                       location=route,
                                       request={"method": "GET", "url": route},
                                       response={"status": r.status, "body": r.body[:500]})],
                    exploit=spec,
                ))
        return findings


# ---- entry point -------------------------------------------------------------------------


def dynamic_pass(ctx: ScanContext, progress=None) -> tuple[list[Finding], dict]:
    emit = progress or (lambda m: None)
    command = ctx.start_command() or detect_start_command(ctx.root)
    if not command:
        return [], {"ran": False, "reason": "no start command detected for this project"}

    routes = mine_routes(ctx)
    emit(f"dynamic: booting app ({' '.join(command)}) on an ephemeral port")
    with AppSandbox(ctx.root, command=command) as sbx:
        if not sbx.healthy:
            return [], {"ran": False, "reason": sbx.error, "routes_mined": len(routes)}
        emit(f"dynamic: app healthy — running two-user probe")
        probe = TwoUserProbe(sbx.base_url, routes, progress=emit)
        findings, meta = probe.run()
        meta["base_url"] = sbx.base_url
        meta["start_command"] = command
        emit(f"dynamic: done ({len(findings)} confirmed finding(s))")
        return findings, meta
