"""Dependency analyzer: hallucinated packages, typosquats, known CVEs.

LLM-generated code confidently imports packages that do not exist — and
sometimes names that *almost* exist, which is how typosquat attacks land.
Offline mode still catches typosquats against a curated popular-package
list; online mode additionally checks the live npm registry and OSV.
"""

from __future__ import annotations

import json
import urllib.parse

from ..context import ScanContext, register
from ..models import Category, Confidence, Evidence, Finding, Severity, VerificationMode
from ..util import HttpClient

# A compact "most-depended-on" seed list. Deliberately not exhaustive — the
# scoring rule is distance ≤ 2 only against packages a vibe-coded app might
# plausibly mean. Extended list lands in a later commit.
POPULAR_NPM = [
    "express", "react", "react-dom", "next", "vue", "svelte", "axios", "lodash",
    "moment", "dayjs", "dotenv", "cors", "helmet", "nodemon", "typescript",
    "eslint", "prettier", "webpack", "vite", "rollup", "esbuild", "zod", "yup",
    "joi", "uuid", "nanoid", "chalk", "commander", "yargs", "inquirer",
    "mongoose", "sequelize", "prisma", "knex", "pg", "mysql2", "redis", "ioredis",
    "jsonwebtoken", "bcrypt", "bcryptjs", "passport", "cookie-parser",
    "body-parser", "multer", "socket.io", "ws", "nodemailer", "stripe",
    "openai", "@supabase/supabase-js", "firebase", "twilio", "pusher",
    "tailwindcss", "postcss", "autoprefixer", "sass", "styled-components",
    "@emotion/react", "framer-motion", "lucide-react", "react-icons",
    "react-router-dom", "react-hook-form", "formik", "redux", "zustand",
    "jotai", "recoil", "tanstack", "@tanstack/react-query", "swr", "graphql",
    "apollo-server", "@apollo/client", "trpc", "@trpc/server", "jest", "vitest",
    "mocha", "playwright", "@playwright/test", "cypress", "puppeteer",
    "cheerio", "marked", "dompurify", "validator", "sharp", "csv-parse",
    "papaparse", "xlsx", "pdfkit", "chart.js", "recharts", "d3", "three",
]


def _levenshtein(a: str, b: str) -> int:
    if abs(len(a) - len(b)) > 2:
        return 3
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def _typosquat_match(name: str) -> str | None:
    base = name.split("/")[-1].lower()
    if base in {p.split("/")[-1] for p in POPULAR_NPM}:
        return None
    for pkg in POPULAR_NPM:
        pb = pkg.split("/")[-1].lower()
        if base == pb:
            continue
        d = _levenshtein(base, pb)
        if 1 <= d <= 2 and abs(len(base) - len(pb)) <= 2:
            return pkg
    return None


def _parse_deps(ctx: ScanContext) -> list[tuple[str, str, str]]:
    """Return [(name, version, source_file), …] from package.json files."""
    deps: list[tuple[str, str, str]] = []
    for f in ctx.by_name("package.json"):
        if f.is_built:
            continue
        try:
            data = json.loads(f.text)
        except Exception:
            continue
        for field in ("dependencies", "devDependencies"):
            for name, ver in (data.get(field) or {}).items():
                deps.append((name, str(ver), f.relpath))
    return deps


@register("deps")
def analyze_deps(ctx: ScanContext) -> list[Finding]:
    out: list[Finding] = []
    deps = _parse_deps(ctx)
    if not deps:
        return out

    http = HttpClient(timeout=8.0)
    online = not ctx.offline()

    checked: set[str] = set()
    for name, version, src in deps:
        if name in checked:
            continue
        checked.add(name)

        # 1. typosquat / near-miss (works offline)
        near = _typosquat_match(name)
        if near:
            out.append(Finding(
                rule="deps/typosquat-suspicion",
                category=Category.SUPPLY_CHAIN,
                title=f"Package `{name}` closely resembles `{near}`",
                severity=Severity.HIGH,
                confidence=Confidence.POSSIBLE,
                description=(
                    f"`{name}` in `{src}` is within edit-distance of the popular package `{near}` and is not "
                    "itself well-known. Typosquatted packages are a common supply-chain attack — the name "
                    "looks right at a glance but runs someone else's code."
                ),
                remediation=f"Verify the import is intentional. If you meant `{near}`, change it; if not, "
                            f"audit what `{name}` does before shipping.",
                location=src,
                evidence=[Evidence(kind="registry",
                                   detail=f"declared dependency `{name}@{version}` ≈ popular package `{near}`",
                                   location=src)],
                verification_mode=VerificationMode.MANUAL,
                tags=["supply-chain"],
            ))

        if not online:
            continue

        # 2. registry existence (online) — hallucinated packages
        r = http.request("GET", f"https://registry.npmjs.org/{urllib.parse.quote(name, safe='@')}")
        if r.status == 404:
            out.append(Finding(
                rule="deps/nonexistent-package",
                category=Category.SUPPLY_CHAIN,
                title=f"Package `{name}` does not exist on npm",
                severity=Severity.HIGH,
                confidence=Confidence.CONFIRMED,
                description=(
                    f"`{name}@{version}` in `{src}` is not registered on the npm registry (HTTP 404). "
                    "This is a hallucinated dependency: either the build fails, or — worse — whoever "
                    "registers that name later gets to run code in your app."
                ),
                remediation=f"Remove `{name}` and fix the import to the intended real package.",
                location=src,
                evidence=[Evidence(kind="registry",
                                   detail=f"GET https://registry.npmjs.org/{name} → 404 Not Found",
                                   location=src)],
                verification_mode=VerificationMode.RESCAN,
                tags=["supply-chain"],
            ))
            continue

        # 3. OSV vulnerability lookup (online)
        clean_ver = version.lstrip("^~>=< ")
        if not clean_ver or not clean_ver[0].isdigit():
            continue
        payload = {"package": {"ecosystem": "npm", "name": name}, "version": clean_ver.split(" ")[0]}
        q = http.request("POST", "https://api.osv.dev/v1/query", json_body=payload)
        data = q.json() or {}
        vulns = data.get("vulns") or []
        if vulns:
            ids = ", ".join(v.get("id", "?") for v in vulns[:4])
            out.append(Finding(
                rule="deps/known-vulnerable",
                category=Category.SUPPLY_CHAIN,
                title=f"`{name}@{clean_ver}` has {len(vulns)} known vulnerability(ies)",
                severity=Severity.MEDIUM,
                confidence=Confidence.CONFIRMED,
                description=(
                    f"OSV reports vulnerabilities for `{name}@{clean_ver}` (declared in `{src}`): {ids}. "
                    "These are public; scanners and attackers both read this list."
                ),
                remediation=f"Upgrade `{name}` to a patched version (`npm audit fix` / bump the range) and "
                            "re-run reprove to confirm.",
                location=src,
                evidence=[Evidence(kind="registry",
                                   detail=f"OSV: {ids}",
                                   location=f"https://osv.dev/list?q={urllib.parse.quote(name)}")],
                verification_mode=VerificationMode.RESCAN,
                tags=["supply-chain", "cve"],
                metadata={"osv_ids": [v.get("id") for v in vulns]},
            ))
    return out
