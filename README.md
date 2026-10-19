# Reprove

**Prove the exploit. Fix the app. Re-prove it.**

[![CI](https://github.com/chaitu0608/reprove/actions/workflows/ci.yml/badge.svg)](https://github.com/chaitu0608/reprove/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)

Proof-carrying security for vibe-coded apps. Reprove finds the flaws AI app
builders routinely ship — leaked keys, missing Supabase RLS, IDOR, injection,
hallucinated dependencies — then **proves each finding with a live exploit**,
generates a minimal patch, and **re-runs the exploit to prove the fix**.

- A finding is real only if an exploit demonstrates it. (`PROVEN`)
- A fix counts only if the exploit fails afterward **and** the app still builds.
- Everything else is honestly labeled `LIKELY`, `manual`, or `inconclusive` —
  never overstated.

MCP-native: the coding agent that generated your app can call Reprove in-loop
and heal it.

---

## The gap Reprove fills

| Existing tools | Reprove |
|---|---|
| Report *possible* issues from pattern matching | Report issues only after **capturing live proof** of exploitation |
| Leave fix verification to the human | **Re-runs the recorded exploit** against the patched app; fix or it didn't happen |
| Generic rules for enterprise codebases | Detectors for the exact failure modes of **AI-generated apps** (Supabase RLS, `service_role` leaks, IDOR shapes, prompt-injection surfaces) |
| Need an LLM in the loop to feel smart | **Deterministic-first**: same input → same audit, offline-capable, no model in the critical path |
| Rarely tested against clean code | Ships a **hardened control corpus** — precision is tested as hard as recall |

## Quickstart

```bash
git clone https://github.com/chaitu0608/reprove && cd reprove
python3 -m venv .venv && . .venv/bin/activate
pip install -e ".[mcp]"          # mcp extra enables the MCP server

reprove demo                      # the full loop on the bundled vulnerable app
reprove scan  path/to/your/app    # static + live exploit proof
reprove audit path/to/your/app --apply   # scan → patch → re-prove on a copy
reprove mcp                       # run as an MCP tool server (stdio)
reprove rules                     # list all analyzers
```

Only Python is required for the core (zero runtime dependencies). The dynamic
exploit layer needs **Node.js ≥ 20** to boot JavaScript/TypeScript apps.

## What the loop looks like

```
$ reprove audit myapp --apply
```

```
VERIFICATION — a fix counts only when it is proven
  ✅ verified   `/api/admin/users` responds to anonymous callers
      the recorded exploit no longer works against the patched app
      proof: anonymous_access: GET http://127.0.0.1:52490/api/admin/users → 401
  ✅ verified   IDOR confirmed: user B can read user A's data via GET /api/orders/o3
      the recorded exploit no longer works against the patched app
      proof: signup_a: POST .../api/auth/signup → 201
  ✅ verified   Environment file committed to the repository: .env
      re-scan no longer detects `secrets/committed-env` in .env
  ✅ verified   SQL built by string concatenation
      re-scan no longer detects `injection/sql-string-concat` in server.js
  ...
  ✋ manual     Package `expres` closely resembles `express`
      cannot be auto-verified (manual step required, e.g. key rotation)

  fixes: 14 verified · 0 still vulnerable · 0 broke build · 2 manual · 0 inconclusive
```

Before → after, from the recorded replay: the IDOR `GET /api/orders/{id}`
returns **404** for the wrong user, and the open admin route returns **401**.
Not "patched" — *proven* patched, on a running instance of your app.

## How it works

```
                    ┌─────────────────────────────────────────────────────┐
   your repo  ──►   │ 1. SCAN   static analyzers (plugin registry)        │
 (or a copy)        │           secrets · RLS · authz · IDOR · injection  │
                    │           deps · config · AI-feature surfaces       │
                    └──────────────────────────┬──────────────────────────┘
                                               ▼
                    ┌─────────────────────────────────────────────────────┐
                    │ 2. PROVE  boot app in an ephemeral sandbox          │
                    │           two-user probe: create as A, fetch as B   │
                    │           anonymous sweep over mined admin routes   │
                    │           captured HTTP exchanges = evidence        │
                    └──────────────────────────┬──────────────────────────┘
                                               ▼
                    ┌─────────────────────────────────────────────────────┐
                    │ 3. PATCH  deterministic template fixes only         │
                    │           anything non-mechanical → `manual`        │
                    │           with precise senior-engineer guidance     │
                    └──────────────────────────┬──────────────────────────┘
                                               ▼
                    ┌─────────────────────────────────────────────────────┐
                    │ 4. RE-PROVE  build gate + exploit replay + rescan   │
                    │           verified only if exploit fails AND build  │
                    │           passes — otherwise it is reported as-is   │
                    └─────────────────────────────────────────────────────┘
```

Every exploit is a serialized **spec** (setup, steps, expected-vulnerable
signal, expected-fixed signal). Discovery and verification share the *same
executor*, so a "verified" fix means the identical attack failed on the patched
build. Evidence is kept: raw HTTP exchanges for proven findings, unified diffs
for patches. See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for internals.

## Analyzers

| Analyzer | Catches |
|---|---|
| `secrets` | Hardcoded keys (OpenAI, Stripe, Supabase…), entropy hits, **client-exposed vs repo-exposed classification**, `service_role` JWTs |
| `rls` | Supabase tables with RLS disabled, permissive `USING (true)` policies — parsed from SQL migrations |
| `authz` | Express/Next/node-http routes handling admin surfaces without an auth call |
| `idor` | `find`-by-id lookups, Supabase `.eq('id', …)` fetches without an ownership clause, SQL `WHERE id =` shapes |
| `injection` | SQL built by string concatenation, XSS sinks, `eval`/`exec` of request data |
| `deps` | Typosquat candidates (offline, edit-distance) + registry/OSV checks (online mode) |
| `config` | Wildcard CORS, stack traces shipped to clients, missing hardening |
| `ai_calls` | Client-side LLM keys, prompt-injection surface, model output reaching dangerous sinks |

## MCP server — let the agent that wrote the code fix it

`reprove mcp` speaks stdio MCP with 7 tools:

`scan_project` · `list_findings` · `explain_finding` · `propose_patch` ·
`apply_patch` (requires `confirm`) · `verify_fix` · `full_audit`

Example client config:

```json
{
  "mcpServers": {
    "reprove": {
      "command": "/absolute/path/to/.venv/bin/reprove",
      "args": ["mcp"]
    }
  }
}
```

Then, in your coding agent: *"Use reprove to scan this project, explain the
critical findings like I'm not a security engineer, fix the ones that are safe
to automate, and prove the exploits no longer work."*

## Exit codes (CI-ready)

| Code | Meaning |
|---|---|
| `0` | clean — or nothing confirmed at `high`+ remains |
| `1` | tool error |
| `2` | confirmed `high`+ findings remain |

```bash
reprove scan . --json > audit.json   # machine-readable, fails CI on confirmed highs
```

## Tests & corpus

```bash
pytest tests/ -q        # 10 tests: static rules, live IDOR/admin proof,
                        # clean-control zero-exploits, MCP tools,
                        # and the full prove→patch→re-prove loop
```

The repo ships an intentionally vulnerable app (`corpus/vuln-node-api`), a
**hardened control** (`corpus/clean-node-api` — must stay exploit-free), and a
static Next.js-like fixture. The control corpus is the point: a scanner that
finds everything in everything is noise.

## Roadmap

Deliberately scoped in phases so every commit is shippable:
[`docs/ROADMAP.md`](docs/ROADMAP.md) · scaling design:
[`docs/SCALING.md`](docs/SCALING.md).

Near-term: Docker-isolated sandbox, GitHub Action that comments verified fixes
on PRs, tree-sitter/semgrep interop, live Supabase policy probing, PyPI release.

## Safety

Reprove boots the target app locally and sends it exploit-shaped requests
(two-user IDOR probes, anonymous sweeps). **Use it only against code you own or
are authorized to test.** The bundled corpus apps are intended to be
vulnerable — never deploy them. No probing escapes localhost in default
configuration.

## License

MIT — see [LICENSE](LICENSE).
