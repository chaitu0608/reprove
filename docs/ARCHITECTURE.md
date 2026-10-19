# Architecture

> The design invariant behind every decision here: **a claim about security
> must carry its proof.** A finding without a captured exploit is labeled
> unproven; a fix without a replay is not called fixed.

## The pipeline

An `audit` run is four stages over one immutable snapshot:

```
snapshot(dir) ──► static analyzers ──► dynamic probe ──► triage ──► patches ──► verifier
                        │                  │               │           │           │
                   per-rule Findings   PROVEN evidence  severity    diffs      verdicts
```

### 1. Ingest

`sandbox`/`context.ScanContext` reads the project once into an in-memory
snapshot: text files, parsed `package.json`/SQL, config properties, path
index. Analyzers never touch the disk directly, which makes them pure
functions of `(snapshot, config)` — trivially parallel, trivially testable,
trivially cacheable. Sensitive files are recorded by path/line only; secret
*values* are masked before they ever enter a Finding.

### 2. Static analyzers (plugin registry)

`context.py` holds the registry. An analyzer is:

```python
def analyze(ctx: ScanContext) -> list[Finding]: ...
register("category/rule-name", analyze)
```

Eight analyzers ship today (see README). Rules of the house:

- **Deterministic.** No network by default (`--online` opts in for registry/OSV
  dependency checks). No LLM anywhere in the pipeline.
- **Evidence-first.** Every finding carries `evidence[]` entries (code excerpt,
  SQL snippet, config property) that the report renders verbatim.
- **Honest confidence.** `PROVEN` (live exploit captured) · `LIKELY` (strong
  deterministic signal) · `POSSIBLE` (heuristic). The scorer in `triage.py`
  maps (severity × confidence) to the audit's headline.
- **False-positive discipline.** The clean-control corpus is scanned in CI on
  every change; a rule that fires on the hardened app must be fixed or made
  conditional before it can reach `main`.

Analyzers run in a `ThreadPoolExecutor` (`--workers`, default 4). They are
CPU-light and I/O-free, so threads over the snapshot are sufficient; the
process-based isolation lives in the sandbox, where it belongs.

### 3. Dynamic probe — the "prove" layer

`dynamic/sandbox.py` (`AppSandbox`) and `dynamic/probe.py` are the heart of
the tool:

- **Boot**: copies the snapshot to a temp working tree, detects the app type
  (`package.json` scripts, `server.js`, …), boots on an **ephemeral port**
  (`PORT=0` semantics via a picked free port), waits for a health probe, and
  tears everything down afterward. The live app's `.reprove-sandbox.log` is
  written and deleted inside the sandbox.
- **Route mining**: the probe extracts candidate routes from the app (server
  source, Next-style `app/api/**/route` files) and classifies admin-shaped
  paths.
- **Two-user probe**: registers identities A and B with unique emails
  (`reprove.a.<nonce>@example.org`), has A create a marker resource, then tries
  to read/modify it as B. A 200 with A's data in the body is a **confirmed
  IDOR**, captured as a full HTTP exchange.
- **Anonymous sweep**: calls admin-shaped endpoints with no credentials; a 200
  (or any authenticated-tier response) is a confirmed open admin surface.
- **ExploitSpec**: every demonstrated attack is serialized as a spec:

  ```json
  {
    "id": "access-control/idor-confirmed",
    "setup":   [{"step": "signup_a"}, {"step": "create_resource"}],
    "attack":  [{"step": "http", "method": "GET", "path": "/api/orders/{resource_id}",
                 "as": "user_b"}],
    "vulnerable_when": {"status": 200, "body_contains": "{marker}"},
    "fixed_when":      {"status": [404, 403]}
  }
  ```

  **Discovery and verification share the exact same executor**
  (`execute_exploit`). That is the load-bearing design choice: "verified" means
  the identical attack spec, replayed by the same code, failed against the
  patched build. No second, softer implementation to hide in.

### 4. Triage

`triage.py` scores findings and decides what the run's exit code communicates:
`0` clean · `1` tool error · `2` confirmed `high`+ findings remain. Dynamic
confirmations upgrade their static siblings in place (same rule, same file, same
line → the static `LIKELY` becomes `PROVEN` with the capture attached).

## Patch → verify — the "re-prove" layer

### Deterministic patch generator

`patch/generator.py` emits a fix only when the transformation is **mechanical
and safe**:

- literal replacements (remove an exposed key from a client bundle),
- guard insertion against an auth helper that *provably exists in the file*
  (`function deny(res, code)` found in source, not guessed),
- SQL string-concat → parameter placeholder with a values array,
- RLS migration generation from the parsed table schema,
- `.env` → delete + `.env.example` + `.gitignore` rule.

Everything else returns a **`manual` patch** with the senior-engineer guidance
shown in the report. We would rather admit "this one is on you" than ship a
patch that deletes the wrong line. Each patch is rendered as a unified diff you
can review before applying (`--apply` does it on a copy by default; `--in-place`
opts into your tree).

### Verifier — a fix counts only when proven

`patch/verifier.py` runs three gates and assigns each finding a verdict:

1. **Build gate** — the patched tree must still build/test (`node --test`,
   `npm test`, or detected equivalent). Any failure → `BREAKS_BUILD`.
   (This gate has already caught the project's own generated patches during
   development — that is exactly why it exists.)
2. **Exploit replay** — for findings with an `ExploitSpec`: boot the patched
   app, replay the spec, read the signal. `exploit-blocked` → `VERIFIED`;
   `exploit-succeeded` → `STILL_VULNERABLE`; environment failure →
   `INCONCLUSIVE` (never reported as fixed).
3. **Rescan** — for the rest: re-run the analyzers over the patched tree and
   require the finding (or its result-equivalent) to be gone. Verdicts are
   **result-based, not rule-name-based**, so a sibling patch that removes the
   same underlying hazard still counts, and a cosmetic rule rename does not.

Only `VERIFIED` fixes appear with a checkmark. The summary line —
`14 verified · 0 still vulnerable · 0 broke build · 2 manual · 0 inconclusive`
— is the artifact you paste into a PR.

## Module map

```
src/reprove/
├── models.py          Finding, Patch, ExploitSpec, FixStatus, Evidence
├── context.py         ScanContext + analyzer registry (plugin seam)
├── scanner.py         orchestrator: parallel analyzers → dynamic → triage
├── triage.py          severity × confidence scoring, exit-code policy
├── report.py          console / Markdown / JSON renderers
├── cli.py             scan · audit · demo · mcp · rules
├── mcp_server.py      FastMCP server (7 tools)
├── analyzers/         the 8 shipped rules families
├── dynamic/
│   ├── sandbox.py     boot/teardown, ephemeral port, health check
│   └── probe.py       route mining, two-user probe, execute_exploit
└── patch/
    ├── generator.py   deterministic templates + manual guidance
    └── verifier.py    build gate + replay + rescan → FixStatus
```

## Invariants (do not break these)

1. **No LLM in the critical path.** Optional future plugins may *explain*;
   they must never gate detection, patching, or verdicts.
2. **Same input → same audit.** No time, no randomness beyond probe nonces,
   no network unless `--online`.
3. **Evidence or it didn't happen.** Proven findings carry raw captures;
   verified fixes carry the replay result that cleared them.
4. **The control corpus stays clean.**
5. **The verifier is the backstop for everything else.** When in doubt, the
   generator is conservative and the verifier is strict.
