# Roadmap

Every phase is a series of shippable commits, ordered so that each one
sharpens the core promise — *proof, not vibes* — without diluting it.

## v0.1 — shipped (this repo)

- [x] Static analyzer framework + 8 vibe-code-specific rule families
  (secrets, RLS, authz, IDOR, injection, deps, config, AI surfaces)
- [x] Dynamic proof: process sandbox, two-user IDOR probe, anonymous admin
  sweep, route mining, shared exploit executor
- [x] Deterministic patch generator (mechanical-only) + manual guidance
- [x] Verifier: build gate + exploit replay + result-based rescan
- [x] MCP server (7 tools), CLI (`scan/audit/demo/mcp/rules`), exit codes
- [x] Vulnerable corpus + hardened control + static Next-like fixture
- [x] End-to-end test: prove → patch → re-prove on the full corpus

## v0.2 — stronger proof

- [ ] **Docker sandbox** (`--sandbox docker`): network-off container per audit,
  seccomp defaults, memory/CPU caps. Process mode stays the dependency-free
  default; Docker becomes the option for untrusted repos.
- [ ] **Playwright crawl mode**: real browser against the booted app to reach
  client-rendered routes the static miner can't see, and to prove XSS sinks
  live instead of reporting them.
- [ ] **Live Supabase probing**: with a project URL + anon key, query
  `pg_policies` through PostgREST to prove RLS gaps against the deployed
  database, not just the migration files.
- [ ] More exploit recipes: token-replay after logout, mass-assignment
  (send `role: "admin"` in a profile update), JWT `alg: none` acceptance,
  exposed debug/`_next` endpoints.
- [ ] `--fail-on` policy flag (e.g. fail CI on `high+`, or on any `PROVEN`).

## v0.3 — more inputs, same discipline

- [ ] **tree-sitter parsing** for JS/TS/Python: real AST matching replaces
  regex where ambiguity bites (authz windows, IDOR shapes).
- [ ] **Semgrep interop plugin**: import semgrep JSON as unproven findings —
  then *prove* them with the dynamic layer. Unproven leads in, proven findings
  out.
- [ ] New analyzers: SSRF, open redirect, CSRF, NoSQL injection, Firebase
  security rules, Stripe webhook signature checks, Next.js server-action auth.
- [ ] Python backends (FastAPI/Flask/Django) in the dynamic probe.
- [ ] **GitHub Action**: run on PRs, comment a table of proven findings, attach
  `fixes.diff`, block merge on `STILL_VULNERABLE`.

## v0.4 — ecosystem & hardening

- [ ] **LLM triage plugin (optional, off by default)**: better explanations
  and `manual` fix drafts — never detection, never verdicts. It may only
  *annotate* what the deterministic core already proved. The MCP tools are the
  sanctioned place for model reasoning.
- [ ] Benchmark corpus: 30–50 real vibe-coded apps (with permission /
  synthetic seeds), measuring precision/recall per rule family and
  “verified-fix rate”. Publish the numbers per release.
- [ ] Rule versioning: findings pin `ruleset_version`; audits are reproducible
  artifacts.
- [ ] PyPI release (`pip install reprove-security`).

## v1.0 — service shape (see docs/SCALING.md)

- [ ] Queue + worker pool + sandbox pool; job = one audit, idempotent, killable.
- [ ] Artifact store (audit JSON, report, diffs) keyed by content-addressed
  snapshot + ruleset version.
- [ ] Hosted “audit this repo URL” endpoint; local-first remains the default.

## Non-goals (kept honest on purpose)

- Not a fuzzer. Reprove proves *specific, plausible* failure modes of
  AI-generated apps, and verifies their fixes.
- Not an LLM wrapper. If a feature only works because a model is in the loop,
  it does not go in the critical path.
- Not an auto-merge bot. Patches are minimal, reviewed, and provable — never
  silently applied to `main`.
