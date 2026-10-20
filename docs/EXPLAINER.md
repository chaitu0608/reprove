# Reprove, explained from scratch

*This document is the friendly, no-security-background tour. For the internals, see
[ARCHITECTURE.md](ARCHITECTURE.md).*

## Contents

1. [What Reprove is](#1-what-reprove-is)
2. [The problem it solves](#2-the-problem-it-solves)
3. [The central idea: proof, not opinions](#3-the-central-idea-proof-not-opinions)
4. [The four stages](#4-the-four-stages)
5. [A walkthrough of the demo](#5-a-walkthrough-of-the-demo)
6. [Key words, in plain English](#6-key-words-in-plain-english)
7. [Every part of the repo](#7-every-part-of-the-repo)
8. [How to use it](#8-how-to-use-it)
9. [The MCP part](#9-the-mcp-part)
10. [Why it is different](#10-why-it-is-different)
11. [What is tested, what is not](#11-what-is-tested-what-is-not)
12. [Troubleshooting](#12-troubleshooting)

---

## 1. What Reprove is

Reprove is a security tool for apps that were built quickly — especially with AI
help ("vibe coding"). It does four things in a loop:

1. **Scan** the code for the classic mistakes.
2. **Prove** each mistake is real by actually breaking into the running app.
3. **Fix** it with a small, careful patch.
4. **Re-prove** the fix by running the exact same break-in again.

That is why it is called **Reprove** — *prove again*.

> Most security tools say: *"this might be a problem."*
> Reprove says: *"I broke in. Here is the receipt. I fixed it. I tried again —
> I can't get in anymore."*

## 2. The problem it solves

When someone describes an app to an AI and the AI writes the code, the result
usually works — but ships the same handful of security holes over and over:

| Mistake | What it means in plain English |
|---|---|
| **Leaked secrets** | An API key (a password-like string for Stripe, OpenAI, etc.) left in the code. Anyone who sees it can spend your money. |
| **No Supabase RLS** | Supabase is a database service. RLS ("Row Level Security") is its rulebook for *who may see which row*. Forget to turn it on and the public key that ships in every browser can read your whole database. |
| **IDOR** | *Insecure Direct Object Reference.* Your API says "give me order #3" and simply returns it — without checking whether order #3 belongs to **you**. Change the number, read someone else's data. |
| **SQL injection** | The app glues user input straight into a database command. An attacker types clever text and the database obeys it. |
| **Typosquatting** | A fake package named `expres` instead of `express` — looks right, runs someone else's code. |
| **Wildcard CORS** | The API says "any website may call me," so a malicious site can act as your logged-in user. |

Existing tools fall into two camps:

- **Scanners** read the code and *guess*. Lots of false alarms, and they never
  check whether a fix actually fixed anything.
- **Penetration tests** are real attacks, but slow, expensive, and manual.

Nobody closed the loop: **is it actually exploitable? And did the fix actually
work?** Reprove fills that gap.

The analogy: a normal scanner stands outside and says *"that window looks
unlocked."* Reprove jiggles the handle, gets in, installs a lock, then tries the
handle again to prove it is locked.

## 3. The central idea: proof, not opinions

Four rules define the project:

1. **A finding is real only if an exploit demonstrates it** — or it is honestly
   labeled as unproven (`LIKELY` / `POSSIBLE`).
2. **A fix counts only if the exploit fails afterward AND the app still builds.**
3. **No LLM in the critical path.** Detection, patching, and verdicts are
   deterministic: same input, same audit, works offline.
4. **Never silently patch what cannot be fixed mechanically.** Reprove would
   rather hand you precise instructions than delete the wrong line.

## 4. The four stages

### Stage 1 — Scan (read the blueprint)

Reprove takes a snapshot of the project's text files, `package.json`, SQL
migrations, and config. Then it runs **8 detectives** (analyzers):

| Analyzer | What it looks for |
|---|---|
| `secrets` | Key-shaped strings, and *where* they are. A key in `public/` ships to every visitor's browser. A Supabase `service_role` key is a master key — it bypasses all database rules. |
| `rls` | Reads Supabase SQL. Is Row Level Security enabled on every table? Do any policies allow everyone? |
| `authz` | Server routes like `/api/admin/users` — is there a login check before the admin work? |
| `idor` | "Look up a record by id" code with no owner check. |
| `injection` | SQL built by gluing strings together; `eval`/`exec` of user input. |
| `deps` | Package names one letter away from popular ones (typosquats), plus optional online registry/OSV checks. |
| `config` | Wildcard CORS, stack traces shown to users, missing security headers / rate limits. |
| `ai_calls` | Client-side LLM keys, prompt-injection surfaces, model output flowing into dangerous places. |

Each result is a **finding** with a confidence level:

- `POSSIBLE` — a hunch;
- `LIKELY` — a strong clue, not yet attacked;
- `PROVEN` — the exploit was actually executed and the evidence captured.

Every finding carries **evidence**: file, line, code snippet, SQL fragment. No
receipt, no promotion.

### Stage 2 — Prove (actually try the doors)

Reprove copies the app to a temporary folder and boots it on a random local
port — a disposable sandbox. Then it plays out a small movie:

1. Create user **A**.
2. A creates a private order (`o3`).
3. Create user **B** — a different person.
4. B asks the API for A's order.
5. If B gets A's data back (`HTTP 200` plus A's data), that is a **proven IDOR**.
6. It also calls admin URLs with no login. If they answer with data, that is a
   **proven open admin panel**.

```text
🔴 IDOR confirmed: user B can read user A's data via GET /api/orders/o3 (PROVEN)
   evidence: user B GET /api/orders/o3 → 200
             body: {"id":"o3","userId":"u1","item":"RP-...","createdAt":"..."}
   exploit: reproducible (4 steps)
```

Each demonstrated attack is saved as a **recipe** (an *exploit spec*):

- setup steps (sign up A, create a record),
- the attack (B fetches the record),
- what a vulnerable response looks like (status 200 with A's data),
- what a fixed response looks like (404/403).

The **same executor** replays this recipe later, so "verified" cannot be faked by
a softer second implementation.

### Stage 3 — Fix (install better locks)

For each finding, Reprove asks: *can this be fixed mechanically and safely?*

When yes, it writes a minimal patch:

- remove a leaked key from a client-side file;
- delete `.env`, create `.env.example`, add `.env` to `.gitignore`;
- insert a real guard: `if (!__rpUser) { return deny(res, 401); }`;
- turn SQL string concatenation into parameterized SQL (`?` + values array);
- generate an RLS migration (`ENABLE ROW LEVEL SECURITY` + `USING (auth.uid() = user_id)`);
- add an owner check to an id lookup;
- replace wildcard CORS with an allowlist from an environment variable.

When no, it emits a **manual** patch with plain-English instructions — for
example "rotate this key; deletion does not un-leak it" or "add helmet and rate
limiting." Honest beats clever.

Patches go to a **copy** by default (`--in-place` opts into your real tree).

### Stage 4 — Re-prove (try the lock again)

Three gates decide the verdict:

1. **Build gate** — does the patched app still build and start? If not:
   `BREAKS_BUILD`, patch rejected.
2. **Replay** — boot the patched app and run the *same recipe*:
   - attack fails → `VERIFIED`
   - attack still works → `STILL_VULNERABLE`
   - environment problem → `INCONCLUSIVE` (never reported as fixed)
3. **Rescan** — for findings without a live recipe, re-run the detectives; the
   finding must be gone.

```text
✅ verified  IDOR confirmed: user B can read user A's data
             the recorded exploit no longer works against the patched app

✅ verified  `/api/admin/users` responds to anonymous callers
             proof: GET http://127.0.0.1:.../api/admin/users → 401
             proof: body: {"error":"unauthorized"}

fixes: 14 verified · 0 still vulnerable · 0 broke build · 2 manual · 0 inconclusive
```

That last line is the whole product in one sentence. If a fix cannot earn that
checkmark, it does not get one.

## 5. A walkthrough of the demo

`reprove demo` runs the loop against the bundled vulnerable app:

- **16 findings**: 8 critical, 6 high, 1 medium, 1 low.
- **14 fixed and verified** — by live replay or clean rescan.
- **2 manual**: a typosquat package (needs a human decision) and server
  hardening (no safe automatic patch).
- **0 still vulnerable. 0 broke the build.**

Outputs:

| File | What it is |
|---|---|
| `reprove-out/audit.json` | machine-readable results |
| `reprove-out/REPORT.md` | human-readable report |
| `reprove-out/fixes.diff` | the actual code changes |

A real captured transcript and report are checked in under
[`example-output/`](example-output/) so you can see the end result without
running anything.

## 6. Key words, in plain English

- **Finding** — one thing Reprove believes is a problem, with a location and
  evidence.
- **Evidence** — the receipt: a code excerpt, SQL fragment, or raw HTTP exchange.
- **Exploit spec / recipe** — a recorded, replayable attack: setup, steps,
  vulnerable signal, fixed signal.
- **Sandbox** — a disposable copy of the app, booted on a random port, never
  your real environment.
- **RLS** — Supabase/Postgres Row Level Security: per-row access rules.
- **IDOR** — fetching a record by id without checking ownership.
- **`service_role` key** — Supabase's master key; it bypasses RLS entirely.
- **Typosquat** — a malicious package whose name resembles a popular one.
- **CORS** — the browser rule for which websites may call your API. `*` means
  everyone.
- **MCP** — Model Context Protocol: a standard way for AI assistants to call
  external tools.
- **Verdict** — `VERIFIED`, `STILL_VULNERABLE`, `BREAKS_BUILD`, `INCONCLUSIVE`,
  or `manual`.

## 7. Every part of the repo

```text
reprove/
├── src/reprove/
│   ├── models.py          the vocabulary: Finding, Evidence, ExploitSpec, Patch
│   ├── context.py         registry where the 8 detectives sign up
│   ├── scanner.py         manager: runs detectives in parallel, then the live probe
│   ├── triage.py          importance: severity × confidence → exit code
│   ├── report.py          translator: console, Markdown, JSON
│   ├── cli.py             front door: scan / audit / demo / mcp / rules
│   ├── mcp_server.py      the phone line AI assistants call
│   ├── analyzers/         the 8 detectives (one file per family)
│   ├── dynamic/
│   │   ├── sandbox.py     lab room: copy, boot on a random port, shut down
│   │   └── probe.py       attacker: route mining, two-user tests, replays
│   └── patch/
│       ├── generator.py   locksmith: mechanical fixes or honest manual guidance
│       └── verifier.py    judge: build gate + replay + rescan → verdict
├── corpus/
│   ├── vuln-node-api/         the sick patient (intentionally vulnerable)
│   ├── clean-node-api/        the healthy control (must stay clean)
│   └── vuln-static-nextlike/  Next.js-style fixture for AI-specific flaws
├── tests/                 10 tests, including the full loop
├── docs/
│   ├── ARCHITECTURE.md    how and why it works
│   ├── ROADMAP.md         future commits, phase by phase
│   ├── SCALING.md         how to turn it into a service
│   ├── EXPLAINER.md       this document
│   └── example-output/    real demo transcript, report, and diff
├── scripts/doctor.sh      environment check + known-quirk repair
├── .github/workflows/     CI: tests + sick/healthy app checks
├── README.md · LICENSE (MIT) · pyproject.toml
```

Why two corpus apps? **Precision.** If the scanner finds problems in the
hardened control app, those are false alarms. Tests and CI assert it stays
clean. A scanner that finds everything in everything is just noise.

## 8. How to use it

```bash
cd reprove
./scripts/doctor.sh                 # check the environment (recommended once)

reprove demo                        # the whole loop on the bundled app
reprove scan  ~/some/app            # find + prove issues in your project
reprove audit ~/some/app --apply    # patch a copy and re-prove every fix
reprove scan  ~/some/app --json     # machine output for CI
reprove rules                       # list all checks
reprove mcp                         # run as an AI-assistant tool server
```

Exit codes: `0` clean · `1` tool error · `2` confirmed high+ findings remain.

## 9. The MCP part

MCP (Model Context Protocol) is how modern AI assistants call outside tools.
Reprove exposes seven:

`scan_project` · `list_findings` · `explain_finding` · `propose_patch` ·
`apply_patch` (asks for confirmation) · `verify_fix` · `full_audit`

The loop becomes: **the same AI that generated your app can secure it** — scan,
explain in plain English, patch, and prove the fix, without leaving the chat.

## 10. Why it is different

1. **Proof-carrying findings** — live HTTP evidence, not guesswork.
2. **Verified fixes** — the exploit must fail and the build must pass.
3. **Deterministic** — no LLM in the critical path; reproducible and offline.
4. **Built for AI-generated apps** — Supabase RLS, client-exposed keys, IDOR,
   AI-feature risks.
5. **Precision discipline** — the hardened control corpus is tested on every change.
6. **Replayable recipes** — exploits are portable data, ready for horizontal
   scaling (queue → workers → sandbox pool, see [SCALING.md](SCALING.md)).

## 11. What is tested, what is not

**Tested (10 tests, green in CI):** every static rule family, live IDOR and
open-admin proof, the clean control staying exploit-free, the MCP tool wrappers,
and the full prove → patch → re-prove loop.

**Working today:** the whole loop, 8 analyzers, the patch generator, the
three-gate verifier, MCP, CLI, corpus, docs.

**Honest limits:** the dynamic prover currently focuses on Node/Express-style
apps; the sandbox is a local process, not a container (Docker is on the
roadmap); two findings in the demo remain manual by design; the benchmark corpus
with published precision/recall numbers is future work. See
[ROADMAP.md](ROADMAP.md).

## 12. Troubleshooting

**`ModuleNotFoundError: No module named 'reprove'` on macOS**

Python 3.14 intentionally ignores `.pth` files carrying the macOS `UF_HIDDEN`
flag, which can silently disable a setuptools editable install if something
flags the venv (backup/sync tools occasionally do). The repair is one command:

```bash
./scripts/doctor.sh        # finds and fixes hidden venv files, then runs tests
```

Manual equivalent: `chflags -R nohidden .venv`. Tests also work without an
editable install because `tests/conftest.py` adds `src/` to the path.

**Dynamic probes are skipped** — install Node.js ≥ 20 (`node --version`).
Static analysis still works without it.

**A patch was not auto-generated** — that is intentional. Reprove only
auto-patches mechanical transformations; everything else includes manual
guidance. Run `reprove audit <path>` to see the guidance.
