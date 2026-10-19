# Scaling — from CLI tool to audit service

Reprove is designed so that the hard part of scaling is *plumbing*, not
redesign. This document sketches why, and what the pieces look like.

## Why Reprove scales naturally

- **Analyzers are pure functions** of `(snapshot, ruleset_version)`. No shared
  state, no disk access, no ordering. This is the definition of a horizontal job.
- **The dynamic layer is already ephemeral**: temp working copy, ephemeral
  port, teardown, no global state. One audit = one sandbox lease.
- **Exploits are portable artifacts**: an `ExploitSpec` is a serialized
  recipe, not a live process. Discovery can happen on worker A; verification
  on worker B, minutes later, and the proof is just as meaningful.
- **Outputs are immutable**: `audit.json`, `REPORT.md`, `fixes.diff` are
  derived from `(snapshot_hash, ruleset_version)`. Same pair → same artifacts,
  so caching and dedup come free.

## Target architecture

```
                        ┌────────────┐
   clients ──► POST /audits ──► QUEUE │  (Redis/SQS/Postgres — anything with
   (CLI, MCP,            └─────┬──────┘   at-least-once semantics and visibility t/o)
    GitHub App,               │
    web)                      ▼
                    ┌───────────────────┐
                    │  worker pool      │   N stateless workers; any of them can
                    │  (audit runtime)  │   die at any point without losing jobs
                    └───────┬───────────┘
                            │ lease
                            ▼
                    ┌───────────────────┐
                    │  sandbox pool     │   M concurrent app runs per worker,
                    │  L0: process      │   isolated by port + temp dir + cgroup
                    │  L1: docker       │   (or container per run)
                    │  L2: microVM      │
                    └───────┬───────────┘
                            ▼
                    ┌───────────────────┐
                    │  artifact store   │   audit.json · REPORT.md · fixes.diff
                    │  (S3/GCS/local)   │   keyed by snapshot_hash+ruleset
                    └───────────────────┘
```

### Job lifecycle

1. `POST /audits {repo_url, ruleset_version, flags}` → `{audit_id}` (202).
   The snapshot is fetched once, hashed, stored content-addressed. Identical
   re-submissions within TTL are deduped to the same `audit_id`.
2. A worker leases the job, materializes the snapshot, runs the pipeline.
3. Progress events (`static done`, `probe phase`, `verify 14/16`) stream to a
   status channel — the UX of `reprove audit` survives the network hop.
4. Artifacts upload; the queue message is acked. Worker state after ack: none.

**Idempotency:** every stage is a pure function of inputs that are all in the
message or the artifact store. A worker killed mid-audit loses nothing; the
visibility timeout returns the message and the next worker re-runs it.

### Sandbox pool

The only expensive resource is “a booted app”. Design:

- **Lease/reap model**: workers acquire sandbox slots from a per-host pool
  (`--max-sandboxes`, e.g. 4). Slots have hard wall-clock TTLs; the reaper
  kills orphans (crash, OOM, runaway boot) — no slot leaks.
- **Isolation levels** (config, not forks):
  - `L0 process` — today's mode. Fast, zero-deps; fine for your own repos.
  - `L1 docker` — one container per sandbox, `network=none` except loopback
    probes, seccomp profile, memory cap. Default for untrusted repos.
  - `L2 microVM` — firecracker-class isolation for a hosted multi-tenant
    service. Same interface (`AppSandbox`), different backend.
- **Port allocation** is ephemeral today and stays per-sandbox (or moves to a
  per-sandbox loopback namespace under L1/L2 — no shared ports, ever).

### Concurrency within a worker

- Analyzers: `ThreadPoolExecutor` (I/O-light, snapshot-shared) — already done.
- Dynamic probes: one sandbox per probe-set; IDOR + admin sweeps run
  sequentially inside a lease, but **multiple findings' replays parallelize
  across sandbox slots** during verification (each replay is independent).
- Backpressure: bounded queue depth per pool; the API returns 429 with a
  retry-after when saturated rather than melting.

### Multi-tenant concerns

- **Never share a sandbox filesystem between tenants.** `mktemp` per job; wipe
  on teardown (today's tool already writes/deletes its own sandbox log).
- **Secret hygiene**: captured evidence masks values at capture time; keys
  found in a tenant's repo never persist to shared storage unmasked.
- **Egress**: default deny. Only `--online` dep checks need DNS/HTTPS, and they
  can be routed through a sandboxed fetcher with an allowlist (registry + OSV).
- **Quotas**: per-tenant concurrent audits, CPU-seconds per day, artifact
  retention.

### What scales along which axis

| Load grows as… | Scale with… | Ceiling breaker |
|---|---|---|
| # of audits | more workers (stateless) | queue depth; add workers |
| repo size | snapshot store + longer analyzer budget | analyzers are O(files), linear |
| probe breadth (routes × identities) | more sandbox slots per worker | CPU/memory per host |
| artifact volume | object store lifecycle policies | cheap, immutable blobs |

## Explicitly deferred

- Cross-repo/cross-version diffing (“did this fix reintroduce yesterday's
  IDOR?”) — a natural v1.1 feature once artifacts are content-addressed.
- Distributed tracing of probe steps — nice for debugging, not needed for the
  proof model.
- Autoscaling policy details — any container platform gives it; the design
  only requires that workers remain killable at any instant.
