# Example output

Real artifacts produced by `reprove demo` on 2026-10-20 (Reprove v0.1.0) against
`corpus/vuln-node-api`:

| File | What it is |
|---|---|
| `demo-console.txt` | full terminal transcript: scan → prove → patch → re-prove |
| `REPORT.md` | the human-readable audit report |
| `fixes.diff` | every automated patch, as a unified diff |

The headline from this run:

```
fixes: 14 verified · 0 still vulnerable · 0 broke build · 2 manual · 0 inconclusive
```

Regenerate everything yourself with:

```bash
reprove demo
```

Artifacts land in `reprove-out/` (gitignored). All credentials in the corpus are
synthetic and non-functional by design.
