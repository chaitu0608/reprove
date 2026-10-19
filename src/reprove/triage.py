"""Triage: dedupe, severity scoring, and ordering.

Deliberately deterministic — no LLM in the critical path. An LLM triage
plugin can be layered on top later, but the verifier's verdict never depends
on model judgment.
"""

from __future__ import annotations

from .models import Confidence, Finding, Severity

_CONFIDENCE_BUMP = {
    Confidence.CONFIRMED: 1,   # proven exploit / deterministic evidence
    Confidence.LIKELY: 0,
    Confidence.POSSIBLE: 0,
}


def triage(findings: list[Finding]) -> list[Finding]:
    merged = _dedupe(findings)
    for f in merged:
        f.severity = _score(f)
    merged.sort(key=lambda f: (f.severity.rank, _conf_rank(f.confidence), f.rule, f.location))
    return merged


def _conf_rank(c: Confidence) -> int:
    return {"confirmed": 0, "likely": 1, "possible": 2}[c.value]


def _score(f: Finding) -> Severity:
    sev = f.severity
    bump = _CONFIDENCE_BUMP.get(f.confidence, 0)
    if bump:
        sev = sev.bump(bump)
    # Exploit-confirmed access-control issues are the real-world breach makers.
    if f.confidence == Confidence.CONFIRMED and f.exploit is not None and sev.rank > 0:
        sev = Severity.CRITICAL
    return sev


def _dedupe(findings: list[Finding]) -> list[Finding]:
    by_key: dict[tuple, Finding] = {}
    for f in findings:
        key = (f.rule, f.location)
        existing = by_key.get(key)
        if existing is None:
            by_key[key] = f
            continue
        # keep the higher-confidence, merge evidence
        if _conf_rank(f.confidence) < _conf_rank(existing.confidence):
            f.evidence = existing.evidence + f.evidence
            by_key[key] = f
        else:
            existing.evidence.extend(f.evidence)
    return list(by_key.values())
