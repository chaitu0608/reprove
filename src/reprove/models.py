"""Core data model for Reprove findings, evidence, patches and verification."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Optional


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        return {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}[self.value]

    def bump(self, levels: int = 1) -> "Severity":
        order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
        idx = min(order.index(self) - levels, len(order) - 1)
        idx = max(idx, 0)
        return order[idx]


class Confidence(str, Enum):
    """How sure we are that the finding is real and exploitable."""

    CONFIRMED = "confirmed"  # proven: exploit fired, or deterministic evidence (e.g. secret in built bundle)
    LIKELY = "likely"        # strong static evidence, one plausible assumption away
    POSSIBLE = "possible"    # heuristic — needs human eyes


class Category(str, Enum):
    SECRETS = "secret-exposure"
    ACCESS_CONTROL = "broken-access-control"
    INJECTION = "injection"
    XSS = "xss"
    SUPPLY_CHAIN = "supply-chain"
    CONFIG = "misconfiguration"
    AI_FEATURE = "ai-feature"


class VerificationMode(str, Enum):
    """How a fix for this finding can be proven."""

    EXPLOIT_REPLAY = "exploit-replay"  # re-run the exact attack; must fail
    RESCAN = "rescan"                  # re-run the analyzer; must not re-detect
    MANUAL = "manual"                  # cannot be auto-verified (e.g. key rotation)


class FixStatus(str, Enum):
    VERIFIED = "verified"              # fix proven
    STILL_VULNERABLE = "still-vulnerable"
    BREAKS_BUILD = "breaks-build"
    NOT_ATTEMPTED = "not-attempted"    # no automated patch available
    INCONCLUSIVE = "inconclusive"      # could not run verification (e.g. offline)


@dataclass
class Evidence:
    """A concrete artifact supporting a finding."""

    kind: str                  # "code" | "http-exchange" | "bundle" | "sql" | "registry"
    detail: str
    location: str              # "path/to/file:line" or URL
    request: Optional[dict] = None
    response: Optional[dict] = None

    def to_dict(self) -> dict:
        d = asdict(self)
        return {k: v for k, v in d.items() if v is not None}


@dataclass
class ExploitSpec:
    """A replayable exploit. The verifier runs this against the fixed app.

    steps: list of HTTP steps with templating ({{base}}, {{token}}, captures via
           "as": "name" and extraction from JSON bodies with dotted paths).
    success_if: which step indicates the exploit worked and what proves it.
    """

    kind: str = "http-replay"
    steps: list[dict] = field(default_factory=list)
    success_if: dict = field(default_factory=dict)
    description: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Finding:
    rule: str                      # stable rule id, e.g. "secrets/supabase-service-role"
    category: Category
    title: str
    severity: Severity
    confidence: Confidence
    description: str               # what you shipped / why it's dangerous
    remediation: str               # what a senior engineer would do
    location: str                  # primary location: "file:line" or URL
    evidence: list[Evidence] = field(default_factory=list)
    exploit: Optional[ExploitSpec] = None
    verification_mode: VerificationMode = VerificationMode.RESCAN
    tags: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    id: str = ""

    def __post_init__(self) -> None:
        if not self.id:
            raw = f"{self.rule}|{self.location}|{self.title}"
            self.id = "R-" + hashlib.sha256(raw.encode()).hexdigest()[:10]
        if self.exploit is not None:
            self.verification_mode = VerificationMode.EXPLOIT_REPLAY

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "rule": self.rule,
            "category": self.category.value,
            "title": self.title,
            "severity": self.severity.value,
            "confidence": self.confidence.value,
            "description": self.description,
            "remediation": self.remediation,
            "location": self.location,
            "evidence": [e.to_dict() for e in self.evidence],
            "exploit": self.exploit.to_dict() if self.exploit else None,
            "verification_mode": self.verification_mode.value,
            "tags": self.tags,
            "metadata": self.metadata,
        }


@dataclass
class Patch:
    """A proposed minimal change fixing one finding."""

    finding_id: str
    summary: str
    edits: list[dict] = field(default_factory=list)       # {"path", "old"?, "new", "kind": "modify"|"create"|"delete"}
    new_files: dict[str, str] = field(default_factory=dict)
    deletions: list[str] = field(default_factory=list)
    diff: str = ""                                        # unified diff for display
    note: str = ""                                        # extra instruction (e.g. "rotate this key NOW")
    automatic: bool = True                                # False => guidance only, cannot auto-apply

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class FixResult:
    finding_id: str
    status: FixStatus
    mode: VerificationMode
    detail: str
    evidence: list[Evidence] = field(default_factory=list)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["status"] = self.status.value
        d["mode"] = self.mode.value
        d["evidence"] = [e.to_dict() for e in self.evidence]
        return d


@dataclass
class ScanReport:
    target: str
    findings: list[Finding] = field(default_factory=list)
    meta: dict[str, Any] = field(default_factory=dict)

    def by_severity(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for f in self.findings:
            counts[f.severity.value] = counts.get(f.severity.value, 0) + 1
        return counts

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "meta": self.meta,
            "summary": self.by_severity(),
            "findings": [f.to_dict() for f in self.findings],
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)


@dataclass
class AuditReport:
    """Scan + patches + verification results for one project."""

    target: str
    scan: ScanReport
    patches: list[Patch] = field(default_factory=list)
    fixes: list[FixResult] = field(default_factory=list)
    meta: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "meta": self.meta,
            "scan": self.scan.to_dict(),
            "patches": [p.to_dict() for p in self.patches],
            "fixes": [f.to_dict() for f in self.fixes],
        }
