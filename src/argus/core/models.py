"""Core data models shared across scanners, agents, and reporters.

Everything Argus produces flows through :class:`Finding`. Keeping a single,
well-defined finding shape is what lets plugins interoperate: a scanner emits
findings, an agent enriches them, and a reporter serializes them without any of
those components knowing about each other.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import IntEnum
from typing import Any

from pydantic import BaseModel, Field


class Severity(IntEnum):
    """Ordered severity levels. Integer ordering allows sorting and thresholds."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, value: str | int | Severity) -> Severity:
        if isinstance(value, Severity):
            return value
        if isinstance(value, int):
            return cls(value)
        return cls[str(value).strip().upper()]

    @property
    def label(self) -> str:
        return self.name.capitalize()

    def to_cvss_band(self) -> str:
        """Rough mapping to a CVSS v3 qualitative band, for report headers."""
        return {
            Severity.INFO: "None",
            Severity.LOW: "Low",
            Severity.MEDIUM: "Medium",
            Severity.HIGH: "High",
            Severity.CRITICAL: "Critical",
        }[self]


class Confidence(IntEnum):
    """How sure Argus is that a finding is a true positive."""

    LOW = 0
    MEDIUM = 1
    HIGH = 2

    @classmethod
    def parse(cls, value: str | int | Confidence) -> Confidence:
        if isinstance(value, Confidence):
            return value
        if isinstance(value, int):
            return cls(value)
        return cls[str(value).strip().upper()]

    @property
    def label(self) -> str:
        return self.name.capitalize()


class Likelihood(IntEnum):
    """Estimated likelihood that a weakness is exploited in practice."""

    RARE = 0
    UNLIKELY = 1
    POSSIBLE = 2
    LIKELY = 3
    ALMOST_CERTAIN = 4

    @property
    def label(self) -> str:
        return self.name.replace("_", " ").title()


class Location(BaseModel):
    """Where a finding lives. Line/column are 1-indexed; None means file-level."""

    path: str
    start_line: int | None = None
    end_line: int | None = None
    start_column: int | None = None
    end_column: int | None = None
    snippet: str | None = None

    def as_ref(self) -> str:
        if self.start_line is None:
            return self.path
        return f"{self.path}:{self.start_line}"


class Remediation(BaseModel):
    """Guidance for fixing a finding, optionally with a concrete patch."""

    summary: str
    guidance: str = ""
    # A unified diff that resolves the finding, when Argus can generate one.
    patch: str | None = None
    # Free-form references (docs, CWE pages, framework advisories).
    references: list[str] = Field(default_factory=list)
    # True once a generated fix has been re-scanned and confirmed to close the issue.
    verified: bool = False


class ExploitScenario(BaseModel):
    """Output of Attack Simulation Mode for a single finding.

    Everything here is generated in an isolated context and is intended to be
    read, not run against production. ``sandbox_ok`` records whether the
    demonstration was executed in a sandbox or produced statically.
    """

    discovery: str = ""          # how an attacker finds the weakness
    exploit_walkthrough: str = ""  # step-by-step, safe to read
    data_at_risk: str = ""       # what could be exposed
    business_impact: str = ""    # plain-language impact
    fix_blocks_attack: str = ""  # why the proposed fix stops it
    before_after: str = ""       # before/after comparison
    sandbox_ok: bool = False


class Finding(BaseModel):
    """A single security finding.

    A finding is more than "line X is vulnerable". It carries the reasoning a
    reviewer needs: why it matters, how it is exploited, its impact, and how to
    fix it — plus the taxonomy mappings tools downstream expect.
    """

    # Identity
    id: str                                  # stable within a scan, e.g. "secrets:aws-key:3"
    rule_id: str                             # the rule/check that produced it
    scanner: str                             # scanner plugin name

    # What & where
    title: str
    description: str
    location: Location

    # Assessment
    severity: Severity = Severity.MEDIUM
    confidence: Confidence = Confidence.MEDIUM
    likelihood: Likelihood = Likelihood.POSSIBLE

    # Taxonomy
    cwe: list[str] = Field(default_factory=list)      # e.g. ["CWE-89"]
    owasp: list[str] = Field(default_factory=list)    # e.g. ["A03:2021-Injection"]

    # The reasoning an AI Security Engineer would give (may be filled by an agent)
    why_vulnerable: str = ""
    attacker_perspective: str = ""
    business_impact: str = ""

    # Remediation & simulation
    remediation: Remediation | None = None
    exploit: ExploitScenario | None = None

    # Provenance / extra data for reporters
    tags: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
    detected_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    def fingerprint(self) -> str:
        """A stable identifier used to de-duplicate and track findings over time."""
        return f"{self.rule_id}|{self.location.path}|{self.location.start_line}"

    def risk_score(self) -> float:
        """A 0–100 score combining severity, confidence, and likelihood.

        Used for ranking and for the dashboard's aggregate risk number. The
        weighting favors severity while letting confidence and likelihood modulate.
        """
        sev = self.severity / Severity.CRITICAL          # 0..1
        conf = (self.confidence + 1) / len(Confidence)   # 0.33..1
        like = (self.likelihood + 1) / len(Likelihood)   # 0.2..1
        return round(100 * sev * (0.6 + 0.25 * conf + 0.15 * like), 1)


class ScanResult(BaseModel):
    """The complete output of a scan: metadata plus every finding."""

    target: str
    started_at: datetime
    finished_at: datetime | None = None
    argus_version: str = ""
    scanners_run: list[str] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    # Snapshot of the project model (languages, frameworks, etc.) for the report.
    project_summary: dict[str, Any] = Field(default_factory=dict)
    errors: list[str] = Field(default_factory=list)

    def add(self, finding: Finding) -> None:
        self.findings.append(finding)

    def sorted_findings(self) -> list[Finding]:
        """Findings ordered most to least important."""
        return sorted(
            self.findings,
            key=lambda f: (f.severity, f.confidence, f.risk_score()),
            reverse=True,
        )

    def counts_by_severity(self) -> dict[str, int]:
        counts = {s.label: 0 for s in reversed(Severity)}
        for f in self.findings:
            counts[f.severity.label] += 1
        return counts

    def aggregate_risk(self) -> float:
        """A single 0–100 risk number for the whole target.

        Not a mean — a single critical should dominate a pile of lows. We take a
        softmax-ish blend: the worst finding sets the floor, volume nudges it up.
        """
        if not self.findings:
            return 0.0
        scores = sorted((f.risk_score() for f in self.findings), reverse=True)
        top = scores[0]
        tail = sum(scores[1:]) / (len(scores) * 20) if len(scores) > 1 else 0
        return round(min(100.0, top + tail), 1)

    def highest_severity(self) -> Severity:
        return max((f.severity for f in self.findings), default=Severity.INFO)
