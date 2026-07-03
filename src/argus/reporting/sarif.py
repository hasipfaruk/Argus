"""SARIF 2.1.0 reporter.

SARIF is the interchange format GitHub Code Scanning and most enterprise security
platforms ingest. This produces a single run with one rule per Argus rule_id and
one result per finding, mapping Argus severities onto SARIF levels and attaching
``security-severity`` (the numeric score GitHub uses to bucket alerts).
"""

from __future__ import annotations

import json

from argus import __version__
from argus.core.models import ScanResult, Severity
from argus.core.plugin import Reporter, reporter

# Argus severity -> SARIF result level.
_LEVEL = {
    Severity.INFO: "note",
    Severity.LOW: "note",
    Severity.MEDIUM: "warning",
    Severity.HIGH: "error",
    Severity.CRITICAL: "error",
}

# Argus severity -> GitHub "security-severity" numeric bucket (CVSS-like).
_SECURITY_SEVERITY = {
    Severity.INFO: "0.0",
    Severity.LOW: "3.0",
    Severity.MEDIUM: "5.5",
    Severity.HIGH: "7.5",
    Severity.CRITICAL: "9.5",
}


@reporter
class SARIFReporter(Reporter):
    name = "sarif"
    extension = "sarif"
    description = "SARIF 2.1.0 for GitHub Code Scanning and enterprise platforms."

    def render(self, result: ScanResult) -> str:
        rules: dict[str, dict] = {}
        results: list[dict] = []

        for f in result.sorted_findings():
            if f.rule_id not in rules:
                rules[f.rule_id] = self._rule(f)
            results.append(self._result(f))

        doc = {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "Argus",
                            "informationUri": "https://github.com/hasipfaruk/Argus",
                            "version": __version__,
                            "rules": list(rules.values()),
                        }
                    },
                    "results": results,
                }
            ],
        }
        return json.dumps(doc, indent=2)

    def _rule(self, f) -> dict:
        rule: dict = {
            "id": f.rule_id,
            "name": f.rule_id.replace(".", "_"),
            "shortDescription": {"text": f.title},
            "fullDescription": {"text": f.why_vulnerable or f.description},
            "defaultConfiguration": {"level": _LEVEL[f.severity]},
            "properties": {
                "security-severity": _SECURITY_SEVERITY[f.severity],
                "tags": ["security", *(f.tags or [])],
            },
        }
        if f.cwe:
            rule["properties"]["cwe"] = f.cwe
        if f.remediation:
            rule["help"] = {
                "text": f.remediation.guidance or f.remediation.summary,
            }
        return rule

    def _result(self, f) -> dict:
        region: dict = {}
        if f.location.start_line:
            region["startLine"] = f.location.start_line
        if f.location.end_line:
            region["endLine"] = f.location.end_line
        if f.location.snippet:
            region["snippet"] = {"text": f.location.snippet}

        physical: dict = {"artifactLocation": {"uri": f.location.path}}
        if region:
            physical["region"] = region

        return {
            "ruleId": f.rule_id,
            "level": _LEVEL[f.severity],
            "message": {"text": self._message(f)},
            "locations": [{"physicalLocation": physical}],
            "partialFingerprints": {"argusFingerprint": f.fingerprint()},
            "properties": {
                "confidence": f.confidence.label,
                "riskScore": f.risk_score(),
            },
        }

    @staticmethod
    def _message(f) -> str:
        parts = [f.title]
        if f.attacker_perspective:
            parts.append(f"Attack: {f.attacker_perspective}")
        if f.remediation:
            parts.append(f"Fix: {f.remediation.summary}")
        return " — ".join(parts)
