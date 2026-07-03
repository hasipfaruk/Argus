"""Markdown reporter.

A human-readable report suitable for PR comments, issue bodies, or committing into
a repo. Leads with a summary table, then one section per finding including the
attack simulation and any generated patch.
"""

from __future__ import annotations

from argus.core.models import ScanResult, Severity
from argus.core.plugin import Reporter, reporter

_SEV_EMOJI = {
    Severity.CRITICAL: "🔴",
    Severity.HIGH: "🟠",
    Severity.MEDIUM: "🟡",
    Severity.LOW: "🔵",
    Severity.INFO: "⚪",
}


@reporter
class MarkdownReporter(Reporter):
    name = "markdown"
    extension = "md"
    description = "Human-readable Markdown report for PRs and issues."

    def render(self, result: ScanResult) -> str:
        out: list[str] = []
        summary = result.project_summary
        out.append(f"# Argus Security Report — {summary.get('name', result.target)}")
        out.append("")
        out.append(self._overview(result))
        out.append("")
        out.append(self._severity_table(result))
        out.append("")

        findings = result.sorted_findings()
        if not findings:
            out.append("No findings at or above the configured severity threshold. ✅")
            return "\n".join(out)

        out.append("## Findings")
        out.append("")
        for i, f in enumerate(findings, start=1):
            out.append(self._finding(i, f))
            out.append("")
        return "\n".join(out)

    def _overview(self, result: ScanResult) -> str:
        s = result.project_summary
        langs = ", ".join(f"{k} ({v})" for k, v in (s.get("languages") or {}).items())
        arch = s.get("architecture", {}) or {}
        lines = [
            f"**Target:** `{result.target}`  ",
            f"**Scanned:** {result.started_at:%Y-%m-%d %H:%M UTC}  ",
            f"**Argus:** v{result.argus_version}  ",
            f"**Aggregate risk:** {result.aggregate_risk()} / 100  ",
            f"**Files:** {s.get('file_count', 'n/a')}  ",
            f"**Languages:** {langs or 'n/a'}  ",
        ]
        if s.get("frameworks"):
            lines.append(f"**Frameworks:** {', '.join(s['frameworks'])}  ")
        if arch.get("apis"):
            lines.append(f"**APIs:** {', '.join(arch['apis'])}  ")
        if arch.get("datastores"):
            lines.append(f"**Datastores:** {', '.join(arch['datastores'])}  ")
        if result.errors:
            lines.append(f"**Scan warnings:** {len(result.errors)}  ")
        return "\n".join(lines)

    def _severity_table(self, result: ScanResult) -> str:
        counts = result.counts_by_severity()
        header = "| " + " | ".join(counts.keys()) + " | Total |"
        divider = "|" + "|".join(["---"] * (len(counts) + 1)) + "|"
        row = "| " + " | ".join(str(v) for v in counts.values()) + \
              f" | {sum(counts.values())} |"
        return "\n".join(["## Summary", "", header, divider, row])

    def _finding(self, index: int, f) -> str:
        emoji = _SEV_EMOJI.get(f.severity, "")
        lines = [
            f"### {index}. {emoji} {f.title}",
            "",
            f"- **Severity:** {f.severity.label} "
            f"(risk {f.risk_score()}/100) · **Confidence:** {f.confidence.label} · "
            f"**Likelihood:** {f.likelihood.label}",
            f"- **Location:** `{f.location.as_ref()}`",
            f"- **Scanner/Rule:** `{f.scanner}` / `{f.rule_id}`",
        ]
        if f.cwe or f.owasp:
            lines.append(f"- **Mapping:** {', '.join(f.cwe + f.owasp)}")
        lines.append("")
        if f.location.snippet:
            lines.append("```")
            lines.append(f.location.snippet)
            lines.append("```")
            lines.append("")
        if f.why_vulnerable:
            lines.append(f"**Why it's a vulnerability:** {f.why_vulnerable}")
            lines.append("")
        if f.attacker_perspective:
            lines.append(f"**How an attacker exploits it:** {f.attacker_perspective}")
            lines.append("")
        if f.business_impact:
            lines.append(f"**Business impact:** {f.business_impact}")
            lines.append("")

        if f.exploit:
            lines.append(self._exploit(f.exploit))

        if f.remediation:
            lines.append("**Remediation:** " + f.remediation.summary)
            if f.remediation.guidance and f.remediation.guidance != f.remediation.summary:
                lines.append("")
                lines.append(f.remediation.guidance)
            if f.remediation.patch:
                status = "✅ verified" if f.remediation.verified else "proposed"
                lines.append("")
                lines.append(f"**Suggested patch ({status}):**")
                lines.append("```diff")
                lines.append(f.remediation.patch.rstrip())
                lines.append("```")
            lines.append("")
        return "\n".join(lines)

    @staticmethod
    def _exploit(ex) -> str:
        lines = ["<details><summary>🎯 Attack simulation</summary>", ""]
        rows = [
            ("Discovery", ex.discovery),
            ("Walkthrough", ex.exploit_walkthrough),
            ("Data at risk", ex.data_at_risk),
            ("Business impact", ex.business_impact),
            ("How the fix blocks it", ex.fix_blocks_attack),
            ("Before / after", ex.before_after),
        ]
        for label, value in rows:
            if value:
                lines.append(f"- **{label}:** {value}")
        lines.append("")
        lines.append("_Simulation generated in an isolated context; no live target "
                     "was contacted._")
        lines.append("</details>")
        lines.append("")
        return "\n".join(lines)
