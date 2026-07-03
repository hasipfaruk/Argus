"""Enrichment agent: fill the reasoning fields of a finding.

Ensures every finding answers "why is this a vulnerability", "how would an
attacker exploit it", and "what is the business impact". Scanners already provide
these for their built-in rules; this agent fills gaps and, when a real model is
configured, rewrites them with project-specific context.
"""

from __future__ import annotations

from argus.agents.base import Agent, AgentContext
from argus.ai.heuristic import HeuristicProvider
from argus.core.models import Finding

_SYSTEM = (
    "You are a senior application security engineer. Given a vulnerability finding, "
    "explain it precisely and without exaggeration. Be concrete and actionable. "
    "Respond in three short sections labelled exactly: WHY, ATTACK, IMPACT."
)


class EnrichmentAgent(Agent):
    name = "enrichment"

    def process(self, finding: Finding, ctx: AgentContext) -> Finding:
        # If the scanner already supplied full reasoning, leave it unless a real
        # model can improve it with project context.
        has_reasoning = all([finding.why_vulnerable, finding.attacker_perspective,
                             finding.business_impact])

        if self._uses_real_model(ctx):
            if not has_reasoning or ctx.config.ai.enabled:
                self._enrich_with_model(finding, ctx)
            return finding

        # Heuristic path: fill any missing fields from CWE templates.
        if not has_reasoning:
            self._enrich_heuristic(finding)
        return finding

    def _enrich_heuristic(self, finding: Finding) -> None:
        for cwe in finding.cwe:
            notes = HeuristicProvider.notes_for_cwe(cwe)
            if notes:
                finding.why_vulnerable = finding.why_vulnerable or notes["why"]
                finding.attacker_perspective = (
                    finding.attacker_perspective or notes["attack"])
                finding.business_impact = finding.business_impact or notes["impact"]
                return
        # Generic fallback when no CWE template matches.
        finding.why_vulnerable = finding.why_vulnerable or finding.description
        finding.attacker_perspective = finding.attacker_perspective or (
            "An attacker who reaches this code path can supply crafted input to "
            "trigger the weakness described above.")
        finding.business_impact = finding.business_impact or (
            "Potential loss of confidentiality, integrity, or availability "
            "depending on the data and privileges involved.")

    def _enrich_with_model(self, finding: Finding, ctx: AgentContext) -> None:
        prompt = self._build_prompt(finding, ctx)
        try:
            answer = ctx.ai.complete(_SYSTEM, prompt)
        except Exception as exc:  # never let enrichment abort a scan
            finding.metadata["enrichment_error"] = str(exc)
            self._enrich_heuristic(finding)
            return
        sections = self._parse_sections(answer)
        if sections.get("why"):
            finding.why_vulnerable = sections["why"]
        if sections.get("attack"):
            finding.attacker_perspective = sections["attack"]
        if sections.get("impact"):
            finding.business_impact = sections["impact"]
        if not any(sections.values()):
            self._enrich_heuristic(finding)

    @staticmethod
    def _build_prompt(finding: Finding, ctx: AgentContext) -> str:
        loc = finding.location
        return (
            f"Project: {ctx.project.name}\n"
            f"Languages: {', '.join(ctx.project.languages) or 'unknown'}\n"
            f"Frameworks: {', '.join(ctx.project.frameworks) or 'none detected'}\n\n"
            f"Finding: {finding.title}\n"
            f"Rule: {finding.rule_id}\n"
            f"CWE: {', '.join(finding.cwe) or 'n/a'}  "
            f"OWASP: {', '.join(finding.owasp) or 'n/a'}\n"
            f"Location: {loc.as_ref()}\n"
            f"Code:\n{loc.snippet or '(not available)'}\n\n"
            "Explain this finding for the developer who owns this code."
        )

    @staticmethod
    def _parse_sections(text: str) -> dict[str, str]:
        out = {"why": "", "attack": "", "impact": ""}
        current = None
        for line in text.splitlines():
            stripped = line.strip()
            upper = stripped.upper()
            if upper.startswith("WHY"):
                current = "why"
                stripped = stripped.split(":", 1)[-1].strip()
            elif upper.startswith("ATTACK"):
                current = "attack"
                stripped = stripped.split(":", 1)[-1].strip()
            elif upper.startswith("IMPACT"):
                current = "impact"
                stripped = stripped.split(":", 1)[-1].strip()
            if current and stripped:
                out[current] = (out[current] + " " + stripped).strip()
        return out
