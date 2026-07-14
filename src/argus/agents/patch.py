"""Patch generation agent.

Proposes a concrete fix as a unified diff and, where possible, verifies it. Two
paths:

* **Deterministic rewrites** for a set of well-understood rules (e.g. unsafe
  ``yaml.load`` → ``yaml.safe_load``). These are self-verifying: Argus re-runs the
  triggering pattern against the rewritten line and only marks the patch
  ``verified`` if the detection no longer fires, a fast, local proxy for "the fix
  resolves the issue without obviously breaking the line".
* **Model-generated patches** when a real provider is configured, for findings
  without a deterministic rewrite. These are proposed but left unverified unless a
  re-scan confirms them.

The agent only proposes changes; it never writes to the working tree. Applying a
patch and opening a pull request is an explicit, separate action.
"""

from __future__ import annotations

import re

from argus.agents.base import Agent, AgentContext
from argus.core.models import Finding, Remediation
from argus.remediation.rewrites import fix_line, verify_line_fixed

_SYSTEM = (
    "You are a secure-coding assistant. Given a vulnerable code snippet and the "
    "issue, return ONLY a minimal corrected version of the snippet that resolves "
    "the vulnerability while preserving behavior. Do not add commentary."
)


class PatchAgent(Agent):
    name = "patch"

    def process(self, finding: Finding, ctx: AgentContext) -> Finding:
        if finding.remediation is None:
            finding.remediation = Remediation(summary="See remediation guidance.")

        original = finding.location.snippet or ""
        fixed = fix_line(finding.rule_id, original)
        verified = False
        source = "deterministic"

        if fixed and fixed != original:
            verified = verify_line_fixed(finding.rule_id, fixed)
        elif self._uses_real_model(ctx) and original:
            # AI-proposed tier: draft a fix, then verify it the same way as a
            # deterministic one (re-run the detection against the rewrite) when a
            # pattern exists. Always labeled for human review; never auto-applied.
            fixed = self._model_fix(finding, ctx, original)
            source = "ai-proposed"
            if fixed and fixed != original:
                verified = verify_line_fixed(finding.rule_id, fixed)

        if fixed and fixed != original:
            finding.remediation.patch = self._unified_diff(
                finding.location.path, original, fixed,
                start_line=finding.location.start_line or 1)
            finding.remediation.verified = verified
            finding.metadata["patch_source"] = source
            if source == "ai-proposed":
                finding.metadata["patch_review"] = "human-review-required"
                note = ("Machine-proposed fix, review before merging."
                        + (" (Re-scan confirmed the detection no longer fires.)"
                           if verified else " (Not automatically verified.)"))
                finding.remediation.guidance = (
                    note + "\n\n" + finding.remediation.guidance
                ).strip()
        return finding

    def _model_fix(self, finding: Finding, ctx: AgentContext, original: str) -> str | None:
        prompt = (
            f"Issue: {finding.title} ({', '.join(finding.cwe)})\n"
            f"File: {finding.location.path}\n"
            f"Vulnerable snippet:\n{original}\n\n"
            "Return the corrected snippet only."
        )
        try:
            out = ctx.ai.complete(_SYSTEM, prompt).strip()
        except Exception as exc:
            finding.metadata["patch_error"] = str(exc)
            return None
        # Strip code fences if the model added them.
        out = re.sub(r"^```[a-zA-Z]*\n?|\n?```$", "", out).strip()
        return out or None

    @staticmethod
    def _unified_diff(path: str, before: str, after: str, start_line: int) -> str:
        """A compact unified diff for a single changed line/snippet."""
        return (
            f"--- a/{path}\n"
            f"+++ b/{path}\n"
            f"@@ -{start_line} +{start_line} @@\n"
            f"-{before}\n"
            f"+{after}\n"
        )
