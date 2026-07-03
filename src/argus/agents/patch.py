"""Patch generation agent.

Proposes a concrete fix as a unified diff and, where possible, verifies it. Two
paths:

* **Deterministic rewrites** for a set of well-understood rules (e.g. unsafe
  ``yaml.load`` → ``yaml.safe_load``). These are self-verifying: Argus re-runs the
  triggering pattern against the rewritten line and only marks the patch
  ``verified`` if the detection no longer fires — a fast, local proxy for "the fix
  resolves the issue without obviously breaking the line".
* **Model-generated patches** when a real provider is configured, for findings
  without a deterministic rewrite. These are proposed but left unverified unless a
  re-scan confirms them.

The agent only proposes changes; it never writes to the working tree. Applying a
patch and opening a pull request is an explicit, separate action.
"""

from __future__ import annotations

import re
from collections.abc import Callable

from argus.agents.base import Agent, AgentContext
from argus.core.models import Finding, Remediation

# rule_id -> function(line) -> fixed_line | None. Deterministic, local rewrites.
_REWRITES: dict[str, Callable[[str], str | None]] = {
    "patterns.python-yaml-load": lambda ln: re.sub(r"yaml\.load\(", "yaml.safe_load(", ln)
        if "yaml.load(" in ln and "Safe" not in ln else None,
    "patterns.weak-hash-md5-sha1": lambda ln: (
        ln.replace("md5", "sha256").replace("sha1", "sha256")
        .replace("MD5", "SHA-256").replace("SHA-1", "SHA-256").replace("SHA1", "SHA-256")
        if re.search(r"(?i)md5|sha-?1", ln) else None),
    "patterns.python-shell-true": lambda ln: re.sub(
        r",?\s*shell\s*=\s*True", "", ln) if "shell=True" in ln.replace(" ", "") or
        "shell = True" in ln else re.sub(r"shell\s*=\s*True", "shell=False", ln),
    "patterns.tls-verify-disabled": lambda ln: (
        ln.replace("verify=False", "verify=True")
        .replace("verify = False", "verify = True")
        .replace("rejectUnauthorized: false", "rejectUnauthorized: true")
        .replace("InsecureSkipVerify: true", "InsecureSkipVerify: false")),
    "patterns.flask-debug-true": lambda ln: re.sub(
        r"debug\s*=\s*True", "debug=False", ln),
}

# For self-verification we need the original detection pattern per rule. We pull
# it from the pattern scanner's rule table lazily to avoid a hard import cycle.
def _detection_pattern(rule_id: str) -> re.Pattern[str] | None:
    from argus.scanners.patterns import RULES
    short = rule_id.split(".", 1)[-1]
    for rule in RULES:
        if rule.id == short:
            return rule.pattern
    return None


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
        fixed = self._deterministic_fix(finding, original)
        verified = False

        if fixed and fixed != original:
            verified = self._verify(finding, fixed)
        elif self._uses_real_model(ctx) and original:
            fixed = self._model_fix(finding, ctx, original)

        if fixed and fixed != original:
            finding.remediation.patch = self._unified_diff(
                finding.location.path, original, fixed,
                start_line=finding.location.start_line or 1)
            finding.remediation.verified = verified
        return finding

    def _deterministic_fix(self, finding: Finding, line: str) -> str | None:
        fn = _REWRITES.get(finding.rule_id)
        if not fn or not line:
            return None
        try:
            return fn(line)
        except Exception:
            return None

    def _verify(self, finding: Finding, fixed_line: str) -> bool:
        """A patch is verified if the original detection no longer matches it."""
        pattern = _detection_pattern(finding.rule_id)
        if pattern is None:
            return False
        return not pattern.search(fixed_line)

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
