"""Deterministic, line-level fix rewrites.

A rewrite maps a finding's ``rule_id`` to a function that transforms the offending
source line into a fixed one, preserving surrounding syntax and indentation (the
function operates on the real line, so whitespace is kept automatically). These
are the fixes Argus can apply and verify locally without a model:

* ``fix_line`` applies the rewrite for a rule to a line.
* ``verify_line_fixed`` confirms the rewrite actually removes the detection — a
  fast, local proxy for "the fix resolves the issue".

Both the :class:`~argus.agents.patch.PatchAgent` (which proposes patches) and the
:mod:`~argus.remediation.applier` (which writes them to disk) use this module, so
proposal and application can never drift apart.
"""

from __future__ import annotations

import re
from collections.abc import Callable

# rule_id -> function(line) -> fixed_line | None (None = no change / not applicable).
REWRITES: dict[str, Callable[[str], str | None]] = {
    "patterns.python-yaml-load": lambda ln: (
        re.sub(r"yaml\.load\(", "yaml.safe_load(", ln)
        if "yaml.load(" in ln and "Safe" not in ln else None
    ),
    "patterns.weak-hash-md5-sha1": lambda ln: (
        ln.replace("md5", "sha256").replace("sha1", "sha256")
        .replace("MD5", "SHA-256").replace("SHA-1", "SHA-256").replace("SHA1", "SHA-256")
        if re.search(r"(?i)md5|sha-?1", ln) else None
    ),
    "patterns.python-shell-true": lambda ln: (
        re.sub(r",?\s*shell\s*=\s*True", "", ln)
        if "shell=True" in ln.replace(" ", "")
        else re.sub(r"shell\s*=\s*True", "shell=False", ln)
    ),
    "patterns.tls-verify-disabled": lambda ln: (
        ln.replace("verify=False", "verify=True")
        .replace("verify = False", "verify = True")
        .replace("rejectUnauthorized: false", "rejectUnauthorized: true")
        .replace("InsecureSkipVerify: true", "InsecureSkipVerify: false")
    ),
    "patterns.flask-debug-true": lambda ln: re.sub(r"debug\s*=\s*True", "debug=False", ln),
}


def has_rewrite(rule_id: str) -> bool:
    return rule_id in REWRITES


def fix_line(rule_id: str, line: str) -> str | None:
    """Return the fixed version of ``line`` for ``rule_id``, or None if not fixable."""
    fn = REWRITES.get(rule_id)
    if fn is None or not line:
        return None
    try:
        return fn(line)
    except Exception:
        return None


def detection_pattern(rule_id: str) -> re.Pattern[str] | None:
    """The pattern-scanner regex that produced this rule, for self-verification.

    Loaded lazily to avoid an import cycle with the scanners package.
    """
    from argus.scanners.patterns import RULES

    short = rule_id.split(".", 1)[-1]
    for rule in RULES:
        if rule.id == short:
            return rule.pattern
    return None


def verify_line_fixed(rule_id: str, fixed_line: str) -> bool:
    """True if the original detection no longer matches the fixed line."""
    pattern = detection_pattern(rule_id)
    if pattern is None:
        return False
    return not pattern.search(fixed_line)
