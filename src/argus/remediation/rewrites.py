"""Deterministic, line-level fix rewrites.

A rewrite maps a finding's ``rule_id`` to a function that transforms the offending
source line into a fixed one, preserving surrounding syntax and indentation (the
function operates on the real line, so whitespace is kept automatically). These
are the fixes Argus can apply and verify locally without a model:

* ``fix_line`` applies the rewrite for a rule to a line.
* ``verify_line_fixed`` confirms the rewrite actually removes the detection, a
  fast, local proxy for "the fix resolves the issue".

Both the :class:`~argus.agents.patch.PatchAgent` (which proposes patches) and the
:mod:`~argus.remediation.applier` (which writes them to disk) use this module, so
proposal and application can never drift apart.
"""

from __future__ import annotations

import re
from collections.abc import Callable


def _fix_yaml_load(ln: str) -> str | None:
    if "yaml.load(" not in ln or "Safe" in ln:
        return None
    return ln.replace("yaml.load(", "yaml.safe_load(")


def _fix_weak_hash(ln: str) -> str | None:
    """Upgrade weak hashes to SHA-256, but only at the actual call sites.

    A blanket string replace would corrupt identifiers or strings that merely
    contain ``md5``/``sha1`` (e.g. a variable named ``md5_util``), so each
    substitution is anchored to the recognized construction pattern.
    """
    replacements = (
        (r"hashlib\.md5\(", "hashlib.sha256("),
        (r"hashlib\.sha1\(", "hashlib.sha256("),
        (r"(createHash\(\s*['\"])md5", r"\1sha256"),
        (r"(createHash\(\s*['\"])sha1", r"\1sha256"),
        (r"(MessageDigest\.getInstance\(\s*['\"])MD5", r"\1SHA-256"),
        (r"(MessageDigest\.getInstance\(\s*['\"])SHA-?1", r"\1SHA-256"),
    )
    fixed = ln
    for pattern, repl in replacements:
        fixed = re.sub(pattern, repl, fixed, flags=re.IGNORECASE)
    return fixed if fixed != ln else None


def _fix_shell_true(ln: str) -> str | None:
    """Set ``shell=False`` rather than deleting the argument.

    Removing ``shell=True`` outright can silently change behavior (and break call
    sites that pass a command string). Flipping the value keeps the call shape and
    still clears the detection; the developer reviews the PR before merging.
    """
    fixed = re.sub(r"shell\s*=\s*True", "shell=False", ln)
    return fixed if fixed != ln else None


def _fix_tls_verify(ln: str) -> str | None:
    fixed = (
        re.sub(r"verify\s*=\s*False", "verify=True", ln)
        .replace("rejectUnauthorized: false", "rejectUnauthorized: true")
        .replace("rejectUnauthorized:false", "rejectUnauthorized:true")
        .replace("InsecureSkipVerify: true", "InsecureSkipVerify: false")
        .replace("InsecureSkipVerify:true", "InsecureSkipVerify:false")
    )
    return fixed if fixed != ln else None


def _fix_flask_debug(ln: str) -> str | None:
    fixed = re.sub(r"debug\s*=\s*True", "debug=False", ln)
    return fixed if fixed != ln else None


def _fix_trust_remote_code(ln: str) -> str | None:
    fixed = re.sub(r"trust_remote_code\s*=\s*True", "trust_remote_code=False", ln)
    return fixed if fixed != ln else None


def _fix_torch_load(ln: str) -> str | None:
    """Add ``weights_only=True`` to a ``torch.load(...)`` call that lacks it.

    Injects the keyword before the first closing paren of the call, which covers
    the common single-line form. Skips lines that already pass weights_only.
    """
    if "torch.load(" not in ln or "weights_only" in ln:
        return None
    fixed = re.sub(r"(torch\.load\([^)]*?)\s*\)", r"\1, weights_only=True)", ln, count=1)
    return fixed if fixed != ln else None


# rule_id -> function(line) -> fixed_line | None (None = no change / not applicable).
REWRITES: dict[str, Callable[[str], str | None]] = {
    "patterns.python-yaml-load": _fix_yaml_load,
    "patterns.weak-hash-md5-sha1": _fix_weak_hash,
    "patterns.python-shell-true": _fix_shell_true,
    "patterns.tls-verify-disabled": _fix_tls_verify,
    "patterns.flask-debug-true": _fix_flask_debug,
    "llm.trust-remote-code": _fix_trust_remote_code,
    "llm.torch-load-pickle": _fix_torch_load,
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
    """The scanner regex that produced this rule, for self-verification.

    Searches both the ``patterns`` and ``llm`` rule sets (loaded lazily to avoid
    an import cycle with the scanners package), so a rewrite for either scanner
    can be verified by confirming the detection no longer fires.
    """
    short = rule_id.split(".", 1)[-1]
    from argus.scanners.llm import RULES as LLM_RULES
    from argus.scanners.patterns import RULES as PATTERN_RULES

    for pattern_rule in PATTERN_RULES:
        if pattern_rule.id == short:
            return pattern_rule.pattern
    for llm_rule in LLM_RULES:
        if llm_rule.id == short:
            return llm_rule.pattern
    return None


def verify_line_fixed(rule_id: str, fixed_line: str) -> bool:
    """True if the original detection no longer matches the fixed line."""
    pattern = detection_pattern(rule_id)
    if pattern is None:
        return False
    return not pattern.search(fixed_line)
