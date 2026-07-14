"""Load user/community SAST rules from YAML, no Python required.

The `patterns` scanner is rule-driven, and this module lets anyone extend it
with a YAML file instead of code, lowering the contribution bar to "regex + a
few fields" (the model that grew Semgrep's community rule registry). Rules are
loaded from:

* any path(s) in ``scanner_options.patterns.rules`` (a string or list; globs
  allowed), and
* the convention directory ``.argus/rules/*.yml`` in the project root.

A YAML rules file:

    rules:
      - id: hardcoded-internal-ip
        title: Hardcoded internal IP address
        pattern: '\\b10\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\b'
        severity: low            # info | low | medium | high | critical
        languages: [Python, Go]  # optional; omit for all languages
        cwe: [CWE-1188]          # optional
        owasp: ["A05:2021-Security Misconfiguration"]   # optional
        confidence: medium       # optional: low | medium | high
        why: "An internal IP is baked into source."
        attack: "..."            # optional
        impact: "..."            # optional
        fix: "Move host addresses to configuration."
        suppress: 'ALLOW_INTERNAL_IP'   # optional: a regex that clears a match

Invalid rules are skipped with a warning rather than aborting the scan, a
malformed community rule must never break a user's pipeline.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path

import yaml

from argus.core.models import Confidence, Severity
from argus.scanners.patterns import Rule

log = logging.getLogger("argus.scanners.custom_rules")

_CONFIDENCE = {"low": Confidence.LOW, "medium": Confidence.MEDIUM,
               "high": Confidence.HIGH}


def _coerce_rule(raw: dict, source: str) -> Rule | None:
    try:
        rid = str(raw["id"]).strip()
        pattern = re.compile(str(raw["pattern"]))
    except (KeyError, re.error, TypeError) as exc:
        log.warning("skipping custom rule in %s: %s", source, exc)
        return None
    if not rid:
        log.warning("skipping custom rule in %s: empty id", source)
        return None
    return Rule(
        id=rid,
        title=str(raw.get("title", rid)),
        pattern=pattern,
        severity=Severity.parse(str(raw.get("severity", "medium"))),
        cwe=list(raw.get("cwe", []) or []),
        owasp=list(raw.get("owasp", []) or []),
        why=str(raw.get("why", "")),
        attack=str(raw.get("attack", "")),
        impact=str(raw.get("impact", "")),
        fix=str(raw.get("fix", "")),
        languages=set(raw.get("languages", []) or []),
        confidence=_CONFIDENCE.get(str(raw.get("confidence", "medium")).lower(),
                                   Confidence.MEDIUM),
        references=list(raw.get("references", []) or []),
        suppress=re.compile(str(raw["suppress"])) if raw.get("suppress") else None,
    )


def _load_file(path: Path) -> list[Rule]:
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError) as exc:
        log.warning("could not read custom rules from %s: %s", path, exc)
        return []
    raw_rules = data.get("rules") if isinstance(data, dict) else None
    if not isinstance(raw_rules, list):
        log.warning("%s: expected a top-level 'rules:' list", path)
        return []
    out = []
    for raw in raw_rules:
        if isinstance(raw, dict):
            rule = _coerce_rule(raw, str(path))
            if rule is not None:
                out.append(rule)
    return out


def _resolve_paths(project_root: Path, option) -> list[Path]:
    """Collect rule-file paths from the config option and the convention dir."""
    paths: list[Path] = []
    specs: list[str] = []
    if isinstance(option, str):
        specs = [option]
    elif isinstance(option, (list, tuple)):
        specs = [str(s) for s in option]
    for spec in specs:
        p = Path(spec)
        if p.is_absolute():
            paths.append(p)
        else:
            paths.extend(sorted(project_root.glob(spec)))
    # Convention directory (deterministic order).
    conv = project_root / ".argus" / "rules"
    if conv.is_dir():
        paths.extend(sorted(conv.glob("*.yml")))
        paths.extend(sorted(conv.glob("*.yaml")))
    # De-duplicate while preserving order.
    seen: set[str] = set()
    unique: list[Path] = []
    for p in paths:
        key = str(p.resolve())
        if key not in seen and p.is_file():
            seen.add(key)
            unique.append(p)
    return unique


def load_custom_rules(project_root: Path, option=None) -> list[Rule]:
    """Load and validate all custom rules for a project. Never raises."""
    rules: list[Rule] = []
    for path in _resolve_paths(project_root, option):
        rules.extend(_load_file(path))
    if rules:
        log.info("loaded %d custom rule(s)", len(rules))
    return rules


def config_signature(project_root: Path, option=None) -> str:
    """A stable signature of the active custom-rule files (path + mtime + size).

    Folded into the scanner cache key so editing a rules file invalidates cached
    findings for that project.
    """
    parts: list[str] = []
    for path in _resolve_paths(project_root, option):
        try:
            st = path.stat()
            parts.append(f"{path}:{int(st.st_mtime)}:{st.st_size}")
        except OSError:
            continue
    return "|".join(parts)
