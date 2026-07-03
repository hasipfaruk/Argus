"""Dependency vulnerability scanner.

Parses dependency manifests for the common ecosystems, then matches declared
versions against a bundled advisory database (``data/advisories.json``). The
database ships as a small seed set so the scanner is useful offline; a plugin can
replace or extend it by syncing from OSV or the GitHub Advisory Database.

Version comparison is intentionally lightweight — enough to evaluate the simple
``<x.y.z`` ranges the seed data uses, without pulling in a full SemVer engine.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable
from functools import lru_cache
from importlib import resources

from argus.core.models import (
    Confidence,
    Finding,
    Likelihood,
    Location,
    Remediation,
    Severity,
)
from argus.core.plugin import Scanner, ScannerContext, scanner


@lru_cache(maxsize=1)
def _load_advisories() -> list[dict]:
    with resources.files("argus.scanners.data").joinpath("advisories.json").open(
        encoding="utf-8"
    ) as fh:
        return json.load(fh).get("advisories", [])


def _parse_version(v: str) -> tuple[int, ...]:
    parts = re.split(r"[.\-+]", v.strip())
    nums: list[int] = []
    for p in parts:
        m = re.match(r"\d+", p)
        nums.append(int(m.group()) if m else 0)
        if not m:
            break
    return tuple(nums) or (0,)


def _version_lt(a: str, b: str) -> bool:
    return _parse_version(a) < _parse_version(b)


def _matches_range(version: str, spec: str) -> bool:
    """Evaluate the small subset of range syntax used by the advisory data."""
    spec = spec.strip()
    if spec.startswith("<="):
        return not _version_lt(spec[2:], version)  # version <= bound
    if spec.startswith("<"):
        return _version_lt(version, spec[1:])
    if spec.startswith(">="):
        return not _version_lt(version, spec[2:])
    if spec.startswith(">"):
        return _version_lt(spec[1:], version)
    if spec.startswith("=="):
        return _parse_version(version) == _parse_version(spec[2:])
    return _parse_version(version) == _parse_version(spec)


# --- manifest parsers ------------------------------------------------------
def _parse_requirements(text: str) -> dict[str, str]:
    deps: dict[str, str] = {}
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line or line.startswith("-"):
            continue
        m = re.match(r"^([A-Za-z0-9_.\-]+)\s*==\s*([0-9][\w.\-]*)", line)
        if m:
            deps[m.group(1).lower()] = m.group(2)
    return deps


def _parse_package_json(text: str) -> dict[str, str]:
    deps: dict[str, str] = {}
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return deps
    for key in ("dependencies", "devDependencies", "optionalDependencies"):
        for name, ver in (data.get(key) or {}).items():
            cleaned = ver.lstrip("^~>=< ").strip()
            if re.match(r"^\d", cleaned):
                deps[name.lower()] = cleaned
    return deps


_PARSERS = {
    "requirements.txt": ("PyPI", _parse_requirements),
    "package.json": ("npm", _parse_package_json),
}


@scanner
class DependencyScanner(Scanner):
    name = "dependencies"
    category = "dependencies"
    description = "Flags dependencies with known published vulnerabilities."

    def applies_to(self, project) -> bool:
        return bool(project.files_matching(*_PARSERS.keys()))

    def scan(self, ctx: ScannerContext) -> Iterable[Finding]:
        advisories = _load_advisories()
        counter = 0
        for manifest_name, (ecosystem, parser) in _PARSERS.items():
            for f in ctx.project.files_matching(manifest_name):
                deps = parser(f.text())
                for pkg, version in deps.items():
                    for adv in advisories:
                        if adv["ecosystem"] != ecosystem or adv["package"] != pkg:
                            continue
                        if _matches_range(version, adv["vulnerable"]):
                            counter += 1
                            yield self._finding(adv, counter, f.rel_path, pkg, version)

    def _finding(self, adv: dict, index: int, path: str, pkg: str,
                 version: str) -> Finding:
        sev = Severity.parse(adv.get("severity", "MEDIUM"))
        cve = adv.get("cve", "")
        fixed = adv.get("fixed", "")
        return Finding(
            id=f"{self.name}:{adv['id']}:{index}",
            rule_id=f"{self.name}.{adv['id']}",
            scanner=self.name,
            title=f"Vulnerable dependency: {pkg} {version} ({cve})" if cve
                  else f"Vulnerable dependency: {pkg} {version}",
            description=adv.get("summary", adv.get("title", "")),
            location=Location(path=path, snippet=f"{pkg}=={version}"),
            severity=sev,
            confidence=Confidence.HIGH,
            likelihood=Likelihood.LIKELY,
            cwe=adv.get("cwe", ["CWE-1104"]),
            owasp=["A06:2021-Vulnerable and Outdated Components"],
            why_vulnerable=(
                f"{pkg} {version} is affected by {cve or adv['id']}: "
                f"{adv.get('title', '')}."
            ),
            attacker_perspective=(
                "An attacker can use the public advisory/exploit for this known "
                "vulnerability directly against the running application."
            ),
            business_impact="Depends on the advisory; see the referenced CVE for the "
                            "specific impact and exploitability.",
            remediation=Remediation(
                summary=f"Upgrade {pkg} to {fixed} or later." if fixed
                        else f"Upgrade {pkg} to a patched version.",
                guidance=(
                    f"Update the pinned version of {pkg} to "
                    f"{fixed or 'the latest patched release'} and re-run tests. "
                    "Review the advisory for any required migration steps."
                ),
                references=[
                    f"https://nvd.nist.gov/vuln/detail/{cve}" if cve else "",
                    f"https://github.com/advisories/{adv['id']}",
                ],
            ),
            tags=["dependency", adv.get("ecosystem", "")],
            metadata={"cve": cve, "fixed_version": fixed, "installed_version": version},
        )
