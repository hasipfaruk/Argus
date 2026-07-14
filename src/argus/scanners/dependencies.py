"""Dependency vulnerability scanner.

Parses dependency manifests **and lock files** for the common ecosystems, then
matches declared versions against live OSV data (falling back to a bundled
advisory seed, ``data/advisories.json``). Lock files matter because they pin the
full *transitive* dependency tree with exact versions, which is where most real
dependency risk lives, whereas top-level manifests only list direct deps and
often use loose ranges.

Supported inputs:

* PyPI: ``requirements.txt`` (``==`` pins), ``poetry.lock``, ``Pipfile.lock``.
* npm: ``package.json`` (direct), ``package-lock.json``, ``yarn.lock``.
* Go: ``go.mod``.
* crates.io: ``Cargo.lock``.
* RubyGems: ``Gemfile.lock``.
* Packagist: ``composer.lock``.

New ecosystems match against live OSV data (the bundled seed only covers
PyPI/npm), so they require network access to surface findings.

Version comparison is intentionally lightweight, enough to evaluate the simple
``<x.y.z`` ranges the seed data uses, without pulling in a full SemVer engine.
"""

from __future__ import annotations

import json
import logging
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

log = logging.getLogger("argus.scanners.dependencies")


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


def _loads(text: str) -> dict | None:
    """Parse JSON tolerantly: strips a UTF-8 BOM (common in Windows-authored files)
    and returns None instead of raising on malformed input."""
    try:
        return json.loads(text.lstrip("\ufeff"))
    except (json.JSONDecodeError, ValueError):
        return None


def _parse_package_json(text: str) -> dict[str, str]:
    deps: dict[str, str] = {}
    data = _loads(text)
    if not isinstance(data, dict):
        return deps
    for key in ("dependencies", "devDependencies", "optionalDependencies"):
        for name, ver in (data.get(key) or {}).items():
            cleaned = ver.lstrip("^~>=< ").strip()
            if re.match(r"^\d", cleaned):
                deps[name.lower()] = cleaned
    return deps


def _parse_package_lock(text: str) -> dict[str, str]:
    """npm ``package-lock.json``, full transitive tree (lockfileVersion 1/2/3)."""
    deps: dict[str, str] = {}
    data = _loads(text)
    if not isinstance(data, dict):
        return deps

    packages = data.get("packages")
    if isinstance(packages, dict):  # lockfileVersion 2/3
        for key, meta in packages.items():
            if not key or not isinstance(meta, dict):
                continue  # "" is the project root
            name = key.split("node_modules/")[-1]
            ver = str(meta.get("version", ""))
            if name and re.match(r"^\d", ver):
                deps.setdefault(name.lower(), ver)

    def _walk(tree: object) -> None:  # lockfileVersion 1
        if not isinstance(tree, dict):
            return
        for name, meta in tree.items():
            if not isinstance(meta, dict):
                continue
            ver = str(meta.get("version", ""))
            if re.match(r"^\d", ver):
                deps.setdefault(name.lower(), ver)
            _walk(meta.get("dependencies"))

    if not packages:
        _walk(data.get("dependencies"))
    return deps


def _parse_yarn_lock(text: str) -> dict[str, str]:
    """yarn.lock (classic v1 and berry), resolved versions per package."""
    deps: dict[str, str] = {}
    names: list[str] = []
    for raw in text.splitlines():
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        if not raw[0].isspace() and raw.rstrip().endswith(":"):
            names = []
            for spec in raw.rstrip()[:-1].split(","):
                spec = spec.strip().strip('"')
                at = spec.rfind("@")  # keep scoped @scope/name; drop the range
                name = spec[:at] if at > 0 else spec
                if name:
                    names.append(name.lower())
        else:
            m = re.match(r'\s+version:?\s+"?([0-9][^"\s]*)"?', raw)
            if m and names:
                for name in names:
                    deps.setdefault(name, m.group(1))
                names = []
    return deps


def _parse_toml_packages(text: str) -> dict[str, str]:
    """TOML lock files with ``[[package]]`` entries, poetry.lock and Cargo.lock."""
    deps: dict[str, str] = {}
    current: str | None = None
    for raw in text.splitlines():
        line = raw.strip()
        if line == "[[package]]":
            current = None
            continue
        m = re.match(r'name\s*=\s*"([^"]+)"', line)
        if m:
            current = m.group(1)
            continue
        m = re.match(r'version\s*=\s*"([^"]+)"', line)
        if m and current:
            deps.setdefault(current, m.group(1))
            current = None
    return deps


# Back-compat alias (poetry.lock shares the [[package]] shape).
_parse_poetry_lock = _parse_toml_packages


def _parse_go_mod(text: str) -> dict[str, str]:
    """go.mod, module requirements (both block and single-line ``require``)."""
    deps: dict[str, str] = {}
    in_block = False
    for raw in text.splitlines():
        line = raw.split("//", 1)[0].strip()  # drop `// indirect` and comments
        if not line:
            continue
        if line.startswith("require (") or line == "require(":
            in_block = True
            continue
        if in_block and line == ")":
            in_block = False
            continue
        if line.startswith("require "):
            line = line[len("require "):].strip()
        elif not in_block:
            continue
        m = re.match(r"^(\S+)\s+v([0-9][\w.\-]*)", line)
        if m:
            deps.setdefault(m.group(1), m.group(2))  # Go paths are case-sensitive
    return deps


def _parse_gemfile_lock(text: str) -> dict[str, str]:
    """Gemfile.lock, resolved gem specs (4-space indented ``name (version)``)."""
    deps: dict[str, str] = {}
    for raw in text.splitlines():
        m = re.match(r"^ {4}([A-Za-z0-9_.\-]+) \(([0-9][^)]*)\)\s*$", raw)
        if m:
            deps.setdefault(m.group(1), m.group(2))
    return deps


def _parse_composer_lock(text: str) -> dict[str, str]:
    """composer.lock, Packagist packages (runtime and dev)."""
    deps: dict[str, str] = {}
    data = _loads(text)
    if not isinstance(data, dict):
        return deps
    for section in ("packages", "packages-dev"):
        for entry in data.get(section) or []:
            if not isinstance(entry, dict):
                continue
            name = entry.get("name", "")
            ver = str(entry.get("version", "")).lstrip("v").strip()
            if name and re.match(r"^\d", ver):
                deps.setdefault(name, ver)
    return deps


def _parse_pipfile_lock(text: str) -> dict[str, str]:
    """Pipfile.lock, default and develop dependency sections."""
    deps: dict[str, str] = {}
    data = _loads(text)
    if not isinstance(data, dict):
        return deps
    for section in ("default", "develop"):
        for name, meta in (data.get(section) or {}).items():
            if not isinstance(meta, dict):
                continue
            ver = str(meta.get("version", "")).lstrip("=<>~ ").strip()
            if re.match(r"^\d", ver):
                deps.setdefault(name.lower(), ver)
    return deps


# Manifest/lock file name -> (ecosystem, parser). Lock files first so their exact,
# transitive versions win the per-(package, version) de-duplication below.
_PARSERS = {
    # Lock files first per ecosystem so a dependency present in both a lock file
    # and a manifest is reported at the (pinned, transitive) lock-file location.
    "poetry.lock": ("PyPI", _parse_poetry_lock),
    "Pipfile.lock": ("PyPI", _parse_pipfile_lock),
    "requirements.txt": ("PyPI", _parse_requirements),
    "package-lock.json": ("npm", _parse_package_lock),
    "yarn.lock": ("npm", _parse_yarn_lock),
    "package.json": ("npm", _parse_package_json),
    "go.mod": ("Go", _parse_go_mod),
    "Cargo.lock": ("crates.io", _parse_toml_packages),
    "Gemfile.lock": ("RubyGems", _parse_gemfile_lock),
    "composer.lock": ("Packagist", _parse_composer_lock),
}


def _dedupe_by_cve(advisories: list[dict]) -> list[dict]:
    """Collapse advisories that describe the same CVE, keeping the most severe.

    OSV often returns several records (e.g. a GHSA and a PYSEC entry) aliasing one
    CVE. Reporting them once, at the highest assessed severity, keeps the output
    clean. Advisories without a CVE are keyed by their own id and never merged.
    """
    best: dict[str, dict] = {}
    order: list[str] = []
    for adv in advisories:
        key = adv.get("cve") or adv.get("id", "")
        current = best.get(key)
        if current is None:
            best[key] = adv
            order.append(key)
        elif Severity.parse(adv.get("severity", "MEDIUM")) > \
                Severity.parse(current.get("severity", "MEDIUM")):
            best[key] = adv
    return [best[k] for k in order]


def _osv_to_dict(adv, ecosystem: str) -> dict:
    """Normalize an OSVAdvisory into the dict shape the finding builder consumes."""
    return {
        "id": adv.id,
        "cve": adv.cve,
        "severity": adv.severity,
        "summary": adv.summary,
        "title": adv.summary,
        "fixed": adv.fixed or "",
        "cwe": adv.cwe,
        "ecosystem": ecosystem,
        "references": adv.references,
    }


def _annotate_reachability(finding: Finding, pkg: str, py_imports: set[str]) -> None:
    """Attach an import-level reachability verdict to a PyPI dependency finding.

    Annotates only, findings are never suppressed by reachability. A package
    that is never imported keeps its severity but drops to an unlikely
    likelihood, so triage naturally sorts confirmed-imported advisories first.
    """
    from argus.analysis import reachability

    verdict = reachability.python_import_verdict(pkg, py_imports)
    finding.metadata["reachability"] = verdict
    finding.description = f"{finding.description}\n\n{reachability.describe(verdict)}"
    if verdict == reachability.NOT_IMPORTED:
        finding.likelihood = Likelihood.UNLIKELY


@scanner
class DependencyScanner(Scanner):
    name = "dependencies"
    category = "dependencies"
    description = "Flags dependencies with known published vulnerabilities."

    def applies_to(self, project) -> bool:
        return bool(project.files_matching(*_PARSERS.keys()))

    def scan(self, ctx: ScannerContext) -> Iterable[Finding]:
        opts = ctx.config.options_for(self.name)
        online = bool(opts.get("online", True))
        timeout = float(opts.get("timeout", 15.0))
        use_cache = bool(opts.get("cache", True))
        use_reachability = bool(opts.get("reachability", False))
        counter = 0

        # Experimental import-level reachability (Python only for now): computed
        # once per scan, used to annotate PyPI findings as imported/not-imported.
        py_imports: set[str] | None = None
        if use_reachability:
            from argus.analysis import reachability
            py_imports = reachability.collect_python_imports(ctx.project)

        # Collect declared dependencies per ecosystem, de-duplicating by
        # (package, version) so a dependency listed in both a manifest and a lock
        # file is scanned and reported once. Lock files are processed first (see
        # _PARSERS ordering), so the reported location prefers the lock file.
        per_eco: dict[str, dict[tuple[str, str], tuple[str, str, str]]] = {}
        for manifest_name, (ecosystem, parser) in _PARSERS.items():
            for f in ctx.project.files_matching(manifest_name):
                for pkg, version in parser(f.text()).items():
                    bucket = per_eco.setdefault(ecosystem, {})
                    bucket.setdefault((pkg, version), (f.rel_path, pkg, version))

        for ecosystem, bucket in per_eco.items():
            entries = list(bucket.values())
            osv_map, source = self._resolve_source(
                ecosystem, entries, online, timeout, use_cache)
            for path, pkg, version in entries:
                if source == "osv":
                    advisories = [_osv_to_dict(a, ecosystem)
                                  for a in osv_map.get((pkg, version), [])]
                else:
                    advisories = self._bundled_matches(ecosystem, pkg, version)
                for adv in _dedupe_by_cve(advisories):
                    counter += 1
                    finding = self._finding(adv, counter, path, pkg, version)
                    if py_imports is not None and ecosystem == "PyPI":
                        _annotate_reachability(finding, pkg, py_imports)
                    yield finding

    def _resolve_source(self, ecosystem, entries, online, timeout, use_cache=True):
        """Return (osv_map, source). Prefer live OSV; fall back to the bundled seed."""
        if not online:
            return {}, "bundled"
        deps = {pkg: version for _, pkg, version in entries}
        from argus.scanners import osv
        try:
            return osv.query(ecosystem, deps, timeout=timeout, use_cache=use_cache), "osv"
        except osv.OSVError as exc:
            # Offline/timeout/API problem: fall back to the bundled seed, but say so
            #, a silent fallback in a security tool hides reduced coverage.
            log.warning(
                "OSV lookup for %s failed (%s); falling back to the bundled advisory "
                "seed, which covers far fewer packages. Findings may be incomplete.",
                ecosystem, exc,
            )
            return {}, "bundled"
        except Exception as exc:  # unexpected bug: degrade, but surface it loudly
            log.error("Unexpected error during OSV lookup for %s: %s; using the "
                      "bundled advisory seed.", ecosystem, exc)
            return {}, "bundled"

    @staticmethod
    def _bundled_matches(ecosystem: str, pkg: str, version: str) -> list[dict]:
        out = []
        for adv in _load_advisories():
            if adv["ecosystem"] == ecosystem and adv["package"] == pkg \
                    and _matches_range(version, adv["vulnerable"]):
                out.append(adv)
        return out

    def _finding(self, adv: dict, index: int, path: str, pkg: str,
                 version: str) -> Finding:
        sev = Severity.parse(adv.get("severity", "MEDIUM"))
        cve = adv.get("cve", "")
        fixed = adv.get("fixed", "")
        references = [r for r in adv.get("references", []) if r] or [
            f"https://nvd.nist.gov/vuln/detail/{cve}" if cve else "",
            f"https://github.com/advisories/{adv['id']}",
        ]
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
                references=references,
            ),
            tags=["dependency", adv.get("ecosystem", "")],
            metadata={"cve": cve, "fixed_version": fixed, "installed_version": version},
        )
