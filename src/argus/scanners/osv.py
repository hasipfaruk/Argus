"""OSV (osv.dev) client for real, current vulnerability data.

The bundled advisory file is a small offline seed. This module queries the public
`OSV database <https://osv.dev>`_ for the project's actual dependencies, which
covers thousands of advisories across PyPI, npm, and more.

Privacy note: only package **names and versions** are sent to OSV — never source
code. This keeps Argus's offline-first promise intact (source stays local) while
still giving accurate results when a network is available. When OSV is
unreachable, the dependency scanner falls back to the bundled seed.

Efficiency: one batched query returns the vulnerability IDs affecting each
package/version, then each unique vulnerability's full record is fetched once.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import httpx

from argus.core.models import Severity

OSV_API = "https://api.osv.dev"

# OSV/GHSA qualitative severity -> Argus severity.
_SEVERITY_WORD = {
    "LOW": Severity.LOW,
    "MODERATE": Severity.MEDIUM,
    "MEDIUM": Severity.MEDIUM,
    "HIGH": Severity.HIGH,
    "CRITICAL": Severity.CRITICAL,
}


@dataclass
class OSVAdvisory:
    id: str
    summary: str
    severity: Severity = Severity.MEDIUM
    cve: str = ""
    fixed: str | None = None
    cwe: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)


class OSVError(RuntimeError):
    pass


def query(ecosystem: str, deps: dict[str, str], *, timeout: float = 15.0,
          max_packages: int = 400) -> dict[tuple[str, str], list[OSVAdvisory]]:
    """Return advisories per (package, version) for the given ecosystem.

    Raises OSVError on any network/HTTP problem so the caller can fall back to the
    offline seed. Never raises for "no vulnerabilities" — that is an empty result.
    """
    items = list(deps.items())[:max_packages]
    if not items:
        return {}

    queries = [{"package": {"name": name, "ecosystem": ecosystem}, "version": version}
               for name, version in items]
    try:
        with httpx.Client(timeout=timeout) as client:
            batch = client.post(f"{OSV_API}/v1/querybatch", json={"queries": queries})
            batch.raise_for_status()
            results = batch.json().get("results", [])

            # Collect unique vuln IDs across all packages.
            id_set: set[str] = set()
            per_pkg_ids: list[list[str]] = []
            for res in results:
                ids = [v["id"] for v in (res.get("vulns") or [])]
                per_pkg_ids.append(ids)
                id_set.update(ids)

            # Fetch each unique vuln record once.
            records: dict[str, OSVAdvisory] = {}
            for vid in id_set:
                r = client.get(f"{OSV_API}/v1/vulns/{vid}")
                if r.status_code == 200:
                    records[vid] = _parse_vuln(r.json())
    except (httpx.HTTPError, ValueError, KeyError) as exc:
        raise OSVError(f"OSV lookup failed: {exc}") from exc

    out: dict[tuple[str, str], list[OSVAdvisory]] = {}
    for (name, version), ids in zip(items, per_pkg_ids, strict=False):
        advisories = [records[i] for i in ids if i in records]
        if advisories:
            out[(name, version)] = advisories
    return out


def _parse_vuln(vuln: dict) -> OSVAdvisory:
    vid = vuln.get("id", "")
    aliases = vuln.get("aliases", []) or []
    cve = next((a for a in aliases if a.startswith("CVE-")), "")
    summary = vuln.get("summary") or (vuln.get("details", "")[:200]) or vid

    refs = [r.get("url", "") for r in (vuln.get("references") or []) if r.get("url")]
    if cve:
        refs.insert(0, f"https://nvd.nist.gov/vuln/detail/{cve}")

    cwe = [c for c in (vuln.get("database_specific", {}).get("cwe_ids") or [])
           if isinstance(c, str)]

    return OSVAdvisory(
        id=vid,
        summary=summary,
        severity=_severity_of(vuln),
        cve=cve,
        fixed=_fixed_version(vuln),
        cwe=cwe or ["CWE-1104"],
        references=refs[:5],
    )


def _severity_of(vuln: dict) -> Severity:
    word = (vuln.get("database_specific", {}) or {}).get("severity")
    if isinstance(word, str) and word.upper() in _SEVERITY_WORD:
        return _SEVERITY_WORD[word.upper()]
    # Fall back to a CVSS base score if present in the vector's severity list.
    for entry in vuln.get("severity", []) or []:
        score = entry.get("score", "")
        band = _cvss_band(score)
        if band is not None:
            return band
    return Severity.MEDIUM


def _cvss_band(vector_or_score: str) -> Severity | None:
    """Map a CVSS base score to a band. Accepts a bare number if present."""
    try:
        value = float(vector_or_score)
    except (TypeError, ValueError):
        return None
    if value >= 9.0:
        return Severity.CRITICAL
    if value >= 7.0:
        return Severity.HIGH
    if value >= 4.0:
        return Severity.MEDIUM
    if value > 0:
        return Severity.LOW
    return None


def _fixed_version(vuln: dict) -> str | None:
    for affected in vuln.get("affected", []) or []:
        for rng in affected.get("ranges", []) or []:
            for event in rng.get("events", []) or []:
                if "fixed" in event:
                    return event["fixed"]
    return None
