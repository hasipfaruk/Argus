"""Tests for the built-in scanners."""

from __future__ import annotations

from argus.core.config import Config
from argus.core.plugin import ScannerContext, registry
from argus.scanners.dependencies import _matches_range, _parse_requirements
from argus.scanners.secrets import _shannon_entropy


def _run(scanner_name: str, project) -> list:
    from argus.analysis.repository import RepositoryAnalyzer

    RepositoryAnalyzer().analyze(project)
    cls = registry.get_scanner(scanner_name)
    ctx = ScannerContext(project=project, config=Config(), ai=None)
    return list(cls().scan(ctx))


def test_secrets_finds_aws_key(vulnerable_project):
    findings = _run("secrets", vulnerable_project)
    rules = {f.rule_id for f in findings}
    assert "secrets.aws-access-key-id" in rules
    # The credential value must be redacted in the snippet.
    aws = next(f for f in findings if f.rule_id == "secrets.aws-access-key-id")
    assert "AKIAIOSFODNN7EXAMPLE" not in (aws.location.snippet or "")


def test_secrets_clean_project_no_findings(clean_project):
    assert _run("secrets", clean_project) == []


def test_patterns_finds_injection_classes(vulnerable_project):
    findings = _run("patterns", vulnerable_project)
    rules = {f.rule_id for f in findings}
    assert "patterns.python-sql-fstring" in rules
    assert "patterns.python-shell-true" in rules
    assert "patterns.python-yaml-load" in rules
    assert "patterns.weak-hash-md5-sha1" in rules


def test_patterns_carry_cwe_and_reasoning(vulnerable_project):
    findings = _run("patterns", vulnerable_project)
    sqli = next(f for f in findings if f.rule_id == "patterns.python-sql-fstring")
    assert sqli.cwe == ["CWE-89"]
    assert sqli.why_vulnerable and sqli.attacker_perspective and sqli.business_impact


def test_dependencies_flags_known_cve(vulnerable_project):
    findings = _run("dependencies", vulnerable_project)
    pkgs = {f.metadata.get("cve") for f in findings}
    assert "CVE-2020-14343" in pkgs  # pyyaml 5.3.1


def test_iac_flags_root_container(vulnerable_project):
    findings = _run("iac", vulnerable_project)
    rules = {f.rule_id for f in findings}
    assert "iac.docker-user-root" in rules
    assert "iac.docker-latest-tag" in rules


def test_dependency_version_range():
    assert _matches_range("2.0.1", "<2.2.5")
    assert not _matches_range("2.2.5", "<2.2.5")
    assert _matches_range("5.3.1", "<5.4")


def test_requirements_parser():
    deps = _parse_requirements("flask==2.0.1\n# comment\nrequests==2.25.0\n-e .\n")
    assert deps == {"flask": "2.0.1", "requests": "2.25.0"}


def test_entropy_distinguishes_random_from_words():
    assert _shannon_entropy("password") < _shannon_entropy("aB3$xZ9!qW2#mK7&")


# --- false-positive suppression (validated against real-world scans) ---------
def _run_patterns(tmp_path, rel_path: str, content: str):
    from argus.analysis.repository import RepositoryAnalyzer
    from argus.core.project import Project

    target = tmp_path / rel_path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")
    project = Project.from_path(tmp_path)
    RepositoryAnalyzer().analyze(project)
    cls = registry.get_scanner("patterns")
    return list(cls().scan(ScannerContext(project=project, config=Config(), ai=None)))


def test_weak_hash_suppressed_when_usedforsecurity_false(tmp_path):
    findings = _run_patterns(
        tmp_path, "auth.py", "h = hashlib.md5(x, usedforsecurity=False).hexdigest()\n")
    assert not [f for f in findings if f.rule_id == "patterns.weak-hash-md5-sha1"]
    # But a plain md5 IS still flagged.
    findings2 = _run_patterns(tmp_path, "auth2.py", "h = hashlib.md5(x).hexdigest()\n")
    assert [f for f in findings2 if f.rule_id == "patterns.weak-hash-md5-sha1"]


def test_pickle_roundtrip_suppressed(tmp_path):
    findings = _run_patterns(tmp_path, "m.py", "y = pickle.loads(pickle.dumps(obj))\n")
    assert not [f for f in findings if f.rule_id == "patterns.python-pickle-loads"]


def test_test_file_findings_are_downgraded(tmp_path):
    from argus.core.models import Confidence, Severity

    findings = _run_patterns(
        tmp_path, "tests/test_x.py", "r = requests.get(url, verify=False)\n")
    tls = [f for f in findings if f.rule_id == "patterns.tls-verify-disabled"]
    assert tls, "should still report, just downgraded"
    assert tls[0].severity < Severity.HIGH          # downgraded from HIGH
    assert tls[0].confidence == Confidence.LOW
    assert "test-context" in tls[0].tags


def test_private_key_in_tests_dir_downgraded(clean_project, tmp_path):
    from argus.core.models import Severity

    # A private key committed under a top-level tests/ dir is test material.
    key = tmp_path / "tests" / "certs" / "server.key"
    key.parent.mkdir(parents=True, exist_ok=True)
    key.write_text("-----BEGIN PRIVATE KEY-----\nMIIabc\n-----END PRIVATE KEY-----\n",
                   encoding="utf-8")
    from argus.core.project import Project

    project = Project.from_path(tmp_path)
    cls = registry.get_scanner("secrets")
    findings = list(cls().scan(ScannerContext(project=project, config=Config(), ai=None)))
    pk = [f for f in findings if f.rule_id == "secrets.private-key-block"]
    assert pk, "still detected"
    assert pk[0].severity <= Severity.LOW           # downgraded, not Critical
