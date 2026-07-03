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
