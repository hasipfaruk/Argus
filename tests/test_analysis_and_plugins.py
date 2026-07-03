"""Tests for repository analysis and the plugin registry."""

from __future__ import annotations

import pytest

from argus.analysis.repository import RepositoryAnalyzer
from argus.core.models import Finding, Location, Severity
from argus.core.plugin import Registry, Scanner, ScannerContext


def test_analyzer_detects_language_and_framework(vulnerable_project):
    RepositoryAnalyzer().analyze(vulnerable_project)
    assert "Python" in vulnerable_project.languages
    assert "Flask" in vulnerable_project.frameworks
    assert "Docker" in vulnerable_project.languages


def test_analyzer_maps_architecture(vulnerable_project):
    RepositoryAnalyzer().analyze(vulnerable_project)
    arch = vulnerable_project.architecture
    assert "REST/HTTP" in arch["apis"]
    assert any("Dockerfile" in c for c in arch["containers"])
    assert "requirements.txt" in arch["dependency_manifests"]


def test_registry_registration_and_lookup():
    reg = Registry()

    @reg.register_scanner
    class Dummy(Scanner):
        name = "dummy"
        category = "test"

        def scan(self, ctx: ScannerContext):
            yield Finding(
                id="dummy:1", rule_id="dummy.r", scanner="dummy",
                title="t", description="d",
                location=Location(path="x", start_line=1),
                severity=Severity.LOW,
            )

    assert "dummy" in reg.scanners()
    assert reg.get_scanner("dummy") is Dummy


def test_registry_rejects_nameless_scanner():
    reg = Registry()
    with pytest.raises(ValueError):
        @reg.register_scanner
        class NoName(Scanner):
            def scan(self, ctx):
                return []


def test_registry_unknown_lookup_raises():
    reg = Registry()
    with pytest.raises(KeyError):
        reg.get_scanner("nope")
