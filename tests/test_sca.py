"""Tests for lock-file / transitive dependency scanning."""

from __future__ import annotations

import json
from pathlib import Path

from argus.core.config import Config
from argus.core.plugin import ScannerContext, registry
from argus.core.project import Project
from argus.scanners.dependencies import (
    _parse_composer_lock,
    _parse_gemfile_lock,
    _parse_go_mod,
    _parse_package_lock,
    _parse_pipfile_lock,
    _parse_poetry_lock,
    _parse_toml_packages,
    _parse_yarn_lock,
)


def _offline_config() -> Config:
    return Config(scanner_options={"dependencies": {"online": False}})


def _scan_deps(tmp_path: Path) -> list:
    project = Project.from_path(tmp_path)
    from argus.analysis.repository import RepositoryAnalyzer

    RepositoryAnalyzer().analyze(project)
    cls = registry.get_scanner("dependencies")
    ctx = ScannerContext(project=project, config=_offline_config(), ai=None)
    return list(cls().scan(ctx))


# --- parser units ----------------------------------------------------------
def test_parse_package_lock_v3_transitive():
    text = json.dumps({
        "lockfileVersion": 3,
        "packages": {
            "": {"name": "app"},
            "node_modules/lodash": {"version": "4.17.20"},
            "node_modules/lodash/node_modules/minimist": {"version": "1.2.5"},
        },
    })
    deps = _parse_package_lock(text)
    assert deps == {"lodash": "4.17.20", "minimist": "1.2.5"}


def test_parse_package_lock_v1_nested():
    text = json.dumps({
        "dependencies": {
            "lodash": {"version": "4.17.20",
                       "dependencies": {"minimist": {"version": "1.2.5"}}},
        },
    })
    assert _parse_package_lock(text) == {"lodash": "4.17.20", "minimist": "1.2.5"}


def test_parse_yarn_lock():
    text = (
        '# yarn lockfile v1\n'
        'lodash@^4.17.0:\n'
        '  version "4.17.20"\n'
        '"@babel/core@npm:^7.0.0":\n'
        '  version: "7.10.0"\n'
    )
    deps = _parse_yarn_lock(text)
    assert deps["lodash"] == "4.17.20"
    assert deps["@babel/core"] == "7.10.0"


def test_parse_poetry_lock():
    text = (
        '[[package]]\nname = "requests"\nversion = "2.20.0"\n\n'
        '[[package]]\nname = "urllib3"\nversion = "1.25.0"\n'
    )
    assert _parse_poetry_lock(text) == {"requests": "2.20.0", "urllib3": "1.25.0"}


def test_parse_pipfile_lock():
    text = json.dumps({
        "default": {"flask": {"version": "==2.0.1"}},
        "develop": {"pytest": {"version": "==7.0.0"}},
    })
    assert _parse_pipfile_lock(text) == {"flask": "2.0.1", "pytest": "7.0.0"}


# --- new ecosystems: Go / Rust / Ruby / PHP --------------------------------
def test_parse_go_mod_block_and_single():
    text = (
        "module example.com/app\n\n"
        "go 1.21\n\n"
        "require (\n"
        "\tgithub.com/gin-gonic/gin v1.7.0\n"
        "\tgolang.org/x/text v0.3.5 // indirect\n"
        ")\n\n"
        "require github.com/pkg/errors v0.9.1\n"
    )
    assert _parse_go_mod(text) == {
        "github.com/gin-gonic/gin": "1.7.0",
        "golang.org/x/text": "0.3.5",
        "github.com/pkg/errors": "0.9.1",
    }


def test_parse_cargo_lock_uses_toml_packages():
    text = (
        '[[package]]\nname = "regex"\nversion = "1.5.4"\n\n'
        '[[package]]\nname = "smallvec"\nversion = "1.6.1"\n'
    )
    assert _parse_toml_packages(text) == {"regex": "1.5.4", "smallvec": "1.6.1"}


def test_parse_gemfile_lock():
    text = (
        "GEM\n"
        "  remote: https://rubygems.org/\n"
        "  specs:\n"
        "    actionpack (6.0.3)\n"
        "    rack (2.2.3)\n"
        "      rack-test (>= 0.6.3)\n"   # nested constraint, not a resolved spec
        "\n"
        "PLATFORMS\n"
        "  ruby\n"
    )
    assert _parse_gemfile_lock(text) == {"actionpack": "6.0.3", "rack": "2.2.3"}


def test_parse_composer_lock():
    text = json.dumps({
        "packages": [{"name": "symfony/http-kernel", "version": "v4.4.0"}],
        "packages-dev": [{"name": "phpunit/phpunit", "version": "9.5.0"}],
    })
    assert _parse_composer_lock(text) == {
        "symfony/http-kernel": "4.4.0",
        "phpunit/phpunit": "9.5.0",
    }


# --- end-to-end: transitive vulnerability from a lock file -----------------
def test_transitive_vuln_from_package_lock(tmp_path: Path):
    (tmp_path / "package-lock.json").write_text(json.dumps({
        "lockfileVersion": 3,
        "packages": {
            "": {"name": "app"},
            "node_modules/lodash": {"version": "4.17.20"},        # < 4.17.21 (vuln)
            "node_modules/express/node_modules/minimist": {"version": "1.2.5"},  # transitive, vuln
        },
    }), encoding="utf-8")

    findings = _scan_deps(tmp_path)
    cves = {f.metadata.get("cve") for f in findings}
    assert "CVE-2021-23337" in cves   # lodash (direct)
    assert "CVE-2021-44906" in cves   # minimist (transitive)


def test_go_module_flows_to_finding_via_osv(tmp_path: Path, monkeypatch):
    """A go.mod dependency is queried under the 'Go' ecosystem and reported."""
    (tmp_path / "go.mod").write_text(
        "module example.com/app\n\ngo 1.21\n\n"
        "require github.com/dgrijalva/jwt-go v3.2.0\n",
        encoding="utf-8",
    )

    from argus.scanners import osv

    captured: dict[str, str] = {}

    def _fake_query(ecosystem, deps, **kwargs):
        captured["ecosystem"] = ecosystem
        adv = osv.OSVAdvisory(
            id="GHSA-w73w-5m7g-f7qc",
            summary="jwt-go allows attackers to bypass validation.",
            severity=osv.Severity.HIGH,
            cve="CVE-2020-26160",
            fixed="4.0.0",
        )
        return {(name, ver): [adv] for name, ver in deps.items()}

    monkeypatch.setattr(osv, "query", _fake_query)

    project = Project.from_path(tmp_path)
    from argus.analysis.repository import RepositoryAnalyzer

    RepositoryAnalyzer().analyze(project)
    cls = registry.get_scanner("dependencies")
    ctx = ScannerContext(
        project=project,
        config=Config(scanner_options={"dependencies": {"online": True}}),
        ai=None,
    )
    findings = list(cls().scan(ctx))

    assert captured["ecosystem"] == "Go"
    assert any(f.metadata.get("cve") == "CVE-2020-26160" for f in findings)


def test_manifest_and_lock_not_double_reported(tmp_path: Path):
    # lodash appears in both package.json and package-lock.json at the same version.
    (tmp_path / "package.json").write_text(
        json.dumps({"dependencies": {"lodash": "4.17.20"}}), encoding="utf-8")
    (tmp_path / "package-lock.json").write_text(json.dumps({
        "lockfileVersion": 3,
        "packages": {"": {}, "node_modules/lodash": {"version": "4.17.20"}},
    }), encoding="utf-8")

    findings = _scan_deps(tmp_path)
    lodash_hits = [f for f in findings if f.metadata.get("cve") == "CVE-2021-23337"]
    assert len(lodash_hits) == 1   # de-duplicated across the two files
