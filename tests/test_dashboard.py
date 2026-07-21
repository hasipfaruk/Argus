"""Tests for the optional web dashboard (ingest, queries, and page rendering).

Skips cleanly if the [dashboard] extra (fastapi/sqlmodel) is not installed.
"""

from __future__ import annotations

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("sqlmodel")

from fastapi.testclient import TestClient  # noqa: E402
from sqlmodel import Session  # noqa: E402

from argus.core.config import Config  # noqa: E402
from argus.core.engine import ScanEngine  # noqa: E402
from argus.dashboard import db, store  # noqa: E402
from argus.dashboard.app import app  # noqa: E402
from argus.reporting.json_reporter import JSONReporter  # noqa: E402


@pytest.fixture(autouse=True)
def _fresh_db(monkeypatch):
    monkeypatch.setenv("ARGUS_DASHBOARD_DB", ":memory:")
    db.reset_engine_for_tests()
    yield


@pytest.fixture
def report(vulnerable_project) -> str:
    result = ScanEngine(Config()).scan(vulnerable_project)
    return JSONReporter().render(result)


@pytest.fixture
def client() -> TestClient:
    return TestClient(app)


# --- ingest + store ---------------------------------------------------------
def test_ingest_stores_scan_and_findings(report):
    with Session(db.get_engine()) as s:
        scan = store.ingest_report(s, report)
        assert scan.id is not None
        assert scan.total_findings > 0
        assert scan.risk_score > 0
        assert sum(scan.severity_counts.values()) == scan.total_findings
        findings = store.get_findings(s, scan.id)
        assert len(findings) == scan.total_findings
        # findings are ordered most-severe first
        assert findings[0].severity >= findings[-1].severity


def test_two_scans_same_project_share_one_project(report):
    with Session(db.get_engine()) as s:
        store.ingest_report(s, report)
        store.ingest_report(s, report)
        projects = store.list_projects(s)
        assert len(projects) == 1
        assert projects[0]["scan_count"] == 2
        assert len(store.trend(s, projects[0]["project"].id)) == 2


def test_overall_stats(report):
    with Session(db.get_engine()) as s:
        store.ingest_report(s, report)
        stats = store.overall_stats(s)
        assert stats["projects"] == 1 and stats["scans"] == 1
        assert stats["worst_risk"] > 0


# --- HTTP API + pages -------------------------------------------------------
def test_api_ingest_and_pages_render(client, report):
    r = client.post("/api/scans", content=report)
    assert r.status_code == 200
    body = r.json()
    assert body["scan_id"] and body["findings"] > 0

    assert client.get("/").status_code == 200
    assert client.get("/upload").status_code == 200
    with Session(db.get_engine()) as s:
        slug = store.list_projects(s)[0]["project"].slug
    proj = client.get(f"/projects/{slug}")
    assert proj.status_code == 200 and "Risk over time" in proj.text
    scan = client.get(f"/scans/{body['scan_id']}")
    assert scan.status_code == 200
    assert "Aggregate risk" in scan.text
    assert "d03b3b" in scan.text  # critical severity color from the palette


def test_upload_form_ingests_file(client, report):
    r = client.post("/upload", files={"file": ("report.json", report, "application/json")},
                    follow_redirects=False)
    assert r.status_code == 303
    assert r.headers["location"].startswith("/scans/")


def test_bad_report_is_rejected(client):
    r = client.post("/api/scans", content="not json")
    assert r.status_code == 400
    assert "error" in r.json()


def test_oversized_api_ingest_is_rejected(client, monkeypatch):
    monkeypatch.setattr("argus.dashboard.app._MAX_REPORT_BYTES", 64)
    r = client.post("/api/scans", content=b"{" + b"x" * 200 + b"}")
    assert r.status_code == 413
    assert "byte limit" in r.json()["error"]


def test_oversized_upload_is_rejected(client, monkeypatch):
    monkeypatch.setattr("argus.dashboard.app._MAX_REPORT_BYTES", 64)
    r = client.post(
        "/upload",
        files={"file": ("report.json", b"{" + b"x" * 200 + b"}", "application/json")},
        follow_redirects=False,
    )
    assert r.status_code == 413


def test_missing_pages_404(client):
    assert client.get("/projects/nope").status_code == 404
    assert client.get("/scans/9999").status_code == 404
