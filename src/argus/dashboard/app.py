"""The dashboard web app (FastAPI + server-rendered templates).

Pages: projects overview (``/``), project detail with a risk trend
(``/projects/{slug}``), and a scan's findings (``/scans/{id}``). Reports get in
either by uploading a JSON file (``/upload``) or by POSTing one to ``/api/scans``,
e.g. ``argus scan . -f json | curl -T- .../api/scans``.
"""

from __future__ import annotations

from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlmodel import Session

from argus import __version__
from argus.dashboard import charts, store
from argus.dashboard.db import get_session

_HERE = Path(__file__).parent
templates = Jinja2Templates(directory=str(_HERE / "templates"))
templates.env.globals.update(
    severity_fill=charts.severity_fill,
    severity_label=store.severity_label,
    severity_order=charts.SEVERITY_ORDER,
    risk_band=charts.risk_band,
    argus_version=__version__,
)

app = FastAPI(title="Argus Dashboard", docs_url=None, redoc_url=None)
app.mount("/static", StaticFiles(directory=str(_HERE / "static")), name="static")


@app.get("/", response_class=HTMLResponse)
def index(request: Request, session: Session = Depends(get_session)):
    return templates.TemplateResponse(request, "projects.html", {
        "projects": store.list_projects(session),
        "stats": store.overall_stats(session),
    })


@app.get("/projects/{slug}", response_class=HTMLResponse)
def project_detail(slug: str, request: Request, session: Session = Depends(get_session)):
    project = store.get_project(session, slug)
    if project is None or project.id is None:
        raise HTTPException(404, "Project not found")
    return templates.TemplateResponse(request, "project.html", {
        "project": project,
        "scans": store.list_scans(session, project.id),
        "trend": charts.trend_geometry(store.trend(session, project.id)),
    })


@app.get("/scans/{scan_id}", response_class=HTMLResponse)
def scan_detail(scan_id: int, request: Request, session: Session = Depends(get_session)):
    scan = store.get_scan(session, scan_id)
    if scan is None:
        raise HTTPException(404, "Scan not found")
    return templates.TemplateResponse(request, "scan.html", {
        "scan": scan,
        "project": store.get_project_by_id(session, scan.project_id),
        "findings": store.get_findings(session, scan_id),
        "bar": charts.severity_bar(scan.severity_counts, scan.total_findings),
    })


@app.get("/upload", response_class=HTMLResponse)
def upload_form(request: Request):
    return templates.TemplateResponse(request, "upload.html", {})


@app.post("/upload")
async def upload_submit(file: UploadFile, session: Session = Depends(get_session)):
    raw = (await file.read()).decode("utf-8", "replace")
    try:
        scan = store.ingest_report(session, raw)
    except Exception as exc:  # bad/incomplete report
        raise HTTPException(400, f"Not a valid Argus JSON report: {exc}") from exc
    return RedirectResponse(f"/scans/{scan.id}", status_code=303)


@app.post("/api/scans")
async def api_ingest(request: Request, session: Session = Depends(get_session)):
    raw = (await request.body()).decode("utf-8", "replace")
    try:
        scan = store.ingest_report(session, raw)
    except Exception as exc:
        return JSONResponse({"error": f"invalid report: {exc}"}, status_code=400)
    return {"scan_id": scan.id, "url": f"/scans/{scan.id}",
            "risk_score": scan.risk_score, "findings": scan.total_findings}


def serve(host: str = "127.0.0.1", port: int = 8000) -> None:
    """Launch the dashboard with uvicorn (used by ``argus dashboard``)."""
    import uvicorn

    uvicorn.run(app, host=host, port=port)
