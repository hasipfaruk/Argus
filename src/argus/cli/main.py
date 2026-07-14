"""The ``argus`` command-line interface.

Commands:

* ``argus scan TARGET``: run a full scan and write reports.
* ``argus fix TARGET``: apply verified fixes on a branch and open a pull request.
* ``argus scanners``: list available scanners.
* ``argus reporters``: list available report formats.
* ``argus providers``: list AI providers and their availability.
* ``argus init``: write a starter ``.argus.yml``.
* ``argus version``: print the version.
"""

from __future__ import annotations

import contextlib
import sys
from pathlib import Path

import typer
from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table

from argus import __version__
from argus.core.config import Config
from argus.core.models import ScanResult, Severity
from argus.core.plugin import registry
from argus.plugins import register_builtins

# On Windows the legacy console defaults to a codepage that can't encode the
# Unicode Argus uses in reports/tables. Force UTF-8 on the streams when possible.
for _stream in (sys.stdout, sys.stderr):
    with contextlib.suppress(AttributeError, ValueError):
        _stream.reconfigure(encoding="utf-8")  # type: ignore[union-attr]

# Register built-in plugins up front so `scanners`/`reporters`/`providers` work
# even without the entry-point discovery path (e.g. running from source).
register_builtins()

app = typer.Typer(
    name="argus",
    help="Argus, an open-source AI Security Engineer.",
    add_completion=False,
    no_args_is_help=True,
)
console = Console()
err_console = Console(stderr=True)


def _version_callback(value: bool) -> None:
    if value:
        console.print(f"Argus v{__version__}")
        raise typer.Exit()


@app.callback()
def _root(
    version: bool = typer.Option(
        False, "--version", "-V", help="Show the Argus version and exit.",
        callback=_version_callback, is_eager=True,
    ),
) -> None:
    """Argus, an open-source AI Security Engineer.

    Point Argus at a codebase and it finds vulnerabilities, explains them, and can
    fix them. Run `argus COMMAND --help` for details on any command, e.g.
    `argus scan --help`.
    """


@app.command()
def scan(
    target: str = typer.Argument(
        ..., help="Local path, git URL (GitHub/GitLab/Bitbucket), or website URL."
    ),
    config: Path | None = typer.Option(
        None, "--config", "-c", help="Path to an .argus.yml config file."
    ),
    scanners: str | None = typer.Option(
        None, "--scanners", "-s", help="Comma-separated scanners to run (default: all)."
    ),
    exclude: str | None = typer.Option(
        None, "--exclude", help="Comma-separated scanners to skip."
    ),
    fmt: list[str] = typer.Option(
        ["table"], "--format", "-f",
        help="Output format(s): table, json, sarif, gitlab, markdown, html, csv. "
             "Repeatable.",
    ),
    output: Path | None = typer.Option(
        None, "--output", "-o",
        help="Write reports here. A directory writes one file per non-table format.",
    ),
    ai_provider: str | None = typer.Option(
        None, "--ai-provider", help="heuristic | anthropic | openai | ollama."
    ),
    ai_model: str | None = typer.Option(None, "--ai-model", help="Model id override."),
    no_ai: bool = typer.Option(False, "--no-ai", help="Disable AI enrichment entirely."),
    attack_sim: bool = typer.Option(
        False, "--attack-sim", help="Enable Attack Simulation Mode."
    ),
    patches: bool = typer.Option(
        False, "--patches", help="Generate (and where possible verify) fix patches."
    ),
    reachability: bool = typer.Option(
        False, "--reachability",
        help="Experimental: annotate dependency findings with an import-level "
             "reachability verdict (Python only for now). Findings for packages "
             "never imported by first-party code are marked and deprioritized, "
             "not suppressed.",
    ),
    no_cache: bool = typer.Option(
        False, "--no-cache",
        help="Re-analyze every file instead of reusing cached findings for "
             "unchanged files.",
    ),
    verify_secrets: bool = typer.Option(
        False, "--verify-secrets",
        help="Opt-in: make read-only calls to confirm detected secrets are LIVE "
             "(GitHub, Stripe, Slack, OpenAI, Google). Local targets only; makes "
             "network requests with the candidate credential. Off by default and "
             "never in CI templates.",
    ),
    min_severity: str | None = typer.Option(
        None, "--min-severity", help="Report findings at/above this severity."
    ),
    fail_on: str | None = typer.Option(
        None, "--fail-on", help="Exit non-zero if any finding is at/above this severity."
    ),
    baseline: Path | None = typer.Option(
        None, "--baseline",
        help="Path to a previous Argus JSON report; report only findings not in it.",
    ),
    branch: str | None = typer.Option(
        None, "--branch", "-b", help="Branch to clone for remote targets."
    ),
    trust_remote_config: bool = typer.Option(
        False, "--trust-remote-config",
        help="Load .argus.yml from a cloned remote repo (off by default; a scanned "
             "repo is untrusted and could suppress its own findings).",
    ),
    live_target: str | None = typer.Option(
        None, "--live-target",
        help="Also run safe, read-only runtime posture checks against this URL "
             "(security headers, cookie flags, TLS, exposed paths). Non-intrusive; "
             "only assess systems you are authorized to test.",
    ),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Suppress progress output."),
) -> None:
    """Scan a target and report findings."""
    from argus.core.engine import ScanEngine
    from argus.targets import resolve

    # Resolve the target first so config discovery can use the project root.
    try:
        resolved = resolve(target, branch=branch)
    except Exception as exc:
        err_console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(2) from exc

    # A URL target runs the posture layer directly (no source to analyze).
    if resolved.web is not None:
        if not quiet:
            err_console.print(
                "[dim]· Running read-only posture checks (not full DAST). "
                "Only assess systems you are authorized to test.[/dim]"
            )
        result = _posture_result(resolved.web.url, quiet=quiet)
        if min_severity:
            floor = Severity.parse(min_severity)
            result.findings = [f for f in result.findings if f.severity >= floor]
        _emit(result, fmt, output)
        gated = fail_on is not None and result.highest_severity() >= \
            Severity.parse(fail_on)
        raise typer.Exit(1 if gated else 0)

    project = resolved.project
    assert project is not None

    # Secret verification makes authenticated calls with the found credential.
    # Doing that with secrets pulled from someone else's cloned repo is out of
    # scope by design, restrict it to local targets.
    if verify_secrets and project.origin != "local":
        err_console.print(
            "[red]Error:[/red] --verify-secrets is only allowed for local targets "
            "(it would otherwise make authenticated calls with credentials from a "
            "remote repository you do not control)."
        )
        resolved.cleanup()
        raise typer.Exit(2)

    # Security: a cloned remote repository is untrusted. Do not honor a config file
    # discovered inside it (which could disable scanners or hide paths) unless the
    # user explicitly opts in. An explicit --config path is always respected.
    trust_project_config = project.origin == "local" or trust_remote_config
    if project.origin != "local" and not trust_remote_config and not quiet:
        err_console.print(
            "[dim]· Ignoring any .argus.yml inside the remote repo "
            "(use --trust-remote-config to honor it).[/dim]"
        )

    try:
        cfg = _build_config(
            config=config,
            project_root=project.root if trust_project_config else None,
            scanners=scanners,
            exclude=exclude, ai_provider=ai_provider, ai_model=ai_model, no_ai=no_ai,
            attack_sim=attack_sim, patches=patches, min_severity=min_severity,
            fail_on=fail_on, reachability=reachability, no_cache=no_cache,
            verify_secrets=verify_secrets,
        )

        progress = None if quiet else (lambda msg: err_console.print(f"[dim]· {escape(msg)}[/dim]"))
        engine = ScanEngine(cfg, progress=progress)
        result = engine.scan(project)

        # Optional runtime posture layer alongside the static scan.
        if live_target:
            if not quiet:
                err_console.print(
                    f"[dim]· Posture checks against {escape(live_target)} "
                    "(read-only; authorized use only)[/dim]"
                )
            from argus.dynamic import probe
            for finding in probe(live_target):
                result.add(finding)
            result.findings = result.sorted_findings()

        if baseline is not None:
            _apply_baseline(result, baseline, quiet=quiet)

        _emit(result, fmt, output)

        if engine.should_fail(result):
            err_console.print(
                f"[red]Failing:[/red] findings at/above "
                f"{cfg.fail_on.label if cfg.fail_on else ''}."
            )
            raise typer.Exit(1)
    finally:
        resolved.cleanup()


@app.command()
def fix(
    target: str = typer.Argument(".", help="Local path to a git repository to fix."),
    open_pr: bool = typer.Option(
        False, "--open-pr", help="Push the branch and open a pull request."
    ),
    dry_run: bool = typer.Option(
        False, "--dry-run", help="Show what would be fixed without writing anything."
    ),
    branch: str = typer.Option(
        "argus/security-fixes", "--branch", help="Name of the branch to create."
    ),
    base: str | None = typer.Option(
        None, "--base", help="Base branch for the PR (default: repo's default branch)."
    ),
    include_unverified: bool = typer.Option(
        False, "--include-unverified",
        help="Also apply fixes that did not self-verify (review carefully).",
    ),
    force_branch: bool = typer.Option(
        False, "--force-branch", help="Reuse/overwrite the branch if it already exists."
    ),
    scanners_opt: str | None = typer.Option(
        None, "--scanners", "-s", help="Comma-separated scanners to run (default: all)."
    ),
    min_severity: str | None = typer.Option(
        None, "--min-severity", help="Only consider findings at/above this severity."
    ),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Suppress progress output."),
) -> None:
    """Scan a repo, apply Argus's deterministic fixes on a branch, and open a PR.

    Only fixes Argus can generate and verify locally are applied (e.g. unsafe
    yaml.load, weak hashes, shell=True). Nothing is pushed or opened unless you
    pass --open-pr; --open-pr requires a GITHUB_TOKEN or GITLAB_TOKEN.
    """
    from argus.core.engine import ScanEngine
    from argus.remediation.pullrequest import FixOptions, run_fix_workflow
    from argus.targets import resolve

    try:
        resolved = resolve(target)
    except Exception as exc:
        err_console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(2) from exc
    if resolved.project is None:
        err_console.print("[red]Error:[/red] `argus fix` requires a local code path.")
        raise typer.Exit(2)

    project = resolved.project
    try:
        # Only honor an in-repo config for local targets (a cloned repo is untrusted).
        cfg = Config.load(
            project_root=project.root if project.origin == "local" else None
        )
        # Fixing is deterministic; AI enrichment is not needed and slows things down.
        cfg.ai.enabled = False
        if scanners_opt:
            cfg.scanners = [s.strip() for s in scanners_opt.split(",") if s.strip()]
        if min_severity:
            cfg.min_severity = Severity.parse(min_severity)

        progress = None if quiet else (lambda msg: err_console.print(f"[dim]· {escape(msg)}[/dim]"))
        result = ScanEngine(cfg, progress=progress).scan(project)

        options = FixOptions(
            branch=branch, base=base, open_pr=open_pr,
            include_unverified=include_unverified, dry_run=dry_run,
            force_branch=force_branch,
        )
        outcome = run_fix_workflow(project, result.findings, options)
        _print_fix_outcome(outcome, open_pr=open_pr, dry_run=dry_run)

        if outcome.error:
            raise typer.Exit(1)
    finally:
        resolved.cleanup()


@app.command()
def scanners() -> None:
    """List available scanners."""
    table = Table(title="Scanners", show_lines=False)
    table.add_column("Name", style="bold")
    table.add_column("Category")
    table.add_column("Description")
    for name, cls in sorted(registry.scanners().items()):
        table.add_row(name, cls.category, escape(cls.description))
    console.print(table)


@app.command()
def reporters() -> None:
    """List available report formats."""
    table = Table(title="Reporters")
    table.add_column("Name", style="bold")
    table.add_column("Extension")
    table.add_column("Description")
    for name, cls in sorted(registry.reporters().items()):
        table.add_row(name, cls.extension, escape(cls.description))
    console.print(table)


@app.command()
def providers() -> None:
    """List AI providers and whether each is currently usable."""
    table = Table(title="AI providers")
    table.add_column("Name", style="bold")
    table.add_column("Location")
    table.add_column("Default model")
    table.add_column("Available")
    for name, cls in sorted(registry.ai_providers().items()):
        loc = "remote" if cls.is_remote else "local"
        ok = "[green]yes[/green]" if cls.is_available() else "[dim]no[/dim]"
        table.add_row(name, loc, escape(cls.default_model or "-"), ok)
    console.print(table)
    console.print("[dim]Argus defaults to 'heuristic' (offline) if the requested "
                  "provider is unavailable.[/dim]")


@app.command()
def dashboard(
    host: str = typer.Option("127.0.0.1", "--host", help="Address to bind."),
    port: int = typer.Option(8000, "--port", "-p", help="Port to listen on."),
) -> None:
    """Launch the web dashboard (scan history and trends).

    Requires the dashboard extra: pip install "argus-appsec[dashboard]".
    """
    try:
        from argus.dashboard.app import serve
    except ImportError as exc:
        err_console.print(
            "[red]The dashboard needs extra dependencies.[/red] Install them with:\n"
            '  pip install "argus-appsec[dashboard]"'
        )
        raise typer.Exit(1) from exc
    console.print(f"Argus dashboard on [bold]http://{host}:{port}[/bold]  (Ctrl+C to stop)")
    serve(host=host, port=port)


@app.command()
def init(
    path: Path = typer.Argument(Path(".argus.yml"), help="Where to write the config."),
) -> None:
    """Write a starter .argus.yml configuration file."""
    if path.exists():
        err_console.print(f"[yellow]{path} already exists; not overwriting.[/yellow]")
        raise typer.Exit(1)
    path.write_text(_STARTER_CONFIG, encoding="utf-8")
    console.print(f"[green]Wrote {path}.[/green] Edit it to tune your scans.")


@app.command()
def version() -> None:
    """Print the Argus version."""
    console.print(f"Argus v{__version__}")


# --- helpers ---------------------------------------------------------------
def _posture_result(url: str, *, quiet: bool) -> ScanResult:
    """Build a ScanResult from live posture checks against a URL."""
    from datetime import datetime, timezone

    from argus.dynamic import probe

    started = datetime.now(timezone.utc)
    result = ScanResult(target=url, started_at=started, argus_version=__version__,
                        scanners_run=["posture"])
    for finding in probe(url):
        result.add(finding)
    result.findings = result.sorted_findings()
    result.finished_at = datetime.now(timezone.utc)
    result.project_summary = {"name": url, "origin": "url", "target": url}
    return result


def _apply_baseline(result: ScanResult, baseline: Path, *, quiet: bool) -> None:
    """Drop findings already present in a baseline report (diff-aware scanning)."""
    from argus.baseline import BaselineError, filter_new, load_fingerprints

    try:
        known = load_fingerprints(baseline)
    except BaselineError as exc:
        err_console.print(f"[yellow]Baseline ignored:[/yellow] {exc}")
        return
    result.findings, suppressed = filter_new(result.findings, known)
    if not quiet:
        err_console.print(
            f"[dim]· Baseline: {suppressed} known finding(s) suppressed, "
            f"{len(result.findings)} new.[/dim]"
        )


def _build_config(*, config, project_root, scanners, exclude, ai_provider, ai_model,
                  no_ai, attack_sim, patches, min_severity, fail_on,
                  reachability=False, no_cache=False, verify_secrets=False) -> Config:
    cfg = Config.load(path=config, project_root=project_root)
    if reachability:
        cfg.scanner_options.setdefault("dependencies", {})["reachability"] = True
    if no_cache:
        cfg.cache = False
    if verify_secrets:
        cfg.scanner_options.setdefault("secrets", {})["verify"] = True
    if scanners:
        cfg.scanners = [s.strip() for s in scanners.split(",") if s.strip()]
    if exclude:
        cfg.exclude_scanners = [s.strip() for s in exclude.split(",") if s.strip()]
    if ai_provider:
        cfg.ai.provider = ai_provider
    if ai_model:
        cfg.ai.model = ai_model
    if no_ai:
        cfg.ai.enabled = False
    if attack_sim:
        cfg.attack_simulation = True
    if patches:
        cfg.generate_patches = True
    if min_severity:
        cfg.min_severity = Severity.parse(min_severity)
    if fail_on:
        cfg.fail_on = Severity.parse(fail_on)
    return cfg


def _print_fix_outcome(outcome, *, open_pr: bool, dry_run: bool) -> None:
    report = outcome.applied
    if report.fixes:
        table = Table(title="Fixes" + (" (dry run)" if dry_run else ""))
        table.add_column("File", style="bold")
        table.add_column("Line", justify="right")
        table.add_column("Rule", style="dim")
        table.add_column("Verified", justify="center")
        for f in report.fixes:
            table.add_row(escape(f.path), str(f.line), escape(f.rule_id),
                          "[green]yes[/green]" if f.verified else "[yellow]no[/yellow]")
        console.print(table)
    else:
        console.print("[yellow]No deterministic fixes were applicable to these "
                      "findings.[/yellow]")

    for msg in outcome.messages:
        console.print(f"[dim]· {escape(msg)}[/dim]")

    if outcome.pull_request:
        console.print(Panel(f"[green]Pull request opened:[/green]\n"
                            f"{outcome.pull_request.url}", border_style="green"))
    elif outcome.committed and not open_pr:
        console.print("[green]Fixes committed to the branch.[/green] "
                      "Add --open-pr to push and open a pull request.")

    if outcome.error:
        err_console.print(f"[red]Stopped:[/red] {outcome.error}")


def _emit(result: ScanResult, formats: list[str], output: Path | None) -> None:
    # Count file-bound formats (everything except the console table) so we know
    # whether a single -o file path is enough or we must disambiguate by extension.
    file_formats = [f for f in formats if f != "table"]
    treat_as_dir = output is not None and (
        output.is_dir() or (output.suffix == "" and not output.exists())
    )

    for fmt in formats:
        if fmt == "table":
            _print_table(result)
            continue
        cls = registry.reporters().get(fmt)
        if cls is None:
            err_console.print(f"[yellow]Unknown format '{fmt}', skipping.[/yellow]")
            continue
        rendered = cls().render(result)
        extension = cls().extension
        if output is None:
            # Write raw to stdout, never through Rich, which would soft-wrap and
            # corrupt machine-readable formats (JSON/SARIF/CSV) when piped.
            sys.stdout.write(rendered)
            if not rendered.endswith("\n"):
                sys.stdout.write("\n")
        elif treat_as_dir:
            output.mkdir(parents=True, exist_ok=True)
            dest = output / f"argus-report.{extension}"
            dest.write_text(rendered, encoding="utf-8")
            console.print(f"[green]Wrote {dest}[/green]")
        elif len(file_formats) > 1:
            # A single file path was given for several formats: keep the stem and
            # give each format its own extension (report.html, report.sarif, ...).
            dest = output.with_suffix(f".{extension}")
            dest.write_text(rendered, encoding="utf-8")
            console.print(f"[green]Wrote {dest}[/green]")
        else:
            output.write_text(rendered, encoding="utf-8")
            console.print(f"[green]Wrote {output}[/green]")


def _print_table(result: ScanResult) -> None:
    findings = result.sorted_findings()
    counts = result.counts_by_severity()

    summary = " · ".join(f"{label}: {n}" for label, n in counts.items())
    console.print(Panel(
        f"[bold]{result.project_summary.get('name', result.target)}[/bold]\n"
        f"Aggregate risk: [bold]{result.aggregate_risk()}/100[/bold]   "
        f"Findings: [bold]{len(findings)}[/bold]\n{summary}",
        title="Argus scan", border_style="cyan",
    ))

    if not findings:
        console.print("[green]No findings at or above the configured severity.[/green]")
        return

    table = Table(show_lines=False)
    table.add_column("Sev", style="bold")
    table.add_column("Risk", justify="right")
    table.add_column("Title")
    table.add_column("Location", style="dim")
    table.add_column("Rule", style="dim")

    colors = {
        Severity.CRITICAL: "red", Severity.HIGH: "orange3",
        Severity.MEDIUM: "yellow", Severity.LOW: "blue", Severity.INFO: "white",
    }
    for f in findings:
        c = colors.get(f.severity, "white")
        table.add_row(
            f"[{c}]{f.severity.label}[/{c}]",
            str(f.risk_score()),
            escape(f.title),
            escape(f.location.as_ref()),
            escape(f.rule_id),
        )
    console.print(table)

    if result.errors:
        err_console.print(f"[yellow]{len(result.errors)} scan warning(s).[/yellow]")


_STARTER_CONFIG = """\
# Argus configuration. See docs/configuration.md for all options.

# Scanners to run (empty = all applicable).
scanners: []
exclude_scanners: []

# Extra path globs to ignore (added to built-in ignores).
exclude_paths: []

# Minimum severity to report: info | low | medium | high | critical
min_severity: info

# Fail the process (non-zero exit) if any finding is at/above this severity.
# Useful in CI. Leave empty to never fail on findings.
fail_on: ""

# Flagship educational feature: safe, sandboxed attack demonstrations.
attack_simulation: false

# Generate (and where possible verify) fix patches.
generate_patches: false

ai:
  # heuristic (offline, no key) | anthropic | openai | ollama (local)
  provider: heuristic
  model: ""
  enabled: true
  temperature: 0.0
  max_tokens: 1500

# Per-scanner options.
scanner_options:
  secrets:
    entropy: true
    entropy_threshold: 4.0
"""


if __name__ == "__main__":  # pragma: no cover
    app()
