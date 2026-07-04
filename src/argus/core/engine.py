"""The scan engine: orchestrates a full analysis.

Pipeline:

1. **Analyze** — build the project model (languages, frameworks, architecture).
2. **Scan** — run every applicable scanner, collecting findings.
3. **Enrich** — run agents over each finding (reasoning, attack simulation,
   patch generation) according to config.
4. **Assemble** — filter by severity, sort, and package into a ``ScanResult``.

The engine is deliberately synchronous and side-effect free apart from reading
the target: it returns a ``ScanResult`` and writes nothing. Reporting and PR
creation are separate steps.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from argus import __version__
from argus.agents import (
    AgentContext,
    AttackSimulationAgent,
    EnrichmentAgent,
    PatchAgent,
)
from argus.ai.factory import build_provider
from argus.analysis.repository import RepositoryAnalyzer
from argus.core.config import Config
from argus.core.models import Finding, ScanResult
from argus.core.plugin import Scanner, ScannerContext, registry
from argus.core.project import Project

if TYPE_CHECKING:
    from argus.ai.base import AIProvider

# A callback the CLI uses to render progress. No-op by default.
ProgressFn = Callable[[str], None]


class ScanEngine:
    def __init__(self, config: Config, progress: ProgressFn | None = None) -> None:
        self.config = config
        self._progress = progress or (lambda _msg: None)

    def scan(self, project: Project) -> ScanResult:
        started = datetime.now(timezone.utc)
        result = ScanResult(
            target=str(project.root),
            started_at=started,
            argus_version=__version__,
        )

        # 1. Analyze
        self._progress("Analyzing project structure...")
        project.extra_ignores = tuple(self.config.exclude_paths)
        RepositoryAnalyzer().analyze(project)
        result.project_summary = project.summary()

        # AI provider (shared by all agents). Falls back to heuristic if needed.
        ai = build_provider(self.config.ai)
        self._progress(
            f"AI provider: {ai.name}"
            + ("" if ai.is_remote else " (local / offline)")
        )

        # 2. Scan
        scanners = self._select_scanners(project)
        result.scanners_run = [s.name for s in scanners]
        scan_ctx = ScannerContext(project=project, config=self.config, ai=ai)
        for scanner in scanners:
            self._progress(f"Running scanner: {scanner.name}")
            try:
                for finding in scanner.scan(scan_ctx):
                    result.add(finding)
            except Exception as exc:  # a broken scanner must not sink the scan
                result.errors.append(f"scanner '{scanner.name}' failed: {exc}")

        # 3. Filter, then enrich. Filtering first means agents (and any paid model
        # calls they make) only run on findings we will actually report.
        result.findings = self._filter(result.findings)
        if self.config.ai.enabled:
            self._run_agents(result, project, ai)

        # 4. Assemble
        result.findings = result.sorted_findings()
        result.finished_at = datetime.now(timezone.utc)
        self._progress(
            f"Done: {len(result.findings)} finding(s), "
            f"highest severity {result.highest_severity().label}."
        )
        return result

    # --- steps --------------------------------------------------------------
    def _select_scanners(self, project: Project) -> list[Scanner]:
        available = registry.scanners()
        explicit = bool(self.config.scanners)
        chosen_names = self.config.scanners or list(available)
        selected: list[Scanner] = []
        for name in chosen_names:
            if name in self.config.exclude_scanners:
                continue
            cls = available.get(name)
            if cls is None:
                # Only warn for names the user asked for explicitly; the "all"
                # default is derived from the registry and can't contain unknowns.
                if explicit:
                    self._progress(
                        f"Unknown scanner '{name}' (available: "
                        f"{', '.join(sorted(available))})."
                    )
                continue
            instance = cls()
            if instance.applies_to(project):
                selected.append(instance)
            else:
                self._progress(f"Skipping scanner '{name}' (not applicable).")
        return selected

    def _run_agents(self, result: ScanResult, project: Project,
                    ai: AIProvider) -> None:
        agent_ctx = AgentContext(project=project, config=self.config, ai=ai)
        enrichment = EnrichmentAgent()
        simulator = AttackSimulationAgent()
        patcher = PatchAgent()

        total = len(result.findings)
        for i, finding in enumerate(result.findings, start=1):
            self._progress(f"Enriching findings ({i}/{total})...")
            enrichment.process(finding, agent_ctx)
            if self.config.attack_simulation:
                simulator.process(finding, agent_ctx)
            if self.config.generate_patches:
                patcher.process(finding, agent_ctx)

    def _filter(self, findings: list[Finding]) -> list[Finding]:
        return [f for f in findings if f.severity >= self.config.min_severity]

    # --- CI gating helper ---------------------------------------------------
    def should_fail(self, result: ScanResult) -> bool:
        if self.config.fail_on is None:
            return False
        return result.highest_severity() >= self.config.fail_on
