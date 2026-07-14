# Architecture

Argus is built as a small, strict core with everything domain-specific pushed out
to plugins. This document describes the core, the data flow, and where the seams
are.

## The pipeline

A scan is a linear pipeline. Each stage has a single responsibility and passes a
well-defined object to the next.

```
              targets.resolve
 target ───────────────────────▶ Project (or WebTarget)
                                    │
        RepositoryAnalyzer.analyze  │  languages, frameworks, architecture
                                    ▼
                             enriched Project
                                    │
             ScanEngine.scan        │  select applicable scanners
                                    ▼
                         [ Scanner.scan(ctx) ]*   ──▶  Finding[]
                                    │
              agents (per finding)  │  EnrichmentAgent → AttackSimulationAgent → PatchAgent
                                    ▼
                              ScanResult
                                    │
             Reporter.render        │  json | sarif | markdown | html | csv
                                    ▼
                             report string(s)
```

The engine (`argus.core.engine.ScanEngine`) owns orchestration. It is synchronous
and free of side effects apart from reading the target: `scan()` returns a
`ScanResult` and writes nothing to disk. Writing reports and creating pull
requests are separate, explicit actions performed by the CLI or an integration.

## Core modules

| Module | Responsibility |
|--------|----------------|
| `argus.core.models` | The `Finding`, `ScanResult`, `Severity`, `Remediation`, and `ExploitScenario` data types. Everything speaks these. |
| `argus.core.project` | `Project` and `FileRef`: a normalized, lazily-read view of the target. Scanners consume this, never the filesystem directly. |
| `argus.core.plugin` | The `Scanner`/`Reporter` contracts and the global `Registry`. The extension surface. |
| `argus.core.config` | `Config` loading and defaults. |
| `argus.core.engine` | The `ScanEngine` orchestrator. |
| `argus.analysis.repository` | `RepositoryAnalyzer`: language, framework, and architecture detection. |
| `argus.ai` | The `AIProvider` contract and the heuristic/Anthropic/OpenAI/Ollama providers, plus the selection `factory`. |
| `argus.agents` | Finding-processing agents: enrichment, attack simulation, patch generation. |
| `argus.scanners` | Built-in scanners. |
| `argus.reporting` | Built-in reporters. |
| `argus.targets` | Resolves a target string into a `Project` or `WebTarget`. |
| `argus.cli` | The Typer command-line interface. |

## The Finding contract

`Finding` is the load-bearing type. A scanner is responsible for identity,
location, severity, and taxonomy (CWE/OWASP). The reasoning fields
(`why_vulnerable`, `attacker_perspective`, `business_impact`), the
`ExploitScenario`, and the `Remediation.patch` may be filled by the scanner or
completed later by an agent. This split is what lets a simple regex scanner and a
sophisticated AI agent contribute to the same finding without coupling.

`risk_score()` blends severity, confidence, and likelihood into a 0–100 number;
`ScanResult.aggregate_risk()` rolls findings up into a single target score that is
dominated by the worst finding rather than averaged.

## Plugin discovery

Two registration paths feed the same global `Registry`:

1. **In-process**, importing a scanner/reporter/provider module runs its
   `@scanner`/`@reporter`/`@ai_provider` decorator, registering the class. The
   built-ins use this via `argus.plugins.register_builtins`.
2. **Entry points**, third-party packages declare a callable under the
   `argus.plugins` entry-point group in their `pyproject.toml`. The registry
   loads these lazily on first lookup. A failure in one plugin is isolated and
   never aborts discovery of the others.

See [plugins.md](plugins.md) for how to write one.

## AI providers and the offline default

Agents talk to models through the `AIProvider` interface. The default provider is
`heuristic`: it requires no key and no network and fills findings from templates
keyed on CWE. This keeps a base scan fully offline and deterministic, important
for tests and air-gapped environments. Cloud (`anthropic`, `openai`) and local
(`ollama`) providers are drop-in alternatives. If a requested provider is
unavailable, the factory falls back to `heuristic` with a warning rather than
failing the scan.

## Error handling philosophy

A scan should be robust to a single broken component. A scanner that raises is
recorded in `ScanResult.errors` and the scan continues. An agent that fails on a
finding falls back to heuristic enrichment for that finding. The goal is that
`argus scan` always produces a usable report.
