# Argus

**An open-source AI Security Engineer.** Point it at a codebase or a running
application; it maps the system, runs layered security analysis, explains every
finding the way a senior application-security engineer would, and — where
possible — proposes and verifies a fix.

Argus is not just another scanner that prints a list. For each finding it tells
you *why* it is a vulnerability, *how* an attacker would exploit it, the *business
impact*, the likelihood and severity, the CWE/OWASP mapping, and concrete
remediation — and it can generate a patch and check that the patch closes the
issue.

> Status: early alpha. The architecture and core pipeline are in place with a
> working CLI, four built-in scanners, a multi-provider AI layer, and five report
> formats. See the [roadmap](#roadmap).

---

## Highlights

- **Understands the project first.** Detects languages and frameworks and builds
  an architecture map — APIs, auth flows, datastores, third-party services, cloud,
  containers, CI/CD, and dependency manifests — before scanning.
- **Layered analysis.** Secret detection, dependency vulnerabilities (checked
  against the live [OSV](https://osv.dev) database), static code analysis (SAST),
  and infrastructure-as-code checks out of the box, extensible via plugins.
- **Findings that teach.** Every finding carries reasoning, taxonomy mappings, and
  remediation — not just a line number.
- **Attack Simulation Mode.** Instead of "this is vulnerable", Argus produces a
  safe, isolated walkthrough: how the flaw is discovered, a step-by-step
  (non-weaponized) exploit, the data at risk, the business impact, and how the fix
  blocks the attack — with a before/after comparison.
- **Bring your own model.** Offline heuristic provider by default (no key, no
  network); Anthropic and OpenAI for cloud models; Ollama for fully local models
  so source never leaves your environment.
- **Plugin-based throughout.** Scanners, reporters, and AI providers are plugins.
  Add a language or a report format without touching the core.
- **CI-ready output.** JSON, SARIF (GitHub Code Scanning), Markdown, HTML, and CSV.

## Install

```bash
# From PyPI
pip install argus-appsec

# With cloud model support
pip install "argus-appsec[anthropic,openai]"
```

From source (for development):

```bash
git clone https://github.com/hasipfaruk/Argus
cd Argus
pip install -e ".[dev]"
```

Requires Python 3.10+. The command installed is `argus`.

## Quick start

```bash
# Scan a local project and print a table
argus scan ./my-app

# Turn on the flagship features and write an HTML report
argus scan ./my-app --attack-sim --patches -f html -o report.html

# Scan a remote repository (shallow-cloned to a temp dir, then cleaned up)
argus scan https://github.com/org/repo

# Apply Argus's verified fixes to a branch and open a pull request
argus fix ./my-app --open-pr

# Use a local model so code stays on your machine
argus scan ./my-app --ai-provider ollama --ai-model llama3.1

# Machine-readable output for CI, failing the build on High+
argus scan ./my-app -f sarif -o results.sarif --fail-on high
```

Explore what's available:

```bash
argus scanners     # list scanners
argus reporters    # list report formats
argus providers    # list AI providers and whether each is usable right now
argus init         # write a starter .argus.yml
```

## How it works

```
target ──▶ resolve ──▶ analyze ──▶ scan ──▶ enrich (agents) ──▶ report
          (path/git/    (languages,  (secrets,   (reasoning,        (json, sarif,
           url)          frameworks,  deps,        attack sim,        markdown,
                         architecture) sast, iac)  patches)           html, csv)
```

The engine is synchronous and side-effect free apart from reading the target: it
returns a `ScanResult` and writes nothing. Reporting and any PR creation are
separate, explicit steps. See [docs/architecture.md](docs/architecture.md).

## Configuration

Drop a `.argus.yml` in your project root (generate one with `argus init`):

```yaml
min_severity: low
fail_on: high
attack_simulation: true
generate_patches: true
ai:
  provider: ollama      # heuristic | anthropic | openai | ollama
  model: llama3.1
scanner_options:
  secrets:
    entropy_threshold: 4.2
```

Full reference: [docs/configuration.md](docs/configuration.md).

## Extending Argus

Everything is a plugin. A minimal scanner:

```python
from argus.core.plugin import Scanner, ScannerContext, scanner
from argus.core.models import Finding, Location, Severity

@scanner
class HelloScanner(Scanner):
    name = "hello"
    category = "example"
    description = "Flags TODO comments as a demo."

    def scan(self, ctx: ScannerContext):
        for f in ctx.project.files():
            for i, line in enumerate(f.lines(), 1):
                if "TODO" in line:
                    yield Finding(
                        id=f"hello:todo:{i}", rule_id="hello.todo", scanner=self.name,
                        title="TODO left in code", description="A TODO marker.",
                        location=Location(path=f.rel_path, start_line=i),
                        severity=Severity.INFO,
                    )
```

Register it via the `argus.plugins` entry point in your package and it is picked
up automatically. Full guide: [docs/plugins.md](docs/plugins.md).

## AI providers and data handling

| Provider    | Location | Source leaves your machine? | Needs |
|-------------|----------|-----------------------------|-------|
| `heuristic` | local    | no                          | nothing (default) |
| `ollama`    | local    | no                          | a running Ollama server |
| `anthropic` | cloud    | yes                         | `ANTHROPIC_API_KEY` + `[anthropic]` extra |
| `openai`    | cloud    | yes                         | `OPENAI_API_KEY` + `[openai]` extra |

If a requested provider is unavailable, Argus warns and falls back to `heuristic`
so a scan always completes.

## Fixing, not just finding

`argus fix` closes the loop: it scans a repository, applies the fixes it can
verify locally to a fresh branch, commits them, and (with `--open-pr`) opens a
pull request.

```bash
argus fix ./my-app --dry-run      # preview the changes, write nothing
argus fix ./my-app                # apply fixes to a branch and commit locally
argus fix ./my-app --open-pr      # also push and open a PR (needs GITHUB_TOKEN)
```

Only deterministic, self-verified fixes are applied by default (e.g. unsafe
`yaml.load` → `yaml.safe_load`, weak hashes → SHA-256, `shell=True` removal,
`debug=True` → `debug=False`). See [docs/fixing.md](docs/fixing.md).

## Roadmap

Implemented: project analysis, secrets/dependency/SAST/IaC scanners, multi-provider
AI enrichment, Attack Simulation Mode, deterministic patch generation with
self-verification, **automated fix branches and pull requests** (`argus fix`), and
JSON/SARIF/Markdown/HTML/CSV reporting.

Planned: dynamic analysis (DAST) for deployed URLs, AST-based per-language
scanners, live advisory-database sync (OSV), the web dashboard (trends, timelines,
collaboration), and richer compliance rule packs.

## Contributing

Contributions are welcome from everyone. The flow is the standard one:

1. **Fork** this repository.
2. Create a branch and make your change (with tests).
3. Open a **pull request** — the template will guide you, and CI runs tests and
   lint automatically.

Scanners, language support, compliance rules, and report formats are especially
welcome — the plugin model means most additions never touch the core. See
[CONTRIBUTING.md](CONTRIBUTING.md) for setup and standards, and
[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) for community guidelines.

## License

Apache-2.0. See [LICENSE](LICENSE).
