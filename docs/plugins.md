# Writing plugins

Argus has three extension points, **scanners**, **reporters**, and **AI
providers**, and adding any of them requires no change to the core. This guide
walks through each.

## Scanners

A scanner analyzes a `Project` and yields `Finding` objects. Subclass `Scanner`,
set the class attributes, and implement `scan`.

```python
from collections.abc import Iterable

from argus.core.plugin import Scanner, ScannerContext, scanner
from argus.core.models import (
    Finding, Location, Remediation, Severity, Confidence,
)


@scanner  # registers the scanner with the global registry
class TodoScanner(Scanner):
    name = "todo"                    # unique id (used in config and finding ids)
    category = "hygiene"             # grouping shown in `argus scanners`
    description = "Flags TODO/FIXME markers left in code."

    def applies_to(self, project) -> bool:
        # Cheap opt-out so the engine can skip irrelevant scanners.
        return bool(project.files())

    def scan(self, ctx: ScannerContext) -> Iterable[Finding]:
        counter = 0
        for f in ctx.project.files():
            if f.language is None:            # skip non-source files
                continue
            for lineno, line in enumerate(f.lines(), start=1):
                if "TODO" in line or "FIXME" in line:
                    counter += 1
                    yield Finding(
                        id=f"{self.name}:marker:{counter}",
                        rule_id=f"{self.name}.marker",
                        scanner=self.name,
                        title="Unresolved TODO/FIXME",
                        description="A TODO or FIXME marker remains in the code.",
                        location=Location(path=f.rel_path, start_line=lineno,
                                          snippet=line.strip()),
                        severity=Severity.INFO,
                        confidence=Confidence.HIGH,
                        remediation=Remediation(summary="Resolve or ticket the item."),
                    )
```

### What the context gives you

`ScannerContext` carries:

- `ctx.project`, the analyzed `Project` (languages, frameworks, architecture, and
  `files()` for iteration).
- `ctx.config`, the active `Config`. Read per-scanner options with
  `ctx.config.options_for(self.name)`.
- `ctx.ai`, the selected `AIProvider`, if a scanner wants to use a model directly
  (most don't; enrichment is the agents' job).

### Good scanner behavior

- **Be cheap when you don't apply.** Use `applies_to` to bail early.
- **Fill the taxonomy.** Set `cwe` and `owasp`; reporters and SARIF consumers rely
  on them.
- **Provide reasoning where you can.** If your rule knows why it's a vulnerability,
  set `why_vulnerable`/`attacker_perspective`/`business_impact` so findings are
  useful even with the offline provider.
- **Never crash the scan.** The engine isolates exceptions, but a scanner that
  guards its own edge cases produces better results.

## Reporters

A reporter turns a `ScanResult` into a string.

```python
from argus.core.plugin import Reporter, reporter
from argus.core.models import ScanResult


@reporter
class OneLineReporter(Reporter):
    name = "oneline"
    extension = "txt"
    description = "One line per finding."

    def render(self, result: ScanResult) -> str:
        return "\n".join(
            f"{f.severity.label}\t{f.location.as_ref()}\t{f.title}"
            for f in result.sorted_findings()
        )
```

The new format is immediately available as `argus scan ... -f oneline`.

## AI providers

Wrap any chat-style model by subclassing `AIProvider`.

```python
from argus.ai.base import AIProvider
from argus.core.plugin import ai_provider


@ai_provider
class MyProvider(AIProvider):
    name = "myprovider"
    is_remote = True                 # does this send code off the machine?
    default_model = "my-model-v1"

    @classmethod
    def is_available(cls) -> bool:
        # Return True only if the SDK and credentials are present.
        return True

    def complete(self, system: str, user: str) -> str:
        # Call your model and return the text completion.
        ...
```

Set `is_remote` honestly, the `argus providers` command surfaces it so users can
choose a local provider when source confidentiality matters.

## Community rules (YAML, no Python)

The `patterns` scanner is rule-driven, and you can extend it with a **YAML file**,
no code, which is the easiest way to contribute a check. Argus loads rules
from any path in `scanner_options.patterns.rules` (a string or list, globs
allowed) and from the convention directory `.argus/rules/*.yml` in your project.

```yaml
# .argus/rules/team.yml
rules:
  - id: hardcoded-internal-ip
    title: Hardcoded internal IP address
    pattern: '\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'
    severity: low            # info | low | medium | high | critical
    languages: [Python, Go]  # optional; omit for all languages
    cwe: [CWE-1188]          # optional
    owasp: ["A05:2021-Security Misconfiguration"]   # optional
    confidence: low          # optional: low | medium | high
    why: An internal IP is baked into source.
    fix: Move host addresses into configuration.
    suppress: 'argus:allow-internal-ip'   # optional: a regex that clears a match
```

Findings from a custom rule are reported as `patterns.<id>`. A malformed rule is
skipped with a warning rather than aborting the scan. A ready-to-copy example
lives in [`examples/custom-rules/`](../examples/custom-rules/). This is the
recommended path for language- or org-specific rules; reach for a Python scanner
plugin (below) only when a rule needs logic a regex can't express.

## Packaging a plugin

Ship your plugins in a normal Python package and declare a registration callable
under the `argus.plugins` entry-point group:

```toml
# your_plugin/pyproject.toml
[project.entry-points."argus.plugins"]
my_plugin = "your_plugin:register"
```

```python
# your_plugin/__init__.py
def register() -> None:
    # Importing the modules runs the @scanner/@reporter/@ai_provider decorators.
    from your_plugin import scanners, reporters  # noqa: F401
```

Once the package is installed alongside Argus, its plugins are discovered
automatically, no configuration required.
