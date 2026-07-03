# CI/CD integration

Argus is built to run in a pipeline: it emits SARIF for code-scanning platforms
and can fail a build on a severity threshold.

## GitHub Actions

A ready-to-copy workflow lives at
[`.github/workflows/argus-scan.yml`](../.github/workflows/argus-scan.yml). It runs
Argus, writes SARIF, and uploads it to GitHub Code Scanning so findings appear as
PR annotations and in the Security tab.

To **block merges** instead of only annotating, add a gate:

```yaml
      - name: Run Argus (gate on High+)
        run: argus scan . --fail-on high --quiet -f sarif -o argus.sarif
```

`--fail-on high` makes the step exit non-zero when any High or Critical finding is
present.

## GitLab CI

```yaml
argus:
  image: python:3.12-slim
  script:
    - pip install argus-sec
    - argus scan . -f sarif -o gl-argus.sarif --fail-on high
  artifacts:
    when: always
    paths:
      - gl-argus.sarif
```

## Pre-commit hook

Catch secrets and obvious issues before they are committed:

```yaml
# .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: argus
        name: argus (secrets + patterns)
        entry: argus scan . -s secrets,patterns --fail-on high --quiet
        language: system
        pass_filenames: false
```

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | Scan completed; no finding met the `--fail-on` threshold (or none was set). |
| 1 | Scan completed but a finding met the `--fail-on` threshold. |
| 2 | The target could not be resolved (bad path/URL, clone failed). |

## Keeping scans fast in CI

- Restrict scanners to what you need: `-s secrets,dependencies,patterns`.
- Disable AI enrichment for speed with `--no-ai` (findings still carry their
  built-in reasoning and taxonomy).
- Use `exclude_paths` in `.argus.yml` to skip vendored or generated code.
