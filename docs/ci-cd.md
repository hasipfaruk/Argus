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

## Diff-aware scanning with a baseline

Adopting a scanner on an existing codebase usually means drowning in pre-existing
findings. Use a **baseline** so a pull request is judged only on the findings it
*introduces*:

```bash
# 1. Scan the base branch and save the report as a baseline (outside the tree).
argus scan /path/to/base-checkout -f json -o /tmp/baseline.json --quiet

# 2. Scan the PR, suppressing anything already in the baseline, and gate on new High+.
argus scan . --baseline /tmp/baseline.json --fail-on high --quiet
```

Findings are matched by a **content-based fingerprint** (the whitespace-normalized
offending code, not the line number), so a finding is still recognized as
pre-existing after unrelated edits shift it up or down the file. The shipped
[`argus-scan.yml`](../.github/workflows/argus-scan.yml) workflow does this
automatically on pull requests.

## Reproducibility

Argus walks files in a deterministic, sorted order, so finding IDs and report
ordering are stable across machines and runs — safe to diff report-to-report.

## Untrusted targets

When scanning a **remote** repository (a git URL), Argus ignores any `.argus.yml`
inside that repo by default, so a scanned project cannot weaken its own scan. Pass
`--trust-remote-config` to opt in when you control the repository.

## GitLab CI

```yaml
argus:
  image: python:3.12-slim
  script:
    - pip install argus-appsec
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
