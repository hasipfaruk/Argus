# Configuration

Argus reads configuration from, in increasing precedence:

1. Built-in defaults.
2. `.argus.yml` (or `.argus.yaml`) in the project root.
3. A file passed with `--config`.
4. Command-line flags.

Generate a starter file with `argus init`.

## Full reference

```yaml
# Scanners to run. Empty = every scanner that applies to the project.
scanners: []            # e.g. ["secrets", "patterns"]

# Scanners to skip (applied after the list above).
exclude_scanners: []    # e.g. ["iac"]

# Extra path globs to ignore, added to the built-in ignore list
# (.git, node_modules, venv, build artifacts, etc.).
exclude_paths: []       # e.g. ["tests/fixtures/*", "*.min.js"]

# Minimum severity to report: info | low | medium | high | critical
min_severity: info

# Exit non-zero if any finding is at/above this severity. Empty = never fail.
# Use this to gate CI.
fail_on: ""             # e.g. high

# Attack Simulation Mode: safe, sandboxed exploit demonstrations per finding.
attack_simulation: false

# Generate fix patches (and verify the deterministic ones).
generate_patches: false

ai:
  # heuristic (offline, default) | anthropic | openai | ollama (local)
  provider: heuristic
  model: ""             # provider-specific; empty uses the provider default
  enabled: true         # false disables all AI enrichment
  temperature: 0.0
  max_tokens: 1500

# Per-scanner options, keyed by scanner name.
scanner_options:
  secrets:
    entropy: true             # enable high-entropy string detection
    entropy_threshold: 4.0    # bits; raise to reduce false positives
```

## Common recipes

**Fast secrets-and-deps check, fail the build on High+:**

```yaml
scanners: [secrets, dependencies]
fail_on: high
```

**Everything, with the flagship features, using a local model:**

```yaml
attack_simulation: true
generate_patches: true
ai:
  provider: ollama
  model: llama3.1
```

**Quiet down a noisy entropy scanner:**

```yaml
scanner_options:
  secrets:
    entropy_threshold: 4.5
```

## Environment variables

Credentials for cloud providers and git hosts are read from the environment (see
`.env.example`):

| Variable | Used by |
|----------|---------|
| `ANTHROPIC_API_KEY` | `anthropic` provider |
| `OPENAI_API_KEY` | `openai` provider |
| `OLLAMA_HOST` | `ollama` provider (default `http://localhost:11434`) |
| `GITHUB_TOKEN` / `GITLAB_TOKEN` / `BITBUCKET_TOKEN` | cloning private remote targets |

## CLI flags

Every relevant config field has a flag, which overrides the file:

```
argus scan TARGET
  -s, --scanners a,b        run only these scanners
      --exclude a,b         skip these scanners
  -f, --format FMT          output format (repeatable): table json sarif markdown html csv
  -o, --output PATH         write reports (a directory writes one file per format)
      --ai-provider NAME    heuristic | anthropic | openai | ollama
      --ai-model ID         model override
      --no-ai               disable AI enrichment
      --attack-sim          enable Attack Simulation Mode
      --patches             generate/verify fix patches
      --min-severity SEV    report findings at/above this severity
      --fail-on SEV         non-zero exit if any finding is at/above this severity
  -b, --branch NAME         branch to clone for remote targets
  -q, --quiet               suppress progress output
```
