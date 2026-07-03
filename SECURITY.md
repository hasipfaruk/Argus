# Security Policy

## Reporting a vulnerability in Argus

If you discover a security vulnerability in Argus itself, please report it
privately. Do **not** open a public issue.

- Email: security@argus-security.example (replace with the project's real contact)
- Or use GitHub's private "Report a vulnerability" advisory flow on the repository.

Please include a description, reproduction steps, and the affected version. We aim
to acknowledge reports within a few business days and to coordinate a fix and
disclosure timeline with you.

## Scope

Argus reads source code and, optionally, sends code to a configured AI provider.
Relevant considerations:

- The default `heuristic` provider and the `ollama` provider keep source on your
  machine. The `anthropic` and `openai` providers send code to those services —
  choose a provider appropriate to your confidentiality requirements
  (`argus providers` shows which are local vs. remote).
- Attack Simulation Mode is descriptive and non-executing: it does not run
  generated exploit code or contact live targets.

## Supported versions

Argus is in early alpha (0.x). Security fixes are applied to the latest release.
