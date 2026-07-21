# Scanners & coverage

Argus runs a set of scanners over one project view in a single pass. They share a
severity model and a report, so you get one prioritized list, not six. Run
`argus scanners` to see which are active in your install.

Each scanner below lists what it detects, what it deliberately does not, and its
current limitations. Stating the limits is intentional: it is how you know where
to still apply human review.

## Secrets

**Detects.** Hardcoded credentials by signature (cloud keys, tokens, private
keys) and by entropy, with common false positives (placeholders, sample values)
filtered out. Optional live verification (`--verify-secrets`) checks whether a
found credential is still active, using read-only endpoints.

**Does not.** Scan git history by default (working tree only), and never stores or
prints a full secret: values are redacted to a short prefix plus length
everywhere.

**Git history (opt-in).** Pass `--secrets-history` to also scan every commit for
secrets that were committed and later deleted, the most dangerous case, since a
credential removed from the current files is still recoverable from history. Each
history finding says plainly: rotate it, deleting it from history is not enough.
Needs a local git repository with full history.

**Limits.** Entropy detection trades recall for low noise. The history scan reads
a bounded amount of diff text (and says so if it truncates on a very large repo).

## Dependencies (SCA)

**Detects.** Known-vulnerable dependencies using live [OSV](https://osv.dev)
data, including transitive packages resolved from lockfiles across PyPI, npm, Go,
Rust, Ruby, and PHP. Findings are ranked by reachability: a CVE in a package your
code never imports is marked lower priority.

**Prioritizes with exploit signals.** Each CVE finding is enriched, best-effort,
with two free feeds: **EPSS** (FIRST.org, the probability the CVE is exploited in
the wild) and the **CISA KEV** catalog (confirmed exploited in the wild). KEV
membership raises a finding's likelihood so "reachable + KEV + high EPSS" sorts to
the top, without ever changing the severity your `--fail-on` gate depends on.
Disable with `exploit_signals: false` under the `dependencies` scanner options.

**Machine-readable exploitability (VEX).** Export an OpenVEX document with
`argus scan ... -f vex`: reachable CVEs are `affected` with the fix, and a CVE in a
package your code never imports is `not_affected` with the standard
`vulnerable_code_not_in_execute_path` justification. It is the formal expression of
the reachability analysis, and pairs with an SBOM for the exposure story
enterprises increasingly request.

**Does not.** Prove exploitability. Reachability is an import-level heuristic, not
a call-graph proof, and EPSS is a probability, not a guarantee.

**Limits.** Coverage is bounded by OSV. Network access is required to refresh
advisories and exploit signals; results are cached on disk with a TTL and degrade
cleanly offline (a missing feed simply means no enrichment, never a failed scan).
Only package names, versions, and CVE ids ever leave your machine.

## SAST (pattern rules)

**Detects.** Dangerous code patterns across many languages: `shell=True`,
`os.system` on dynamic input, unsafe `yaml.load`, weak hashing, insecure
deserialization, and more, each with a CWE mapping and a concrete fix.

**Does not.** Follow data across functions and files on its own (that is the
taint tier below). Flag every dynamic call, on purpose, to stay low-noise.

**Limits.** Pattern rules are precise but shallow. Lines above a length cap
(2000 chars) are skipped to avoid pathological-regex hangs on minified files.

## Taint / data-flow (AST)

**Detects.** Untrusted input flowing into a dangerous sink across function and
file boundaries (injection, SSRF, path traversal, command execution), using
tree-sitter for Python and JavaScript/TypeScript.

**Does not.** Cover every language at this depth. Requires the `ast` extra
(`pip install "argus-appsec[ast]"`); without it, Argus falls back to the
lightweight-taint code scanner and says so.

**Limits.** Strongest for Python and JS/TS. Interprocedural analysis is bounded;
extremely dynamic code can defeat static tracing.

## Infrastructure as Code

**Detects.** Misconfiguration in Dockerfiles, Terraform, and Kubernetes
manifests: running as root, privileged containers, exposed services, weak
defaults.

**Does not.** Assess a live cluster (that is the commercial `argus-k8s` add-on).

**Limits.** Static file analysis only; it evaluates the declared config, not the
running state.

## LLM / AI application security

**Detects.** The OWASP Top 10 for LLM Apps: insecure model-output handling,
prompt injection, secrets in prompts, over-privileged agent tools, and unsafe
model loading. See [LLM / AI security](llm-security.md).

**Does not.** Test a deployed model or run prompts against it.

**Limits.** A newer domain; rules are evolving. This is the area under the most
active development.

## Custom rules

**Detects.** Whatever you define. Drop YAML rules in `.argus/rules/*.yml` or point
Argus at a rules file; no code needed. See [Writing plugins](plugins.md).

**Limits.** Custom rules loaded from a scanned repository are ignored for remote
targets by default, so an untrusted repo cannot define rules that reconfigure the
scanner.
