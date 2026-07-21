# Argus — detection-accuracy fixes

This round focused on the confirmed false-positive / under-rating defects that
remained after the Phase 0 hardening (the FileRef race, `git add -A` guard,
untrusted-rule trust gate, torch.load/yaml.load rewrites, and the cloud ingest
bridge were already fixed in this tree and verified against the code).

All changes are covered by new regression tests in
`tests/test_detection_fixes.py`. Full suite: **297 passed, 2 skipped** (skips are
optional TypeScript / sqlmodel extras, unrelated to these changes).

## Fixed

1. **`os.system` false positives on constant commands** —
   `src/argus/scanners/patterns.py`
   The `[+%f]` character class matched any literal `f`, so `os.system("df -h")`
   and `os.system("find .")` fired as command-injection. Rewritten to match only
   genuine dynamic arguments: string concatenation (`+`), `%`-format, and an
   f-string prefix anchored to its quote. True positives (concat / f-string /
   `%`-format) are retained.

2. **`--config <typo>` silently ignored** —
   `src/argus/core/config.py`, `src/argus/cli/main.py`
   An explicit config path that did not exist fell through to built-in defaults,
   silently disabling `fail_on` gating in CI. `Config.load` now raises
   `FileNotFoundError` for a missing explicit path (discovery mode is unchanged),
   and the scan command surfaces it as a clean error with exit code 2 instead of
   a traceback.

3. **JS eval/Function sink over-match** —
   `src/argus/scanners/ast_js.py`
   The sink regex `(^|\.)?(eval|Function)$` had an *optional* prefix, so it
   matched names merely ending in the word: `retrieval`, `myFunction`,
   `medieval`. The prefix is now required — the call must be the whole name or a
   real member access (`.eval`, `.Function`).

4. **`toString` wrongly treated as a JS sanitizer** —
   `src/argus/scanners/ast_js.py`
   `toString` was in `_SANITIZERS`, so `userInput.toString()` incorrectly cleared
   taint even though it does nothing against XSS/injection. Removed; the real
   sanitizers (encodeURIComponent, DOMPurify-style, etc.) are untouched.

5. **CVSS vector strings under-rated to MEDIUM** —
   `src/argus/scanners/osv.py`
   OSV/GHSA advisories carry a CVSS *vector* (`CVSS:3.1/AV:N/AC:L/...`), not a
   bare number, so `float()` always failed and every vector-only advisory
   defaulted to MEDIUM — under-rating real 9.8s that teams gate CI on. Added a
   correct CVSS v3.x base-score parser (validated against published reference
   scores: 9.8, 10.0, 1.8, 5.4, 6.1). Bare numeric scores still work.

6. **Secret verification: 403 mis-classified as INVALID** —
   `src/argus/scanners/secret_verify.py`
   403 was bundled with 401 as "invalid," but 403 is commonly rate-limiting
   (GitHub) or a valid-but-forbidden token — it does not prove the secret is
   dead. Only 401 now maps to INVALID; 403 (and anything else) falls through to
   UNKNOWN, so a live secret is never downgraded on ambiguous evidence.

## Still open (flagged, not yet changed)

* **Dependency version-collapse** (`src/argus/scanners/dependencies.py`) — the
  lockfile parsers return `dict[str, str]` keyed by package name, so a package
  pinned at two versions in the tree loses one before it reaches OSV. Fixing this
  correctly means allowing multiple versions per package through the scanner,
  which is a structural change rather than a one-line patch — left for a
  dedicated pass to avoid rushing a cascading refactor.
