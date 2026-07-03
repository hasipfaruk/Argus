"""Static analysis via language-aware source patterns.

This is a lightweight, regex-based SAST pass covering the highest-value injection
and misuse classes across many languages. It is intentionally rule-driven: each
rule is a small dataclass, and adding coverage means appending a rule, not
touching the scanner. A plugin can register a more precise, AST-based scanner for
a specific language and coexist with this one.

Every rule carries the reasoning fields (why / attacker view / impact) and a CWE
and OWASP mapping so findings are actionable without an AI provider present.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass, field

from argus.core.models import (
    Confidence,
    Finding,
    Likelihood,
    Location,
    Remediation,
    Severity,
)
from argus.core.plugin import Scanner, ScannerContext, scanner


@dataclass
class Rule:
    id: str
    title: str
    pattern: re.Pattern[str]
    severity: Severity
    cwe: list[str]
    owasp: list[str]
    why: str
    attack: str
    impact: str
    fix: str
    # Restrict to files of these languages; empty means all.
    languages: set[str] = field(default_factory=set)
    confidence: Confidence = Confidence.MEDIUM
    references: list[str] = field(default_factory=list)
    # If this pattern also matches the line, the finding is suppressed. Used to
    # encode safe idioms that would otherwise be false positives (e.g. a hash
    # marked usedforsecurity=False, or a pickle round-trip of the app's own data).
    suppress: re.Pattern[str] | None = None


def _rx(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern)


# The rule set. Kept readable and grouped by weakness class.
RULES: list[Rule] = [
    # --- SQL injection ---
    Rule(
        id="python-sql-fstring",
        title="Possible SQL injection via string formatting",
        pattern=_rx(r"(?i)(execute|executemany)\s*\(\s*f?['\"].*?(select|insert|update|delete|drop)\b.*?(['\"]\s*(%|\+|\.format\()|\{[^}]*\})"),
        severity=Severity.HIGH, cwe=["CWE-89"], owasp=["A03:2021-Injection"],
        languages={"Python"}, confidence=Confidence.MEDIUM,
        why="A SQL statement is assembled with string formatting/concatenation from "
            "variables, so input can alter the query structure.",
        attack="Pass a value like `' OR '1'='1` or a stacked query in the tainted "
               "parameter to read or modify unintended rows.",
        impact="Unauthorized data access or modification, potentially full database "
               "compromise.",
        fix="Use parameterized queries / bound parameters (e.g. cursor.execute(sql, "
            "params)) and never interpolate user input into SQL text.",
    ),
    Rule(
        id="js-sql-concat",
        title="Possible SQL injection via string concatenation",
        pattern=_rx(r"(?i)(query|execute)\s*\(\s*[`'\"].*?(select|insert|update|delete).*?[`'\"]\s*\+|\$\{[^}]+\}.*?(from|where)"),
        severity=Severity.HIGH, cwe=["CWE-89"], owasp=["A03:2021-Injection"],
        languages={"JavaScript", "TypeScript"}, confidence=Confidence.MEDIUM,
        why="A SQL query is built by concatenating or interpolating variables into "
            "the query string.",
        attack="Inject SQL metacharacters through the interpolated value to change "
               "the executed statement.",
        impact="Unauthorized data access or modification.",
        fix="Use parameterized queries (placeholders + values array) or an ORM's "
            "safe query builder.",
    ),
    # --- Command injection ---
    Rule(
        id="python-shell-true",
        title="Command execution with shell=True",
        pattern=_rx(r"subprocess\.(?:call|run|Popen|check_output)\(.*shell\s*=\s*True"),
        severity=Severity.HIGH, cwe=["CWE-78"], owasp=["A03:2021-Injection"],
        languages={"Python"}, confidence=Confidence.MEDIUM,
        why="Running a subprocess through the shell lets shell metacharacters in any "
            "interpolated input execute additional commands.",
        attack="Provide input containing `; rm -rf /` or `$(...)` to run arbitrary "
               "commands as the app user.",
        impact="Remote code execution on the host.",
        fix="Pass the command as an argument list without shell=True, and validate/"
            "escape any external input.",
    ),
    Rule(
        id="python-os-system",
        title="Use of os.system with a dynamic argument",
        pattern=_rx(r"os\.system\(\s*[^)]*[+%f]"),
        severity=Severity.HIGH, cwe=["CWE-78"], owasp=["A03:2021-Injection"],
        languages={"Python"}, confidence=Confidence.MEDIUM,
        why="os.system runs its argument through the shell; building it from "
            "variables enables command injection.",
        attack="Inject shell metacharacters via the concatenated value.",
        impact="Remote code execution on the host.",
        fix="Use subprocess with an argument list, or shlex.quote inputs.",
    ),
    Rule(
        id="js-child-process-exec",
        title="Command injection via child_process.exec",
        pattern=_rx(r"child_process\.exec\(|\bexec\(\s*[`'\"].*?\$\{"),
        severity=Severity.HIGH, cwe=["CWE-78"], owasp=["A03:2021-Injection"],
        languages={"JavaScript", "TypeScript"}, confidence=Confidence.MEDIUM,
        why="exec() runs a command string through the shell; interpolated input can "
            "inject commands.",
        attack="Supply shell metacharacters in the interpolated value.",
        impact="Remote code execution on the host.",
        fix="Use execFile/spawn with an argument array instead of exec with an "
            "interpolated string.",
    ),
    # --- Code evaluation / deserialization ---
    Rule(
        id="python-eval-exec",
        title="Use of eval/exec on dynamic input",
        pattern=_rx(r"\b(eval|exec)\s*\(\s*(?!['\"]\s*\))"),
        severity=Severity.HIGH, cwe=["CWE-95"], owasp=["A03:2021-Injection"],
        languages={"Python"}, confidence=Confidence.LOW,
        why="eval/exec execute their argument as code; if any part comes from input, "
            "that is arbitrary code execution.",
        attack="Provide a Python expression/statement in the evaluated value.",
        impact="Remote code execution within the interpreter.",
        fix="Avoid eval/exec. Use ast.literal_eval for data, or an explicit dispatch "
            "table for behavior.",
    ),
    Rule(
        id="python-yaml-load",
        title="Unsafe yaml.load without SafeLoader",
        pattern=_rx(r"yaml\.load\((?![^)]*Safe)"),
        severity=Severity.HIGH, cwe=["CWE-502"], owasp=["A08:2021-Software and Data Integrity Failures"],
        languages={"Python"}, confidence=Confidence.MEDIUM,
        why="yaml.load with the default loader can construct arbitrary Python objects "
            "from the document.",
        attack="Feed a YAML payload using `!!python/object/apply` tags to execute code.",
        impact="Remote code execution.",
        fix="Use yaml.safe_load, or yaml.load(..., Loader=yaml.SafeLoader).",
    ),
    Rule(
        id="python-pickle-loads",
        title="Deserialization of untrusted data with pickle",
        pattern=_rx(r"\bpickle\.(loads|load)\("),
        severity=Severity.HIGH, cwe=["CWE-502"], owasp=["A08:2021-Software and Data Integrity Failures"],
        languages={"Python"}, confidence=Confidence.LOW,
        # A round-trip of the app's own freshly-pickled data is not untrusted input.
        suppress=_rx(r"pickle\.loads\(\s*pickle\.dumps"),
        why="pickle executes code during deserialization; loading untrusted bytes is "
            "unsafe.",
        attack="Provide a crafted pickle stream whose __reduce__ runs a command.",
        impact="Remote code execution.",
        fix="Do not unpickle untrusted data. Use JSON or a schema-validated format.",
    ),
    # --- XSS ---
    Rule(
        id="js-innerhtml",
        title="Potential DOM XSS via innerHTML",
        pattern=_rx(r"\.innerHTML\s*=\s*[^'\"];?|dangerouslySetInnerHTML"),
        severity=Severity.MEDIUM, cwe=["CWE-79"], owasp=["A03:2021-Injection"],
        languages={"JavaScript", "TypeScript"}, confidence=Confidence.LOW,
        why="Assigning untrusted data to innerHTML (or dangerouslySetInnerHTML) lets "
            "the browser execute embedded markup/script.",
        attack="Get the app to render an attacker-controlled string containing a "
               "script payload.",
        impact="Cross-site scripting: session theft and actions as the victim.",
        fix="Use textContent, framework-escaped bindings, or sanitize with a vetted "
            "library (e.g. DOMPurify) before inserting HTML.",
    ),
    # --- Weak crypto ---
    Rule(
        id="weak-hash-md5-sha1",
        title="Weak hash algorithm (MD5/SHA1)",
        pattern=_rx(r"(?i)(hashlib\.(md5|sha1)\(|MessageDigest\.getInstance\(\s*['\"](MD5|SHA-?1)|createHash\(\s*['\"](md5|sha1))"),
        severity=Severity.MEDIUM, cwe=["CWE-327"], owasp=["A02:2021-Cryptographic Failures"],
        confidence=Confidence.MEDIUM,
        # Python lets callers mark a hash as non-security (e.g. HTTP digest auth);
        # respect that intent rather than flagging it.
        suppress=_rx(r"usedforsecurity\s*=\s*False"),
        why="MD5 and SHA-1 are broken for security purposes (collisions, speed) and "
            "must not be used for integrity or password hashing.",
        attack="Exploit collision weaknesses, or brute-force fast hashes for stored "
               "passwords.",
        impact="Forged signatures/integrity checks, or recovered passwords.",
        fix="Use SHA-256+ for integrity and a slow KDF (bcrypt/scrypt/Argon2) for "
            "passwords.",
    ),
    # --- TLS verification disabled ---
    Rule(
        id="tls-verify-disabled",
        title="TLS certificate verification disabled",
        pattern=_rx(r"(?i)(verify\s*=\s*False|rejectUnauthorized\s*:\s*false|InsecureSkipVerify\s*:\s*true|CURLOPT_SSL_VERIFYPEER\s*,\s*(0|false))"),
        severity=Severity.HIGH, cwe=["CWE-295"], owasp=["A07:2021-Identification and Authentication Failures"],
        confidence=Confidence.MEDIUM,
        why="Disabling certificate verification removes protection against "
            "man-in-the-middle attacks on TLS connections.",
        attack="Intercept the connection with a forged certificate; the client "
               "accepts it.",
        impact="Interception and modification of supposedly encrypted traffic, "
               "including credentials.",
        fix="Enable certificate verification and configure a proper trust store "
            "instead of turning verification off.",
    ),
    # --- Path traversal ---
    Rule(
        id="path-traversal-join",
        title="Possible path traversal in file access",
        pattern=_rx(r"(?i)(open|readFile|sendFile|File)\(\s*[^)]*(request|req\.|params|input|argv)[^)]*\)"),
        severity=Severity.MEDIUM, cwe=["CWE-22"], owasp=["A01:2021-Broken Access Control"],
        confidence=Confidence.LOW,
        why="A filesystem path is built from request input without normalization, so "
            "`../` can escape the intended directory.",
        attack="Request a path such as `../../etc/passwd` to read files outside the "
               "intended root.",
        impact="Disclosure of sensitive files, or writing outside the intended area.",
        fix="Resolve the path and verify it stays within an allowed base directory; "
            "reject paths containing traversal sequences.",
    ),
    # --- Debug / misconfig ---
    Rule(
        id="flask-debug-true",
        title="Flask app running with debug=True",
        pattern=_rx(r"app\.run\([^)]*debug\s*=\s*True"),
        severity=Severity.MEDIUM, cwe=["CWE-489"], owasp=["A05:2021-Security Misconfiguration"],
        languages={"Python"}, confidence=Confidence.MEDIUM,
        why="Flask debug mode exposes an interactive debugger that allows arbitrary "
            "code execution if reachable.",
        attack="Reach the Werkzeug debugger and execute code through the console.",
        impact="Remote code execution and information disclosure in production.",
        fix="Never enable debug mode in production; gate it behind an environment "
            "variable defaulting to off.",
    ),
]


# Paths that are test/fixture code. Findings here are real but lower priority
# (e.g. a test deliberately using verify=False), so they are downgraded, not hidden.
_TEST_PATH = re.compile(
    r"(?i)(^|/)(tests?|testing|__tests__|fixtures?|specs?)/|"
    r"(^|/)(test_[^/]*|[^/]*_test|conftest)\.[a-z0-9]+$"
)


def _is_test_file(path: str) -> bool:
    return bool(_TEST_PATH.search(path))


@scanner
class PatternScanner(Scanner):
    name = "patterns"
    category = "sast"
    description = "Regex-based static analysis for common injection and misuse classes."

    # Only source-y files; skip data/asset languages entirely.
    _SKIP_LANGS = {"JSON", "CSS", "HTML", "YAML", None}

    def scan(self, ctx: ScannerContext) -> Iterable[Finding]:
        counter = 0
        for f in ctx.project.files():
            if f.language in self._SKIP_LANGS or f.is_probably_binary():
                continue
            in_test = _is_test_file(f.rel_path)
            lines = f.lines()
            for rule in RULES:
                if rule.languages and f.language not in rule.languages:
                    continue
                for lineno, line in enumerate(lines, start=1):
                    if len(line) > 2000:
                        continue
                    if not rule.pattern.search(line):
                        continue
                    if rule.suppress and rule.suppress.search(line):
                        continue  # a known-safe idiom on this line
                    counter += 1
                    yield self._finding(rule, counter, f.rel_path, lineno, line,
                                        in_test=in_test)

    def _finding(self, rule: Rule, index: int, path: str, lineno: int,
                 line: str, *, in_test: bool = False) -> Finding:
        severity = rule.severity
        confidence = rule.confidence
        tags = ["sast"]
        # Test/fixture code is lower risk: downgrade a level and mark it, rather
        # than hiding it. Keeps the signal without drowning real production issues.
        if in_test:
            severity = Severity(max(Severity.INFO, rule.severity - 1))
            confidence = Confidence.LOW
            tags.append("test-context")
        return Finding(
            id=f"{self.name}:{rule.id}:{index}",
            rule_id=f"{self.name}.{rule.id}",
            scanner=self.name,
            title=rule.title,
            description=rule.why,
            location=Location(path=path, start_line=lineno, snippet=line.strip()[:240]),
            severity=severity,
            confidence=confidence,
            likelihood=Likelihood.POSSIBLE,
            cwe=rule.cwe,
            owasp=rule.owasp,
            why_vulnerable=rule.why,
            attacker_perspective=rule.attack,
            business_impact=rule.impact,
            remediation=Remediation(
                summary=rule.fix,
                guidance=rule.fix,
                references=rule.references or [
                    f"https://cwe.mitre.org/data/definitions/{rule.cwe[0].split('-')[1]}.html"
                    if rule.cwe else "",
                ],
            ),
            tags=tags,
        )
