"""AST-based taint analysis for Python (the precise SAST tier).

The regex ``patterns`` scanner is fast but line-anchored: it can follow a value
one hop from an input source into a sink, but not through a chain of assignments.
This scanner parses Python with tree-sitter and tracks tainted values through
multiple hops, so it catches injection that the regex tier misses:

    name  = request.args.get("user")   # source
    safe  = name                       # hop 1
    value = safe                       # hop 2
    cursor.execute("SELECT ... " + value)   # sink  -> reported here

It is **optional**: tree-sitter is an extra (``pip install "argus-appsec[ast]"``).
Without it the scanner reports as not-applicable and Argus falls back to the
regex tier — nothing breaks. Analysis is intra-file and per-function-scope, which
keeps it fast and low-noise; whole-program and cross-file flow remain future work.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from functools import lru_cache

from argus.core.models import (
    Confidence,
    Finding,
    Likelihood,
    Location,
    Remediation,
    Severity,
)
from argus.core.plugin import Scanner, ScannerContext, scanner


@lru_cache(maxsize=1)
def _load_parser():
    """Return a tree-sitter (Parser, Language) for Python, or None if unavailable."""
    try:
        import tree_sitter_python as tspython
        from tree_sitter import Language, Parser
    except ImportError:
        return None
    lang = Language(tspython.language())
    try:
        return Parser(lang)                      # tree-sitter >= 0.22
    except TypeError:                            # pragma: no cover - old API
        parser = Parser()
        parser.set_language(lang)
        return parser


def is_available() -> bool:
    return _load_parser() is not None


# Untrusted-input sources: an expression mentioning one of these is tainted.
_SOURCE_RE = re.compile(
    r"\brequest\.(args|form|values|json|data|files|cookies|headers|query_params|GET|POST)\b"
    r"|\binput\s*\("
    r"|\bsys\.argv\b"
    r"|\bflask\.request\b"
    r"|\bos\.environ\b"
)
# Function-name last components that neutralize taint (numeric coercion, quoting,
# path basename, HTML escaping). Keyed on the final identifier of the call target.
_SANITIZERS = {
    "int", "float", "bool", "secure_filename", "basename", "quote", "escape",
    "safe_join", "quote_plus", "shlex",
}


@dataclass
class Sink:
    id: str
    fn: re.Pattern[str]     # matches the call's function text (e.g. "cursor.execute")
    cwe: list[str]
    owasp: list[str]
    title: str
    severity: Severity
    why: str
    attack: str
    impact: str
    fix: str
    references: list[str] = field(default_factory=list)


SINKS: list[Sink] = [
    Sink(
        id="ast-sql-injection",
        fn=re.compile(r"(^|\.)(execute|executemany|executescript)$"),
        cwe=["CWE-89"], owasp=["A03:2021-Injection"], severity=Severity.HIGH,
        title="SQL injection (tainted value reaches a database query)",
        why="A value derived from untrusted input flows into a database query "
            "without parameterization, so input can change the query's structure.",
        attack="Supply `' OR '1'='1` (or a UNION/stacked query) in the tainted "
               "parameter to read or modify unintended rows.",
        impact="Unauthorized data access or modification, up to full database "
               "compromise.",
        fix="Use parameterized queries / bound parameters and never build SQL from "
            "input, even across intermediate variables.",
    ),
    Sink(
        id="ast-command-injection",
        fn=re.compile(r"(^|\.)system$|(^|\.)popen$|^subprocess\.\w+$"),
        cwe=["CWE-78"], owasp=["A03:2021-Injection"], severity=Severity.HIGH,
        title="OS command injection (tainted value reaches a shell command)",
        why="A value derived from untrusted input flows into a command executed by "
            "the OS/shell, so shell metacharacters can inject additional commands.",
        attack="Inject `; rm -rf` or `$(...)` through the tainted parameter to run "
               "arbitrary commands.",
        impact="Remote code execution on the host.",
        fix="Pass arguments as a list without a shell, and validate/quote input.",
    ),
    Sink(
        id="ast-path-traversal",
        fn=re.compile(r"(^|\.)open$|send_file$|send_from_directory$"),
        cwe=["CWE-22"], owasp=["A01:2021-Broken Access Control"], severity=Severity.MEDIUM,
        title="Path traversal (tainted value reaches a file operation)",
        why="A filesystem path derived from untrusted input reaches a file operation "
            "without normalization, so `../` can escape the intended directory.",
        attack="Request a path such as `../../etc/passwd` to read or write files "
               "outside the intended location.",
        impact="Disclosure of sensitive files, or writing outside the intended area.",
        fix="Resolve the path and confirm it stays within an allowed base directory "
            "(e.g. os.path.realpath + prefix check, or secure_filename).",
    ),
    Sink(
        id="ast-code-injection",
        fn=re.compile(r"^(eval|exec)$"),
        cwe=["CWE-95"], owasp=["A03:2021-Injection"], severity=Severity.HIGH,
        title="Code injection (tainted value reaches eval/exec)",
        why="Untrusted input flows into eval/exec, which executes it as code.",
        attack="Provide a Python expression/statement in the tainted value.",
        impact="Remote code execution within the interpreter.",
        fix="Never eval/exec untrusted input; use a safe parser or explicit dispatch.",
    ),
]

# Test/fixture paths — findings there are downgraded, matching the regex scanner.
from argus.scanners.patterns import _is_test_file  # noqa: E402  (shared helper)


@scanner
class ASTPythonScanner(Scanner):
    name = "ast-python"
    category = "sast"
    description = ("Data-flow (taint) analysis for Python via tree-sitter; catches "
                   "multi-hop injection the regex tier misses. Needs the [ast] extra.")

    def applies_to(self, project) -> bool:
        return is_available() and bool(project.files_matching("*.py"))

    def scan(self, ctx: ScannerContext) -> Iterable[Finding]:
        parser = _load_parser()
        if parser is None:
            return
        for f in ctx.project.files():
            if f.language != "Python" or f.is_probably_binary():
                continue
            src = f.text().encode("utf-8", "replace")
            if not src.strip():
                continue
            try:
                tree = parser.parse(src)
            except Exception:  # never let one unparseable file sink the scan
                continue
            analyzer = _Analyzer(src, f.rel_path, _is_test_file(f.rel_path))
            yield from analyzer.run(tree.root_node)


class _Analyzer:
    """Intra-file, per-function-scope taint walk over a Python AST."""

    def __init__(self, src: bytes, path: str, in_test: bool) -> None:
        self._src = src
        self._path = path
        self._in_test = in_test
        self._seen: set[tuple[str, int]] = set()  # (sink_id, line) de-dup within file

    def run(self, root) -> Iterable[Finding]:
        yield from self._walk(root, set())

    # --- traversal ----------------------------------------------------------
    def _walk(self, node, tainted: set[str]) -> Iterable[Finding]:
        t = node.type
        if t == "function_definition":
            body = node.child_by_field_name("body")
            if body is not None:
                yield from self._walk(body, set())   # fresh scope per function
            return
        if t in ("assignment", "augmented_assignment"):
            self._apply_assignment(node, tainted, augmented=(t == "augmented_assignment"))
            right = node.child_by_field_name("right")
            if right is not None:
                yield from self._walk(right, tainted)  # catch sinks on the RHS too
            return
        if t == "call":
            finding = self._check_sink(node, tainted)
            if finding is not None:
                yield finding
        for child in node.children:
            yield from self._walk(child, tainted)

    # --- taint rules --------------------------------------------------------
    def _apply_assignment(self, node, tainted: set[str], *, augmented: bool) -> None:
        left = node.child_by_field_name("left")
        right = node.child_by_field_name("right")
        if left is None or right is None:
            return
        names = self._target_names(left)
        if self._tainted(right, tainted):
            tainted.update(names)
        elif not augmented:
            tainted.difference_update(names)  # reassigned to a clean value

    def _tainted(self, node, tainted: set[str]) -> bool:
        if node.type == "call" and self._is_sanitizer(node):
            return False
        text = self._text(node)
        if _SOURCE_RE.search(text):
            return True
        if node.type == "identifier" and text in tainted:
            return True
        return any(self._tainted(c, tainted) for c in node.children)

    def _check_sink(self, call, tainted: set[str]) -> Finding | None:
        fn_node = call.child_by_field_name("function")
        if fn_node is None:
            return None
        fn_text = self._text(fn_node)
        sink = next((s for s in SINKS if s.fn.search(fn_text)), None)
        if sink is None:
            return None
        args = call.child_by_field_name("arguments")
        if args is None:
            return None
        if not any(self._tainted(a, tainted) for a in args.named_children):
            return None
        line = call.start_point[0] + 1
        key = (sink.id, line)
        if key in self._seen:
            return None
        self._seen.add(key)
        return self._finding(sink, line, call)

    # --- helpers ------------------------------------------------------------
    def _is_sanitizer(self, call) -> bool:
        fn = call.child_by_field_name("function")
        if fn is None:
            return False
        last = self._text(fn).rsplit(".", 1)[-1]
        return last in _SANITIZERS

    def _target_names(self, left) -> set[str]:
        """Identifier names assigned by an LHS (handles simple and tuple targets)."""
        names: set[str] = set()
        if left.type == "identifier":
            names.add(self._text(left))
        else:
            for c in left.children:
                names |= self._target_names(c)
        return names

    def _text(self, node) -> str:
        return self._src[node.start_byte:node.end_byte].decode("utf-8", "ignore")

    def _line_text(self, line: int) -> str:
        try:
            return self._src.decode("utf-8", "ignore").splitlines()[line - 1].strip()
        except IndexError:  # pragma: no cover
            return ""

    def _finding(self, sink: Sink, line: int, call) -> Finding:
        severity = sink.severity
        confidence = Confidence.HIGH  # backed by real data flow, not a pattern
        tags = ["sast", "ast", "taint"]
        if self._in_test:
            severity = Severity(max(Severity.INFO, sink.severity - 1))
            confidence = Confidence.LOW
            tags.append("test-context")
        return Finding(
            id=f"{ASTPythonScanner.name}:{sink.id}:{self._path}:{line}",
            rule_id=f"{ASTPythonScanner.name}.{sink.id}",
            scanner=ASTPythonScanner.name,
            title=sink.title,
            description=sink.why,
            location=Location(path=self._path, start_line=line,
                              snippet=self._line_text(line)[:240]),
            severity=severity, confidence=confidence, likelihood=Likelihood.LIKELY,
            cwe=sink.cwe, owasp=sink.owasp,
            why_vulnerable=sink.why,
            attacker_perspective=sink.attack,
            business_impact=sink.impact,
            remediation=Remediation(
                summary=sink.fix, guidance=sink.fix,
                references=sink.references or [
                    f"https://cwe.mitre.org/data/definitions/{sink.cwe[0].split('-')[1]}.html"
                ],
            ),
            tags=tags,
            metadata={"analysis": "taint-dataflow"},
        )
