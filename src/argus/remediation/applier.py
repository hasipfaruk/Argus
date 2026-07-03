"""Apply deterministic fixes to real files.

The patch agent proposes fixes against a stored *snippet* (which is stripped and
truncated). To actually change a file we must operate on its real content, so the
applier re-reads each file and rewrites the exact offending line — preserving
indentation and trailing content automatically, because the rewrite runs on the
real line.

Only findings whose rewrite verifies (the detection no longer fires on the fixed
line) are applied by default; unverified rewrites can be opted in. The applier
writes each file at most once, even when it fixes several findings in it.
"""

from __future__ import annotations

import difflib
from dataclasses import dataclass, field
from pathlib import Path

from argus.core.models import Finding
from argus.core.project import Project
from argus.remediation.rewrites import fix_line, verify_line_fixed


@dataclass
class AppliedFix:
    """One line-level change the applier made (or would make, when dry-run)."""

    path: str            # project-relative path
    rule_id: str
    line: int            # 1-indexed
    before: str
    after: str
    finding_id: str
    verified: bool

    def unified_diff(self) -> str:
        return "".join(
            difflib.unified_diff(
                [self.before + "\n"], [self.after + "\n"],
                fromfile=f"a/{self.path}", tofile=f"b/{self.path}",
                lineterm="\n",
            )
        )


@dataclass
class ApplyReport:
    fixes: list[AppliedFix] = field(default_factory=list)
    changed_files: list[str] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)  # human-readable reasons
    dry_run: bool = False

    @property
    def any_changes(self) -> bool:
        return bool(self.fixes)

    def summary(self) -> str:
        verb = "would fix" if self.dry_run else "fixed"
        return (f"{verb} {len(self.fixes)} finding(s) across "
                f"{len(self.changed_files)} file(s)")


def apply_fixes(
    project: Project,
    findings: list[Finding],
    *,
    include_unverified: bool = False,
    dry_run: bool = False,
) -> ApplyReport:
    """Apply deterministic fixes for the given findings to the project's files."""
    report = ApplyReport(dry_run=dry_run)

    # Group findings that have a line by file so each file is read/written once.
    # Whether a rule is actually fixable is decided per-line below via fix_line().
    by_file: dict[str, list[Finding]] = {}
    for f in findings:
        if f.location.start_line is None:
            continue
        by_file.setdefault(f.location.path, []).append(f)

    for rel_path, file_findings in by_file.items():
        abs_path = project.root / rel_path
        if not abs_path.exists():
            report.skipped.append(f"{rel_path}: file not found")
            continue
        try:
            text = abs_path.read_text(encoding="utf-8")
        except OSError as exc:
            report.skipped.append(f"{rel_path}: unreadable ({exc})")
            continue

        newline = "\r\n" if "\r\n" in text else "\n"
        lines = text.splitlines()
        file_changed = False

        # Apply the most severe / lowest line first is irrelevant since each fix is
        # confined to its own line; process in line order for determinism.
        for finding in sorted(file_findings, key=lambda f: f.location.start_line or 0):
            idx = (finding.location.start_line or 0) - 1
            if idx < 0 or idx >= len(lines):
                report.skipped.append(
                    f"{rel_path}:{finding.location.start_line}: line out of range")
                continue
            original = lines[idx]
            fixed = fix_line(finding.rule_id, original)
            if fixed is None or fixed == original:
                report.skipped.append(
                    f"{rel_path}:{finding.location.start_line}: "
                    f"no deterministic fix for {finding.rule_id}")
                continue
            verified = verify_line_fixed(finding.rule_id, fixed)
            if not verified and not include_unverified:
                report.skipped.append(
                    f"{rel_path}:{finding.location.start_line}: "
                    f"fix for {finding.rule_id} did not verify (use --include-unverified)")
                continue

            lines[idx] = fixed
            file_changed = True
            report.fixes.append(AppliedFix(
                path=rel_path, rule_id=finding.rule_id,
                line=finding.location.start_line or 0,
                before=original, after=fixed,
                finding_id=finding.id, verified=verified,
            ))

        if file_changed:
            report.changed_files.append(rel_path)
            if not dry_run:
                new_text = newline.join(lines)
                if text.endswith(("\n", "\r\n")):
                    new_text += newline
                _write(abs_path, new_text)

    return report


def _write(path: Path, text: str) -> None:
    path.write_text(text, encoding="utf-8", newline="")
