"""The project model: a normalized view of the target Argus is analyzing.

A ``Project`` is produced by loading a local directory (or a checked-out remote
repo) and is then enriched by the :mod:`argus.analysis.repository` analyzer with
detected languages, frameworks, and architecture facts. Scanners consume the
project rather than touching the filesystem directly, which keeps them testable.
"""

from __future__ import annotations

import fnmatch
import os
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# Directories that are noise for security analysis. Skipped during file walks.
DEFAULT_IGNORES: tuple[str, ...] = (
    ".git", ".hg", ".svn", "node_modules", "vendor", "dist", "build",
    ".venv", "venv", "env", "__pycache__", ".mypy_cache", ".pytest_cache",
    ".ruff_cache", ".tox", ".next", ".nuxt", "target", ".gradle", ".idea",
    ".argus", "coverage", "htmlcov", ".terraform",
)

# Files above this size are treated as assets/blobs and not read as source.
MAX_TEXT_BYTES = 2_000_000


@dataclass
class FileRef:
    """A single project file. Content is read lazily and cached per instance."""

    path: Path            # absolute path on disk
    rel_path: str         # POSIX-style path relative to project root
    size: int
    language: str | None = None

    _text: str | None = field(default=None, repr=False, compare=False)
    _read_attempted: bool = field(default=False, repr=False, compare=False)

    @property
    def name(self) -> str:
        return self.path.name

    @property
    def suffix(self) -> str:
        return self.path.suffix.lower()

    def is_probably_binary(self) -> bool:
        if self.size > MAX_TEXT_BYTES:
            return True
        try:
            chunk = self.path.read_bytes()[:2048]
        except OSError:
            return True
        return b"\x00" in chunk

    def text(self) -> str:
        """Return file contents as text, or "" if unreadable/binary. Cached."""
        if self._read_attempted:
            return self._text or ""
        self._read_attempted = True
        if self.is_probably_binary():
            self._text = ""
            return ""
        try:
            self._text = self.path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            self._text = ""
        return self._text or ""

    def lines(self) -> list[str]:
        return self.text().splitlines()


@dataclass
class Project:
    """A normalized, analyzable view of the scan target."""

    root: Path
    name: str
    origin: str = "local"           # local | github | gitlab | bitbucket | url
    origin_url: str | None = None

    # Populated by the repository analyzer.
    languages: dict[str, int] = field(default_factory=dict)  # language -> file count
    frameworks: list[str] = field(default_factory=list)
    architecture: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)

    extra_ignores: tuple[str, ...] = ()

    # Materialized file list, computed on first access. Not part of equality.
    _files_cache: tuple[FileRef, ...] | None = field(
        default=None, repr=False, compare=False)

    @classmethod
    def from_path(cls, path: str | os.PathLike[str], **kwargs: Any) -> Project:
        root = Path(path).resolve()
        if not root.exists():
            raise FileNotFoundError(f"Project path does not exist: {root}")
        if root.is_file():
            root = root.parent
        return cls(root=root, name=kwargs.pop("name", None) or root.name, **kwargs)

    def _ignored(self) -> set[str]:
        return set(DEFAULT_IGNORES)

    def _excluded(self, rel_path: str) -> bool:
        """True if a relative path matches any configured exclude glob.

        ``extra_ignores`` (from ``exclude_paths`` in config) are treated as globs
        against the POSIX relative path, e.g. ``examples/**``, ``*.min.js``,
        ``src/argus/scanners/llm.py``, as well as the bare basename, so both a
        directory subtree and a single file can be excluded.
        """
        name = rel_path.rsplit("/", 1)[-1]
        for pat in self.extra_ignores:
            if fnmatch.fnmatch(rel_path, pat) or fnmatch.fnmatch(name, pat):
                return True
            # `dir/**` should also match the directory prefix `dir/...`.
            if pat.endswith("/**") and (rel_path == pat[:-3]
                                        or rel_path.startswith(pat[:-2])):
                return True
        return False

    def iter_files(self) -> Iterator[FileRef]:
        """Walk the project, skipping ignored directories and unreadable files.

        Directories and files are traversed in sorted order so that the file list,
        and therefore finding ids and report ordering, is deterministic and
        reproducible across machines and filesystems.
        """
        ignores = self._ignored()
        for dirpath, dirnames, filenames in os.walk(self.root):
            base_rel = Path(dirpath).relative_to(self.root).as_posix()
            # Sorting dirnames in place also fixes os.walk's traversal order.
            # Prune by built-in basename ignores and by exclude-glob (which lets
            # us skip descending into an excluded subtree entirely).
            dirnames[:] = sorted(
                d for d in dirnames
                if d not in ignores
                and not self._excluded(f"{base_rel}/{d}".lstrip("/"))
            )
            for filename in sorted(filenames):
                abs_path = Path(dirpath) / filename
                rel = abs_path.relative_to(self.root).as_posix()
                if self._excluded(rel):
                    continue
                try:
                    size = abs_path.stat().st_size
                except OSError:
                    continue
                yield FileRef(path=abs_path, rel_path=rel, size=size)

    def files(self) -> tuple[FileRef, ...]:
        """All project files, materialized and cached on first access."""
        if self._files_cache is None:
            self._files_cache = tuple(self.iter_files())
        return self._files_cache

    def files_matching(self, *patterns: str) -> list[FileRef]:
        """Return files whose relative path matches any glob pattern."""
        out: list[FileRef] = []
        for f in self.files():
            if any(fnmatch.fnmatch(f.rel_path, p) or fnmatch.fnmatch(f.name, p)
                   for p in patterns):
                out.append(f)
        return out

    def find_file(self, name: str) -> FileRef | None:
        for f in self.files():
            if f.name == name or f.rel_path == name:
                return f
        return None

    def summary(self) -> dict[str, Any]:
        """A compact, serializable snapshot for reports and the dashboard."""
        return {
            "name": self.name,
            "root": str(self.root),
            "origin": self.origin,
            "origin_url": self.origin_url,
            "file_count": len(self.files()),
            "languages": dict(sorted(self.languages.items(),
                                     key=lambda kv: kv[1], reverse=True)),
            "frameworks": self.frameworks,
            "architecture": self.architecture,
        }
