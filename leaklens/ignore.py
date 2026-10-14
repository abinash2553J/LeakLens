"""Simple gitignore-style path filtering and inline suppression helpers."""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass
from pathlib import Path


DEFAULT_EXCLUDED_DIRS = {
    ".git", ".hg", ".svn", ".venv", "venv", "env", "node_modules",
    "dist", "build", "coverage", "__pycache__", ".mypy_cache", ".pytest_cache",
    ".tox", ".next", ".nuxt", "vendor",
}


@dataclass(frozen=True, slots=True)
class IgnorePattern:
    pattern: str
    negated: bool = False
    directory_only: bool = False
    anchored: bool = False


class IgnoreMatcher:
    """Match relative POSIX paths against root-level ignore files and CLI excludes."""

    def __init__(self, root: Path, *, load_files: bool = True, extra_patterns: list[str] | None = None) -> None:
        self.root = root.resolve()
        self.patterns: list[IgnorePattern] = []
        if load_files:
            for filename in (".gitignore", ".leaklensignore"):
                ignore_file = self.root / filename
                try:
                    lines = ignore_file.read_text(encoding="utf-8", errors="replace").splitlines()
                except OSError:
                    continue
                self.patterns.extend(self._parse(lines))
        self.patterns.extend(self._parse(extra_patterns or []))

    @staticmethod
    def _parse(lines: list[str]) -> list[IgnorePattern]:
        result: list[IgnorePattern] = []
        for raw_line in lines:
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            negated = line.startswith("!")
            if negated:
                line = line[1:]
            if not line:
                continue
            directory_only = line.endswith("/")
            line = line.rstrip("/")
            anchored = line.startswith("/")
            line = line.lstrip("/")
            if line:
                result.append(IgnorePattern(line, negated, directory_only, anchored))
        return result

    @staticmethod
    def _matches(pattern: IgnorePattern, rel_path: str, is_dir: bool) -> bool:
        if pattern.directory_only and not is_dir:
            # A directory-only pattern can still match a file nested under that directory.
            parts = rel_path.split("/")
            return any(IgnoreMatcher._matches(pattern, "/".join(parts[:i]), True) for i in range(1, len(parts)))

        path = rel_path.strip("/")
        raw = pattern.pattern
        if pattern.anchored or "/" in raw:
            return fnmatch.fnmatchcase(path, raw) or path.startswith(raw + "/")
        return any(fnmatch.fnmatchcase(part, raw) for part in path.split("/"))

    def is_ignored(self, rel_path: str, *, is_dir: bool = False) -> bool:
        path = rel_path.replace("\\", "/").strip("/")
        if not path:
            return False
        if any(part in DEFAULT_EXCLUDED_DIRS for part in path.split("/")):
            return True
        ignored = False
        for pattern in self.patterns:
            if self._matches(pattern, path, is_dir):
                ignored = not pattern.negated
        return ignored


def inline_suppresses(line: str, rule_id: str) -> bool:
    """Support '# leaklens:ignore' or '# leaklens:ignore LL001,LL012'."""
    marker = "leaklens:ignore"
    lower = line.lower()
    index = lower.find(marker)
    if index < 0:
        return False
    suffix = line[index + len(marker):].strip()
    if not suffix or suffix.startswith(("#", "--", "//", "*/")):
        return True
    tokens = {token.strip(" ,;[](){}") for token in suffix.upper().replace(",", " ").split()}
    return not tokens or rule_id.upper() in tokens or "ALL" in tokens
