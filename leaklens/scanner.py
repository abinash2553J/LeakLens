"""Local file discovery and secret detection engine."""

from __future__ import annotations

import hashlib
import math
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from .ignore import IgnoreMatcher, inline_suppresses
from .models import Finding, ScanResult
from .rules import ALL_RULES, ENTROPY_RULE, RULES, Rule


PLACEHOLDER_PREFIXES = (
    "your_", "your-", "replace_", "replace-", "change_me", "change-me",
    "changeme", "placeholder", "example_", "example-", "dummy_", "dummy-",
    "insert_", "insert-", "put_your", "redacted", "todo_", "todo-",
)
PLACEHOLDER_VALUES = {
    "changeme", "change-me", "change_me", "password", "yourpassword",
    "your-password", "your_api_key", "your-api-key", "api_key_here",
    "api-key-here", "secret_here", "secret-here", "placeholder", "example",
    "examplekey", "sample", "dummy", "redacted", "null", "none", "undefined",
    "xxxxxxxx", "xxxxxxxxxx", "1234567890", "abcdefabcdefabcdef",
}

STRING_LITERALS = re.compile(r"(?P<quote>['\"])(?P<value>.*?)(?P=quote)")
SECRET_WORDS = re.compile(r"api|key|token|secret|password|passwd|credential|auth|private", re.I)


@dataclass(frozen=True, slots=True)
class ScanConfig:
    root: Path
    paths: tuple[Path, ...] = ()
    max_file_size: int = 1_000_000
    load_ignore_files: bool = True
    extra_excludes: tuple[str, ...] = ()
    include_entropy: bool = True


@dataclass(frozen=True, slots=True)
class _Detection:
    rule: Rule
    start: int
    end: int
    value: str


class SecretScanner:
    """Scan local text files for likely secrets without transmitting source code."""

    def __init__(self, config: ScanConfig) -> None:
        self.config = config
        self.root = config.root.resolve()
        self.matcher = IgnoreMatcher(
            self.root,
            load_files=config.load_ignore_files,
            extra_patterns=list(config.extra_excludes),
        )

    def scan(self) -> ScanResult:
        result = ScanResult(root=str(self.root))
        for file_path in self._iter_files():
            try:
                findings, skipped = self._scan_file(file_path)
            except OSError as exc:
                result.errors.append(f"{self._display_path(file_path)}: {exc}")
                continue
            if skipped:
                result.skipped_files += 1
                continue
            result.scanned_files += 1
            result.findings.extend(findings)
        result.findings.sort(key=lambda item: (item.path.casefold(), item.line, item.column, item.rule_id))
        return result

    def _iter_files(self) -> Iterable[Path]:
        requested = self.config.paths or (Path("."),)
        seen: set[Path] = set()
        for requested_path in requested:
            candidate = requested_path if requested_path.is_absolute() else self.root / requested_path
            if candidate.is_symlink():
                continue
            try:
                candidate = candidate.resolve(strict=True)
            except OSError:
                # Surface inaccessible paths through the normal error channel.
                yield candidate
                continue
            if candidate.is_symlink():
                continue
            if candidate.is_file():
                rel = self._relative_path(candidate)
                if self.matcher.is_ignored(rel, is_dir=False):
                    continue
                if candidate not in seen:
                    seen.add(candidate)
                    yield candidate
                continue
            if not candidate.is_dir():
                yield candidate
                continue
            for current, dirnames, filenames in os.walk(candidate, topdown=True, followlinks=False):
                current_path = Path(current)
                kept_dirs: list[str] = []
                for dirname in sorted(dirnames):
                    child = current_path / dirname
                    if child.is_symlink():
                        continue
                    rel = self._relative_path(child)
                    if self.matcher.is_ignored(rel, is_dir=True):
                        continue
                    kept_dirs.append(dirname)
                dirnames[:] = kept_dirs
                for filename in sorted(filenames):
                    child = current_path / filename
                    if child.is_symlink():
                        continue
                    rel = self._relative_path(child)
                    if self.matcher.is_ignored(rel, is_dir=False):
                        continue
                    if child not in seen:
                        seen.add(child)
                        yield child

    def _scan_file(self, path: Path) -> tuple[list[Finding], bool]:
        try:
            stat = path.stat()
        except OSError:
            raise
        if stat.st_size > self.config.max_file_size:
            return [], True
        with path.open("rb") as handle:
            raw = handle.read(self.config.max_file_size + 1)
        if len(raw) > self.config.max_file_size:
            return [], True
        if b"\x00" in raw[:8192]:
            return [], True
        text = raw.decode("utf-8", errors="replace")
        findings: list[Finding] = []
        relative_path = self._display_path(path)
        for line_number, line in enumerate(text.splitlines(), start=1):
            detections = self._detect_line(line, allow_bare=self._supports_bare_values(path))
            if not detections:
                continue
            unsuppressed = [
                detection for detection in detections
                if not inline_suppresses(line, detection.rule.rule_id)
            ]
            chosen = self._remove_overlaps(unsuppressed)
            if not chosen:
                continue
            redacted = self._redact(line, [(item.start, item.end) for item in chosen])
            for detection in chosen:
                secret_digest = hashlib.sha256(detection.value.encode("utf-8", errors="replace")).hexdigest()
                fingerprint = hashlib.sha256(
                    f"{relative_path}:{detection.rule.rule_id}:{secret_digest}".encode("utf-8")
                ).hexdigest()
                findings.append(Finding(
                    rule_id=detection.rule.rule_id,
                    rule_name=detection.rule.name,
                    severity=detection.rule.severity,
                    message=detection.rule.message,
                    path=relative_path,
                    line=line_number,
                    column=detection.start + 1,
                    snippet=redacted.strip()[:300],
                    fingerprint=fingerprint,
                    recommendation=detection.rule.recommendation,
                ))
        return findings, False

    @staticmethod
    def _supports_bare_values(path: Path) -> bool:
        """Return whether unquoted secret values are valid in this file format."""
        if path.name.startswith(".env") or path.name == "Dockerfile":
            return True
        return path.suffix.lower() in {
            ".ini", ".cfg", ".conf", ".properties", ".yaml", ".yml", ".sh", ".bash", ".zsh",
        }

    def _detect_line(self, line: str, *, allow_bare: bool = False) -> list[_Detection]:
        detections: list[_Detection] = []
        for rule in RULES:
            for match in rule.pattern.finditer(line):
                group = rule.secret_group
                span: tuple[int, int] | None = None
                value = ""
                if group == "quoted":
                    if match.groupdict().get("quoted") is not None:
                        span = match.span("quoted")
                        value = match.group("quoted")
                    elif match.groupdict().get("bare") is not None and allow_bare:
                        span = match.span("bare")
                        value = match.group("bare")
                elif isinstance(group, str):
                    try:
                        value = match.group(group) or ""
                        span = match.span(group) if value else None
                    except IndexError:
                        span = None
                elif isinstance(group, int):
                    value = match.group(group) or ""
                    span = match.span(group) if value else None
                if span is None or span[0] == span[1] or self._is_placeholder(value):
                    continue
                if rule.rule_id == "LL012":
                    key = match.group("key").strip("'\"").lower()
                    normalized_key = key.translate(str.maketrans("", "", "_.-"))
                    sensitive_suffixes = (
                        "apikey", "secretkey", "accesskey", "privatekey", "clientsecret",
                        "authtoken", "accesstoken", "refreshtoken", "token", "password",
                        "passwd", "secret", "credential", "credentials", "dburl", "databaseurl",
                    )
                    if not normalized_key.endswith(sensitive_suffixes):
                        continue
                detections.append(_Detection(rule, span[0], span[1], value))

        if self.config.include_entropy:
            for match in ENTROPY_RULE.pattern.finditer(line):
                value = match.group("secret")
                if self._is_placeholder(value) or not self._looks_high_entropy(value):
                    continue
                if value.islower() or value.isupper():
                    continue
                # Do not treat plain hexadecimal checksums as credentials unless the line is secret-related.
                if re.fullmatch(r"[0-9a-fA-F]{32,}", value) and not SECRET_WORDS.search(line):
                    continue
                detections.append(_Detection(ENTROPY_RULE, *match.span("secret"), value))

        # Specific provider patterns win over generic assignments and entropy heuristics.
        detections.sort(key=lambda item: (-item.rule.priority, item.start, -(item.end - item.start)))
        return detections

    @staticmethod
    def _is_placeholder(value: str) -> bool:
        normalized = value.strip().strip("`${}[]<> ").lower()
        if not normalized:
            return True
        if normalized in PLACEHOLDER_VALUES:
            return True
        if normalized.startswith(PLACEHOLDER_PREFIXES):
            return True
        if any(marker in normalized for marker in (
            "process.env", "os.environ", "environ.get", "environ[", "getenv", "env(",
            "secretref", "<your", "<secret", "${", "{{",
        )):
            return True
        return False

    @staticmethod
    def _looks_high_entropy(value: str) -> bool:
        if len(value) < 32:
            return False
        classes = sum((
            any(char.islower() for char in value),
            any(char.isupper() for char in value),
            any(char.isdigit() for char in value),
            any(char in "_+/=-" for char in value),
        ))
        if classes < 3:
            return False
        frequencies = {char: value.count(char) for char in set(value)}
        entropy = -sum((count / len(value)) * math.log2(count / len(value)) for count in frequencies.values())
        return entropy >= 3.6

    @staticmethod
    def _remove_overlaps(detections: list[_Detection]) -> list[_Detection]:
        selected: list[_Detection] = []
        for detection in detections:
            if any(detection.start < item.end and item.start < detection.end for item in selected):
                continue
            selected.append(detection)
        return sorted(selected, key=lambda item: item.start)

    @staticmethod
    def _redact(line: str, spans: list[tuple[int, int]]) -> str:
        redacted = line
        for start, end in sorted(spans, reverse=True):
            redacted = redacted[:start] + "[REDACTED]" + redacted[end:]
        return redacted

    def _relative_path(self, path: Path) -> str:
        try:
            return path.resolve().relative_to(self.root).as_posix()
        except ValueError:
            return os.path.relpath(path.resolve(), self.root).replace(os.sep, "/")

    def _display_path(self, path: Path) -> str:
        return self._relative_path(path)
