"""Small, serializable data models used by LeakLens."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

from ._version import __version__


SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


@dataclass(frozen=True, slots=True)
class Finding:
    rule_id: str
    rule_name: str
    severity: str
    message: str
    path: str
    line: int
    column: int
    snippet: str
    fingerprint: str
    recommendation: str

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-ready dictionary; raw secret material is never stored here."""
        return asdict(self)


@dataclass(slots=True)
class ScanResult:
    root: str
    scanned_files: int = 0
    skipped_files: int = 0
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def counts_by_severity(self) -> dict[str, int]:
        counts = {name: 0 for name in SEVERITY_ORDER}
        for finding in self.findings:
            counts[finding.severity] = counts.get(finding.severity, 0) + 1
        return counts

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": {"name": "LeakLens", "version": __version__},
            "root": self.root,
            "summary": {
                "scanned_files": self.scanned_files,
                "skipped_files": self.skipped_files,
                "finding_count": len(self.findings),
                "counts_by_severity": self.counts_by_severity,
                "error_count": len(self.errors),
            },
            "findings": [finding.to_dict() for finding in self.findings],
            "errors": self.errors,
        }
