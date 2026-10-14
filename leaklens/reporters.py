"""Human-readable, JSON, and SARIF report formatters."""

from __future__ import annotations

import json
from typing import Any

from .models import Finding, ScanResult, SEVERITY_ORDER
from .rules import ALL_RULES


SEVERITY_COLORS = {
    "critical": "\033[95m",
    "high": "\033[91m",
    "medium": "\033[93m",
    "low": "\033[94m",
    "info": "\033[90m",
}
RESET = "\033[0m"


def render_text(result: ScanResult, *, color: bool = False) -> str:
    lines: list[str] = []

    def severity_label(severity: str) -> str:
        label = severity.upper()
        return f"{SEVERITY_COLORS.get(severity, '')}{label}{RESET}" if color else label

    lines.append("LeakLens · local secret scanner")
    lines.append("─" * 42)
    lines.append(
        f"Scanned {result.scanned_files} file(s) · "
        f"{len(result.findings)} finding(s) · {result.skipped_files} skipped · {len(result.errors)} error(s)"
    )
    lines.append("")

    if result.findings:
        for finding in result.findings:
            lines.append(f"{severity_label(finding.severity)}  {finding.rule_id} · {finding.rule_name}")
            lines.append(f"  {finding.path}:{finding.line}:{finding.column} — {finding.message}")
            if finding.snippet:
                lines.append(f"  {finding.snippet}")
            lines.append(f"  Fix: {finding.recommendation}")
            lines.append("")
    else:
        lines.append("✓ No likely secrets found.")
        lines.append("")

    if result.errors:
        lines.append("Errors:")
        for error in result.errors:
            lines.append(f"  - {error}")
        lines.append("")

    lines.append("Safety note: output is redacted. Verify findings and rotate any credential that was exposed.")
    return "\n".join(lines).rstrip() + "\n"


def render_json(result: ScanResult) -> str:
    return json.dumps(result.to_dict(), indent=2, ensure_ascii=False) + "\n"


def render_sarif(result: ScanResult) -> str:
    rules = []
    for rule in ALL_RULES:
        rules.append({
            "id": rule.rule_id,
            "name": rule.name,
            "shortDescription": {"text": rule.name},
            "fullDescription": {"text": rule.message},
            "defaultConfiguration": {"level": _sarif_level(rule.severity)},
            "properties": {"severity": rule.severity, "tags": ["security", "secret-scanning"]},
        })

    results = []
    for finding in result.findings:
        results.append({
            "ruleId": finding.rule_id,
            "level": _sarif_level(finding.severity),
            "message": {"text": f"{finding.message} {finding.recommendation}"},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": finding.path.replace("\\", "/")},
                    "region": {
                        "startLine": finding.line,
                        "startColumn": finding.column,
                        "snippet": {"text": finding.snippet},
                    },
                }
            }],
            "partialFingerprints": {"leaklens/v1": finding.fingerprint},
            "properties": {"severity": finding.severity},
        })

    document: dict[str, Any] = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "LeakLens",
                "version": "1.0.0",
                "rules": rules,
            }},
            "results": results,
            "properties": {
                "scannedFiles": result.scanned_files,
                "skippedFiles": result.skipped_files,
                "errorCount": len(result.errors),
                "errors": result.errors,
            },
        }],
    }
    return json.dumps(document, indent=2, ensure_ascii=False) + "\n"


def _sarif_level(severity: str) -> str:
    if SEVERITY_ORDER.get(severity, 0) >= SEVERITY_ORDER["high"]:
        return "error"
    if severity == "medium":
        return "warning"
    return "note"
