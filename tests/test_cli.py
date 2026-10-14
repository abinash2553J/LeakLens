from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from leaklens.cli import main


def test_cli_returns_one_when_findings_meet_fail_threshold(tmp_path: Path, monkeypatch) -> None:
    token = "AKIA" + "C" * 16
    (tmp_path / "app.py").write_text(f'key = "{token}"\n', encoding="utf-8")
    monkeypatch.chdir(tmp_path)

    assert main(["--format", "json"]) == 1


def test_cli_writes_json_report(tmp_path: Path, monkeypatch) -> None:
    token = "ghp_" + "f" * 36
    (tmp_path / "app.py").write_text(f'GH_TOKEN = "{token}"\n', encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    report_path = tmp_path / "reports" / "scan.json"

    exit_code = main(["--format", "json", "--output", str(report_path)])

    assert exit_code == 1
    document = json.loads(report_path.read_text(encoding="utf-8"))
    assert document["summary"]["finding_count"] == 1
    assert token not in report_path.read_text(encoding="utf-8")


def test_demo_runs_without_installing_and_redacts_synthetic_values() -> None:
    repository_root = Path(__file__).resolve().parents[1]
    completed = subprocess.run(
        [sys.executable, "examples/demo.py"],
        cwd=repository_root,
        capture_output=True,
        text=True,
        check=False,
    )

    assert completed.returncode == 0
    assert "[REDACTED]" in completed.stdout
    assert "Demo complete" in completed.stdout
    assert "ghp_" not in completed.stdout
