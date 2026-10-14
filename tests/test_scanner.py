from __future__ import annotations

import json
from pathlib import Path

from leaklens.reporters import render_json, render_sarif, render_text
from leaklens.scanner import ScanConfig, SecretScanner


def scan(tmp_path: Path, *, paths: tuple[Path, ...] = ()):
    return SecretScanner(ScanConfig(root=tmp_path, paths=paths or (Path("."),))).scan()


def test_detects_provider_token_and_redacts_output(tmp_path: Path) -> None:
    token = "AKIA" + "A" * 16
    (tmp_path / "app.py").write_text(f'AWS_KEY = "{token}"\n', encoding="utf-8")

    result = scan(tmp_path)

    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.rule_id == "LL001"
    assert finding.severity == "high"
    assert token not in finding.snippet
    assert "[REDACTED]" in finding.snippet
    assert token not in render_text(result)
    assert token not in render_json(result)


def test_detects_bare_env_value_and_quoted_generic_secret(tmp_path: Path) -> None:
    (tmp_path / ".env").write_text("API_KEY=Abcdef1234567890\n", encoding="utf-8")  # leaklens:ignore
    (tmp_path / "settings.py").write_text('database_password = "correct-horse-battery-staple"\n', encoding="utf-8")  # leaklens:ignore

    result = scan(tmp_path)

    assert {finding.rule_id for finding in result.findings} == {"LL012"}
    assert all("[REDACTED]" in finding.snippet for finding in result.findings)


def test_ignores_common_placeholders(tmp_path: Path) -> None:
    (tmp_path / "example.py").write_text(
        'API_KEY = "YOUR_API_KEY_HERE"\npassword = "change-me"\nsecret = "placeholder"\n',
        encoding="utf-8",
    )

    result = scan(tmp_path)

    assert result.findings == []


def test_inline_suppression_supports_one_rule_or_all(tmp_path: Path) -> None:
    aws = "AKIA" + "B" * 16
    github = "ghp_" + "c" * 36
    (tmp_path / "suppressed.py").write_text(
        f'AWS_KEY = "{aws}"  # leaklens:ignore LL001\n'
        f'GITHUB_TOKEN = "{github}"  # leaklens:ignore\n',
        encoding="utf-8",
    )

    result = scan(tmp_path)

    assert result.findings == []


def test_gitignore_and_leaklensignore_are_respected(tmp_path: Path) -> None:
    token = "ghp_" + "d" * 36
    (tmp_path / ".gitignore").write_text("generated/\n", encoding="utf-8")
    (tmp_path / ".leaklensignore").write_text("private.env\n", encoding="utf-8")
    (tmp_path / "generated").mkdir()
    (tmp_path / "generated" / "bundle.js").write_text(f'token = "{token}"\n', encoding="utf-8")
    (tmp_path / "private.env").write_text(f'GH_TOKEN="{token}"\n', encoding="utf-8")
    (tmp_path / "safe.py").write_text("print('hello')\n", encoding="utf-8")

    result = scan(tmp_path)

    assert result.findings == []
    assert result.scanned_files == 3  # safe.py plus the two text ignore files


def test_detects_private_key_header_as_critical(tmp_path: Path) -> None:
    (tmp_path / "deploy.key").write_text("-----BEGIN PRIVATE KEY-----\nnot-a-real-key\n", encoding="utf-8")  # leaklens:ignore LL010

    result = scan(tmp_path)

    assert len(result.findings) == 1
    assert result.findings[0].rule_id == "LL010"
    assert result.findings[0].severity == "critical"


def test_entropy_heuristic_can_be_disabled(tmp_path: Path) -> None:
    value = "Aa1_+Bc2-De3/Fg4=Hi5_Jk6+Lm7-No8/Pq9=Rs0_Tu1+Vw2-Xy3/Zz4="  # leaklens:ignore LL014
    (tmp_path / "config.js").write_text(f'const value = "{value}";\n', encoding="utf-8")

    enabled = scan(tmp_path)
    disabled = SecretScanner(ScanConfig(root=tmp_path, paths=(Path("."),), include_entropy=False)).scan()

    assert any(finding.rule_id == "LL014" for finding in enabled.findings)
    assert disabled.findings == []


def test_sarif_is_valid_json_and_uses_redacted_snippets(tmp_path: Path) -> None:
    token = "ghp_" + "e" * 36
    (tmp_path / "service.js").write_text(f'const token = "{token}";\n', encoding="utf-8")

    result = scan(tmp_path)
    document = json.loads(render_sarif(result))

    assert document["version"] == "2.1.0"
    sarif_result = document["runs"][0]["results"][0]
    assert sarif_result["ruleId"] == "LL002"
    assert token not in json.dumps(document)
    assert "[REDACTED]" in sarif_result["locations"][0]["physicalLocation"]["region"]["snippet"]["text"]


def test_oversized_and_binary_files_are_skipped(tmp_path: Path) -> None:
    (tmp_path / "large.txt").write_text("a" * 300, encoding="utf-8")
    (tmp_path / "image.bin").write_bytes(b"\x00\x01\x02")

    result = SecretScanner(ScanConfig(root=tmp_path, paths=(Path("."),), max_file_size=100)).scan()

    assert result.scanned_files == 0
    assert result.skipped_files == 2
