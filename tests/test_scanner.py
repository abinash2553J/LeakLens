from __future__ import annotations

import json
from pathlib import Path

import pytest

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
    synthetic_password = "correct" + "-horse-" + "battery-" + "staple"
    (tmp_path / "settings.py").write_text(f'database_password = "{synthetic_password}"\n', encoding="utf-8")  # leaklens:ignore

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
        f'GITHUB_TOKEN = "{github}"  # leaklens:ignore\n',  # leaklens:ignore LL012
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


@pytest.mark.parametrize(
    ("filename", "source", "expected"),
    [
        ("database.py", 'DATABASE_PASSWORD = "' + ("hunter2" * 2) + '"', True),
        ("github.py", 'GITHUB_TOKEN = "' + ("abcd1234" + "efgh5678") + '"', True),
        ("aws.py", 'AWS_SECRET_ACCESS_KEY = "' + ("abcd1234" + "efgh5678") + '"', True),
        ("jwt.py", 'JWT_SECRET = "' + ("abcd1234" + "efgh5678") + '"', True),
        ("settings.json", '{"password": "' + ("hunter2" * 2) + '"}', True),
        ("config.json", 'config = {"api_key": "' + ("abcd1234" + "efgh5678") + '"}', True),
        ("app.ts", 'apiKey: "' + ("abcd1234" + "efgh5678") + '"', True),
        ("config.yaml", "x-api-key: " + ("abcd1234" + "efgh5678"), True),
        ("application.properties", "spring.datasource.password=" + ("abcd1234" + "efgh5678"), True),
        ("typed.py", 'api_key: str = "' + ("abcd1234" + "efgh5678") + '"', True),
        (".env", "POSTGRES_PASSWORD=" + ("abcd1234" + "efgh5678"), True),
        ("miss.py", 'password_hash = "' + "abcdefghijklmnop" + '"', False),
        ("miss.py", "max_tokens = 4096", False),
        ("miss.ts", 'token_url = "https://example.com/token"', False),
        ("miss.py", 'AWS_ACCESS_KEY_ID = "' + "not-an-aws-id" + '"', False),
    ],
)
def test_ll012_sensitive_key_suffixes_through_scanner(
    tmp_path: Path, filename: str, source: str, expected: bool
) -> None:
    (tmp_path / filename).write_text(source + "\n", encoding="utf-8")
    result = scan(tmp_path)
    if expected:
        assert len(result.findings) == 1
        assert result.findings[0].rule_id == "LL012"
        assert "[REDACTED]" in result.findings[0].snippet
        assert "hunter2" not in result.findings[0].snippet
        assert "abcd1234" not in result.findings[0].snippet
    else:
        assert result.findings == []


def test_ll012_ignores_unquoted_code_expressions_in_python(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        'password = os.environ.get("X")\n'
        'token = self.request_token_value\n'
        'password = form.password_field_value\n',
        encoding="utf-8",
    )

    result = scan(tmp_path)

    assert result.findings == []


def test_ll012_scans_bare_values_only_in_config_files(tmp_path: Path) -> None:
    value = "abcd1234" + "efgh5678"
    (tmp_path / ".env.local").write_text(f"POSTGRES_PASSWORD={value}\n", encoding="utf-8")
    (tmp_path / "settings.py").write_text(f"POSTGRES_PASSWORD={value}\n", encoding="utf-8")

    result = scan(tmp_path)

    assert len(result.findings) == 1
    assert result.findings[0].path == ".env.local"
    assert result.findings[0].rule_id == "LL012"
    assert value not in result.findings[0].snippet


def test_suppressed_provider_winner_does_not_leak_to_ll012(tmp_path: Path) -> None:
    token = "ghp_" + "a1B2c3D4" * 5
    (tmp_path / "suppressed.py").write_text(
        f'token = "{token}"  # leaklens:ignore LL002\n', encoding="utf-8"
    )

    result = scan(tmp_path)

    assert result.findings == []


def test_suppressing_ll012_keeps_the_overlapping_provider_rule(tmp_path: Path) -> None:
    token = "ghp_" + "a1B2c3D4" * 5
    (tmp_path / "suppressed.py").write_text(
        f'token = "{token}"  # leaklens:ignore LL012\n', encoding="utf-8"
    )

    result = scan(tmp_path)

    assert len(result.findings) == 1
    assert result.findings[0].rule_id == "LL002"


def test_bare_inline_suppression_hides_all_overlapping_findings(tmp_path: Path) -> None:
    token = "ghp_" + "a1B2c3D4" * 5
    (tmp_path / "suppressed.py").write_text(
        f'token = "{token}"  # leaklens:ignore\n', encoding="utf-8"
    )

    result = scan(tmp_path)

    assert result.findings == []


def test_explicit_ignored_file_is_scanned_but_directory_scan_skips_it(tmp_path: Path) -> None:
    value = "abcd1234" + "efgh5678"
    (tmp_path / ".gitignore").write_text(".env.local\n", encoding="utf-8")
    (tmp_path / ".env.local").write_text(f"POSTGRES_PASSWORD={value}\n", encoding="utf-8")

    explicit = scan(tmp_path, paths=(Path(".env.local"),))
    directory = scan(tmp_path)

    assert len(explicit.findings) == 1
    assert explicit.findings[0].path == ".env.local"
    assert directory.findings == []


def test_fingerprint_does_not_hash_the_raw_secret(tmp_path: Path) -> None:
    import hashlib

    weak_password = "weak" + "password"
    (tmp_path / "settings.py").write_text(f'password = "{weak_password}"\n', encoding="utf-8")  # leaklens:ignore LL012

    result = scan(tmp_path)
    finding = result.findings[0]
    old_secret_digest = hashlib.sha256(weak_password.encode()).hexdigest()
    old_fingerprint = hashlib.sha256(
        f"{finding.path}:{finding.rule_id}:{old_secret_digest}".encode()
    ).hexdigest()

    assert finding.fingerprint != old_fingerprint
    assert weak_password not in json.dumps(result.to_dict())
    assert old_secret_digest not in render_json(result)


def test_duplicate_secret_lines_receive_distinct_fingerprints(tmp_path: Path) -> None:
    weak_password = "weak" + "password"
    line = f'password = "{weak_password}"'  # leaklens:ignore LL012
    (tmp_path / "settings.py").write_text(line + "\n" + line + "\n", encoding="utf-8")

    result = scan(tmp_path)

    assert len(result.findings) == 2
    assert result.findings[0].fingerprint != result.findings[1].fingerprint


def test_fingerprints_are_stable_for_identical_scans(tmp_path: Path) -> None:
    weak_password = "weak" + "password"
    (tmp_path / "settings.py").write_text(f'password = "{weak_password}"\n', encoding="utf-8")  # leaklens:ignore LL012

    first = scan(tmp_path)
    second = scan(tmp_path)

    assert [item.fingerprint for item in first.findings] == [
        item.fingerprint for item in second.findings
    ]


def test_sarif_uses_v2_partial_fingerprint_key(tmp_path: Path) -> None:
    token = "ghp_" + "a1B2c3D4" * 5
    (tmp_path / "service.py").write_text(f'token = "{token}"\n', encoding="utf-8")

    document = json.loads(render_sarif(scan(tmp_path)))
    fingerprints = document["runs"][0]["results"][0]["partialFingerprints"]

    assert list(fingerprints) == ["leaklens/v2"]


def test_root_file_named_build_is_scanned_but_build_directory_is_skipped(tmp_path: Path) -> None:
    value = "weak" + "password"
    (tmp_path / "build").write_text(f'password = "{value}"\n', encoding="utf-8")
    nested_build = tmp_path / "nested" / "build"
    nested_build.mkdir(parents=True)
    (nested_build / "x.py").write_text(f'password = "{value}"\n', encoding="utf-8")

    result = scan(tmp_path)

    assert len(result.findings) == 1
    assert result.findings[0].path == "build"


def test_non_regular_fifo_is_skipped_without_reading(tmp_path: Path) -> None:
    import os

    if not hasattr(os, "mkfifo"):
        pytest.skip("FIFO creation is not available on this platform")
    fifo = tmp_path / "secret-pipe"
    os.mkfifo(fifo)

    result = scan(tmp_path, paths=(Path("secret-pipe"),))

    assert result.errors == []
    assert result.scanned_files == 0
    assert result.skipped_files == 1


def test_line_numbers_only_advance_on_newline_characters(tmp_path: Path) -> None:
    value = "weak" + "password"
    (tmp_path / "controls.py").write_text(
        "banner\x0c\x0b\u2028\n"
        "safe = 1\n"
        f'password = "{value}"\n',
        encoding="utf-8",
    )

    result = scan(tmp_path)

    assert len(result.findings) == 1
    assert result.findings[0].line == 3


def test_single_source_version_is_used_in_json_and_sarif(tmp_path: Path) -> None:
    from leaklens import __version__

    (tmp_path / "app.py").write_text('print("safe")\n', encoding="utf-8")
    result = scan(tmp_path)

    assert json.loads(render_json(result))["tool"]["version"] == __version__
    assert json.loads(render_sarif(result))["runs"][0]["tool"]["driver"]["version"] == __version__


def test_entropy_heuristic_excludes_hexadecimal_and_single_case_values(tmp_path: Path) -> None:
    lower_hex = "abcdef0123456789" * 3
    mixed_hex = "aB12cD34" * 5
    lower_single_case = "lowercase" * 5
    (tmp_path / "checksums.py").write_text(
        f'checksum = "{lower_hex}"\n'
        f'checksum = "{mixed_hex}"\n'
        f'value = "{lower_single_case}"\n',
        encoding="utf-8",
    )

    result = scan(tmp_path)

    assert result.findings == []
