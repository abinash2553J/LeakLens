"""Run a safe end-to-end demo using synthetic, runtime-generated token-shaped values."""

from __future__ import annotations

import tempfile
from pathlib import Path

from leaklens.reporters import render_text
from leaklens.scanner import ScanConfig, SecretScanner


def main() -> int:
    # These values are synthetic and generated at runtime; no credential is stored in this file.
    fake_aws_key = "AKIA" + "A" * 16
    fake_github_token = "ghp_" + "b" * 36
    source = (
        f'aws_access_key = "{fake_aws_key}"\n'
        f'GITHUB_TOKEN = "{fake_github_token}"\n'
        'API_KEY = "YOUR_API_KEY_HERE"\n'
    )

    with tempfile.TemporaryDirectory(prefix="leaklens-demo-") as temporary_directory:
        root = Path(temporary_directory)
        (root / "settings.py").write_text(source, encoding="utf-8")
        result = SecretScanner(ScanConfig(root=root)).scan()
        print(render_text(result), end="")
        print("\nDemo complete: the findings above use synthetic values only.")
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
