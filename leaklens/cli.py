"""Command-line interface for LeakLens."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Sequence

from . import __version__
from .models import SEVERITY_ORDER
from .reporters import render_json, render_sarif, render_text
from .scanner import ScanConfig, SecretScanner


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="leaklens",
        description="Scan local source code for likely API keys, tokens, private keys, and hard-coded secrets.",
        epilog="Source files stay on your machine. Findings are redacted in every report format.",
    )
    parser.add_argument("paths", nargs="*", metavar="PATH", help="files or directories to scan (default: current directory)")
    parser.add_argument("--format", choices=("text", "json", "sarif"), default="text", help="report format (default: text)")
    parser.add_argument("--output", "-o", metavar="FILE", help="write the report to FILE; use '-' for stdout")
    parser.add_argument("--exclude", action="append", default=[], metavar="PATTERN", help="additional gitignore-style path pattern; may be repeated")
    parser.add_argument("--no-ignore-files", action="store_true", help="do not read .gitignore or .leaklensignore")
    parser.add_argument("--max-file-size", type=float, default=1.0, metavar="MB", help="skip files larger than this size in MiB (default: 1.0)")
    parser.add_argument("--fail-on", choices=("critical", "high", "medium", "low", "none"), default="low", help="exit 1 when a finding at this severity or higher exists (default: low)")
    parser.add_argument("--no-entropy", action="store_true", help="disable heuristic high-entropy string detection")
    parser.add_argument("--version", action="version", version=f"LeakLens {__version__}")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.max_file_size <= 0:
        parser.error("--max-file-size must be greater than zero")

    root = Path.cwd().resolve()
    paths = tuple(Path(path) for path in args.paths) if args.paths else (Path("."),)
    max_bytes = int(args.max_file_size * 1024 * 1024)
    config = ScanConfig(
        root=root,
        paths=paths,
        max_file_size=max_bytes,
        load_ignore_files=not args.no_ignore_files,
        extra_excludes=tuple(args.exclude),
        include_entropy=not args.no_entropy,
    )
    result = SecretScanner(config).scan()
    if args.format == "json":
        rendered = render_json(result)
    elif args.format == "sarif":
        rendered = render_sarif(result)
    else:
        rendered = render_text(result, color=(args.output in (None, "-") and sys.stdout.isatty()))

    try:
        if args.output and args.output != "-":
            output_path = Path(args.output)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(rendered, encoding="utf-8")
            print(f"Report written to {output_path}", file=sys.stderr)
        else:
            sys.stdout.write(rendered)
    except OSError as exc:
        print(f"leaklens: could not write report: {exc}", file=sys.stderr)
        return 2

    if result.errors:
        return 2
    if args.fail_on == "none":
        return 0
    minimum = SEVERITY_ORDER[args.fail_on]
    if any(SEVERITY_ORDER.get(finding.severity, 0) >= minimum for finding in result.findings):
        return 1
    return 0


if __name__ == "__main__":  # pragma: no cover - covered through console entry point
    raise SystemExit(main())
