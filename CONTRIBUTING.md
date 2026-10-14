# Contributing

Thanks for considering a contribution to LeakLens.

## Development setup

```bash
python -m venv .venv
# Windows PowerShell: .venv\Scripts\Activate.ps1
# macOS/Linux: source .venv/bin/activate
python -m pip install -e ".[test]"
python -m pytest -q
```

## Pull request expectations

- Add regression tests for detection rules, exclusions, report formats, and suppressions as relevant.
- Generate synthetic token-shaped values at runtime instead of committing real-looking credentials.
- Ensure output never includes the matched value.
- Keep runtime dependencies at zero unless a dependency materially improves correctness or maintainability.
- Update `docs/RULES.md` and the README when behavior or supported formats change.

## Design principles

Local-first by default, redacted output, explicit limitations, useful actionable findings, and predictable exit codes.
