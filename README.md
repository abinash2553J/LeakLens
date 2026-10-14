# LeakLens

**A local-first secret scanner for code repositories.** Catch likely API keys, access tokens, private-key material, and hard-coded passwords before they ship.

![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white)
![Dependencies](https://img.shields.io/badge/runtime_dependencies-none-2E8B57)
![License](https://img.shields.io/badge/License-MIT-blue.svg)
![CI](https://github.com/abinash2553J/LeakLens/actions/workflows/ci.yml/badge.svg)

LeakLens runs on your machine. It does **not** upload source code, contact external services, or attempt to validate credentials against provider APIs. Findings are redacted in terminal, JSON, and SARIF output.

## Why LeakLens?

Secrets accidentally committed to source code can grant access to cloud infrastructure, payment systems, source-control accounts, or user data. LeakLens gives developers a simple pre-commit and CI check without requiring a hosted service or runtime dependencies.

### Features

- **Provider-aware rules:** AWS access-key IDs, GitHub and GitLab tokens, Slack tokens, Stripe keys, Google API keys, OpenAI keys, Hugging Face tokens, SendGrid keys, and private-key headers.
- **Generic detection:** suspicious values assigned to variables such as `API_KEY`, `DATABASE_PASSWORD`, `ACCESS_TOKEN`, or `CLIENT_SECRET`.
- **Entropy heuristic:** flags some long, high-entropy string literals that do not match a known provider pattern.
- **Redacted-by-default reporting:** the raw matched value is never stored in a finding object or printed in reports.
- **Repository-aware exclusions:** reads root `.gitignore` and `.leaklensignore`, skips common generated/vendor directories, binary files, symlinks, and oversized files.
- **Inline suppressions:** document intentional test cases with `# leaklens:ignore` or a rule-specific suppression.
- **CI-friendly exit codes:** fail builds when findings reach a configurable severity.
- **Portable output:** readable terminal output, JSON for scripts, and SARIF 2.1.0 for code-scanning workflows.
- **No runtime dependencies:** uses the Python standard library.

## Quick start

Requires Python 3.10 or newer.

### Run without installing

```bash
git clone https://github.com/abinash2553J/LeakLens.git
cd LeakLens
python -m leaklens .
```

### Install as a CLI

```bash
python -m pip install -e .
leaklens .
```

### Try the safe demo

The demo generates synthetic token-shaped values at runtime, creates a temporary project, scans it, prints redacted findings, and removes the temporary files.

```bash
python examples/demo.py
```

### Scan a specific project or file

```bash
leaklens ./src ./config
leaklens .env.local
```

LeakLens scans the current directory when no path is supplied. Relative paths are resolved from the directory where the command is run.

## Example output

```text
LeakLens · local secret scanner
──────────────────────────────────────────
Scanned 42 file(s) · 2 finding(s) · 3 skipped · 0 error(s)

HIGH  LL001 · AWS access key ID
  src/cloud.py:18:16 — Potential AWS access key ID detected.
  aws_access_key = "[REDACTED]"
  Fix: Revoke or rotate the exposed AWS key in IAM, review CloudTrail for misuse, and use an IAM role where possible.

HIGH  LL012 · Generic secret assignment
  config/settings.py:7:13 — A secret-like value is assigned to a sensitive variable or key.
  DATABASE_PASSWORD = "[REDACTED]"
  Fix: Move the value into an environment variable or secret manager...
```

The example is illustrative; counts and source locations depend on the repository being scanned.

## CLI reference

```text
leaklens [PATH ...] [options]
```

| Option | Purpose |
| --- | --- |
| `--format text\|json\|sarif` | Choose terminal, JSON, or SARIF output. |
| `-o, --output FILE` | Write report to a file, for example `-o reports/secrets.sarif`. Use `-` for stdout. |
| `--exclude PATTERN` | Add a path pattern; repeat the option for multiple patterns. |
| `--no-ignore-files` | Ignore `.gitignore` and `.leaklensignore` rules. Built-in generated-directory exclusions still apply. |
| `--max-file-size MB` | Skip files larger than this size; default is 1 MiB. |
| `--fail-on LEVEL` | Exit 1 on a finding at `critical`, `high`, `medium`, or `low` severity and above. `none` disables finding-based failure. |
| `--no-entropy` | Disable heuristic high-entropy checks. |
| `--version` | Print the installed version. |

### Exit codes

- `0`: no findings meet the configured `--fail-on` threshold.
- `1`: one or more findings meet the configured threshold.
- `2`: a scan or report-writing error occurred.

### JSON report

```bash
leaklens . --format json --output reports/leaklens.json
```

### SARIF report for GitHub code scanning

```bash
leaklens . --format sarif --output reports/leaklens.sarif
```

Upload the generated SARIF in a GitHub Actions workflow using the official SARIF upload action. Review your repository's code-scanning availability and permissions before enabling uploads. A sample CI workflow is included in `.github/workflows/ci.yml` for running the tests; SARIF uploading is intentionally not enabled by default.

## Ignore rules and suppressions

LeakLens reads patterns from the repository-root `.gitignore` and `.leaklensignore` files. It supports common patterns, directory suffixes such as `generated/`, comments, and basic `!` negation. Nested ignore files and every edge case of Git's ignore semantics are not currently implemented.

Add a repository-specific exclusion to `.leaklensignore`:

```gitignore
# Generated bundles can be scanned separately if needed
generated/
fixtures/large-snapshots/
```

Suppress one rule on a line when a test fixture intentionally contains a secret-shaped value:

```python
example = build_test_token()  # leaklens:ignore LL002
```

Suppress all findings on that line only when justified:

```python
example = load_test_fixture()  # leaklens:ignore
```

Prefer fixing a finding over suppressing it. Keep suppressions narrow and explain unusual cases in a nearby comment.

## Run the tests

```bash
python -m pip install -e ".[test]"
python -m pytest -q
```

The tests construct synthetic credentials at runtime instead of checking real-looking credential strings into the repository.

## How it works

1. **Discover files:** walk requested paths without following symlinks; prune standard build, cache, and dependency folders.
2. **Filter files:** apply ignore patterns, file-size limits, and a lightweight binary-file check.
3. **Match rules:** run provider-specific regular expressions and generic assignment checks line by line. Optionally inspect long string literals with a Shannon-entropy heuristic.
4. **Suppress and de-duplicate:** honor inline directives and prioritize specific provider rules when matches overlap.
5. **Redact and report:** replace the detected span with `[REDACTED]`; emit text, JSON, or SARIF with file, line, column, rule, severity, recommendation, and a non-secret fingerprint.

See [`docs/RULES.md`](docs/RULES.md) for coverage and [`docs/SECURITY.md`](docs/SECURITY.md) for safe handling guidance.

## Security notes and limitations

LeakLens is a lightweight, heuristic scanner—not a guarantee that a repository is secret-free.

- It scans the working-tree files you point it at; it does **not** scan Git history, untracked branches, container layers, deployed systems, or remote repositories.
- Pattern and entropy checks can produce false positives and false negatives. Review findings before taking action.
- It does not contact a cloud provider to verify whether a credential is live.
- Root-level ignore support is intentionally smaller than Git's full ignore implementation.
- A clean result does not establish that an application is secure.
- If a real secret was committed, **rotate or revoke it first**. Deleting a line or rewriting history does not invalidate an exposed credential.

For production repositories, pair this tool with a maintained secret scanner, push protection, least-privilege credentials, and a managed secret store.

## Roadmap

- Optional Git-history scanning with explicit opt-in.
- Rule configuration and custom patterns.
- Baseline files for existing findings.
- Pre-commit integration and richer CI annotations.
- Benchmarks against curated public test fixtures with documented false-positive tradeoffs.

## License

MIT. See [`LICENSE`](LICENSE).
