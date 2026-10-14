# Detection rules

LeakLens combines known-format matchers with conservative heuristics. A matching pattern means **potential secret**, not verified credential.

| Rule | Severity | Detects |
| --- | --- | --- |
| `LL001` | High | AWS access-key ID prefixes `AKIA` and `ASIA` |
| `LL002` | High | Common GitHub token formats (`gh*_*` and `github_pat_*`) |
| `LL003` | High | GitLab personal access-token format (`glpat-…`) |
| `LL004` | High | Slack token prefixes (`xox…`) |
| `LL005` | High | Stripe secret/restricted keys (`sk_live_`, `sk_test_`, `rk_live_`, `rk_test_`) |
| `LL006` | High | Google API-key format (`AIza…`) |
| `LL007` | High | OpenAI API-key-like values (`sk-…` and `sk-proj-…`) |
| `LL008` | High | Hugging Face token format (`hf_…`) |
| `LL009` | High | SendGrid API-key-like values (`SG.….…`) |
| `LL010` | Critical | PEM/OpenSSH private-key header (including encrypted PEM headers) |
| `LL011` | Medium | JWT-shaped strings |
| `LL012` | High | Values assigned to secret-like names such as `API_KEY`, `TOKEN`, `PASSWORD`, `CLIENT_SECRET`, or `DATABASE_URL` |
| `LL013` | High | Hard-coded `Bearer` token values |
| `LL014` | Medium | Long quoted strings with high character diversity and estimated Shannon entropy |

## Entropy heuristic

Entropy checks only apply to long quoted alphanumeric/symbol string literals. LeakLens requires several character classes and a minimum estimated entropy, then excludes several common placeholder forms and plain hexadecimal checksums unless the line appears secret-related. This reduces noise but cannot remove all false positives. Use `--no-entropy` for a pattern-only run.

## Suppressions

Use `# leaklens:ignore LL002` to suppress one matching rule on a source line. Use `# leaklens:ignore` to suppress every finding on that line. Suppression does not remove a value from source code; it merely hides the report item. Treat suppressions as reviewed exceptions.

## Extending coverage

Rules live in `leaklens/rules.py`. Each rule has an ID, name, severity, message, matching expression, secret capture group, and priority. Add regression tests that synthesize token-like strings at runtime so examples do not accidentally resemble real production credentials.
