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
| `LL012` | High | Values assigned to keys whose normalized names end with a recognized credential suffix, including `API_KEY`, `GITHUB_TOKEN`, `DATABASE_PASSWORD`, `JWT_SECRET`, and `DATABASE_URL` |
| `LL013` | High | Hard-coded `Bearer` token values |
| `LL014` | Medium | Long quoted strings with high character diversity and estimated Shannon entropy |

## Generic assignment rule and key normalization

`LL012` captures the complete key, including optional quotes around JSON keys and optional type annotations such as `api_key: str = ...`. It supports unquoted values only in configuration-style files: filenames beginning with `.env`, `.ini`, `.cfg`, `.conf`, `.properties`, `.yaml`, `.yml`, `.sh`, `.bash`, `.zsh`, and `Dockerfile`. In source code, only quoted generic values count. The bare-value alphabet excludes periods to avoid treating dotted code expressions as literals. It lowercases the key and removes `_`, `.`, and `-`, then requires the normalized key to end with one of these suffixes: `apikey`, `secretkey`, `accesskey`, `privatekey`, `clientsecret`, `authtoken`, `accesstoken`, `refreshtoken`, `token`, `password`, `passwd`, `secret`, `credential`, `credentials`, `dburl`, or `databaseurl`. Therefore `password_hash`, `token_url`, `max_tokens`, `secret_name`, and `AWS_ACCESS_KEY_ID` do not match this generic rule. Provider-specific rules are still evaluated independently.

## Entropy heuristic

Entropy checks only apply to long quoted alphanumeric/symbol string literals. LeakLens requires several character classes and a minimum estimated entropy, then excludes several common placeholder forms, single-case strings, and hexadecimal strings. This reduces noise but cannot remove all false positives. Use `--no-entropy` for a pattern-only run.

## Suppressions

Use `# leaklens:ignore LL002` to suppress one matching rule on a source line. Use `# leaklens:ignore` to suppress every finding on that line. Suppression does not remove a value from source code; it merely hides the report item. Treat suppressions as reviewed exceptions.

## Extending coverage

Rules live in `leaklens/rules.py`. Each rule has an ID, name, severity, message, matching expression, secret capture group, and priority. Add regression tests that synthesize token-like strings at runtime so examples do not accidentally resemble real production credentials.
