"""Built-in, dependency-free detection rules for common secret formats."""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Rule:
    rule_id: str
    name: str
    severity: str
    message: str
    pattern: re.Pattern[str]
    secret_group: str | int | None = 0
    priority: int = 50
    recommendation: str = "Remove the secret from source control, rotate it, and load it from a secret manager or environment variable."


def _rule(
    rule_id: str,
    name: str,
    severity: str,
    message: str,
    pattern: str,
    *,
    group: str | int | None = 0,
    priority: int = 50,
    flags: int = 0,
    recommendation: str | None = None,
) -> Rule:
    return Rule(
        rule_id=rule_id,
        name=name,
        severity=severity,
        message=message,
        pattern=re.compile(pattern, flags),
        secret_group=group,
        priority=priority,
        recommendation=recommendation or "Remove the secret from source control, rotate it, and load it from a secret manager or environment variable.",
    )


RULES: tuple[Rule, ...] = (
    _rule(
        "LL001", "AWS access key ID", "high", "Potential AWS access key ID detected.",
        r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b", priority=100,
        recommendation="Revoke or rotate the exposed AWS key in IAM, review CloudTrail for misuse, and use an IAM role where possible.",
    ),
    _rule(
        "LL002", "GitHub token", "high", "Potential GitHub access token detected.",
        r"\b(?:gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,})\b", priority=100,
        recommendation="Revoke the token in GitHub settings, review its scopes and audit logs, then use a fine-grained token or GitHub Actions OIDC.",
    ),
    _rule(
        "LL003", "GitLab token", "high", "Potential GitLab access token detected.",
        r"\bglpat-[A-Za-z0-9_-]{20,}\b", priority=100,
        recommendation="Revoke the token in GitLab and create a replacement with the minimum required scope.",
    ),
    _rule(
        "LL004", "Slack token", "high", "Potential Slack access token detected.",
        r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b", priority=100,
        recommendation="Revoke the token in Slack, review app permissions, and store replacement credentials outside source control.",
    ),
    _rule(
        "LL005", "Stripe secret key", "high", "Potential Stripe secret or restricted key detected.",
        r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b", priority=100,
        recommendation="Rotate the key in the Stripe Dashboard. Keep live-mode secret keys on trusted server-side infrastructure only.",
    ),
    _rule(
        "LL006", "Google API key", "high", "Potential Google API key detected.",
        r"\bAIza[0-9A-Za-z_-]{35}\b", priority=100,
        recommendation="Restrict or rotate the key in Google Cloud Console, limiting it by API and application where supported.",
    ),
    _rule(
        "LL007", "OpenAI API key", "high", "Potential OpenAI API key detected.",
        r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b", priority=100,
        recommendation="Revoke the key in the OpenAI dashboard and issue a replacement stored on the server, not in client-side code.",
    ),
    _rule(
        "LL008", "Hugging Face token", "high", "Potential Hugging Face access token detected.",
        r"\bhf_[A-Za-z0-9]{30,}\b", priority=100,
        recommendation="Revoke the token in Hugging Face settings and replace it with a least-privilege token stored outside source control.",
    ),
    _rule(
        "LL009", "SendGrid API key", "high", "Potential SendGrid API key detected.",
        r"\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{20,}\b", priority=100,
        recommendation="Revoke the key in SendGrid and create a new key with only the required permissions.",
    ),
    _rule(
        "LL010", "Private key", "critical", "Private-key material header detected.",
        r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----", priority=110,
        recommendation="Treat the private key as compromised: revoke or replace it, remove it from history where feasible, and use a secret manager.",
    ),
    _rule(
        "LL011", "JWT token", "medium", "A string resembling a JSON Web Token was found.",
        r"\b(?P<secret>eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,})\b", group="secret", priority=80,
        recommendation="Determine whether the JWT is live. Invalidate it if necessary and never commit session or bearer tokens.",
    ),
    _rule(
        "LL012", "Generic secret assignment", "high", "A secret-like value is assigned to a sensitive variable or key.",
        r"\b(?:api[_-]?key|client[_-]?secret|access[_-]?token|auth[_-]?token|refresh[_-]?token|token|password|passwd|database[_-]?password|db[_-]?password|secret(?:[_-]?key)?|private[_-]?key|credential|db[_-]?url|database[_-]?url)\b\s*(?:=|:)\s*(?:['\"](?P<quoted>[^'\"\r\n]{8,})['\"]|(?P<bare>[A-Za-z0-9_./+=-]{12,}))",
        group="quoted", priority=60, flags=re.IGNORECASE,
        recommendation="Move the value into an environment variable or secret manager. If it was committed, rotate it; deleting the line alone is not enough.",
    ),
    _rule(
        "LL013", "Bearer token", "high", "A hard-coded bearer token was found.",
        r"\bBearer\s+(?P<secret>[A-Za-z0-9._~+/=-]{20,})", group="secret", priority=90,
        recommendation="Invalidate the bearer token and obtain it at runtime from a trusted authentication flow.",
    ),
)

# High-entropy scanning is a heuristic, so it has a lower priority than specific rules.
ENTROPY_RULE = _rule(
    "LL014", "High-entropy string", "medium", "A long, high-entropy string may be a secret.",
    r"(?P<quote>['\"])(?P<secret>[A-Za-z0-9_+/=-]{32,})(?P=quote)", group="secret", priority=10,
    recommendation="Verify whether this value is a credential. If it is, rotate it and remove it from the codebase.",
)

ALL_RULES: tuple[Rule, ...] = RULES + (ENTROPY_RULE,)
RULE_BY_ID = {rule.rule_id: rule for rule in ALL_RULES}
