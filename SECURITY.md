# Security policy

## Reporting a vulnerability

Please do not open a public issue containing real credentials, exploitable sample secrets, or private application data. Use GitHub's private vulnerability reporting feature if it is enabled for the repository, or contact the maintainer privately through a verified channel.

When reporting a problem, include the affected version, steps to reproduce, expected behavior, actual behavior, and a sanitized example. Do not include live tokens.

## Safe use

- Run LeakLens locally against files you are authorized to inspect.
- Do not paste secrets into issue reports or public pull requests.
- Treat real findings as compromised: revoke or rotate the credential, inspect relevant audit logs, then remove it from current files and—where appropriate—repository history.
- Review generated reports before uploading or sharing them. LeakLens redacts detected values, but file paths and surrounding source lines may still be sensitive.

## Scope

LeakLens is a best-effort detector. It does not verify credentials, scan remote systems, or replace provider-side push protection, code review, access controls, or a dedicated security review.
