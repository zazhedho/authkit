# Security policy

## Supported versions

Security fixes go into the latest release of `github.com/zazhedho/authkit` only. Upgrade to the latest tag before reporting a problem that an upgrade may already fix.

## Reporting a vulnerability

Please report suspected vulnerabilities privately, not in a public issue or pull request.

- Use GitHub's private vulnerability reporting for this repository (Security tab, "Report a vulnerability").
- Include the version, a description of the impact, and the smallest reproduction you can give. Do not include real credentials, tokens or personal data.

Response targets: an acknowledgement within 3 working days, an assessment within 10 working days, and a fix or mitigation for a confirmed high-severity issue within 30 days. Fixes are released as a patch version with a note in the release description; credit is given if you want it.

## Scope

In scope: the authentication, session, token, RBAC, OTP and password reset code in this module and its embedded migrations.

Out of scope: how a host application configures gin (trusted proxies, CORS), Redis, SMTP or the database, and secrets that a deployment keeps in the wrong place. The README's "Security notes" section lists what the host must decide.

## Hardening checklist for deployments

- Set `JWTKey`, `OTP.Secret` and `Reset.Secret` to distinct random values of at least 32 characters, outside the repository.
- Configure gin's trusted proxies; the rate limiters and audit IPs depend on `ClientIP()`.
- Run Redis with authentication and a database or ACL prefix of its own.
- Keep `AccessTokenTTL` short and consider `FailClosedLimiters` when Redis outages must not lift rate limits.
