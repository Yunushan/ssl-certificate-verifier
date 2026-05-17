# Security Policy

## Reporting vulnerabilities

Please report security issues privately to the repository owner or maintainer before opening a public issue. Include:

- A concise description of the issue.
- Affected version or commit.
- Reproduction steps.
- Potential impact.
- Suggested mitigation, if known.

## Scope

In scope:

- Incorrect certificate verification behavior.
- Hostname/IP verification bypasses.
- Unsafe GUI/API behavior.
- Sensitive data exposure in reports.
- Build or release integrity issues.

Out of scope:

- Third-party network targets you do not own or have permission to test.
- Vulnerabilities in a remote site discovered by using this checker.
- Denial-of-service claims caused by deliberately running high-volume scans.

## Operational safety

The GUI binds to `127.0.0.1` by default. If you bind it to another interface, protect it with network controls because it can be used to initiate checks from the host running the service.
