# Security Policy / Safe Use

HegoSentinel is intended for lawful and authorized testing of assets a user owns or has explicit, documented permission to assess.

## Authorization and scope

- Obtain explicit authorization identifying owner, asset allowlist, permitted methods, testing window, and emergency contact before scanning.
- Prove control of a domain/repository where technically feasible, but do not mistake domain proof for permission to perform every test.
- Default to passive checks. Active testing requires a separately approved, restricted, later-release workflow, preferably on staging.
- Never scan unrelated domains, third-party services, or cloud infrastructure discovered through redirects, links, or DNS resolutions.

## Prohibited default behavior

- Credential stuffing, brute force, denial-of-service or stress testing.
- Exploit chaining, destructive payloads, or data modification/exfiltration.
- Internet-scale discovery or unrestricted IP scanning.
- Running attacker-provided shell commands or installing untrusted binaries without isolation.
- Uploading private source code, keys, personal data, or complete raw responses to an AI provider by default.

## Platform safeguards

- Re-resolve and validate every target, host/IP, and redirect; enforce scope boundaries at the worker’s network egress layer.
- Block RFC1918/private, loopback, link-local, cloud metadata, and other non-public destinations in remote services, using a dedicated isolated local-demo mode when necessary.
- Use unprivileged containers, restricted filesystem mounts, resource limits, and no host Docker socket.
- Treat fetched pages, scan findings, dependencies, and repositories as untrusted inputs.
- Redact sensitive evidence in logs/reports; encrypt stored artifacts; apply short retention and role-based access.
- Limit concurrency and request rates; support an immediate job cancellation mechanism.
- Require human approval before notifying external recipients or creating public issues.

## Reporting a HegoSentinel vulnerability

Use GitHub's private vulnerability reporting feature (once enabled) or a maintainer-provided private contact mechanism. **Do not open a public issue containing exploitable details, secrets, or sensitive data.**

## Testing disclaimer

Automated assessment may miss important issues and may produce false positives. The product should not advertise an unqualified guarantee of security or a fully comprehensive penetration test.
