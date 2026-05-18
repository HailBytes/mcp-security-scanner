# Security Policy

## Supported Versions

During incubation this package has not yet reached a stable release. No versions are currently patched for security vulnerabilities.

| Version | Supported |
|---------|-----------|
| 0.0.x   | Incubation — not yet supported |

## Reporting a Vulnerability

**Please do NOT open a public GitHub issue for security vulnerabilities.**

Email **security@hailbytes.com** with:
- A description of the vulnerability and its impact
- Steps to reproduce (or a minimal proof-of-concept)
- Any suggested remediation you may have

You can expect an acknowledgement within **48 hours** and a status update within **7 days**.

## Security Considerations When Using This Tool

- **CI integration**: Use `--exit-code` to fail pipelines on any finding, not just critical ones
- **SARIF upload**: Use `--format=sarif` and upload to GitHub Code Scanning for centralised tracking
- **Do not scan production secrets**: Example configs are for testing only — never put real API keys or credentials in config files checked into source control
- **Keep updated**: Security rules evolve; re-run the scanner after each new release
