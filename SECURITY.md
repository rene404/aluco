# Security

## Reporting a vulnerability

Please **do not** open a public issue. Instead, report it via GitHub:
**Security → Report a vulnerability** ([private report](https://github.com/rene404/aluco/security/advisories/new)).

Helpful: affected version or commit, steps to reproduce, possible impact.

You will usually get a response within 7 days. Aluco is a hobby project without warranty.

## Supported versions

Only the latest release (see [CHANGELOG.md](CHANGELOG.md)); fixes land in `develop` and come with the next release.

## Operating notes

- Make the dashboard reachable only from the home network or via VPN, never directly from the internet.
- Give the firewall's API key only the privileges Aluco needs (block list).
