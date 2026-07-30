<!--
SPDX-FileCopyrightText: 2026 Vetra Automation AB
SPDX-License-Identifier: CC-BY-4.0
-->

# Security policy

Garmr is **alpha software**. Treat this project as under active security
hardening. Please read [`docs/security/known-limitations.md`](docs/security/known-limitations.md)
before deploying — several ingest and audit surfaces are not yet safe to expose to
untrusted networks, and some features are experimental and disabled by default.

## Supported versions

Until the first stable release (`1.0`), only the **latest `0.1.x` alpha** tag is
supported for security fixes. There is no backport or long-term-support commitment
during alpha. Pre-1.0 releases carry **no compatibility guarantee**.

| Version | Supported |
|---------|-----------|
| latest `0.1.x-alpha` | ✅ security fixes |
| older pre-releases   | ❌ |

## Reporting a vulnerability — privately

**Do not open a public issue for a security vulnerability.**

Report privately through **GitHub Private Vulnerability Reporting**:

1. Go to the repository's **Security** tab → **Report a vulnerability**.
2. Describe the issue, affected version/commit, deployment mode, and a minimal
   reproduction.

If private reporting is unavailable to you, open a **minimal** public issue that
says only "security issue, requesting a private channel" — with **no details** —
and a maintainer will follow up.

### Do not include secrets or sensitive data

When reporting (or attaching logs), **never paste**:

- API tokens, bearer/admin tokens, passwords, private keys, or session cookies;
- real audit logs, real personal data, or production hostnames/IPs.

Redact first. If a report would require sensitive data to reproduce, say so and a
maintainer will arrange a secure exchange.

## What to expect

This is a small, best-effort project during alpha. Target response times:

- **Acknowledgement:** within ~7 days.
- **Triage / assessment:** as capacity allows; we will keep you updated.
- **Fix & disclosure:** coordinated with you. We aim to credit reporters who wish
  to be credited, once a fix is available.

These are goals, not contractual guarantees.

## Scope

In scope: the Garmr source code in this repository (crates under `crates/`,
`flightbeat/`, `xtask/`, and the deployment/scripts we ship). Out of scope:
third-party/vendored dependencies (report those upstream), issues that require
a deployment to be deliberately misconfigured against the documented secure
defaults, and purely theoretical findings without a plausible attack path.

## Safe harbor

We will not pursue or support legal action against good-faith security research
that: respects this policy, tests only against **your own** installation (never a
third party's data or systems), avoids privacy violations and service disruption,
and gives us a reasonable chance to fix the issue before public disclosure. This
is a good-faith statement for research against your own deployments; it is not a
waiver of third parties' rights.

## Known alpha limitations

Some security-relevant defaults are still being hardened and are documented openly
rather than hidden. See [`docs/security/known-limitations.md`](docs/security/known-limitations.md)
and [`docs/status/alpha-status.md`](docs/status/alpha-status.md). In particular,
do not expose Garmr's ingest or API surfaces to untrusted networks without a
reviewed, authenticated configuration, and keep experimental features (e.g. Arrow
Flight ingest) disabled unless you understand their current limitations.
