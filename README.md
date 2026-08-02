<!--
SPDX-FileCopyrightText: 2026 Vetra Automation AB
SPDX-License-Identifier: CC-BY-4.0
-->

<p align="center"><img src="docs/garmr.png" alt="Garmr" width="180"></p>

# Garmr

Self-hosted security monitoring and application auditing, written in Rust.

Garmr ingests logs and PostgreSQL/pgAudit activity, runs detection and
user-behaviour analytics over a columnar lakehouse, records findings in a
tamper-evident ledger, and gives you search, link analysis, and a read-only LLM
agent to investigate — all on your own hardware, air-gap included.

> **Alpha.** Evaluate it in an isolated lab. It is not ready to be your only line
> of production defence, and its ingest and API surfaces should not face untrusted
> networks without a reviewed, authenticated configuration. Expect breaking changes
> before 1.0.

## What it does

- **Ingest** — syslog and NDJSON over HTTP, with optional Loki-compatible and Arrow
  Flight receivers, normalised into an Iceberg lakehouse you can query with SQL.
- **Detect** — Sigma rules, correlation, and SQL-aware PostgreSQL/pgAudit analysis.
- **Analytics** — per-entity baselines, anomaly scoring, and silence detection.
- **Audit** — findings and audit records are hash-chained and ed25519-signed, so the
  ledger can be independently verified.
- **Investigate** — full-text search, optional semantic search, a link-analysis graph
  with attack paths, and an LLM agent (also available over MCP).

## Safety model

The agent is read-only. It queries, correlates, and *proposes* next steps; it never
approves or executes actions, and there is no automatic cloud fallback. Policy denial
is a separate signal from anomaly scoring — a high score is a reason to look, not a
verdict. External model calls are gated by an egress policy, and `GARMR_AIRGAP=1`
blocks every external route.

## Quick start (lab)

```bash
cargo build --release -p garmr-cli
./target/release/garmr serve
# The query API defaults to loopback (127.0.0.1:3110).
# Native ingest defaults to 0.0.0.0:3100 and requires collector authentication
# when bound to a non-loopback address — `serve` refuses to start otherwise.
```

So a default `serve` on a machine with a routable interface **will refuse to start**
until you either set `GARMR_COLLECTORS` (per-collector bearer tokens) or move
`ingest.ingest_bind` to loopback. That is deliberate: an open, unauthenticated ingest
port lets anyone who can reach it forge events into the SOC.

Read [Secure deployment](docs/deployment/secure-deployment.md) before exposing
anything: it covers collector authentication, the API token / passkey gates, the
egress policy, and which surfaces still need a reverse proxy in front of them. Some
capabilities are behind Cargo features, e.g. `--features "semantic loki-compat flight"`;
the optional Loki and Arrow Flight receivers have **different** security properties
from native ingest — see [Known limitations](docs/security/known-limitations.md).

## Documentation

[Architecture](docs/architecture/overview.md) ·
[Trust model](docs/architecture/trust-model.md) ·
[Deployment](docs/deployment/) ·
[Security & known limitations](docs/security/known-limitations.md) ·
[Alpha status](docs/status/alpha-status.md)

## Development

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
```

See [CONTRIBUTING.md](CONTRIBUTING.md). Contributions are accepted under a
[CLA](CLA.md), since Garmr is dual-licensed.

## Security

Report vulnerabilities privately through the repository's Security tab — see
[SECURITY.md](SECURITY.md). Never paste secrets or real audit logs into an issue.

## License

Code is **AGPL-3.0-only**; original documentation is **CC-BY-4.0**; vendored
third-party components keep their own licenses
([THIRD_PARTY_LICENSES.md](THIRD_PARTY_LICENSES.md)). Commercial licensing is
available separately from Vetra Automation AB
([details](COMMERCIAL-LICENSING.md)). "Garmr" and its logo are trademarks of Vetra
Automation AB and are not granted by these licenses
([TRADEMARKS.md](TRADEMARKS.md)). This is not legal advice.
