<!--
SPDX-FileCopyrightText: 2026 Vetra Automation AB
SPDX-License-Identifier: CC-BY-4.0
-->

# Changelog

All notable changes to Garmr are recorded here. Pre-1.0 releases carry **no
compatibility guarantee** — schemas, configuration keys, and APIs may break
between pre-releases.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versions follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html) with
alpha pre-release identifiers.

## [v0.1.0-alpha.1]

First public alpha. Evaluate in an isolated lab; this is not ready to be your
only line of production defence.

### Added

- Log ingestion (syslog, NDJSON over HTTP) into an Iceberg columnar lakehouse
  queryable with SQL, plus optional Loki-compatible and Arrow Flight receivers.
- Sigma-based detection, correlation rules, and a PostgreSQL/pgAudit parser with
  SQL-aware analysis.
- User-behaviour analytics: per-entity baselines, anomaly scoring, risk-based
  alerting, and silence detection.
- Tamper-evident audit ledger — hash-chained and ed25519-signed, verifiable
  offline.
- Full-text search, optional semantic search, and a link-analysis graph with
  attack paths.
- A read-only, propose-only LLM investigation agent, also reachable over MCP.
- Air-gapped operation: `GARMR_AIRGAP=1` closes a single egress chokepoint and
  overrides any `[route.egress]` allowlist.
- Web console (Leptos/WASM) as the single supported console.
- Supply-chain tooling: CycloneDX SBOM, `cargo deny` gates, reproducible release
  script, and signed air-gap bundles.

### Security

Secure-default behaviour verified by tests in this release:

- Native HTTP ingest and Arrow Flight ingest **fail closed** on a non-loopback
  bind when no collector authentication is configured — `garmr serve` refuses to
  start rather than serving an open ingest port.
- Native ingest authenticates the collector bearer token **before** decoding the
  body, allowlists the sources a collector may assert, rejects the **whole**
  batch when any event names a forbidden source, and stamps the trusted
  collector id server-side.
- Native ingest enforces request-body (8 MiB), events-per-request (50 000),
  message (256 KiB), and field-value (64 KiB) limits.
- Arrow Flight authenticates against the same collector registry, never trusts
  the legacy self-declared collector header, and enforces per-batch, per-stream,
  and receive-timeout caps.
- The query/console API fails closed on a non-loopback bind without
  `GARMR_API_TOKEN`.
- `/api/audit/status` and `/api/audit/verify` require admin credentials.
- Anonymous passkey login failures no longer write one durable audit record
  each; they are coalesced per window.

### Known limitations

Read [`docs/security/known-limitations.md`](docs/security/known-limitations.md)
before deploying. In brief:

- The optional **Loki-compat** receiver has **no authentication**, no
  fail-closed bind gate, no source binding, and no garmr-enforced size limits.
- **No listener has built-in TLS**, and none has request-frequency rate
  limiting; both must come from a reverse proxy or the network layer.
- `garmr pgaudit-ship` ships **raw** csvlog rows to native ingest — the pgAudit
  parser and SQL analysis run only in `garmr replay` and on the live Loki
  adapter, so the typed audit record projected from `pgaudit-ship` events is
  largely empty.
- Arrow Flight is **experimental** and off by default.
- Multi-node HA failover is unverified; online backup capture is deferred;
  response actions ship empty and require human approval.

### Release-preparation hardening

Changes made while preparing this public release:

- Reconciled the public security documentation with the code. The
  known-limitations page had been listing already-fixed issues as live
  vulnerabilities while omitting real ones; every claim is now checked against
  the implementation, with the covering test named.
- Corrected the README quick start, which claimed `garmr serve` "binds loopback
  by default". The query API does; native ingest binds `0.0.0.0:3100` and
  requires collector authentication there.
- Documented the pgAudit partial wiring described above, which was previously
  implied to be a full semantic path.
- Pinned every external GitHub Action to a full commit SHA, and added a CI gate
  that rejects unpinned actions.
- Made the CI `trunk` download checksum-verified against both an in-repo pin and
  the publisher's published digest.
- Added `scripts/check-doc-consistency.sh` (74 checks) so documentation claims
  cannot silently drift from the code, and wired it into CI.
- Added wire-level tests for native ingest authentication, which previously had
  none.
- Made CLA agreement a required, checked step rather than an optional one.

[v0.1.0-alpha.1]: https://github.com/hentorp/garmr/releases/tag/v0.1.0-alpha.1
