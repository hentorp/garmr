<!--
SPDX-FileCopyrightText: 2026 Vetra Automation AB
SPDX-License-Identifier: CC-BY-4.0
-->

# Testing

garmr ships several layers of verification, from unit tests to end-to-end offline
harnesses. This page lists them and the commands to run them.

## The workspace gate

Each change is expected to pass the same gate CI uses:

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
```

Clippy runs with `-D warnings` (warnings are errors). Tests cover the crates'
internal logic, including security-critical properties — for example the egress
chokepoint's parser (no userinfo-SSRF bypass, fail-closed on an unparseable
destination) is pinned by test, and a **source-walk lint**
(`crates/garmr-cli/tests/egress_chokepoint_lint.rs`) fails the build if a raw
outbound client is constructed outside the reviewed allowlist.

> **Resource note.** A full `--all-features` build/test pulls in the semantic
> (candle) stack and is memory- and CPU-intensive. On a constrained machine, build
> and test the features you need rather than everything at once.

## End-to-end, offline

These exercise real pipeline paths without needing a live warehouse or a cloud key:

- **`garmr selftest`** — runs the full agent tool-loop offline on a canned case.
  Point `[agent]` at a local model to run it entirely offline (see
  [../deployment/local-llm.md](../deployment/local-llm.md)).
- **`garmr replay <file>`** — feed a captured window (canonical event JSON / NDJSON,
  or raw syslog) through the pipeline.
- **`garmr correlate --hours N`** — run the correlation rules on demand, so you can
  author and verify a rule immediately.
- **`garmr eval <file>`** — replay a golden set of (alert → expected verdict) cases
  through the triage agent and score the verdicts (regression + calibration).
- **`garmr synth-eval`** — generate a labeled dataset (normal traffic plus injected
  known-attack scenarios), run it through the deterministic detection plane, and
  report which scenarios were caught plus the normal-event false-positive rate. This
  validates the shipped detectors offline (no warehouse).

## Detector shadow evaluation

A detector challenger registered on the `shadow` channel runs alongside the champion
without affecting production. Inspect the divergence — disagreement counts,
dangerous-miss count, and a recommended (human-gated) decision — with `garmr shadow`
(reads the live daemon's shadow summary). Nothing goes live without a human-approved
`registry promote`.

## Resilience and air-gap scenarios

`scripts/resilience-harness.sh` drives resilience / air-gap scenarios end to end. It
is safety-interlocked; read the script's own header before running it, and run it on
a disposable test instance, not a live SOC.

## Supply-chain checks

The supply-chain gate is reproducible on your own machine and runs in CI
(`.github/workflows/supply-chain.yml`):

```sh
cargo deny check          # licenses, advisories, bans, sources
bash scripts/sbom.sh      # regenerate the CycloneDX SBOM (deterministic)
```

See [release-process.md](release-process.md).

## Audit-ledger verification

`garmr audit verify` re-checks the tamper-evident ledger offline and exits non-zero
on any tampering, so it is suitable for CI or a monitoring cron.

## Writing tests

- Keep human-readable strings and test assertions in **English only** (a project
  rule). When you translate a message, translate its assertion together so tests
  keep matching.
- Prefer deterministic, offline tests; the pipeline is designed to be exercised
  without a live model (the agent's LLM calls are the only online part, and
  `selftest` runs them against a local backend).
