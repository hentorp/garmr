<!--
SPDX-FileCopyrightText: 2026 Vetra Automation AB
SPDX-License-Identifier: CC-BY-4.0
-->

# Architecture overview

garmr is a self-hosted Security Operations Center for a **single operator**, where
an agentic LLM analyst sits at the core of the pipeline rather than bolted on the
side. Logs come in, deterministic detections fire, and a **read-only** LLM agent
investigates each resulting case with a bounded set of read-only tools, then posts
an explainable, triaged verdict to a human. It is one Rust binary with an embedded
store — no external Grafana, Loki, Elasticsearch, or Wazuh.

> **Status: alpha, single-operator.** The end-to-end pipeline runs
> (ingest → store → detect/correlate → agentic triage → notify), but garmr is
> intended for **isolated lab evaluation**, not as the sole security control for a
> production estate or for exposure to untrusted networks without a reviewed
> configuration. See [status/alpha-status.md](../status/alpha-status.md) and
> [security/known-limitations.md](../security/known-limitations.md).

## The pipeline

```
 collectors ──HTTP JSON──▶ ingest ──▶ store ──▶ detection ──▶ agent ──▶ notify
  (your logs) /ingest/v1/events  Iceberg     Sigma · correlation   read-only    Matrix ·
              (auth optional)    lakehouse   · analytics · env      tool loop    webhook · SMTP
                                 + redb      model → one Case                    + web console
                                                                    │
        every protected change: propose → validate → human-approve → apply → AUDIT → rollback
```

The system is organized into cooperating **planes**, each with a defined trust
level and write discipline. This separation — not any single feature — is the
architecture. See [trust-model.md](trust-model.md) for the invariants that hold it
together.

## Components

Each plane maps to one or more crates under `crates/`.

### Ingest and storage

- **garmr-ingest** — a native, vendor-neutral HTTP endpoint
  (`POST /ingest/v1/events`, canonical JSON or NDJSON) that any collector able to
  POST JSON can speak (Vector, Fluent Bit, a cron job, `curl`), plus an optional
  syslog receiver. A **Loki push** endpoint and an experimental **Arrow Flight**
  endpoint are opt-in feature builds (`loki-compat`, `flight`). Collectors can be
  **authenticated** with a per-collector bearer token bound to specific sources.
  *Auth is optional today — see the ingest note in
  [security/known-limitations.md](../security/known-limitations.md).*
- **garmr-store** — an embedded Apache Iceberg lakehouse (the vendored **skade**
  engine) for columnar event history, queried with DataFusion SQL, plus an
  embedded **redb** store for agent/case state. One process owns the data; there
  is no external database.
- **garmr-retention** — seals aged event windows into immutable, checksum-verified
  cold archives (hot/cold tiering). See [storage.md](storage.md).
- **garmr-search** (Tantivy full-text) and **garmr-embed** (optional, pure-Rust
  embeddings behind the `semantic` feature) provide full-text and semantic
  retrieval. **garmr-enrich** adds RFC1918 / offline GeoIP / IOC-membership tags.

### Detection

- **garmr-detect** — Sigma rules evaluated per event. A burst collapses into one
  case.
- **garmr-correlate** — windowed, stateful multi-event rules (TOML + SQL): e.g. a
  brute-force burst *then* a success from the same source. A hit becomes a
  synthetic detection on the same case path.
- **garmr-analytics** — new-template anomaly detection, per-host (and per-actor)
  risk-based alerting (RBA), and frequency baselines, fused with a temporal
  environment model of learned asset/role facts.
- **garmr-appdetect / garmr-policy** — a first-class, **config-gated**
  application-audit detection plane (policy engine + stateless audit detectors).
  See [application-audit.md](application-audit.md).

### The agent

- **garmr-agent** — the differentiator: a bounded LLM tool-use loop over a
  **read-only** tool surface. It can *propose* an action but never execute one. A
  separate response executor is the only code that can act, and only on a
  human-approved, independently re-validated request. See
  [agent-safety.md](agent-safety.md).
- **garmr-query / garmr-graph** — a typed, safe-by-construction hybrid search IR
  fusing structured + full-text + semantic retrieval, and an in-memory entity
  graph for pivot / link analysis. See [guides/audit-search.md](../guides/audit-search.md).
- **garmr-llm** — one trait, two backends: the Anthropic Messages API and any
  OpenAI-compatible endpoint (Ollama / llama.cpp / vLLM), behind a model router
  that keeps classified data on a local model.

### Governance, safety, and consoles

- **garmr-audit** — an append-only, BLAKE3-chained, ed25519-signed,
  offline-verifiable audit ledger. Protected changes are recorded fail-closed.
- **garmr-learning** — an offline, LLM-free champion/challenger loop over
  immutable, content-addressed datasets: detectors can improve, but nothing goes
  live without a versioned registry record and a human-approved, audited
  promotion.
- **garmr-route** — human-approved silences and per-rule throttling in front of
  the notification channels (Matrix, webhook, SMTP).
- **garmr-webui** — the single supported analyst + administration console
  (Leptos/WASM over the serve API). It replaced the earlier native client
  (ADR-0002).

## What runs where

`garmr serve` is the daemon: it hosts the web console + read/query API (default
`127.0.0.1:3110`) and the ingest endpoint (default `0.0.0.0:3100`). Every other
`garmr` subcommand is one-shot and prefers the running daemon's API when one is
up; the raw-file commands (offline analysis, replay, backup) run when `serve` is
stopped, because the embedded store is single-process. See
[cli-reference.md](../cli-reference.md).

## Design stance

- **Local-first, domain-neutral core.** garmr is fully usable and `selftest`-able
  with no cloud key; the core carries no domain-specific vocabulary.
- **Air-gap by default is a first-class mode.** `GARMR_AIRGAP=1` closes a single
  egress chokepoint. See [deployment/airgap.md](../deployment/airgap.md).
- **Prediction, decision, and outcome are distinct.** The model's verdict is a
  prediction, never adjudicated truth; a human decision and a post-incident
  outcome are separate, append-only records.
- **Nothing goes live without a record and an audit event.** Prompts, toolsets,
  detectors, models, rules, and policies are content-addressed registry records;
  promotion is human-approved and tamper-evidently audited.
