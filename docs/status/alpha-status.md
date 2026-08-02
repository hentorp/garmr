<!--
SPDX-FileCopyrightText: 2026 Vetra Automation AB
SPDX-License-Identifier: CC-BY-4.0
-->

# Alpha status

garmr is **alpha** software, built and sized for a **single operator** evaluating
it in an **isolated lab**. This page states plainly what that means, what works,
what is experimental, and what is planned — so you can decide whether it fits your
use before you invest in it.

## What "alpha for lab evaluation" means

- garmr is intended for **isolated lab evaluation**, not as the **sole production
  security control** for a real estate, and not for exposure to **untrusted
  networks** without a reviewed configuration.
- The full pipeline runs end to end (ingest → store → detect/correlate → agentic
  triage → notify), but interfaces, config keys, and on-disk formats may change.
- The agent **proposes** — it does not approve or execute actions. A human approves,
  and a separate executor (which ships with no capabilities wired) re-validates and
  acts.
- Some capabilities require feature flags or config; some are experimental or
  planned. See the status table below.

Before any exposure beyond an isolated lab, read
[security/known-limitations.md](../security/known-limitations.md) and
[security/threat-model.md](../security/threat-model.md). The most important gaps
today:

- **The Loki-compat receiver has no authentication and no fail-closed bind gate.**
  Native ingest and Arrow Flight both refuse a non-loopback bind without
  configured collectors; the Loki path does not, and never consults the collector
  registry. It is the weakest surface in the tree.
- **No listener has built-in TLS or rate limiting.** Transport encryption and
  request-frequency limits must come from a reverse proxy or the network layer.
- **`garmr pgaudit-ship` does not run the pgAudit/SQL semantic parser.** The
  recommended collector ships raw csvlog rows to native ingest, which applies only
  the generic field extractor. Full pg parsing runs on the offline `replay` path
  and on the (unauthenticated) live Loki path. See known-limitations.
- **Audit verification and passkey login remain uncapped in frequency**, though
  both were tightened: audit status/verify are now admin-gated, and anonymous
  failed-login audit writes are coalesced.

## Status legend

- **Implemented / runtime-wired** — built and running in `garmr serve`.
- **Config-gated** — implemented, off unless a config key / env var enables it.
- **Feature-gated** — requires a Cargo build feature.
- **Experimental** — implemented but not verified for production-like conditions.
- **Planned / in progress** — designed (and sometimes partly built); not something
  to rely on yet.

## Status by area

| Area | Status |
|---|---|
| Native HTTP ingest (`/ingest/v1/events`) | Implemented, runtime-wired; **fails closed** on a non-loopback bind without collectors, enforces body/event/message/field limits. No TLS, no rate limiting. |
| Loki push ingest | Feature-gated (`loki-compat`); **no authentication, no fail-closed bind gate, no garmr-enforced limits** — the weakest surface |
| Arrow Flight ingest | Feature-gated (`flight`), **off by default**; **experimental**. Authenticates against the collector registry, fails closed off-loopback, enforces per-batch/per-stream/timeout caps. No TLS. |
| Authenticated collectors (`GARMR_COLLECTORS`) | Config-gated; **enforced by the native and Flight bind gates** (not consulted on the Loki path) |
| Iceberg warehouse + redb state + full-text index | Implemented, runtime-wired |
| Semantic search / embeddings | Feature-gated (`semantic`) + local model (`GARMR_EMBED_MODEL`) |
| Hot/cold retention tiering | Config-gated (`[retention] enabled`) |
| Sigma detection + correlation rules | Implemented, runtime-wired |
| Anomaly / RBA / frequency baselines / environment model | Implemented, runtime-wired |
| Application-audit detection plane (policy + audit detectors + catalog + monitoring) | Config-gated (`[detect] app_audit_enabled`) |
| Multidimensional UEBA (per-dimension baselines, peer groups, service-account profiling) | Partly implemented / **planned** |
| PostgreSQL / pgAudit ingestion | Partly wired: `pgaudit-ship` delivers authenticated + durable but **unparsed** rows; full pg/SQL parsing runs only in `replay` and the `loki-compat` live adapter |
| Read-only triage agent + propose-only executor + change pipeline | Implemented, runtime-wired |
| Typed hybrid search IR (safe by construction) | Implemented, runtime-wired |
| Model router (classification-aware; keeps classified data local) | Implemented (minimum viable); role-based routing is a design target |
| Local LLM backend (Ollama / llama.cpp / vLLM) | Implemented; the only mode under air-gap |
| External LLM (Anthropic) | Optional, egress-policy controlled |
| Egress chokepoint + `GARMR_AIRGAP` | Implemented, runtime-wired, lint-backed |
| Tamper-evident audit ledger + offline verify | Implemented, runtime-wired |
| Governed registry (versioned, audited) | Implemented; registry-backed policy/catalog/monitoring enforcement config-gated |
| Offline learning plane (champion/challenger) | Implemented (minimum viable) |
| Bearer-token RBAC | Implemented, runtime-wired; API fails closed off-loopback |
| Passkey / WebAuthn login | Implemented (needs HTTPS + real hostname); anonymous failed-login audit writes are coalesced — **still no rate limiting** |
| Backup / restore / single-host promotion | Implemented (minimum viable); online capture deferred |
| Multi-node HA failover | **Experimental / unverified** (single-host only) |
| Supply chain (SBOM, `cargo deny`, signed releases, air-gap bundles) | Implemented |
| Web console (Leptos/WASM) | Implemented, runtime-wired (the single supported console) |

## Explicitly not claimed

- Not a distributed system: HA is one writer + read-only followers, **not**
  distributed consensus, and multi-node failover is unverified.
- Not a hardened multi-tenant service: it is a single-operator tool.
- Not a turnkey production SIEM/SOAR: response actions ship empty and must be wired
  and human-approved.
- The agent's verdict is a **prediction**, not adjudicated incident truth.

## Reporting problems

Use the issue templates under `.github/ISSUE_TEMPLATE/`. **Do not** report suspected
vulnerabilities in public issues — follow the private disclosure process in
`SECURITY.md`, and never paste secrets or real audit-log content into a report.
