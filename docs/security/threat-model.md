<!--
SPDX-FileCopyrightText: 2026 Vetra Automation AB
SPDX-License-Identifier: CC-BY-4.0
-->

# Threat model

This page is the consolidated threat model: the adversaries garmr defends against,
the controls in place, and the residual risks. It summarizes the detailed
per-adversary models and points to them for the full attack→defense tables:

- [insider-risk](../threat-models/insider-risk.md) — the authorized user who abuses
  access.
- [sensitive-search-and-export](../threat-models/sensitive-search-and-export.md) —
  the audit layer itself becoming a surveillance/exfiltration tool.
- [audit-log-poisoning](../threat-models/audit-log-poisoning.md) — forging,
  injecting, or dropping ingested audit events.
- [baseline-poisoning](../threat-models/baseline-poisoning.md) — training "normal"
  to include misuse.
- [audit-integrity](../threat-model-audit-integrity.md) and
  [learning-and-poisoning](../threat-model-learning-and-poisoning.md) — the
  cross-cutting integrity and learning models.

Read this together with [known-limitations.md](known-limitations.md), which lists
the surfaces that are **not** yet hardened.

## Scope and assumptions

- **Deployment assumption.** garmr is designed for a **single operator** in an
  **isolated lab / trusted-network** setting. It is **not** hardened for exposure
  to untrusted networks (see [known-limitations.md](known-limitations.md)).
- **In scope:** the integrity of garmr's own actions; the confidentiality of
  sensitive audit content; resistance to poisoning of learned baselines; the
  read-only/propose-only boundary around the agent; prompt injection via log
  content.
- **Out of scope / assumed trusted:** the host OS and its root, the operator's
  workstation and passkeys, the collectors' host integrity, and (today) the network
  path to the ingest endpoints.

## Adversaries and primary defenses

### The authorized insider

An actor with valid credentials and role who snoops, enumerates, or exfiltrates.
Integrity controls do not help (the events are real); the defense is the layered
combination of:

- **Explicit policy** — a forbidden action is denied deterministically on the first
  offense, no baseline needed.
- **Behavioral analytics** — deviation from a trusted baseline, when one exists
  (abstains on novelty).
- **Weak-signal RBA** — low-and-slow misuse spread below every threshold still
  accrues a per-actor risk sum and opens a case.
- **Monitoring** — raises attention (a score multiplier), never declares guilt.

Residual: an insider acting entirely within role, justification, baseline, and
policy is invisible to behavioral controls — bounded by least-privilege and
after-the-fact investigation.

### The over-reaching auditor / exfiltration path

The audit layer itself as a surveillance or leak tool (an over-reaching analyst, a
compromised session, or a prompt-injected agent). Defenses:

- **RBAC + retention on the audit stream** — restrict who may query it; a sensitive
  search is itself audited.
- **Safe-by-construction retrieval** — the typed query IR is bounded, read-only, and
  cannot widen its own scope or reach an arbitrary column.
- **Export controls** — `COPY`/`UNLOAD`/`EXPORT` is a first-class, policy-gated,
  audited event; garmr's own read tools are row-bounded.
- **Egress ceiling** — restricted/confidential data never reaches an external model;
  no silent fallback; every route decision audited; `GARMR_AIRGAP=1` denies all
  external egress.

Residual: classification depends on correct tagging; free-text PII routes by the
`default_classification` floor only — set it for PII deployments.

### The audit-stream poisoner

An adversary who forges, injects, drops, or tampers with **ingested** audit events.
Defenses:

- **Content-addressed provenance** — `event_id` and `raw_payload_hash` make
  post-ingest tampering and replay detectable.
- **Per-collector sequence tracking** — an authenticated collector stamps a
  monotonic sequence; a confirmed gap is audited (silent tail-drops are caught).
- **Authenticated collector binding** — a source is bound to a trusted collector id,
  not a self-declared string, so one compromised collector can forge only its own
  single source; unauthenticated events are dropped by the learner in bind mode.
- **Parser health** — a degraded parser drives baselines to abstain rather than
  emit garbage.

Residual: a fully compromised producer host can emit self-consistent forged rows
under its own valid collector token, bounded to that one source's scope. Binding
governs future learning only — configure it before enabling learning. **Note:** the
integrity controls above assume authenticated collectors; the ingest transport
itself is not yet hardened (see [known-limitations.md](known-limitations.md)).

### The baseline poisoner

An adversary who slowly trains "normal" to include misuse. Defenses:

- **Candidate vs. trusted split** — a new behavior is only a Candidate; it becomes
  trusted only through the anti-poisoning gate (quarantine age, minimum
  observations, minimum *distinct authenticated* sources, per-source influence cap).
- **Inviolable hard blocks** — an open/malicious case touching an entity blocks
  promotion, and no one (not even an analyst) can clear it, so misuse under
  investigation can never teach the baseline.
- **The trusted-view gate** — detectors read only trusted facts; a Candidate,
  Suspicious, or forged fact can never be read as "normal".
- **Trusted-labels-only learning** — training rows come only from human decisions
  and incident outcomes, never from unresolved self-predictions.
- **Overriding invariant** — forbidden-by-policy is never learnable as normal.

Residual: a patient adversary who also controls the analyst and stays under every
cap can bias slowly — bounded by holdouts, drift monitoring, and audited
promotions, not eliminated.

### The prompt injector

A crafted log line that tries to steer the agent. Defense: the agent is read-only
and propose-only; tool output and log rows are treated as attacker-controlled data,
never instructions; the grounding flow has no tools. A prompt-injected row can at
worst skew summary prose — not trigger an action or an unauthorized retrieval.

## garmr's own integrity

Every security-relevant action garmr takes is recorded in the append-only,
BLAKE3-chained, ed25519-signed audit ledger, offline-verifiable with `garmr audit
verify` (fail-closed for high-risk operations). This bounds an attacker who
compromises garmr, not just the upstream producer.

## Unhardened surfaces (must-read)

The ingest transport (native/Loki/Flight), and the audit-status/verify and
passkey-login-finish denial-of-service surfaces, are **not** yet hardened. They are
documented plainly in [known-limitations.md](known-limitations.md) and are the
reason garmr must not be exposed to untrusted networks without the mitigations
listed there.
