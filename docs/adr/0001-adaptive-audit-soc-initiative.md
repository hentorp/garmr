# ADR-0001: Adaptive-audit SOC initiative and non-negotiable invariants

- Status: Accepted
- Date: 2026-07-24
- Deciders: Lead architect / principal Rust / security / ML / test lead (single owner)
- Supersedes: none

## Context

garmr today is a working one-person agentic SOC: it ingests logs into a skade
(Iceberg) lakehouse, runs deterministic detection (Sigma, correlation,
frequency/template baselines, RBA), opens cases, and runs a read-only LLM triage
agent that emits a `Verdict`. State (cases, verdicts, budget) lives in an
embedded redb store. The console (Leptos/WASM) and 3D map (egui/WASM) sit on a
read-mostly serve API guarded by a passkey session or bearer token.

We now need garmr to be deployable as an **audit-first, adaptive** security
platform in **disconnected and air-gapped** environments (government, defense,
enterprise, industrial, OT/ICS). That raises requirements the prototype does not
yet meet:

- **Provable integrity** of what the system saw and did (tamper-evident audit).
- **Learning** the normal environment and improving from analyst feedback —
  **without** letting an attacker (or the agent's own mistakes) poison it.
- **Local-GPU inference** (vLLM/llama.cpp/Ollama over an OpenAI-compatible API)
  as the default reasoning path, with external model APIs allowed **only** by
  explicit policy.
- A **generic, domain-neutral core** rather than register-specific concepts.

The prototype conflates several things that a trustworthy platform must keep
apart: model output vs. human ground truth; novelty vs. anomaly vs. drift;
proposal vs. applied change; "we logged it" vs. "we can prove we logged it and
nobody tampered with it."

## Decision

We adopt an **adaptive-audit architecture** built on a small set of
non-negotiable invariants, implemented incrementally across 14 phases on branch
`feature/adaptive-audit-soc`. Each phase lands as compiling, tested,
documented code before the next begins.

### Non-negotiable invariants (enforced in code and tests)

1. **Air-gap is the default posture.** `GARMR_AIRGAP=1` overrides every other
   setting and forbids all external egress (external LLM APIs, online IOC feeds,
   remote MCP, telemetry, update checks, model downloads, any new integration).
   All outbound network access flows through one auditable egress chokepoint.

2. **The LLM never directly changes protected state.** The agent may search,
   investigate, explain, draft, recommend, propose. Every protected change
   (enable a rule, move a threshold, change a baseline, promote a model, change a
   prompt, silence an alert, run a response, export sensitive data, change egress
   policy) follows: **propose → validate → evaluate → human approval → apply →
   audit → rollback**.

3. **No unrestricted online learning.** The serving process never continuously
   fine-tunes a generative model from raw production logs. Learning is offline,
   on immutable content-addressed datasets, with temporal holdouts, shadow mode,
   champion/challenger evaluation, signed promotion, and rollback.

4. **The existing safety architecture is preserved, not weakened**: read-only
   agent tools, AST-level SQL guards, prompt-injection boundaries, human
   approval, a separate response executor, revalidation before execution, budget
   controls, replay and golden-set evaluation.

5. **The default deployment stays self-contained.** No mandatory dependency on
   Elasticsearch, OpenSearch, Loki, Kafka, Neo4j, external vector DBs, cloud
   services, or Python/Java runtimes. Optional integrations are feature-gated;
   Loki compatibility stays optional.

6. **Local GPU serving is an external local process.** No CUDA/vLLM embedded in
   the Rust process; garmr speaks an OpenAI-compatible API to a local server and
   owns routing, auth, capability discovery, health, queueing, timeouts, model
   identity, structured outputs, audit, and fallback policy.

7. **The generic core is domain-neutral.** Register-specific concepts move to an
   optional domain profile; the core speaks Actor, Identity, DataSubject,
   Resource, Asset, Service, Session, AccessOperation, Finding.

### Phase plan

1. Tamper-evident audit ledger (`garmr-audit`).
2. Event V2 + provenance (backward compatible).
3. Separate `AgentPrediction` / `AnalystDecision` / `IncidentOutcome`.
4. Model / prompt / detector / dataset registries.
5. Temporal environment model.
6. Hybrid agentic search (typed Query IR + persistent ANN).
7. Detector ensemble + drift + domain-neutral core.
8. Safe learning plane (`garmr-learning`).
9. Agent mistake learning (episodic/semantic/procedural memory).
10. Model router (local GPU + optional external).
11. Air-gap bundles + supply chain.
12. Collector reliability.
13. HA, backup, restore.
14. UI + explainability + security hardening.

## Consequences

**Positive.** Every security-relevant action becomes provable and offline-
verifiable. Predictions and human decisions become distinct immutable records,
so learning has trustworthy labels. The platform becomes deployable air-gapped
with local inference and honest degraded modes. Poisoning of baselines, labels,
and memory is structurally resisted rather than hoped against.

**Negative / cost.** More types, stores, and indirection (proposal pipelines,
registries, ledger). A durable audit write is added to high-risk paths — we cap
the default ingest-path regression at 10% (ADR required to exceed) and keep the
audit off the hot per-event ingest path. Migration surface grows; we mitigate
with versioned schemas, backward-compatible reads, and new versioned endpoints
instead of breaking existing ones.

**Neutral.** Several prototype shortcuts (single `Verdict` as both output and
truth; flat-file semantic scan; heuristic host classification) are replaced by
their principled successors; the old shapes remain readable for compatibility.

## Alternatives considered

- **Bolt audit on as tracing/log lines.** Rejected: logs are mutable and not
  offline-verifiable; invariant #1/#4 need a hash-chained, signed ledger.
- **Continuous/online model updates from production.** Rejected outright by
  invariant #3 (poisoning and non-reproducibility).
- **Let the agent apply low-risk changes directly.** Rejected by invariant #2;
  the propose→approve→apply→rollback pipeline is uniform with no privileged
  bypass for the model.
- **Depend on an external SIEM/vector DB for scale.** Rejected by invariant #5;
  self-contained default with feature-gated optional integrations instead.
