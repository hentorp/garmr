<!--
SPDX-FileCopyrightText: 2026 Vetra Automation AB
SPDX-License-Identifier: CC-BY-4.0
-->

# Trust model

garmr's safety rests on a small set of invariants and on keeping distinct concepts
distinct. This page states the invariants, the trust levels of each plane, and the
concepts the system deliberately never collapses. It is the conceptual companion to
the concrete controls in [agent-safety.md](agent-safety.md),
[storage.md](storage.md), and the [threat model](../security/threat-model.md).

## Core invariants

1. **The agent is read-only and propose-only.** The LLM detects, explains, and
   *proposes*. It never mutates protected state or executes an action directly. A
   separate executor is the only thing that can act, and only on a human-approved,
   independently re-validated request.
2. **Nothing goes live without a record and an audit event.** Prompts, toolsets,
   detectors, models, rules, and policies are content-addressed registry records;
   promotion is a human-approved, tamper-evidently audited transition, reversible
   by rollback.
3. **No unrestricted online learning.** Learning is offline and gated. The
   temporal environment model auto-promotes facts only through a two-tier
   anti-poisoning gate, and only over authenticated collector sources.
4. **Log contents are evidence, not instructions.** Log lines and any untrusted
   text are treated as hostile input to analyze, never as commands. A prompt-
   injected log line can at worst skew summary prose; it cannot trigger an action
   or a retrieval the caller is not authorized for.
5. **Air-gap is a single, loud switch.** `GARMR_AIRGAP=1` denies every outbound
   egress class through one chokepoint and cannot be re-enabled by any other
   config.
6. **Bounded cost.** A per-case iteration/token ceiling and a global daily USD
   budget; when the budget is exhausted, cases queue for a human rather than
   silently degrading.
7. **Local-first, domain-neutral core.** garmr is fully usable and `selftest`-able
   with no cloud key; the core carries no domain-specific vocabulary.

## Trust levels of the planes

| Plane | Trust | Write discipline |
|---|---|---|
| Ingest | Untrusted input | Normalizes; stamps provenance; never executes content |
| Data (warehouse / index / graph) | System-owned | Single writer; content-addressed, immutable event history |
| Detection | Deterministic | Emits findings; never acts |
| Agent (read-only) | Untrusted output | Reads via bounded tools; emits a *prediction* only |
| Decision | Human authority | Append-only human decisions and incident outcomes |
| Change / executor | Privileged | Acts only on a human-approved, re-validated proposal |
| Learning | Offline, gated | Trusted-labels only; promotion is human-approved + audited |
| Audit ledger | Cross-cutting | Append-only, hash-chained, signed; fail-closed for high-risk ops |

## Prediction ≠ decision ≠ outcome

The single most load-bearing split: the model's verdict is a **prediction**, not
adjudicated truth. Three distinct, append-only record types replace any single
mutable "verdict":

- **AgentPrediction** — what the model concluded (with model/prompt/toolset
  digests, evidence references, and cost).
- **AnalystDecision** — what a human decided (never overwrites a prior decision;
  corrections *supersede*).
- **IncidentOutcome** — the post-incident ground truth, including false negatives
  that never generated a case.

Risk scoring and all learning consume **trusted outcome first, discounted
prediction otherwise, and never give positive weight to an unresolved
self-prediction** — so the system cannot be trained on its own guesses.

## Concepts kept distinct

A trustworthy audit-analytics platform must not collapse these into a single
"alert":

- **Explicit policy violation** (a forbidden action occurred) — decided
  deterministically by the policy engine.
- **Behavioral anomaly** (deviates from a trusted baseline) — decided by
  behavioral detectors, and only when a baseline exists.
- **Novel behavior** (never seen before, no baseline yet) — detectors *abstain*
  rather than treat novelty as anomaly.
- **Expected operational change** (a maintenance window explains it) — the
  environment model.
- **Concept drift** (the world legitimately changed) — flagged as drift, never
  auto-absorbed as normal.
- **Weak risk indicator** (sub-threshold on its own) — accrues via RBA.

Two rules govern this taxonomy:

> **A forbidden action stays forbidden no matter how frequent.** Frequency and
> baselines can only ever *raise* attention, never legitimize an explicit policy
> violation. The policy engine sits **beside**, not downstream of, the anomaly
> plane; an explicit deny overrides any learned "this is normal now".

> **Monitoring raises attention, not guilt.** A user-monitoring profile can only
> raise a finding's score (a multiplier ≥ 1.0); it never declares wrongdoing. A
> notification is an attention signal, not a determination of incident truth.

## Candidate baselines are not trusted

A newly observed behavior or environment fact is a **Candidate**, not a fact the
detectors may treat as normal. It becomes trusted only through an anti-poisoning
gate (quarantine age, minimum observations, minimum *distinct authenticated*
sources, and a per-source influence cap). An open or malicious case touching an
entity is a **hard block** on promotion that no one — not even an analyst — can
clear, so misuse under investigation can never teach the baseline. Detectors read
only the trusted view; a Candidate, Suspicious, or forged fact can never be read
as "normal". See [security/threat-model.md](../security/threat-model.md).

## Where the trust boundary ends (honest residuals)

- The egress chokepoint governs garmr's **own** autonomous egress. A human-approved
  executor subprocess, and separate operator CLI/MCP processes, are outside it (the
  human approval is the gate there).
- Integrity controls cannot distinguish "real misuse" from "real use" by an
  authorized identity — that is the job of behavioral analytics and policy, not the
  integrity layer.
- Collector source-binding governs *future* learning only; configure authenticated
  collectors before enabling environment learning.

These are documented residuals, not hidden gaps.
