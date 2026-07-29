<!--
SPDX-FileCopyrightText: 2026 Vetra Automation AB
SPDX-License-Identifier: CC-BY-4.0
-->

# Agent safety

garmr puts an LLM at the center of triage. This page explains the controls that
make that safe: the agent is read-only, it proposes but never acts, its retrieval
is safe by construction, its cost is bounded, and its network egress is gated
through one chokepoint. See [trust-model.md](trust-model.md) for the invariants
these controls implement.

## The agent proposes; it never acts

The triage agent (`garmr-agent`) runs a bounded tool-use loop over a **read-only**
tool surface: query event history, run the hybrid search IR, pivot the entity
graph, check the baseline / environment model, and search past cases. Its output
is a single **AgentPrediction** — a disposition, severity, rationale, evidence
references, and optionally *proposed* actions. That prediction is never consumed as
adjudicated truth (see [trust-model.md](trust-model.md)).

A **separate response executor** is the only code that can change external system
state, and it acts only under a uniform change pipeline:

```
propose → validate → evaluate → human approval → apply → audit → rollback
```

Properties the executor enforces:

- **Independent re-validation at apply time** — it never trusts the stored
  proposal.
- **At-most-once** — the state flips to `Executing` and is persisted *before* any
  side effect; a crash leaves a claimed action for human reconciliation, never a
  silent re-run.
- **Reversibility gate + evidence attestation** — a change must be justified by the
  case's own evidence.
- **A full audit record** per transition.

garmr ships **no** response capability by default: each action must be wired to an
argv template under `[executor]` first, and the executor loop is opt-in
(`[executor] enabled`). Approvals are RBAC-gated (admin), and the authenticated
approval *is* the human sign-off.

## Retrieval is safe by construction

The agent retrieves through a typed **hybrid query IR** (`garmr-query`), not raw
SQL. The IR is the seam that makes model-authored retrieval safe:

- Every struct is `deny_unknown_fields`, so a typo'd key is a hard error, never a
  silently widened filter.
- The filter is a closed, typed, per-column set — an "arbitrary column" is
  unrepresentable.
- `validate()` clamps limits, bounds the time window, and length/NUL-checks every
  model-supplied value.
- Compilation uses a closed identifier set: the table, columns, projection,
  `ORDER BY`, and `LIMIT` are compile-time constants, and input reaches SQL only
  inside a quoted literal (or a doubly-escaped `LIKE` pattern). An injection
  attempt becomes an inert literal.
- As defense in depth, the compiled string is re-checked read-only and run under a
  timeout.

The older natural-language `ask` flow (which plans one read-only SQL `SELECT` or a
full-text search) passes an AST-level read-only guard and bounds its result rows.
Result rows are treated as **attacker-controlled data** everywhere — a
prompt-injected log line cannot make the flow execute a tool, because the grounding
step has no tools.

## Cost is bounded

Each case has an iteration and token ceiling, and a global **daily USD budget**
ledger tracks spend with cancellation-safe reservations. When the budget is
exhausted, cases queue for a human instead of running unbounded. Local inference is
free, so the budget gate is effectively a no-op on a local model.

garmr is **fully functional without any LLM** (invariant #7): ingest continues,
deterministic detections fire, cases open, and queries work; agent triage is simply
queued or marked unavailable, and health reports the missing model clearly.

## Egress is gated through one chokepoint

Every outbound-capable component resolves an `EgressPolicy` decision at
client-construction time. The classes are the LLM providers (Anthropic + any
OpenAI-compatible base URL), the notifier sinks (Matrix / webhook / SMTP), the
external MCP client spawn, IOC feed refresh, and the S3 object store (cold tier /
HA).

- `GARMR_AIRGAP=1` denies every external class outright and is **unoverridable** by
  any other config. Only local-loopback / private-range destinations classified
  `local` are permitted.
- Every egress decision is **audited**.
- **No silent fallback** — a denied local model resolves to the audited
  `NeedsHuman` state, never a quiet reroute to an external provider.
- A source-walk lint fails the build if a raw outbound client is constructed
  outside the reviewed allowlist — the structural backing for "no bypass".

See [deployment/airgap.md](../deployment/airgap.md).

## Keeping classified data local (model routing)

The model router selects exactly one model per case by **data classification +
air-gap + availability**, over the same chokepoint. Two hard, non-removable floors:

- **Restricted/confidential data never reaches an external model.** Locality is
  derived from the endpoint host, not a flag; config may only tighten.
- **No silent fallback**, as above.

Honest residuals the operator owns:

- Classification is lifted from the trigger event's canonical access fields plus an
  explicit `data_classification` tag. **Free-text PII in a message body is not
  auto-classified** — the mitigation is to set `default_classification =
  "confidential"` for a register/PII deployment, which also fail-closes the
  ask/hunt/rule surfaces off external models.
- The router gates the *model* endpoint. An external MCP tool call during a
  locally-routed case is a separate egress that the chokepoint gates (and air-gap
  closes entirely).
- The base `[agent]` provider must be policy-constructible: in an air-gapped
  deployment, point `[agent]` at a local endpoint or startup fails — the model
  catalog does not make an external `[agent]` constructible.

## Status of the pieces

- **Read-only agent + propose-only executor + change pipeline** — Implemented,
  runtime-wired.
- **Typed hybrid query IR (safe-by-construction retrieval)** — Implemented.
- **Egress chokepoint + `GARMR_AIRGAP`** — Implemented, runtime-wired, lint-backed.
- **Model router (classification-aware, one model per case)** — Implemented
  (minimum viable); the fuller role-based routing vocabulary is a design target.
- **External model use** — Optional and egress-policy controlled; a local model is
  first-class and the only mode under air-gap.
