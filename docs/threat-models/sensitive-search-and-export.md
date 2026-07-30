# Threat model — sensitive search & export

Scope: the risk that the audit/monitoring layer itself becomes a surveillance and
exfiltration tool — that an analyst (or a compromised analyst session, or the LLM
tool loop) uses garmr's search, export, and AI surfaces to read or leak sensitive
data beyond a legitimate investigation. "The auditors must not become an unaudited
surveillance layer."

Companion: [insider-risk](insider-risk.md). Design:
[../architecture/hybrid-investigation-search.md](../architecture/hybrid-investigation-search.md),
[../architecture/model-routing.md](../architecture/model-routing.md);
[../access-audit.md](../access-audit.md) §top-note.

## Assets

- The **content** of sensitive audit records (who was investigated, what they
  contain).
- The **audit stream itself** — it reveals investigative interest and subjects.
- The **boundary against exfiltration** to external models and export sinks.

## Adversaries

| Adversary | Capability |
|-----------|-----------|
| Over-reaching analyst | authorized to investigate, snoops beyond scope |
| Compromised analyst session | an outsider with a valid session |
| Prompt-injected agent | steered by a crafted log line to retrieve/leak |
| Exfiltration path | data routed to an external model or export sink |

## Attack → defense

### 1. The auditor becomes a surveillance layer

- **Defense: RBAC on the audit stream + retention.** Access logs reveal who was
  investigated, so who may query them is restricted (RBAC via `GARMR_USERS`) and the
  audit stream has its own **retention window** ([../access-audit.md](../access-audit.md)
  top-note). A sensitive search is itself audited as `data.search_sensitive`
  (`crates/garmr-audit/src/event.rs:178`) in the tamper-evident ledger — so the
  watchers are watched, and an analyst's own searches are provable after the fact
  ([../threat-model-audit-integrity.md](../threat-model-audit-integrity.md)).

### 2. Search beyond authorization

- **Defense: authorization filters on search + safe-by-construction retrieval.**
  Retrieval runs under the caller's RBAC tier; the unified investigation search is a
  typed `HybridQuery` IR that is bounded, read-only, and injection-safe by
  construction (`crates/garmr-query/src/compile.rs`;
  [../architecture/hybrid-investigation-search.md](../architecture/hybrid-investigation-search.md)),
  so a model-authored query cannot widen its own scope or reach an arbitrary
  column. The target Phase-14 authorization filter constrains *which* records a tier
  may retrieve (not just whether the SQL is read-only), so a lower tier cannot pull
  a classification it may not see. Result rows are treated as attacker-controlled
  data everywhere (`crates/garmr-agent/src/ask.rs:69`).

### 3. Bulk export / `COPY` / mass extraction

- **Defense: export controls.** `COPY`/`UNLOAD`/`EXPORT` all fold to
  `QueryType::Copy` (`app_audit.rs:251`) and set `action.export_operation`
  (`app_audit.rs:411`); an export is a first-class, policy-gated, audited event
  (`data.export`, `event.rs:179`). The access-policy engine
  ([../architecture/access-policy-engine.md](../architecture/access-policy-engine.md))
  can `Deny` or `RequireJustification` on `export_operation` /
  `bulk_operation`, and UEBA flags an export off an actor's fingerprint/volume
  baseline. garmr's own read tools are bounded (`MAX_ROWS`/`MAX_ROW_CHARS`,
  `ask.rs:26-28`) so a single query cannot buffer a full table.

### 4. Exfiltration to an external model (the AI surface as a leak)

- **Defense: the egress ceiling + data-classification-aware routing.** Two hard,
  non-removable floors ([../architecture/model-routing.md](../architecture/model-routing.md)):
  - **restricted/confidential data never reaches an EXTERNAL model**
    (`EXTERNAL_CEILING = Internal`; config may only tighten; locality is derived
    from the endpoint host, not a flag);
  - **no silent fallback** — a denied local model resolves to the audited
    `NeedsHuman` state, never a quiet reroute to an external provider.

  Classification is lifted from the trigger event's canonical access fields
  (`classify_event`: a data subject ⇒ Confidential, a watched subject ⇒ Restricted)
  plus an explicit `data_classification` tag (`app_audit.rs:116`). Because free-text
  PII in a message body is NOT auto-classified, the operator mitigation is the
  **`default_classification` floor — set it to `confidential` for a register/PII
  deployment** (this also fail-closes the ask/hunt/rule surfaces off external
  models). `GARMR_AIRGAP=1` denies every external class outright and is
  unoverridable ([../architecture/model-routing.md](../architecture/model-routing.md);
  every route decision is audited as `egress.decision`, `event.rs:236`).

### 5. Prompt-injected retrieval / leak via the agent

- **Defense.** The agent is read-only + propose-only; tool output and log rows are
  data, never instructions (`ask.rs:69`); an external MCP tool call during a
  locally-routed case is a *separate* egress the chokepoint gates (closed under
  air-gap). A prompt-injected row can at worst skew summary prose, not trigger a
  retrieval it is not authorized for or an egress the policy forbids.

## The audit is itself sensitive (the meta-control)

Every control above rests on one stance: **the audit and its content are sensitive
assets**, not free-to-read operational logs. So the audit stream carries its own
RBAC, its own retention, its own classification floor for AI routing, and its own
tamper-evident record of who read it. An investigation surface that ignored this
would be a more efficient surveillance tool than the systems it audits.

## Residual risks

- An authorized, in-tier analyst who reads sensitive records **within** their
  mandate but for an illegitimate *purpose* is a policy/HR problem — bounded by the
  audit-of-the-audit and retention, detectable as a UEBA deviation, not prevented.
- Classification depends on correct tagging; an untagged PII field in a free-text
  message routes by the `default_classification` floor only — set it correctly for
  PII deployments (the documented operator responsibility,
  [../architecture/model-routing.md](../architecture/model-routing.md)).
- Retention is a trade-off: too long widens the surveillance surface, too short
  loses investigative history — the operator owns this per deployment.
