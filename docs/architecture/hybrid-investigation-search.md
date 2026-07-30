# Hybrid investigation search — architecture (Phase 6 target)

Status: the typed Query IR and the deterministic executor are **done**
(`crates/garmr-query`, Phase 6 of the adaptive-audit initiative); unifying the
natural-language `ask` flow onto it, and persisting plans for reproduction, is the
Phase-6 deliverable of the audit-first evolution. See
[application-audit-analytics.md](application-audit-analytics.md).

## 1. Two search surfaces exist today; they should be one

garmr currently has two retrieval front-ends:

1. **Natural-language `ask`** (`crates/garmr-agent/src/ask.rs`) — the "ask, don't
   SPL" flow. A model translates the question into a `Plan` that is exactly one of
   **two modes**: read-only `Sql` over `events`, or a fulltext `Search`
   (`ask.rs:35`). garmr validates and executes it deterministically, then a second
   model call grounds the answer in the rows with `[n]` citations. The model never
   executes anything; the SQL passes the AST-level read-only guard
   (`reject_non_readonly`, `ask.rs:147`) and results are bounded
   (`MAX_ROWS`/`MAX_ROW_CHARS`, `ask.rs:26-28`) and treated as attacker-controlled
   data (`ANSWER_SYSTEM`, `ask.rs:69`).

2. **The typed hybrid Query IR** (`crates/garmr-query`) — a `HybridQuery`
   (`ir.rs:29`) carrying a structured filter, an optional full-text clause, and an
   optional semantic clause, fused with Reciprocal Rank Fusion. It backs the
   agent's `hybrid_search` tool (`crates/garmr-agent/src/tools/mod.rs:167`),
   `POST /api/hsearch` (`crates/garmr-cli/src/api/hsearch.rs:29`), and `garmr
   hsearch`.

The `ask` SQL mode is the **larger injection surface** (a whole model-authored
`SELECT`, guarded only by an AST check). The target is to make `ask` *plan into the
typed IR* instead of raw SQL — shrinking the read plane's largest injection
surface to the one already proven safe by construction.

## 2. The typed IR is safe by construction

`HybridQuery` (`ir.rs`) is the seam that makes model-authored retrieval safe:

- **Every struct is `#[serde(default, deny_unknown_fields)]`** (`ir.rs:28`) — a
  typo'd key is a HARD error, never a silently-dropped predicate that would widen a
  filter.
- **The filter is a closed, typed per-column set** (`StructuredFilter`,
  `ir.rs:44`) — the six event labels plus generic `fields` key=value predicates.
  An "arbitrary column" is *unrepresentable*, which is the root of the
  injection-safety guarantee.
- **`validate()` clamps and bounds** (`ir.rs:182`): fusion knobs clamped
  (`MAX_LIMIT`/`MAX_PER_SIGNAL_K`/`MAX_CANDIDATE_CAP`), an entirely unbounded query
  rejected, every model-supplied value length- and NUL-checked, field keys
  restricted to `[A-Za-z0-9_.-]` (`is_valid_field_key`, `ir.rs:169`), and the time
  window bounded to at most a leap year.
- **Compilation is a closed identifier set + single value chokepoint**
  (`compile.rs`): the table, columns, projection, `ORDER BY`, and `LIMIT` are
  compile-time constants (`compile.rs:1-19`); input reaches SQL only inside a
  quoted literal (`sql_lit`, `compile.rs:28`) or a `LIKE … ESCAPE '\'` pattern with
  key AND value escaped (`like_escape`, `compile.rs:36`). Exactly one bounded
  `SELECT` is emitted (`compile.rs:117`). An injection attempt becomes an inert
  literal (test, `compile.rs:150`).
- **Defense in depth at execution** (`exec.rs:44`): the compiled string is still
  re-checked with `reject_non_readonly` and run under a 60s timeout — never
  trusting the compiler.

The three signals — structured (the gate), full-text (Tantivy BM25), semantic
(local embedding cosine) — are fused with RRF (rank-only, so heterogeneous scores
need no calibration, `ir.rs:144`). Each result carries **per-signal provenance**
(`SignalMatch` with signal tag `S`/`F`/`V`, rank, raw score — `result.rs:33,50`),
so an ordering is explainable, not opaque. A semantic hit reinforces all events
sharing its `(host,service,message)` triple rather than one timestamp it cannot
name (`fuse.rs:5-11`).

## 3. Target: one plan type, typed / validated / authorized / cost-bounded / audited / reproducible

The unified investigation plan is a `HybridQuery` (plus a natural-language
question and the two-call grounding of `ask`). Every property the two surfaces have
today is preserved and made uniform:

- **Typed** — the plan is the IR, not a free-text SQL string.
- **Validated** — `HybridQuery::validate` (`ir.rs:182`) before execution.
- **Authorized** — the search runs under the caller's RBAC tier; a sensitive
  search is audited as `data.search_sensitive` (`event.rs:178`) and subject to
  authorization filters (see
  [../threat-models/sensitive-search-and-export.md](../threat-models/sensitive-search-and-export.md)).
- **Cost-bounded** — the `ask` grounding calls charge the daily USD ledger with a
  cancellation-safe reservation (`ask.rs:97`); retrieval itself is bounded by the
  IR clamps + query timeout.
- **Audited** — the plan and the model/prompt/toolset digests are stamped on the
  immutable `AgentPrediction` (`learning-plane.md`), and a sensitive query hits the
  audit ledger.
- **Reproducible** — see §4.

## 4. Reproduce without an LLM

The IR executor is already deterministic and LLM-free: `Executor::run`
(`exec.rs:28`) runs a `HybridQuery` against the lakehouse + Tantivy + an injected
semantic backend and fuses — no model in the loop. So **reproduction = re-run the
persisted IR**, no LLM required.

The Phase-6 target adds the persistence needed to make that a first-class button:

- persist the **exact `HybridQuery` IR** the plan resolved to (already fully
  serializable, `ir.rs`), pinned to the `AgentPrediction` that produced it;
- pin the **event id set** returned (stable `event_id`s, `schema.rs:80`) so a
  re-run over the same warehouse is verifiable even as new data arrives;
- pin the **semantic index/model version** (a semantic clause is only reproducible
  against the same embedding model — `SemanticStatus` already reports availability
  honestly, `result.rs`, so a missing model is visible, never silently dropped).

A `reproduce(prediction_id)` function (target) deserializes the stored IR and
calls `Executor::run` directly, bypassing both model calls — turning "the agent
concluded X from these rows" into an offline-verifiable claim. This is the
retrieval-side analogue of the learning plane's replay path
(`learning-plane.md`).

## 5. What the unified surface must not do

- Never let a model author a raw SQL string where the typed IR can express the
  query (shrink the injection surface).
- Never drop a requested semantic clause silently — report it unavailable
  (`SemanticStatus::RequestedButUnavailable`, `exec.rs:89`).
- Never treat result rows as instructions — they are attacker-controlled data
  (`ask.rs:69`); a prompt-injected log line can at worst skew summary prose, never
  trigger an action (the flow has no tools).
