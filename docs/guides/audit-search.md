<!--
SPDX-FileCopyrightText: 2026 Vetra Automation AB
SPDX-License-Identifier: CC-BY-4.0
-->

# Guide: searching and investigating

garmr gives you several complementary ways to search your event history and pivot
through an investigation. They share one storage backend and one safe retrieval
layer, so you can move from a broad question to a precise query without switching
tools. All read surfaces run under the caller's RBAC tier, and a sensitive search is
itself audited.

## The search surfaces

| Surface | Use it for | Needs |
|---|---|---|
| `garmr query "<SQL>"` | Precise, structured questions in read-only SQL over `events` | — |
| `garmr search "<terms>"` | Full-text keyword search over messages (Tantivy syntax) | — |
| `garmr semantic "<phrase>"` | Find events by **meaning** (embedding cosine) | `semantic` build + `GARMR_EMBED_MODEL` |
| `garmr hsearch "<query>"` | **Hybrid** structured + full-text + (semantic) fused search | semantic clause needs the `semantic` build |
| `garmr ask "<question>"` | A natural-language question, answered with cited rows | an LLM backend + budget |

The same capabilities are available in the web console and over the serve API
(`POST /api/hsearch`, `/api/query`, `/api/query/cold`, etc.).

## Structured SQL

```sh
garmr query "SELECT log_type, count(*) FROM events GROUP BY 1 ORDER BY 2 DESC"
```

Queries are **read-only** and bounded. For sealed cold-tier history, use
`garmr cold-query "<SELECT…>" --from <rfc3339> --to <rfc3339>` (offline, serve
stopped) or `GET /api/query/cold` (bound the range).

## Full-text and semantic

```sh
garmr search "failed password"          # bare terms hit the message
garmr search "host:app-01 invalid"      # field-qualified Tantivy syntax
garmr semantic "someone brute forcing SSH"   # meaning, not keywords
```

Semantic search needs the `semantic` build and a local embedding model directory
(`GARMR_EMBED_MODEL`), and queries the index built by `garmr embed-index`. Without
the `semantic` feature, garmr is structured + full-text only.

## Hybrid search (recommended default)

`hsearch` fuses three signals — structured filter (the gate), full-text (BM25), and
(with the `semantic` build) semantic cosine — with Reciprocal Rank Fusion, and tags
each result with per-signal provenance (`[S]` structured / `[F]` full-text / `[V]`
semantic):

```sh
garmr hsearch "failed login from a new host"
```

Hybrid search composes the **typed query IR**, not raw SQL. That IR is safe by
construction: a closed, typed, per-column filter, bounded and validated, compiled so
that no input can widen the query's scope or reach an arbitrary column. This is why
the same IR is safe to expose to the agent. See
[../architecture/agent-safety.md](../architecture/agent-safety.md) and
[../architecture/hybrid-investigation-search.md](../architecture/hybrid-investigation-search.md).

## Natural language ("ask, don't SPL")

```sh
garmr ask "which hosts had the most failed logins in the last 24 hours?"
```

The model plans a **read-only** query, garmr executes it deterministically, and a
second model call grounds the answer in the returned rows with `[n]` citations. The
model never executes anything; result rows are treated as attacker-controlled data,
and the flow is cost-bounded (it charges the daily budget). `ask` needs an LLM
backend (Anthropic or a local OpenAI-compatible endpoint).

## Pivoting an investigation

- **Entity pages** — `garmr entity <kind> <name>` (host / ip / user, and the
  audit-specific `staff` actor / `person` subject) renders one entity as a single
  document: volume, history, recent events, and every case it triggered
  (institutional memory).
- **The graph** — `garmr graph <kind> <name>` does link analysis over cases
  (host ↔ ip ↔ user ↔ case): "show everything connected to this IP", or the shortest
  path / attack paths between two entities. Built in-memory, read-only.
- **Cases** — `garmr cases list` and `garmr cases show <id>` (the full agent
  transcript and verdict for a triaged case).

## Reproducibility

The hybrid IR executor is deterministic and LLM-free — re-running a persisted query
reproduces its results without a model in the loop. A missing semantic model is
reported as unavailable, never silently dropped, so a result set is honest about
which signals contributed.

## A note on live-data searches

On a live, high-volume stream, a broad full-text query over a very common term can
return an enormous match set and take a long time to render. Prefer a **specific,
low-cardinality** term (or a structured filter) when you want a fast answer.
