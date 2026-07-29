# WebUI information architecture — architecture (Phase 16 target)

> **Superseded.** This is the original Phase-16 *target* design, kept for history
> and its inbound links. For the **shipped** console's information architecture
> (12 task-oriented areas, matching `crates/garmr-webui/src/route.rs`), see
> [`docs/webui/information-architecture.md`](../webui/information-architecture.md) —
> that file is authoritative. The naming differs (Overview → Command Center, Audit
> Search → Audit Explorer; Resources/Collectors/Models/Audit-Integrity/
> Administration ship folded into Applications/Data-Sources/System rather than as
> separate areas).

Status: target design. The current console is a 12-route Leptos/WASM app
(`crates/garmr-webui/src/lib.rs:17`); this doc defines the audit-first target nav
and how today's routes consolidate into it. See
[application-audit-analytics.md](application-audit-analytics.md).

## 1. Current routes (shipped)

`Route` (`crates/garmr-webui/src/lib.rs:17-30`, labels at `lib.rs:47-62`):

`Overview · Investigate · Events · Cases · Findings · Risk · Map (Topology) ·
ATT&CK (Attack) · Ingest · Registry · Environment · Ops`

These are telemetry-first: they answer "what is happening on my hosts?" The
audit-first product needs to answer "what did this **user** do to this
**resource**, and was it allowed?" — which is an entity-first reorganization, not a
rewrite.

## 2. Target navigation

| Target page | Shows | Consolidates from |
|-------------|-------|-------------------|
| **Overview** | posture tiles: audit volume, open cases, top-risk actors, policy-violation count, collector health | Overview |
| **Investigations** | the case queue + the auto-detecting pivot search (actor/subject/host) | Cases, Investigate |
| **Users** | per-actor page: volume, top resources, query-fingerprints, baselines + maturity, peer-group position, RBA score, cases | (new; extends the `staff` entity pivot) |
| **Applications** | per-application page: expected vs observed users, operations, sensitive access | (new) |
| **Resources** | per-resource/subject page: who accessed it, from where, under which justification | (new; extends the `person` entity pivot) |
| **Audit Search** | the unified hybrid investigation search (NL + typed IR) | (new; folds `ask` + hsearch) |
| **Policies** | policy list, editor, simulation/backtest, version history | (new) |
| **Detections** | findings + rule/correlation coverage + ATT&CK map | Findings, ATT&CK |
| **Learning** | datasets, challenger evals, champion/challenger diffs, promotions | (new; surfaces `garmr-learning`) |
| **Collectors** | per-collector health, parser metrics, ingest sequence gaps | Ingest |
| **Models** | model catalog, routing/fence decisions, capability profiles | (new; surfaces the router) |
| **Audit Integrity** | ledger status: chain intact, last checkpoint, signature validity | (new; surfaces `garmr audit verify`) |
| **Administration** | registry, environment facts, ops, RBAC, silences | Registry, Environment, Ops |

Retained-but-folded: **Events** becomes a mode inside Audit Search; **Risk** folds
into Users (per-actor) and Overview (top-risk tile); **Map (Topology)** folds into
Administration → Environment (the environment graph). Nothing is deleted — every
current capability has a home.

## 3. Consolidation map (current → target)

```
Overview      → Overview
Investigate   ┐
Cases         ┴→ Investigations
Events        → Audit Search (events mode)
Findings      ┐
ATT&CK        ┴→ Detections
Risk          → Users + Overview (top-risk tile)
Map/Topology  → Administration (Environment graph)
Ingest        → Collectors
Registry      ┐
Environment   ┼→ Administration
Ops           ┘
(new)         → Users · Applications · Resources · Audit Search ·
                Policies · Learning · Models · Audit Integrity
```

## 4. Page contents grounded in existing data

The new entity pages extend the shipped entity pivots and APIs rather than adding a
parallel data path:

- **Users** extends the `staff` (actor / `db_user`) pivot
  (`/api/entity/staff/<actor>`, [access-audit.md](../access-audit.md) §5): volume,
  top subjects, object types, recent accesses with justification, and the cases the
  actor triggered — plus the UEBA baselines/maturity
  ([user-behavior-analytics.md](user-behavior-analytics.md)) and the RBA score
  (`score_staff`, `crates/garmr-analytics/src/risk.rs:351`).
- **Resources** extends the `person`/subject pivot
  (`/api/entity/person/<subject>`): which actors accessed it, from where, and the
  cases naming it.
- **Detections** surfaces `SecurityFinding`s (`GET /api/findings`) and the ATT&CK
  coverage view (`/api/attack/coverage`) already shipped.
- **Audit Integrity** surfaces the read-only audit-verification status the ledger
  already exposes (chain intact, last checkpoint, segment count, signature
  validity — [../threat-model-audit-integrity.md](../threat-model-audit-integrity.md) §102).

## 5. Usability requirements (non-negotiable)

Every page must meet these, enforced by review:

- **Accessibility (a11y).** Semantic HTML, keyboard-navigable, labelled controls,
  sufficient contrast in both light and dark, no colour-only signalling.
- **Deep links.** Every entity/case/finding/policy view has a stable URL that
  restores state (actor, time range, filters) — an investigation is shareable.
- **Empty / loading / error states.** Every data pane distinguishes "no data yet"
  from "failed to load" from "you lack permission"; a missing model or an
  air-gapped feature says so plainly (mirroring `SemanticStatus`).
- **Confirmations on side-effects.** Any action that proposes/approves/silences
  requires an explicit confirmation and shows exactly what will change (the change
  pipeline is human-gated, invariant #2).
- **Audit references.** A view that shows a decision links to its audit record
  (`audit_id`) and its evidence (`event_id`s) — provenance is one click away.
- **No hardcoded values.** Thresholds, timezones, working hours, classifications,
  and labels come from config/data (the `[params]` discipline from
  [access-audit.md](../access-audit.md) §3), never baked into the UI.

## 6. What the UI must not do

- Never mutate protected state directly — the console proposes; a human approves
  through the audited channel.
- Never display raw sensitive audit content beyond the caller's RBAC tier — the
  audit stream is itself sensitive
  ([../threat-models/sensitive-search-and-export.md](../threat-models/sensitive-search-and-export.md)).
- Never invent a value the backend did not send (no client-side "reasonable
  default" that hides a missing signal).
