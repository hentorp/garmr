# garmr WebUI — information architecture

Navigation is organised around **what an analyst wants to accomplish**, not around
backend crates or implementation phases. Eleven top-level areas, grouped into four
intents in the sidebar.

## Before → after

| Old (module-oriented, in-memory routing) | New (task-oriented, URL-routed) |
|---|---|
| Overview | **Command Center** |
| Investigate + Cases | **Investigations** (queue + evidence-driven detail) |
| Events + semantic-in-Investigate + (hidden hsearch/ask) | **Audit Explorer** (Simple / Advanced / Natural language) |
| (entity pages only inside Investigate) | **Users**, **Applications** |
| Findings + Baselines + (Ops › Rules) | **Detections** (findings / proposals / baselines / silences / learning) |
| (none — no policy API) | **Policies** |
| ATT&CK + Environment + (Ops › Hunts) + the former top-level Map | **Intelligence** (relationships / 3D map / ATT&CK coverage / environment model / threat hunts) |
| (none) | **Detections › Learning** (champion / challengers / dangerous misses — formerly the top-level Learning area) |
| Ingest | **Data Sources** |
| Registry + (audit/HA/posture unсurfaced) | **System** (audit integrity / registry / posture & HA / access) |
| Risk (standalone list) | folded into Command Center + entity detail |
| Ops (Hunts/Rules/Actions bundle) | split into Intelligence / Detections / Investigations |

## Sidebar grouping

- **Monitor** — Command Center
- **Investigate** — Investigations, Audit Explorer, Users, Applications, Resources
- **Detect & govern** — Detections, Policies, Intelligence
- **Operate** — Data Sources, System

## URL map (deep links)

| URL | Screen |
|-----|--------|
| `/` | Command Center |
| `/investigations` | Investigation queue (`?state=needs_human` filters) |
| `/investigations/:id` | Case detail (evidence, agent analysis, analyst decision, history) |
| `/audit` | Audit Explorer (`?mode=text|advanced|nl&q=…`) |
| `/users` | User directory (`?…` filter) |
| `/users/:name` | User detail (behaviour, risk, monitoring, cases) |
| `/applications` | Application / asset inventory |
| `/applications/:name` | Application detail (coverage, findings, cases) |
| `/detections` | Detections (`?tab=findings|proposals|baselines|silences|learning`) |
| `/policies` | Access-policy list |
| `/policies/:id` | Policy detail + related violation cases |
| `/intelligence` | Intelligence (`?tab=relationships|map|attack|environment|hunts`) |
| `/topology` | *Legacy* — normalised to `/intelligence?tab=map` (the embedded 3D topology, iframe of `/map/`) |
| `/learning` | *Legacy* — normalised to `/detections?tab=learning` |
| `/data-sources` | Collectors, ingest health, retention |
| `/system` | System (`?tab=audit|registry|posture|access`) |
| `/entity/:kind/:name` | Universal entity deep link → the right detail/drawer |

Browser back/forward and hard refresh restore any of these. Filters, the active
sub-tab, the search mode and the search text are all in the query string, so a
shared link reproduces the exact screen. Unknown paths render a useful *not-found*
state; unauthorized deep links render an *access-denied* state (from the API's
401/403).

## One concept, one home

- A **case** is only ever inspected in Investigations (Command Center, Users,
  Applications, Policies all *link* to it — none re-implement it).
- **Search** is only ever done in Audit Explorer (three modes over one result
  table); no other page ships a competing search box.
- **Promotion / grant-of-trust** uses one control primitive, placed by *what* is
  promoted: baselines → Detections, registry artifacts → System, environment facts
  → Intelligence.
- The **3D map** and the **relationship table** are deliberately *two views of the
  same* host↔ip↔user↔case graph — the map for exploration, the table for an
  accessible, keyboard-navigable alternative. They live as sibling tabs of
  Intelligence so the duplicate is visible as such, not spread across two
  top-level areas.

> This document is authoritative for the shipped console (11 areas, matching
> `crates/garmr-webui/src/route.rs`). The older `docs/architecture/webui-information-architecture.md`
> is the historical Phase-16 target design and is superseded by this file.
