# Governed persistence — the versioned-registry backbone (Phase A)

The application-audit catalog domains — **policies, catalog entries, applications,
resources, and user-monitoring profiles** — were loaded from TOML/JSON at `serve`
start and held immutable for the process. That is fine for a static lab but is not
*governed*: there is no version history, no approval step, no rollback, and no
audit trail of who changed what and why.

Phase A models these domains as **versioned registry kinds**, reusing the
mechanism garmr already uses for the model / prompt / toolset / rule / detector-
config it runs (`crates/garmr-core/src/registry.rs`, the `registry` /
`registry_promotions` redb tables). Nothing new had to be invented for the
governance guarantees — a domain becomes a `RegistryKind` and inherits all of them.

## What a registry kind gives you for free

An artifact is an **immutable** `RegistryRecord` identified by its BLAKE3
`content_digest` — a changed policy is a *new* record, never a rewrite. Which
version is *live* is a separate, **append-only** stream of `PromotionEvent`s folded
to a current view (`registry::active`). So every governance field the DoD asks for
is already present and audited:

| DoD field | Registry field |
|-----------|----------------|
| stable object id | `RegistryRecord.name` (+ `id`) |
| version | `RegistryRecord.version` |
| previous version | `RegistryRecord.parent_version` |
| actor | `registered_by` / `PromotionEvent.actor` |
| timestamp | `registered_at` / `PromotionEvent.at` |
| reason | `rationale` / `PromotionEvent.reason` |
| approval reference | the `PromotionEvent` itself |
| audit-ledger reference | `audit_id` (the hard invariant) |
| before / after digest | `from_version`'s digest / `target_digest` (= `content_digest`) |

The **hard invariant** (enforced where the audit ledger lives): *no artifact is
live without a versioned record AND an audit event.* A `PromotionEvent` with an
empty `audit_id` is inert on read, so a hand-forged redb row can never make a
policy enforced. Rollback and retirement are just further appends.

## The kinds (all five added)

`RegistryKind::{Policy, Catalog, Application, Resource, Monitoring}` are now
first-class kinds (`tag()` / `from_tag()`), so **today** each is registrable,
promotable, roll-back-able, and listable through the existing generic registry
surface — `GET /api/registry/:kind`, the admin register/promote/rollback/retire
endpoints (each fail-closed audited via `record_admin`), and the console's registry
view. That alone gives DoD 1/2 (versioned + audited persistence) for all five.

## Wired end-to-end: policies + catalog + monitoring

The three domains with a live engine consumer are wired through; applications and
resources have no consumer yet (a future Resources workspace) but are already
*storable* as kinds. **Policy** is the reference:

- **Read (enforcement).** `AppAudit::load` composes the active policy set from the
  registry via `active_policies_from_registry` — for each policy name, the record
  the promotion stream currently points at on the `production` channel (approved +
  audit-bound), its `spec` deserialized into a `Policy`. `GET /api/policies` reads
  the same set, so the console shows *exactly* what is enforced.
- **Opt-in, non-disruptive.** Gated by `GARMR_REGISTRY_POLICIES=1`. Unset (the
  default) keeps the file loader, so a deployment is unchanged until it migrates.
- **Write (lifecycle).** Draft = register a `Policy` record (`kind=policy`,
  `name=<policy id>`, `spec=<the Policy JSON>`); approve = promote it on
  `production`; rollback = promote a prior version; retire = a retire append. All
  through the existing registry admin surface, all audited. `POST /api/policies/simulate`
  (already shipped) backtests a draft before it is promoted.

**Catalog** is wired the same way (`active_catalog_from_registry`,
`GARMR_REGISTRY_CATALOG=1`): each `CatalogEntry` is a `Catalog`-kind record
(`name` = entry id, `spec` = the entry). The active, audit-bound entry per name is
composed into the enforced `Catalog` and marked **Trusted** — the registry
promotion is the operator's vouching, mirroring the file-import `promote` (and the
catalog resolves Trusted entries only, so this is what makes a registry-backed
classification actually stamp).

**Monitoring** is wired the same way (`active_monitoring_from_registry`,
`GARMR_REGISTRY_MONITORING=1`): each `UserMonitoringProfile` is a `Monitoring`-kind
record (`name` = `user_id`, `spec` = the profile). The active, audit-bound profile
per user composes the enforced `MonitoringRegistry` — so *start / modify / end
monitoring* becomes a register + audited promotion / rollback with full version
history, instead of editing a JSON file. There is no Trusted-marking (being the
*live* record is what makes it in effect; the profile's own expiry still governs,
and monitoring only ever raises attention, never declares guilt).

### Migrating a deployment's policies

```bash
# 1. Register each current policy file as a Policy record (spec = the policy TOML
#    converted to JSON), via the admin registry surface.
# 2. Promote each on the production channel (an audited approval).
# 3. Restart serve with GARMR_REGISTRY_POLICIES=1 — the engine now enforces the
#    governed set; GET /api/policies reflects it.
```

## Hot-reload without restart

The enforced config (policies + catalog + monitoring + the catalog's object index)
lives in one `ConfigSet` behind a swap lock (`AppAudit.config: RwLock<Arc<ConfigSet>>`).
The parallel per-event `prepare_event` path reads it via a single cheap `Arc`
clone — concurrent readers, no serialization — so the read cost is one atomic
increment and a swap never tears an in-flight evaluation.

`POST /admin/appaudit/reload` (admin, fail-closed audited) rebuilds the `ConfigSet`
from its sources — files and/or the governed registry, honoring the same
`GARMR_REGISTRY_*` gates as startup — and swaps it in atomically. So a governance
change (a registry promotion, **or** a plain policy-file edit) takes effect
**without restarting `serve`**, and `GET /api/policies` — which reads the same
composed set — never drifts from what is enforced. The accumulated learning state
(behavioral baselines, stateful-detector windows) is untouched; only config swaps.

### Auto-reload on promotion

An operator no longer has to remember the reload step. Every registry
promotion/rollback/retire (`do_promotion`) ends by calling
`AppAudit::reload_if_governed(kind, channel)`, which reloads **only** when the
promotion actually changes what is enforced — a config-consuming domain (policy,
catalog, monitoring) that is registry-backed (`GARMR_REGISTRY_*` on), on the
`production` channel enforcement composes from. A `Model` / `Prompt` /
applications / resources / staging promotion, or a plane still loading from files,
rebuilds nothing (`None`), so the hot path is never disturbed by an unrelated
governance write. The decision is a pure, fully unit-tested function
(`promotion_touches_enforcement`, gate injected). The response body then carries a
`reloaded` block with the new counts, and the reload is itself recorded as a
best-effort `appaudit.config_reload` audit event — best-effort because the
promotion it follows is already durable and audited, so a supplementary
"enforcement recompiled" line must never un-acknowledge a committed promotion.

## Remaining Phase-A work (follow-ons)

- **Applications + resources wired to a consumer.** Both are already *storable* as
  governed kinds, but have no engine reading them yet — they feed a future
  Resources/Applications workspace (Phase B), at which point the read-the-active-set
  step is the same one-function repeat as policies / catalog / monitoring.
- **Typed lifecycle endpoints + console CRUD** (`POST /api/policies` draft →
  simulate → approve → rollback) on top of the generic registry surface — Phase B.
- **Optimistic concurrency** on update is inherent (the `(kind, name, version)`
  triple + content-digest guard: `register_record` returns `Conflict` on a
  divergent same-version write).
