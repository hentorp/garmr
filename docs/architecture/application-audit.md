<!--
SPDX-FileCopyrightText: 2026 Vetra Automation AB
SPDX-License-Identifier: CC-BY-4.0
-->

# Application-audit analytics

Beyond host/network telemetry, garmr can treat an **application audit trail** as a
first-class object and reason about *who did what to which resource, under which
justification, and how sensitive it was*. The flagship case is an access-audit /
register investigation ("who accessed whom or what"), but the model is
domain-neutral: a PostgreSQL/pgAudit trail, an API access log, an IAM change log,
or a document-management audit all map onto the same normalized fields.

> **Status note.** The pieces differ in maturity. The canonical record model and a
> config-gated detection plane are implemented; the deeper multidimensional
> behavioral analytics are partly in progress. Each section below is labeled. Where
> the internal architecture docs
> ([application-audit-analytics](application-audit-analytics.md),
> [user-behavior-analytics](user-behavior-analytics.md),
> [access-policy-engine](access-policy-engine.md),
> [postgresql-audit](postgresql-audit.md)) describe a fuller design, they mark it as
> target design.

## The canonical audit record — Implemented

garmr stores one thin event type; the audit view is a typed **lens** over an
event's already-normalized fields, not a second stored type. Ingest folds many
input vocabularies onto canonical keys (for example `db_user`, `target_person`,
`object_table`, `action`, `statement`, `ticket_ref`, `client_addr`, plus app flags
`watched` and `is_self`), so a producer's own field names map without code changes.
The discriminator that ties a feed to the audit rules is a single label:
`log_type = audit`.

The lens derives useful facts automatically — a `COPY`/`EXPORT`/`UNLOAD` folds to a
single export operation; a `GRANT`/`REVOKE`/`SET ROLE` is flagged as a privilege
operation; a permission-denied outcome is a first-class negative outcome (the raw
material for failed-access detection).

Two flags let the **application** decide sensitivity (`watched`, `is_self`), so
garmr never holds a watchlist or an actor-to-own-record map. That is deliberate
data minimization: garmr should not become a copy of the sensitive lists it helps
audit.

## Config-driven correlation rules — Implemented

The simplest onboarding path needs no code: drop-in correlation rules (TOML + SQL)
over `log_type = 'audit'`, each keyed per actor. Shipped examples cover bulk
lookups, off-hours access, watchlisted-subject access, access without
justification, and self-lookup. Thresholds, working hours, and timezone live in a
`[params]` table in each rule — config data, not SQL — so porting to another
environment is editing values. Author or verify on demand with `garmr correlate`.

## The typed detection plane — Config-gated

garmr also has a first-class typed detection plane for audit events. It is **off by
default** (it adds per-event CPU on an audit firehose) and is enabled in `[detect]`:

```toml
[detect]
app_audit_enabled = true
policies_dir    = "./policies"          # one access-policy TOML per file
catalog_file    = "./catalog.toml"      # resource catalog (data_classification, sensitive_resource)
monitoring_file = "./monitoring.json"   # user-monitoring profiles
```

When enabled, `serve` runs this per audit event, in the same commit cycle as Sigma,
feeding the identical case → triage pipeline:

1. **Gate** — a cheap check; non-audit events cost nothing.
2. **Project** — the event's normalized fields become the canonical audit record.
3. **Enrich** — the catalog stamps `data_classification` / `sensitive_resource`
   from **Trusted** entries.
4. **Policy** — the access is evaluated against `policies/` into an explainable
   decision; an explicit `deny` is the strongest outcome and is never suppressed.
5. **Detect** — the stateless audit detectors fire: forbidden access, missing
   justification, self-access, watched-subject access, privilege change, export,
   bulk read, service-account misuse, failed access.
6. **Monitor** — a user-monitoring profile only *raises* a finding's score
   (multiplier ≥ 1.0); monitoring increases visibility, never implies guilt.
7. **Lower** — each finding becomes a detection on the existing case + agent-triage
   path.

The policy engine is **separate from and authoritative over** the anomaly plane: a
policy `Deny` is a violation no matter how baseline-normal the action has become.
See [guides/policies.md](../guides/policies.md).

## Per-actor risk and behavioral baselines — Runtime-wired / in progress

- **Per-actor RBA** (`[detect] risk_enabled`) scores each actor (`db_user`) as well
  as each host: an actor spreading low-and-slow misuse across several rules — none
  individually paging — accrues a decayed risk sum and, over threshold, opens a
  `garmr-risk-user-<actor>` case. Empty without an audit feed. *Runtime-wired.*
- **Behavioral baselines** (`garmr app-baseline`) learn a per-entity model of
  normal; a profile's behavioral detectors fire **only after it is promoted to
  Trusted**, and a baseline touched by an adverse case is excluded from "normal".
  The core promotion + abstain-until-baseline machinery is wired; the **fuller
  multidimensional UEBA** (per-dimension baselines, peer-group comparison,
  service-account profiling) is described as target design in
  [user-behavior-analytics](user-behavior-analytics.md). *Partly implemented /
  in progress.*

Behavioral analytics only ever **raises** attention; it never overrides the policy
engine, and it abstains rather than treating a first sighting (novelty) as an
anomaly.

## PostgreSQL / pgAudit — Config-gated

garmr ingests a PostgreSQL audit trail two ways, both shipping already-normalized
`log_type = audit` events:

- **The durable native collector** (`garmr pgaudit-ship`) runs on the PostgreSQL
  host, follows the newest pgAudit `csvlog`, spools to disk so no record is lost
  across a receiver outage, and ships to the authenticated native ingest endpoint.
  This is the recommended path.
- **A live Loki-path adapter** parses a stream labeled `source = postgres-csvlog`
  (or `postgres-jsonlog`) through the pg adapter — full canonical fields plus SQL
  fingerprint. This path requires the `loki-compat` build.

See [deployment/postgresql-pgaudit.md](../deployment/postgresql-pgaudit.md).

## Governance

The application-audit domains (policies, catalog entries, monitoring profiles) are
governed registry kinds: versioned, content-addressed, human-promoted, and audited,
with hot-reload on change. See [storage.md](storage.md#governed-persistence-versioned-registry).

## The audit stream is itself sensitive

Access logs reveal *who was investigated*. Restrict who may query the audit stream
(RBAC via `GARMR_USERS`), set a retention window on it, and — for a PII deployment —
set the model-routing classification floor to `confidential` so audit content never
routes to an external model. The auditors must not become an unaudited surveillance
layer. See the [sensitive-search-and-export](../security/threat-model.md) defenses.
