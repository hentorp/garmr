# Access-audit investigations — "who accessed whom/what"

garmr can run internal investigations over any **access audit log**: who (which
actor/account) accessed which subject (person, account, record, document, case),
when, from where, under which justification — plus misuse detection, per-actor
risk, and alerting. It reuses the whole existing pipeline (Loki-push ingest →
skade lakehouse → correlation/RBA → Case → notify → the Investigate view);
nothing parallel is added.

It is **environment- and domain-agnostic**: a Swedish person-register
(registerkontroll) is the flagship case, but the same normalized fields and rules
drive an account/document/record audit, an API access log, an EHR module log, and
so on — configured by data and labels, with no code edits.

> **The audit is itself sensitive.** Access logs reveal who was investigated. Set
> a retention window for the audit stream and restrict who may query it (RBAC via
> `GARMR_USERS`), so the auditors don't become an unaudited surveillance layer.

## 1. The audit event contract

The producer (an app, or a DB audit plugin/pgaudit) emits one structured JSON
line per access. The subject must be **explicit** (it can't be reliably
reverse-engineered from a SQL `WHERE` clause). Minimal shape:

```json
{
  "actor": "anna.h",
  "target": "subject-42",
  "object_type": "person",
  "action": "read",
  "client_addr": "10.0.0.12",
  "reason": "AR-2026-4711",
  "watched": false,
  "is_self": false
}
```

garmr's ingest classifier folds many input names onto each **normalized key**, so
your audit's own vocabulary maps without code changes:

| normalized key | meaning | accepted input names |
|----------------|---------|----------------------|
| `db_user` | the actor (who) | `db_user`, `session_user`, `actor`, `principal`, `acting_user`, `performed_by`, `accessed_by`, `operator`, `account`, `user_id` |
| `target_person` | the subject (whom/what) — an opaque id | `target_person`, `target`, `subject`, `target_id`, `subject_id`, `object_id`, `record_id`, `resource_id`, `entity_id`, `target_pnr` |
| `object_table` | kind of thing accessed | `object_table`, `object_type`, `resource_type`, `entity_type`, `resource`, `collection`, `dataset`, `endpoint`, `relation`, `table_name` |
| `action` | the operation verb | `action`, `operation`, `op`, `verb`, `method` |
| `statement` | full statement / SQL text | `statement`, `sql`, `sql_text`, `query_text` (**not** `query` → maps to `dns`) |
| `ticket_ref` | justification | `ticket_ref`, `case_ref`, `reason`, `purpose`, `justification`, `access_reason`, `arende`, `diarienr` |
| `client_addr` | client origin (not IP-guarded) | `client_addr`, `remote_host`, `remote_addr`, `source_host`, `origin`, `client_address` |
| `watched` | app flag: subject is watchlisted | `watched`, `is_watched`, `watchlisted` (JSON bool or `"true"`) |
| `is_self` | app flag: actor == subject | `is_self`, `self_lookup`, `self_access` (JSON bool or `"true"`) |

The two flags let the **app** decide sensitivity, so garmr never holds a
watchlist or an actor→own-record map (data minimisation + portability).

## 2. Ship it (Alloy → Loki push)

garmr keeps only six Loki labels (`host / service / source / environment /
severity / log_type`); every other label is dropped, so all per-access
attributes live in the JSON message line (the classifier reads them), not as
labels. Use the Loki **push** path (at-least-once), not syslog.

**The one discriminator that ties the feed to the rules is `log_type=audit`** —
set it on every audit event. `source` is free (`postgres-audit`, `mysql-audit`,
`app-audit`, anything); nothing keys on it.

| label | value |
|-------|-------|
| `log_type` | `audit` **(required — the rules key on this)** |
| `source` | any label identifying the producer |
| `service`, `host`, `environment`, `severity` | per deployment |

## 3. Detection rules (`correlations/reg-*.toml`)

Drop-in TOML + SQL over `log_type='audit'`, each keyed **per actor** (dedup uses
`db_user`, so a burst opens one case per actor, not one lumped host case).
Author/verify instantly: `garmr correlate --hours 24`.

| rule | fires on | tunable `[params]` |
|------|----------|--------------------|
| `reg-bulk-lookups` | ≥ N accesses by one actor in the window | `min_lookups` (default 50) |
| `reg-off-hours` | access outside local working hours / weekends | `tz_offset`, `day_start`, `day_end` |
| `reg-watchlist` | access to a `watched:true` subject (critical) | — (app flag) |
| `reg-lookup-without-ticket` | access with no justification | — (opt-in) |
| `reg-self-lookup` | actor accessed their own record (`is_self:true`) | — (app flag) |

Thresholds and the timezone/working-hours live in a `[params]` table in each
rule (substituted as `{name}` at render) — **config data, not SQL**. So porting
to another environment is editing values, not code. A hit flows through the
unchanged Case → triage → notify path and appears in the ATT&CK coverage view.

## 4. Per-actor risk (RBA)

With `detect.risk_enabled = true`, the risk loop scores **each actor** (by
`db_user`) as well as each host: an actor who spreads low-and-slow misuse across
several rules — none individually paging — accumulates a decayed risk sum and,
over threshold, opens a `garmr-risk-user-<actor>` case. Empty without an audit
feed, so existing deployments are unaffected.

> RBA needs the per-access rules to yield **Suspicious/untriaged** — a Benign
> verdict zeroes a case and risk never accrues. Individual accesses are not
> auto-closed Benign.

## 5. Investigate

- **actor pivot** (`staff` kind) — *what did actor X access?*:
  `/api/entity/staff/<actor>` → volume, top subjects, object types, recent
  accesses (with justification), and the cases X triggered.
- **subject pivot** (`person` kind) — *who accessed subject Y?*:
  `/api/entity/person/<subject>` → which actors, from where, and cases naming Y.
- **Graph** — `staff` (actor) and `person` (subject) node kinds; an access case
  links actor—case—subject, and raw accesses add direct actor↔subject edges, so
  who-accessed-whom is graphable even without an adjudicated case. Source-agnostic
  (keyed on the fields, not a producer string).
- The Investigate view auto-detects a bare token as actor/subject and fans out.

(The `staff`/`person` kind names are flagship flavour; the mechanism keys
generically off the `db_user`/`target_person` fields, so any subject id shape
works.)

## 6. Alerting

A rule/risk hit rides the existing Matrix + webhook + SMTP path (per-rule
throttle + silences included). Alerts name the parties: the verdict body gains a
`Actor X → Subject Y` line and the webhook JSON gains `db_user` +
`target_person`. Route a watchlist hit as an escalation so a host-level silence
can't mute it.

## 7. Portability & the decisions you own

- **Onboard a new audit feed** = emit the JSON contract above with
  `log_type=audit`. No code edits: the field aliases, the flag contract, and the
  `[params]` knobs cover thresholds, timezone, and sensitivity.
- **Watchlist / self** = app flags (`watched`, `is_self`). garmr holds no
  sensitive lists. (Fallback: inline CTEs in the rule TOML — then that file holds
  sensitive ids; `chmod 0640` it.)
- **Working hours** = `tz_offset` + `day_start`/`day_end` params per environment.
- **Justification policy** = the without-ticket rule is opt-in; disable it where
  a per-access reason isn't mandated.
- **Retention & access** on the audit stream itself (see the note at the top).

## 8. Deploy

`scripts/deploy.sh` (parameterized by `GARMR_HOST`/`PREFIX`/`ETC`/`UNIT`) builds
the binary + web console, ships them plus the rules, and restarts the service —
touching only the install prefix and rule dirs, **never** the lakehouse. First
install: `scripts/airgap-install.sh`; service unit: `packaging/garmr.service`.

## 9. Enable the application-audit detection plane (Phases 1/3/5/8)

Beyond the config-driven `correlations/reg-*.toml` rules, garmr has a first-class
typed detection plane for audit events. It is **off by default** (it adds
per-event CPU on an audit firehose). Turn it on in `[detect]`:

```toml
[detect]
app_audit_enabled = true
policies_dir   = "./policies"          # one access-policy TOML per file
catalog_file   = "./catalog.toml"      # resource catalog (see catalog.example.toml)
monitoring_file = "./monitoring.json"  # JSON array of user-monitoring profiles
```

When enabled, `serve` runs this per audit event (`log_type=audit`), in the same
commit cycle as Sigma, feeding results into the identical case → triage pipeline:

1. **Gate** — `AuditRecord::is_audit_event` (cheap; non-audit events cost nothing).
2. **Project** — the event's normalized fields → the canonical `AuditRecord`.
3. **Enrich** — the catalog stamps `data_classification` / `sensitive_resource`
   from **Trusted** entries (file-imported entries are promoted at load).
4. **Policy** — the access is evaluated against `policies/` → an explainable
   decision; an explicit `deny` is the strongest outcome and is never suppressed.
5. **Detect** — the stateless application-audit detectors fire: forbidden access,
   missing justification, self-access, watched-subject access, privilege change,
   export, bulk read, service-account misuse, failed access.
6. **Monitor** — a `UserMonitoringProfile` only *raises* a finding's score
   (multiplier ≥ 1.0); monitoring increases visibility, never implies guilt.
7. **Lower** — each finding becomes a `Detection` (dedup key
   `rule_id|host|db_user`) → the existing case + agent-triage path.

### Policy files (`policies/*.toml`)

One `Policy` per file (see `policies/deny-raw-person-data.toml`,
`policies/require-ticket-for-sensitive.toml`):

```toml
id = "deny-raw-person-data"
title = "No direct access to raw person tables"
effect = "deny"            # allow | deny | require_justification | require_approval
                           #   | alert | increase_risk | step_up_review
enabled = true
version = 1
priority = 100
[resource]
objects = ["raw.*"]        # schema.* wildcard, or an unqualified/qualified name
# [subject] users/roles/groups/applications/service_account
# [condition] environments/weekdays/hours/operations/client_ip_prefixes/export/
#             self_access/watched_subject/privileged/bulk_operation/min_rows_read/…
```

`garmr` deployments without an audit feed are unaffected: with the flag off (or
no audit events), nothing here runs.

### Live pgAudit feed (Alloy → garmr)

The pg adapter runs LIVE in the loki ingest path (not just offline `replay`): a
Loki stream whose `source` label is `postgres-csvlog` (or `postgres-jsonlog`) is
parsed through the pg adapter — full canonical fields + SQL fingerprint, with
multiline csvlog records stitched across a push. Point Alloy at the PostgreSQL
`csvlog` and relabel the stream `source="postgres-csvlog"`, `log_type="audit"`,
`host="<db-host>"`, forwarding to garmr's loki endpoint (`:3105`). Every other
`source` (journald/kunai/…) is unaffected — it still takes the generic
classifier. Enabling pgAudit itself: `apt install postgresql-<v>-pgaudit`, set
`shared_preload_libraries='pgaudit'`, `pgaudit.log='read,write,ddl,role'`,
`logging_collector=on`, `log_destination='csvlog'`, then restart PostgreSQL.
