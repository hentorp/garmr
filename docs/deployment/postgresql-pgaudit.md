<!--
SPDX-FileCopyrightText: 2026 Vetra Automation AB
SPDX-License-Identifier: CC-BY-4.0
-->

# PostgreSQL / pgAudit ingestion

garmr can ingest a PostgreSQL audit trail (via the pgAudit extension) and reason
over it as first-class audit records — who ran what statement against which object,
under which justification, with what outcome. This page covers enabling pgAudit,
shipping its logs to garmr durably, and turning on the application-audit detection
plane.

> **Status.** The canonical audit-record model and the config-gated detection plane
> (policy engine + audit detectors + catalog + monitoring) are implemented. The
> deeper multidimensional behavioral analytics are partly in progress — see
> [../architecture/application-audit.md](../architecture/application-audit.md).

## 1. Enable pgAudit in PostgreSQL

In `postgresql.conf` (adjust the version-specific paths):

```conf
shared_preload_libraries = 'pgaudit'
pgaudit.log = 'read, write, role, ddl, misc'   # the classes you want audited
pgaudit.log_parameter = on

logging_collector = on
log_destination = 'csvlog'
log_directory = 'log'                 # relative to the data dir, or an absolute path
log_filename = 'postgresql-%Y-%m-%d.csv'
log_rotation_age = 1d
```

Install the extension first (for example `apt install postgresql-<version>-pgaudit`)
and restart PostgreSQL. Audit rows then appear in `<data_dir>/log/*.csv` as
`... LOG:  AUDIT: SESSION,...`.

## 2. Ship the logs — the durable native collector (recommended)

`garmr pgaudit-ship` runs **on the PostgreSQL host**, follows the newest pgAudit
`csvlog`, reassembles multiline CSV records, and ships the `AUDIT:` rows to garmr's
**native** ingest endpoint — authenticated, sequence-tracked, and **spooled to disk
so no audit record is lost** across a receiver outage or a collector restart.

What it guarantees: no drops (every record is fsync'd to a bounded on-disk spool and
removed only after a confirmed `2xx`); bounded disk (the spool is rewritten from the
undelivered backlog on each commit); backpressure-safe retry; and gap detection via
`X-Garmr-Seq` / `X-Garmr-Epoch` headers.

### Get a collector token

Register a collector in garmr and mint a bearer token, then set it as
`GARMR_COLLECTOR_TOKEN`. The native ingest stamps the authenticated collector id on
every batch and tracks its sequence. Without a token the collector still ships, but
**unauthenticated** — no server-side sequence/gap tracking.

### Run it

Configuration is entirely by environment:

| Variable | Meaning |
|----------|---------|
| `GARMR_INGEST_URL` | Native ingest endpoint, e.g. `http://garmr-node.example.internal:3100/ingest/v1/events` |
| `GARMR_COLLECTOR_TOKEN` | Bearer token for the collector (unset → unauthenticated) |
| `PG_LOGDIR` | Directory of pgAudit `*.csv` files |
| `PG_HOST_LABEL` | `host` label stamped on events |
| `PG_ENVIRONMENT` | `environment` label |
| `GARMR_SPOOL` | Disk spool path |
| `GARMR_BATCH` | Records per POST |
| `GARMR_POLL_MS` | Follow poll interval (ms) |

```sh
# Catch up the current tail and exit (a good first test):
GARMR_COLLECTOR_TOKEN=… PG_LOGDIR=/var/lib/postgresql/17/main/log \
  garmr pgaudit-ship --once

# Follow forever (the service mode):
garmr pgaudit-ship
```

### systemd unit

```ini
# /etc/systemd/system/garmr-pgaudit.service
[Unit]
Description=garmr pgAudit collector (durable csvlog -> native ingest)
After=network-online.target postgresql.service
Wants=network-online.target

[Service]
Type=simple
User=postgres
Environment=GARMR_INGEST_URL=http://garmr-node.example.internal:3100/ingest/v1/events
Environment=GARMR_COLLECTOR_TOKEN=REPLACE_ME
Environment=PG_LOGDIR=/var/lib/postgresql/17/main/log
Environment=PG_HOST_LABEL=soc-db
Environment=GARMR_SPOOL=/var/lib/garmr/pgaudit.spool
ExecStart=/usr/local/bin/garmr pgaudit-ship
Restart=always
RestartSec=5
RuntimeDirectory=garmr
StateDirectory=garmr

[Install]
WantedBy=multi-user.target
```

```sh
install -m0755 target/release/garmr /usr/local/bin/garmr
mkdir -p /var/lib/garmr && chown postgres:postgres /var/lib/garmr
systemctl daemon-reload && systemctl enable --now garmr-pgaudit
journalctl -u garmr-pgaudit -f
```

The collector is a single static binary — it also works air-gapped: copy it in,
drop the unit, set the env. No network access is needed beyond reaching
`GARMR_INGEST_URL`.

## 3. Alternative: the live Loki-path adapter

If you already ship Postgres logs through a Loki-compatible agent, garmr can parse a
stream labeled `source = postgres-csvlog` (or `postgres-jsonlog`) through the pg
adapter directly in the live ingest path — full canonical fields plus SQL
fingerprint. This path requires a **`loki-compat`** build and the Loki endpoint,
and (like all ingest paths today) is not network-hardened — keep it on a trusted
network. Relabel the stream `source="postgres-csvlog"`, `log_type="audit"`,
`host="<db-host>"`, and point it at garmr's Loki endpoint.

## 4. Turn on the detection plane

Both shipping paths deliver `log_type = audit` events. The typed application-audit
detection plane is **off by default** (it adds per-event CPU on an audit firehose);
enable it in `[detect]`:

```toml
[detect]
app_audit_enabled = true
policies_dir    = "./policies"          # one access-policy TOML per file
catalog_file    = "./catalog.toml"      # resource catalog (classification)
monitoring_file = "./monitoring.json"   # user-monitoring profiles
risk_enabled    = true                  # per-actor RBA (recommended)
```

With the plane on, each audit event is projected to a canonical record, enriched
from the catalog, evaluated against policies (an explicit `deny` is authoritative),
run through the stateless audit detectors, and lowered into the normal case →
triage pipeline. See [../guides/policies.md](../guides/policies.md) and
[../guides/user-monitoring.md](../guides/user-monitoring.md).

## 5. Verify

- `garmr ingest-health` — per-collector last sequence, gaps, and freshness (for
  authenticated collectors), also visible on the console's Data Sources panel.
- `garmr correlate --hours 24` — run the audit correlation rules on demand.
- `garmr tail` / `garmr query "SELECT ... FROM events WHERE log_type='audit'"` —
  confirm records are landing with the expected fields.

## Handling notes

- The full reassembled SQL is stored as `statement` and is treated as **data, never
  instructions** everywhere downstream.
- Sensitivity classification is **operator/collector-supplied** (`data_classification`
  tags / the catalog), not inferred by inspecting SQL. For a PII deployment, set the
  model-routing floor to `confidential` (see
  [secure-deployment.md](secure-deployment.md)).
- The audit stream is itself sensitive (it reveals who was queried) — restrict who
  may read it and set a retention window.
