# pgAudit collector (`garmr pgaudit-ship`)

A durable PostgreSQL/pgAudit log collector. It runs **on the PostgreSQL host**,
follows the newest pgAudit `csvlog`, reassembles multiline CSV records, and ships
the rows containing `AUDIT:` to garmr's **native** ingest (`/ingest/v1/events`) —
authenticated, sequence-tracked, and **spooled to disk so no audit record is lost**
across a receiver outage or a collector restart.

This replaces the old `scripts/garmr-pgaudit-ship.py`, which used the
unauthenticated Loki path and dropped records on any failure.

## What it guarantees

- **No drops.** Every record is appended to a bounded on-disk spool (fsync'd) and
  removed only after a confirmed `2xx`. A crash between "spooled" and "delivered"
  re-sends on restart (at-least-once; the server's per-collector sequence tracking
  and content-addressed event ids absorb any duplicate).
- **Bounded disk.** The spool is rewritten from the *undelivered* backlog on every
  commit, so it never grows past what's actually outstanding; a fully-drained spool
  leaves no file.
- **Backpressure-safe retry.** Failed batches retry with capped exponential backoff
  (0.5 s → 30 s); `--once` gives up after a bounded number of attempts.
- **Gap detection.** Each delivered batch carries `X-Garmr-Seq` (monotonic) and
  `X-Garmr-Epoch` (bumped on restart), so the receiver can detect a missing batch.

## 1. Enable pgAudit csvlog in PostgreSQL

In `postgresql.conf` (adjust the version path):

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

Reload/restart PostgreSQL. Audit rows appear in `<data_dir>/log/*.csv` as
`... LOG:  AUDIT: SESSION,...`.

## 2. Get a collector token

Register a collector in garmr and mint a bearer token (the native ingest stamps the
authenticated collector id on every batch and only then tracks its sequence). Set it
as `GARMR_COLLECTOR_TOKEN` below. Without a token the collector still ships, but
**unauthenticated** — no server-side sequence/gap tracking.

## 3. Run it

Configuration is entirely by environment (defaults in parentheses):

| Variable | Meaning | Default |
|----------|---------|---------|
| `GARMR_INGEST_URL` | Native ingest endpoint | `http://127.0.0.1:3100/ingest/v1/events` |
| `GARMR_COLLECTOR_TOKEN` | Bearer token for the collector | *(unset → unauthenticated)* |
| `PG_LOGDIR` | Directory of pgAudit `*.csv` files | `/var/lib/postgresql/17/main/log` |
| `PG_HOST_LABEL` | `host` label stamped on events | `postgres` |
| `PG_ENVIRONMENT` | `environment` label | `prod` |
| `GARMR_SPOOL` | Disk spool path | `/var/lib/garmr/pgaudit.spool` |
| `GARMR_BATCH` | Records per POST | `500` |
| `GARMR_POLL_MS` | Follow poll interval (ms) | `1000` |

```bash
# Catch up the current tail and exit (a good first test):
GARMR_COLLECTOR_TOKEN=… PG_LOGDIR=/var/lib/postgresql/17/main/log \
  garmr pgaudit-ship --once

# Follow forever (the service mode):
garmr pgaudit-ship
```

## 4. systemd unit

`/etc/systemd/system/garmr-pgaudit.service`:

```ini
[Unit]
Description=garmr pgAudit collector (durable csvlog → native ingest)
After=network-online.target postgresql.service
Wants=network-online.target

[Service]
Type=simple
User=postgres
Environment=GARMR_INGEST_URL=http://127.0.0.1:3100/ingest/v1/events
Environment=GARMR_COLLECTOR_TOKEN=REPLACE_ME
Environment=PG_LOGDIR=/var/lib/postgresql/17/main/log
Environment=PG_HOST_LABEL=soc-db
Environment=GARMR_SPOOL=/var/lib/garmr/pgaudit.spool
ExecStart=/usr/local/bin/garmr pgaudit-ship
Restart=always
RestartSec=5
# The spool needs a writable dir owned by the service user:
RuntimeDirectory=garmr
StateDirectory=garmr

[Install]
WantedBy=multi-user.target
```

```bash
install -m0755 target/release/garmr /usr/local/bin/garmr    # or the offline RPM/deb
mkdir -p /var/lib/garmr && chown postgres:postgres /var/lib/garmr
systemctl daemon-reload && systemctl enable --now garmr-pgaudit
journalctl -u garmr-pgaudit -f     # heartbeat + delivery logs
```

## Offline / air-gapped install

The collector is a single static `garmr` binary — copy it in (or the RPM/LXC image),
drop the unit above, and set the env. No network access is needed beyond reaching
`GARMR_INGEST_URL`. The spool absorbs any window where the receiver is unreachable.

## Verifying delivery

Watch collector delivery on the garmr side with the Collector health surface
(`GET /api/collectors` / the Data Sources → Collector panel): the authenticated
collector's last sequence, gaps and freshness are reported there.
