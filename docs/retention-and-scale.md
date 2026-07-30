# Retention & scale — hot/cold tiering

garmr's event store is a single embedded skade (Iceberg) lakehouse with one
writer. Ingest appends; periodically the writer **compacts** — it rebuilds the
table into a few large files so scans stay fast and old snapshots are reclaimed.

Compaction is the scaling pressure point: it runs on the writer, so while it
rebuilds, appends wait. If compaction rebuilt the *entire* history every cycle,
its cost — and the ingest stall — would grow without bound as the table grows.

The fix is **hot/cold tiering** (the Splunk hot→frozen→thawed model): keep only a
bounded recent window in the hot table, and seal older windows into an immutable
cold tier. Compaction then only ever rebuilds the bounded hot window, so its cost
is fixed by `retention_days`, **not** by total history. That is what makes ingest
scale.

## How it works

1. **Seal** (`[retention]`, runs every `interval_secs`). Each pass finds
   `window_days`-sized `event_ts` windows older than `now - retention_days` and
   seals each into a checksummed cold archive (znippy by default) under
   `cold_dir`. Sealing does not yet remove the rows from hot.
2. **Prune.** The next compaction drops rows already sealed to cold as part of
   its rebuild (`rows_pruned` in the compaction log) — reclaiming hot space. So
   the hot table converges to `~retention_days` of data.
3. **Query.** Recent data is served hot by `/api/query` (fast). Sealed history is
   thawed on demand:
   - HTTP: `GET /api/query/cold?sql=<SELECT…>&from=<rfc3339>&to=<rfc3339>` —
     runs read-only SQL over the archives overlapping the range; the response
     includes `archives` (how many were thawed). Bound the range; an unbounded
     cold query over years of archives is refused.
   - CLI (offline, daemon stopped): `garmr coldquery "<SELECT…>" --from … --to …`.

## Configuration

```toml
retention_days = 14           # hot window; also the compaction-cost bound

[retention]
cold_dir = "/var/lib/garmr/cold"
window_days = 1               # seal granularity
interval_secs = 1800          # how often the seal pass runs
```

- **Lower `retention_days`** → smaller hot table → cheaper, faster compaction →
  more ingest headroom, at the cost of more queries hitting the (slower) cold
  path. Raise it to keep more history hot.
- Cold archives are immutable and checksum-verified on read; a tampered or
  truncated archive is refused, not silently returned.
- Documented edge: a row arriving *more* than `retention_days` late, into a
  window already sealed, is pruned without being in that archive — re-import
  such history explicitly if needed. Real log streams are near-ordered, so this
  is rare.

## Operating notes

- Sealing materialises one window at a time in RAM; keep `window_days` at 1 for
  high-volume sources so a window stays small.
- High-volume telemetry (e.g. Kunai endpoint events) dominates hot-table size;
  a shorter `retention_days` is the lever if compaction starts to stall ingest
  (watch for push timeouts / a rising compaction duration in the logs).
- The shippers retry on push failure, so a transient compaction stall delays but
  never drops logs — tiering removes the *cause* of the stall growing over time.
