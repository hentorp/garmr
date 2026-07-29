# HA read replicas — design & status

garmr is single-writer by design: exactly one process ingests, detects, and owns
the skade lakehouse (with its embedded catalog lock). That is a feature — it is
why the storage layer is simple and consistent — but it means a single node is
both the only reader-at-scale and a single point of failure. This is the M7-5 HA
work: **read replicas** that pull the writer's data and serve the read API,
giving horizontal read scale and a warm standby **without ever introducing a
second writer**.

> **Status: partial.** The ship/pull mechanism is implemented and unit-tested;
> the writer ship loop and the read-only follower serve path are implemented and
> compile. **True multi-node failover and consistency under concurrent write
> load are UNVERIFIED** — everything here has only been exercised on a single
> host. The "Known-unverified" section is explicit about what that leaves open.
>
> **Phase 13 (backup/restore + promotion).** A restored node is a read-only
> follower until an audited `garmr backup promote`, whose redb-lock fence is the
> concrete single-host anti-split-brain gate (refuses if a writer holds the lock).
> That gate is authoritative **on one host only**; cross-host failover still
> relies on the operational runbook and stays UNVERIFIED. See
> [backup-design.md](backup-design.md).

## Model — one writer, N read-only followers

```
        ┌──────────┐   ship snapshot    ┌───────────────┐
        │  writer  │ ─────────────────► │ object store  │
        │ (ingest, │   (warehouse +     │  bucket/ha/   │
        │  detect) │    MANIFEST.json)  │  MANIFEST.json │
        └──────────┘                    └───────┬───────┘
                                                │ pull (poll)
                                   ┌────────────┼────────────┐
                                   ▼            ▼            ▼
                              ┌─────────┐  ┌─────────┐  ┌─────────┐
                              │follower │  │follower │  │follower │
                              │read-only│  │read-only│  │read-only│
                              │  API    │  │  API    │  │  API    │
                              └─────────┘  └─────────┘  └─────────┘
```

- **Role** is `[ha].role` — `writer` (default) or `follower`. A follower is
  chosen *before* the writable store is opened, so two nodes can never both be
  writers by configuration.
- **No split-brain on writes.** A follower never ingests, never runs detection
  or the agent, and serves only the read surface. There is no write path to
  conflict, so the classic split-brain failure mode doesn't exist here — the
  worst case is a follower serving slightly *stale* reads.
- **Transport** is the same object store as the cold tier (`GARMR_S3_*`), under
  a separate `GARMR_HA_S3_PREFIX` (default `ha/`).

## The consistency contract — the manifest is the pointer

Iceberg data files are immutable and content-addressed, so shipping them is safe
to do incrementally and in any order. The only mutable thing is *which snapshot
is current*. So (see [`garmr-retention/src/ha.rs`](../crates/garmr-retention/src/ha.rs)):

- **Ship** uploads every data + metadata file first, then writes `MANIFEST.json`
  **last** — a monotonically-numbered list of the snapshot's files. Immutable
  `.parquet` already present at the same size is skipped (cheap incrementality).
- **Pull** reads `MANIFEST.json` **first**, materialises exactly the files it
  names into a staging dir (reusing already-local parquet), then swaps staging
  into place with a rename.

A follower therefore never observes a half-shipped snapshot: it sees either the
previous complete manifest or the new one, never a torn mix. This is
unit-tested (`ship_pull_roundtrip_and_snapshot_gating`): byte-identical
round-trip, snapshot-id gating, and incremental skip of unchanged parquet.

## Follower runtime

A follower loops: pull → if a newer snapshot landed, reopen the store read-only
(`Store::open` — no writer lock; it creates an empty local state/search and reads
the synced warehouse) and rebind the read-only API. The API is served with
`read_only = true`, which omits every mutating / model-spending route
(`/api/ask`, `POST /api/hunt`, `POST /api/rules/propose`) and the entire
`/admin/*` surface — a replica can neither burn LLM budget nor persist state.

Read scale comes from the events lakehouse (query, tail, attack coverage, graph
pivots over the shipped events). Analyst state (cases, risk) and the full-text
index are writer-side and start empty on a follower; a follower is a **query +
standby** node, not a full mirror of investigative state.

## Failover runbook (manual)

There is no automatic leader election (deliberately — auto-failover without
fencing is how you *get* two writers). To promote a follower:

1. **Fence the old writer** — confirm it is actually down (stop the unit; if the
   host is unreachable, ensure it cannot come back and resume ingest).
2. On the chosen follower, do a final `pull` to get the latest shipped snapshot.
3. Flip `[ha].role` to `writer` (and set `ship_interval_secs` if it will feed new
   followers), point ingest (the native endpoint / your collector) at it, and restart.
4. The promoted node opens the store writable and resumes the full pipeline.

The window of possible data loss is one ship interval (events ingested by the old
writer since its last ship). Tighten `ship_interval_secs` to shrink it, at the
cost of more object-store traffic.

## Known-unverified (needs a second node + load)

- **Failover has not been executed.** The promote path above is designed, not
  drilled. No measured RTO/RPO.
- **Torn catalog under concurrent write.** The redb catalog is copied whole; a
  ship that races a writer commit can capture a torn page. skade's heal-on-open
  (the durability work) rolls a torn catalog back to its last good root on the
  follower, so the expected cost is one stale pull rather than corruption — but
  this has **not** been exercised under real concurrent write load on separate
  nodes.
- **Rebind blip.** Reopening on a new snapshot aborts and rebinds the API; a
  brief connection drop and a possible bind race are handled with a short delay,
  not proven under load.
- **Single-host only.** Everything was tested as one writer + one follower on the
  same box. Network partitions, clock skew, and real object-store latency/errors
  between distinct nodes are untested.

The honest summary: the **data-movement core is implemented and tested**; the
**operational HA story (failover, consistency under load) is designed but
unproven** and should be drilled on real nodes before anyone relies on it.
