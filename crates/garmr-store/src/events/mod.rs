// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! The events lakehouse: a serial writer actor + a concurrent read lane.
//!
//! `Table::append` needs `&mut` and skade is single-process, so appends are
//! funnelled through ONE tokio task (serialised commits). Reads are different:
//! `Warehouse::sql(&self)` builds a fresh DataFusion session per call and holds
//! no exclusive lock (redb gives snapshot-isolated reads against the writer), so
//! queries run **concurrently on a shared `Arc<Warehouse>`, off the actor**.
//! This is what stops a slow/expensive `/api/query` from head-of-line-blocking
//! ingest, correlation, and live agent triage — the read lane and the write
//! lane are independent.
//!
//! ## Compaction
//!
//! iceberg-rust's only writer is `fast_append`, which appends one manifest per
//! commit and carries the whole manifest list forward — so under continuous
//! ingest the snapshot log, manifest list, and tiny-file count grow without
//! bound and eventually OOM the process. To fix that, the actor counts
//! snapshots accrued **since the last compaction** and, once
//! `compact_snapshot_threshold` new ones exist, runs `Warehouse::compact_table`
//! (rebuild the table as a few big zstd files in ONE commit + atomically swap
//! it in), reloads its handle, and GC's the retired data directory after a
//! grace window. The rebuilt table always has one snapshot, so the trigger
//! converges regardless of table size (an absolute-count trigger would re-fire
//! on every append once the table were big enough). A failed attempt backs off
//! for [`COMPACT_FAIL_COOLDOWN`] instead of retrying on the next append —
//! `compact_table` cleans up its own scratch copy on failure, and retrying a
//! full rebuild every group commit would turn disk pressure into a spiral.
//!
//! When retention is enabled, the rebuild also **prunes** rows already sealed
//! to cold storage (`event_ts` inside a sealed cold window — see
//! `compaction::sealed_prune_hook` for why membership, not the watermark, is
//! the criterion): the rebuild is the one safe moment to shrink the hot table
//! (single writer, full rewrite anyway), and without it rebuild cost grows
//! monotonically forever.
//!
//! Compaction runs ON the actor, so no append races it; reads stay concurrent
//! (the swap is gap-free and readers resolve tables per query). The GC grace
//! window (`compact_gc_grace_secs`) must exceed the longest reader — API
//! queries are capped well below it. The rebuild/prune/orphan-sweep mechanics
//! live in the sibling [`compaction`] module.

use std::collections::{HashSet, VecDeque};
use std::sync::Arc;
use std::time::Duration;

use garmr_core::{Config, Error, Event, Result};
use skade::arrow_array::RecordBatch;
use tokio::sync::{mpsc, oneshot};
use tokio::time::Instant;

use crate::schema::{events_schema, T_EVENTS};
use crate::state::StateStore;

mod compaction;
pub use compaction::TombstoneMatcher;

use compaction::{cleanup_orphans, run_compaction};

enum Cmd {
    /// Each event carries an optional AUTHENTICATED collector id (Phase 12);
    /// `None` = unattributed (legacy/unauthenticated), byte-identical to before.
    Append(Vec<(Event, Option<String>)>, oneshot::Sender<Result<usize>>),
    /// The Arrow-Flight columnar swallow: a **wire batch** (the 9 v1 payload
    /// columns) plus the AUTHENTICATED Flight peer identity. The actor builds the
    /// full events batch from the arrays (no owned `Event`), dedups on the
    /// computed `event_id` column, and appends — sharing the write + compaction
    /// path with `Append`, so both ingest paths behave identically.
    AppendBatch(RecordBatch, Option<String>, oneshot::Sender<Result<usize>>),
    /// Re-resolve the actor's table handle after an EXTERNALLY-driven rebuild
    /// (the offline erase pass). Without this the actor's handle still points at
    /// the retired data directory, and the next append writes into files the
    /// next cleanup deletes — silent data loss, not an error.
    Refresh(oneshot::Sender<Result<()>>),
}

/// Back-off after a FAILED compaction attempt. Success needs none — the next
/// trigger requires `threshold` fresh snapshots, which only ingest can create —
/// but a failure leaves the count at the threshold, and without a cooldown the
/// very next append would launch another full-table rebuild.
const COMPACT_FAIL_COOLDOWN: Duration = Duration::from_secs(600);

/// Floor for `compact_snapshot_threshold` (when non-zero): a compacted table
/// restarts at 1 snapshot, so a threshold of 1-2 would rebuild the whole table
/// after (nearly) every append.
const COMPACT_THRESHOLD_FLOOR: usize = 8;

/// Tunables for the actor's automatic compaction.
#[derive(Clone)]
struct CompactCfg {
    /// Compact once this many snapshots accrued since the last compaction
    /// (0 = disabled).
    threshold: usize,
    /// Wait this long after a swap before deleting the retired data dir, so an
    /// in-flight reader that resolved just before the swap can finish streaming.
    gc_grace: Duration,
    /// Prune rows already sealed to cold storage during the rebuild. Set from
    /// `[retention].enabled`; the cutoff is the retention watermark read at
    /// compaction time (sealed archives stay queryable via cold-query).
    prune_sealed: bool,
    /// Agent-state store holding the retention watermark.
    state: StateStore,
    /// `[[retention.class]]` policies: sources excluded from cold whose rows
    /// prune from hot after their class's `hot_days`.
    classes: Vec<garmr_core::RetentionClass>,
}

/// A cheap, clonable handle to the events store: appends via the writer actor,
/// queries directly against the shared warehouse.
#[derive(Clone)]
pub struct EventsHandle {
    tx: mpsc::Sender<Cmd>,
    wh: Arc<skade::Warehouse>,
    /// Bounds how many read queries execute against the warehouse AT ONCE. Each
    /// `sql()` fans its scan across a bounded subset of the available cores,
    /// and the callers are many and concurrent (correlation's rules, the web
    /// console's polling, the API),
    /// and DataFusion planning/execution is CPU-bound — an unbounded burst pegs
    /// every core and STARVES the async runtime, so even `/health` stalls for
    /// seconds. Capping concurrency leaves cores for ingest, detection, and the
    /// runtime; excess queries queue briefly instead of thrashing.
    query_sem: Arc<tokio::sync::Semaphore>,
}

impl EventsHandle {
    /// Append normalised events to the lakehouse (serialised through the actor).
    /// Unattributed — the collector id is `None`; behaviour is unchanged.
    pub async fn append(&self, events: Vec<Event>) -> Result<usize> {
        self.append_attributed(events.into_iter().map(|e| (e, None)).collect())
            .await
    }

    /// Append events each tagged with an optional AUTHENTICATED collector id
    /// (Phase 12). The native ingest path uses this to stamp the trusted source.
    pub async fn append_attributed(&self, rows: Vec<(Event, Option<String>)>) -> Result<usize> {
        let (r, rx) = oneshot::channel();
        self.tx
            .send(Cmd::Append(rows, r))
            .await
            .map_err(|_| gone())?;
        rx.await.map_err(|_| gone())?
    }

    /// **The Arrow-Flight columnar swallow.** Append a **wire batch** — the 9 v1
    /// payload columns a `flightbeat` sender ships — straight into the lakehouse,
    /// with no JSON parse and no intermediate owned `Event`. `collector` is the
    /// AUTHENTICATED Flight peer identity (or `None`), which stamps `collector_id`
    /// and lifts `source_trust` to `authenticated`. The v2 provenance columns
    /// (`event_id`, `ingest_time`, …) are computed server-side from the arrays, so
    /// a Flight event and the same event via NDJSON share one `event_id` and dedup
    /// against each other. Serialised through the same actor as `append`, so dedup
    /// and compaction are identical. See `schema::build_events_batch_from_wire`.
    pub async fn append_batch(
        &self,
        wire: RecordBatch,
        collector: Option<String>,
    ) -> Result<usize> {
        let (r, rx) = oneshot::channel();
        self.tx
            .send(Cmd::AppendBatch(wire, collector, r))
            .await
            .map_err(|_| gone())?;
        rx.await.map_err(|_| gone())?
    }

    /// Run a read-only DataFusion query over `events`, concurrently (not via the
    /// append actor). The caller enforces read-only (see the AST guard in
    /// `garmr-agent`); this path executes whatever it is handed.
    pub async fn sql(&self, query: impl Into<String>) -> Result<Vec<RecordBatch>> {
        // Bound concurrent warehouse queries so a burst can't peg every core and
        // starve the runtime (see `query_sem`). The permit is held for the whole
        // query and released on drop.
        let _permit = self
            .query_sem
            .acquire()
            .await
            .map_err(|_| Error::store("query semaphore closed"))?;
        // Fan queries across cores, but reserve half of them for the runtime,
        // ingest, and detection. Only one parallel query is admitted at a time,
        // so callers cannot multiply this per-query CPU budget.
        //
        // Setting target_partitions above 1 means a single analytical query
        // (correlation rule, /api/overview, tail) runs
        // its operators in parallel instead of serial on one core. The earlier
        // target_partitions(1) pinned EVERY query serial (no RepartitionExec at
        // all), so even a multi-file scan's downstream filter/sort/aggregate ran
        // on one core. With multiple partitions, DataFusion inserts a round-robin
        // RepartitionExec that spreads that work — and a many-file scan's per-file
        // partitions — across the query's core budget. NB: skade's
        // IcebergTableScan partitions per DATA FILE (not per row group), so a
        // single compacted file still decodes on one thread; parallelizing that
        // decode is a skade read-path concern, not a target_partitions one.
        // (`sql_stream`
        // KEEPS 1 on purpose — single-partition backpressure bounds retention's
        // peak memory, a different constraint.)
        let partitions = query_partitions(
            std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(1),
        );
        let config =
            skade::datafusion::prelude::SessionConfig::new().with_target_partitions(partitions);
        let ctx = self.wh.session_with(config).await.map_err(Error::store)?;
        let df = ctx.sql(&query.into()).await.map_err(Error::store)?;
        df.collect().await.map_err(Error::store)
    }

    /// Like [`sql`](Self::sql) but STREAMS result batches — the caller pulls
    /// them one at a time, so an arbitrarily large result set never
    /// materialises fully in RAM. Retention uses this to seal windows of any
    /// size with bounded memory (a dense firehose day is otherwise multi-GB).
    pub async fn sql_stream(
        &self,
        query: impl Into<String>,
    ) -> Result<skade::datafusion::physical_plan::SendableRecordBatchStream> {
        // Pin target_partitions(1): the default parallel plan puts a round-robin
        // RepartitionExec above the scan that reads it AHEAD of a slow consumer
        // (the parquet-seal writer) and buffers it unboundedly — that was the
        // retention OOM. A single partition streams the scan row-group by
        // row-group under the consumer's backpressure, so peak memory stays
        // bounded regardless of window size.
        let config = skade::datafusion::prelude::SessionConfig::new().with_target_partitions(1);
        let ctx = self.wh.session_with(config).await.map_err(Error::store)?;
        let df = ctx.sql(&query.into()).await.map_err(Error::store)?;
        df.execute_stream().await.map_err(Error::store)
    }
}

fn gone() -> Error {
    Error::store("events actor gone")
}

/// CPU budget for an analytical query. Reserving at least half the logical
/// cores where possible prevents warehouse work from monopolising the process.
fn query_partitions(available: usize) -> usize {
    (available / 2).max(1)
}

/// Open the lakehouse and spawn its writer task. `state` supplies the retention
/// watermark that gates sealed-row pruning during compaction.
pub async fn spawn(cfg: &Config, state: StateStore) -> Result<EventsHandle> {
    let wh = Arc::new(
        skade::open(&cfg.store.warehouse_dir)
            .await
            .map_err(Error::store)?,
    );

    // Crash-recovery: an unclean shutdown can leave the durable catalog pointer
    // aimed at an un-fsync'd (zero-byte) metadata file, which would make the
    // open below fail with an EOF parse error and crash-loop the daemon. Roll
    // the pointer back to the newest intact snapshot first (no-op if healthy).
    match wh.heal_table(T_EVENTS).await {
        Ok(skade::HealOutcome::Healed { from, to }) => {
            tracing::warn!(%from, %to, "events store healed: rolled catalog pointer back to the last intact metadata after a torn commit (likely an unclean shutdown)");
        }
        Ok(skade::HealOutcome::Unrecoverable { location }) => {
            tracing::error!(%location, "events store pointer is corrupt and no intact metadata was found — manual recovery needed");
        }
        Ok(_) => {}
        Err(e) => tracing::warn!(error = %e, "events store heal check failed (non-fatal)"),
    }

    let mut events = wh
        .table_or_create(T_EVENTS, &events_schema())
        .await
        .map_err(Error::store)?;
    // Additive schema evolution: an existing (pre-V2) warehouse is missing the
    // provenance columns; add them BEFORE serving. Without this, appending a
    // V2 batch (more columns than the on-disk table) fails skade's positional
    // recast (column-count mismatch) and halts ingest. Idempotent + field-id
    // stable, so a fresh or already-current table is a no-op.
    events
        .ensure_schema(&events_schema())
        .await
        .map_err(Error::store)?;
    // Enable a Parquet bloom filter on `event_id` for every append (see
    // `events_write_props`): the read-path lever that lets an exact-id probe skip
    // whole row groups. Additive — only the id column gains a filter; the append
    // path is otherwise byte-identical (uncompressed, dictionary on) to before.
    events.set_write_props(crate::schema::events_write_props());

    // Sweep any scratch tables / retired data dirs a crash mid-compaction left
    // behind, BEFORE serving. `events` (loaded above) is authoritative; a
    // leftover `events__c<stamp>` is at most a partial copy, safe to discard.
    if let Err(e) = cleanup_orphans(&wh, T_EVENTS).await {
        tracing::warn!(error = %e, "compaction orphan cleanup failed (non-fatal)");
    }

    tracing::info!(dir = %cfg.store.warehouse_dir.display(), "events lakehouse opened");

    let threshold = cfg.store.compact_snapshot_threshold as usize;
    let compact = CompactCfg {
        threshold: if threshold == 0 {
            0
        } else {
            threshold.max(COMPACT_THRESHOLD_FLOOR)
        },
        gc_grace: Duration::from_secs(cfg.store.compact_gc_grace_secs),
        prune_sealed: cfg.retention.enabled,
        state,
        classes: cfg.retention.class.clone(),
    };

    let (tx, rx) = mpsc::channel(64);
    tokio::spawn(actor_loop(
        events,
        wh.clone(),
        rx,
        compact,
        cfg.ingest.dedup_recent,
    ));
    // A query may use the full query CPU budget, so admit only one at a time.
    // Additional callers queue without multiplying DataFusion's parallel work.
    let query_sem = Arc::new(tokio::sync::Semaphore::new(1));
    Ok(EventsHandle { tx, wh, query_sem })
}

/// One-shot **offline** compaction of the events table: open the lakehouse, heal
/// a torn commit if any, sweep leftover scratch tables, then collapse the entire
/// snapshot log into a SINGLE snapshot via [`skade::Warehouse::compact_table`].
///
/// This is the manual recovery for a table whose iceberg metadata has bloated —
/// thousands of `fast_append` snapshots, an O(N) manifest-list rewrite per
/// commit — to the point where the in-`serve` auto-compaction can't win a cycle
/// against live ingest + analytics scans. Run it with the daemon STOPPED:
/// skade's single-writer contract requires no concurrent writer, and running
/// alone (no scan contention) is the whole point. Keeps every row — it fixes
/// metadata bloat, not data volume (no sealed-row pruning).
impl EventsHandle {
    /// Targeted-erasure pass: rebuild the events table dropping every row that
    /// matches a persistent tombstone. For the OFFLINE `garmr erase` command —
    /// run with the daemon stopped (the store locks enforce single-writer).
    /// Returns the number of rows erased.
    ///
    /// This is the enforcement half of erasure: the tombstone is persisted
    /// FIRST (so a crash here still converges at the next serve compaction),
    /// then this rebuild makes the hot store clean now rather than eventually.
    pub async fn erase_matching(&self, state: &StateStore) -> Result<u64> {
        let n = erase_pass(&self.wh, state).await?;
        // The rebuild swapped the table out from under the actor. Refresh its
        // handle BEFORE returning: an append raced against a stale handle lands
        // in the retired directory, which the next pass's cleanup deletes.
        let (ack, rx) = oneshot::channel();
        self.tx
            .send(Cmd::Refresh(ack))
            .await
            .map_err(|_| Error::store("events writer gone"))?;
        rx.await
            .map_err(|_| Error::store("events writer dropped ack"))??;
        Ok(n)
    }
}

async fn erase_pass(wh: &skade::Warehouse, state: &StateStore) -> Result<u64> {
    use std::sync::atomic::Ordering;

    let matcher = compaction::TombstoneMatcher::new(state.list_tombstones().map_err(Error::store)?);
    if matcher.is_empty() {
        return Ok(0);
    }
    if let Err(e) = compaction::cleanup_orphans(wh, T_EVENTS).await {
        tracing::warn!(error = %e, "scratch cleanup before erase failed (non-fatal)");
    }
    let erased = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
    let hook_count = erased.clone();
    let hook = move |batch: skade::arrow_array::RecordBatch| -> skade::Result<skade::arrow_array::RecordBatch> {
        use skade::arrow_array::Array;
        let Some(ts) = batch
            .column_by_name("event_ts")
            .and_then(|c| c.as_any().downcast_ref::<skade::arrow_array::TimestampMicrosecondArray>())
        else {
            return Ok(batch);
        };
        let host_col = batch
            .column_by_name("host")
            .and_then(|c| c.as_any().downcast_ref::<skade::arrow_array::StringArray>());
        let fields_col = batch
            .column_by_name("fields")
            .and_then(|c| c.as_any().downcast_ref::<skade::arrow_array::StringArray>());
        let mut n = 0u64;
        let keep: skade::arrow_array::BooleanArray = (0..ts.len())
            .map(|i| {
                if ts.is_null(i) {
                    return Some(true);
                }
                let host = host_col
                    .filter(|h| !h.is_null(i))
                    .map(|h| h.value(i))
                    .unwrap_or("");
                let fields = fields_col.filter(|f| !f.is_null(i)).map(|f| f.value(i));
                if matcher.matches(host, fields, ts.value(i)) {
                    n += 1;
                    return Some(false);
                }
                Some(true)
            })
            .collect();
        hook_count.fetch_add(n, Ordering::Relaxed);
        skade::datafusion::arrow::compute::filter_record_batch(&batch, &keep)
            .map_err(|e| skade::SkadeError::other(e.to_string()))
    };
    let hook_ref: &(dyn Fn(skade::arrow_array::RecordBatch) -> skade::Result<skade::arrow_array::RecordBatch>
          + Send
          + Sync) = &hook;
    wh.compact_table_props(
        T_EVENTS,
        Some(hook_ref),
        &crate::schema::events_compact_write_props(),
    )
    .await
    .map_err(Error::store)?;
    Ok(erased.load(Ordering::Relaxed))
}

pub async fn compact_now(cfg: &Config) -> Result<skade::CompactReport> {
    let wh = skade::open(&cfg.store.warehouse_dir)
        .await
        .map_err(Error::store)?;
    match wh.heal_table(T_EVENTS).await {
        Ok(skade::HealOutcome::Healed { from, to }) => {
            tracing::warn!(%from, %to, "events store healed before compaction (torn commit rolled back)");
        }
        Ok(skade::HealOutcome::Unrecoverable { location }) => {
            return Err(Error::store(format!(
                "events pointer corrupt and no intact metadata found ({location}); manual recovery needed"
            )));
        }
        Ok(_) => {}
        Err(e) => tracing::warn!(error = %e, "heal check before compaction failed (non-fatal)"),
    }
    // A fresh/empty warehouse dir would otherwise error the compaction below.
    // Evolve the schema too, so an offline compaction of a pre-V2 warehouse
    // leaves it carrying the provenance columns.
    let mut t = wh
        .table_or_create(T_EVENTS, &events_schema())
        .await
        .map_err(Error::store)?;
    t.ensure_schema(&events_schema())
        .await
        .map_err(Error::store)?;
    // Discard scratch tables/dirs left by earlier failed in-serve attempts.
    if let Err(e) = cleanup_orphans(&wh, T_EVENTS).await {
        tracing::warn!(error = %e, "scratch-table cleanup before compaction failed (non-fatal)");
    }
    // Rebuild with the bloom-carrying props so an offline compaction preserves
    // the `event_id` filter (a plain `compact_table` rebuild would drop it).
    wh.compact_table_props(T_EVENTS, None, &crate::schema::events_compact_write_props())
        .await
        .map_err(Error::store)
}

/// Bounded exact-id ingest dedup. Remembers the last `cap` distinct event ids
/// (FIFO eviction) and rejects a re-appearing one — an at-least-once collector's
/// retry. Size-bounded (not time-bounded), so it can only ever collapse an exact
/// content+timestamp re-appearance within the recent window; it never drops two
/// genuinely distinct events.
struct Dedup {
    cap: usize,
    seen: HashSet<String>,
    order: VecDeque<String>,
}

impl Dedup {
    fn new(cap: usize) -> Self {
        Dedup {
            cap,
            seen: HashSet::with_capacity(cap.min(1024)),
            order: VecDeque::new(),
        }
    }

    /// Admit an id: `true` if newly seen (keep the event), `false` if a recent
    /// duplicate (drop it).
    fn admit(&mut self, id: String) -> bool {
        if self.seen.contains(&id) {
            return false;
        }
        if self.order.len() >= self.cap {
            if let Some(old) = self.order.pop_front() {
                self.seen.remove(&old);
            }
        }
        self.seen.insert(id.clone());
        self.order.push_back(id);
        true
    }
}

/// Dedup a fully-built events batch on its `event_id` column: admit each row
/// through the shared [`Dedup`] and keep only the newly-seen rows, so a Flight
/// retry — or an event already stored via NDJSON — collapses exactly as the
/// native path (both compute the same `event_id`). Returns the filtered batch and
/// its surviving row count. With dedup disabled, or if the column is absent, the
/// batch passes through untouched.
fn dedup_batch(dedup: Option<&mut Dedup>, batch: RecordBatch) -> (RecordBatch, usize) {
    use skade::arrow_array::{Array, BooleanArray, StringArray};

    let Some(dedup) = dedup else {
        let n = batch.num_rows();
        return (batch, n);
    };
    let ids = batch
        .schema()
        .index_of("event_id")
        .ok()
        .and_then(|i| batch.column(i).as_any().downcast_ref::<StringArray>());
    let Some(ids) = ids else {
        let n = batch.num_rows();
        return (batch, n);
    };
    // admit() is called for every row in order, so the dedup window advances
    // correctly; a (never-expected) NULL id is kept rather than silently dropped.
    let mask: BooleanArray = (0..batch.num_rows())
        .map(|i| Some(ids.is_null(i) || dedup.admit(ids.value(i).to_string())))
        .collect();
    match skade::arrow_select::filter::filter_record_batch(&batch, &mask) {
        Ok(kept) => {
            let n = kept.num_rows();
            (kept, n)
        }
        // Filtering can't fail for a valid mask; if it somehow does, keep the
        // batch whole rather than drop data.
        Err(_) => {
            let n = batch.num_rows();
            (batch, n)
        }
    }
}

async fn actor_loop(
    mut events: skade::Table,
    wh: Arc<skade::Warehouse>,
    mut rx: mpsc::Receiver<Cmd>,
    compact: CompactCfg,
    dedup_cap: usize,
) {
    let mut dedup = (dedup_cap > 0).then(|| Dedup::new(dedup_cap));
    // Snapshot count right after the last compaction (1 once one has run; a
    // fresh table starts low, a pre-existing bloated one triggers immediately).
    let mut baseline: usize = 1;
    let mut failed_at: Option<Instant> = None;

    while let Some(cmd) = rx.recv().await {
        // Each command reduces to (a batch to append or None, the post-dedup row
        // count, the reply channel). BOTH paths build the events batch first (which
        // computes `event_id` once) and then dedup on that column via the shared
        // `dedup_batch` — `Append` from owned `Event`s, `AppendBatch` (Flight) from
        // the wire arrays. Both feed the SAME append + compaction tail below.
        let (batch, n, submitted, reply): (
            anyhow::Result<Option<RecordBatch>>,
            usize,
            usize,
            oneshot::Sender<Result<usize>>,
        ) = match cmd {
            Cmd::Append(rows, reply) => {
                let submitted = rows.len();
                // Build first (event_id computed ONCE inside build_batch), then
                // dedup on the batch's event_id column — the same path Flight uses.
                // This drops an at-least-once retry without hashing event_id a
                // second time (the old dedup filter recomputed it via
                // `event_id_for`). A fully-deduped batch still ACKs Ok(0) so the
                // collector stops retrying.
                if rows.is_empty() {
                    (Ok(None), 0, submitted, reply)
                } else {
                    match crate::schema::build_events_batch_attributed(&rows) {
                        Ok(b) => {
                            let (b, n) = dedup_batch(dedup.as_mut(), b);
                            (Ok(if n == 0 { None } else { Some(b) }), n, submitted, reply)
                        }
                        Err(e) => (Err(e), 0, submitted, reply),
                    }
                }
            }
            Cmd::AppendBatch(wire, collector, reply) => {
                let submitted = wire.num_rows();
                // Build the full events batch from the wire arrays (computes the
                // v2 provenance incl. `event_id`), then dedup on that column so a
                // Flight retry — or the same event already seen via NDJSON —
                // collapses exactly as the native path.
                match crate::schema::build_events_batch_from_wire(&wire, collector.as_deref()) {
                    Ok(full) => {
                        let (full, n) = dedup_batch(dedup.as_mut(), full);
                        let batch = if n == 0 { Ok(None) } else { Ok(Some(full)) };
                        (batch, n, submitted, reply)
                    }
                    Err(e) => (Err(e), 0, submitted, reply),
                }
            }
            Cmd::Refresh(ack) => {
                // Externally-driven rebuild (offline erase): re-resolve the
                // table handle so subsequent appends land in the LIVE data dir,
                // not the retired one.
                let _ = ack.send(events.refresh().await.map_err(Error::store));
                continue;
            }
        };
        if submitted > n {
            garmr_core::metrics::registry()
                .ingest_dedup_dropped_total
                .add(&[("path", "store")], (submitted - n) as u64);
            tracing::debug!(
                dropped = submitted - n,
                "ingest dedup: dropped duplicate event(s)"
            );
        }
        let r = match batch {
            Ok(None) => Ok(0),
            Ok(Some(batch)) => events
                .append(&[batch])
                .await
                .map(|_| n)
                .map_err(Error::store),
            Err(e) => Err(Error::store(e)),
        };
        let appended = r.is_ok() && n > 0;
        let _ = reply.send(r);

        // Compaction check runs AFTER the append is acknowledged, so an append's
        // latency never includes a rebuild. Only after a real append (snapshot
        // count only grows on append). Trigger arithmetic is RELATIVE to the
        // last compaction so it converges on big tables, and a failed attempt
        // cools down instead of retrying next append.
        if appended && compact.threshold > 0 {
            let snaps = events.inner().metadata().snapshots().len();
            let due = snaps.saturating_sub(baseline) >= compact.threshold;
            let cooled = failed_at.is_none_or(|t| t.elapsed() >= COMPACT_FAIL_COOLDOWN);
            if due && cooled {
                if run_compaction(&mut events, &wh, &compact).await {
                    baseline = events.inner().metadata().snapshots().len();
                    failed_at = None;
                } else {
                    failed_at = Some(Instant::now());
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    use garmr_core::Event;

    use super::*;
    use crate::schema::build_events_batch;

    #[test]
    fn query_parallelism_reserves_cpu_headroom() {
        assert_eq!(query_partitions(1), 1);
        assert_eq!(query_partitions(2), 1);
        assert_eq!(query_partitions(3), 1);
        assert_eq!(query_partitions(4), 2);
        assert_eq!(query_partitions(32), 16);
    }

    fn tmp(tag: &str) -> PathBuf {
        let n = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        std::env::temp_dir().join(format!("garmr-compact-{tag}-{n}"))
    }

    fn event(msg: &str) -> Event {
        event_at(msg, chrono::Utc::now())
    }

    fn event_at(msg: &str, ts: chrono::DateTime<chrono::Utc>) -> Event {
        Event {
            ts,
            host: "pve".into(),
            service: "sshd".into(),
            source: "journald".into(),
            environment: "test".into(),
            severity: "info".into(),
            log_type: "system".into(),
            message: msg.into(),
            fields: BTreeMap::new(),
        }
    }

    async fn count_events(wh: &skade::Warehouse) -> i64 {
        let rows = wh.sql("SELECT count(*) AS n FROM events").await.unwrap();
        rows[0]
            .column(0)
            .as_any()
            .downcast_ref::<skade::arrow_array::Int64Array>()
            .unwrap()
            .value(0)
    }

    async fn snapshot_count(wh: &skade::Warehouse, name: &str) -> usize {
        // Load fresh to see the current catalog head.
        wh.table(name)
            .await
            .unwrap()
            .inner()
            .metadata()
            .snapshots()
            .len()
    }

    /// The primitive: N appends make N snapshots; compact_table collapses them
    /// to ONE (single commit — this is what makes the trigger arithmetic
    /// converge), preserves every row, and reports the retired data dir (still
    /// on disk — GC is the caller's job). A second compaction must also
    /// converge, not re-inflate the snapshot count.
    #[tokio::test]
    async fn compact_table_collapses_snapshots_and_converges() {
        let dir = tmp("prim");
        let wh = skade::open(&dir).await.expect("open");
        {
            let mut t = wh
                .table_or_create(T_EVENTS, &events_schema())
                .await
                .unwrap();
            for i in 0..20 {
                let b = build_events_batch(&[event(&format!("line {i}"))]).unwrap();
                t.append(&[b]).await.unwrap();
            }
        }
        assert_eq!(
            snapshot_count(&wh, T_EVENTS).await,
            20,
            "one snapshot per append"
        );

        let report = wh.compact_table(T_EVENTS, None).await.unwrap();
        assert_eq!(report.snapshots_before, 20);
        assert_eq!(report.rows, 20);
        assert_eq!(report.rows_pruned, 0);
        let old_dir = report.old_data_dir.expect("retired dir reported");
        assert!(old_dir.exists(), "compact does not GC — caller does");

        // Collapsed to a single snapshot, rows intact, live dir rotated.
        assert_eq!(
            snapshot_count(&wh, T_EVENTS).await,
            1,
            "rebuild commits exactly once"
        );
        assert_eq!(count_events(&wh).await, 20, "every row survived compaction");
        let live_dir = wh
            .table(T_EVENTS)
            .await
            .unwrap()
            .inner()
            .metadata()
            .location()
            .to_string();
        assert!(
            !live_dir.ends_with("/events"),
            "live table rotated to a fresh dir: {live_dir}"
        );

        // Convergence: compacting the compacted table stays at one snapshot.
        let report2 = wh.compact_table(T_EVENTS, None).await.unwrap();
        assert_eq!(report2.rows, 20);
        assert_eq!(
            snapshot_count(&wh, T_EVENTS).await,
            1,
            "second compaction converges"
        );
        assert_eq!(count_events(&wh).await, 20);

        std::fs::remove_dir_all(&dir).ok();
    }

    /// The prune hook drops rows during the rebuild and reports them.
    #[tokio::test]
    async fn compact_table_prunes_via_hook() {
        let dir = tmp("prune");
        let wh = skade::open(&dir).await.expect("open");
        let cutoff = chrono::Utc::now();
        {
            let mut t = wh
                .table_or_create(T_EVENTS, &events_schema())
                .await
                .unwrap();
            for i in 0..4 {
                let e = event_at(&format!("old {i}"), cutoff - chrono::Duration::days(100));
                t.append(&[build_events_batch(&[e]).unwrap()])
                    .await
                    .unwrap();
            }
            for i in 0..3i64 {
                let e = event_at(
                    &format!("new {i}"),
                    cutoff + chrono::Duration::seconds(i + 1),
                );
                t.append(&[build_events_batch(&[e]).unwrap()])
                    .await
                    .unwrap();
            }
        }
        let w = cutoff.timestamp_micros();
        let prune = move |batch: RecordBatch| -> skade::Result<RecordBatch> {
            let ts = batch
                .column_by_name("event_ts")
                .unwrap()
                .as_any()
                .downcast_ref::<skade::arrow_array::TimestampMicrosecondArray>()
                .unwrap();
            let cut = skade::arrow_array::TimestampMicrosecondArray::from(vec![w]);
            let keep = skade::datafusion::arrow::compute::kernels::cmp::gt_eq(
                ts,
                &skade::arrow_array::Scalar::new(&cut),
            )
            .unwrap();
            Ok(skade::datafusion::arrow::compute::filter_record_batch(&batch, &keep).unwrap())
        };
        let report = wh.compact_table(T_EVENTS, Some(&prune)).await.unwrap();
        assert_eq!(report.rows, 3, "only unsealed rows carried");
        assert_eq!(report.rows_pruned, 4, "sealed rows dropped and counted");
        assert_eq!(count_events(&wh).await, 3);

        std::fs::remove_dir_all(&dir).ok();
    }

    fn test_cfg(base: &std::path::Path, threshold: u32) -> Config {
        use garmr_core::{AgentConfig, DetectConfig, IngestConfig, LlmBackend, StoreConfig};
        Config {
            audit: Default::default(),
            backup: Default::default(),
            store: StoreConfig {
                warehouse_dir: base.join("wh"),
                state_db: base.join("state.redb"),
                search_dir: base.join("search"),
                retention_days: 90,
                compact_snapshot_threshold: threshold,
                compact_gc_grace_secs: 0, // delete promptly in the test
                fulltext_exclude_sources: vec![],
            },
            ingest: IngestConfig {
                ingest_bind: None,
                loki_bind: "127.0.0.1:0".into(),
                syslog_bind: None,
                default_environment: "test".into(),
                api_bind: None,
                ui_dir: None,
                dedup_recent: 0,
                flight_bind: None,
                collectors_file: None,
            },
            detect: DetectConfig {
                rules_dir: base.join("rules"),
                correlations_dir: base.join("correlations"),
                realert_secs: 900,
                hunts_dir: base.join("hunts"),
                app_audit_enabled: false,
                policies_dir: std::path::PathBuf::from("policies"),
                catalog_file: None,
                monitoring_file: None,
                anomaly_enabled: false,
                anomaly_min_count: 3,
                anomaly_max_per_tick: 0,
                anomaly_exclude_sources: vec![],
                risk_enabled: false,
                risk_threshold: 20.0,
                risk_halflife_hours: 12.0,
                risk_realert_secs: 3600,
                freq_baseline_enabled: false,
                freq_k: 3.0,
                freq_min_count: 20,
                prediction_discount: 0.5,
            },
            cases: Default::default(),
            agent: AgentConfig {
                backend: LlmBackend::Anthropic,
                model: "claude-opus-4-8".into(),
                prefilter_model: None,
                openai_base_url: None,
                max_iterations: 12,
                max_tokens: 4096,
                daily_budget_usd: 5.0,
                allow_online_lookups: false,
                geoip_dir: None,
                ioc_feeds: vec![],
                mcp_servers: vec![],
                pricing: Default::default(),
            },
            retention: Default::default(),
            route: Default::default(),
            executor: Default::default(),
            ha: Default::default(),
            environment: Default::default(),
            matrix: None,
        }
    }

    /// End-to-end proof that `constrain_sources` actually FILTERS, not merely
    /// that it produces plausible SQL. A rewrite can look correct as a string
    /// and still return every row — only executing it against DataFusion
    /// settles that.
    #[tokio::test]
    async fn source_scoped_sql_returns_only_allowed_sources_through_datafusion() {
        use crate::sql_guard::constrain_sources;

        let base = tmp("scoped-sql");
        std::fs::create_dir_all(&base).unwrap();
        let cfg = test_cfg(&base, 0);
        let state = StateStore::open(&cfg.store.state_db).expect("state");
        let handle = spawn(&cfg, state).await.expect("spawn");

        let mut hr = event("hr record one");
        hr.source = "hr".into();
        let mut hr2 = event("hr record two");
        hr2.source = "hr".into();
        let mut infra = event("infra record");
        infra.source = "infra".into();
        handle
            .append(vec![hr.clone(), hr2.clone(), infra.clone()])
            .await
            .unwrap();

        let allowed = vec!["hr".to_string()];
        let count_scoped = |sql: &str| {
            let rewritten = constrain_sources(sql, &allowed).expect("rewrite");
            let h = &handle;
            async move {
                let rows = h.sql(rewritten).await.expect("scoped query runs");
                rows[0]
                    .column(0)
                    .as_any()
                    .downcast_ref::<skade::arrow_array::Int64Array>()
                    .unwrap()
                    .value(0)
            }
        };

        // Unscoped sees all three; every scoped shape sees only the two hr rows.
        assert_eq!(count_via(&handle).await, 3);
        assert_eq!(count_scoped("SELECT count(*) AS n FROM events").await, 2);
        assert_eq!(
            count_scoped("SELECT count(*) AS n FROM events AS t").await,
            2,
            "an alias must not widen the scope"
        );
        assert_eq!(
            count_scoped("WITH t AS (SELECT source FROM events) SELECT count(*) AS n FROM t").await,
            2,
            "a CTE must not widen the scope"
        );
        assert_eq!(
            count_scoped(
                "SELECT count(*) AS n FROM (SELECT source FROM events UNION ALL \
                 SELECT source FROM events) u"
            )
            .await,
            4,
            "both UNION branches are constrained (2 hr rows twice), not 6"
        );

        // And the infra row is genuinely unreachable, not merely uncounted.
        let rewritten = constrain_sources("SELECT message FROM events", &allowed).expect("rewrite");
        let rows = handle.sql(rewritten).await.expect("runs");
        let msgs: Vec<String> = rows
            .iter()
            .flat_map(|b| {
                use skade::arrow_array::Array;
                let col = b
                    .column(0)
                    .as_any()
                    .downcast_ref::<skade::arrow_array::StringArray>()
                    .unwrap();
                (0..col.len())
                    .map(|i| col.value(i).to_string())
                    .collect::<Vec<_>>()
            })
            .collect();
        assert!(
            !msgs.iter().any(|m| m.contains("infra")),
            "an out-of-scope row leaked: {msgs:?}"
        );
        assert_eq!(msgs.len(), 2, "{msgs:?}");
    }

    async fn count_via(handle: &EventsHandle) -> i64 {
        let rows = handle
            .sql("SELECT count(*) AS n FROM events")
            .await
            .unwrap();
        rows[0]
            .column(0)
            .as_any()
            .downcast_ref::<skade::arrow_array::Int64Array>()
            .unwrap()
            .value(0)
    }

    async fn count_sql(handle: &EventsHandle, sql: &str) -> i64 {
        let rows = handle.sql(sql).await.unwrap();
        rows[0]
            .column(0)
            .as_any()
            .downcast_ref::<skade::arrow_array::Int64Array>()
            .unwrap()
            .value(0)
    }

    #[test]
    fn dedup_admits_new_rejects_recent_and_evicts_oldest() {
        let mut d = Dedup::new(3);
        assert!(d.admit("a".into()));
        assert!(d.admit("b".into()));
        assert!(!d.admit("a".into()), "an in-window id is a duplicate");
        assert!(d.admit("c".into()));
        // order is [a,b,c]; admitting d evicts the oldest (a).
        assert!(d.admit("d".into()));
        // a was evicted, so it is seen as new again (never a false-positive drop).
        assert!(d.admit("a".into()));
        assert!(!d.admit("d".into()), "d is still in window");
    }

    #[tokio::test]
    async fn ingest_dedup_drops_retries_but_keeps_distinct_events() {
        let base = tmp("dedup");
        std::fs::create_dir_all(&base).unwrap();
        let mut cfg = test_cfg(&base, 0); // compaction off
        cfg.ingest.dedup_recent = 1024;
        let state = StateStore::open(&cfg.store.state_db).expect("state");
        let handle = spawn(&cfg, state).await.expect("spawn");

        // Same content AND same timestamp ⇒ same stable event_id ⇒ a retry.
        let ts = chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap();
        let dup = event_at("dup line", ts);
        handle.append(vec![dup.clone()]).await.unwrap();
        handle.append(vec![dup.clone()]).await.unwrap(); // at-least-once retry
        assert_eq!(count_via(&handle).await, 1, "the retry was deduped");

        // A genuinely distinct event (different time/content) is still stored.
        handle.append(vec![event("other line")]).await.unwrap();
        assert_eq!(count_via(&handle).await, 2);
    }

    /// The Arrow-Flight columnar swallow through the actor: `append_batch` stores
    /// a wire batch, stamps the collector attribution, and dedups on `event_id` —
    /// including CROSS-PATH, so an event delivered via Flight and the same event
    /// re-sent via NDJSON collapse to one row (both compute the same id).
    #[tokio::test]
    async fn append_batch_swallows_wire_stamps_collector_and_dedups_cross_path() {
        let base = tmp("flight");
        std::fs::create_dir_all(&base).unwrap();
        let mut cfg = test_cfg(&base, 0); // compaction off
        cfg.ingest.dedup_recent = 1024;
        let state = StateStore::open(&cfg.store.state_db).expect("state");
        let handle = spawn(&cfg, state).await.expect("spawn");

        // Three distinct events (with a field, so `fields` hashing is exercised);
        // the wire batch is their canonical 9 v1 payload columns.
        let ts = chrono::DateTime::from_timestamp(1_700_000_100, 0).unwrap();
        let events: Vec<Event> = (0..3)
            .map(|i| {
                let mut e = event_at(
                    &format!("flight line {i}"),
                    ts + chrono::Duration::seconds(i),
                );
                e.fields.insert("src_ip".into(), format!("10.0.0.{i}"));
                e
            })
            .collect();
        let full = build_events_batch(&events).unwrap();
        let wire = full.project(&(0..9).collect::<Vec<_>>()).unwrap();

        // Swallow with an AUTHENTICATED collector.
        let stored = handle
            .append_batch(wire.clone(), Some("edge-01".into()))
            .await
            .unwrap();
        assert_eq!(stored, 3, "all three wire rows stored");
        assert_eq!(count_via(&handle).await, 3);
        // v2 provenance stamped server-side.
        assert_eq!(
            count_sql(
                &handle,
                "SELECT count(*) AS n FROM events \
                 WHERE source_trust='authenticated' AND collector_id='edge-01'"
            )
            .await,
            3,
            "collector attribution stamped on every row"
        );

        // Cross-path dedup: re-send the SAME events via the NATIVE path. Same
        // event_id, so all are duplicates and nothing new is stored.
        let native = handle.append(events.clone()).await.unwrap();
        assert_eq!(
            native, 0,
            "native re-send of Flight-stored events is fully deduped"
        );
        assert_eq!(count_via(&handle).await, 3);

        // A Flight retry of the same wire batch is deduped too.
        let retry = handle.append_batch(wire, None).await.unwrap();
        assert_eq!(retry, 0, "the Flight retry was deduped");
        assert_eq!(count_via(&handle).await, 3);
    }

    /// Backward-compat migration: a warehouse created with the pre-V2 nine-column
    /// schema must upgrade in place (via `Table::ensure_schema` on open) and keep
    /// accepting V2 appends. Without the upgrade, appending a V2 batch (more
    /// columns than the on-disk table) fails skade's positional recast and halts
    /// ingest — this test guards that exact regression.
    #[tokio::test]
    async fn v1_warehouse_upgrades_to_v2_and_keeps_appending() {
        use skade::arrow_array::{RecordBatch, StringArray, TimestampMicrosecondArray};
        use skade::arrow_schema::{DataType, Field, Schema, TimeUnit};
        use std::sync::Arc;

        let base = tmp("migrate");
        std::fs::create_dir_all(&base).unwrap();
        let cfg = test_cfg(&base, 0); // compaction off

        // 1) Simulate a pre-V2 warehouse: a nine-column events table + one row.
        {
            let wh = skade::open(&cfg.store.warehouse_dir).await.unwrap();
            let v1 = Schema::new(vec![
                Field::new(
                    "event_ts",
                    DataType::Timestamp(TimeUnit::Microsecond, None),
                    false,
                ),
                Field::new("host", DataType::Utf8, false),
                Field::new("service", DataType::Utf8, true),
                Field::new("source", DataType::Utf8, true),
                Field::new("environment", DataType::Utf8, true),
                Field::new("severity", DataType::Utf8, true),
                Field::new("log_type", DataType::Utf8, true),
                Field::new("message", DataType::Utf8, false),
                Field::new("fields", DataType::Utf8, true),
            ]);
            let mut t = wh.table_or_create(T_EVENTS, &v1).await.unwrap();
            let s = |v: &str| -> StringArray { std::iter::once(Some(v)).collect() };
            let ts: TimestampMicrosecondArray = std::iter::once(Some(0i64)).collect();
            let batch = RecordBatch::try_new(
                Arc::new(v1.clone()),
                vec![
                    Arc::new(ts),
                    Arc::new(s("legacy-host")),
                    Arc::new(s("svc")),
                    Arc::new(s("syslog")),
                    Arc::new(s("prod")),
                    Arc::new(s("info")),
                    Arc::new(s("system")),
                    Arc::new(s("legacy line")),
                    Arc::new(s("{}")),
                ],
            )
            .unwrap();
            t.append(&[batch]).await.unwrap();
        } // drop the raw handle so spawn() can reopen the single-writer warehouse

        // 2) Open via spawn() (which calls ensure_schema) and append a V2 event.
        let state = StateStore::open(&cfg.store.state_db).expect("state");
        let handle = spawn(&cfg, state).await.expect("spawn");
        handle.append(vec![event("v2 line")]).await.unwrap();

        assert_eq!(count_via(&handle).await, 2, "legacy + V2 rows both present");
        // Provenance: only the V2 row carries a stable event_id; the legacy row
        // reads back NULL for the added columns.
        assert_eq!(
            count_sql(
                &handle,
                "SELECT count(*) AS n FROM events WHERE event_id IS NOT NULL"
            )
            .await,
            1,
            "only the V2 row has provenance columns populated"
        );
    }

    /// End-to-end through the actor: auto-compaction fires at the threshold,
    /// the handle reloads transparently, and both the write and read lanes keep
    /// working across the swap — no data lost, no stale-handle append failure.
    /// Asserts compaction ACTUALLY ran (rotated live dir + bounded snapshot
    /// count), so a silently-failing compactor can't pass.
    #[tokio::test]
    async fn actor_auto_compacts_and_stays_consistent() {
        let base = tmp("actor");
        std::fs::create_dir_all(&base).unwrap();
        let cfg = test_cfg(&base, 8); // the floor — compact every 8 fresh snapshots
        let state = StateStore::open(&cfg.store.state_db).expect("state");
        let handle = spawn(&cfg, state).await.expect("spawn");

        // 30 appends → the actor crosses the threshold several times and
        // compacts in between; each append is acknowledged only after persist.
        for i in 0..30 {
            handle
                .append(vec![event(&format!("evt {i}"))])
                .await
                .unwrap();
        }
        // Read lane sees all rows (compaction is transparent + gap-free).
        assert_eq!(
            count_via(&handle).await,
            30,
            "no rows lost across auto-compactions"
        );

        // Appending still works after the handle was reloaded post-swap.
        handle.append(vec![event("after")]).await.unwrap();
        assert_eq!(count_via(&handle).await, 31);

        // Compaction really fired: the live table rotated to a scratch-named
        // dir, and the snapshot count is bounded well below the append count.
        let loc = handle
            .wh
            .table(T_EVENTS)
            .await
            .unwrap()
            .inner()
            .metadata()
            .location()
            .to_string();
        assert!(loc.contains("__c"), "live table rotated by a swap: {loc}");
        let snaps = snapshot_count(&handle.wh, T_EVENTS).await;
        assert!(
            snaps <= 10,
            "snapshot count bounded by compaction, got {snaps}"
        );

        drop(handle);
        std::fs::remove_dir_all(&base).ok();
    }

    /// With retention enabled and a watermark set, the actor's compaction
    /// prunes sealed rows from the hot table.
    #[tokio::test]
    async fn actor_compaction_prunes_sealed_rows() {
        let base = tmp("actor-prune");
        std::fs::create_dir_all(&base).unwrap();
        let mut cfg = test_cfg(&base, 8);
        cfg.retention.enabled = true;
        let state = StateStore::open(&cfg.store.state_db).expect("state");
        let cutoff = chrono::Utc::now();
        // A sealed cold window covering the old rows — membership in this range
        // (not the watermark) is what licenses pruning.
        state
            .put_cold_archive(&garmr_core::ColdArchive {
                id: "prune-test".into(),
                kind: "plain".into(),
                file: "prune-test.parquet".into(),
                start_us: (cutoff - chrono::Duration::days(150)).timestamp_micros(),
                end_us: (cutoff - chrono::Duration::days(50)).timestamp_micros(),
                rows: 6,
                bytes_in: 0,
                bytes_out: 0,
                checksum: String::new(),
                hot_pruned: false,
                sealed_at: cutoff,
                legal_hold: false,
            })
            .unwrap();
        let handle = spawn(&cfg, state).await.expect("spawn");

        // 6 sealed-old + 3 fresh appends: the 9th append crosses the threshold
        // (8 fresh snapshots since baseline 1) and compacts with pruning. The
        // compaction runs on the actor AFTER acking the 9th append, so
        // serialise on it with a 10th append (the actor is serial: its ack
        // means the compaction finished) before asserting.
        for i in 0..6 {
            let e = event_at(&format!("old {i}"), cutoff - chrono::Duration::days(100));
            handle.append(vec![e]).await.unwrap();
        }
        for i in 0..3i64 {
            let e = event_at(
                &format!("new {i}"),
                cutoff + chrono::Duration::seconds(i + 1),
            );
            handle.append(vec![e]).await.unwrap();
        }
        handle.append(vec![event("after")]).await.unwrap();
        assert_eq!(
            count_via(&handle).await,
            4,
            "6 sealed rows pruned on compaction; 3 fresh + 1 post-swap kept"
        );

        drop(handle);
        std::fs::remove_dir_all(&base).ok();
    }

    /// Startup orphan sweep: drops leftover digit-suffixed scratch tables and
    /// retired data dirs, but never the live dir — and never a legitimate table
    /// that merely shares the `__c` prefix.
    #[tokio::test]
    async fn cleanup_orphans_sweeps_scratch_but_spares_live_and_lookalikes() {
        let dir = tmp("cleanup");
        let wh = skade::open(&dir).await.expect("open");
        {
            let mut t = wh
                .table_or_create(T_EVENTS, &events_schema())
                .await
                .unwrap();
            for i in 0..3 {
                t.append(&[build_events_batch(&[event(&format!("e {i}"))]).unwrap()])
                    .await
                    .unwrap();
            }
        }
        // A compaction leaves the retired original dir behind (GC is deferred).
        wh.compact_table(T_EVENTS, None).await.unwrap();
        let ns_dir = wh.root().join("warehouse").join(skade::DEFAULT_NAMESPACE);
        assert!(
            ns_dir.join("events").exists(),
            "retired original dir present pre-sweep"
        );

        // Plant a crashed-compaction scratch table and a legitimate lookalike.
        wh.create_table("events__c424242", &events_schema())
            .await
            .unwrap();
        wh.create_table("events__cold", &events_schema())
            .await
            .unwrap();

        cleanup_orphans(&wh, T_EVENTS).await.unwrap();

        // Scratch table + retired dir gone; live + lookalike intact.
        assert!(!ns_dir.join("events").exists(), "retired dir swept");
        assert!(
            !ns_dir.join("events__c424242").exists(),
            "scratch dir swept"
        );
        assert!(
            wh.table("events__c424242").await.is_err(),
            "scratch table dropped"
        );
        assert!(
            wh.table("events__cold").await.is_ok(),
            "lookalike table survives"
        );
        assert!(
            ns_dir.join("events__cold").exists(),
            "lookalike dir survives"
        );
        assert_eq!(count_events(&wh).await, 3, "live table intact after sweep");

        std::fs::remove_dir_all(&dir).ok();
    }

    /// Absolute paths of the live `events` table's current Parquet data files.
    async fn live_data_files(wh: &skade::Warehouse) -> Vec<PathBuf> {
        let loc = wh
            .table(T_EVENTS)
            .await
            .unwrap()
            .inner()
            .metadata()
            .location()
            .to_string();
        let dir = loc.strip_prefix("file://").unwrap_or(&loc);
        let data = std::path::Path::new(dir).join("data");
        std::fs::read_dir(&data)
            .unwrap()
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|x| x == "parquet"))
            .collect()
    }

    /// True iff any row group in the Parquet file at `path` carries a bloom
    /// filter on the leaf column `col` (a `bloom_filter_offset` in its footer).
    fn parquet_has_bloom_on(path: &std::path::Path, col: &str) -> bool {
        use skade::parquet::file::reader::{FileReader, SerializedFileReader};
        let file = std::fs::File::open(path).unwrap();
        let reader = SerializedFileReader::new(file).unwrap();
        reader.metadata().row_groups().iter().any(|rg| {
            rg.columns()
                .iter()
                .any(|c| c.column_path().string() == col && c.bloom_filter_offset().is_some())
        })
    }

    /// The read-path lever: events appends must write a Parquet bloom filter on
    /// `event_id` (and only there), the compaction rebuild must preserve it, and
    /// an exact `event_id` lookup must resolve the row through skade's
    /// bloom-aware point-lookup path.
    #[tokio::test]
    async fn events_bloom_on_event_id_written_survives_compaction_and_lookup_works() {
        let dir = tmp("bloom");
        let wh = skade::open(&dir).await.expect("open");

        // Append via a handle configured exactly like the actor's (bloom on
        // event_id). Fixed timestamps make the ids reproducible for the lookup.
        let base = chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap();
        let probe = event_at("line 2", base + chrono::Duration::seconds(2));
        let probe_id = crate::schema::event_id_for(&probe);
        {
            let mut t = wh
                .table_or_create(T_EVENTS, &events_schema())
                .await
                .unwrap();
            t.set_write_props(crate::schema::events_write_props());
            for i in 0..5i64 {
                let e = event_at(&format!("line {i}"), base + chrono::Duration::seconds(i));
                t.append(&[build_events_batch(&[e]).unwrap()])
                    .await
                    .unwrap();
            }
        }

        // Every data file blooms event_id — and nothing else (e.g. not `host`).
        let files = live_data_files(&wh).await;
        assert!(!files.is_empty(), "append produced data files");
        assert!(
            files.iter().all(|f| parquet_has_bloom_on(f, "event_id")),
            "every appended data file carries a bloom filter on event_id"
        );
        assert!(
            files.iter().all(|f| !parquet_has_bloom_on(f, "host")),
            "only event_id is bloomed, not other columns"
        );

        // The compaction rebuild keeps the bloom (a plain rebuild would drop it).
        wh.compact_table_props(T_EVENTS, None, &crate::schema::events_compact_write_props())
            .await
            .unwrap();
        let files = live_data_files(&wh).await;
        assert!(!files.is_empty(), "compaction produced data files");
        assert!(
            files.iter().all(|f| parquet_has_bloom_on(f, "event_id")),
            "event_id bloom survives the compaction rebuild"
        );

        // The bloom's consumer: an exact event_id probe resolves the row.
        let t = wh.table(T_EVENTS).await.unwrap();
        let row = t
            .lookup(&[("event_id", skade::Scalar::Str(probe_id))], None)
            .await
            .unwrap();
        assert!(row.is_some(), "exact event_id lookup finds the row");

        std::fs::remove_dir_all(&dir).ok();
    }

    /// Walk `root` and total the Iceberg metadata footprint — the pathology is
    /// the resident `*.metadata.json` growing without bound as the table accretes
    /// one tiny Parquet file per commit. Returns
    /// `(largest_metadata_json_bytes, total_metadata_json_bytes, parquet_files)`.
    fn metadata_footprint(root: &std::path::Path) -> (u64, u64, u64) {
        fn walk(dir: &std::path::Path, acc: &mut (u64, u64, u64)) {
            let Ok(entries) = std::fs::read_dir(dir) else {
                return;
            };
            for e in entries.flatten() {
                let p = e.path();
                if p.is_dir() {
                    walk(&p, acc);
                    continue;
                }
                let name = e.file_name();
                let name = name.to_string_lossy();
                let len = e.metadata().map(|m| m.len()).unwrap_or(0);
                if name.ends_with(".metadata.json") {
                    acc.0 = acc.0.max(len); // largest single = the one loaded into RAM
                    acc.1 += len;
                } else if name.ends_with(".parquet") {
                    acc.2 += 1;
                }
            }
        }
        let mut acc = (0u64, 0u64, 0u64);
        walk(root, &mut acc);
        acc
    }

    /// THE OOM PROOF. Drive the same continuous single-row-per-commit ingest
    /// (what group-commit produces on a live SOC) two ways — compaction OFF vs
    /// ON — and show that OFF grows the resident metadata O(appends) while ON
    /// stays flat. This is the regression guard for the pathology that OOM-killed
    /// the dogfood every ~5 h and hung 208 soc-warehouse (RSS 1.1→6.1 GB).
    ///
    /// `#[ignore]` — it does N fsync-ing commits; run explicitly:
    /// `cargo test -p garmr-store growth -- --ignored --nocapture`.
    #[tokio::test]
    #[ignore]
    async fn compaction_bounds_metadata_growth_over_time() {
        const N: usize = 250;
        const THRESHOLD: usize = 8;

        // --- OFF: fast_append per commit, never compacted (today's pathology).
        let off_dir = tmp("growth-off");
        let off = skade::open(&off_dir).await.unwrap();
        {
            let mut t = off
                .table_or_create(T_EVENTS, &events_schema())
                .await
                .unwrap();
            for i in 0..N {
                t.append(&[build_events_batch(&[event(&format!("line {i}"))]).unwrap()])
                    .await
                    .unwrap();
            }
        }
        let off_snaps = snapshot_count(&off, T_EVENTS).await;
        let (off_cur, off_total, off_parquet) = metadata_footprint(&off_dir);

        // --- ON: identical ingest, compacted every THRESHOLD fresh snapshots
        // (what the actor does automatically; done inline here so the test needs
        // no live Loki/actor plumbing).
        let on_dir = tmp("growth-on");
        let on = skade::open(&on_dir).await.unwrap();
        {
            let mut t = on
                .table_or_create(T_EVENTS, &events_schema())
                .await
                .unwrap();
            let mut baseline = 1usize;
            for i in 0..N {
                t.append(&[build_events_batch(&[event(&format!("line {i}"))]).unwrap()])
                    .await
                    .unwrap();
                let snaps = t.inner().metadata().snapshots().len();
                if snaps.saturating_sub(baseline) >= THRESHOLD {
                    on.compact_table(T_EVENTS, None).await.unwrap();
                    t.refresh().await.unwrap();
                    baseline = t.inner().metadata().snapshots().len();
                }
            }
        }
        let on_snaps = snapshot_count(&on, T_EVENTS).await;
        let (on_cur, on_total, on_parquet) = metadata_footprint(&on_dir);

        // Both paths preserved every row (correctness before footprint).
        assert_eq!(count_events(&off).await, N as i64, "OFF kept all rows");
        assert_eq!(count_events(&on).await, N as i64, "ON kept all rows");

        eprintln!("\n=== skade metadata growth over {N} commits (threshold {THRESHOLD}) ===");
        eprintln!("               snapshots  live-metadata.json  all-metadata.json  parquet-files");
        eprintln!(
            "  compaction OFF: {off_snaps:>7}  {off_cur:>14} B  {off_total:>15} B  {off_parquet:>10}"
        );
        eprintln!(
            "  compaction ON:  {on_snaps:>7}  {on_cur:>14} B  {on_total:>15} B  {on_parquet:>10}"
        );
        eprintln!(
            "  → live-metadata shrunk {:.1}×, snapshots {:.1}× fewer, tiny files {:.1}× fewer\n",
            off_cur as f64 / on_cur.max(1) as f64,
            off_snaps as f64 / on_snaps.max(1) as f64,
            off_parquet as f64 / on_parquet.max(1) as f64,
        );

        // The pathology: OFF's live metadata.json grows ~linearly with commits.
        assert!(off_snaps >= N - 1, "OFF accretes one snapshot per commit");
        // The fix: ON's live metadata.json (the thing loaded into RAM) and its
        // snapshot count are BOUNDED — independent of how long ingest runs.
        assert!(
            on_snaps <= THRESHOLD + 2,
            "ON snapshot count bounded, got {on_snaps}"
        );
        assert!(
            on_cur * 4 < off_cur,
            "ON live metadata.json must be far smaller: on={on_cur} off={off_cur}"
        );

        std::fs::remove_dir_all(&off_dir).ok();
        std::fs::remove_dir_all(&on_dir).ok();
    }

    #[tokio::test]
    async fn erase_removes_the_subject_and_spares_everyone_else() {
        // The M3 acceptance line: src_ip A erased from hot, B survives, and a
        // re-run is a zero-delta no-op (idempotent convergence).
        let base = tmp("erase");
        std::fs::create_dir_all(&base).unwrap();
        let cfg = test_cfg(&base, 0);
        let state = StateStore::open(&cfg.store.state_db).expect("state");
        let handle = spawn(&cfg, state.clone()).await.expect("spawn");

        let with_ip = |msg: &str, ip: &str| {
            let mut e = event(msg);
            e.fields.insert("src_ip".to_string(), ip.to_string());
            e
        };
        handle
            .append(vec![
                with_ip("login A one", "203.0.113.7"),
                with_ip("login A two", "203.0.113.7"),
                with_ip("login B", "10.0.0.5"),
            ])
            .await
            .unwrap();
        assert_eq!(count_via(&handle).await, 3);

        state
            .put_tombstone(&garmr_core::Tombstone {
                id: "erase-test".into(),
                field: garmr_core::EraseField::SrcIp,
                value: "203.0.113.7".into(),
                from_us: None,
                to_us: None,
                placed_at: chrono::Utc::now(),
                reason: "test".into(),
            })
            .unwrap();

        let erased = handle.erase_matching(&state).await.unwrap();
        assert_eq!(erased, 2, "both of A's rows go");
        assert_eq!(count_via(&handle).await, 1, "B survives");

        // Idempotent: nothing left to erase, nothing else harmed.
        let again = handle.erase_matching(&state).await.unwrap();
        assert_eq!(again, 0, "re-run is a zero-delta no-op");
        assert_eq!(count_via(&handle).await, 1);

        // Convergence: a LATE ARRIVAL matching the tombstone is erased by the
        // next pass — the reason the tombstone is persistent.
        handle
            .append(vec![with_ip("late replay of A", "203.0.113.7")])
            .await
            .unwrap();
        assert_eq!(count_via(&handle).await, 2);
        assert_eq!(handle.erase_matching(&state).await.unwrap(), 1);
        assert_eq!(
            count_via(&handle).await,
            1,
            "the late arrival converged away"
        );
    }
}
