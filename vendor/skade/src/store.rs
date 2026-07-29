// Apache-2.0 licensed.

//! Thin typed wrapper around the redb database.
//!
//! Three tables live inside the file:
//!
//! * `namespaces`        — marker rows; presence = "namespace exists".
//! * `namespace_props`   — `(catalog, ns, prop_key)` → prop value.
//! * `tables`            — `(catalog, ns, table_name)` → current metadata
//!   location (Iceberg metadata JSON path).
//!
//! All writes are funnelled through a `tokio::sync::Mutex<Database>` so that
//! the async `Catalog` trait can call us from multiple tasks without each one
//! having to block a runtime thread on redb's sync transaction APIs. redb
//! itself only allows a single writer at a time anyway, so this just makes
//! the queueing explicit and non-blocking.

use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex};

use arc_swap::ArcSwapOption;
use iceberg::{Error, ErrorKind};
use redb::{Database, ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, broadcast, oneshot};

use crate::pointer_cache::PointerCache;
use crate::static_index::StaticIndex;

/// A durable catalog commit became visible: the streaming spine's unit of
/// change. Published on a `tokio::sync::broadcast` after the redb write commits
/// and the L1 mirror is updated, and also reconstructable from the durable
/// [`COMMIT_LOG`] via [`crate::RedbCatalog::commits_since`]. Cheap to clone
/// (`Arc`-backed strings); a dropped event on a no-receiver channel is fine —
/// the broadcast is a low-latency *hint*, the durable log is the truth.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitEvent {
    /// Internal table key `"{catalog}\x1f{ns}\x1f{table}"` (see
    /// [`crate::RedbCatalog::commit_table_key`] to compute it for a `TableIdent`).
    pub table_key: Arc<str>,
    /// The snapshot the commit advanced the table to, or `None` for a
    /// snapshot-less pointer move (a table create or a metadata-only property
    /// update — these carry no changelog window, so a changelog consumer skips
    /// them; the event still marks the commit for `commit_seq` accounting).
    pub snapshot_id: Option<i64>,
    /// The metadata location the pointer now points at.
    pub metadata_location: Arc<str>,
    /// Durable, gapless, monotonic commit cursor (`META_COMMIT_SEQ`). The
    /// resume/exactly-once key: `commits_since(cursor)` returns every event with
    /// `commit_seq > cursor`.
    pub commit_seq: u64,
    /// Event time, microseconds since the Unix epoch (stamped in the txn).
    pub ts_micros: i64,
}

/// Broadcast ring capacity: how many commit events a lagging subscriber may fall
/// behind before it observes `RecvError::Lagged` and must catch up via the
/// durable [`crate::RedbCatalog::commits_since`]. The broadcast is intentionally
/// lossy under slow consumers (bounded memory); the durable log recovers
/// correctness.
pub const COMMIT_EVENT_BUFFER: usize = 1024;

/// The on-disk row of the [`COMMIT_LOG`] secondary index: everything needed to
/// reconstruct a [`CommitEvent`] from a `commit_seq` range scan. Serialized as
/// JSON (one row per snapshot-carrying commit, in the same write txn — no extra
/// fsync).
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct CommitLogRow {
    pub(crate) table_key: String,
    pub(crate) snapshot_id: Option<i64>,
    pub(crate) metadata_location: String,
    pub(crate) ts_micros: i64,
}

/// Microseconds since the Unix epoch, saturating at 0 before the epoch.
pub(crate) fn now_micros() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_micros() as i64)
        .unwrap_or(0)
}

/// Decode a [`COMMIT_LOG`] row (`commit_seq` + JSON bytes) into a [`CommitEvent`].
pub(crate) fn decode_commit_log(
    seq: u64,
    bytes: &[u8],
) -> Result<CommitEvent, crate::error::RedbCatalogError> {
    let row: CommitLogRow = serde_json::from_slice(bytes)?;
    Ok(CommitEvent {
        table_key: Arc::from(row.table_key.as_str()),
        snapshot_id: row.snapshot_id,
        metadata_location: Arc::from(row.metadata_location.as_str()),
        commit_seq: seq,
        ts_micros: row.ts_micros,
    })
}

/// What a committed write should publish to the in-memory L1 pointer mirror once
/// its group transaction lands. Returned by a [`CommitFn`].
#[derive(Default)]
pub(crate) struct CommitOutcome {
    /// `(table_key, metadata_location)` to insert into the mirror.
    pub(crate) mirror_insert: Option<(String, String)>,
    /// `table_key` to remove from the mirror.
    pub(crate) mirror_remove: Option<String>,
    /// The commit event to broadcast once the group transaction lands (set by
    /// the commit closure from [`record_commit`]'s output; `None` for a
    /// snapshot-less pointer move).
    pub(crate) event: Option<CommitEvent>,
}

impl CommitOutcome {
    pub(crate) fn insert(key: impl Into<String>, loc: impl Into<String>) -> Self {
        Self {
            mirror_insert: Some((key.into(), loc.into())),
            mirror_remove: None,
            event: None,
        }
    }

    /// Attach the commit event to broadcast post-commit (builder form).
    pub(crate) fn with_event(mut self, event: Option<CommitEvent>) -> Self {
        self.event = event;
        self
    }
}

/// A single catalog mutation's redb work, run *inside* a shared group write
/// transaction. It must check its own optimistic precondition and **write
/// nothing** when returning `Err`, so a failing op cannot taint the others'
/// commit. Returns the mirror update to publish after the group commits.
pub(crate) type CommitFn =
    Box<dyn FnOnce(&redb::WriteTransaction) -> iceberg::Result<CommitOutcome> + Send>;

struct PendingCommit {
    apply: CommitFn,
    done: oneshot::Sender<iceberg::Result<CommitOutcome>>,
}

impl std::fmt::Debug for PendingCommit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PendingCommit")
    }
}

pub(crate) const NAMESPACES: TableDefinition<&str, &[u8]> = TableDefinition::new("namespaces");
pub(crate) const NAMESPACE_PROPS: TableDefinition<&str, &str> =
    TableDefinition::new("namespace_props");
pub(crate) const TABLES: TableDefinition<&str, &str> = TableDefinition::new("tables");

/// Immutable commit log: `{table_key}\x1f{snapshot_id:u64_be} → metadata_location`,
/// appended on every commit that carries a snapshot. Keyed by the (monotonic,
/// never-mutated) snapshot id, so it is the source the Ragnar `StaticIndex`
/// compactor scans and the backing store for `load_table_at(snapshot_id)`.
pub(crate) const COMMITS: TableDefinition<&[u8], &str> = TableDefinition::new("commits");
/// Secondary commit index keyed by the monotonic `commit_seq` (`u64`, natural
/// ascending order) → a JSON [`CommitLogRow`]. `COMMITS` is keyed by
/// `(table_key, snapshot_id)` and so cannot be range-scanned by sequence; this
/// index is what [`crate::RedbCatalog::commits_since`] walks to replay the
/// durable commit stream for a late/lagged subscriber. Appended in the *same*
/// write txn as everything else, so it costs no extra fsync.
pub(crate) const COMMIT_LOG: TableDefinition<u64, &[u8]> = TableDefinition::new("commit_log");
/// Small key/value counters table (see the `META_*` keys).
pub(crate) const META: TableDefinition<&str, u64> = TableDefinition::new("meta");

/// Monotonic count of all commits ever recorded (never reset).
pub(crate) const META_COMMIT_SEQ: &str = "commit_seq";
/// Commits since the last static-index compaction (drives rebuild triggers; the
/// compactor resets it).
pub(crate) const META_UPDATE_COUNTER: &str = "update_counter";
/// Reads that fell through to the redb live tail above the static-index cutoff.
#[allow(dead_code)] // consumed by the static-index routing/compactor (items f/g)
pub(crate) const META_LIVE_TAIL_MISSES: &str = "live_tail_misses";

/// Commits since the last compaction that trigger a background static-index
/// rebuild. Small enough that real workloads compact promptly; large enough
/// that bursty writers don't thrash.
pub(crate) const COMPACT_THRESHOLD: u64 = 1024;

/// Encode a commit-log key: `{table_key}\x1f{snapshot_id as u64, big-endian}`.
/// Big-endian keeps redb's lexicographic order equal to ascending snapshot
/// order within a table, so per-table range scans and time-travel cutoffs are
/// contiguous.
pub(crate) fn commit_key(table_key: &str, snapshot_id: i64) -> Vec<u8> {
    let mut k = Vec::with_capacity(table_key.len() + 1 + 8);
    k.extend_from_slice(table_key.as_bytes());
    k.push(b'\x1f');
    k.extend_from_slice(&(snapshot_id as u64).to_be_bytes());
    k
}

/// What [`record_commit`] produced: the new gapless `commit_seq`, and the
/// [`CommitEvent`] to broadcast once the transaction lands (present iff the
/// commit carried a snapshot).
pub(crate) struct RecordedCommit {
    /// The new gapless `commit_seq` (asserted by tests; callers on the write
    /// path only need `event`).
    #[allow(dead_code)]
    pub(crate) seq: u64,
    pub(crate) event: Option<CommitEvent>,
}

/// Append the commit to the immutable [`COMMITS`] log and the `commit_seq`-keyed
/// [`COMMIT_LOG`] index (both only when it carries a `snapshot_id`) and bump the
/// [`META`] counters — all inside the caller's write transaction, so the logs
/// and counters advance atomically with the table pointer in [`TABLES`]. Returns
/// the new `commit_seq` plus the [`CommitEvent`] the caller must broadcast once
/// `write.commit()` succeeds.
pub(crate) fn record_commit(
    write: &redb::WriteTransaction,
    table_key: &str,
    snapshot_id: Option<i64>,
    metadata_location: &str,
) -> Result<RecordedCommit, crate::error::RedbCatalogError> {
    let ts_micros = now_micros();
    if let Some(sid) = snapshot_id {
        let mut commits = write.open_table(COMMITS)?;
        commits.insert(commit_key(table_key, sid).as_slice(), metadata_location)?;
    }
    let mut meta = write.open_table(META)?;
    let seq = meta.get(META_COMMIT_SEQ)?.map(|v| v.value()).unwrap_or(0) + 1;
    meta.insert(META_COMMIT_SEQ, seq)?;
    let upd = meta
        .get(META_UPDATE_COUNTER)?
        .map(|v| v.value())
        .unwrap_or(0)
        + 1;
    meta.insert(META_UPDATE_COUNTER, upd)?;

    // Every pointer advance gets a durable, seq-ordered [`COMMIT_LOG`] row + a
    // broadcast event (whether or not it carried a snapshot). The `COMMITS`
    // time-travel index above is still snapshot-only; this seq-keyed log is the
    // streaming cursor and includes snapshot-less commits so `commit_seq`
    // accounting stays gapless for a resuming consumer.
    let row = CommitLogRow {
        table_key: table_key.to_string(),
        snapshot_id,
        metadata_location: metadata_location.to_string(),
        ts_micros,
    };
    let bytes = serde_json::to_vec(&row)?;
    let mut log = write.open_table(COMMIT_LOG)?;
    log.insert(seq, bytes.as_slice())?;
    let event = Some(CommitEvent {
        table_key: Arc::from(table_key),
        snapshot_id,
        metadata_location: Arc::from(metadata_location),
        commit_seq: seq,
        ts_micros,
    });
    Ok(RecordedCommit { seq, event })
}

/// Shared, cloneable handle to the underlying redb database.
#[derive(Debug, Clone)]
pub(crate) struct Store {
    pub(crate) path: PathBuf,
    pub(crate) db: Arc<Mutex<Database>>,
    /// L1: lock-free current-pointer mirror, shared across catalog clones.
    pub(crate) pointers: PointerCache,
    /// Durability applied to every catalog-mutation write transaction.
    pub(crate) durability: redb::Durability,
    /// L1-historical: the swappable Ragnar static snapshot-id index. `None`
    /// until the first compaction (or a warm rebuild at open). Read lock-free
    /// via [`ArcSwapOption`]; the compactor replaces it wholesale.
    pub(crate) static_index: Arc<ArcSwapOption<StaticIndex>>,
    /// Highest snapshot id covered by `static_index` — the routing cutoff.
    pub(crate) cutoff: Arc<AtomicI64>,
    /// Single-flight guard: set while a background compaction is in flight.
    pub(crate) compacting: Arc<AtomicBool>,
    /// Commits observed since the last compaction (drives the rebuild trigger).
    pub(crate) writes_since_compaction: Arc<AtomicU64>,
    /// Group-commit queue: pending mutations waiting to be coalesced into one
    /// write transaction (one fsync) by whichever task wins the db lock.
    commit_queue: Arc<StdMutex<VecDeque<PendingCommit>>>,
    /// The streaming spine: a [`CommitEvent`] is published here after every
    /// snapshot-carrying commit lands. Cloned across catalog clones (all share
    /// one channel). Eagerly created; `send` on a no-receiver channel is a cheap
    /// no-op, so the poll-only default pays nothing.
    pub(crate) events: broadcast::Sender<CommitEvent>,
}

impl Store {
    pub(crate) fn open(
        path: PathBuf,
        durability: redb::Durability,
    ) -> Result<Self, redb::DatabaseError> {
        let db = Database::create(&path)?;
        // Ensure all tables exist so reads on a brand-new file don't trip
        // `TableError::TableDoesNotExist`.
        let write = db.begin_write().map_err(|e| match e {
            redb::TransactionError::Storage(s) => redb::DatabaseError::Storage(s),
            other => redb::DatabaseError::Storage(redb::StorageError::Io(std::io::Error::other(
                other.to_string(),
            ))),
        })?;
        {
            let _ = write.open_table(NAMESPACES);
            let _ = write.open_table(NAMESPACE_PROPS);
            let _ = write.open_table(TABLES);
            let _ = write.open_table(COMMITS);
            let _ = write.open_table(COMMIT_LOG);
            let _ = write.open_table(META);
        }
        write.commit().map_err(|e| {
            redb::DatabaseError::Storage(redb::StorageError::Io(std::io::Error::other(
                e.to_string(),
            )))
        })?;

        // Build the L1 pointer mirror from a one-shot scan of the (small)
        // `tables` keyspace. This is the only full scan; thereafter the mirror
        // is maintained write-through and reads never touch redb.
        let pointers = {
            let read = db.begin_read().map_err(other_db_err)?;
            let tbl = read.open_table(TABLES).map_err(other_db_err)?;
            let mut entries: Vec<(String, String)> = Vec::new();
            for row in tbl.iter().map_err(other_db_err)? {
                let (k, v) = row.map_err(other_db_err)?;
                entries.push((k.value().to_string(), v.value().to_string()));
            }
            PointerCache::from_entries(entries)
        };

        // Warm-start the historical static index from the durable commit log,
        // so a reopened database with history is immediately accelerated. Also
        // carry the pending update counter into the in-memory trigger.
        let (static_index, cutoff, pending) = {
            let read = db.begin_read().map_err(other_db_err)?;
            let idx = StaticIndex::build(&read).map_err(other_db_err)?;
            let cutoff = idx.as_ref().map(|i| i.max_id()).unwrap_or(i64::MIN);
            let pending = read
                .open_table(META)
                .ok()
                .and_then(|m| m.get(META_UPDATE_COUNTER).ok().flatten().map(|v| v.value()))
                .unwrap_or(0);
            (idx.map(Arc::new), cutoff, pending)
        };

        Ok(Self {
            path,
            db: Arc::new(Mutex::new(db)),
            pointers,
            durability,
            static_index: Arc::new(ArcSwapOption::from(static_index)),
            cutoff: Arc::new(AtomicI64::new(cutoff)),
            compacting: Arc::new(AtomicBool::new(false)),
            writes_since_compaction: Arc::new(AtomicU64::new(pending)),
            commit_queue: Arc::new(StdMutex::new(VecDeque::new())),
            events: broadcast::channel(COMMIT_EVENT_BUFFER).0,
        })
    }

    /// Broadcast a commit event on the streaming spine. A dropped send (no
    /// subscribers) is fine — durability is the [`COMMIT_LOG`], not the channel.
    pub(crate) fn publish(&self, event: Option<CommitEvent>) {
        if let Some(ev) = event {
            let _ = self.events.send(ev);
        }
    }

    /// Group commit: enqueue `apply`, then race for the db write lock. Whoever
    /// wins drains **all** queued mutations and runs them in a single redb write
    /// transaction with a single `commit()` (one fsync amortised across the
    /// whole batch), then publishes each op's mirror update and wakes its
    /// caller. Concurrent committers that lose the race find their work already
    /// done. Optimistic conflicts are isolated per op (a failing op writes
    /// nothing), exactly as in the one-txn-per-commit path.
    pub(crate) async fn group_commit(&self, apply: CommitFn) -> iceberg::Result<CommitOutcome> {
        let (tx, rx) = oneshot::channel();
        self.commit_queue
            .lock()
            .unwrap()
            .push_back(PendingCommit { apply, done: tx });

        {
            let db = self.db.lock().await;
            // Drain everything queued so far — this is the coalesced batch.
            let batch: Vec<PendingCommit> = self.commit_queue.lock().unwrap().drain(..).collect();

            if !batch.is_empty() {
                let mut committed: Vec<(
                    oneshot::Sender<iceberg::Result<CommitOutcome>>,
                    iceberg::Result<CommitOutcome>,
                )> = Vec::with_capacity(batch.len());
                let mut applied = 0u64;

                match db.begin_write() {
                    Ok(mut write) => {
                        write.set_durability(self.durability);
                        for PendingCommit { apply, done } in batch {
                            let r = apply(&write);
                            if r.is_ok() {
                                applied += 1;
                            }
                            committed.push((done, r));
                        }
                        // One fsync for the whole batch.
                        match write.commit() {
                            Ok(()) => {
                                for (done, r) in committed {
                                    if let Ok(out) = &r {
                                        if let Some((k, loc)) = &out.mirror_insert {
                                            self.pointers.insert(k, loc);
                                        }
                                        if let Some(k) = &out.mirror_remove {
                                            self.pointers.remove(k);
                                        }
                                        // Streaming spine: publish the commit event
                                        // now that it is durable + mirror-visible.
                                        if let Some(ev) = &out.event {
                                            let _ = self.events.send(ev.clone());
                                        }
                                    }
                                    let _ = done.send(r);
                                }
                                // Advance the compaction counter once per applied
                                // commit (single-flight spawns at most one rebuild).
                                for _ in 0..applied {
                                    self.maybe_trigger_compaction();
                                }
                            }
                            Err(e) => {
                                // The whole group failed to land — fail all.
                                let msg = format!("group commit failed: {e}");
                                for (done, _) in committed {
                                    let _ = done
                                        .send(Err(Error::new(ErrorKind::Unexpected, msg.clone())));
                                }
                            }
                        }
                    }
                    Err(e) => {
                        let msg = format!("begin_write failed: {e}");
                        for PendingCommit { apply: _, done } in batch {
                            let _ = done.send(Err(Error::new(ErrorKind::Unexpected, msg.clone())));
                        }
                    }
                }
            }
        }

        rx.await.map_err(|_| {
            Error::new(
                ErrorKind::Unexpected,
                "group commit worker dropped the result",
            )
        })?
    }

    /// Rebuild the static index from the durable commit log and swap it in,
    /// advancing the cutoff and resetting the persisted update counter. The
    /// caller supplies the already-locked database. Returns the entry count.
    pub(crate) fn compact_with_db(
        &self,
        db: &Database,
    ) -> Result<usize, crate::error::RedbCatalogError> {
        let idx = {
            let read = db.begin_read()?;
            StaticIndex::build(&read)?
        };
        let count = idx.as_ref().map(|i| i.len()).unwrap_or(0);
        let max = idx.as_ref().map(|i| i.max_id()).unwrap_or(i64::MIN);
        self.static_index.store(idx.map(Arc::new));
        self.cutoff.store(max, Ordering::Release);
        {
            let mut w = db.begin_write()?;
            w.set_durability(self.durability);
            {
                let mut meta = w.open_table(META)?;
                meta.insert(META_UPDATE_COUNTER, 0u64)?;
            }
            w.commit()?;
        }
        self.writes_since_compaction.store(0, Ordering::Release);
        Ok(count)
    }

    /// Count a freshly-committed write and, if the threshold is crossed and no
    /// compaction is already running, kick a background rebuild (fire-and-forget,
    /// single-flight via `compacting`). Reads stay lock-free throughout; the
    /// only cost on the write path is one atomic increment.
    pub(crate) fn maybe_trigger_compaction(&self) {
        let n = self.writes_since_compaction.fetch_add(1, Ordering::AcqRel) + 1;
        if n < COMPACT_THRESHOLD {
            return;
        }
        if self
            .compacting
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return; // a compaction is already in flight
        }
        let me = self.clone();
        std::thread::spawn(move || {
            let db = me.db.blocking_lock();
            let _ = me.compact_with_db(&db);
            me.compacting.store(false, Ordering::Release);
        });
    }
}

/// Map any redb sub-error into a `DatabaseError` for the `open` path.
fn other_db_err(e: impl std::fmt::Display) -> redb::DatabaseError {
    redb::DatabaseError::Storage(redb::StorageError::Io(std::io::Error::other(e.to_string())))
}

#[cfg(test)]
mod tests {
    use super::*;
    use redb::Database;

    #[test]
    fn commit_key_orders_ascending_by_snapshot() {
        let tk = "cat\x1fns\x1ft";
        assert!(commit_key(tk, 1) < commit_key(tk, 2));
        assert!(commit_key(tk, 2) < commit_key(tk, 1_000_000));
        // Distinct tables don't collide.
        assert_ne!(
            commit_key("cat\x1fns\x1fa", 1),
            commit_key("cat\x1fns\x1fb", 1)
        );
    }

    // Many tasks commit concurrently through `group_commit`; coalescing into
    // shared transactions must still land every commit in both redb and the
    // lock-free pointer mirror.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn group_commit_lands_all_concurrent_commits() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path().join("c.redb"), redb::Durability::Immediate).unwrap();
        let n = 64usize;
        let mut handles = Vec::new();
        for i in 0..n {
            let s = store.clone();
            handles.push(tokio::spawn(async move {
                let key = format!("cat\x1fns\x1ft{i:03}");
                let loc = format!("s3://wh/{i:03}.metadata.json");
                let (k, l) = (key.clone(), loc.clone());
                s.group_commit(Box::new(move |w| {
                    let mut t = w
                        .open_table(TABLES)
                        .map_err(|e| Error::new(ErrorKind::Unexpected, e.to_string()))?;
                    t.insert(k.as_str(), l.as_str())
                        .map_err(|e| Error::new(ErrorKind::Unexpected, e.to_string()))?;
                    Ok(CommitOutcome::insert(k, l))
                }))
                .await
                .unwrap();
            }));
        }
        for h in handles {
            h.await.unwrap();
        }

        // Every key present in the mirror…
        let mut in_mirror = 0usize;
        for i in 0..n {
            let key = format!("cat\x1fns\x1ft{i:03}");
            assert!(store.pointers.get(&key).is_some(), "mirror missing {key}");
            in_mirror += 1;
        }
        // …and durably in redb.
        let db = store.db.lock().await;
        let read = db.begin_read().unwrap();
        let t = read.open_table(TABLES).unwrap();
        let mut in_redb = 0usize;
        for i in 0..n {
            let key = format!("cat\x1fns\x1ft{i:03}");
            assert!(t.get(key.as_str()).unwrap().is_some(), "redb missing {key}");
            in_redb += 1;
        }
        assert!(in_mirror == n && in_redb == n);
        #[cfg(feature = "testmatrix")]
        nornir_testmatrix::functional_status(
            "store",
            "group_commit_lands_all_concurrent_commits",
            in_mirror == n && in_redb == n,
            &format!(
                "{n} concurrent group commits → mirror={in_mirror} redb={in_redb} (want {n} each)"
            ),
        );
    }

    #[test]
    fn record_commit_appends_log_and_bumps_counters() {
        let dir = tempfile::tempdir().unwrap();
        let db = Database::create(dir.path().join("c.redb")).unwrap();
        {
            let w = db.begin_write().unwrap();
            {
                let _ = w.open_table(COMMITS);
                let _ = w.open_table(COMMIT_LOG);
                let _ = w.open_table(META);
            }
            w.commit().unwrap();
        }

        let tk = "cat\x1fns\x1ft";
        {
            let w = db.begin_write().unwrap();
            let s1 = record_commit(&w, tk, Some(10), "loc-a").unwrap().seq;
            // A commit without a snapshot still counts but adds no log row.
            let s2 = record_commit(&w, tk, None, "loc-b").unwrap().seq;
            let s3 = record_commit(&w, tk, Some(20), "loc-c").unwrap().seq;
            assert_eq!((s1, s2, s3), (1, 2, 3));
            w.commit().unwrap();
        }

        let r = db.begin_read().unwrap();
        let commits = r.open_table(COMMITS).unwrap();
        assert_eq!(
            commits
                .get(commit_key(tk, 10).as_slice())
                .unwrap()
                .unwrap()
                .value(),
            "loc-a"
        );
        assert_eq!(
            commits
                .get(commit_key(tk, 20).as_slice())
                .unwrap()
                .unwrap()
                .value(),
            "loc-c"
        );
        // The None commit added no row.
        let none_added_no_row = commits.get(commit_key(tk, 0).as_slice()).unwrap().is_none();
        assert!(
            none_added_no_row,
            "the None-snapshot commit added no log row"
        );

        let meta = r.open_table(META).unwrap();
        let seq = meta.get(META_COMMIT_SEQ).unwrap().unwrap().value();
        let upd = meta.get(META_UPDATE_COUNTER).unwrap().unwrap().value();
        assert_eq!(seq, 3);
        assert_eq!(upd, 3);
        #[cfg(feature = "testmatrix")]
        nornir_testmatrix::functional_status(
            "store",
            "record_commit_appends_log_and_bumps_counters",
            seq == 3 && upd == 3 && none_added_no_row,
            &format!(
                "commit_seq={seq} update_counter={upd} (want 3/3); snapshot-less commit added no log row={none_added_no_row}"
            ),
        );
    }

    fn record(db: &Database, tk: &str, sid: i64, loc: &str) {
        let w = db.begin_write().unwrap();
        record_commit(&w, tk, Some(sid), loc).unwrap();
        w.commit().unwrap();
    }

    #[test]
    fn compaction_builds_swaps_and_resets_counter() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path().join("c.redb"), redb::Durability::Immediate).unwrap();
        let tk = "cat\x1fns\x1ft";
        {
            let db = store.db.blocking_lock();
            record(&db, tk, 100, "loc-100");
            record(&db, tk, 200, "loc-200");
        }
        // Nothing compacted yet → no static index, cutoff at the floor.
        assert!(store.static_index.load().is_none());
        assert_eq!(store.cutoff.load(Ordering::Acquire), i64::MIN);

        let n = {
            let db = store.db.blocking_lock();
            store.compact_with_db(&db).unwrap()
        };
        assert_eq!(n, 2);

        let idx = store.static_index.load_full().expect("index swapped in");
        assert_eq!(
            idx.lookup(100).unwrap().metadata_location.as_ref(),
            "loc-100"
        );
        assert_eq!(
            idx.lookup(200).unwrap().metadata_location.as_ref(),
            "loc-200"
        );
        let cutoff = store.cutoff.load(Ordering::Acquire);
        assert_eq!(cutoff, 200);
        assert_eq!(store.writes_since_compaction.load(Ordering::Acquire), 0);

        // The persisted update counter was reset by compaction.
        let db = store.db.blocking_lock();
        let r = db.begin_read().unwrap();
        let meta = r.open_table(META).unwrap();
        let counter_reset = meta.get(META_UPDATE_COUNTER).unwrap().unwrap().value();
        assert_eq!(counter_reset, 0);
        #[cfg(feature = "testmatrix")]
        nornir_testmatrix::functional_status(
            "store",
            "compaction_builds_swaps_and_resets_counter",
            n == 2 && cutoff == 200 && counter_reset == 0,
            &format!(
                "compacted {n} entries, swapped static index, cutoff={cutoff} (want 200), update_counter reset={counter_reset}"
            ),
        );
    }

    #[test]
    fn reopen_warm_starts_static_index() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("c.redb");
        let tk = "cat\x1fns\x1ft";
        {
            let store = Store::open(path.clone(), redb::Durability::Immediate).unwrap();
            let db = store.db.blocking_lock();
            record(&db, tk, 5, "loc-5");
        }
        // Reopen: the index must be rebuilt from the durable log at open.
        let store = Store::open(path, redb::Durability::Immediate).unwrap();
        let idx = store.static_index.load_full().expect("warm-started index");
        let loc = idx.lookup(5).map(|e| e.metadata_location.to_string());
        assert_eq!(loc.as_deref(), Some("loc-5"));
        let cutoff = store.cutoff.load(Ordering::Acquire);
        let pending = store.writes_since_compaction.load(Ordering::Acquire);
        assert_eq!(cutoff, 5);
        // The single pending commit is carried into the live trigger counter.
        assert_eq!(pending, 1);
        #[cfg(feature = "testmatrix")]
        nornir_testmatrix::functional_status(
            "store",
            "reopen_warm_starts_static_index",
            loc.as_deref() == Some("loc-5") && cutoff == 5 && pending == 1,
            &format!(
                "warm-start rebuilt index (lookup(5)={loc:?}), cutoff={cutoff} (want 5), pending writes carried={pending}"
            ),
        );
    }
}
