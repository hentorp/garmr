// Apache-2.0 licensed.

//! [`RedbCatalog`] — implementation of [`iceberg::Catalog`] over redb.

use std::collections::HashMap;
use std::ops::Bound;
use std::str::FromStr;
use std::sync::Arc;

use async_trait::async_trait;
use iceberg::io::FileIO;
use iceberg::spec::{TableMetadata, TableMetadataBuilder};
use iceberg::table::Table;
use iceberg::{
    Catalog, Error, ErrorKind, MetadataLocation, Namespace, NamespaceIdent, Result, TableCommit,
    TableCreation, TableIdent, TableRequirement, TableUpdate,
};
use redb::ReadableTable;

use crate::error::map_redb;
use crate::keys::{
    SEP, catalog_prefix, namespace_key, namespace_prop_key, namespace_prop_prefix, ns_path,
    prefix_upper, table_key, table_prefix,
};
use crate::store::{NAMESPACE_PROPS, NAMESPACES, Store, TABLES};

const NAMESPACE_LOCATION_PROPERTY_KEY: &str = "location";

/// Embedded Iceberg catalog backed by redb.
///
/// Constructed via [`crate::RedbCatalogBuilder`].
#[derive(Debug, Clone)]
pub struct RedbCatalog {
    pub(crate) name: String,
    pub(crate) warehouse_location: String,
    pub(crate) fileio: FileIO,
    pub(crate) store: Store,
    /// L0: parsed-metadata cache. See [`crate::meta_cache`].
    pub(crate) meta_cache: crate::meta_cache::MetadataCache,
    /// L1.5: built-`Table` handle cache. See [`crate::table_cache`].
    pub(crate) table_cache: crate::table_cache::TableHandleCache,
}

impl RedbCatalog {
    /// Catalog name (the logical name passed at builder time).
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Warehouse root URI (e.g. `file:///var/.../warehouse`).
    pub fn warehouse_location(&self) -> &str {
        &self.warehouse_location
    }

    /// File-system path of the underlying redb database file.
    pub fn db_path(&self) -> &std::path::Path {
        &self.store.path
    }

    /// Underlying `FileIO` used to read/write Iceberg metadata blobs.
    pub fn file_io(&self) -> &FileIO {
        &self.fileio
    }

    /// Generation of the in-memory pointer mirror (L1): the number of catalog
    /// mutations published since this database was opened. Monotonic, shared
    /// across clones of this catalog. Useful as a cheap change-detector and as
    /// the trigger counter for the planned historical static-index compaction.
    pub fn pointer_generation(&self) -> u64 {
        self.store.pointers.generation()
    }

    /// Monotonic count of all commits recorded in the durable commit log
    /// (`commits`/`meta` redb tables) — advanced once per table-pointer
    /// advance across `create`/`update`/`register`/`atomic_release`. Unlike
    /// [`Self::pointer_generation`] (in-memory, reset to 0 on reopen), this is
    /// persisted, so it survives restarts. It is the durable source the planned
    /// Ragnar static-index compactor scans against.
    pub async fn commit_seq(&self) -> Result<u64> {
        let db = self.store.db.lock().await;
        let read = db.begin_read().map_err(map_redb)?;
        let meta = read.open_table(crate::store::META).map_err(map_redb)?;
        Ok(meta
            .get(crate::store::META_COMMIT_SEQ)
            .map_err(map_redb)?
            .map(|v| v.value())
            .unwrap_or(0))
    }

    /// The internal commit-log key `"{catalog}\x1f{ns}\x1f{table}"` for
    /// `identifier` — the value carried in [`CommitEvent::table_key`]. Consumers
    /// of [`Self::subscribe_commits`] use this to filter the broadcast to a table
    /// without reaching into the crate-private key encoding.
    pub fn commit_table_key(&self, identifier: &TableIdent) -> String {
        table_key(&self.name, identifier)
    }

    /// Subscribe to the commit stream: every snapshot-carrying commit (through
    /// `create`/`update`/`register`/`atomic_release`) publishes a
    /// [`CommitEvent`] to the returned receiver. The returned `u64` is the
    /// durable `commit_seq` cursor at subscribe time — events with
    /// `commit_seq > cursor` are guaranteed to flow through the receiver (subject
    /// to broadcast lag, recovered via [`Self::commits_since`]).
    ///
    /// The receiver is subscribed *before* the cursor is read, so no commit can
    /// slip through the gap: a commit racing the subscribe is delivered on the
    /// channel (and de-duplicated by the `> cursor` rule) rather than lost.
    pub async fn subscribe_commits(
        &self,
    ) -> Result<(
        u64,
        tokio::sync::broadcast::Receiver<crate::store::CommitEvent>,
    )> {
        let rx = self.store.events.subscribe();
        let cursor = self.commit_seq().await?;
        Ok((cursor, rx))
    }

    /// Replay durable commit events with `commit_seq` strictly greater than
    /// `after` by range-scanning the [`crate::store::COMMIT_LOG`] index — the
    /// catch-up path for a late or lagged subscriber (`RecvError::Lagged`). The
    /// durable log is the source of truth; the broadcast is only a low-latency
    /// hint. Returns events oldest-first, gapless.
    pub async fn commits_since(&self, after: u64) -> Result<Vec<crate::store::CommitEvent>> {
        let db = self.store.db.lock().await;
        let read = db.begin_read().map_err(map_redb)?;
        let log = read
            .open_table(crate::store::COMMIT_LOG)
            .map_err(map_redb)?;
        let mut out = Vec::new();
        for entry in log
            .range::<u64>((Bound::Excluded(after), Bound::Unbounded))
            .map_err(map_redb)?
        {
            let (k, v) = entry.map_err(map_redb)?;
            out.push(crate::store::decode_commit_log(k.value(), v.value()).map_err(Error::from)?);
        }
        Ok(out)
    }

    /// Resolve a table's current parsed metadata via the L1 pointer mirror and
    /// L0 metadata cache, **without** constructing an [`iceberg::table::Table`].
    ///
    /// This is the catalog's fast read path — warm reads are lock-free and
    /// sub-microsecond. Prefer it over [`Catalog::load_table`] when you only
    /// need metadata (schema, snapshots, properties, current location); the
    /// trait's `load_table` additionally runs `Table::build()`, whose per-call
    /// `ObjectCache` allocation dominates its cost and is iceberg-rust internal,
    /// not anything this catalog controls.
    pub async fn resolve_metadata(&self, identifier: &TableIdent) -> Result<Arc<TableMetadata>> {
        Ok(self.resolve(identifier).await?.1)
    }

    /// Resolve the current `metadata_location` for `identifier` through the
    /// lock-free L1 pointer mirror, falling back to redb only on a mirror miss
    /// (a genuinely-absent table). Returns no metadata — the caller decides
    /// whether to parse it (a handle-cache hit doesn't need to).
    async fn resolve_location(&self, identifier: &TableIdent) -> Result<String> {
        let key = table_key(&self.name, identifier);
        match self.store.pointers.get(&key) {
            Some(loc) => Ok(loc.to_string()),
            None => {
                let db = self.store.db.lock().await;
                let read = db.begin_read().map_err(map_redb)?;
                let tables_tbl = read.open_table(TABLES).map_err(map_redb)?;
                match tables_tbl.get(key.as_str()).map_err(map_redb)? {
                    Some(v) => Ok(v.value().to_string()),
                    None => Err(no_such_table(identifier)),
                }
            }
        }
    }

    /// Shared read core: resolve `(metadata_location, parsed_metadata)` through
    /// L1 then L0. The redb branch is a safety net for a mirror miss and never
    /// runs on the warm path.
    async fn resolve(&self, identifier: &TableIdent) -> Result<(String, Arc<TableMetadata>)> {
        let metadata_location = self.resolve_location(identifier).await?;
        let metadata = self
            .meta_cache
            .get_or_load(&self.fileio, &metadata_location)
            .await?;
        Ok((metadata_location, metadata))
    }

    /// Compact the historical static index now: rebuild it from the durable
    /// commit log, swap it in lock-free, advance the cutoff, and reset the
    /// update counter. Normally triggered automatically in the background once
    /// `COMPACT_THRESHOLD` commits accumulate; exposed for deterministic
    /// rebuilds. Returns the number of indexed commits.
    pub async fn compact_static_index(&self) -> Result<usize> {
        let db = self.store.db.lock().await;
        self.store.compact_with_db(&db).map_err(Error::from)
    }

    /// Resolve the metadata location recorded for `(table, snapshot_id)`: first
    /// via the lock-free static index (when the id is covered by the cutoff),
    /// then falling back to the redb commit-log live tail. `None` when no commit
    /// for that snapshot of that table was ever recorded.
    async fn resolve_location_at(
        &self,
        table_key: &str,
        snapshot_id: i64,
    ) -> Result<Option<String>> {
        if let Some(idx) = self.store.static_index.load_full() {
            if let Some(e) = idx.lookup(snapshot_id) {
                if e.table_key.as_ref() == table_key {
                    return Ok(Some(e.metadata_location.to_string()));
                }
            }
        }
        let db = self.store.db.lock().await;
        let read = db.begin_read().map_err(map_redb)?;
        let commits = read.open_table(crate::store::COMMITS).map_err(map_redb)?;
        let k = crate::store::commit_key(table_key, snapshot_id);
        Ok(commits
            .get(k.as_slice())
            .map_err(map_redb)?
            .map(|v| v.value().to_string()))
    }

    /// Time-travel: resolve a table's **parsed** metadata as of `snapshot_id`
    /// (static index → commit log → L0 cache), without building an
    /// [`iceberg::table::Table`]. The fast metadata-only historical read.
    pub async fn resolve_metadata_at(
        &self,
        identifier: &TableIdent,
        snapshot_id: i64,
    ) -> Result<Arc<TableMetadata>> {
        let key = table_key(&self.name, identifier);
        let loc = self
            .resolve_location_at(&key, snapshot_id)
            .await?
            .ok_or_else(|| snapshot_not_found(identifier, snapshot_id))?;
        self.meta_cache.get_or_load(&self.fileio, &loc).await
    }

    /// Time-travel: load a table as it was at `snapshot_id`, routed through the
    /// historical static index when the id is covered, else the redb commit log.
    pub async fn load_table_at(&self, identifier: &TableIdent, snapshot_id: i64) -> Result<Table> {
        let key = table_key(&self.name, identifier);
        // Location-first: a warm handle-cache hit clones a built `Table` without
        // touching L0 (the cached handle already carries the metadata).
        let loc = self
            .resolve_location_at(&key, snapshot_id)
            .await?
            .ok_or_else(|| snapshot_not_found(identifier, snapshot_id))?;
        if let Some(table) = self.table_cache.get(&loc, identifier).await {
            return Ok(table);
        }
        let metadata = self.meta_cache.get_or_load(&self.fileio, &loc).await?;
        self.table_cache
            .build_and_insert(&self.fileio, identifier, loc, metadata)
            .await
    }

    /// Resolve the `metadata_location` of the newest commit of `table_key`
    /// whose timestamp is `<= ts_micros` — the table's pointer as it stood at
    /// that wall-clock instant. Commit timestamps are assigned in `commit_seq`
    /// order, so a reverse scan of the [`crate::store::COMMIT_LOG`] returns the
    /// first (hence highest-`seq`, hence newest) qualifying row. Every commit-
    /// log row carries a real `metadata_location` (a rename mints none, so it
    /// records no row), so this covers a create-only table too — unlike
    /// [`Self::resolve_location_at`], which is keyed by data-snapshot id.
    /// `None` when the table had no commit at or before `ts_micros`.
    async fn resolve_location_as_of(
        &self,
        table_key: &str,
        ts_micros: i64,
    ) -> Result<Option<String>> {
        let db = self.store.db.lock().await;
        let read = db.begin_read().map_err(map_redb)?;
        let log = read
            .open_table(crate::store::COMMIT_LOG)
            .map_err(map_redb)?;
        for entry in log.range::<u64>(..).map_err(map_redb)?.rev() {
            let (k, v) = entry.map_err(map_redb)?;
            let ev = crate::store::decode_commit_log(k.value(), v.value()).map_err(Error::from)?;
            if ev.ts_micros <= ts_micros && ev.table_key.as_ref() == table_key {
                return Ok(Some(ev.metadata_location.to_string()));
            }
        }
        Ok(None)
    }

    /// Time-travel by **timestamp**: load a table as it was at wall-clock
    /// `ts_micros` (µs since the Unix epoch), routed through the same
    /// table/meta caches as [`Self::load_table_at`]. Resolves the newest commit
    /// at or before `ts_micros`; a timestamp earlier than the table's first
    /// commit surfaces a clear not-found error.
    pub async fn load_table_as_of(&self, identifier: &TableIdent, ts_micros: i64) -> Result<Table> {
        let key = table_key(&self.name, identifier);
        let loc = self
            .resolve_location_as_of(&key, ts_micros)
            .await?
            .ok_or_else(|| timestamp_not_found(identifier, ts_micros))?;
        if let Some(table) = self.table_cache.get(&loc, identifier).await {
            return Ok(table);
        }
        let metadata = self.meta_cache.get_or_load(&self.fileio, &loc).await?;
        self.table_cache
            .build_and_insert(&self.fileio, identifier, loc, metadata)
            .await
    }

    /// Time-travel by **timestamp**: resolve a table's parsed metadata as of
    /// wall-clock `ts_micros`, without building an [`iceberg::table::Table`] —
    /// the metadata-only historical read (mirrors [`Self::resolve_metadata_at`]
    /// but keyed by timestamp instead of snapshot id).
    pub async fn resolve_metadata_as_of(
        &self,
        identifier: &TableIdent,
        ts_micros: i64,
    ) -> Result<Arc<TableMetadata>> {
        let key = table_key(&self.name, identifier);
        let loc = self
            .resolve_location_as_of(&key, ts_micros)
            .await?
            .ok_or_else(|| timestamp_not_found(identifier, ts_micros))?;
        self.meta_cache.get_or_load(&self.fileio, &loc).await
    }

    /// Batch time-travel: resolve `identifier`'s parsed metadata for **many**
    /// snapshot ids at once. The static-index probes run in one software-
    /// pipelined `STree64` pass; everything the index doesn't cover is filled in
    /// from a single redb read transaction; then each distinct location is
    /// resolved through the L0 cache. Returns one slot per input id, in order
    /// (`None` where that snapshot of the table was never committed).
    ///
    /// This is the path where Ragnar's batch win lands — query planners that
    /// fan out over many snapshots pay one tree walk and one redb txn, not N.
    pub async fn resolve_many(
        &self,
        identifier: &TableIdent,
        snapshot_ids: &[i64],
    ) -> Result<Vec<Option<Arc<TableMetadata>>>> {
        let key = table_key(&self.name, identifier);
        let mut locations: Vec<Option<String>> = vec![None; snapshot_ids.len()];

        // Phase 1 — one pipelined static-index pass (lock-free).
        if let Some(idx) = self.store.static_index.load_full() {
            for (slot, hit) in locations.iter_mut().zip(idx.lookup_many(snapshot_ids)) {
                if let Some(e) = hit {
                    if e.table_key.as_ref() == key {
                        *slot = Some(e.metadata_location.to_string());
                    }
                }
            }
        }

        // Phase 2 — one redb read txn for the live-tail / static-index misses.
        if locations.iter().any(Option::is_none) {
            let db = self.store.db.lock().await;
            let read = db.begin_read().map_err(map_redb)?;
            let commits = read.open_table(crate::store::COMMITS).map_err(map_redb)?;
            for (slot, &sid) in locations.iter_mut().zip(snapshot_ids) {
                if slot.is_none() {
                    let k = crate::store::commit_key(&key, sid);
                    if let Some(v) = commits.get(k.as_slice()).map_err(map_redb)? {
                        *slot = Some(v.value().to_string());
                    }
                }
            }
        }

        // Phase 3 — resolve each location through the L0 metadata cache.
        let mut out = Vec::with_capacity(snapshot_ids.len());
        for loc in locations {
            match loc {
                Some(l) => out.push(Some(self.meta_cache.get_or_load(&self.fileio, &l).await?)),
                None => out.push(None),
            }
        }
        Ok(out)
    }

    /// Apply a set of Iceberg [`TableRequirement`]s + [`TableUpdate`]s to a table
    /// and durably commit the result, returning the updated [`Table`].
    ///
    /// This is the raw commit primitive that backs the [`Catalog::update_table`]
    /// trait method (whose `TableCommit` builder is crate-private to `iceberg`,
    /// so callers that already hold the wire pieces — e.g. an Iceberg-REST
    /// `commit_table` request — cannot reconstruct a `TableCommit`). It mirrors
    /// `TableCommit::apply` exactly: every requirement is checked against the
    /// table's *current* metadata, then each update is folded into a metadata
    /// builder; the new metadata is written to a `with_next_version()` location
    /// and the catalog pointer is advanced through the optimistic group-commit
    /// path (one redb txn / fsync, commit-log append, L0/L1 write-through).
    pub async fn commit_table(
        &self,
        ident: TableIdent,
        requirements: Vec<TableRequirement>,
        updates: Vec<TableUpdate>,
    ) -> Result<Table> {
        let current_table = self.load_table(&ident).await?;
        let current_metadata_location = current_table.metadata_location_result()?.to_string();

        // Validate every requirement against the current metadata before any I/O.
        for requirement in &requirements {
            requirement.check(Some(current_table.metadata()))?;
        }

        // Fold the updates into a fresh metadata builder seeded from current.
        let mut metadata_builder = current_table
            .metadata()
            .clone()
            .into_builder(Some(current_metadata_location.clone()));
        for update in updates {
            metadata_builder = update.apply(metadata_builder)?;
        }
        let new_metadata = metadata_builder.build()?.metadata;

        let staged_metadata_location = MetadataLocation::from_str(&current_metadata_location)?
            .with_next_version()
            .to_string();
        // `Table::with_metadata*` is crate-private to iceberg, so rebuild the
        // handle from its public builder (the same path create/register take).
        let staged_table = Table::builder()
            .file_io(current_table.file_io().clone())
            .identifier(ident.clone())
            .metadata(new_metadata)
            .metadata_location(staged_metadata_location)
            .build()?;

        self.persist_commit(ident, current_metadata_location, staged_table)
            .await
    }

    /// Durably advance a table's pointer to `staged_table`'s already-applied
    /// metadata: write the metadata blob, then optimistically swap the redb
    /// pointer (group-commit), recording the commit and publishing the L0/L1
    /// write-through. Fails with `CatalogCommitConflicts` if another writer
    /// moved the pointer off `base_metadata_location` since it was read.
    async fn persist_commit(
        &self,
        ident: TableIdent,
        base_metadata_location: String,
        staged_table: Table,
    ) -> Result<Table> {
        let staged_metadata_location = staged_table.metadata_location_result()?.to_string();

        staged_table
            .metadata()
            .write_to(staged_table.file_io(), &staged_metadata_location)
            .await?;
        // Durably flush the metadata blob before the pointer advances, so an
        // unclean shutdown can't leave the pointer aimed at un-fsync'd bytes.
        crate::heal::fsync_local_metadata(&staged_metadata_location);

        // Group-commit: this optimistic pointer-advance is coalesced with any
        // other concurrent commits into a single redb write txn (one fsync). The
        // closure does the compare-and-swap itself and writes nothing on
        // conflict, so a failing op never taints the shared transaction.
        let key = table_key(&self.name, &ident);
        let snapshot_id = staged_table.metadata().current_snapshot_id();
        let conflict_ident = ident.clone();
        let staged_loc = staged_metadata_location.clone();
        self.store
            .group_commit(Box::new(move |write| {
                {
                    let mut tables_tbl = write.open_table(TABLES).map_err(map_redb)?;
                    let existing = tables_tbl
                        .get(key.as_str())
                        .map_err(map_redb)?
                        .map(|v| v.value().to_string());
                    match existing {
                        Some(loc) if loc == base_metadata_location => {
                            tables_tbl
                                .insert(key.as_str(), staged_loc.as_str())
                                .map_err(map_redb)?;
                        }
                        Some(_) => {
                            return Err(Error::new(
                                ErrorKind::CatalogCommitConflicts,
                                format!("Commit conflicted for table: {conflict_ident}"),
                            )
                            .with_retryable(true));
                        }
                        None => return Err(no_such_table(&conflict_ident)),
                    }
                }
                let rec = crate::store::record_commit(write, &key, snapshot_id, &staged_loc)
                    .map_err(map_redb)?;
                Ok(crate::store::CommitOutcome::insert(key, staged_loc).with_event(rec.event))
            }))
            .await?;

        Ok(staged_table)
    }

    /// Atomically swap the compacted table `temp` into the `live` name in ONE
    /// redb write transaction: repoint `live` at `temp`'s metadata and remove
    /// `temp`. This is the crash-safe primitive the rebuild-swap compactor needs.
    ///
    /// Unlike a two-step rename (`live`→`live_old`, then `temp`→`live`), there is
    /// no instant where `live` resolves to nothing: a crash leaves `live` at
    /// either the old or the new metadata, never absent (which `table_or_create`
    /// would otherwise silently re-create as an empty table — data loss). It is
    /// likewise gap-free for concurrent readers, which never 404 on `live`.
    ///
    /// `temp` must exist; `live` is overwritten whether or not it currently
    /// exists (so a half-finished prior swap heals forward). Returns the previous
    /// `live` metadata_location, if any, so the caller can GC the retired table's
    /// data directory. Pointer-only, like `rename_table`: no data files are moved
    /// or deleted — the caller owns physical reclaim.
    ///
    /// The commit log swaps along with the pointer: every logged commit for both
    /// keys is removed — the retired entries would resolve to metadata files the
    /// caller is about to GC, and under continuous compact-swap cycles an
    /// unpruned log (and the static index rebuilt from it) grows without bound,
    /// the same slow-OOM class compaction exists to fix. `new_snapshot` (the
    /// compacted table's snapshot, when it has one) is re-seeded under the live
    /// key so the log stays consistent with the pointer.
    pub async fn swap_table(
        &self,
        live: &TableIdent,
        temp: &TableIdent,
        new_snapshot: Option<i64>,
    ) -> Result<Option<String>> {
        let db = self.store.db.lock().await;
        let live_key = table_key(&self.name, live);
        let temp_key = table_key(&self.name, temp);
        let mut write = db.begin_write().map_err(map_redb)?;
        // Force per-commit fsync for the swap regardless of the configured
        // durability: losing this commit after the caller has reloaded its
        // handle and appended to the new directory would strand those appends.
        // (Immediate is also skade's default.)
        write.set_durability(redb::Durability::Immediate);
        let (new_loc, old_loc) = {
            let mut tables_tbl = write.open_table(TABLES).map_err(map_redb)?;
            let new_loc = match tables_tbl.get(temp_key.as_str()).map_err(map_redb)? {
                Some(v) => v.value().to_string(),
                None => return Err(no_such_table(temp)),
            };
            let old_loc = tables_tbl
                .get(live_key.as_str())
                .map_err(map_redb)?
                .map(|v| v.value().to_string());
            tables_tbl.remove(temp_key.as_str()).map_err(map_redb)?;
            tables_tbl
                .insert(live_key.as_str(), new_loc.as_str())
                .map_err(map_redb)?;
            drop(tables_tbl);

            let mut commits = write.open_table(crate::store::COMMITS).map_err(map_redb)?;
            for key in [live_key.as_str(), temp_key.as_str()] {
                // commit_key encodes the id `as u64` big-endian, so the full
                // 8-byte suffix space is [id 0 .. id -1] (-1 casts to u64::MAX);
                // this range covers every possible snapshot id under `key`.
                let from = crate::store::commit_key(key, 0);
                let to = crate::store::commit_key(key, -1);
                commits
                    .retain_in(from.as_slice()..=to.as_slice(), |_, _| false)
                    .map_err(map_redb)?;
            }
            drop(commits);
            crate::store::record_commit(&write, &live_key, new_snapshot, &new_loc)
                .map_err(map_redb)?;
            (new_loc, old_loc)
        };
        write.commit().map_err(map_redb)?;
        // L1 write-through (under the redb write lock).
        self.store.pointers.remove(&temp_key);
        self.store.pointers.insert(&live_key, &new_loc);
        Ok(old_loc)
    }
}

fn no_such_namespace(ns: &NamespaceIdent) -> Error {
    Error::new(
        ErrorKind::NamespaceNotFound,
        format!("Namespace does not exist: {ns}"),
    )
}

fn namespace_already_exists(ns: &NamespaceIdent) -> Error {
    Error::new(
        ErrorKind::NamespaceAlreadyExists,
        format!("Namespace already exists: {ns}"),
    )
}

fn no_such_table(t: &TableIdent) -> Error {
    Error::new(
        ErrorKind::TableNotFound,
        format!("Table does not exist: {t}"),
    )
}

fn table_already_exists(t: &TableIdent) -> Error {
    Error::new(
        ErrorKind::TableAlreadyExists,
        format!("Table already exists: {t}"),
    )
}

fn snapshot_not_found(t: &TableIdent, snapshot_id: i64) -> Error {
    Error::new(
        ErrorKind::TableNotFound,
        format!("No recorded commit for snapshot {snapshot_id} of table {t}"),
    )
}

fn timestamp_not_found(t: &TableIdent, ts_micros: i64) -> Error {
    Error::new(
        ErrorKind::TableNotFound,
        format!("No recorded commit at or before timestamp {ts_micros}\u{b5}s of table {t}"),
    )
}

#[async_trait]
impl Catalog for RedbCatalog {
    async fn list_namespaces(
        &self,
        parent: Option<&NamespaceIdent>,
    ) -> Result<Vec<NamespaceIdent>> {
        let db = self.store.db.lock().await;
        let read = db.begin_read().map_err(map_redb)?;
        let table = read.open_table(NAMESPACES).map_err(map_redb)?;

        let prefix = catalog_prefix(&self.name);
        let upper = prefix_upper(&prefix);

        let range = if upper.is_empty() {
            table
                .range::<&str>((Bound::Included(prefix.as_str()), Bound::Unbounded))
                .map_err(map_redb)?
        } else {
            table
                .range::<&str>((
                    Bound::Included(prefix.as_str()),
                    Bound::Excluded(upper.as_str()),
                ))
                .map_err(map_redb)?
        };

        let parent_prefix = parent.map(|p| format!("{}.", ns_path(p)));
        let parent_components = parent.map(|p| p.clone().inner().len()).unwrap_or(0);

        let mut out = Vec::new();
        for entry in range {
            let (k, _v) = entry.map_err(map_redb)?;
            let key = k.value();
            // Strip "{catalog}\x1f" prefix → leaves "{ns_path}"
            let ns_str = &key[prefix.len()..];

            match &parent_prefix {
                None => {
                    // Top-level only: skip any namespace that contains a `.`
                    if !ns_str.contains('.') && !ns_str.is_empty() {
                        out.push(NamespaceIdent::from_strs(ns_str.split('.'))?);
                    }
                }
                Some(pp) => {
                    if !ns_str.starts_with(pp) {
                        continue;
                    }
                    let tail = &ns_str[pp.len()..];
                    if tail.is_empty() || tail.contains('.') {
                        continue;
                    }
                    let parts: Vec<&str> = ns_str.split('.').collect();
                    if parts.len() == parent_components + 1 {
                        out.push(NamespaceIdent::from_strs(parts)?);
                    }
                }
            }
        }
        Ok(out)
    }

    async fn create_namespace(
        &self,
        namespace: &NamespaceIdent,
        properties: HashMap<String, String>,
    ) -> Result<Namespace> {
        let db = self.store.db.lock().await;
        let mut write = db.begin_write().map_err(map_redb)?;
        write.set_durability(self.store.durability);
        {
            let mut ns_tbl = write.open_table(NAMESPACES).map_err(map_redb)?;
            let key = namespace_key(&self.name, namespace);
            if ns_tbl.get(key.as_str()).map_err(map_redb)?.is_some() {
                return Err(namespace_already_exists(namespace));
            }
            ns_tbl
                .insert(key.as_str(), &[] as &[u8])
                .map_err(map_redb)?;

            let mut props_tbl = write.open_table(NAMESPACE_PROPS).map_err(map_redb)?;
            for (k, v) in &properties {
                let pk = namespace_prop_key(&self.name, namespace, k);
                props_tbl
                    .insert(pk.as_str(), v.as_str())
                    .map_err(map_redb)?;
            }
        }
        write.commit().map_err(map_redb)?;

        Ok(Namespace::with_properties(namespace.clone(), properties))
    }

    async fn get_namespace(&self, namespace: &NamespaceIdent) -> Result<Namespace> {
        let db = self.store.db.lock().await;
        let read = db.begin_read().map_err(map_redb)?;

        let ns_tbl = read.open_table(NAMESPACES).map_err(map_redb)?;
        let key = namespace_key(&self.name, namespace);
        if ns_tbl.get(key.as_str()).map_err(map_redb)?.is_none() {
            return Err(no_such_namespace(namespace));
        }

        let props_tbl = read.open_table(NAMESPACE_PROPS).map_err(map_redb)?;
        let prefix = namespace_prop_prefix(&self.name, namespace);
        let upper = prefix_upper(&prefix);

        let mut props = HashMap::new();
        let iter = if upper.is_empty() {
            props_tbl
                .range::<&str>((Bound::Included(prefix.as_str()), Bound::Unbounded))
                .map_err(map_redb)?
        } else {
            props_tbl
                .range::<&str>((
                    Bound::Included(prefix.as_str()),
                    Bound::Excluded(upper.as_str()),
                ))
                .map_err(map_redb)?
        };
        for entry in iter {
            let (k, v) = entry.map_err(map_redb)?;
            let key = k.value();
            let prop = &key[prefix.len()..];
            props.insert(prop.to_string(), v.value().to_string());
        }

        Ok(Namespace::with_properties(namespace.clone(), props))
    }

    async fn namespace_exists(&self, namespace: &NamespaceIdent) -> Result<bool> {
        let db = self.store.db.lock().await;
        let read = db.begin_read().map_err(map_redb)?;
        let ns_tbl = read.open_table(NAMESPACES).map_err(map_redb)?;
        let key = namespace_key(&self.name, namespace);
        Ok(ns_tbl.get(key.as_str()).map_err(map_redb)?.is_some())
    }

    async fn update_namespace(
        &self,
        namespace: &NamespaceIdent,
        properties: HashMap<String, String>,
    ) -> Result<()> {
        let db = self.store.db.lock().await;
        let mut write = db.begin_write().map_err(map_redb)?;
        write.set_durability(self.store.durability);
        {
            let ns_tbl = write.open_table(NAMESPACES).map_err(map_redb)?;
            let key = namespace_key(&self.name, namespace);
            if ns_tbl.get(key.as_str()).map_err(map_redb)?.is_none() {
                return Err(no_such_namespace(namespace));
            }
            drop(ns_tbl);

            let mut props_tbl = write.open_table(NAMESPACE_PROPS).map_err(map_redb)?;

            // Per the trait contract: "The properties must be the full set of
            // namespace." → wipe existing, write new.
            let prefix = namespace_prop_prefix(&self.name, namespace);
            let upper = prefix_upper(&prefix);
            let to_remove: Vec<String> = {
                let iter = if upper.is_empty() {
                    props_tbl
                        .range::<&str>((Bound::Included(prefix.as_str()), Bound::Unbounded))
                        .map_err(map_redb)?
                } else {
                    props_tbl
                        .range::<&str>((
                            Bound::Included(prefix.as_str()),
                            Bound::Excluded(upper.as_str()),
                        ))
                        .map_err(map_redb)?
                };
                iter.map(|e| e.map(|(k, _)| k.value().to_string()).map_err(map_redb))
                    .collect::<Result<Vec<_>>>()?
            };
            for k in to_remove {
                props_tbl.remove(k.as_str()).map_err(map_redb)?;
            }
            for (k, v) in &properties {
                let pk = namespace_prop_key(&self.name, namespace, k);
                props_tbl
                    .insert(pk.as_str(), v.as_str())
                    .map_err(map_redb)?;
            }
        }
        write.commit().map_err(map_redb)?;
        Ok(())
    }

    async fn drop_namespace(&self, namespace: &NamespaceIdent) -> Result<()> {
        let db = self.store.db.lock().await;
        let mut write = db.begin_write().map_err(map_redb)?;
        write.set_durability(self.store.durability);
        {
            let mut ns_tbl = write.open_table(NAMESPACES).map_err(map_redb)?;
            let key = namespace_key(&self.name, namespace);
            if ns_tbl.get(key.as_str()).map_err(map_redb)?.is_none() {
                return Err(no_such_namespace(namespace));
            }

            // Reject drop if any tables remain in the namespace.
            let tables_tbl = write.open_table(TABLES).map_err(map_redb)?;
            let prefix = table_prefix(&self.name, namespace);
            let upper = prefix_upper(&prefix);
            let mut iter = if upper.is_empty() {
                tables_tbl
                    .range::<&str>((Bound::Included(prefix.as_str()), Bound::Unbounded))
                    .map_err(map_redb)?
            } else {
                tables_tbl
                    .range::<&str>((
                        Bound::Included(prefix.as_str()),
                        Bound::Excluded(upper.as_str()),
                    ))
                    .map_err(map_redb)?
            };
            if iter.next().is_some() {
                return Err(Error::new(
                    ErrorKind::Unexpected,
                    format!("Namespace {namespace} is not empty"),
                ));
            }
            drop(iter);
            drop(tables_tbl);

            ns_tbl.remove(key.as_str()).map_err(map_redb)?;

            // Also clear any orphan namespace props.
            let mut props_tbl = write.open_table(NAMESPACE_PROPS).map_err(map_redb)?;
            let prefix = namespace_prop_prefix(&self.name, namespace);
            let upper = prefix_upper(&prefix);
            let to_remove: Vec<String> = {
                let iter = if upper.is_empty() {
                    props_tbl
                        .range::<&str>((Bound::Included(prefix.as_str()), Bound::Unbounded))
                        .map_err(map_redb)?
                } else {
                    props_tbl
                        .range::<&str>((
                            Bound::Included(prefix.as_str()),
                            Bound::Excluded(upper.as_str()),
                        ))
                        .map_err(map_redb)?
                };
                iter.map(|e| e.map(|(k, _)| k.value().to_string()).map_err(map_redb))
                    .collect::<Result<Vec<_>>>()?
            };
            for k in to_remove {
                props_tbl.remove(k.as_str()).map_err(map_redb)?;
            }
        }
        write.commit().map_err(map_redb)?;
        Ok(())
    }

    async fn list_tables(&self, namespace: &NamespaceIdent) -> Result<Vec<TableIdent>> {
        let db = self.store.db.lock().await;
        let read = db.begin_read().map_err(map_redb)?;

        let ns_tbl = read.open_table(NAMESPACES).map_err(map_redb)?;
        let ns_key = namespace_key(&self.name, namespace);
        if ns_tbl.get(ns_key.as_str()).map_err(map_redb)?.is_none() {
            return Err(no_such_namespace(namespace));
        }

        let tables_tbl = read.open_table(TABLES).map_err(map_redb)?;
        let prefix = table_prefix(&self.name, namespace);
        let upper = prefix_upper(&prefix);
        let iter = if upper.is_empty() {
            tables_tbl
                .range::<&str>((Bound::Included(prefix.as_str()), Bound::Unbounded))
                .map_err(map_redb)?
        } else {
            tables_tbl
                .range::<&str>((
                    Bound::Included(prefix.as_str()),
                    Bound::Excluded(upper.as_str()),
                ))
                .map_err(map_redb)?
        };

        let mut out = Vec::new();
        for entry in iter {
            let (k, _) = entry.map_err(map_redb)?;
            let key = k.value();
            let tail = &key[prefix.len()..];
            if !tail.is_empty() && !tail.contains(SEP) {
                out.push(TableIdent::new(namespace.clone(), tail.to_string()));
            }
        }
        Ok(out)
    }

    async fn create_table(
        &self,
        namespace: &NamespaceIdent,
        creation: TableCreation,
    ) -> Result<Table> {
        if !self.namespace_exists(namespace).await? {
            return Err(no_such_namespace(namespace));
        }

        let tbl_name = creation.name.clone();
        let tbl_ident = TableIdent::new(namespace.clone(), tbl_name.clone());

        if self.table_exists(&tbl_ident).await? {
            return Err(table_already_exists(&tbl_ident));
        }

        let (tbl_creation, location) = match creation.location.clone() {
            Some(location) => (creation, location),
            None => {
                let nsp_properties = self.get_namespace(namespace).await?.properties().clone();
                let nsp_location = match nsp_properties.get(NAMESPACE_LOCATION_PROPERTY_KEY) {
                    Some(loc) => loc.clone(),
                    None => format!(
                        "{}/{}",
                        self.warehouse_location,
                        namespace.clone().inner().join("/")
                    ),
                };
                let tbl_location = format!("{}/{}", nsp_location, tbl_ident.name());
                (
                    TableCreation {
                        location: Some(tbl_location.clone()),
                        ..creation
                    },
                    tbl_location,
                )
            }
        };

        let tbl_metadata = TableMetadataBuilder::from_table_creation(tbl_creation)?
            .build()?
            .metadata;
        let tbl_metadata_location = format!(
            "{}/metadata/00000-{}.metadata.json",
            location,
            tbl_metadata.uuid()
        );

        tbl_metadata
            .write_to(&self.fileio, &tbl_metadata_location)
            .await?;
        // Flush the initial metadata before the pointer that names it lands.
        crate::heal::fsync_local_metadata(&tbl_metadata_location);

        {
            let db = self.store.db.lock().await;
            let mut write = db.begin_write().map_err(map_redb)?;
            write.set_durability(self.store.durability);
            // Build the redb key once — it is identical across the insert, the
            // commit-log record, and the L1 write-through below (3 allocs → 1).
            let key = table_key(&self.name, &tbl_ident);
            {
                let mut tables_tbl = write.open_table(TABLES).map_err(map_redb)?;
                // Recheck under write lock to close TOCTOU race.
                if tables_tbl.get(key.as_str()).map_err(map_redb)?.is_some() {
                    return Err(table_already_exists(&tbl_ident));
                }
                tables_tbl
                    .insert(key.as_str(), tbl_metadata_location.as_str())
                    .map_err(map_redb)?;
            }
            let rec = crate::store::record_commit(
                &write,
                &key,
                tbl_metadata.current_snapshot_id(),
                &tbl_metadata_location,
            )
            .map_err(map_redb)?;
            write.commit().map_err(map_redb)?;
            // L1 write-through (under the redb write lock).
            self.store.pointers.insert(&key, &tbl_metadata_location);
            // Streaming spine: publish post-commit (this non-`group_commit` path
            // fires its own event).
            self.store.publish(rec.event);
        }
        self.store.maybe_trigger_compaction();

        Ok(Table::builder()
            .file_io(self.fileio.clone())
            .metadata_location(tbl_metadata_location)
            .identifier(tbl_ident)
            .metadata(tbl_metadata)
            .build()?)
    }

    async fn load_table(&self, identifier: &TableIdent) -> Result<Table> {
        // Location-first: L1.5 handle-cache hit clones a built `Table` straight
        // from the lock-free pointer location, skipping L0 entirely. Only a
        // handle-cache miss parses metadata (L0) and builds + caches the handle.
        let metadata_location = self.resolve_location(identifier).await?;
        if let Some(table) = self.table_cache.get(&metadata_location, identifier).await {
            crate::testmatrix::functional_status(
                "skade.read",
                "load_table",
                true,
                "L1.5 handle-cache hit",
            );
            return Ok(table);
        }
        let metadata = self
            .meta_cache
            .get_or_load(&self.fileio, &metadata_location)
            .await?;
        let table = self
            .table_cache
            .build_and_insert(&self.fileio, identifier, metadata_location, metadata)
            .await?;
        crate::testmatrix::functional_status(
            "skade.read",
            "load_table",
            true,
            "handle-cache miss → parsed L0 metadata",
        );
        Ok(table)
    }

    async fn drop_table(&self, identifier: &TableIdent) -> Result<()> {
        let db = self.store.db.lock().await;
        let mut write = db.begin_write().map_err(map_redb)?;
        write.set_durability(self.store.durability);
        {
            let mut tables_tbl = write.open_table(TABLES).map_err(map_redb)?;
            let key = table_key(&self.name, identifier);
            if tables_tbl.get(key.as_str()).map_err(map_redb)?.is_none() {
                return Err(no_such_table(identifier));
            }
            tables_tbl.remove(key.as_str()).map_err(map_redb)?;
        }
        write.commit().map_err(map_redb)?;
        // L1 write-through (under the redb write lock).
        self.store
            .pointers
            .remove(&table_key(&self.name, identifier));
        Ok(())
    }

    async fn table_exists(&self, identifier: &TableIdent) -> Result<bool> {
        let key = table_key(&self.name, identifier);
        // L1 fast path: the lock-free pointer mirror knows every live table
        // (built from a full scan at open, maintained write-through). A hit
        // answers without the tokio mutex or a redb read.
        if self.store.pointers.get(&key).is_some() {
            return Ok(true);
        }
        // Mirror miss → confirm against redb (the source of truth) before
        // reporting absence, mirroring `resolve_location`'s safety net.
        let db = self.store.db.lock().await;
        let read = db.begin_read().map_err(map_redb)?;
        let tables_tbl = read.open_table(TABLES).map_err(map_redb)?;
        Ok(tables_tbl.get(key.as_str()).map_err(map_redb)?.is_some())
    }

    async fn rename_table(&self, src: &TableIdent, dest: &TableIdent) -> Result<()> {
        if src == dest {
            return Ok(());
        }

        let db = self.store.db.lock().await;
        let src_key = table_key(&self.name, src);
        let dest_key = table_key(&self.name, dest);
        let mut write = db.begin_write().map_err(map_redb)?;
        write.set_durability(self.store.durability);
        let metadata_location = {
            let ns_tbl = write.open_table(NAMESPACES).map_err(map_redb)?;
            let dest_ns_key = namespace_key(&self.name, dest.namespace());
            if ns_tbl
                .get(dest_ns_key.as_str())
                .map_err(map_redb)?
                .is_none()
            {
                return Err(no_such_namespace(dest.namespace()));
            }
            drop(ns_tbl);

            let mut tables_tbl = write.open_table(TABLES).map_err(map_redb)?;
            let metadata_location = match tables_tbl.get(src_key.as_str()).map_err(map_redb)? {
                Some(v) => v.value().to_string(),
                None => return Err(no_such_table(src)),
            };
            if tables_tbl
                .get(dest_key.as_str())
                .map_err(map_redb)?
                .is_some()
            {
                return Err(table_already_exists(dest));
            }

            tables_tbl.remove(src_key.as_str()).map_err(map_redb)?;
            tables_tbl
                .insert(dest_key.as_str(), metadata_location.as_str())
                .map_err(map_redb)?;
            metadata_location
        };
        write.commit().map_err(map_redb)?;
        // L1 write-through (under the redb write lock).
        self.store.pointers.remove(&src_key);
        self.store.pointers.insert(&dest_key, &metadata_location);
        Ok(())
    }

    async fn register_table(
        &self,
        table_ident: &TableIdent,
        metadata_location: String,
    ) -> Result<Table> {
        if self.table_exists(table_ident).await? {
            return Err(table_already_exists(table_ident));
        }

        let metadata = TableMetadata::read_from(&self.fileio, &metadata_location).await?;

        {
            let db = self.store.db.lock().await;
            let mut write = db.begin_write().map_err(map_redb)?;
            write.set_durability(self.store.durability);
            // Build the redb key once and reuse it across the insert, the
            // commit-log record, and the L1 write-through (3 allocs → 1).
            let key = table_key(&self.name, table_ident);
            {
                let mut tables_tbl = write.open_table(TABLES).map_err(map_redb)?;
                if tables_tbl.get(key.as_str()).map_err(map_redb)?.is_some() {
                    return Err(table_already_exists(table_ident));
                }
                tables_tbl
                    .insert(key.as_str(), metadata_location.as_str())
                    .map_err(map_redb)?;
            }
            let rec = crate::store::record_commit(
                &write,
                &key,
                metadata.current_snapshot_id(),
                &metadata_location,
            )
            .map_err(map_redb)?;
            write.commit().map_err(map_redb)?;
            // L1 write-through (under the redb write lock).
            self.store.pointers.insert(&key, &metadata_location);
            // Streaming spine: publish post-commit.
            self.store.publish(rec.event);
        }
        self.store.maybe_trigger_compaction();

        Ok(Table::builder()
            .identifier(table_ident.clone())
            .metadata_location(metadata_location)
            .metadata(metadata)
            .file_io(self.fileio.clone())
            .build()?)
    }

    async fn update_table(&self, commit: TableCommit) -> Result<Table> {
        let table_ident = commit.identifier().clone();
        let current_table = self.load_table(&table_ident).await?;
        let current_metadata_location = current_table.metadata_location_result()?.to_string();

        let staged_table = commit.apply(current_table)?;

        self.persist_commit(table_ident, current_metadata_location, staged_table)
            .await
    }
}
