// Apache-2.0 licensed.

//! L1.5 built-`Table` handle cache.
//!
//! [`iceberg::Catalog::load_table`] returns an owned [`Table`]. Constructing one
//! via `Table::builder().build()` is dominated — by ~14 µs on this dev box,
//! ~99% of `load_table`'s warm cost — by a single thing: iceberg-rust builds a
//! fresh per-`Table` `ObjectCache` (a `moka` cache) on **every** call. That cost
//! is intrinsic to building the cache structure; `disable_cache()` does *not*
//! avoid it (it still constructs a capacity-0 `moka` cache, measured at the same
//! ~14 µs), and there is no public way to inject a pre-built cache.
//!
//! But [`Table`] derives [`Clone`], and cloning one shares the underlying
//! `Arc<ObjectCache>` — measured at **~100 ns**, ~140× cheaper than building.
//! So we build a `Table` once per `metadata_location` and hand out clones.
//!
//! Like the L0 [`crate::meta_cache`], the key is the **immutable,
//! content-addressed** `metadata_location`: a new commit writes a new metadata
//! file and a new key, so a cached handle can only be *evicted*, never *stale*.
//! Sharing one `ObjectCache` across the clones of a location is a bonus — it
//! turns iceberg's per-call throwaway manifest cache into a shared one.

use std::sync::Arc;

use iceberg::io::FileIO;
use iceberg::spec::TableMetadata;
use iceberg::table::Table;
use iceberg::{Result, TableIdent};
use moka::future::Cache;

/// Default number of built-`Table` handles to keep resident. Entries are NOT
/// free: each pins its parsed `TableMetadata` (O(snapshots) — hundreds of KB on
/// a busy table) plus a scan-populated `ObjectCache`, and under continuous
/// ingest every commit inserts a new metadata_location, so a generous cap
/// steadily pins gigabytes (observed on garmr's 8 GB SOC host). 512 ≈ tens of
/// MB worst case while still covering every hot table. `0` disables the cache.
pub const DEFAULT_TABLE_HANDLE_CACHE_CAPACITY: u64 = 512;

/// Lock-free cache of built [`Table`] handles keyed by `metadata_location`.
///
/// Cloneable and cheap to clone (shares one underlying store). A capacity of `0`
/// disables it (every `load_table` builds a fresh `Table`).
#[derive(Clone)]
pub(crate) struct TableHandleCache {
    inner: Option<Cache<String, Table>>,
}

impl TableHandleCache {
    /// Build a handle cache holding at most `capacity` entries. `0` disables it.
    pub(crate) fn new(capacity: u64) -> Self {
        let inner = if capacity == 0 {
            None
        } else {
            Some(
                Cache::builder()
                    .name("skade-katalog.table-handles")
                    .max_capacity(capacity)
                    .build(),
            )
        };
        Self { inner }
    }

    /// Clone of the cached [`Table`] for `metadata_location`, if present and its
    /// identifier matches — letting `load_table` short-circuit before touching
    /// the L0 metadata cache. An identifier mismatch (only possible when two
    /// catalog entries alias the *same* metadata file, e.g. via `register_table`)
    /// is treated as a miss.
    pub(crate) async fn get(
        &self,
        metadata_location: &str,
        identifier: &TableIdent,
    ) -> Option<Table> {
        let hit = self.inner.as_ref()?.get(metadata_location).await?;
        (hit.identifier() == identifier).then_some(hit)
    }

    /// Build a [`Table`] for `(identifier, metadata_location)` from already-loaded
    /// metadata, cache it (keyed by the immutable location), and return it. Call
    /// on a [`Self::get`] miss. With caching disabled this just builds.
    pub(crate) async fn build_and_insert(
        &self,
        fileio: &FileIO,
        identifier: &TableIdent,
        metadata_location: String,
        metadata: Arc<TableMetadata>,
    ) -> Result<Table> {
        let built = build(fileio, identifier, metadata_location.clone(), metadata)?;
        if let Some(cache) = &self.inner {
            cache.insert(metadata_location, built.clone()).await;
        }
        Ok(built)
    }
}

impl std::fmt::Debug for TableHandleCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.inner {
            Some(c) => f
                .debug_struct("TableHandleCache")
                .field("entries", &c.entry_count())
                .finish(),
            None => f
                .debug_struct("TableHandleCache")
                .field("enabled", &false)
                .finish(),
        }
    }
}

fn build(
    fileio: &FileIO,
    identifier: &TableIdent,
    metadata_location: String,
    metadata: Arc<TableMetadata>,
) -> Result<Table> {
    Table::builder()
        .file_io(fileio.clone())
        .identifier(identifier.clone())
        .metadata_location(metadata_location)
        .metadata(metadata)
        .build()
}
