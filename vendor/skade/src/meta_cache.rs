// Apache-2.0 licensed.

//! L0 parsed-metadata cache.
//!
//! Caches deserialized [`TableMetadata`] keyed by its metadata-file location.
//!
//! Iceberg metadata files are **immutable and content-addressed**: a new commit
//! writes a brand-new `…/metadata/<uuid>.metadata.json` file and flips the
//! table pointer to it. The old file is never mutated in place. Therefore a
//! cached `(metadata_location → TableMetadata)` entry can never be *stale* — it
//! can only be *evicted*. There is no TTL, no invalidation, no coherence logic:
//! the key changes whenever the value would.
//!
//! This is the L0 of the three-layer read path described in `plan.md`. It
//! removes the real cost of [`crate::RedbCatalog::load_table`] — the `FileIO`
//! round-trip plus JSON parse (~150 µs on NVMe, 10–50 ms on object storage) —
//! replacing it on a warm hit with an `Arc` clone (~100–300 ns).

use std::sync::Arc;

use iceberg::io::FileIO;
use iceberg::spec::TableMetadata;
use iceberg::{Error, Result};
use moka::future::Cache;

/// Default budget for the parsed-metadata cache (128 MiB).
pub const DEFAULT_METADATA_CACHE_BYTES: u64 = 128 * 1024 * 1024;

/// Byte-bounded, lock-free cache of parsed [`TableMetadata`].
///
/// Cloneable and cheap to clone (shares one underlying store). A budget of `0`
/// disables caching entirely (every load reads through to `FileIO`).
#[derive(Clone)]
pub(crate) struct MetadataCache {
    inner: Option<Cache<String, Arc<TableMetadata>>>,
}

impl MetadataCache {
    /// Build a cache bounded to roughly `max_bytes` of parsed metadata. A value
    /// of `0` disables the cache.
    pub(crate) fn new(max_bytes: u64) -> Self {
        let inner = if max_bytes == 0 {
            None
        } else {
            Some(
                Cache::builder()
                    .name("skade-katalog.metadata")
                    .max_capacity(max_bytes)
                    .weigher(|_loc: &String, meta: &Arc<TableMetadata>| weight_of(meta))
                    .build(),
            )
        };
        Self { inner }
    }

    /// Return the parsed metadata for `metadata_location`, reading + parsing it
    /// via `fileio` on a miss.
    ///
    /// Concurrent misses on the *same* location coalesce into a single
    /// `read_from` (moka single-flight), so a hot table is parsed at most once
    /// even under a thundering herd of readers.
    pub(crate) async fn get_or_load(
        &self,
        fileio: &FileIO,
        metadata_location: &str,
    ) -> Result<Arc<TableMetadata>> {
        let Some(cache) = &self.inner else {
            return TableMetadata::read_from(fileio, metadata_location)
                .await
                .map(Arc::new);
        };

        // Fast path: a plain hit skips the single-flight coordination machinery
        // (and the owned-input clones below), which dominates the warm read.
        if let Some(hit) = cache.get(metadata_location).await {
            return Ok(hit);
        }

        // Miss: own the inputs so the (possibly shared) init future is
        // self-contained, and coalesce concurrent misses on the same location
        // into a single `read_from`. The clones happen only on a miss, where
        // they are dwarfed by the I/O they precede.
        let fileio = fileio.clone();
        let loc = metadata_location.to_string();
        cache
            .try_get_with_by_ref(metadata_location, async move {
                TableMetadata::read_from(&fileio, &loc).await.map(Arc::new)
            })
            .await
            .map_err(|e: Arc<Error>| Error::new(e.kind(), e.to_string()))
    }
}

impl std::fmt::Debug for MetadataCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.inner {
            Some(c) => f
                .debug_struct("MetadataCache")
                .field("entries", &c.entry_count())
                .field("weighted_bytes", &c.weighted_size())
                .finish(),
            None => f
                .debug_struct("MetadataCache")
                .field("enabled", &false)
                .finish(),
        }
    }
}

/// Estimate the in-RAM footprint of a parsed `TableMetadata`.
///
/// `TableMetadata` is not `Serialize` (writes go through a separate enum), so we
/// can't measure JSON length cheaply. This structural estimate is intentionally
/// approximate — the cache budget is a soft memory guard, and moka only needs
/// *relative* weights to make sane eviction decisions. Snapshots and schemas
/// dominate real metadata size, so they carry the bulk of the weight.
fn weight_of(meta: &TableMetadata) -> u32 {
    const BASE: usize = 4 * 1024;
    const PER_SNAPSHOT: usize = 1024;
    const PER_SCHEMA: usize = 2 * 1024;
    const PER_LOG: usize = 256;

    let props: usize = meta
        .properties()
        .iter()
        .map(|(k, v)| k.len() + v.len() + 32)
        .sum();

    let est = BASE
        + meta.snapshots().len() * PER_SNAPSHOT
        + meta.schemas_iter().len() * PER_SCHEMA
        + meta.metadata_log().len() * PER_LOG
        + props;

    est.min(u32::MAX as usize) as u32
}
