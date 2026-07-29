// Apache-2.0 licensed.

//! L1: lock-free current-pointer mirror.
//!
//! An in-memory, generation-stamped snapshot of `table_key → metadata_location`
//! for every table in the catalog, published via [`ArcSwap`]. Reads load the
//! snapshot lock-free and resolve the pointer **without touching redb** —
//! removing the `begin_read()` + `open_table()` cost (~16 µs, measured) from
//! the warm [`crate::RedbCatalog::load_table`] path.
//!
//! ## Why this is correct
//!
//! Correctness rests on **single-process ownership**: redb takes an exclusive
//! file lock, so *every* mutation of the `tables` keyspace flows through this
//! process. Each write path updates the mirror write-through *after* its redb
//! commit, while still holding the redb write lock — so mirror updates are
//! serialized with each other and ordered after the durable commit. The mirror
//! is therefore always complete and never stale; a key absent from it means the
//! table does not exist.
//!
//! A redb fallback on a mirror miss is kept purely as a safety net. It only ever
//! runs for genuinely-absent tables (or a hypothetical missed write-through),
//! never on the warm path, so it costs nothing in the common case.
//!
//! ## Snapshot semantics
//!
//! Each published [`PointerSnapshot`] is immutable and carries a monotonic
//! `generation`. Readers observe one whole snapshot atomically (never a torn
//! state), exactly the "swap a new immutable view atomically" model from
//! `plan.md`. The generation also serves as the "writes since open" counter
//! that will later trigger the historical static-tree (STree64) compaction.

use std::sync::Arc;

use arc_swap::ArcSwap;
use imbl::HashMap;

/// The mirror map. Keys are internal, content-addressed table identifiers — not
/// attacker-controlled — so the default SipHash buys nothing but latency. We use
/// `foldhash` (fast, well-distributed, AES-NI-free) instead; reads stay lock-free
/// and the `O(1)` structural-sharing clone on write-through is unchanged.
type PtrMap = HashMap<String, Arc<str>, foldhash::fast::RandomState>;

/// Immutable, generation-stamped point-in-time view of all table pointers.
#[derive(Debug)]
pub(crate) struct PointerSnapshot {
    /// Monotonic id, bumped on every published mutation.
    pub(crate) generation: u64,
    map: PtrMap,
}

impl PointerSnapshot {
    fn get(&self, key: &str) -> Option<Arc<str>> {
        self.map.get(key).cloned()
    }
}

/// Shared, cheaply-cloneable handle to the pointer mirror.
#[derive(Clone)]
pub(crate) struct PointerCache {
    inner: Arc<ArcSwap<PointerSnapshot>>,
}

impl PointerCache {
    /// Build the initial mirror from a full scan of the `tables` keyspace.
    pub(crate) fn from_entries(entries: impl IntoIterator<Item = (String, String)>) -> Self {
        let map: PtrMap = entries
            .into_iter()
            .map(|(k, v)| (k, Arc::from(v.as_str())))
            .collect();
        Self {
            inner: Arc::new(ArcSwap::from_pointee(PointerSnapshot {
                generation: 0,
                map,
            })),
        }
    }

    /// Lock-free read of the current pointer for `key`.
    pub(crate) fn get(&self, key: &str) -> Option<Arc<str>> {
        self.inner.load().get(key)
    }

    /// Current generation: number of published mutations since open.
    pub(crate) fn generation(&self) -> u64 {
        self.inner.load().generation
    }

    /// Publish a new snapshot with `key → loc` inserted (or overwritten).
    ///
    /// Callers must hold the redb write lock, which serializes mutations; the
    /// load→clone→store sequence is therefore race-free against other writers,
    /// while readers still observe the swap atomically.
    pub(crate) fn insert(&self, key: &str, loc: &str) {
        self.mutate(|m| {
            m.insert(key.to_string(), Arc::from(loc));
        });
    }

    /// Publish a new snapshot with `key` removed.
    pub(crate) fn remove(&self, key: &str) {
        self.mutate(|m| {
            m.remove(key);
        });
    }

    fn mutate(&self, f: impl FnOnce(&mut PtrMap)) {
        let cur = self.inner.load();
        // `imbl::HashMap::clone` is O(1) (structural sharing); the subsequent
        // insert/remove is O(log n) and only copies the touched path.
        let mut map = cur.map.clone();
        f(&mut map);
        self.inner.store(Arc::new(PointerSnapshot {
            generation: cur.generation + 1,
            map,
        }));
    }
}

impl std::fmt::Debug for PointerCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let snap = self.inner.load();
        f.debug_struct("PointerCache")
            .field("generation", &snap.generation)
            .field("entries", &snap.map.len())
            .finish()
    }
}
