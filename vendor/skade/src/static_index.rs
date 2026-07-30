// Apache-2.0 licensed.

//! L1-historical: the Ragnar static snapshot-id index.
//!
//! An immutable, read-optimized projection of the [`crate::store::COMMITS`]
//! log: `snapshot_id (i64) → (table_key, metadata_location)`. It is built by
//! scanning the durable commit log into a sorted key array, then constructing a
//! [`STree64`](znippy_zoomies::stree::STree64) — Ragnar Groot Koerkamp's
//! cache-line-packed implicit B-tree — over the snapshot ids. Lookups are a
//! handful of cache-line probes with no hashing (snapshot ids are already
//! `i64`), no locks, and no redb access.
//!
//! Correctness: snapshot ids are **immutable and globally unique** in Iceberg,
//! so an entry can only be evicted (by a rebuild that drops nothing it still
//! needs), never wrong. The compactor rebuilds this whole structure and swaps
//! it atomically; this module only *builds* and *reads* one immutable instance.
//!
//! Wired in: the background compactor in [`crate::store`] builds this index and
//! swaps it via `ArcSwapOption`, and the snapshot-id read paths
//! (`resolve_location_at`, `load_table_at`, `resolve_metadata_at`, `resolve_many`)
//! route through it before falling back to the redb commit log. Every accessor
//! here has a production call site EXCEPT `min_id`, which is exercised only by
//! tests — so the `dead_code` allow is scoped to that one accessor rather than
//! the whole module, so genuinely-dead future additions aren't masked.

use std::sync::Arc;

use redb::ReadableTable;
use znippy_zoomies::stree::STree64;

use crate::error::RedbCatalogError;
use crate::store::COMMITS;

/// One resolved commit: which table and which immutable metadata file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Entry {
    pub(crate) table_key: Box<str>,
    pub(crate) metadata_location: Box<str>,
}

/// Immutable snapshot-id → location index. Built once, read lock-free, replaced
/// wholesale by the compactor (never mutated in place).
pub(crate) struct StaticIndex {
    min_id: i64,
    max_id: i64,
    /// STree64 over `ids` (ascending). `find_exact` returns the index into the
    /// parallel `entries`/`ids` arrays.
    tree: STree64,
    /// Sorted snapshot ids, parallel to `entries`.
    ids: Arc<[i64]>,
    entries: Arc<[Entry]>,
}

impl std::fmt::Debug for StaticIndex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StaticIndex")
            .field("min_id", &self.min_id)
            .field("max_id", &self.max_id)
            .field("len", &self.entries.len())
            .finish()
    }
}

impl StaticIndex {
    /// Build the index from every row currently in the commit log. Returns
    /// `None` when the log is empty (nothing to accelerate yet).
    pub(crate) fn build(read: &redb::ReadTransaction) -> Result<Option<Self>, RedbCatalogError> {
        let tbl = read.open_table(COMMITS)?;
        let mut rows: Vec<(i64, Entry)> = Vec::new();
        for row in tbl.iter()? {
            let (k, v) = row?;
            let key = k.value();
            if let Some((sid, table_key)) = decode_commit_key(key) {
                rows.push((
                    sid,
                    Entry {
                        table_key: table_key.into(),
                        metadata_location: v.value().into(),
                    },
                ));
            }
        }
        Ok(Self::from_rows(rows))
    }

    /// Build directly from `(snapshot_id, entry)` pairs (used by tests and a
    /// future in-memory compaction path). De-duplicates on snapshot id keeping
    /// the last seen, then sorts — `STree64` requires strictly sorted keys.
    fn from_rows(mut rows: Vec<(i64, Entry)>) -> Option<Self> {
        if rows.is_empty() {
            return None;
        }
        rows.sort_by_key(|(sid, _)| *sid);
        rows.dedup_by_key(|(sid, _)| *sid);
        let ids: Vec<i64> = rows.iter().map(|(s, _)| *s).collect();
        let entries: Vec<Entry> = rows.into_iter().map(|(_, e)| e).collect();
        let min_id = ids[0];
        let max_id = *ids.last().unwrap();
        let tree = STree64::new(&ids);
        Some(Self {
            min_id,
            max_id,
            tree,
            ids: ids.into(),
            entries: entries.into(),
        })
    }

    /// Inclusive lowest snapshot id covered by this index. Test-only introspection
    /// (production routing keys off `max_id`); the `min_id` field itself is live
    /// (printed by the `Debug` impl), only this accessor is unused in prod.
    #[allow(dead_code)]
    pub(crate) fn min_id(&self) -> i64 {
        self.min_id
    }
    /// Inclusive highest snapshot id covered (the routing cutoff: ids `<=`
    /// this are served here; ids above fall through to the redb live tail).
    pub(crate) fn max_id(&self) -> i64 {
        self.max_id
    }
    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }

    /// Resolve a snapshot id to its `(table_key, metadata_location)`.
    pub(crate) fn lookup(&self, snapshot_id: i64) -> Option<&Entry> {
        let idx = self.tree.find_exact(snapshot_id)?;
        // Defensive: STree64 returns an index into the array it was built over.
        debug_assert_eq!(self.ids.get(idx).copied(), Some(snapshot_id));
        self.entries.get(idx)
    }

    /// Batch-resolve many snapshot ids in one software-pipelined `STree64` pass
    /// (prefetch overlaps the cache-line probes — Ragnar's batch win). Returns
    /// one slot per input id, in the same order; `None` where the id is absent.
    pub(crate) fn lookup_many(&self, snapshot_ids: &[i64]) -> Vec<Option<&Entry>> {
        self.tree
            .batch_stream::<16>(snapshot_ids)
            .into_iter()
            .zip(snapshot_ids)
            .map(|(hit, &q)| {
                hit.and_then(|i| {
                    // Map an index back to an entry only on a true exact hit.
                    if self.ids.get(i).copied() == Some(q) {
                        self.entries.get(i)
                    } else {
                        None
                    }
                })
            })
            .collect()
    }
}

/// Split a [`COMMITS`] key `{table_key}\x1f{snapshot_id:u64_be}` back into
/// `(snapshot_id, table_key)`. The last 8 bytes are the big-endian id; the byte
/// before them is the `\x1f` separator we appended in `store::commit_key`.
fn decode_commit_key(key: &[u8]) -> Option<(i64, String)> {
    let n = key.len();
    if n < 9 {
        return None;
    }
    let mut be = [0u8; 8];
    be.copy_from_slice(&key[n - 8..]);
    let sid = u64::from_be_bytes(be) as i64;
    let table_key = std::str::from_utf8(&key[..n - 9]).ok()?.to_string();
    Some((sid, table_key))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(loc: &str) -> Entry {
        Entry {
            table_key: "cat\x1fns\x1ft".into(),
            metadata_location: loc.into(),
        }
    }

    #[test]
    fn decode_round_trips_commit_key() {
        let k = crate::store::commit_key("cat\x1fns\x1ft", 123456789);
        let (sid, tk) = decode_commit_key(&k).unwrap();
        assert_eq!(sid, 123456789);
        assert_eq!(tk, "cat\x1fns\x1ft");
    }

    #[test]
    fn empty_log_builds_nothing() {
        assert!(StaticIndex::from_rows(vec![]).is_none());
    }

    #[test]
    fn lookup_hits_and_misses() {
        // Intentionally unsorted input: build must sort before STree64.
        let rows = vec![(300, entry("c")), (100, entry("a")), (200, entry("b"))];
        let idx = StaticIndex::from_rows(rows).unwrap();
        assert_eq!(idx.min_id(), 100);
        assert_eq!(idx.max_id(), 300);
        assert_eq!(idx.len(), 3);
        assert_eq!(idx.lookup(100).unwrap().metadata_location.as_ref(), "a");
        assert_eq!(idx.lookup(200).unwrap().metadata_location.as_ref(), "b");
        assert_eq!(idx.lookup(300).unwrap().metadata_location.as_ref(), "c");
        let miss = idx.lookup(150).is_none() && idx.lookup(400).is_none();
        assert!(miss);
        #[cfg(feature = "testmatrix")]
        nornir_testmatrix::functional_status(
            "static_index",
            "lookup_hits_and_misses",
            idx.len() == 3 && idx.min_id() == 100 && idx.max_id() == 300 && miss,
            &format!(
                "STree64 len={} min={} max={}, present-hit + absent-miss ok={miss}",
                idx.len(),
                idx.min_id(),
                idx.max_id()
            ),
        );
    }

    #[test]
    fn lookup_many_batches_hits_and_misses_in_order() {
        // > 16 entries so batch_stream exercises both the pipelined chunk path
        // and the single-query remainder.
        let rows: Vec<(i64, Entry)> = (0..20)
            .map(|i| (i * 10, entry(&format!("loc-{i}"))))
            .collect();
        let idx = StaticIndex::from_rows(rows).unwrap();

        // Mix present ids, absent ids, and an out-of-order arrangement.
        let queries = [0, 5, 190, 100, 999, 30, 195, 10];
        let got = idx.lookup_many(&queries);
        let locs: Vec<Option<&str>> = got
            .iter()
            .map(|e| e.map(|x| x.metadata_location.as_ref()))
            .collect();
        assert_eq!(
            locs,
            vec![
                Some("loc-0"),  // 0
                None,           // 5 absent
                Some("loc-19"), // 190
                Some("loc-10"), // 100
                None,           // 999 absent
                Some("loc-3"),  // 30
                None,           // 195 absent
                Some("loc-1"),  // 10
            ]
        );

        // Matches single-lookup semantics element-for-element.
        let mut parity = true;
        for q in [0i64, 5, 50, 190, 195, 200] {
            let single = idx.lookup(q).map(|e| e.metadata_location.as_ref());
            let batched = idx.lookup_many(&[q])[0].map(|e| e.metadata_location.as_ref());
            assert_eq!(single, batched, "mismatch at {q}");
            parity &= single == batched;
        }
        let order_ok = locs
            == vec![
                Some("loc-0"),
                None,
                Some("loc-19"),
                Some("loc-10"),
                None,
                Some("loc-3"),
                None,
                Some("loc-1"),
            ];
        assert!(order_ok && parity);
        #[cfg(feature = "testmatrix")]
        nornir_testmatrix::functional_status(
            "static_index",
            "lookup_many_batches_hits_and_misses_in_order",
            order_ok && parity,
            &format!(
                "batch over {} entries preserves order={order_ok}, single/batch parity={parity}",
                idx.len()
            ),
        );
    }

    #[test]
    fn builds_from_a_real_commit_log() {
        use crate::store::{COMMITS, META, record_commit};
        let dir = tempfile::tempdir().unwrap();
        let db = redb::Database::create(dir.path().join("c.redb")).unwrap();
        {
            let w = db.begin_write().unwrap();
            {
                let _ = w.open_table(COMMITS);
                let _ = w.open_table(META);
            }
            w.commit().unwrap();
        }
        {
            let w = db.begin_write().unwrap();
            record_commit(&w, "cat\x1fns\x1ft", Some(42), "loc-42").unwrap();
            record_commit(&w, "cat\x1fns\x1fu", Some(7), "loc-7").unwrap();
            record_commit(&w, "cat\x1fns\x1ft", None, "ignored").unwrap();
            w.commit().unwrap();
        }
        let read = db.begin_read().unwrap();
        let idx = StaticIndex::build(&read).unwrap().unwrap();
        assert_eq!(idx.len(), 2, "the snapshot-less commit adds no index entry");
        assert_eq!(idx.lookup(42).unwrap().metadata_location.as_ref(), "loc-42");
        assert_eq!(idx.lookup(42).unwrap().table_key.as_ref(), "cat\x1fns\x1ft");
        assert_eq!(idx.lookup(7).unwrap().metadata_location.as_ref(), "loc-7");
        assert_eq!(idx.lookup(7).unwrap().table_key.as_ref(), "cat\x1fns\x1fu");
        assert_eq!(idx.min_id(), 7);
        assert_eq!(idx.max_id(), 42);
        #[cfg(feature = "testmatrix")]
        nornir_testmatrix::functional_status(
            "static_index",
            "builds_from_a_real_commit_log",
            idx.len() == 2 && idx.min_id() == 7 && idx.max_id() == 42,
            &format!(
                "built from redb commit log: indexed={} (snapshot-less commit skipped), min={} max={}",
                idx.len(),
                idx.min_id(),
                idx.max_id()
            ),
        );
    }
}
