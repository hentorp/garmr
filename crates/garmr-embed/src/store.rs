// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! A tiny on-disk vector store for semantic search — append records, then serve
//! queries through a vendored **HNSW** ANN index (`znippy-zoomies::vann`) instead
//! of the old brute-force cosine scan: O(log n) graph descent rather than an O(n)
//! sweep of the window. Deliberately simple: home-lab scale (tens to low-hundreds
//! of thousands of vectors), a bounded window kept in RAM, one flat file for
//! persistence.
//!
//! Records are denormalized (they carry ts/host/service/message alongside the
//! vector) so a search result needs no lakehouse round-trip and no event id —
//! the cost is bounded by the window cap.
//!
//! The HNSW index is built lazily on the first [`search`](VectorStore::search)
//! and memoized (interior mutability), so it reflects the records present at that
//! point — exactly the construction-time set in garmr's usage, where a store is
//! filled by `push`es and `flush`ed before any query. Any [`push`](VectorStore::push)
//! after a build invalidates the memoized graph so a stale index is never served;
//! the 900s rebuild-and-swap harness handles ongoing freshness. The graph is
//! approximate, so results may differ from an exact scan on the tail; a short
//! exact-[`cosine`] rerank of the over-fetched candidates keeps the returned
//! scores exact and their order consistent with the old brute-force ranking.

use std::collections::VecDeque;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::sync::OnceLock;

use garmr_core::{Error, Result};
use znippy_zoomies::vann::{HnswIndex, HnswParams};

use crate::{cosine, EMBED_DIM};

/// One embedded event.
#[derive(Debug, Clone)]
pub struct Record {
    pub ts_micros: i64,
    pub host: String,
    pub service: String,
    pub message: String,
    pub vec: Vec<f32>,
}

/// Magic + format version for the stamped file header (see [`encode_header`]).
const MAGIC: &[u8; 4] = b"GVS2";
const FORMAT_VERSION: u16 = 1;

/// A bounded, flat-file vector store. The newest `cap` records are kept in
/// memory (and are what a `flush` persists), so both RAM and disk stay bounded.
///
/// The file is **stamped with the embedding-model digest** and [`EMBED_DIM`]: on
/// [`open`](Self::open) a file whose stamp does not match the current model (or a
/// legacy/unstamped file) is discarded rather than served — vectors from a
/// different model are not comparable, so a model change forces a clean rebuild
/// instead of silently corrupting search.
pub struct VectorStore {
    path: PathBuf,
    records: VecDeque<Record>,
    cap: usize,
    /// The embedding-model digest this store's vectors were produced by. Written
    /// into the file header on [`flush`](Self::flush); checked on [`open`](Self::open).
    model_digest: String,
    /// Lazily-built, memoized HNSW ANN index over the current [`Self::records`]
    /// (built on the first [`search`](Self::search)). Reset to empty on any
    /// mutation ([`push`](Self::push)) so it can never serve a graph whose node
    /// ids no longer line up with the record window. Node id `i` maps to
    /// `records[i]` (the record's position at build time).
    ann: OnceLock<HnswIndex>,
}

impl VectorStore {
    /// A fresh empty store bound to `path` (ignores any existing file), stamped
    /// with `model_digest` — for rebuilding from scratch, then [`flush`](Self::flush)ing.
    pub fn new(path: impl Into<PathBuf>, cap: usize, model_digest: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            records: VecDeque::new(),
            cap: cap.max(1),
            model_digest: model_digest.into(),
            ann: OnceLock::new(),
        }
    }

    /// Open (loading an existing file if present), keeping at most `cap` newest
    /// records — but ONLY if the file's stamp matches `model_digest` + [`EMBED_DIM`].
    /// A missing, legacy/unstamped, or mismatched file yields an empty store (a
    /// rebuild), never records from a different model. A missing file is empty.
    pub fn open(
        path: impl Into<PathBuf>,
        cap: usize,
        model_digest: impl Into<String>,
    ) -> Result<Self> {
        let path = path.into();
        let cap = cap.max(1);
        let model_digest = model_digest.into();
        let mut records = VecDeque::new();
        if path.exists() {
            let bytes = std::fs::read(&path)
                .map_err(|e| Error::store(format!("vector store read: {e}")))?;
            match decode_stamped(&bytes, &model_digest) {
                Some(recs) => records = recs,
                None => tracing::warn!(
                    path = %path.display(),
                    "vector store stamp mismatch (model change / legacy / corrupt) — discarding; the reindex loop rebuilds it"
                ),
            }
            while records.len() > cap {
                records.pop_front();
            }
        }
        Ok(Self {
            path,
            records,
            cap,
            model_digest,
            ann: OnceLock::new(),
        })
    }

    /// The embedding-model digest this store is stamped with.
    pub fn model_digest(&self) -> &str {
        &self.model_digest
    }

    /// The newest record timestamp (µs), for an index-freshness / lag metric.
    pub fn newest_ts(&self) -> Option<i64> {
        self.records.iter().map(|r| r.ts_micros).max()
    }

    pub fn len(&self) -> usize {
        self.records.len()
    }
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Iterate the current in-memory records. Lets a rebuild carry forward
    /// vectors it already computed — a message's embedding depends only on its
    /// text, so an unchanged message never needs re-embedding.
    pub fn records(&self) -> impl Iterator<Item = &Record> {
        self.records.iter()
    }

    /// Add a record to the in-memory window (evicting the oldest past `cap`).
    /// Skips records whose vector isn't [`EMBED_DIM`] (defensive). Call
    /// [`flush`](Self::flush) to persist.
    pub fn push(&mut self, rec: Record) {
        if rec.vec.len() != EMBED_DIM {
            return;
        }
        self.records.push_back(rec);
        while self.records.len() > self.cap {
            self.records.pop_front();
        }
        // The record window changed → drop any memoized HNSW graph. Its node ids
        // are record positions, which an eviction/append shifts, so a stale graph
        // could map a hit to the wrong record. The next search rebuilds it.
        self.ann = OnceLock::new();
    }

    /// Rewrite the file from the current (capped) window — bounds the file. The
    /// file is prefixed with the model-digest stamp so a later [`open`](Self::open)
    /// can reject it after a model change.
    pub fn flush(&self) -> Result<()> {
        let mut buf = Vec::new();
        encode_header(&mut buf, &self.model_digest);
        for r in &self.records {
            encode_into(&mut buf, r);
        }
        // Write to a temp then rename, so a crash never leaves a half file.
        let tmp = self.path.with_extension("tmp");
        {
            let mut f = std::fs::File::create(&tmp)
                .map_err(|e| Error::store(format!("vector store write: {e}")))?;
            f.write_all(&buf)
                .map_err(|e| Error::store(format!("vector store write: {e}")))?;
            f.sync_all().ok();
        }
        std::fs::rename(&tmp, &self.path)
            .map_err(|e| Error::store(format!("vector store rename: {e}")))?;
        // fsync the parent dir so the rename (the directory entry) survives a
        // crash — the index is cheap to rebuild, but this makes it durable.
        if let Some(parent) = self.path.parent() {
            if let Ok(d) = std::fs::File::open(parent) {
                d.sync_all().ok();
            }
        }
        Ok(())
    }

    /// Top-`n` records by cosine similarity to `query`, highest first.
    ///
    /// Runs the memoized HNSW graph (built on first call), over-fetching a wider
    /// candidate band that a short exact-[`cosine`] rerank narrows to the top `n`.
    /// The returned scores are therefore the exact cosine (a dot product of the
    /// L2-normalized vectors) — same units and ordering as the old brute-force
    /// scan — while the graph descent replaces the O(n) sweep. Approximate: a true
    /// nearest neighbour missed by the graph won't be recalled by the rerank.
    pub fn search(&self, query: &[f32], n: usize) -> Vec<(f32, Record)> {
        // A wrong-dimensioned query can't be scored (and would panic the HNSW's
        // dim assertion); mirror `cosine`'s defensive "no match" for a mismatch.
        if n == 0 || self.records.is_empty() || query.len() != EMBED_DIM {
            return Vec::new();
        }
        let hnsw = self.ann.get_or_init(|| self.build_ann());

        // Over-fetch so the exact rerank has a band to reorder — HNSW's approximate
        // ranking on the tail is tightened by rescoring with the exact cosine. The
        // widening is bounded (never below `n + 16`) so tiny windows still fetch all.
        let fetch = n.saturating_mul(4).max(n.saturating_add(16));
        // Rerank the candidate band by exact cosine while only *borrowing* each
        // record; the record clones happen after the truncate, so we copy the `n`
        // survivors — not the whole (~4n) over-fetched band.
        let mut hits: Vec<(f32, &Record)> = hnsw
            .search(query, fetch)
            .into_iter()
            // Node id is the record's position at build time; a memoized graph is
            // always paired with the record window it was built from (reset on
            // `push`), so this lookup can't go stale.
            .filter_map(|(id, _approx)| {
                self.records
                    .get(id as usize)
                    .map(|r| (cosine(query, &r.vec), r))
            })
            .collect();
        hits.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));
        hits.truncate(n);
        hits.into_iter().map(|(s, r)| (s, r.clone())).collect()
    }

    /// Force the ANN graph to build NOW, if it has not already, and report
    /// whether the store has anything to search. Lets a caller pay the
    /// O(N·log N) graph construction off the query hot path — e.g. the reindex
    /// task warms a freshly-rebuilt store BEFORE swapping it in, so no live query
    /// ever eats the build cost while holding the read lock.
    pub fn warm(&self) -> bool {
        if self.records.is_empty() {
            return false;
        }
        let _ = self.ann.get_or_init(|| self.build_ann());
        true
    }

    /// Build the HNSW ANN index over the current record window. The stored vectors
    /// are already L2-normalized (the embedder normalizes), which is exactly what
    /// [`HnswIndex`] wants; node id `i` is the record's position, so a hit maps
    /// straight back via `records[id]`. Records with an off-dimension vector are
    /// skipped (their id is simply absent from the graph). Single-threaded build;
    /// the win is on the query side, and it happens once per memoized store.
    fn build_ann(&self) -> HnswIndex {
        let mut flat = Vec::with_capacity(self.records.len() * EMBED_DIM);
        let mut ids = Vec::with_capacity(self.records.len());
        for (i, r) in self.records.iter().enumerate() {
            if r.vec.len() == EMBED_DIM {
                flat.extend_from_slice(&r.vec);
                ids.push(i as u64);
            }
        }
        HnswIndex::build(EMBED_DIM, ids, flat, HnswParams::default())
    }
}

// ---- binary framing -------------------------------------------------------
// header: [MAGIC "GVS2"][u16 format_ver][u32 digest_len][digest][u16 embed_dim]
// record: [i64 ts][u16 host_len][host][u16 svc_len][svc][u32 msg_len][msg][u16 dim][dim×f32]

/// Write the model-digest stamp header.
fn encode_header(buf: &mut Vec<u8>, digest: &str) {
    buf.extend_from_slice(MAGIC);
    buf.extend_from_slice(&FORMAT_VERSION.to_le_bytes());
    let db = digest.as_bytes();
    buf.extend_from_slice(&(db.len().min(u32::MAX as usize) as u32).to_le_bytes());
    buf.extend_from_slice(db);
    buf.extend_from_slice(&(EMBED_DIM as u16).to_le_bytes());
}

/// Decode a stamped file: `Some(records)` only when the header is present and its
/// model digest + embed dim match `expected_digest`/[`EMBED_DIM`]; otherwise `None`
/// (a legacy/unstamped, mismatched, or corrupt file — the caller discards it).
fn decode_stamped(bytes: &[u8], expected_digest: &str) -> Option<VecDeque<Record>> {
    let mut c = std::io::Cursor::new(bytes);
    let mut magic = [0u8; 4];
    if c.read_exact(&mut magic).is_err() || &magic != MAGIC {
        return None; // legacy/unstamped or empty — cannot trust the model
    }
    let mut fv = [0u8; 2];
    c.read_exact(&mut fv).ok()?;
    if u16::from_le_bytes(fv) != FORMAT_VERSION {
        return None;
    }
    let mut dl = [0u8; 4];
    c.read_exact(&mut dl).ok()?;
    let dlen = u32::from_le_bytes(dl) as usize;
    if dlen > 512 {
        return None; // a sane model digest is short; a huge length is corruption
    }
    let mut db = vec![0u8; dlen];
    c.read_exact(&mut db).ok()?;
    if String::from_utf8_lossy(&db) != expected_digest {
        return None; // vectors from a different model — not comparable
    }
    let mut dim = [0u8; 2];
    c.read_exact(&mut dim).ok()?;
    if u16::from_le_bytes(dim) as usize != EMBED_DIM {
        return None;
    }
    let rest = &bytes[c.position() as usize..];
    decode_all(rest).ok()
}

fn encode_into(buf: &mut Vec<u8>, r: &Record) {
    buf.extend_from_slice(&r.ts_micros.to_le_bytes());
    put_str(buf, &r.host, 2);
    put_str(buf, &r.service, 2);
    put_str(buf, &r.message, 4);
    buf.extend_from_slice(&(r.vec.len() as u16).to_le_bytes());
    for f in &r.vec {
        buf.extend_from_slice(&f.to_le_bytes());
    }
}

fn put_str(buf: &mut Vec<u8>, s: &str, width: usize) {
    let b = s.as_bytes();
    let n = b.len();
    if width == 2 {
        buf.extend_from_slice(&(n.min(u16::MAX as usize) as u16).to_le_bytes());
    } else {
        buf.extend_from_slice(&(n.min(u32::MAX as usize) as u32).to_le_bytes());
    }
    buf.extend_from_slice(
        &b[..n.min(if width == 2 {
            u16::MAX as usize
        } else {
            u32::MAX as usize
        })],
    );
}

/// Decode all records; stops at the first truncated/garbled frame (a partial
/// tail from an interrupted write is dropped, not an error).
fn decode_all(bytes: &[u8]) -> Result<VecDeque<Record>> {
    let mut c = std::io::Cursor::new(bytes);
    let mut out = VecDeque::new();
    loop {
        match decode_one(&mut c) {
            Ok(Some(r)) => out.push_back(r),
            Ok(None) => break,
            Err(_) => break, // truncated tail — keep what we have
        }
    }
    Ok(out)
}

fn decode_one(c: &mut std::io::Cursor<&[u8]>) -> std::io::Result<Option<Record>> {
    // At a record boundary there are either ≥8 bytes (a record) or 0 (clean
    // EOF); anything in between is a truncated tail.
    let mut tsb = [0u8; 8];
    let mut got = 0;
    while got < 8 {
        let n = c.read(&mut tsb[got..])?;
        if n == 0 {
            break;
        }
        got += n;
    }
    if got == 0 {
        return Ok(None); // clean EOF
    }
    if got < 8 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "truncated",
        ));
    }
    let ts = i64::from_le_bytes(tsb);
    let host = get_str(c, 2)?;
    let service = get_str(c, 2)?;
    let message = get_str(c, 4)?;
    let mut d2 = [0u8; 2];
    c.read_exact(&mut d2)?;
    let dim = u16::from_le_bytes(d2) as usize;
    // Guard a garbled dim from triggering a huge allocation.
    if dim > 8192 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "bad dim",
        ));
    }
    let mut vec = vec![0f32; dim];
    let mut fb = [0u8; 4];
    for v in vec.iter_mut() {
        c.read_exact(&mut fb)?;
        *v = f32::from_le_bytes(fb);
    }
    Ok(Some(Record {
        ts_micros: ts,
        host,
        service,
        message,
        vec,
    }))
}

fn get_str(c: &mut std::io::Cursor<&[u8]>, width: usize) -> std::io::Result<String> {
    let len = if width == 2 {
        let mut b = [0u8; 2];
        c.read_exact(&mut b)?;
        u16::from_le_bytes(b) as usize
    } else {
        let mut b = [0u8; 4];
        c.read_exact(&mut b)?;
        u32::from_le_bytes(b) as usize
    };
    // Bound the length by the bytes actually remaining before allocating, so a
    // corrupt/crafted length prefix (u32 → up to 4 GiB) can't trigger a huge
    // up-front allocation — the same corruption-tolerance the dim guard gives.
    let remaining = (c.get_ref().len() as u64).saturating_sub(c.position()) as usize;
    if len > remaining {
        return Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "string len past EOF",
        ));
    }
    let mut buf = vec![0u8; len];
    c.read_exact(&mut buf)?;
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(ts: i64, msg: &str, v: f32) -> Record {
        Record {
            ts_micros: ts,
            host: "pve".into(),
            service: "sshd".into(),
            message: msg.into(),
            vec: vec![v; EMBED_DIM],
        }
    }

    #[test]
    fn roundtrips_and_caps_and_searches() {
        let dir = std::env::temp_dir().join(format!("garmr-vec-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("vectors.bin");

        let mut s = VectorStore::open(&path, 3, "m1").unwrap();
        s.push(rec(1, "a", 0.0));
        s.push(rec(2, "b", 0.5));
        s.push(rec(3, "c", 1.0));
        s.push(rec(4, "d", 0.9)); // evicts ts=1 (cap 3)
        assert_eq!(s.len(), 3);
        s.flush().unwrap();

        // Reload with the SAME model digest keeps the newest 3.
        let s2 = VectorStore::open(&path, 3, "m1").unwrap();
        assert_eq!(s2.len(), 3);
        assert!(s2.records.iter().all(|r| r.ts_micros != 1));

        // Reload with a DIFFERENT model digest discards the (incompatible) vectors.
        let s3 = VectorStore::open(&path, 3, "m2-different").unwrap();
        assert!(s3.is_empty(), "a model change must not serve stale vectors");

        // A query near v=1.0 ranks ts=3 (all-ones) first.
        let q = vec![1.0 / (EMBED_DIM as f32).sqrt(); EMBED_DIM];
        let hits = s2.search(&q, 2);
        assert_eq!(hits.len(), 2);
        assert_eq!(hits[0].1.ts_micros, 3);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn warm_builds_the_graph_off_the_query_path() {
        let mut s = VectorStore::new(std::env::temp_dir().join("garmr-vec-warm.bin"), 10, "m1");
        assert!(!s.warm(), "an empty store has nothing to warm");
        s.push(rec(1, "a", 0.2));
        s.push(rec(2, "b", 0.9));
        assert!(s.warm(), "a populated store warms");
        // A subsequent query returns the memoized graph's results (nearest first).
        let q = vec![1.0 / (EMBED_DIM as f32).sqrt(); EMBED_DIM];
        let hits = s.search(&q, 1);
        assert_eq!(hits[0].1.ts_micros, 2);
    }

    #[test]
    fn wrong_dim_is_skipped() {
        let mut s =
            VectorStore::open(std::env::temp_dir().join("garmr-vec-skip.bin"), 10, "m1").unwrap();
        s.push(Record {
            ts_micros: 1,
            host: "h".into(),
            service: "s".into(),
            message: "m".into(),
            vec: vec![0.0; 3],
        });
        assert!(s.is_empty());
    }
}
