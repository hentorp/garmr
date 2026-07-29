//! `vann` — a self-contained **vector-ANN engine**: an exact brute-force
//! ("flat") nearest-neighbour index over `f32` vectors (the 100%-recall ORACLE)
//! and the runtime-detected SIMD + int8/VNNI cosine kernels it scores with.
//!
//! This is a pure compute core, extracted verbatim from nornir's `src/vector`
//! math layer — no embedder, no warehouse glue, no model registry. Its only
//! dependencies are `std`, `anyhow`, and this crate's own
//! [`crate::gatling_forkjoin`] fork-join pool (used to parallelise the flat
//! scan). Vectors are L2-normalized on insert so cosine similarity is a plain
//! dot product; the per-vector kernel is chosen once per search from what the
//! running CPU supports (AVX-512F → AVX2+FMA → scalar, plus an AVX-512 VNNI
//! int8 path). See [`VectorIndex`], [`score_i8_batch`], and [`bench_kernels`].

use std::collections::HashMap;
use std::path::Path;
use std::sync::OnceLock;

use anyhow::{Context, Result, bail, ensure};

pub mod hnsw;
pub use hnsw::{HnswIndex, HnswParams};

/// Minimum rows a single thread should own before we bother spawning more.
/// Below `2 * MIN_ROWS_PER_THREAD` the search runs single-threaded (spawning
/// is pure overhead for tiny corpora).
const MIN_ROWS_PER_THREAD: usize = 1024;

/// Corpus size at/above which [`VectorIndex::search_auto`] prefers the int8
/// fast-scan (+ exact f32 rerank) path over the pure f32 scan. Chosen the same
/// way the multicore spawn threshold is: below this the f32 matrix comfortably
/// fits in cache and the extra quantize/rerank machinery is pure overhead;
/// above it the memory-bound scan streams 4× fewer bytes as int8 (and, on
/// AVX-512 VNNI silicon, folds 64 int8 MACs/instr). Mirrors the runtime SIMD
/// tier selection — a *speed* switch, never a *results* switch (rerank keeps the
/// returned scores exact-f32).
pub const I8_SCAN_THRESHOLD: usize = 4 * MIN_ROWS_PER_THREAD; // 4096

/// On-disk format magic + version (`NVF` = nornir vector flat, gen 1).
const MAGIC: &[u8; 4] = b"NVF1";

/// An exact (brute-force) nearest-neighbour index over `f32` vectors of a
/// fixed dimensionality, keyed by stable `u64` ids.
pub struct VectorIndex {
    dim: usize,
    /// External ids, parallel to the rows of [`Self::data`].
    ids: Vec<u64>,
    /// Row-major, L2-normalized vectors: `ids.len() * dim` floats.
    data: Vec<f32>,
    /// `id → row index`, for O(1) `contains` / `remove`.
    pos: HashMap<u64, usize>,
    /// Lazily-built int8 quantization of `data` (row-major i8 matrix + per-row
    /// integer sums), memoized so the int8 fast-scan path amortizes the
    /// quantize pass across the many queries that hit a cached index. Reset to
    /// empty on any mutation (`add`/`remove`) so it can never serve a stale
    /// matrix. See [`Self::i8_matrix`] / [`Self::search_i8_rerank`].
    i8_cache: OnceLock<(Vec<i8>, Vec<i32>)>,
}

impl VectorIndex {
    /// Create an empty index over `dim`-dimensional vectors. `dim` must be
    /// non-zero.
    pub fn new(dim: usize) -> Result<Self> {
        ensure!(dim != 0, "vector dim must be non-zero");
        Ok(Self {
            dim,
            ids: Vec::new(),
            data: Vec::new(),
            pos: HashMap::new(),
            i8_cache: OnceLock::new(),
        })
    }

    /// Vector dimensionality this index was built for.
    pub fn dim(&self) -> usize {
        self.dim
    }

    /// Number of vectors currently stored.
    pub fn len(&self) -> usize {
        self.ids.len()
    }

    /// True when no vectors are stored.
    pub fn is_empty(&self) -> bool {
        self.ids.is_empty()
    }

    /// True when `id` is present in the index.
    pub fn contains(&self, id: u64) -> bool {
        self.pos.contains_key(&id)
    }

    /// Add `ids.len()` vectors. `vectors` is the row-major flattened matrix —
    /// exactly `ids.len() * dim` floats. Each vector is L2-normalized before
    /// storage. Ids must be unique both within this call and against vectors
    /// already present.
    pub fn add(&mut self, vectors: &[f32], ids: &[u64]) -> Result<()> {
        ensure!(
            vectors.len() == ids.len() * self.dim,
            "vectors len {} != ids len {} * dim {}",
            vectors.len(),
            ids.len(),
            self.dim
        );
        // Validate ids up front so a partial add is impossible.
        let mut seen = std::collections::HashSet::with_capacity(ids.len());
        for &id in ids {
            ensure!(
                !self.pos.contains_key(&id) && seen.insert(id),
                "duplicate id {id}"
            );
        }
        self.ids.reserve(ids.len());
        self.data.reserve(vectors.len());
        self.pos.reserve(ids.len());
        for (i, &id) in ids.iter().enumerate() {
            let row = &vectors[i * self.dim..(i + 1) * self.dim];
            let row_idx = self.ids.len();
            push_normalized(&mut self.data, row);
            self.ids.push(id);
            self.pos.insert(id, row_idx);
        }
        // The stored matrix changed → drop any memoized int8 quantization.
        self.i8_cache = OnceLock::new();
        Ok(())
    }

    /// Remove the vector with this id (O(1) swap-remove). Returns `true` if it
    /// was present.
    pub fn remove(&mut self, id: u64) -> bool {
        let Some(idx) = self.pos.remove(&id) else {
            return false;
        };
        let last = self.ids.len() - 1;
        let dim = self.dim;
        if idx != last {
            // Move the last row into the hole, fix up its id → index entry.
            self.data
                .copy_within(last * dim..(last + 1) * dim, idx * dim);
            let moved_id = self.ids[last];
            self.ids[idx] = moved_id;
            self.pos.insert(moved_id, idx);
        }
        self.ids.pop();
        self.data.truncate(last * dim);
        // The stored matrix changed → drop any memoized int8 quantization.
        self.i8_cache = OnceLock::new();
        true
    }

    /// Top-`k` nearest ids to `query` (a single `dim`-length vector), best
    /// match first, as `(id, score)` pairs. `score` is cosine similarity in
    /// `[-1, 1]`; higher = closer. Exact — every stored vector is scored.
    ///
    /// # Panics
    /// If `query.len() != dim` (a programmer error, surfaced loudly).
    pub fn search(&self, query: &[f32], k: usize) -> Vec<(u64, f32)> {
        assert_eq!(
            query.len(),
            self.dim,
            "query dim {} != index dim {}",
            query.len(),
            self.dim
        );
        let n = self.ids.len();
        let m = k.min(n);
        if m == 0 {
            return Vec::new();
        }
        let qn = normalized(query);
        let kernel = select_dot_kernel();

        let threads = thread_count(n);
        let mut merged = if threads <= 1 {
            self.score_range(0, n, &qn, kernel, m)
        } else {
            let chunk = n.div_ceil(threads);
            // One unit per contiguous `chunk`-sized range, scored on the
            // no-barrier self-dispatch pool. `gatling_for_each` returns the
            // per-range partials in range (index) order, so flattening yields
            // the same `merged` vector the scoped pool produced before `top_k`.
            let nranges = n.div_ceil(chunk);
            crate::gatling_forkjoin::gatling_for_each(nranges, threads, |r| {
                let start = r * chunk;
                let end = (start + chunk).min(n);
                self.score_range(start, end, &qn, kernel, m)
            })
            .into_iter()
            .flatten()
            .collect()
        };

        top_k(&mut merged, m);
        merged
    }

    /// Top-`k` like [`Self::search`], but scoring through the **int8-quantized
    /// VNNI path** (G2): every stored vector is quantized to `i8` on the fly,
    /// then [`score_i8_batch`] runs the AVX-512 VNNI (or scalar) int8 cosine.
    /// Results match [`Self::search`]'s ranking; scores agree to ~1e-2 (the
    /// quantization tolerance). Useful when the corpus is large enough that the
    /// f32 matrix no longer fits comfortably in cache — the i8 copy is 4× denser.
    ///
    /// This convenience method re-quantizes the whole matrix per call; a corpus
    /// you query repeatedly should keep a persistent i8 copy (see
    /// [`Self::quantized`]).
    ///
    /// # Panics
    /// If `query.len() != dim`.
    pub fn search_i8(&self, query: &[f32], k: usize) -> Vec<(u64, f32)> {
        assert_eq!(
            query.len(),
            self.dim,
            "query dim {} != index dim {}",
            query.len(),
            self.dim
        );
        let n = self.ids.len();
        let m = k.min(n);
        if m == 0 {
            return Vec::new();
        }
        let (rows, sums) = self.quantized();
        let scores = score_i8_batch(query, &rows, self.dim, &sums);
        let mut scored: Vec<(u64, f32)> = self.ids.iter().copied().zip(scores).collect();
        top_k(&mut scored, m);
        scored
    }

    /// Quantize the whole stored matrix to `i8`, returning `(rows, row_sums)`
    /// ready for [`score_i8_batch`]. `rows` is the row-major `n × dim` i8 matrix;
    /// `row_sums[i] = Σ rows[i]`, the VNNI bias-correction term.
    pub fn quantized(&self) -> (Vec<i8>, Vec<i32>) {
        let n = self.ids.len();
        let mut rows = Vec::with_capacity(n * self.dim);
        let mut sums = Vec::with_capacity(n);
        for idx in 0..n {
            let row = &self.data[idx * self.dim..(idx + 1) * self.dim];
            sums.push(quantize_i8(row, &mut rows));
        }
        (rows, sums)
    }

    /// Build a vendored **HNSW** ANN index ([`HnswIndex`]) over this index's
    /// stored (already-L2-normalized) vectors — the O(log n) approximate search
    /// that routes the live dense-kNN retrieval, with THIS flat index kept as the
    /// exact recall **oracle** + small-corpus fallback. Reuses the stored matrix
    /// verbatim (same rows, same ids). Build is single-threaded; the win is on
    /// the query side. `NORNIR_VECTOR_HNSW` gates whether the live path uses it.
    pub fn build_hnsw(&self, params: HnswParams) -> HnswIndex {
        HnswIndex::build(self.dim, self.ids.clone(), self.data.clone(), params)
    }

    /// The memoized int8 matrix + row sums (see [`Self::quantized`]), built once
    /// and reused across queries against this (immutable-between-mutations)
    /// index. The whole point of caching it: the int8 fast-scan's win is memory
    /// traffic, which only materializes when the dense i8 copy is reused rather
    /// than re-derived from `data` on every query.
    fn i8_matrix(&self) -> &(Vec<i8>, Vec<i32>) {
        self.i8_cache.get_or_init(|| self.quantized())
    }

    /// Exact top-`k` computed via an **int8/VNNI fast-scan PREFILTER + exact f32
    /// rerank** (G2). The int8 kernel ([`score_i8_batch`]) scans the whole corpus
    /// — the memory-bound hot loop, streaming the 4×-denser cached i8 matrix — to
    /// build a candidate band; every row in that band is then re-scored with the
    /// **exact** f32 cosine and top-`k`'d. The returned `(id, score)` pairs are
    /// therefore **byte-identical** to [`Self::search`]: quantization only decides
    /// *which rows survive the prefilter*, never the final ranking or scores.
    ///
    /// ## Why the band is provably lossless
    /// int8 quantization perturbs each component by at most `δ = 1/Q`, so the int8
    /// cosine of any pair differs from the exact cosine by at most
    /// `E = 2·δ·√dim + dim·δ²` ([`i8_score_error_bound`]). Let `τ` be the `k`-th
    /// largest **int8** score. Keeping every row with `int8_score ≥ τ − 2E` is
    /// guaranteed to contain the true exact top-`k` (proof: a true top-`k` row's
    /// exact score is `≥` the true `k`-th score `≥ τ − E`, so its int8 score is
    /// `≥ τ − 2E`). The rerank of that band then reproduces the exact result. On
    /// well-separated corpora the band prunes most rows (the speed win); on a
    /// near-tie corpus it degrades to reranking (almost) everything — slower, but
    /// still exact. Falls back to the scalar int8 kernel where VNNI is absent.
    ///
    /// # Panics
    /// If `query.len() != dim`.
    pub fn search_i8_rerank(&self, query: &[f32], k: usize) -> Vec<(u64, f32)> {
        assert_eq!(
            query.len(),
            self.dim,
            "query dim {} != index dim {}",
            query.len(),
            self.dim
        );
        let n = self.ids.len();
        let m = k.min(n);
        if m == 0 {
            return Vec::new();
        }

        // int8 fast scan over the entire corpus (the cached dense i8 matrix).
        let (rows, sums) = self.i8_matrix();
        let i8_scores = score_i8_batch(query, rows, self.dim, sums);

        // τ = the m-th largest int8 score, then keep every row whose int8 score
        // is within the 2E error band below τ. This candidate band PROVABLY
        // contains the exact top-m (see the method doc); it never drops a true
        // hit, so the exact rerank below is lossless.
        let tau = {
            let mut s = i8_scores.clone();
            s.select_nth_unstable_by(m - 1, |a, b| b.total_cmp(a));
            s[m - 1]
        };
        let threshold = tau - 2.0 * i8_score_error_bound(self.dim);
        let cand: Vec<usize> = (0..n).filter(|&i| i8_scores[i] >= threshold).collect();

        // Exact f32 rerank of the candidate band — the ONLY scores that reach the
        // caller, so the top-k is identical to `search`'s exact cosine.
        let qn = normalized(query);
        let kernel = select_dot_kernel();
        let mut exact: Vec<(u64, f32)> = cand
            .iter()
            .map(|&idx| {
                let row = &self.data[idx * self.dim..(idx + 1) * self.dim];
                // SAFETY: `kernel` matches a runtime-confirmed CPU feature (or
                // the always-sound scalar fallback); `qn` and `row` are `dim` long.
                let score = unsafe { kernel(&qn, row) };
                (self.ids[idx], score)
            })
            .collect();
        top_k(&mut exact, m);
        exact
    }

    /// Exact top-`k`, choosing the scan kernel by **corpus size** the same way
    /// the dot kernel is chosen by CPU features: at/above [`I8_SCAN_THRESHOLD`]
    /// rows the int8 fast-scan + exact rerank ([`Self::search_i8_rerank`]) is
    /// used; below it the pure f32 [`Self::search`]. Both return the exact
    /// cosine top-k — the selector trades speed, not results — so this is a safe
    /// drop-in for [`Self::search`] on the live query path.
    ///
    /// # Panics
    /// If `query.len() != dim`.
    pub fn search_auto(&self, query: &[f32], k: usize) -> Vec<(u64, f32)> {
        if self.ids.len() >= I8_SCAN_THRESHOLD {
            self.search_i8_rerank(query, k)
        } else {
            self.search(query, k)
        }
    }

    /// **Batched exact search** — top-`k` for MANY queries at once, reading the
    /// corpus **once** instead of once per query. `queries` is a row-major
    /// `nq × dim` matrix (`queries.len()` must be a multiple of `dim`); the return
    /// is `nq` result lists, `out[i]` = the exact top-`k` for query `i`, in the
    /// same `(id, score)` form and order [`Self::search`] produces.
    ///
    /// ## Why this is faster than `nq` separate `search` calls (and still exact)
    /// Exact flat search is **memory-bandwidth-bound**: the cost is streaming the
    /// stored matrix past the ALU, not the dot-products themselves. Running `nq`
    /// independent `search` calls streams the whole corpus `nq` times. This method
    /// streams it **once**: each row is loaded and, while it is hot in
    /// cache/registers, dotted against **all** `nq` queries before moving on. That
    /// amortizes the corpus read by `~nq×` — the CPU analogue of turning `nq`
    /// matrix–vector products into one matrix–matrix product (GEMM). It is **not**
    /// an approximation: every row is scored against every query with the exact
    /// f32 cosine, so `out[i]` is **byte-identical** to `search(query_i, k)` (same
    /// kernel, same deterministic top-`k` tie-break). The win only materializes
    /// when you genuinely have many queries in hand — bulk re-ranking, or a
    /// self-similarity sweep. For a single query use [`Self::search_auto`].
    ///
    /// # Panics
    /// If `queries.len()` is not a multiple of `dim`.
    pub fn search_batch(&self, queries: &[f32], k: usize) -> Vec<Vec<(u64, f32)>> {
        assert_eq!(
            queries.len() % self.dim,
            0,
            "queries len {} is not a multiple of dim {}",
            queries.len(),
            self.dim
        );
        let nq = queries.len() / self.dim;
        if nq == 0 {
            return Vec::new();
        }
        let n = self.ids.len();
        let m = k.min(n);
        if m == 0 {
            return vec![Vec::new(); nq];
        }

        // Normalize every query once into a flat nq×dim buffer (read-only + `Sync`,
        // so every fork-join worker shares it).
        let mut qns: Vec<f32> = Vec::with_capacity(nq * self.dim);
        for qi in 0..nq {
            let q = &queries[qi * self.dim..(qi + 1) * self.dim];
            assert_eq!(q.len(), self.dim);
            push_normalized(&mut qns, q);
        }
        let kernel = select_dot_kernel();

        // Fork-join over disjoint row ranges exactly like `search`. Each worker
        // scans its range ONCE, keeping a per-query local top-`m`; per-row dots are
        // independent so any split reproduces the single-thread result. Returns,
        // per range, an `nq`-long vec of local top-`m` lists.
        let threads = thread_count(n);
        let per_range: Vec<Vec<Vec<(u64, f32)>>> = if threads <= 1 {
            vec![self.score_range_batch(0, n, &qns, nq, kernel, m)]
        } else {
            let chunk = n.div_ceil(threads);
            let nranges = n.div_ceil(chunk);
            crate::gatling_forkjoin::gatling_for_each(nranges, threads, |r| {
                let start = r * chunk;
                let end = (start + chunk).min(n);
                self.score_range_batch(start, end, &qns, nq, kernel, m)
            })
            .into_iter()
            .collect()
        };

        // Merge each query's per-range local top-`m` into its global top-`m`.
        (0..nq)
            .map(|qi| {
                let mut merged: Vec<(u64, f32)> = Vec::new();
                for range in &per_range {
                    merged.extend_from_slice(&range[qi]);
                }
                top_k(&mut merged, m);
                merged
            })
            .collect()
    }

    /// Score rows `[start, end)` against ALL `nq` normalized queries in `qns`
    /// (row-major `nq × dim`), returning this range's per-query local top-`m`. The
    /// row is the OUTER loop so it is loaded once and reused across every query —
    /// the corpus-read amortization that makes [`Self::search_batch`] worth it.
    fn score_range_batch(
        &self,
        start: usize,
        end: usize,
        qns: &[f32],
        nq: usize,
        kernel: DotFn,
        m: usize,
    ) -> Vec<Vec<(u64, f32)>> {
        let mut per_q: Vec<Vec<(u64, f32)>> = vec![Vec::with_capacity(end - start); nq];
        for idx in start..end {
            let row = &self.data[idx * self.dim..(idx + 1) * self.dim];
            let id = self.ids[idx];
            for qi in 0..nq {
                let qn = &qns[qi * self.dim..(qi + 1) * self.dim];
                // SAFETY: `kernel` matches a runtime-confirmed CPU feature (or the
                // sound scalar fallback); `qn` and `row` are both `self.dim` long.
                let score = unsafe { kernel(qn, row) };
                per_q[qi].push((id, score));
            }
        }
        // Reduce each query's range candidates to its local top-`m` — mirrors
        // `score_range` so the merged result is identical to per-query `search`.
        for v in per_q.iter_mut() {
            top_k(v, m.min(v.len()));
        }
        per_q
    }

    /// Score rows `[start, end)` against the normalized query `qn`, returning
    /// this range's local top-`m` (already sorted, descending).
    fn score_range(
        &self,
        start: usize,
        end: usize,
        qn: &[f32],
        kernel: DotFn,
        m: usize,
    ) -> Vec<(u64, f32)> {
        let mut local: Vec<(u64, f32)> = Vec::with_capacity(end - start);
        for idx in start..end {
            let row = &self.data[idx * self.dim..(idx + 1) * self.dim];
            // SAFETY: `kernel` was chosen by `select_dot_kernel` to match a
            // CPU feature confirmed present at runtime (or the scalar
            // fallback, which is always sound). `qn` and `row` are both
            // `self.dim` long.
            let score = unsafe { kernel(qn, row) };
            local.push((self.ids[idx], score));
        }
        top_k(&mut local, m);
        local
    }

    /// Serialize the index to `path` (a small dependency-free binary format:
    /// magic, dim, count, ids, then the normalized f32 matrix).
    pub fn write(&self, path: impl AsRef<Path>) -> Result<()> {
        let path = path.as_ref();
        let n = self.ids.len();
        let mut buf = Vec::with_capacity(16 + n * 8 + self.data.len() * 4);
        buf.extend_from_slice(MAGIC);
        buf.extend_from_slice(&(self.dim as u32).to_le_bytes());
        buf.extend_from_slice(&(n as u64).to_le_bytes());
        for &id in &self.ids {
            buf.extend_from_slice(&id.to_le_bytes());
        }
        for &f in &self.data {
            buf.extend_from_slice(&f.to_le_bytes());
        }
        std::fs::write(path, &buf).with_context(|| format!("write vector index {}", path.display()))
    }

    /// Load an index previously written by [`Self::write`].
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let buf =
            std::fs::read(path).with_context(|| format!("read vector index {}", path.display()))?;
        ensure!(buf.len() >= 16, "vector index too short");
        ensure!(&buf[0..4] == MAGIC, "bad vector index magic");
        let dim = u32::from_le_bytes(buf[4..8].try_into().unwrap()) as usize;
        let n = u64::from_le_bytes(buf[8..16].try_into().unwrap()) as usize;
        ensure!(dim != 0, "vector index has zero dim");
        let want = 16 + n * 8 + n * dim * 4;
        if buf.len() != want {
            bail!(
                "vector index length {} != expected {want} (dim {dim}, n {n})",
                buf.len()
            );
        }
        let mut off = 16;
        let mut ids = Vec::with_capacity(n);
        let mut pos = HashMap::with_capacity(n);
        for row_idx in 0..n {
            let id = u64::from_le_bytes(buf[off..off + 8].try_into().unwrap());
            off += 8;
            ensure!(
                pos.insert(id, row_idx).is_none(),
                "duplicate id {id} in file"
            );
            ids.push(id);
        }
        let mut data = Vec::with_capacity(n * dim);
        for _ in 0..n * dim {
            data.push(f32::from_le_bytes(buf[off..off + 4].try_into().unwrap()));
            off += 4;
        }
        Ok(Self {
            dim,
            ids,
            data,
            pos,
            i8_cache: OnceLock::new(),
        })
    }
}

/// Name of the SIMD kernel the running CPU will use — `"avx512f"`,
/// `"avx2+fma"`, or `"scalar"`. Diagnostics / tests only.
pub fn active_simd() -> &'static str {
    #[cfg(target_arch = "x86_64")]
    {
        if std::is_x86_feature_detected!("avx512f") {
            return "avx512f";
        }
        if std::is_x86_feature_detected!("avx2") && std::is_x86_feature_detected!("fma") {
            return "avx2+fma";
        }
    }
    "scalar"
}

// ----- dot-product kernels ---------------------------------------------------

/// A dot-product kernel. `unsafe` because the SIMD variants require their
/// target feature to be present; callers must only select a variant via
/// [`select_dot_kernel`]. Both slices must be the same length. `pub(crate)` so
/// the vendored [`hnsw`] index reuses the exact same runtime-detected cosine.
pub(crate) type DotFn = unsafe fn(&[f32], &[f32]) -> f32;

pub(crate) fn select_dot_kernel() -> DotFn {
    #[cfg(target_arch = "x86_64")]
    {
        if std::is_x86_feature_detected!("avx512f") {
            return dot_avx512;
        }
        if std::is_x86_feature_detected!("avx2") && std::is_x86_feature_detected!("fma") {
            return dot_avx2;
        }
    }
    dot_scalar
}

/// Portable scalar fallback. `unsafe` only to share [`DotFn`]; always sound.
unsafe fn dot_scalar(a: &[f32], b: &[f32]) -> f32 {
    a.iter().zip(b).map(|(x, y)| x * y).sum()
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx512f")]
unsafe fn dot_avx512(a: &[f32], b: &[f32]) -> f32 {
    unsafe {
        use std::arch::x86_64::*;
        let n = a.len();
        let mut acc = _mm512_setzero_ps();
        let mut i = 0;
        while i + 16 <= n {
            let va = _mm512_loadu_ps(a.as_ptr().add(i));
            let vb = _mm512_loadu_ps(b.as_ptr().add(i));
            acc = _mm512_fmadd_ps(va, vb, acc);
            i += 16;
        }
        let mut s = _mm512_reduce_add_ps(acc);
        while i < n {
            s += a[i] * b[i];
            i += 1;
        }
        s
    }
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2,fma")]
unsafe fn dot_avx2(a: &[f32], b: &[f32]) -> f32 {
    unsafe {
        use std::arch::x86_64::*;
        let n = a.len();
        let mut acc = _mm256_setzero_ps();
        let mut i = 0;
        while i + 8 <= n {
            let va = _mm256_loadu_ps(a.as_ptr().add(i));
            let vb = _mm256_loadu_ps(b.as_ptr().add(i));
            acc = _mm256_fmadd_ps(va, vb, acc);
            i += 8;
        }
        // Horizontal sum of the 8 lanes.
        let mut tmp = [0f32; 8];
        _mm256_storeu_ps(tmp.as_mut_ptr(), acc);
        let mut s = tmp.iter().sum::<f32>();
        while i < n {
            s += a[i] * b[i];
            i += 1;
        }
        s
    }
}

// ----- int8 quantized dot (G2: AVX-512 VNNI) ---------------------------------
//
// The stored vectors are already L2-normalized, so every component lies in
// `[-1, 1]`. We quantize to `i8` by scaling by `Q = 127` and rounding; the dot
// of two quantized vectors, divided by `Q*Q`, recovers the cosine to ~1e-2.
// That halves-then-quarters the memory traffic (4 B f32 → 1 B i8) — the scoring
// loop is memory-bound on a big corpus, so less bytes/row ≈ proportionally
// faster — and lets a single AVX-512 VNNI `vpdpbusd` fold 64 lanes of
// multiply-accumulate into int32 per instruction (vs 16 f32 FMA lanes).
//
// VNNI's `vpdpbusd` is **unsigned × signed**. We keep the row signed (`i8`) and
// bias the query into unsigned: with `qu = q + 128 ∈ [0,255]`,
//   Σ q·r = Σ (qu-128)·r = Σ qu·r − 128·Σ r.
// `Σ qu·r` is the `vpdpbusd` accumulation; `Σ r` (the row's int sum) is
// precomputed once at quantization time, so the correction is a single scalar
// fixup per row.

/// `Q` — the int8 quantization scale (max |component| of a unit vector is 1).
const Q: f32 = 127.0;

/// A **sound upper bound** on `|int8_cosine − f32_cosine|` for two L2-normalized
/// `dim`-vectors, each quantized to i8 by `round(x·Q)`. Each component is off by
/// at most `δ = 1/Q` (a deliberately generous `1/Q` rather than the exact
/// `0.5/Q`, to absorb f32 accumulation while keeping the bound an *over*-estimate),
/// and the dot-product error is `≤ 2·δ·√dim + dim·δ²`. Over-estimating only
/// widens the exact-rerank candidate band ([`VectorIndex::search_i8_rerank`]), so
/// the bound stays safe: it can never drop a true nearest neighbour.
pub fn i8_score_error_bound(dim: usize) -> f32 {
    let delta = 1.0 / Q;
    2.0 * delta * (dim as f32).sqrt() + (dim as f32) * delta * delta
}

/// Quantize a (normalized) f32 vector to `i8`, returning the components' integer
/// sum `Σ r` (needed for the VNNI unsigned-bias correction). Round-to-nearest,
/// clamped to `[-127, 127]` so the `+128` query bias never overflows `u8`.
pub fn quantize_i8(v: &[f32], out: &mut Vec<i8>) -> i32 {
    let mut sum = 0i32;
    for &x in v {
        let q = (x * Q).round().clamp(-127.0, 127.0) as i32;
        sum += q;
        out.push(q as i8);
    }
    sum
}

/// Scalar int8 dot, returned as the **f32 cosine** (divided back by `Q*Q`).
/// Always sound; the reference the SIMD int8 path is checked against.
fn dot_i8_scalar(q: &[i8], r: &[i8]) -> f32 {
    let mut acc = 0i32;
    for (a, b) in q.iter().zip(r) {
        acc += (*a as i32) * (*b as i32);
    }
    acc as f32 / (Q * Q)
}

/// AVX-512 VNNI int8 dot via `vpdpbusd`. `q_biased` is the query pre-biased to
/// `u8` (`q + 128`); `row_sum` is `Σ row` (the i8 components). Returns the f32
/// cosine. 64 int8 MACs per instruction.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx512f,avx512vnni,avx512bw")]
unsafe fn dot_i8_vnni(q_biased: &[u8], row: &[i8], row_sum: i32) -> f32 {
    unsafe {
        use std::arch::x86_64::*;
        let n = row.len();
        // EIGHT independent accumulators. `vpdpbusd` has ~5-cycle latency; on server
        // silicon (Cascade Lake / Sapphire Rapids / Emerald Rapids) it dual-issues on
        // two ports at ~0.5-cycle reciprocal throughput, so hiding the latency AND
        // feeding both ports needs latency ÷ recip-throughput = 5 / 0.5 ≈ 10 in-flight
        // MACs (Little's law). FOUR accumulators saturate a single-port *client*
        // (~80%) but only ~40% of a dual-port server; EIGHT gets both ports near-full
        // and still leaves 24 of 32 zmm registers for operands. (uops.info VPDPBUSD.)
        // Integer addition is associative, so folding the eight partials at the end
        // yields the *identical* int32 dot the 4-accumulator version produced → the
        // returned f32 cosine is BIT-EXACT (the total is the same set of i8 products,
        // regrouped; no floating-point sum is reordered).
        let mut acc0 = _mm512_setzero_si512();
        let mut acc1 = _mm512_setzero_si512();
        let mut acc2 = _mm512_setzero_si512();
        let mut acc3 = _mm512_setzero_si512();
        let mut acc4 = _mm512_setzero_si512();
        let mut acc5 = _mm512_setzero_si512();
        let mut acc6 = _mm512_setzero_si512();
        let mut acc7 = _mm512_setzero_si512();
        macro_rules! mac {
            ($acc:ident, $off:expr) => {{
                let vu = _mm512_loadu_si512(q_biased.as_ptr().add($off) as *const _);
                let vi = _mm512_loadu_si512(row.as_ptr().add($off) as *const _);
                $acc = _mm512_dpbusd_epi32($acc, vu, vi);
            }};
        }
        let mut i = 0;
        // Main body: eight independent 64-byte lanes per iteration (512 B).
        while i + 512 <= n {
            mac!(acc0, i);
            mac!(acc1, i + 64);
            mac!(acc2, i + 128);
            mac!(acc3, i + 192);
            mac!(acc4, i + 256);
            mac!(acc5, i + 320);
            mac!(acc6, i + 384);
            mac!(acc7, i + 448);
            i += 512;
        }
        // Remaining whole 64-byte blocks (< 8 of them): a fixed ladder that lands each
        // in a DISTINCT accumulator, so the tail stays fully parallel too — no serial
        // dependent chain (at dim 768 the main loop runs once, then 4 of these fire).
        if i + 64 <= n {
            mac!(acc0, i);
            i += 64;
        }
        if i + 64 <= n {
            mac!(acc1, i);
            i += 64;
        }
        if i + 64 <= n {
            mac!(acc2, i);
            i += 64;
        }
        if i + 64 <= n {
            mac!(acc3, i);
            i += 64;
        }
        if i + 64 <= n {
            mac!(acc4, i);
            i += 64;
        }
        if i + 64 <= n {
            mac!(acc5, i);
            i += 64;
        }
        if i + 64 <= n {
            mac!(acc6, i);
            i += 64;
        }
        // Merge the eight partials (associative int add → identical total to 4 chains).
        let acc = _mm512_add_epi32(
            _mm512_add_epi32(_mm512_add_epi32(acc0, acc1), _mm512_add_epi32(acc2, acc3)),
            _mm512_add_epi32(_mm512_add_epi32(acc4, acc5), _mm512_add_epi32(acc6, acc7)),
        );
        let mut biased = _mm512_reduce_add_epi32(acc);
        while i < n {
            biased += (q_biased[i] as i32) * (row[i] as i32);
            i += 1;
        }
        // Undo the +128 query bias: Σ q·r = Σ qu·r − 128·Σ r.
        ((biased - 128 * row_sum) as f32) / (Q * Q)
    }
}

/// True if the running CPU can run the int8 VNNI kernel.
pub fn vnni_available() -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        return std::is_x86_feature_detected!("avx512f")
            && std::is_x86_feature_detected!("avx512vnni")
            && std::is_x86_feature_detected!("avx512bw");
    }
    #[allow(unreachable_code)]
    false
}

/// Score `query` against `rows` (a row-major `n × dim` **i8**-quantized matrix)
/// using the best int8 kernel the CPU supports (VNNI → scalar), returning each
/// row's cosine. `row_sums[i] = Σ rows[i]` (from [`quantize_i8`]). The query is
/// quantized + biased once and reused across all rows — batching the per-query
/// setup. Cache-blocking falls out naturally: rows are contiguous i8, four times
/// denser than f32, so a cache line covers 4× the components.
pub fn score_i8_batch(query: &[f32], rows: &[i8], dim: usize, row_sums: &[i32]) -> Vec<f32> {
    let n = row_sums.len();
    debug_assert_eq!(rows.len(), n * dim);
    // Quantize the query once; pre-bias to u8 for VNNI. Reused across every row
    // and every worker (`q_i8` / `q_biased` are read-only, so `Sync`).
    let mut q_i8 = Vec::with_capacity(dim);
    let qn = normalized(query);
    quantize_i8(&qn, &mut q_i8);
    let q_biased: Option<Vec<u8>> = if vnni_available() {
        Some(q_i8.iter().map(|&x| (x as i16 + 128) as u8).collect())
    } else {
        None
    };

    // Fork-join the scan across cores exactly like the pure-f32 `search` path
    // (see `VectorIndex::score_range`): each worker owns a contiguous, disjoint
    // row range. Per-row int32 dots are independent, so ANY row split yields
    // byte-identical scores — `gatling_for_each` returns the per-range partials
    // in range order, and flattening reassembles the same `Vec<f32>` a single
    // thread would. Below `2 * MIN_ROWS_PER_THREAD` we stay single-threaded
    // (spawning is pure overhead for tiny corpora) — the same threshold `search`
    // uses via `thread_count`.
    let threads = thread_count(n);
    if threads <= 1 {
        return score_i8_range(&q_i8, q_biased.as_deref(), rows, dim, row_sums, 0, n);
    }
    let chunk = n.div_ceil(threads);
    let nranges = n.div_ceil(chunk);
    crate::gatling_forkjoin::gatling_for_each(nranges, threads, |r| {
        let start = r * chunk;
        let end = (start + chunk).min(n);
        score_i8_range(&q_i8, q_biased.as_deref(), rows, dim, row_sums, start, end)
    })
    .into_iter()
    .flatten()
    .collect()
}

/// Score rows `[start, end)` of the i8 matrix against the (already quantized)
/// query, appending each row's f32 cosine in order. `q_biased` is `Some` iff the
/// VNNI kernel is to be used (query pre-biased to u8); `None` selects the scalar
/// int8 kernel. Kept range-parameterized so [`score_i8_batch`] can hand each
/// fork-join worker a disjoint slice of rows — the per-row dot is independent, so
/// the concatenation of the ranges is identical to a single-threaded scan.
fn score_i8_range(
    q_i8: &[i8],
    q_biased: Option<&[u8]>,
    rows: &[i8],
    dim: usize,
    row_sums: &[i32],
    start: usize,
    end: usize,
) -> Vec<f32> {
    let mut out = Vec::with_capacity(end - start);
    match q_biased {
        Some(qb) => {
            // `dot_i8_vnni` is `#[cfg(target_arch = "x86_64")]`, and `q_biased` is
            // `Some` only when `vnni_available()` returned true — which is likewise
            // x86_64-only. On every other target (e.g. wasm32) `q_biased` is always
            // `None`, so this arm is dead; cfg-gate it out so the call to the
            // non-existent VNNI kernel doesn't fail to compile off x86_64.
            #[cfg(target_arch = "x86_64")]
            for i in start..end {
                let row = &rows[i * dim..(i + 1) * dim];
                // SAFETY: `q_biased` is `Some` only when `vnni_available()` in
                // `score_i8_batch` confirmed the VNNI target features are present.
                out.push(unsafe { dot_i8_vnni(qb, row, row_sums[i]) });
            }
            #[cfg(not(target_arch = "x86_64"))]
            {
                let _ = qb;
                unreachable!("VNNI kernel is x86_64-only; q_biased is never Some on other targets");
            }
        }
        None => {
            for i in start..end {
                let row = &rows[i * dim..(i + 1) * dim];
                out.push(dot_i8_scalar(q_i8, row));
            }
        }
    }
    out
}

// ----- bench (G2) ------------------------------------------------------------

/// One kernel's timing in a [`bench_kernels`] run.
#[derive(Debug, Clone)]
pub struct KernelTiming {
    /// Kernel name: `"scalar"`, `"simd (avx512f|avx2+fma)"`, `"int8 (vnni|scalar)"`.
    pub name: String,
    /// Wall time to score the whole corpus once, in microseconds.
    pub micros: u128,
    /// Millions of dot-products per second.
    pub mdps: f64,
    /// Max absolute cosine error vs the scalar f32 reference (0 for scalar).
    pub max_err: f32,
}

/// Result of a [`bench_kernels`] sweep over an `n × dim` synthetic corpus.
#[derive(Debug, Clone)]
pub struct BenchReport {
    pub n: usize,
    pub dim: usize,
    pub simd_kernel: &'static str,
    pub timings: Vec<KernelTiming>,
}

impl BenchReport {
    /// Speedup of the SIMD f32 kernel over the scalar baseline.
    pub fn simd_speedup(&self) -> f64 {
        let s = self.timings.iter().find(|t| t.name == "scalar");
        let v = self.timings.iter().find(|t| t.name.starts_with("simd"));
        match (s, v) {
            (Some(s), Some(v)) if v.micros > 0 => s.micros as f64 / v.micros as f64,
            _ => 1.0,
        }
    }
    /// Speedup of the int8 kernel over the scalar baseline.
    pub fn int8_speedup(&self) -> f64 {
        let s = self.timings.iter().find(|t| t.name == "scalar");
        let q = self.timings.iter().find(|t| t.name.starts_with("int8"));
        match (s, q) {
            (Some(s), Some(q)) if q.micros > 0 => s.micros as f64 / q.micros as f64,
            _ => 1.0,
        }
    }
}

/// Benchmark the CPU cosine kernels (G2) on a deterministic synthetic corpus of
/// `n` `dim`-dim vectors: scalar f32, the runtime-selected SIMD f32 kernel, and
/// the int8 (VNNI/scalar) kernel. Every kernel scores the *same* single query
/// against *all* rows; the int8 errors are measured against the scalar f32
/// reference so the bench doubles as a correctness check. `iters` averages out
/// noise. Pure-Rust, no external bench dep — drives `nornir vector bench`.
pub fn bench_kernels(n: usize, dim: usize, iters: usize) -> BenchReport {
    use std::time::Instant;
    let iters = iters.max(1);

    // Deterministic corpus + query, normalized like real stored vectors.
    let mk = |seed: f32| -> Vec<f32> {
        let v: Vec<f32> = (0..dim).map(|i| ((i as f32 + 1.0) * seed).sin()).collect();
        normalized(&v)
    };
    let mut data = Vec::with_capacity(n * dim);
    for r in 0..n {
        data.extend(mk(0.001 + r as f32 * 0.0003));
    }
    let query = mk(0.737);
    let qn = normalized(&query);

    // Scalar reference scores (also the correctness oracle).
    let mut reference = vec![0f32; n];
    for (r, slot) in reference.iter_mut().enumerate() {
        let row = &data[r * dim..(r + 1) * dim];
        // SAFETY: dot_scalar is always sound.
        *slot = unsafe { dot_scalar(&qn, row) };
    }

    let dps = |micros: u128| -> f64 {
        if micros == 0 {
            0.0
        } else {
            (n as f64) / (micros as f64)
        }
    };

    let mut timings = Vec::new();

    // 1. Scalar.
    let t = Instant::now();
    for _ in 0..iters {
        for r in 0..n {
            let row = &data[r * dim..(r + 1) * dim];
            std::hint::black_box(unsafe { dot_scalar(&qn, row) });
        }
    }
    let micros = t.elapsed().as_micros() / iters as u128;
    timings.push(KernelTiming {
        name: "scalar".into(),
        micros,
        mdps: dps(micros),
        max_err: 0.0,
    });

    // 2. SIMD f32 (runtime-selected).
    let kernel = select_dot_kernel();
    let simd_kernel = active_simd();
    let t = Instant::now();
    let mut simd_err = 0f32;
    for it in 0..iters {
        for r in 0..n {
            let row = &data[r * dim..(r + 1) * dim];
            // SAFETY: kernel matches a confirmed CPU feature (or scalar).
            let s = unsafe { kernel(&qn, row) };
            std::hint::black_box(s);
            if it == 0 {
                simd_err = simd_err.max((s - reference[r]).abs());
            }
        }
    }
    let micros = t.elapsed().as_micros() / iters as u128;
    timings.push(KernelTiming {
        name: format!("simd ({simd_kernel})"),
        micros,
        mdps: dps(micros),
        max_err: simd_err,
    });

    // 3. int8 (VNNI / scalar). Quantize once, score per iter.
    let mut rows = Vec::with_capacity(n * dim);
    let mut sums = Vec::with_capacity(n);
    for r in 0..n {
        sums.push(quantize_i8(&data[r * dim..(r + 1) * dim], &mut rows));
    }
    let i8_kernel = if vnni_available() { "vnni" } else { "scalar" };
    let t = Instant::now();
    let mut i8_scores = Vec::new();
    for _ in 0..iters {
        i8_scores = score_i8_batch(&query, &rows, dim, &sums);
        std::hint::black_box(&i8_scores);
    }
    let micros = t.elapsed().as_micros() / iters as u128;
    let i8_err = i8_scores
        .iter()
        .zip(&reference)
        .map(|(a, b)| (a - b).abs())
        .fold(0f32, f32::max);
    timings.push(KernelTiming {
        name: format!("int8 ({i8_kernel})"),
        micros,
        mdps: dps(micros),
        max_err: i8_err,
    });

    BenchReport {
        n,
        dim,
        simd_kernel,
        timings,
    }
}

// ----- helpers ---------------------------------------------------------------

/// Number of worker threads to use for scoring `n` rows. 1 for small corpora.
fn thread_count(n: usize) -> usize {
    if n < 2 * MIN_ROWS_PER_THREAD {
        return 1;
    }
    let hw = std::thread::available_parallelism()
        .map(|x| x.get())
        .unwrap_or(1);
    hw.min(n / MIN_ROWS_PER_THREAD).max(1)
}

/// L2-normalize `v` into a fresh `Vec`. A zero vector is returned unchanged.
pub fn normalized(v: &[f32]) -> Vec<f32> {
    let norm = v.iter().map(|x| x * x).sum::<f32>().sqrt();
    if norm > 0.0 {
        v.iter().map(|x| x / norm).collect()
    } else {
        v.to_vec()
    }
}

/// Append `row`, L2-normalized, to `data`.
fn push_normalized(data: &mut Vec<f32>, row: &[f32]) {
    let norm = row.iter().map(|x| x * x).sum::<f32>().sqrt();
    if norm > 0.0 {
        data.extend(row.iter().map(|x| x / norm));
    } else {
        data.extend_from_slice(row);
    }
}

/// Reduce `v` to its top-`m` by descending score, sorted. Ties (equal scores)
/// break by **ascending id**, so the order is a strict total order over the
/// unique ids — fully deterministic, and crucially *independent of the input
/// set*. That independence is what lets the int8 prefilter + exact rerank
/// ([`VectorIndex::search_i8_rerank`]) return a top-`k` byte-identical to the
/// full-corpus [`VectorIndex::search`]: whichever equally-scored rows sit on the
/// `k`-th boundary, both paths pick the same ones. `f32::total_cmp` keeps the
/// score order well-defined even for NaN.
pub fn top_k(v: &mut Vec<(u64, f32)>, m: usize) {
    let cmp = |a: &(u64, f32), b: &(u64, f32)| b.1.total_cmp(&a.1).then(a.0.cmp(&b.0));
    if v.len() > m {
        v.select_nth_unstable_by(m - 1, cmp);
        v.truncate(m);
    }
    v.sort_unstable_by(cmp);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unit(dim: usize, axis: usize) -> Vec<f32> {
        let mut v = vec![0.0f32; dim];
        v[axis] = 1.0;
        v
    }

    #[test]
    fn rejects_zero_dim() {
        match VectorIndex::new(0) {
            Ok(_) => panic!("dim 0 should be rejected"),
            Err(e) => assert!(e.to_string().contains("non-zero"), "{e}"),
        }
    }

    #[test]
    fn add_and_search_nearest() {
        let mut idx = VectorIndex::new(8).unwrap();
        idx.add(&unit(8, 0), &[10]).unwrap();
        idx.add(&unit(8, 1), &[20]).unwrap();
        idx.add(&unit(8, 2), &[30]).unwrap();
        assert_eq!(idx.len(), 3);
        assert!(!idx.is_empty());

        let mut q = unit(8, 0);
        q[1] = 0.1; // mostly axis-0
        let hits = idx.search(&q, 2);
        assert_eq!(hits.len(), 2);
        assert_eq!(hits[0].0, 10, "nearest is the axis-0 vector");
        assert_eq!(hits[1].0, 20, "runner-up is the axis-1 vector");
        assert!(hits[0].1 > hits[1].1, "scores sorted descending");
    }

    #[test]
    fn add_rejects_wrong_buffer_len() {
        let mut idx = VectorIndex::new(8).unwrap();
        let err = idx.add(&[1.0, 2.0, 3.0, 4.0], &[1]).unwrap_err();
        assert!(err.to_string().contains("!= ids len"), "{err}");
    }

    #[test]
    fn add_rejects_duplicate_id() {
        let mut idx = VectorIndex::new(8).unwrap();
        idx.add(&unit(8, 0), &[7]).unwrap();
        let err = idx.add(&unit(8, 1), &[7]).unwrap_err();
        assert!(err.to_string().contains("duplicate id 7"), "{err}");
        // and a duplicate within the same call
        let mut two = unit(8, 0);
        two.extend(unit(8, 1));
        let err = idx.add(&two, &[9, 9]).unwrap_err();
        assert!(err.to_string().contains("duplicate id 9"), "{err}");
    }

    #[test]
    fn remove_and_contains() {
        let mut idx = VectorIndex::new(8).unwrap();
        idx.add(&unit(8, 0), &[10]).unwrap();
        idx.add(&unit(8, 1), &[20]).unwrap();
        idx.add(&unit(8, 2), &[30]).unwrap();
        assert!(idx.contains(20));
        assert!(idx.remove(20));
        assert!(!idx.contains(20));
        assert!(!idx.remove(20), "second remove is a no-op");
        assert_eq!(idx.len(), 2);
        // Surviving ids still searchable and correctly mapped.
        let hits = idx.search(&unit(8, 2), 1);
        assert_eq!(hits[0].0, 30);
    }

    #[test]
    fn write_then_load_roundtrips() {
        let mut idx = VectorIndex::new(8).unwrap();
        idx.add(&unit(8, 0), &[10]).unwrap();
        idx.add(&unit(8, 1), &[20]).unwrap();
        idx.add(&unit(8, 2), &[30]).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("basis.nvf");
        idx.write(&path).unwrap();

        let loaded = VectorIndex::load(&path).unwrap();
        assert_eq!(loaded.len(), 3);
        assert_eq!(loaded.dim(), 8);
        let hits = loaded.search(&unit(8, 2), 1);
        assert_eq!(hits[0].0, 30, "nearest to axis-2 query is id 30");
    }

    #[test]
    fn load_rejects_corrupt_header() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad.nvf");
        std::fs::write(&path, b"NOPExxxxxxxxxxxx").unwrap();
        assert!(VectorIndex::load(&path).is_err());
    }

    /// Exercises the high-dim SIMD path (768 = jina dim) and confirms the
    /// active kernel agrees with an independent scalar reference.
    #[test]
    fn high_dim_search_matches_reference() {
        let dim = 768;
        let mut idx = VectorIndex::new(dim).unwrap();
        // Three distinct directions built deterministically.
        let mk = |seed: f32| -> Vec<f32> { (0..dim).map(|i| (i as f32 * seed).sin()).collect() };
        let a = mk(0.013);
        let b = mk(0.027);
        let c = mk(0.041);
        idx.add(&a, &[1]).unwrap();
        idx.add(&b, &[2]).unwrap();
        idx.add(&c, &[3]).unwrap();

        // Query == b's direction → b must win.
        let hits = idx.search(&b, 1);
        assert_eq!(hits[0].0, 2);
        // Self-cosine of a normalized vector is ~1.0.
        assert!((hits[0].1 - 1.0).abs() < 1e-3, "score {}", hits[0].1);
    }

    /// Triggers the multicore path (n well above the spawn threshold) and
    /// checks that a uniquely-aligned vector is still found exactly.
    #[test]
    fn parallel_path_finds_exact_match() {
        let dim = 32;
        let n = 4 * MIN_ROWS_PER_THREAD; // 4096 → multithreaded
        let mut idx = VectorIndex::new(dim).unwrap();
        let target_id = 1234u64;
        // Most vectors point along axis 1; the target points along axis 0.
        let mut flat = Vec::with_capacity(n * dim);
        let mut ids = Vec::with_capacity(n);
        for j in 0..n as u64 {
            let axis = if j == target_id { 0 } else { 1 };
            flat.extend(unit(dim, axis));
            ids.push(j);
        }
        idx.add(&flat, &ids).unwrap();
        assert!(
            thread_count(idx.len()) > 1,
            "test should hit the parallel path"
        );

        let hits = idx.search(&unit(dim, 0), 1);
        assert_eq!(hits[0].0, target_id, "the lone axis-0 vector wins");
    }

    #[test]
    fn active_simd_is_known() {
        let s = active_simd();
        assert!(
            matches!(s, "avx512f" | "avx2+fma" | "scalar"),
            "unexpected kernel {s}"
        );
    }

    // ----- G2: SIMD/int8 correctness + bench --------------------------------

    /// LAW (inject-assert): the runtime SIMD f32 kernel must produce the SAME
    /// dot product as the scalar reference, within f32 rounding tolerance, on
    /// real injected high-dim vectors — not merely "didn't crash".
    #[test]
    fn simd_kernel_matches_scalar_dot() {
        let dim = 768; // jina dim — exercises the AVX-512/AVX2 tail handling
        let a: Vec<f32> = (0..dim).map(|i| ((i as f32 + 1.0) * 0.013).sin()).collect();
        let b: Vec<f32> = (0..dim).map(|i| ((i as f32 + 1.0) * 0.027).cos()).collect();
        let an = normalized(&a);
        let bn = normalized(&b);
        let scalar = unsafe { dot_scalar(&an, &bn) };
        let kernel = select_dot_kernel();
        let simd = unsafe { kernel(&an, &bn) };
        assert!(
            (scalar - simd).abs() < 1e-5,
            "SIMD {} dot {simd} != scalar {scalar}",
            active_simd()
        );
    }

    /// LAW (inject-assert): the int8 (VNNI or scalar) cosine must match the
    /// scalar f32 cosine within the quantization tolerance, and rank the same
    /// nearest vector. Injects a corpus + a query and asserts both score
    /// agreement and ranking agreement against the f32 path.
    #[test]
    fn int8_matches_f32_within_tolerance() {
        let dim = 768;
        let n = 200;
        let mut idx = VectorIndex::new(dim).unwrap();
        let mk =
            |seed: f32| -> Vec<f32> { (0..dim).map(|i| ((i as f32 + 1.0) * seed).sin()).collect() };
        let mut flat = Vec::with_capacity(n * dim);
        let mut ids = Vec::with_capacity(n);
        for r in 0..n as u64 {
            flat.extend(mk(0.005 + r as f32 * 0.0007));
            ids.push(r);
        }
        idx.add(&flat, &ids).unwrap();

        let query = mk(0.005 + 42.0 * 0.0007); // == row 42's direction
        let f32_hits = idx.search(&query, 5);
        let i8_hits = idx.search_i8(&query, 5);

        // Same top-1 (row 42 wins under both kernels).
        assert_eq!(f32_hits[0].0, 42, "f32 top-1 should be the matching row");
        assert_eq!(i8_hits[0].0, f32_hits[0].0, "int8 top-1 disagrees with f32");

        // Scores agree within the quantization tolerance for the shared ids.
        use std::collections::HashMap;
        let f32_map: HashMap<u64, f32> = f32_hits.iter().copied().collect();
        for (id, s8) in &i8_hits {
            if let Some(s32) = f32_map.get(id) {
                // int8 quantization of 768 components accumulates ≲4e-2 of
                // absolute cosine error on high-similarity pairs; the ranking
                // (asserted above) is what matters, the score is approximate.
                assert!(
                    (s8 - s32).abs() < 4e-2,
                    "int8 cosine {s8} vs f32 {s32} for id {id} exceeds tolerance"
                );
            }
        }
    }

    /// LAW (inject-assert): the WIRED int8 path — int8 fast-scan + exact f32
    /// rerank ([`VectorIndex::search_i8_rerank`], what [`VectorIndex::search_auto`]
    /// dispatches to for large corpora) — must return results **identical** to
    /// the exact f32 [`VectorIndex::search`]: same ids in the same order, same
    /// scores bit-for-bit (rerank re-scores with the f32 kernel, so the returned
    /// scores are exact cosine, not int8-approx). This is the guard that quant
    /// can never silently change the live search results.
    #[test]
    fn i8_rerank_is_identical_to_exact_f32_search() {
        let dim = 768;
        let n = 500;
        let mut idx = VectorIndex::new(dim).unwrap();
        let mk =
            |seed: f32| -> Vec<f32> { (0..dim).map(|i| ((i as f32 + 1.0) * seed).sin()).collect() };
        let mut flat = Vec::with_capacity(n * dim);
        let mut ids = Vec::with_capacity(n);
        for r in 0..n as u64 {
            flat.extend(mk(0.003 + r as f32 * 0.00051));
            ids.push(r * 7 + 1); // non-trivial id mapping
        }
        idx.add(&flat, &ids).unwrap();

        // A handful of queries, including exact row directions and off-axis ones.
        for &qs in &[0.003 + 17.0 * 0.00051, 0.05, 0.731, 0.003 + 480.0 * 0.00051] {
            let query = mk(qs);
            for k in [1usize, 5, 20, 50] {
                let exact = idx.search(&query, k);
                let wired = idx.search_i8_rerank(&query, k);
                assert_eq!(exact.len(), wired.len(), "len mismatch k={k} qs={qs}");
                for (a, b) in exact.iter().zip(&wired) {
                    assert_eq!(a.0, b.0, "id rank mismatch k={k} qs={qs}: {a:?} vs {b:?}");
                    assert_eq!(
                        a.1.to_bits(),
                        b.1.to_bits(),
                        "score mismatch (rerank must return exact f32) k={k} qs={qs}"
                    );
                }
            }
        }
    }

    /// `search_auto` is a size selector only: below the threshold it IS
    /// `search`; at/above it it IS `search_i8_rerank`. Both branches must equal
    /// the exact f32 oracle. Exercises the real crossover at `I8_SCAN_THRESHOLD`.
    #[test]
    fn search_auto_selects_by_size_and_stays_exact() {
        let dim = 64;
        let mk =
            |seed: f32| -> Vec<f32> { (0..dim).map(|i| ((i as f32 + 1.0) * seed).sin()).collect() };

        // Small corpus (< threshold) → f32 path; result == search.
        let mut small = VectorIndex::new(dim).unwrap();
        {
            let n = 128u64;
            let mut flat = Vec::new();
            let mut ids = Vec::new();
            for r in 0..n {
                flat.extend(mk(0.01 + r as f32 * 0.002));
                ids.push(r);
            }
            small.add(&flat, &ids).unwrap();
        }
        assert!(small.len() < I8_SCAN_THRESHOLD);
        let q = mk(0.37);
        assert_eq!(small.search_auto(&q, 5), small.search(&q, 5));

        // Large corpus (>= threshold) → int8 rerank path; still == search.
        let mut big = VectorIndex::new(dim).unwrap();
        {
            let n = I8_SCAN_THRESHOLD as u64 + 37;
            let mut flat = Vec::with_capacity((n as usize) * dim);
            let mut ids = Vec::with_capacity(n as usize);
            for r in 0..n {
                flat.extend(mk(0.001 + r as f32 * 0.00013));
                ids.push(r);
            }
            big.add(&flat, &ids).unwrap();
        }
        assert!(big.len() >= I8_SCAN_THRESHOLD);
        let q = mk(0.912);
        assert_eq!(
            big.search_auto(&q, 10),
            big.search(&q, 10),
            "int8 rerank path must match the exact f32 oracle"
        );
    }

    /// LAW (inject-assert): batched multi-query search must be **byte-identical**
    /// to running `search` once per query. `search_batch` reads the corpus once,
    /// scoring each row against all queries (the amortization); that must not
    /// change any result vs the per-query oracle — same ids, same score bits.
    /// Uses a corpus above `2 * MIN_ROWS_PER_THREAD` so the fork-join batch path
    /// (and its per-range merge) is actually exercised.
    #[test]
    fn search_batch_is_identical_to_per_query_search() {
        let dim = 64;
        let n = 3 * MIN_ROWS_PER_THREAD; // 3072 → multicore batch path fires
        assert!(
            thread_count(n) > 1,
            "test must exercise the multicore batch scan"
        );

        let mk =
            |seed: f32| -> Vec<f32> { (0..dim).map(|i| ((i as f32 + 1.0) * seed).sin()).collect() };
        let mut idx = VectorIndex::new(dim).unwrap();
        let mut flat = Vec::with_capacity(n * dim);
        let mut ids = Vec::with_capacity(n);
        for r in 0..n as u64 {
            flat.extend(mk(0.002 + r as f32 * 0.00017));
            ids.push(r * 3 + 5); // non-trivial id mapping
        }
        idx.add(&flat, &ids).unwrap();

        // A batch of varied queries, incl. exact row directions and off-axis ones.
        let seeds = [
            0.002 + 42.0 * 0.00017,
            0.19,
            0.55,
            0.913,
            0.002 + 3000.0 * 0.00017,
        ];
        let mut batch = Vec::with_capacity(seeds.len() * dim);
        for &s in &seeds {
            batch.extend(mk(s));
        }
        for k in [1usize, 5, 20] {
            let batched = idx.search_batch(&batch, k);
            assert_eq!(batched.len(), seeds.len(), "one result list per query");
            for (qi, &s) in seeds.iter().enumerate() {
                let solo = idx.search(&mk(s), k);
                assert_eq!(batched[qi].len(), solo.len(), "len mismatch qi={qi} k={k}");
                for (a, b) in batched[qi].iter().zip(&solo) {
                    assert_eq!(a.0, b.0, "id rank mismatch qi={qi} k={k}: {a:?} vs {b:?}");
                    assert_eq!(
                        a.1.to_bits(),
                        b.1.to_bits(),
                        "score mismatch (batch must equal per-query exact) qi={qi} k={k}"
                    );
                }
            }
        }
    }

    /// LAW (inject-assert): the fork-join int8 scan must be **byte-identical** to
    /// a single-threaded reference scan. `score_i8_batch` splits the corpus into
    /// contiguous disjoint row ranges scored on separate cores; per-row int32 dots
    /// are independent, so the concatenated result must equal what one thread
    /// produces. Uses a corpus well above `2 * MIN_ROWS_PER_THREAD` so the real
    /// multithreaded path fires, and compares bit-for-bit against a serial
    /// reference built from the same quantized query + kernel dispatch.
    #[test]
    fn i8_parallel_scan_matches_serial_reference() {
        let dim = 96;
        let n = 8 * MIN_ROWS_PER_THREAD; // 8192 → well into the parallel path
        assert!(thread_count(n) > 1, "test must exercise the multicore scan");

        let mk =
            |seed: f32| -> Vec<f32> { (0..dim).map(|i| ((i as f32 + 1.0) * seed).sin()).collect() };
        let mut idx = VectorIndex::new(dim).unwrap();
        let mut flat = Vec::with_capacity(n * dim);
        let mut ids = Vec::with_capacity(n);
        for r in 0..n as u64 {
            flat.extend(mk(0.001 + r as f32 * 0.00021));
            ids.push(r);
        }
        idx.add(&flat, &ids).unwrap();
        let (rows, sums) = idx.quantized();

        for &qs in &[0.017f32, 0.42, 0.913] {
            let query = mk(qs);

            // Serial reference: replicate score_i8_batch's query setup, then score
            // the whole corpus as ONE range (no fork-join).
            let mut q_i8 = Vec::with_capacity(dim);
            let qn = normalized(&query);
            quantize_i8(&qn, &mut q_i8);
            let q_biased: Option<Vec<u8>> = if vnni_available() {
                Some(q_i8.iter().map(|&x| (x as i16 + 128) as u8).collect())
            } else {
                None
            };
            let reference = score_i8_range(&q_i8, q_biased.as_deref(), &rows, dim, &sums, 0, n);

            // Parallel path (score_i8_batch dispatches over gatling_for_each).
            let parallel = score_i8_batch(&query, &rows, dim, &sums);

            assert_eq!(parallel.len(), reference.len(), "length mismatch qs={qs}");
            for (r, (p, s)) in parallel.iter().zip(&reference).enumerate() {
                assert_eq!(
                    p.to_bits(),
                    s.to_bits(),
                    "parallel int8 scan diverges from serial at row {r} (qs={qs})"
                );
            }
        }
    }

    /// The memoized int8 matrix must be dropped on mutation, so a search after
    /// `add`/`remove` can never score against a stale quantization.
    #[test]
    fn i8_cache_invalidates_on_mutation() {
        let dim = 16;
        let mk =
            |seed: f32| -> Vec<f32> { (0..dim).map(|i| ((i as f32 + 1.0) * seed).sin()).collect() };
        let mut idx = VectorIndex::new(dim).unwrap();
        idx.add(&mk(0.1), &[1]).unwrap();
        // Prime the cache via a rerank search.
        let _ = idx.search_i8_rerank(&mk(0.1), 1);
        assert!(idx.i8_cache.get().is_some(), "cache primed");
        // Mutating must clear it.
        idx.add(&mk(0.9), &[2]).unwrap();
        assert!(idx.i8_cache.get().is_none(), "cache cleared on add");
        // A fresh search now sees BOTH rows (proves it re-quantized).
        let _ = idx.search_i8_rerank(&mk(0.9), 2);
        idx.remove(2);
        assert!(idx.i8_cache.get().is_none(), "cache cleared on remove");
    }

    /// LAW (inject-assert): the bench must run every kernel, return real timing
    /// numbers (not zero on a non-trivial corpus), and its int8 path must stay
    /// within tolerance — proving the bench is also a correctness gate. We
    /// assert a concrete bench number exists per the G2 requirement.
    #[test]
    fn bench_kernels_reports_real_numbers() {
        let rep = bench_kernels(2000, 768, 3);
        assert_eq!(rep.timings.len(), 3, "expected scalar+simd+int8 timings");
        assert!(rep.timings.iter().any(|t| t.name == "scalar"));
        assert!(rep.timings.iter().any(|t| t.name.starts_with("simd")));
        assert!(rep.timings.iter().any(|t| t.name.starts_with("int8")));
        // Real wall-clock numbers on a 2000×768 corpus.
        for t in &rep.timings {
            assert!(t.micros > 0, "kernel {} reported 0µs", t.name);
            assert!(t.mdps > 0.0, "kernel {} reported 0 Mdps", t.name);
        }
        // The SIMD/int8 paths agree with the scalar reference.
        let simd = rep
            .timings
            .iter()
            .find(|t| t.name.starts_with("simd"))
            .unwrap();
        assert!(simd.max_err < 1e-4, "simd error {} too high", simd.max_err);
        let i8 = rep
            .timings
            .iter()
            .find(|t| t.name.starts_with("int8"))
            .unwrap();
        assert!(i8.max_err < 4e-2, "int8 error {} too high", i8.max_err);
        // Speedups are computable (≥ ~1×; SIMD shouldn't be slower than scalar).
        assert!(
            rep.simd_speedup() > 0.5,
            "implausible simd speedup {}",
            rep.simd_speedup()
        );
    }
}
