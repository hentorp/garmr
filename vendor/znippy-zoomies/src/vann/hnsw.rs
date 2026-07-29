//! `hnsw` — a **vendored, dependency-free HNSW** (Hierarchical Navigable Small
//! World, Malkov & Yashunin 2016) approximate nearest-neighbour index, built to
//! sit behind the same [`super::VectorIndex`] seam as the exact brute-force flat
//! scan.
//!
//! ## Why vendored (and not `hnsw_rs` / `instant-distance`)
//! The nordisk ROOT LAW is **gatling-only** parallelism — `rayon` /
//! `thread::spawn` (incl. transitively in any dependency) are forbidden. The two
//! obvious embeddable Rust HNSW crates both break it:
//! - `hnsw_rs` (hnswlib-rs) parallelises inserts with `rayon`.
//! - `instant-distance` pulls `rayon` into its `Builder::build`.
//!
//! So this is a minimal HNSW written directly onto `std` (no new dep at all): the
//! crate that gains the code (`znippy-zoomies`) stays `cargo tree | grep rayon`
//! **empty**, and any parallelism we add later goes through this crate's own
//! [`crate::gatling_forkjoin`] pool, never rayon. The build here is
//! single-threaded (graph mutation is inherently serial); the win is on the
//! **query** side — O(log n) graph descent instead of the O(n) flat scan.
//!
//! ## Correctness contract
//! The flat [`super::VectorIndex`] remains the exact **oracle**: HNSW is
//! *approximate*, so its top-`k` is validated against the flat top-`k` by a
//! **recall floor** (see the tests + the `nornir.mimir.search.vec_hnsw_*`
//! benches). Vectors are L2-normalized (the flat index already stores them so),
//! and the graph metric is `dist = 1 − cosine`, so a returned score is the plain
//! cosine `1 − dist` — identical units to [`super::VectorIndex::search`].

use std::cmp::{Ordering, Reverse};
use std::collections::{BinaryHeap, HashSet};

use super::{DotFn, normalized, select_dot_kernel};

/// Tunables for an HNSW build + query. Defaults target **recall@10 ≥ ~0.95** on
/// code-embedding-shaped corpora while keeping the single-threaded build cheap
/// enough for a 100k×128 corpus in the LIGHT bench.
#[derive(Debug, Clone, Copy)]
pub struct HnswParams {
    /// Max neighbours per node on the upper layers (`M`). Layer 0 uses `2*M`.
    pub m: usize,
    /// Candidate list width during construction (`efConstruction`). Larger =
    /// better graph quality (recall) at higher build cost.
    pub ef_construction: usize,
    /// Candidate list width during search (`efSearch`); the query raises it to
    /// `max(ef_search, k)`. Larger = higher recall, slower query.
    pub ef_search: usize,
    /// Seed for the deterministic level-assignment RNG, so a build is
    /// reproducible (same graph → same benches/tests every run).
    pub seed: u64,
}

impl Default for HnswParams {
    fn default() -> Self {
        Self {
            m: 16,
            ef_construction: 128,
            ef_search: 64,
            seed: 0x5EED_1234_ABCD_0001,
        }
    }
}

/// A vendored HNSW index over L2-normalized `f32` vectors of a fixed
/// dimensionality, keyed by stable `u64` ids (parallel to the stored rows).
pub struct HnswIndex {
    dim: usize,
    /// External ids, parallel to the rows of [`Self::data`] (node index order).
    ids: Vec<u64>,
    /// Row-major, L2-normalized vectors: `ids.len() * dim` floats.
    data: Vec<f32>,
    /// `graph[node][layer]` = neighbour node indices of `node` at `layer`. A node
    /// present up to `node_level[node]` has `node_level[node] + 1` layers.
    graph: Vec<Vec<Vec<u32>>>,
    /// Top layer each node participates in.
    node_level: Vec<usize>,
    /// Entry point (the node with the current max level).
    entry: u32,
    /// Highest layer any node reaches.
    max_level: usize,
    m: usize,
    m_max0: usize,
    ef_search: usize,
}

impl HnswIndex {
    /// Build an HNSW over `ids.len()` vectors. `data` is the row-major
    /// **already-L2-normalized** matrix (`ids.len() * dim` floats), in `ids`
    /// order — exactly what [`super::VectorIndex`] stores, so the caller hands
    /// its stored matrix straight in. Single-threaded (graph mutation is serial).
    pub fn build(dim: usize, ids: Vec<u64>, data: Vec<f32>, params: HnswParams) -> Self {
        let n = ids.len();
        debug_assert_eq!(data.len(), n * dim, "data must be n*dim floats");
        let kernel = select_dot_kernel();
        let m = params.m.max(2);
        let m_max0 = m * 2;
        let m_l = 1.0 / (m as f64).ln();
        let mut rng = SplitMix64::new(params.seed);

        let mut idx = HnswIndex {
            dim,
            ids,
            data,
            graph: Vec::with_capacity(n),
            node_level: Vec::with_capacity(n),
            entry: 0,
            max_level: 0,
            m,
            m_max0,
            ef_search: params.ef_search.max(1),
        };

        for node in 0..n {
            let level = assign_level(&mut rng, m_l);
            idx.node_level.push(level);
            idx.graph.push((0..=level).map(|_| Vec::new()).collect());
            if node == 0 {
                idx.entry = 0;
                idx.max_level = level;
                continue;
            }
            idx.insert(node as u32, level, params.ef_construction, kernel);
        }
        idx
    }

    /// Number of stored vectors.
    pub fn len(&self) -> usize {
        self.ids.len()
    }
    /// True when empty.
    pub fn is_empty(&self) -> bool {
        self.ids.is_empty()
    }
    /// Dimensionality.
    pub fn dim(&self) -> usize {
        self.dim
    }

    /// Approximate top-`k` nearest ids to `query`, best-first, as `(id, score)`
    /// where `score` is cosine similarity in `[-1, 1]` (higher = closer) — the
    /// SAME units and ordering [`super::VectorIndex::search`] returns, so this is
    /// a drop-in for the exact scan (approximate: validated by the recall floor).
    ///
    /// # Panics
    /// If `query.len() != dim`.
    pub fn search(&self, query: &[f32], k: usize) -> Vec<(u64, f32)> {
        assert_eq!(
            query.len(),
            self.dim,
            "query dim {} != index dim {}",
            query.len(),
            self.dim
        );
        if self.ids.is_empty() || k == 0 {
            return Vec::new();
        }
        let kernel = select_dot_kernel();
        let qn = normalized(query);
        let ef = self.ef_search.max(k);

        // Greedy descent from the top layer with ef=1, then a wide ef search at
        // layer 0 (the standard HNSW K-NN-SEARCH).
        let mut ep = vec![self.entry];
        let mut lc = self.max_level;
        while lc > 0 {
            let w = self.search_layer(&qn, &ep, 1, lc, kernel);
            if let Some(&(_, best)) = w.first() {
                ep = vec![best];
            }
            lc -= 1;
        }
        let w = self.search_layer(&qn, &ep, ef, 0, kernel);
        w.into_iter()
            .take(k)
            .map(|(d, node)| (self.ids[node as usize], 1.0 - d))
            .collect()
    }

    // ----- internals ---------------------------------------------------------

    #[inline]
    fn row(&self, i: usize) -> &[f32] {
        &self.data[i * self.dim..(i + 1) * self.dim]
    }

    /// `dist = 1 − cosine` between the query-vector `target` and node `i`.
    #[inline]
    fn dist_to(&self, target: &[f32], i: u32, kernel: DotFn) -> f32 {
        // SAFETY: `kernel` was chosen by `select_dot_kernel` to match a CPU
        // feature confirmed present at runtime (or the always-sound scalar
        // fallback); `target` and the row are both `self.dim` long.
        1.0 - unsafe { kernel(target, self.row(i as usize)) }
    }

    /// `dist = 1 − cosine` between two stored nodes.
    #[inline]
    fn dist_nodes(&self, a: u32, b: u32, kernel: DotFn) -> f32 {
        // SAFETY: as `dist_to`; both rows are `self.dim` long.
        1.0 - unsafe { kernel(self.row(a as usize), self.row(b as usize)) }
    }

    /// Insert node `node` (already present in `data`/`graph` with empty edges) at
    /// `level`, wiring its bidirectional links per the HNSW INSERT algorithm.
    fn insert(&mut self, node: u32, level: usize, ef_c: usize, kernel: DotFn) {
        // The new node's own vector is the search target. Clone it so the later
        // `&mut self.graph` mutations don't alias the `&self.data` borrow.
        let target = self.row(node as usize).to_vec();

        let mut ep = vec![self.entry];
        // Descend the layers ABOVE `level` greedily (ef = 1) to reach a good ep.
        let mut lc = self.max_level;
        while lc > level {
            let w = self.search_layer(&target, &ep, 1, lc, kernel);
            if let Some(&(_, best)) = w.first() {
                ep = vec![best];
            }
            lc -= 1;
        }

        // From min(max_level, level) down to 0: find efC candidates, select
        // neighbours (heuristic), link both ways, prune over-full neighbours.
        let mut lc = level.min(self.max_level);
        loop {
            let w = self.search_layer(&target, &ep, ef_c, lc, kernel);
            let m_at = if lc == 0 { self.m_max0 } else { self.m };
            let selected = self.select_neighbors(&w, m_at, kernel);

            self.graph[node as usize][lc] = selected.clone();
            for &nb in &selected {
                self.graph[nb as usize][lc].push(node);
                let m_nb = if lc == 0 { self.m_max0 } else { self.m };
                if self.graph[nb as usize][lc].len() > m_nb {
                    // Re-select nb's connections down to m_nb (keeps degree bounded
                    // while preserving the best-navigable edges).
                    let conns: Vec<(f32, u32)> = self.graph[nb as usize][lc]
                        .iter()
                        .map(|&e| (self.dist_nodes(nb, e, kernel), e))
                        .collect();
                    let pruned = self.select_neighbors(&conns, m_nb, kernel);
                    self.graph[nb as usize][lc] = pruned;
                }
            }

            ep = w.iter().map(|&(_, n)| n).collect();
            if lc == 0 {
                break;
            }
            lc -= 1;
        }

        if level > self.max_level {
            self.max_level = level;
            self.entry = node;
        }
    }

    /// HNSW SEARCH-LAYER: from entry points `ep`, greedily explore `layer` keeping
    /// the `ef` closest to `target` seen. Returns them sorted **ascending by
    /// distance** (closest first) as `(dist, node)`.
    fn search_layer(
        &self,
        target: &[f32],
        ep: &[u32],
        ef: usize,
        layer: usize,
        kernel: DotFn,
    ) -> Vec<(f32, u32)> {
        let mut visited: HashSet<u32> = HashSet::with_capacity(ef * 8);
        // candidates: min-dist on top (explore closest first).
        let mut candidates: BinaryHeap<Reverse<Ord32>> = BinaryHeap::new();
        // results: max-dist on top (so we can evict the worst when over ef).
        let mut results: BinaryHeap<Ord32> = BinaryHeap::new();

        for &e in ep {
            if visited.insert(e) {
                let d = self.dist_to(target, e, kernel);
                candidates.push(Reverse(Ord32(d, e)));
                results.push(Ord32(d, e));
            }
        }

        while let Some(Reverse(Ord32(cd, c))) = candidates.pop() {
            let worst = results.peek().map(|x| x.0).unwrap_or(f32::INFINITY);
            if cd > worst && results.len() >= ef {
                break;
            }
            // `layer` is always <= node_level[c] for any node reachable here, so
            // this index is in bounds by construction.
            for &nb in &self.graph[c as usize][layer] {
                if visited.insert(nb) {
                    let d = self.dist_to(target, nb, kernel);
                    let worst = results.peek().map(|x| x.0).unwrap_or(f32::INFINITY);
                    if d < worst || results.len() < ef {
                        candidates.push(Reverse(Ord32(d, nb)));
                        results.push(Ord32(d, nb));
                        if results.len() > ef {
                            results.pop();
                        }
                    }
                }
            }
        }

        let mut out: Vec<(f32, u32)> = results.into_iter().map(|Ord32(d, n)| (d, n)).collect();
        out.sort_by(|a, b| a.0.total_cmp(&b.0).then(a.1.cmp(&b.1)));
        out
    }

    /// HNSW neighbour selection (the simple heuristic, Malkov & Yashunin
    /// Algorithm 4): keep a candidate only if it is closer to the target than to
    /// every already-selected neighbour (spreads edges around the query, the key
    /// to navigability). Falls back to nearest-remaining to top up to `m` so node
    /// degree — and thus graph connectivity/recall — is not starved.
    fn select_neighbors(&self, candidates: &[(f32, u32)], m: usize, kernel: DotFn) -> Vec<u32> {
        let mut c = candidates.to_vec();
        c.sort_by(|a, b| a.0.total_cmp(&b.0).then(a.1.cmp(&b.1)));
        let mut result: Vec<u32> = Vec::with_capacity(m);
        for &(d_q, e) in &c {
            if result.len() >= m {
                break;
            }
            let good = result.iter().all(|&r| self.dist_nodes(e, r, kernel) >= d_q);
            if good {
                result.push(e);
            }
        }
        if result.len() < m {
            for &(_, e) in &c {
                if result.len() >= m {
                    break;
                }
                if !result.contains(&e) {
                    result.push(e);
                }
            }
        }
        result
    }
}

/// Ordered `f32` (with an id tie-break) so distances live in a `BinaryHeap`.
/// `total_cmp` keeps the order well-defined even for NaN.
#[derive(Clone, Copy)]
struct Ord32(f32, u32);
impl PartialEq for Ord32 {
    fn eq(&self, other: &Self) -> bool {
        self.0.to_bits() == other.0.to_bits() && self.1 == other.1
    }
}
impl Eq for Ord32 {}
impl Ord for Ord32 {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.total_cmp(&other.0).then(self.1.cmp(&other.1))
    }
}
impl PartialOrd for Ord32 {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Assign an HNSW level: `floor(-ln(U) * mL)`, `U ∈ (0,1]`. The geometric decay
/// gives the O(log n) layer structure.
fn assign_level(rng: &mut SplitMix64, m_l: f64) -> usize {
    let mut r = rng.next_f64();
    if r <= 0.0 {
        r = f64::MIN_POSITIVE;
    }
    (-(r.ln()) * m_l).floor() as usize
}

/// A tiny deterministic PRNG (splitmix64) — no `rand` dep, reproducible builds.
struct SplitMix64(u64);
impl SplitMix64 {
    fn new(seed: u64) -> Self {
        Self(seed)
    }
    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    /// Uniform in `[0, 1)`.
    fn next_f64(&mut self) -> f64 {
        (self.next_u64() >> 11) as f64 / (1u64 << 53) as f64
    }
}

#[cfg(test)]
mod tests {
    use super::super::VectorIndex;
    use super::*;

    /// Well-spread deterministic pseudo-random vector (NOT the smooth near-tie
    /// shape) so recall@k is a meaningful metric — near-duplicate corpora make
    /// the "true top-k" ill-defined.
    fn rand_vec(seed: u64, dim: usize) -> Vec<f32> {
        let mut s = seed
            .wrapping_mul(0x9E37_79B9_7F4A_7C15)
            .wrapping_add(0xABCD_1234);
        (0..dim)
            .map(|_| {
                s ^= s << 13;
                s ^= s >> 7;
                s ^= s << 17;
                ((s >> 11) as f64 / (1u64 << 53) as f64 * 2.0 - 1.0) as f32
            })
            .collect()
    }

    fn recall_at_k(flat: &VectorIndex, hnsw: &HnswIndex, queries: &[Vec<f32>], k: usize) -> f64 {
        let mut hit = 0usize;
        let mut tot = 0usize;
        for q in queries {
            let oracle: std::collections::HashSet<u64> =
                flat.search(q, k).into_iter().map(|(id, _)| id).collect();
            let got = hnsw.search(q, k);
            for (id, _) in got {
                if oracle.contains(&id) {
                    hit += 1;
                }
            }
            tot += oracle.len();
        }
        hit as f64 / tot.max(1) as f64
    }

    #[test]
    fn hnsw_recall_floor_vs_flat_oracle() {
        let dim = 64;
        let n = 3_000usize;
        let mut flat = VectorIndex::new(dim).unwrap();
        let mut data = Vec::with_capacity(n * dim);
        let mut ids = Vec::with_capacity(n);
        for i in 0..n as u64 {
            let v = rand_vec(i, dim);
            data.extend_from_slice(&v);
            ids.push(i);
        }
        flat.add(&data, &ids).unwrap();
        let hnsw = flat.build_hnsw(HnswParams::default());
        assert_eq!(hnsw.len(), n);

        let queries: Vec<Vec<f32>> = (0..100).map(|q| rand_vec(1_000_000 + q, dim)).collect();
        let recall = recall_at_k(&flat, &hnsw, &queries, 10);
        assert!(
            recall >= 0.90,
            "HNSW recall@10 {recall:.3} fell below the 0.90 floor vs the flat oracle"
        );
    }

    #[test]
    fn hnsw_finds_exact_planted_match() {
        // A corpus of random vectors plus the query itself planted at a known id —
        // its self-cosine is 1.0, so it MUST be the rank-1 hit.
        let dim = 48;
        let n = 2_000usize;
        let mut flat = VectorIndex::new(dim).unwrap();
        let mut data = Vec::with_capacity(n * dim);
        let mut ids = Vec::with_capacity(n);
        // Seed far outside the corpus id range so the planted vector is unique
        // (a colliding seed would create a legitimate rank-1 tie).
        let planted = rand_vec(5_000_000, dim);
        for i in 0..n as u64 {
            if i == 1234 {
                data.extend_from_slice(&planted);
            } else {
                data.extend_from_slice(&rand_vec(i, dim));
            }
            ids.push(i);
        }
        flat.add(&data, &ids).unwrap();
        let hnsw = flat.build_hnsw(HnswParams::default());
        let hits = hnsw.search(&planted, 1);
        assert_eq!(hits[0].0, 1234, "planted self-match must be rank 1");
        assert!(
            (hits[0].1 - 1.0).abs() < 1e-3,
            "self-cosine ~1.0, got {}",
            hits[0].1
        );
    }

    #[test]
    fn empty_and_k0_are_safe() {
        let idx = HnswIndex::build(8, vec![], vec![], HnswParams::default());
        assert!(idx.is_empty());
        assert!(idx.search(&[0.0; 8], 5).is_empty());
        let mut flat = VectorIndex::new(8).unwrap();
        flat.add(&[1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0], &[9])
            .unwrap();
        let h = flat.build_hnsw(HnswParams::default());
        assert!(
            h.search(&[1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0], 0)
                .is_empty()
        );
    }
}
