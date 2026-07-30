//! S-tree static search index for sorted **u32** keys — Ragnar's ORIGINAL width.
//!
//! ORIGINAL AUTHOR: **Ragnar Groot Koerkamp** — `static-search-tree`
//!   <https://github.com/RagnarGrootKoerkamp/static-search-tree>
//!   Writeup: "Static search trees: 40× faster than binary search"
//!   <https://curiouscoding.nl/posts/static-search-tree/>
//!
//! This module is a derivative work; the algorithm — the cache-line-sized
//! implicit S(+)-tree, the branchless SIMD node compare, and the software-
//! pipelined/prefetched batch traversal that hides memory latency — is entirely
//! Ragnar's. **Thank you, Ragnar Groot Koerkamp**, for the design and the
//! beautifully written explanation. Licensed MIT — Copyright (c) 2025 Ragnar
//! Groot Koerkamp. The upstream MIT notice is retained in this crate's LICENSE
//! file.
//!
//! ## Why a second concrete type (and NOT a generic `STree<T>`)?
//!
//! [`crate::stree`] (`STree64`) is the znippy adaptation to **i64** keys, needed
//! for OSM node IDs (which exceed `u32`) and skade snapshot IDs. This module is a
//! clean, separate clone restoring Ragnar's **original 32-bit width** for future
//! non-OSM use where keys fit in `u32`. The owner was explicit: *"klona 64 till
//! 32, ge dig inte på att parametrisera 64/32 bitar"* — two clean concrete
//! implementations, never a generic. A `STree<T>` would force the SIMD node
//! compare (`_mm256_cmpgt_epi32` vs `_mm256_cmpgt_epi64`), the per-node element
//! count `B`, the sentinel, and the leaf stride to all become type-parametric,
//! which (a) defeats the const-folding the branchless inner loop relies on and
//! (b) couples two paths whose B/SIMD trade-offs were measured independently.
//!
//! ## Differences from [`crate::stree`] (`STree64`)
//!   - Key type: i64 → **u32** (Ragnar's original); sentinel `u32::MAX`.
//!   - Node size: B=8 i64 (64 B) → **B=16 u32 (64 B, one cache line)** — Ragnar's
//!     original branching factor. 2× the key density per cache line: a u32 tree
//!     has fewer levels than an i64 tree over the same key count, so fewer
//!     dependent cache-line loads per query.
//!   - SIMD: `_mm256_cmpgt_epi32` compares **8 × u32** per 256-bit register
//!     (vs `_mm256_cmpgt_epi64`'s 4 × i64), so `B/8 = 2` register compares cover
//!     a 16-element node (the i64 path did `B/4 = 2` compares for an 8-element
//!     node — same 2 compares/node, but each covers twice the keys). 2× SIMD
//!     width over the i64 version.
//!   - Same software-pipelined `_mm_prefetch` MLP batch traversal, with the
//!     **const-generic P** in-flight-query depth preserved. P is the *pipeline
//!     depth*, not a key-width parameter — it is exactly the prefetch knob the
//!     owner did NOT forbid.
//!
//! Build: `STree32::new(sorted_keys)` — O(n).
//! Query: `find_exact(key)` → `Option<usize>` — O(log₁₇ n).
//!
//! `STree32Mmap` — same tree but WITHOUT the leaf layer. The sorted mmap IS the
//! leaf layer. Default record stride is **4 bytes** (a pure little-endian `u32`
//! column / SoA layout) — the natural layout for a 32-bit key file. Use
//! [`STree32Mmap::new_with_stride`] for a wider AoS record.

const B: usize = 16; // elements per node = branching factor (Ragnar's original)
const MAX32: u32 = u32::MAX; // sentinel for unused slots

// ── Public type ────────────────────────────────────────────────────────────────

/// Immutable S-tree over a sorted `&[u32]` slice.
/// Stores a complete copy of the data internally.
pub struct STree32 {
    tree: Vec<[u32; B]>,
    offsets: Vec<usize>,
    n: usize,
}

impl STree32 {
    /// Build from a **sorted** slice. Panics in debug if not sorted.
    pub fn new(vals: &[u32]) -> Self {
        assert!(!vals.is_empty(), "STree32::new: empty input");
        #[cfg(debug_assertions)]
        for w in vals.windows(2) {
            assert!(w[0] <= w[1], "STree32::new: input not sorted");
        }

        let n = vals.len();
        let height = height(n);
        let lsizes = layer_sizes(n, height);
        let n_blocks: usize = lsizes.iter().sum();

        let mut offsets = Vec::with_capacity(height);
        let mut acc = 0;
        for &ls in &lsizes {
            offsets.push(acc);
            acc += ls;
        }

        let mut tree = vec![[MAX32; B]; n_blocks];

        // ── Leaf layer ────────────────────────────────────────────────────────
        let ol = offsets[height - 1];
        for (i, &val) in vals.iter().enumerate() {
            tree[ol + i / B][i % B] = val;
        }
        if n % B != 0 {
            tree[ol + n / B][n % B..].fill(MAX32);
        }

        // ── Internal layers (root … leaf−1, built bottom-up) ──────────────────
        for h in (0..height - 1).rev() {
            let oh = offsets[h];
            tree[oh..oh + lsizes[h]]
                .iter_mut()
                .for_each(|nd| nd.fill(MAX32));

            for i in 0..B * lsizes[h] {
                let j = i % B;
                let mut k = (i / B) * (B + 1) + j + 1;
                for _ in h..height - 2 {
                    k *= B + 1;
                }
                tree[oh + i / B][j] = if k * B < n { tree[ol + k][0] } else { MAX32 };
            }
        }

        advise_hugepage(&tree);
        Self { tree, offsets, n }
    }

    /// Find the index of `q` in the original sorted slice, or `None` if absent.
    #[inline]
    pub fn find_exact(&self, q: u32) -> Option<usize> {
        #[cfg(target_arch = "x86_64")]
        if is_x86_feature_detected!("avx2") {
            return unsafe { self.find_exact_avx2(q) };
        }
        self.find_exact_impl(q, count_lt_scalar)
    }

    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "avx2")]
    unsafe fn find_exact_avx2(&self, q: u32) -> Option<usize> {
        self.find_exact_impl(q, |n, q| unsafe { count_lt_avx2(n, q) })
    }

    #[inline(always)]
    fn find_exact_impl<F: Fn(&[u32; B], u32) -> usize>(&self, q: u32, cnt: F) -> Option<usize> {
        let height = self.offsets.len();
        let mut k = 0usize;

        for h in 0..height - 1 {
            let o = self.offsets[h];
            let jump = cnt(&self.tree[o + k], q);
            k = k * (B + 1) + jump;
        }

        let o = self.offsets[height - 1];
        let idx = cnt(&self.tree[o + k], q);

        // idx can be 0..=B.  When idx == B all leaf elements were < q,
        // so the target is at the start of the NEXT leaf block (overflow by 1).
        let block = k + idx / B;
        let slot = idx % B;
        let pos = block * B + slot;

        if pos < self.n && self.tree[o + block][slot] == q {
            Some(pos)
        } else {
            None
        }
    }
}

// ── STree32Mmap — internal-nodes-only tree, mmap is the leaf layer ────────────
//
// Default mmap record layout: a pure little-endian `u32` column (stride = 4 B,
// SoA). Build reads the first key of each B-record leaf block directly from the
// data slice (stride scan). find_exact navigates internal nodes then does a ≤B+1
// record linear scan in the data.

const MMAP_RECORD: usize = 4; // default bytes per record (u32 SoA column)

pub struct STree32Mmap {
    tree: Vec<[u32; B]>,
    offsets: Vec<usize>,
    pub count: usize,
    pub stride: usize, // bytes between consecutive u32 keys in the data slice
}

impl STree32Mmap {
    /// Build from a data slice with the default 4-byte pure-`u32`-column layout.
    pub fn new(data: &[u8], count: usize) -> Self {
        Self::new_with_stride(data, count, MMAP_RECORD)
    }

    /// Build from a data slice where each key is `stride` bytes apart.
    /// Use stride=4 for a pure u32 key column; larger strides for AoS records
    /// whose leading 4 bytes are the little-endian u32 key.
    pub fn new_with_stride(data: &[u8], count: usize, stride: usize) -> Self {
        assert!(count > 0);
        assert!(stride >= 4);
        let h = height(count);
        let lsizes = layer_sizes(count, h);
        let ni = h - 1;

        let n_blocks: usize = lsizes[..ni].iter().sum();
        let mut offsets = Vec::with_capacity(ni);
        let mut acc = 0usize;
        for &ls in &lsizes[..ni] {
            offsets.push(acc);
            acc += ls;
        }

        let mut tree = vec![[MAX32; B]; n_blocks];

        // Per-layer fill, bottom-up. Layers are independent and parallelise; we
        // keep bottom-up for cache friendliness.
        //
        // ROOT LAW #0 (2026-07-22): the fan-out was a hand-rolled
        // `std::thread::scope` pool over one static chunk per thread. It is now
        // `gatling_scanlines` — the same `rows * stride` disjoint-row shape, with
        // each row a BAND of blocks rather than a single block. See the twin in
        // `stree.rs` for why the band exists: one block per unit turns a 64-byte
        // fill into a shared `fetch_add`, and measured 2x slower.
        const SMALL_LAYER_BLOCKS: usize = 4096;
        let n_threads = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1)
            .max(1);
        for lvl in (0..ni).rev() {
            let oh = offsets[lvl];
            let n_nodes = lsizes[lvl];
            let slice = &mut tree[oh..oh + n_nodes];
            let fill_block = |blk: usize, node: &mut [u32]| {
                node.fill(MAX32);
                for j in 0..B {
                    let mut k = blk * (B + 1) + j + 1;
                    for _ in lvl..h - 2 {
                        k *= B + 1;
                    }
                    node[j] = if k * B < count {
                        id_at(data, k * B, stride)
                    } else {
                        MAX32
                    };
                }
            };
            if n_nodes < SMALL_LAYER_BLOCKS {
                for (blk, node) in slice.chunks_mut(1).enumerate() {
                    fill_block(blk, node.as_flattened_mut());
                }
                continue;
            }
            let band = n_nodes.div_ceil(n_threads * 4).max(1);
            let rows = n_nodes / band;
            let flat = slice.as_flattened_mut();
            let (head, tail) = flat.split_at_mut(rows * band * B);
            gatling::gatling_forkjoin::gatling_scanlines(
                head,
                rows,
                band * B,
                0,
                2,
                |u, banded| {
                    for (i, node) in banded.chunks_mut(B).enumerate() {
                        fill_block(u * band + i, node);
                    }
                },
            );
            for (i, node) in tail.chunks_mut(B).enumerate() {
                fill_block(rows * band + i, node);
            }
        }

        advise_hugepage(&tree);
        Self {
            tree,
            offsets,
            count,
            stride,
        }
    }

    #[inline]
    pub fn find_exact(&self, q: u32, data: &[u8]) -> Option<usize> {
        #[cfg(target_arch = "x86_64")]
        if is_x86_feature_detected!("avx2") {
            return unsafe { self.find_exact_avx2(q, data) };
        }
        self.find_exact_impl(q, data, count_lt_scalar)
    }

    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "avx2")]
    unsafe fn find_exact_avx2(&self, q: u32, data: &[u8]) -> Option<usize> {
        self.find_exact_impl(q, data, |n, qq| unsafe { count_lt_avx2(n, qq) })
    }

    #[inline(always)]
    fn find_exact_impl<F: Fn(&[u32; B], u32) -> usize>(
        &self,
        q: u32,
        data: &[u8],
        cnt: F,
    ) -> Option<usize> {
        let mut k = 0usize;
        for &o in &self.offsets {
            let jump = cnt(&self.tree[o + k], q);
            k = k * (B + 1) + jump;
        }
        let stride = self.stride;
        for i in 0..=B {
            let pos = k * B + i;
            if pos >= self.count {
                break;
            }
            match id_at(data, pos, stride).cmp(&q) {
                std::cmp::Ordering::Equal => return Some(pos),
                std::cmp::Ordering::Greater => break,
                std::cmp::Ordering::Less => {}
            }
        }
        None
    }

    /// Tree-only routing: descend internal nodes to a leaf block index.
    /// Returns the leaf block index `k`; the candidate record range is
    /// `[k*B, k*B + B + 1)` (the trailing +1 handles overflow).
    #[inline]
    pub fn route_to_block(&self, q: u32) -> usize {
        #[cfg(target_arch = "x86_64")]
        if is_x86_feature_detected!("avx2") {
            return unsafe { self.route_to_block_avx2(q) };
        }
        self.route_to_block_impl(q, count_lt_scalar)
    }

    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "avx2")]
    unsafe fn route_to_block_avx2(&self, q: u32) -> usize {
        self.route_to_block_impl(q, |n, qq| unsafe { count_lt_avx2(n, qq) })
    }

    #[inline(always)]
    fn route_to_block_impl<F: Fn(&[u32; B], u32) -> usize>(&self, q: u32, cnt: F) -> usize {
        let mut k = 0usize;
        for &o in &self.offsets {
            let jump = cnt(&self.tree[o + k], q);
            k = k * (B + 1) + jump;
        }
        k
    }

    /// Batch lookup: resolve `ids` against the on-disk sorted record store.
    /// Routes every id through the tree, sorts `(leaf_block, original_index)` so
    /// the data walk is sequential, `madvise(WILLNEED)` over the touched range,
    /// then linear leaf scan in sorted order; scatter results back.
    pub fn lookup_batch(&self, ids: &[u32], data: &[u8]) -> Vec<Option<usize>> {
        let n = ids.len();
        if n == 0 {
            return Vec::new();
        }

        let mut routed: Vec<(usize, u32)> = (0..n)
            .map(|i| (self.route_to_block(ids[i]), i as u32))
            .collect();

        routed.sort_unstable_by_key(|&(k, _)| k);

        if let (Some(&(lo_k, _)), Some(&(hi_k, _))) = (routed.first(), routed.last()) {
            let stride = self.stride;
            let lo_byte = lo_k * B * stride;
            let hi_byte = ((hi_k + 1) * B + 1).min(self.count) * stride;
            if hi_byte > lo_byte {
                advise_willneed(&data[lo_byte..hi_byte]);
            }
        }

        let stride = self.stride;
        let mut out = vec![None; n];
        for (k, orig) in routed {
            let q = ids[orig as usize];
            for i in 0..=B {
                let pos = k * B + i;
                if pos >= self.count {
                    break;
                }
                match id_at(data, pos, stride).cmp(&q) {
                    std::cmp::Ordering::Equal => {
                        out[orig as usize] = Some(pos);
                        break;
                    }
                    std::cmp::Ordering::Greater => break,
                    std::cmp::Ordering::Less => {}
                }
            }
        }
        out
    }

    /// Pipelined batched lookup using software-pipelined internal traversal.
    /// Const generic P sets the number of in-flight queries to overlap memory
    /// latency — Ragnar's key MLP trick (this is what pegs all cores at 100%).
    pub fn lookup_batch_pipeline<const P: usize>(
        &self,
        ids: &[u32],
        data: &[u8],
    ) -> Vec<Option<usize>> {
        #[cfg(target_arch = "x86_64")]
        if is_x86_feature_detected!("avx2") {
            return unsafe { self.lookup_batch_pipeline_avx2::<P>(ids, data) };
        }
        self.lookup_batch_pipeline_impl::<P, _>(ids, data, count_lt_scalar)
    }

    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "avx2")]
    unsafe fn lookup_batch_pipeline_avx2<const P: usize>(
        &self,
        ids: &[u32],
        data: &[u8],
    ) -> Vec<Option<usize>> {
        self.lookup_batch_pipeline_impl::<P, _>(ids, data, |n, q| unsafe { count_lt_avx2(n, q) })
    }

    #[inline(always)]
    fn lookup_batch_pipeline_impl<const P: usize, F: Fn(&[u32; B], u32) -> usize>(
        &self,
        ids: &[u32],
        data: &[u8],
        cnt: F,
    ) -> Vec<Option<usize>> {
        let n = ids.len();
        if n == 0 {
            return Vec::new();
        }

        // 1. Route queries in batches of P through internal nodes with prefetch.
        let mut routed: Vec<(usize, u32)> = Vec::with_capacity(n);
        let mut i = 0usize;
        let offs = &self.offsets;
        let n_levels = offs.len();
        while i + P <= n {
            let mut q = [0u32; P];
            for j in 0..P {
                q[j] = ids[i + j];
            }

            let mut kk = [0usize; P];
            // Traverse all internal layers except the last with prefetch
            for h in 0..n_levels.saturating_sub(1) {
                let o = offs[h];
                let o2 = offs[h + 1];
                for j in 0..P {
                    let jump = cnt(&self.tree[o + kk[j]], q[j]);
                    kk[j] = kk[j] * (B + 1) + jump;
                    prefetch_index(&self.tree, o2 + kk[j]);
                }
            }
            // Final internal level (no next tree level to prefetch)
            if n_levels > 0 {
                let o = offs[n_levels - 1];
                for j in 0..P {
                    let jump = cnt(&self.tree[o + kk[j]], q[j]);
                    kk[j] = kk[j] * (B + 1) + jump;
                }
            }
            for j in 0..P {
                routed.push((kk[j], (i + j) as u32));
            }
            i += P;
        }
        // Remainder
        while i < n {
            routed.push((self.route_to_block(ids[i]), i as u32));
            i += 1;
        }

        // 2. Sort & madvise
        routed.sort_unstable_by_key(|&(k, _)| k);
        let stride = self.stride;
        if let (Some(&(lo_k, _)), Some(&(hi_k, _))) = (routed.first(), routed.last()) {
            let lo_byte = lo_k * B * stride;
            let hi_byte = ((hi_k + 1) * B + 1).min(self.count) * stride;
            if hi_byte > lo_byte {
                advise_willneed(&data[lo_byte..hi_byte]);
            }
        }

        // 3. linear leaf scan, scatter results
        let mut out = vec![None; n];
        for (k, orig) in routed {
            let q = ids[orig as usize];
            for t in 0..=B {
                let pos = k * B + t;
                if pos >= self.count {
                    break;
                }
                match id_at(data, pos, stride).cmp(&q) {
                    std::cmp::Ordering::Equal => {
                        out[orig as usize] = Some(pos);
                        break;
                    }
                    std::cmp::Ordering::Greater => break,
                    _ => {}
                }
            }
        }
        out
    }
}

/// Best-effort `madvise(MADV_HUGEPAGE)` over the tree's backing store. The tree
/// is the random-access hot structure: every query touches one cache line per
/// level; hinting transparent hugepages (2 MB) cuts dTLB pressure in the
/// RAM-bound regime (cf. Ragnar's hugepage results). Best-effort: errors
/// ignored, no-op off Linux.
#[inline]
fn advise_hugepage<T>(slice: &[T]) {
    #[cfg(target_os = "linux")]
    unsafe {
        let _ = libc::madvise(
            slice.as_ptr() as *mut libc::c_void,
            std::mem::size_of_val(slice),
            libc::MADV_HUGEPAGE,
        );
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = slice;
    }
}

/// Best-effort `madvise(MADV_WILLNEED)` over a data slice. Linux-only; no-op
/// elsewhere. Errors are silently ignored.
#[inline]
fn advise_willneed(slice: &[u8]) {
    #[cfg(target_os = "linux")]
    unsafe {
        let _ = libc::madvise(
            slice.as_ptr() as *mut libc::c_void,
            slice.len(),
            libc::MADV_WILLNEED,
        );
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = slice;
    }
}

/// Prefetch the given cacheline into L1 cache (pointer form).
#[inline]
fn prefetch_ptr<T>(ptr: *const T) {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        std::arch::x86_64::_mm_prefetch(ptr as *const i8, std::arch::x86_64::_MM_HINT_T0);
    }
    #[cfg(target_arch = "x86")]
    unsafe {
        std::arch::x86::_mm_prefetch(ptr as *const i8, std::arch::x86::_MM_HINT_T0);
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "x86")))]
    {
        let _ = ptr;
    }
}

/// Prefetch the given cacheline by indexing into a slice.
#[inline]
fn prefetch_index<T>(s: &[T], index: usize) {
    let ptr = unsafe { s.as_ptr().add(index) } as *const T;
    prefetch_ptr(ptr);
}

#[inline]
fn id_at(data: &[u8], idx: usize, stride: usize) -> u32 {
    let off = idx * stride;
    u32::from_le_bytes(data[off..off + 4].try_into().unwrap())
}

// ── Tree shape helpers ─────────────────────────────────────────────────────────

fn blocks(n: usize) -> usize {
    n.div_ceil(B)
}

fn prev_keys(n: usize) -> usize {
    blocks(n).div_ceil(B + 1) * B
}

fn height(n: usize) -> usize {
    if n <= B { 1 } else { height(prev_keys(n)) + 1 }
}

fn layer_size(mut n: usize, h: usize, height: usize) -> usize {
    for _ in h..height - 1 {
        n = prev_keys(n);
    }
    n
}

fn layer_sizes(n: usize, height: usize) -> Vec<usize> {
    (0..height)
        .map(|h| layer_size(n, h, height).div_ceil(B))
        .collect()
}

// ── SIMD node comparison ───────────────────────────────────────────────────────

/// Count elements in `node` that are strictly less than `q`.
/// Equivalently: the index of the first element >= q (predecessor step).
///
/// Selected **once per query (or per batch)** by the public entry points — never
/// per node. The hot traversal loops are generic over the counter (`F: Fn`) and
/// the AVX2 variant runs inside a `#[target_feature(enable = "avx2")]` wrapper,
/// so [`count_lt_avx2`] inlines straight into the loop. The scalar variant is the
/// correctness fallback on non-AVX2 CPUs.
#[inline(always)]
fn count_lt_scalar(node: &[u32; B], q: u32) -> usize {
    node.iter().filter(|&&x| x < q).count()
}

/// AVX2 path: one 256-bit compare per **8 × u32**, looped over the whole node
/// (`B/8 = 2` calls for a one-cache-line B=16 node). AVX2 has only a *signed*
/// 32-bit greater-than (`_mm256_cmpgt_epi32`), so we bias both operands by
/// `i32::MIN` (XOR `0x8000_0000`) to map the unsigned order onto the signed one
/// — the standard unsigned-compare-via-signed trick. Each i32 lane yields 4
/// identical result bytes → total popcount / 4 = count of elements `< q`. `B`
/// must be a multiple of 8 (it is: 16). The loop is fully unrolled by the
/// optimiser.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
#[inline]
unsafe fn count_lt_avx2(node: &[u32; B], q: u32) -> usize {
    use std::arch::x86_64::*;
    unsafe {
        let bias = _mm256_set1_epi32(i32::MIN); // 0x8000_0000 in each lane
        let q_v = _mm256_xor_si256(_mm256_set1_epi32(q as i32), bias);
        let mut bits = 0u32;
        let mut i = 0;
        while i < B {
            let v = _mm256_loadu_si256(node.as_ptr().add(i) as *const __m256i);
            let vb = _mm256_xor_si256(v, bias);
            // count elements x < q  ⟺  q > x  ⟺  cmpgt(q, x)
            let c = _mm256_cmpgt_epi32(q_v, vb);
            bits += (_mm256_movemask_epi8(c) as u32).count_ones();
            i += 8;
        }
        (bits / 4) as usize
    }
}

// ── STree32 batch methods (Ragnar-style pipelined) ─────────────────────────────

impl STree32 {
    /// Pipelined batch search — process P queries lock-step through the tree,
    /// issuing prefetch for the next level's node while other queries overlap
    /// their cache-miss latency. The core of Ragnar's throughput trick.
    ///
    /// Returns `[Option<usize>; P]` — index in the original sorted slice or None.
    pub fn batch_prefetch<const P: usize>(&self, queries: &[u32; P]) -> [Option<usize>; P] {
        #[cfg(target_arch = "x86_64")]
        if is_x86_feature_detected!("avx2") {
            return unsafe { self.batch_prefetch_avx2(queries) };
        }
        self.batch_prefetch_impl(queries, count_lt_scalar)
    }

    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "avx2")]
    unsafe fn batch_prefetch_avx2<const P: usize>(&self, queries: &[u32; P]) -> [Option<usize>; P] {
        self.batch_prefetch_impl(queries, |n, q| unsafe { count_lt_avx2(n, q) })
    }

    #[inline(always)]
    fn batch_prefetch_impl<const P: usize, F: Fn(&[u32; B], u32) -> usize>(
        &self,
        queries: &[u32; P],
        cnt: F,
    ) -> [Option<usize>; P] {
        let height = self.offsets.len();
        let mut k = [0usize; P];

        // Internal levels with prefetch
        for h in 0..height - 1 {
            let o = self.offsets[h];
            let o2 = self.offsets[h + 1];
            for j in 0..P {
                let jump = cnt(&self.tree[o + k[j]], queries[j]);
                k[j] = k[j] * (B + 1) + jump;
                prefetch_index(&self.tree, o2 + k[j]);
            }
        }

        // Leaf level — no prefetch needed, just resolve
        let o = self.offsets[height - 1];
        let mut results = [None; P];
        for j in 0..P {
            let idx = cnt(&self.tree[o + k[j]], queries[j]);
            let block = k[j] + idx / B;
            let slot = idx % B;
            let pos = block * B + slot;
            if pos < self.n && self.tree[o + block][slot] == queries[j] {
                results[j] = Some(pos);
            }
        }
        results
    }

    /// Streaming batch: process a slice of arbitrary length, chunked into
    /// batches of P internally with prefetch. Returns `Vec<Option<usize>>`.
    pub fn batch_stream<const P: usize>(&self, queries: &[u32]) -> Vec<Option<usize>> {
        let n = queries.len();
        let mut out = Vec::with_capacity(n);
        let mut i = 0;

        while i + P <= n {
            let chunk: &[u32; P] = queries[i..i + P].try_into().unwrap();
            let results = self.batch_prefetch(chunk);
            out.extend_from_slice(&results);
            i += P;
        }

        // Remainder: single queries
        for j in i..n {
            out.push(self.find_exact(queries[j]));
        }
        out
    }
}

// ── STree32 floor / lower-bound (the predecessor the descent already computes) ──
//
// `find_exact` computes `pos = k*B + idx` — the index of the first stored key
// `>= q` (the lower bound) — then adds an equality check. Exposing `pos` WITHOUT
// that check turns the same nanosecond-scale, cache-optimal, SIMD-pipelined
// descent into a floor/predecessor primitive — the missing piece for RANGE
// lookups (IP-CIDR membership, range→value). Additive; the exact-match paths are
// untouched. The batch form is the throughput path — Ragnar's whole point.
impl STree32 {
    /// Lower bound: the index of the first stored key `>= q` (in `0..=n`).
    /// `find_exact(q)` is this plus `key[pos] == q`. Use with the stored keys to
    /// derive the floor (greatest key `<= q`): `pos` if `key[pos] == q`, else
    /// `pos - 1` (or none when `pos == 0`).
    #[inline]
    pub fn lower_bound(&self, q: u32) -> usize {
        #[cfg(target_arch = "x86_64")]
        if is_x86_feature_detected!("avx2") {
            return unsafe { self.lower_bound_avx2(q) };
        }
        self.lower_bound_impl(q, count_lt_scalar)
    }

    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "avx2")]
    unsafe fn lower_bound_avx2(&self, q: u32) -> usize {
        self.lower_bound_impl(q, |n, qq| unsafe { count_lt_avx2(n, qq) })
    }

    #[inline(always)]
    fn lower_bound_impl<F: Fn(&[u32; B], u32) -> usize>(&self, q: u32, cnt: F) -> usize {
        let height = self.offsets.len();
        let mut k = 0usize;
        for h in 0..height - 1 {
            let o = self.offsets[h];
            k = k * (B + 1) + cnt(&self.tree[o + k], q);
        }
        let o = self.offsets[height - 1];
        let idx = cnt(&self.tree[o + k], q);
        (k * B + idx).min(self.n)
    }

    /// Pipelined batch lower-bound — the same P-deep prefetch trick as
    /// [`batch_prefetch`](Self::batch_prefetch) but returning the lower-bound
    /// index per query (never None). This is the 2M-req/s path for range lookups:
    /// resolve a whole event-batch of keys in one pipelined pass.
    pub fn lower_bound_batch<const P: usize>(&self, queries: &[u32]) -> Vec<usize> {
        #[cfg(target_arch = "x86_64")]
        if is_x86_feature_detected!("avx2") {
            return unsafe { self.lower_bound_batch_avx2::<P>(queries) };
        }
        self.lower_bound_batch_impl::<P, _>(queries, count_lt_scalar)
    }

    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "avx2")]
    unsafe fn lower_bound_batch_avx2<const P: usize>(&self, queries: &[u32]) -> Vec<usize> {
        self.lower_bound_batch_impl::<P, _>(queries, |n, q| unsafe { count_lt_avx2(n, q) })
    }

    #[inline(always)]
    fn lower_bound_batch_impl<const P: usize, F: Fn(&[u32; B], u32) -> usize>(
        &self,
        queries: &[u32],
        cnt: F,
    ) -> Vec<usize> {
        let n = queries.len();
        let mut out = Vec::with_capacity(n);
        let height = self.offsets.len();
        let mut i = 0;
        while i + P <= n {
            let mut k = [0usize; P];
            for h in 0..height - 1 {
                let o = self.offsets[h];
                let o2 = self.offsets[h + 1];
                for j in 0..P {
                    k[j] = k[j] * (B + 1) + cnt(&self.tree[o + k[j]], queries[i + j]);
                    prefetch_index(&self.tree, o2 + k[j]);
                }
            }
            let o = self.offsets[height - 1];
            for j in 0..P {
                let idx = cnt(&self.tree[o + k[j]], queries[i + j]);
                out.push((k[j] * B + idx).min(self.n));
            }
            i += P;
        }
        for j in i..n {
            out.push(self.lower_bound(queries[j]));
        }
        out
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// TESTS — inject real u32 keys + assert correctness; pipeline == scalar; benches.
// ═══════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::StdRng;
    use rand::{Rng, SeedableRng};
    use std::time::Instant;

    fn gen_sorted_sparse_keys(n: usize, seed: u64) -> Vec<u32> {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut keys = Vec::with_capacity(n);
        let mut cur: u32 = 1;
        for _ in 0..n {
            cur += rng.gen_range(1..20) as u32;
            keys.push(cur);
        }
        keys
    }

    /// Like `gen_sorted_sparse_keys` but with small gaps (1..=3) so that even
    /// 2^27 keys stay below `u32::MAX` (max cumulative ≈ 2^27 * 3 ≈ 4.0e8 < 4.29e9).
    fn gen_sorted_sparse_keys_dense(n: usize, seed: u64) -> Vec<u32> {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut keys = Vec::with_capacity(n);
        let mut cur: u32 = 1;
        for _ in 0..n {
            cur = cur.wrapping_add(rng.gen_range(1..4) as u32);
            keys.push(cur);
        }
        keys
    }

    fn gen_queries(keys: &[u32], n_hit: usize, n_miss: usize, seed: u64) -> Vec<u32> {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut qs = Vec::with_capacity(n_hit + n_miss);
        for _ in 0..n_hit {
            qs.push(keys[rng.gen_range(0..keys.len())]);
        }
        let max = keys.last().copied().unwrap_or(1000);
        for _ in 0..n_miss {
            qs.push(
                rng.gen_range(0..max.saturating_mul(2))
                    .saturating_mul(3)
                    .wrapping_add(2),
            );
        }
        qs
    }

    fn build_ids_only(keys: &[u32]) -> Vec<u8> {
        let mut buf = Vec::with_capacity(keys.len() * 4);
        for &k in keys {
            buf.extend_from_slice(&k.to_le_bytes());
        }
        buf
    }

    // ── Inject-and-assert correctness: present, absent, boundaries ──────────────

    #[test]
    fn stree32_inject_present_absent_boundaries() {
        // INJECT a known sorted Vec<u32>; ASSERT exact positions, misses, edges.
        let vals: Vec<u32> = vec![
            1, 3, 5, 7, 9, 11, 13, 15, 17, 19, 21, 23, 25, 27, 29, 31, 100, 200, 12345,
        ];
        let tree = STree32::new(&vals);

        // present → exact index
        for (i, &v) in vals.iter().enumerate() {
            assert_eq!(tree.find_exact(v), Some(i), "present key {v} at {i}");
        }
        // absent (interior gaps)
        for &miss in &[2u32, 4, 8, 30, 50, 150, 999] {
            assert_eq!(tree.find_exact(miss), None, "absent key {miss}");
        }
        // boundaries: below-min, above-max, exact-min, exact-max
        assert_eq!(tree.find_exact(0), None, "below min");
        assert_eq!(
            tree.find_exact(u32::MAX - 1),
            None,
            "above max (and not sentinel)"
        );
        assert_eq!(
            tree.find_exact(*vals.first().unwrap()),
            Some(0),
            "exact min"
        );
        assert_eq!(
            tree.find_exact(*vals.last().unwrap()),
            Some(vals.len() - 1),
            "exact max"
        );
    }

    #[test]
    fn stree32_round_trip_large() {
        let vals: Vec<u32> = (0..200_000u32).map(|i| i * 3).collect();
        let tree = STree32::new(&vals);
        for (i, &v) in vals.iter().enumerate() {
            assert_eq!(tree.find_exact(v), Some(i));
        }
        assert_eq!(tree.find_exact(1), None);
        assert_eq!(tree.find_exact(599_999), None);
    }

    #[test]
    fn stree32_single_and_exact_b() {
        let t = STree32::new(&[42u32]);
        assert_eq!(t.find_exact(42), Some(0));
        assert_eq!(t.find_exact(41), None);
        assert_eq!(t.find_exact(43), None);

        // exactly B and B+1 elements exercise the leaf-overflow path
        let b: Vec<u32> = (1..=B as u32).collect();
        let tb = STree32::new(&b);
        for (i, &v) in b.iter().enumerate() {
            assert_eq!(tb.find_exact(v), Some(i));
        }
        assert_eq!(tb.find_exact(0), None);
        assert_eq!(tb.find_exact(B as u32 + 1), None);

        let bp1: Vec<u32> = (1..=B as u32 + 1).collect();
        let tbp1 = STree32::new(&bp1);
        for (i, &v) in bp1.iter().enumerate() {
            assert_eq!(tbp1.find_exact(v), Some(i));
        }
    }

    #[test]
    fn stree32_full_u32_range_keys() {
        // keys spanning near u32::MAX exercise the unsigned-compare-via-signed bias.
        let vals: Vec<u32> = vec![
            0,
            1,
            1000,
            1_000_000,
            0x7FFF_FFFF,
            0x8000_0000,
            0x8000_0001,
            0xFFFF_FFFE, // u32::MAX-1; u32::MAX is the sentinel so excluded
        ];
        let tree = STree32::new(&vals);
        for (i, &v) in vals.iter().enumerate() {
            assert_eq!(tree.find_exact(v), Some(i), "high-range key {v} at {i}");
        }
        assert_eq!(tree.find_exact(0x8000_0002), None);
        assert_eq!(tree.find_exact(2), None);
    }

    // ── pipeline / batch == scalar find_exact ───────────────────────────────────

    #[test]
    fn stree32_batch_prefetch_matches_scalar() {
        let vals = gen_sorted_sparse_keys(80_000, 100);
        let tree = STree32::new(&vals);
        let qs = gen_queries(&vals, 1000, 1000, 200);

        for chunk in qs.chunks(16) {
            if chunk.len() == 16 {
                let arr: [u32; 16] = chunk.try_into().unwrap();
                let batch = tree.batch_prefetch(&arr);
                let serial: Vec<_> = chunk.iter().map(|&q| tree.find_exact(q)).collect();
                for (j, (&b, &s)) in batch.iter().zip(serial.iter()).enumerate() {
                    assert_eq!(b, s, "batch_prefetch mismatch at {j}, q={}", chunk[j]);
                }
            }
        }
    }

    #[test]
    fn stree32_batch_stream_matches_scalar_all_p() {
        let vals = gen_sorted_sparse_keys(60_000, 103);
        let tree = STree32::new(&vals);
        let qs = gen_queries(&vals, 2000, 2000, 203);
        let serial: Vec<_> = qs.iter().map(|&q| tree.find_exact(q)).collect();

        assert_eq!(tree.batch_stream::<8>(&qs), serial, "P=8");
        assert_eq!(tree.batch_stream::<16>(&qs), serial, "P=16");
        assert_eq!(tree.batch_stream::<32>(&qs), serial, "P=32");

        // non-multiple-of-P sizes (remainder path)
        for size in [0, 1, 7, 15, 16, 17, 31, 33, 127, 129, 1000] {
            let q = gen_queries(&vals, size / 2 + 1, size / 2, 300 + size as u64);
            let q = &q[..size.min(q.len())];
            let s: Vec<_> = q.iter().map(|&x| tree.find_exact(x)).collect();
            assert_eq!(tree.batch_stream::<16>(q), s, "stream size={size}");
        }
    }

    // ── STree32Mmap (stride=4 u32 column) inject-and-assert + pipeline==scalar ──

    #[test]
    fn stree32mmap_inject_and_pipeline_matches_scalar() {
        let keys = gen_sorted_sparse_keys(50_000, 50);
        let buf = build_ids_only(&keys);
        let tree = STree32Mmap::new(&buf, keys.len());

        // present + boundaries via find_exact
        for (i, &k) in keys.iter().enumerate() {
            assert_eq!(tree.find_exact(k, &buf), Some(i), "mmap present {k} @ {i}");
        }
        assert_eq!(
            tree.find_exact(keys[0].saturating_sub(0).wrapping_sub(0), &buf),
            Some(0)
        );
        assert_eq!(tree.find_exact(*keys.last().unwrap() + 1, &buf), None);
        assert_eq!(tree.find_exact(0, &buf), None);

        // pipeline P=4/8/16/32 == serial find_exact
        let qs = gen_queries(&keys, 5_000, 5_000, 61);
        let serial: Vec<_> = qs.iter().map(|&q| tree.find_exact(q, &buf)).collect();
        assert_eq!(tree.lookup_batch(&qs, &buf), serial, "lookup_batch");
        assert_eq!(
            tree.lookup_batch_pipeline::<4>(&qs, &buf),
            serial,
            "pipeline P=4"
        );
        assert_eq!(
            tree.lookup_batch_pipeline::<8>(&qs, &buf),
            serial,
            "pipeline P=8"
        );
        assert_eq!(
            tree.lookup_batch_pipeline::<16>(&qs, &buf),
            serial,
            "pipeline P=16"
        );
        assert_eq!(
            tree.lookup_batch_pipeline::<32>(&qs, &buf),
            serial,
            "pipeline P=32"
        );
    }

    #[test]
    fn stree32mmap_all_hits_all_misses_empty() {
        let keys = gen_sorted_sparse_keys(5_000, 120);
        let buf = build_ids_only(&keys);
        let tree = STree32Mmap::new(&buf, keys.len());

        let all_hits: Vec<_> = (0..keys.len()).map(Some).collect();
        assert_eq!(tree.lookup_batch_pipeline::<16>(&keys, &buf), all_hits);

        let misses: Vec<u32> = (0..1000).map(|i| keys.last().unwrap() + i + 1).collect();
        assert_eq!(
            tree.lookup_batch_pipeline::<16>(&misses, &buf),
            vec![None; 1000]
        );

        assert_eq!(
            tree.lookup_batch_pipeline::<16>(&[], &buf),
            Vec::<Option<usize>>::new()
        );
    }

    // ── Micro-bench: STree32 vs std binary search, and STree32 vs STree64 ───────
    // Run with: cargo test -p znippy-zoomies --release stree32_bench -- --nocapture
    //
    // Returns (speedup_vs_binsearch, stree32_vs_stree64). Prints a table per size.
    fn run_stree32_bench(log2n: u32) -> (f64, f64) {
        use crate::stree::STree64;
        use std::hint::black_box;

        let n = 1usize << log2n;
        let q = (1usize << 20).min(n); // 1M queries (or fewer)

        // u32 keys (small gaps so n keys stay < u32::MAX even at 2^27).
        let keys32 = gen_sorted_sparse_keys_dense(n, 0xD15 ^ log2n as u64);
        let tree32 = STree32::new(&keys32);
        let qs32 = gen_queries(&keys32, q, 0, 0xC0FFEE ^ log2n as u64); // hit workload

        // matching i64 keys (same values, widened) for the density comparison
        let keys64: Vec<i64> = keys32.iter().map(|&k| k as i64).collect();
        let tree64 = STree64::new(&keys64);
        let qs64: Vec<i64> = qs32.iter().map(|&k| k as i64).collect();

        // Correctness gate before timing.
        for &qq in qs32.iter().take(64) {
            assert_eq!(tree32.find_exact(qq).map(|i| keys32[i]), Some(qq));
        }

        black_box(tree32.batch_stream::<32>(&qs32));

        let reps = if log2n >= 26 { 3 } else { 5 };
        let per_q = move |d: std::time::Duration| d.as_nanos() as f64 / q as f64;
        let time = |f: &dyn Fn()| {
            let t = Instant::now();
            for _ in 0..reps {
                f();
            }
            t.elapsed() / reps
        };

        let d_bin = time(&|| {
            let mut acc = 0usize;
            for &qq in &qs32 {
                acc ^= black_box(keys32.binary_search(&qq)).unwrap_or(0);
            }
            black_box(acc);
        });
        let d_b32 = time(&|| {
            black_box(tree32.batch_stream::<32>(&qs32));
        });
        let d_b16 = time(&|| {
            black_box(tree32.batch_stream::<16>(&qs32));
        });
        let d_64 = time(&|| {
            black_box(tree64.batch_stream::<32>(&qs64));
        });

        let bin_ns = per_q(d_bin);
        let best32 = per_q(d_b32).min(per_q(d_b16));
        let s64 = per_q(d_64);
        let speedup = bin_ns / best32;
        let density = s64 / best32;

        let mb = n * 4 / (1 << 20);
        let regime = if log2n >= 26 {
            "RAM-bound — Ragnar's 40× regime"
        } else {
            "cache→RAM"
        };
        eprintln!("\n=== STree32 micro-bench ({n} keys = {mb} MB u32, {q} queries, {regime}) ===");
        eprintln!("  std binary_search:   {:>7.1} ns/q", bin_ns);
        eprintln!("  STree32 batch P=16:  {:>7.1} ns/q", per_q(d_b16));
        eprintln!("  STree32 batch P=32:  {:>7.1} ns/q", per_q(d_b32));
        eprintln!(
            "  STree64 batch P=32:  {:>7.1} ns/q (i64, half density)",
            s64
        );
        eprintln!("  speedup vs binsearch: {:>5.1}x", speedup);
        eprintln!(
            "  STree32 vs STree64:   {:>5.2}x (u32 density win)",
            density
        );
        (speedup, density)
    }

    #[test]
    fn stree32_bench_vs_binsearch_and_vs_stree64() {
        // In-cache / cache→RAM sweep (fast, always runs). 16 MB u32 store.
        // (`_speedup` is only asserted in release — see note below.)
        let (_speedup, _density) = run_stree32_bench(22);
        // The whole win is SIMD + software-pipelined prefetch, which the debug
        // build neither vectorises nor schedules — an unoptimised run is
        // meaningless, so the perf assertion is release-only. Run optimised:
        //   cargo test -p znippy-zoomies --release stree32_bench -- --nocapture
        #[cfg(not(debug_assertions))]
        assert!(
            _speedup > 1.0,
            "STree32 batch should beat binary search (got {_speedup:.1}x)"
        );
    }

    // RAM-bound regime (512 MB u32 store, 2^27 keys) — reproduces Ragnar's
    // headline ~40× vs binary search. Heavy; `#[ignore]` so the default suite
    // stays fast. Run with:
    //   cargo test -p znippy-zoomies --release stree32_bench_ram -- --ignored --nocapture
    #[test]
    #[ignore = "heavy: 512 MB allocation, RAM-bound timing; run with --release --ignored"]
    fn stree32_bench_ram_bound_40x() {
        let (_speedup, _density) = run_stree32_bench(27);
        #[cfg(not(debug_assertions))]
        assert!(
            _speedup > 10.0,
            "RAM-bound STree32 should be ≫10× binary search (got {_speedup:.1}x)"
        );
    }
}
