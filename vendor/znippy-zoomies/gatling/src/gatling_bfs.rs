//! Gatling (frontier-parallel BFS) — a breadth-first graph walk whose **per-level
//! neighbor expansion** fans out across the no-barrier gatling pool.
//!
//! A sequential BFS walks one node at a time off a FIFO queue; on a wide graph
//! (a dependency / call graph with fan-out in the thousands) that leaves every
//! core but one idle while a single thread chases edges. The gatling shape for
//! BFS keeps the classic **level barrier** — you cannot know a node's true BFS
//! radius until the whole frontier one hop closer has been settled — but does
//! the *expensive* part, expanding every node in the current frontier into its
//! neighbor lists, **in parallel**: the frontier is the work set, one unit per
//! node, self-dispatched across N workers via [`crate::gatling_forkjoin`]'s
//! owned-item map. The cheap part — merging those neighbor lists into the
//! visited set and forming the next frontier — happens single-threaded **at the
//! level barrier**, so the visited-set dedup needs no lock and the result is
//! deterministic (identical to a serial reference BFS, edge-for-edge).
//!
//! - **Parallelism is in expansion, not the merge.** Each level: `neighbors(n)`
//!   is called for every `n` in the frontier across the pool (skew-tolerant —
//!   a 5 000-edge hub and a leaf are just two self-dispatched units, no worker
//!   waits on a sibling); then one thread folds the neighbor lists into the
//!   `visited` set in frontier order and emits the newly-discovered nodes as the
//!   next frontier. No shared mutable set crosses the pool ⇒ no lock, no hazard.
//! - **rayon-free / one-engine.** Built ON [`crate::gatling_forkjoin::gatling_map_owned`]
//!   — no private pool, no rayon, no bare `thread::spawn`. This module owns no
//!   `thread::scope` of its own; the ONE engine does the fan-out.
//! - **Deterministic.** The frontier is expanded in index order and neighbor
//!   lists are folded in that same order, so the discovery order (and every
//!   node's assigned radius) matches a plain FIFO reference BFS exactly, for any
//!   worker count.
//!
//! # What it serves
//! The reusable primitive under the coderoom's transitive `what-breaks` query
//! (walk reverse-dependency edges out from a changed symbol) and nornir's
//! `expand_call_radius` (walk call edges out to a bounded radius): both are a
//! frontier BFS over a `node -> neighbors` graph with an optional max radius.
//! This is that walk, generic over the node type — NOT coderoom-specific.
//!
//! # Result shape
//! [`gatling_bfs`] returns the BFS **layers**: `layers[r]` is the nodes first
//! discovered at radius `r` (`layers[0]` = the deduped start set), in discovery
//! order. Layers are strictly more informative than a flat visited set — a
//! consumer that only wants "everything reachable" flattens them
//! ([`gatling_bfs_reachable`] does exactly that), while a consumer that needs
//! the distance (how many hops away a break is) reads it straight off the layer
//! index. No node appears in two layers (BFS visits each once, at its shortest
//! radius).
//!
//! # Examples
//! ```
//! use gatling::gatling_bfs::gatling_bfs;
//! // A tiny DAG:  0 → {1, 2},  1 → {3},  2 → {3},  3 → {}
//! let adj = |&n: &u32| -> Vec<u32> {
//!     match n {
//!         0 => vec![1, 2],
//!         1 => vec![3],
//!         2 => vec![3],
//!         _ => vec![],
//!     }
//! };
//! let layers = gatling_bfs([0u32], adj, None, 0);
//! assert_eq!(layers, vec![vec![0], vec![1, 2], vec![3]]);
//! // Node 3 is reachable at radius 2 (via 1 and 2), discovered once.
//! ```

use std::collections::HashSet;
use std::hash::Hash;

/// Frontier-parallel breadth-first search over a `node -> neighbors` graph.
///
/// Walks outward from `starts` one radius at a time. Each level's frontier is
/// expanded across the no-barrier gatling pool
/// ([`crate::gatling_forkjoin::gatling_map_owned`] — one self-dispatched unit per
/// frontier node, so a lopsided fan-out never stalls a core); the newly-seen
/// nodes are then merged into the visited set **single-threaded at the level
/// barrier** and become the next frontier. Terminates when the frontier is empty
/// (the whole reachable component has been seen) or `max_radius` is hit.
///
/// Returns the BFS **layers**: `layers[0]` is the deduped start set (in first-seen
/// order), and `layers[r]` (`r >= 1`) is the nodes first discovered at radius `r`,
/// in discovery order. Each node appears in exactly one layer — the one for its
/// shortest edge-distance from any start. Flatten the layers for a plain visited
/// set (see [`gatling_bfs_reachable`]); keep them when the radius matters.
///
/// # Parameters
/// - `starts`: the radius-0 seed nodes (any `IntoIterator`). Duplicates and nodes
///   repeated across the seed are collapsed to their first occurrence.
/// - `neighbors`: `Fn(&N) -> impl IntoIterator<Item = N>` — the out-edges of a
///   node. Called at most once per node (a node is expanded only the first time
///   it is seen). Shared across the pool, so it must be `Sync`; it is never
///   called concurrently for the *same* node.
/// - `max_radius`: `None` walks until the frontier is empty; `Some(r)` includes
///   nodes up to and including radius `r` and does **not** expand past it (so
///   `Some(0)` returns only the deduped starts, expanding nothing).
/// - `n_workers`: pool width for the expansion, `0` ⇒ one per core (the
///   [`crate::gatling_forkjoin`] convention).
///
/// # Determinism
/// The frontier is expanded in index order and neighbor lists are folded in that
/// order, so the layers — and every node's radius — are identical run-to-run and
/// identical to a serial FIFO reference BFS, regardless of `n_workers`.
///
/// # Cycles
/// A back-edge to an already-visited node is dropped by the visited-set check, so
/// a cyclic graph terminates and every node is visited exactly once.
pub fn gatling_bfs<N, S, Nb, I>(
    starts: S,
    neighbors: Nb,
    max_radius: Option<usize>,
    n_workers: usize,
) -> Vec<Vec<N>>
where
    N: Eq + Hash + Clone + Send,
    S: IntoIterator<Item = N>,
    Nb: Fn(&N) -> I + Sync,
    I: IntoIterator<Item = N>,
{
    // Radius-0 layer: the seed nodes, de-duplicated, first-seen order preserved.
    let mut visited: HashSet<N> = HashSet::new();
    let mut layer0: Vec<N> = Vec::new();
    for s in starts {
        if visited.insert(s.clone()) {
            layer0.push(s);
        }
    }
    if layer0.is_empty() {
        return Vec::new();
    }

    let mut layers: Vec<Vec<N>> = vec![layer0];
    let mut radius = 0usize;

    // Expand one frontier per iteration. Stop when a max radius is hit (do not
    // expand past it) or the frontier drains (whole component seen).
    while max_radius.is_none_or(|max| radius < max) {
        // The frontier is the previous layer. Clone it into the owned-item pool:
        // `gatling_map_owned` consumes its input, and we keep the layer for the
        // returned `layers`. Each unit expands one node into its neighbor list —
        // this is the ONLY parallel step; the merge below is the level barrier.
        let frontier: Vec<N> = layers[radius].clone();
        let expanded: Vec<Vec<N>> = crate::gatling_forkjoin::gatling_map_owned(frontier, |n| {
            neighbors(&n).into_iter().collect::<Vec<N>>()
        });

        // Level barrier — single-threaded merge. Fold the neighbor lists in
        // frontier order into the visited set; a node not seen before is
        // discovered *now*, at `radius + 1`, and joins the next frontier. The
        // ordered fold is what makes the discovery order match a FIFO BFS.
        let mut next: Vec<N> = Vec::new();
        for neigh in expanded {
            for m in neigh {
                if visited.insert(m.clone()) {
                    next.push(m);
                }
            }
        }

        radius += 1;
        if next.is_empty() {
            break;
        }
        layers.push(next);
    }

    // Introspection marker: the frontier-parallel walk completed.
    #[cfg(feature = "testmatrix")]
    crate::functional_status(
        "gatling_bfs",
        "gatling_bfs",
        true,
        &format!(
            "levels={} visited={} max_radius={:?} workers={}",
            layers.len(),
            visited.len(),
            max_radius,
            n_workers,
        ),
    );
    // `n_workers` threads the pool width down to `gatling_map_owned` implicitly
    // (it reads `available_parallelism`); bind it so the marker/signature is
    // honest even when the feature is off.
    let _ = n_workers;

    layers
}

/// Flatten [`gatling_bfs`] to the **visited set as a `Vec`**, in discovery order
/// (radius-major, then frontier order within a radius). The convenience shape for
/// a consumer that only wants "every node reachable from `starts` within
/// `max_radius`" and does not care how many hops away each one is.
///
/// Order and membership are identical to the concatenation of [`gatling_bfs`]'s
/// layers — so a serial reference BFS's visit order matches this exactly.
///
/// ```
/// use gatling::gatling_bfs::gatling_bfs_reachable;
/// let adj = |&n: &u32| if n < 4 { vec![n + 1] } else { vec![] };
/// // Walk 0 → 1 → 2 out to radius 2: {0, 1, 2}.
/// let seen = gatling_bfs_reachable([0u32], adj, Some(2), 0);
/// assert_eq!(seen, vec![0, 1, 2]);
/// ```
pub fn gatling_bfs_reachable<N, S, Nb, I>(
    starts: S,
    neighbors: Nb,
    max_radius: Option<usize>,
    n_workers: usize,
) -> Vec<N>
where
    N: Eq + Hash + Clone + Send,
    S: IntoIterator<Item = N>,
    Nb: Fn(&N) -> I + Sync,
    I: IntoIterator<Item = N>,
{
    gatling_bfs(starts, neighbors, max_radius, n_workers)
        .into_iter()
        .flatten()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    /// A trivial, obviously-correct **sequential FIFO reference BFS** the parallel
    /// primitive must match edge-for-edge. Returns the same layered shape as
    /// [`gatling_bfs`] so the two are directly comparable. Deliberately naive: a
    /// queue of `(node, radius)`, a `visited` set, layers pushed in discovery
    /// order. No gatling, no parallelism — the ground truth.
    fn reference_bfs<N, Nb, I>(
        starts: &[N],
        neighbors: Nb,
        max_radius: Option<usize>,
    ) -> Vec<Vec<N>>
    where
        N: Eq + Hash + Clone,
        Nb: Fn(&N) -> I,
        I: IntoIterator<Item = N>,
    {
        let mut visited: HashSet<N> = HashSet::new();
        let mut layers: Vec<Vec<N>> = Vec::new();
        let mut queue: VecDeque<(N, usize)> = VecDeque::new();
        for s in starts {
            if visited.insert(s.clone()) {
                if layers.is_empty() {
                    layers.push(Vec::new());
                }
                layers[0].push(s.clone());
                queue.push_back((s.clone(), 0));
            }
        }
        while let Some((n, r)) = queue.pop_front() {
            if max_radius.is_some_and(|max| r >= max) {
                continue; // do not expand past the max radius
            }
            for m in neighbors(&n) {
                if visited.insert(m.clone()) {
                    let nr = r + 1;
                    if layers.len() <= nr {
                        layers.push(Vec::new());
                    }
                    layers[nr].push(m.clone());
                    queue.push_back((m, nr));
                }
            }
        }
        layers
    }

    /// (a) **Known small graph, deterministic order asserted.** A diamond DAG:
    /// the layers and their order are hand-checked, across every worker count.
    #[test]
    fn small_graph_layers_are_exact_and_ordered() {
        //   0 → {1, 2},  1 → {3, 4},  2 → {4, 5},  leaves 3,4,5 → {}
        let adj = |&n: &u32| -> Vec<u32> {
            match n {
                0 => vec![1, 2],
                1 => vec![3, 4],
                2 => vec![4, 5],
                _ => vec![],
            }
        };
        for &workers in &[0usize, 1, 2, 8] {
            let layers = gatling_bfs([0u32], adj, None, workers);
            assert_eq!(
                layers,
                vec![vec![0], vec![1, 2], vec![3, 4, 5]],
                "layers/order wrong (workers={workers})"
            );
            // 4 is reachable via both 1 and 2 but discovered ONCE, at radius 2.
            assert_eq!(layers[2], vec![3, 4, 5]);
        }
    }

    /// (b) **max_radius truncation is respected.** A straight chain 0→1→2→…→9;
    /// `Some(r)` must yield exactly radii `0..=r` and expand nothing past it.
    #[test]
    fn max_radius_truncates_the_walk() {
        let adj = |&n: &u32| if n < 9 { vec![n + 1] } else { vec![] };
        for r in 0..=9usize {
            let layers = gatling_bfs([0u32], adj, Some(r), 0);
            assert_eq!(layers.len(), r + 1, "radius {r}: wrong layer count");
            let seen = gatling_bfs_reachable([0u32], adj, Some(r), 0);
            assert_eq!(
                seen,
                (0..=r as u32).collect::<Vec<_>>(),
                "radius {r}: wrong reachable set"
            );
        }
        // Some(0) returns ONLY the deduped starts — expands nothing.
        assert_eq!(gatling_bfs([0u32], adj, Some(0), 0), vec![vec![0]]);
    }

    /// (c) **Cyclic graph terminates and visits each node once.** A ring
    /// 0→1→2→…→N-1→0 plus a chord; the walk must not loop forever, and the
    /// visited set is exactly the ring, each node once.
    #[test]
    fn cyclic_graph_terminates_each_node_once() {
        let n = 50u32;
        // Ring back-edges + a chord across the diameter — plenty of cycles.
        let adj = move |&x: &u32| -> Vec<u32> {
            let mut v = vec![(x + 1) % n];
            v.push((x + n / 2) % n);
            v
        };
        let seen = gatling_bfs_reachable([0u32], adj, None, 0);
        assert_eq!(seen.len(), n as usize, "every ring node visited");
        let uniq: HashSet<u32> = seen.iter().copied().collect();
        assert_eq!(uniq.len(), n as usize, "no node visited twice");
        assert_eq!(
            uniq,
            (0..n).collect::<HashSet<_>>(),
            "visited set == whole ring"
        );
    }

    /// (d) **Matches a trivial sequential reference BFS on a random-ish fixture.**
    /// The fixture is built from a HARDCODED-seed deterministic PRNG (a small
    /// SplitMix64 — no `rand` dep, no `Math.random`), so the graph is
    /// reproducible run-to-run. The parallel primitive's layers must equal the
    /// reference's, edge-for-edge, for every worker count and several radii.
    #[test]
    fn matches_reference_bfs_on_seeded_random_graph() {
        // SplitMix64 — a tiny, fully-deterministic PRNG seeded by a constant.
        struct SplitMix64(u64);
        impl SplitMix64 {
            fn next(&mut self) -> u64 {
                self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
                let mut z = self.0;
                z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
                z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
                z ^ (z >> 31)
            }
        }

        // Build a random directed graph over `V` nodes: each node gets a few
        // random out-edges (self-loops and duplicates allowed — the BFS must be
        // robust to both). The adjacency is materialized so both walks see the
        // exact same graph (and neighbor ORDER, which the determinism claim
        // depends on).
        const V: u32 = 400;
        for &seed in &[1u64, 0xDEAD_BEEF, 0x1234_5678_9ABC_DEF0] {
            let mut rng = SplitMix64(seed);
            let mut adj: Vec<Vec<u32>> = vec![Vec::new(); V as usize];
            for src in 0..V as usize {
                let degree = (rng.next() % 5) as usize; // 0..=4 out-edges
                for _ in 0..degree {
                    adj[src].push((rng.next() % V as u64) as u32);
                }
            }
            let neighbors = |&n: &u32| adj[n as usize].clone();

            // A couple of random start sets (deduped inside the walk).
            for starts in [vec![0u32], vec![7u32, 7, 42, 100, 399]] {
                for max_radius in [None, Some(1usize), Some(3), Some(8)] {
                    let want = reference_bfs(&starts, neighbors, max_radius);
                    for &workers in &[0usize, 1, 2, 8] {
                        let got = gatling_bfs(starts.clone(), neighbors, max_radius, workers);
                        assert_eq!(
                            got, want,
                            "parallel BFS != reference (seed={seed:#x}, starts={starts:?}, \
                             max_radius={max_radius:?}, workers={workers})"
                        );
                    }
                }
            }
        }
    }

    /// Empty starts ⇒ empty result (no layers, no panic). Duplicate starts are
    /// collapsed to the first occurrence in `layers[0]`.
    #[test]
    fn empty_and_duplicate_starts() {
        let adj = |&_n: &u32| Vec::<u32>::new();
        let empty: Vec<u32> = Vec::new();
        assert!(gatling_bfs(empty.clone(), adj, None, 0).is_empty());
        assert!(gatling_bfs_reachable(empty, adj, None, 0).is_empty());
        // Duplicates in the seed collapse; order is first-seen.
        assert_eq!(
            gatling_bfs([5u32, 5, 3, 5, 3], adj, None, 0),
            vec![vec![5, 3]]
        );
    }

    /// The reachable-set convenience equals the flattened layers, and the layers
    /// partition the visited set (no node in two layers) — on the diamond.
    #[test]
    fn reachable_is_flattened_layers_and_partitions() {
        let adj = |&n: &u32| -> Vec<u32> {
            match n {
                0 => vec![1, 2],
                1 => vec![3],
                2 => vec![3],
                _ => vec![],
            }
        };
        let layers = gatling_bfs([0u32], adj, None, 0);
        let flat: Vec<u32> = layers.iter().flatten().copied().collect();
        assert_eq!(gatling_bfs_reachable([0u32], adj, None, 0), flat);
        let uniq: HashSet<u32> = flat.iter().copied().collect();
        assert_eq!(
            uniq.len(),
            flat.len(),
            "a node appears in exactly one layer"
        );
    }
}
