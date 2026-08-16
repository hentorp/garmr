//! The **BULK** shape — [`BulkGraph`]: hand over the whole vertex + edge set, and
//! get the whole-graph algorithms as pure deterministic defaults.
//!
//! This is the shape the release doctor reasons over: a directed graph of publish
//! units whose edge `A→B` reads "**A depends on B**" (⇒ `B` must publish first).
//! The questions — *what are the cycles?*, *what is the publish order?*, *what is
//! the release closure of this root?* — are whole-graph questions, so the trait
//! asks for the whole graph and answers them ONCE, here, for every backend.
//!
//! A backend that can only answer bounded/local questions must NOT implement this
//! trait; it implements [`GraphQuery`](crate::GraphQuery) instead. That split is
//! the point: forcing a 2.3 GB edge table through `edges()` to answer a one-node
//! question is exactly what the two-trait design exists to prevent.
//!
//! Everything here is PURE (no I/O), deterministic (BTree-ordered throughout) and
//! independent of how the edges were sourced.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt;

use crate::{Edge, EdgeLabel};

/// A directed graph as `node → the set of nodes it points at`. Throughout this
/// module `A→B` reads "**A depends on B**".
pub type Adj = BTreeMap<String, BTreeSet<String>>;

/// Failure of a total ordering: the graph is not a DAG.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DepGraphError {
    /// The graph contains at least one dependency cycle; the payload is the sorted
    /// set of nodes that could not be linearized (every node on some cycle, plus any
    /// node transitively gated behind one).
    Cycle(Vec<String>),
}

impl fmt::Display for DepGraphError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DepGraphError::Cycle(nodes) => {
                write!(
                    f,
                    "dependency cycle blocks a total publish order: {}",
                    nodes.join(", ")
                )
            }
        }
    }
}

impl std::error::Error for DepGraphError {}

/// The backend-agnostic BULK graph.
///
/// Implementors MUST supply [`nodes`](BulkGraph::nodes) and
/// [`edges`](BulkGraph::edges); [`scc`](BulkGraph::scc), [`topo`](BulkGraph::topo)
/// and [`release_closure`](BulkGraph::release_closure) are provided as pure,
/// deterministic defaults derived from them. An implementor MAY override one for a
/// native backend query — [`PetGraph`](crate::PetGraph) overrides `scc` with
/// petgraph's Tarjan, which is what makes it an independent cross-check of the
/// implementation in this module.
pub trait BulkGraph {
    /// Domain-owned edge provenance. Set to `()` when edges are unlabelled — the
    /// bulk algorithms never read the label, they only preserve it through
    /// [`edges`](BulkGraph::edges).
    type Label: EdgeLabel;

    /// Every node, the graph's vertex set. Order is NOT significant — the default
    /// algorithms sort internally for determinism.
    fn nodes(&self) -> Vec<String>;

    /// Every directed edge `from → to`. An edge whose endpoint is absent from
    /// [`nodes`](BulkGraph::nodes) is still honoured (the endpoint is treated as an
    /// implicit node) so a partial graph stays sound.
    fn edges(&self) -> Vec<Edge<Self::Label>>;

    // ───────────────────────── derived (default) methods ─────────────────────────

    /// The full vertex set as a deterministic sorted set, folding in any node that
    /// appears only as an edge endpoint. The basis every default method reasons over.
    fn all_nodes(&self) -> BTreeSet<String> {
        let mut set: BTreeSet<String> = self.nodes().into_iter().collect();
        for e in self.edges() {
            set.insert(e.from);
            set.insert(e.to);
        }
        set
    }

    /// Forward adjacency `node → {nodes it points at}` (out-edges), BTree-ordered.
    fn adjacency(&self) -> Adj {
        let mut adj: Adj = BTreeMap::new();
        for n in self.all_nodes() {
            adj.entry(n).or_default();
        }
        for e in self.edges() {
            adj.entry(e.from).or_default().insert(e.to.clone());
            adj.entry(e.to).or_default();
        }
        adj
    }

    /// Strongly-connected components. Every component with >1 member — or a single
    /// node bearing a self-loop — IS a dependency cycle. Members are sorted and the
    /// outer vector is deterministic (sorted by first member).
    ///
    /// Default: an iterative (stack-safe) Tarjan over [`adjacency`](BulkGraph::adjacency).
    fn scc(&self) -> Vec<Vec<String>> {
        let mut out = tarjan_scc(&self.adjacency());
        out.sort_by(|a, b| a.first().cmp(&b.first()));
        out
    }

    /// Just the components that are real cycles (the >1-member or self-loop ones),
    /// the unshippable knots that must be cut before a total order exists.
    fn cycles(&self) -> Vec<Vec<String>> {
        let adj = self.adjacency();
        self.scc()
            .into_iter()
            .filter(|c| {
                c.len() > 1 || (c.len() == 1 && adj.get(&c[0]).is_some_and(|s| s.contains(&c[0])))
            })
            .collect()
    }

    /// A total **publish order**: deps first, so for every edge `A→B` (`A` depends on
    /// `B`) `B` precedes `A`. Deterministic (ties broken by name via a sorted ready
    /// frontier). `Err(`[`DepGraphError::Cycle`]`)` if the graph is not a DAG.
    ///
    /// Default: Kahn's algorithm over [`adjacency`](BulkGraph::adjacency).
    fn topo(&self) -> Result<Vec<String>, DepGraphError> {
        let adj = self.adjacency();
        // A node is ready once all its dependencies (out-edges) are already emitted.
        // Track the number of not-yet-emitted deps per node, and the reverse map
        // (dependents) to decrement when a node is emitted.
        let mut unmet: BTreeMap<String, usize> = BTreeMap::new();
        let mut dependents: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        for (node, deps) in &adj {
            // Self-loops are their own cycle; count them so such a node never becomes
            // ready and surfaces in the residual cycle set.
            unmet.insert(node.clone(), deps.len());
            for d in deps {
                dependents
                    .entry(d.clone())
                    .or_default()
                    .insert(node.clone());
            }
        }
        let mut ready: BTreeSet<String> = unmet
            .iter()
            .filter(|(_, n)| **n == 0)
            .map(|(k, _)| k.clone())
            .collect();
        let mut order: Vec<String> = Vec::with_capacity(unmet.len());
        while let Some(next) = ready.iter().next().cloned() {
            ready.remove(&next);
            order.push(next.clone());
            if let Some(deps) = dependents.get(&next) {
                for dep in deps.clone() {
                    if let Some(c) = unmet.get_mut(&dep) {
                        *c = c.saturating_sub(1);
                        if *c == 0 {
                            ready.insert(dep);
                        }
                    }
                }
            }
        }
        if order.len() != adj.len() {
            let emitted: BTreeSet<String> = order.into_iter().collect();
            let stuck: Vec<String> = adj
                .keys()
                .filter(|k| !emitted.contains(*k))
                .cloned()
                .collect();
            return Err(DepGraphError::Cycle(stuck));
        }
        Ok(order)
    }

    /// The **release closure** of `roots`: `roots` plus every node transitively
    /// reachable by following out-edges, bounded by `max_depth` hops. `None` =
    /// unbounded; `Some(0)` = just the roots present in the graph; `Some(1)` = roots
    /// + their direct deps; and so on. Deterministic set.
    fn release_closure(&self, roots: &[String], max_depth: Option<usize>) -> BTreeSet<String> {
        let adj = self.adjacency();
        let mut seen: BTreeSet<String> = BTreeSet::new();
        let mut queue: VecDeque<(String, usize)> = VecDeque::new();
        for r in roots {
            if adj.contains_key(r) && seen.insert(r.clone()) {
                queue.push_back((r.clone(), 0));
            }
        }
        while let Some((node, depth)) = queue.pop_front() {
            if max_depth.is_some_and(|m| depth >= m) {
                continue;
            }
            if let Some(deps) = adj.get(&node) {
                for d in deps {
                    if seen.insert(d.clone()) {
                        queue.push_back((d.clone(), depth + 1));
                    }
                }
            }
        }
        seen
    }
}

// ─────────────────────────── iterative Tarjan (the ONE home) ───────────────────────────

/// Tarjan's strongly-connected components over `adj`, `O(V+E)`. Each returned
/// component is a sorted member list. Every component with more than one node — or
/// a single node with a self-loop — IS a dependency cycle (the nodes that provably
/// cannot be linearly ordered).
///
/// Iterative (explicit work stack) so a deep graph can't blow the call stack.
///
/// This is the constellation's ONE Tarjan. It moved here from
/// `nornir-release-core`'s `graph_math`, which now delegates to it, so the SCC math
/// has exactly one home (LAW 5: reuse, never twin).
pub fn tarjan_scc(adj: &Adj) -> Vec<Vec<String>> {
    let nodes: Vec<String> = adj.keys().cloned().collect();
    let mut index: BTreeMap<String, usize> = BTreeMap::new();
    let mut low: BTreeMap<String, usize> = BTreeMap::new();
    let mut on_stack: BTreeSet<String> = BTreeSet::new();
    let mut stack: Vec<String> = Vec::new();
    let mut idx = 0usize;
    let mut out: Vec<Vec<String>> = Vec::new();

    // Each work frame `(v, i)` resumes v's successor scan at index i.
    for start in &nodes {
        if index.contains_key(start) {
            continue;
        }
        let mut work: Vec<(String, usize)> = vec![(start.clone(), 0)];
        while let Some((v, mut i)) = work.pop() {
            if i == 0 {
                index.insert(v.clone(), idx);
                low.insert(v.clone(), idx);
                idx += 1;
                stack.push(v.clone());
                on_stack.insert(v.clone());
            }
            let succs: Vec<String> = adj
                .get(&v)
                .map(|s| s.iter().cloned().collect())
                .unwrap_or_default();
            let mut recursed = false;
            while i < succs.len() {
                let w = &succs[i];
                if !index.contains_key(w) {
                    // Descend into the unvisited successor, resuming v after it.
                    work.push((v.clone(), i + 1));
                    work.push((w.clone(), 0));
                    recursed = true;
                    break;
                } else if on_stack.contains(w) {
                    let lw = index[w];
                    let lv = low[&v];
                    low.insert(v.clone(), lv.min(lw));
                }
                i += 1;
            }
            if recursed {
                continue;
            }
            // v's scan is complete: close a root component, then propagate its
            // low-link to the frame directly beneath (its parent), if any.
            if low[&v] == index[&v] {
                let mut comp: Vec<String> = Vec::new();
                while let Some(w) = stack.pop() {
                    on_stack.remove(&w);
                    let done = w == v;
                    comp.push(w);
                    if done {
                        break;
                    }
                }
                comp.sort();
                out.push(comp);
            }
            if let Some((parent, _)) = work.last() {
                let lp = low[parent];
                let lv = low[&v];
                low.insert(parent.clone(), lp.min(lv));
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal `BulkGraph` implementing ONLY the required pair, to prove the
    /// default algorithms stand on `nodes`/`edges` alone.
    struct RawGraph {
        nodes: Vec<String>,
        edges: Vec<Edge>,
    }
    impl BulkGraph for RawGraph {
        type Label = ();
        fn nodes(&self) -> Vec<String> {
            self.nodes.clone()
        }
        fn edges(&self) -> Vec<Edge> {
            self.edges.clone()
        }
    }

    fn s(x: &str) -> String {
        x.to_string()
    }

    fn raw(nodes: &[&str], edges: &[(&str, &str)]) -> RawGraph {
        RawGraph {
            nodes: nodes.iter().map(|x| s(x)).collect(),
            edges: edges.iter().map(|(a, b)| Edge::new(*a, *b)).collect(),
        }
    }

    #[test]
    fn scc_finds_the_cycle() {
        let g = raw(&[], &[("a", "b"), ("b", "c"), ("c", "a"), ("a", "d")]);
        let scc = g.scc();
        assert!(
            scc.contains(&vec![s("a"), s("b"), s("c")]),
            "cycle abc missing: {scc:?}"
        );
        assert!(scc.contains(&vec![s("d")]), "singleton d missing: {scc:?}");
        assert_eq!(g.cycles(), vec![vec![s("a"), s("b"), s("c")]]);
    }

    #[test]
    fn self_loop_is_a_cycle() {
        let g = raw(&[], &[("a", "a"), ("b", "a")]);
        assert_eq!(g.cycles(), vec![vec![s("a")]]);
    }

    #[test]
    fn topo_orders_deps_first() {
        let g = raw(&[], &[("a", "b"), ("a", "c"), ("b", "d"), ("c", "d")]);
        let order = g.topo().expect("dag must linearize");
        assert_eq!(order, vec![s("d"), s("b"), s("c"), s("a")]);
    }

    #[test]
    fn topo_rejects_a_cycle() {
        let g = raw(&[], &[("a", "b"), ("b", "a"), ("c", "a")]);
        match g.topo() {
            Err(DepGraphError::Cycle(stuck)) => {
                assert!(
                    stuck.contains(&s("a")) && stuck.contains(&s("b")),
                    "stuck={stuck:?}"
                );
            }
            other => panic!("expected a cycle error, got {other:?}"),
        }
    }

    #[test]
    fn release_closure_is_depth_bounded() {
        let g = raw(
            &[],
            &[("a", "b"), ("a", "c"), ("b", "d"), ("c", "d"), ("d", "e")],
        );
        let set = |v: &[&str]| -> BTreeSet<String> { v.iter().map(|x| s(x)).collect() };
        assert_eq!(g.release_closure(&[s("a")], Some(0)), set(&["a"]));
        assert_eq!(g.release_closure(&[s("a")], Some(1)), set(&["a", "b", "c"]));
        assert_eq!(
            g.release_closure(&[s("a")], Some(2)),
            set(&["a", "b", "c", "d"])
        );
        assert_eq!(
            g.release_closure(&[s("a")], None),
            set(&["a", "b", "c", "d", "e"])
        );
        assert!(g.release_closure(&[s("zzz")], None).is_empty());
    }

    /// An isolated node declared via `nodes()` but touched by no edge must still
    /// appear — the `nodes()` half of the contract is load-bearing, and a backend
    /// that returned an empty node set would go red here.
    #[test]
    fn a_node_with_no_edges_still_appears() {
        let g = raw(&["lonely"], &[("a", "b")]);
        assert_eq!(
            g.all_nodes(),
            ["a", "b", "lonely"].iter().map(|x| s(x)).collect()
        );
        // Kahn's sorted ready frontier: {b, lonely} — `b` first; emitting it frees
        // `a`, which then beats `lonely` on name.
        assert_eq!(g.topo().unwrap(), vec![s("b"), s("a"), s("lonely")]);
    }
}
