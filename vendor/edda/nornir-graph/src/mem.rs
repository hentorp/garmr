//! [`MemGraph`] — the pure-std in-memory graph. The DEFAULT backend: zero
//! dependencies, and the only one that honestly implements BOTH shapes, because it
//! already holds everything in memory so `edges()` costs nothing extra.
//!
//! It is also the reference the database backends are checked against: the same
//! graph loaded into `MemGraph` and into [`CozoGraph`](crate::CozoGraph) must give
//! identical `pivot` / `shortest_path` / `scc` / `topo` / `release_closure`.
//!
//! # Traversal semantics — the exact contract the backends must match
//!
//! * `pivot` is a FIFO breadth-first search from `start`, visiting each node's
//!   neighbours in sorted-id order, emitting a node the first time it is reached
//!   (so `hop` is its minimum distance and `via` is the label of the edge that
//!   FIRST reached it in visitation order). Results are in BFS visitation order.
//!   A neighbour with no payload is skipped — the graph may record an edge to an
//!   id it has no node for, and a `Hit` must always carry a real payload.
//! * `shortest_path` is the same BFS recording a predecessor per node, then walking
//!   back from the target. `a == b` yields the single-node path.
//!
//! Both are ported unchanged from the hand-rolled traversal that motivated this
//! crate, so a consumer swapping its own BFS for `MemGraph` sees byte-identical
//! output including tie-breaks.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::convert::Infallible;

use crate::{BulkGraph, Edge, EdgeLabel, GraphQuery, GraphStore, Hit};

/// An in-memory graph: node payloads plus a labelled adjacency.
///
/// Generic in the payload `N` (default `()` — ids only) and the label `L` (default
/// `()` — unlabelled). Store DIRECTED edges with
/// [`add_edge`](GraphStore::add_edge) or UNDIRECTED ones with
/// [`link`](GraphStore::link); the traversals always follow out-edges, so an
/// undirected consumer simply records both directions.
#[derive(Debug, Clone)]
pub struct MemGraph<N = (), L = ()> {
    nodes: BTreeMap<String, N>,
    /// node → (out-neighbour → strongest label).
    adj: BTreeMap<String, BTreeMap<String, L>>,
}

impl<N, L> Default for MemGraph<N, L> {
    fn default() -> Self {
        Self {
            nodes: BTreeMap::new(),
            adj: BTreeMap::new(),
        }
    }
}

impl<N, L> MemGraph<N, L> {
    /// An empty graph.
    pub fn new() -> Self {
        Self::default()
    }

    /// Every node id, sorted.
    pub fn node_ids(&self) -> impl Iterator<Item = &String> {
        self.nodes.keys()
    }

    /// Every node payload, in id order.
    pub fn payloads(&self) -> impl Iterator<Item = &N> {
        self.nodes.values()
    }

    /// Every `(id, payload)` pair, in id order.
    pub fn entries(&self) -> impl Iterator<Item = (&String, &N)> {
        self.nodes.iter()
    }

    /// A mutable handle on a payload, for a consumer that enriches nodes in place.
    pub fn payload_mut(&mut self, id: &str) -> Option<&mut N> {
        self.nodes.get_mut(id)
    }

    /// `(node count, UNDIRECTED edge count)` — the directed edge count halved, the
    /// right answer for a graph built with [`link`](GraphStore::link).
    pub fn size(&self) -> (usize, usize) {
        let directed: usize = self.adj.values().map(BTreeMap::len).sum();
        (self.nodes.len(), directed / 2)
    }
}

impl<N, L: EdgeLabel> MemGraph<N, L> {
    /// Every UNDIRECTED edge once, as `(a, b, label)` with `a < b`, carrying the
    /// strongest recorded label for the pair. For a graph built with
    /// [`link`](GraphStore::link) this is the whole edge list; for a genuinely
    /// directed graph use [`BulkGraph::edges`] instead, which keeps direction.
    pub fn undirected_edges(&self) -> Vec<(String, String, L)> {
        let mut out = Vec::new();
        for (a, adj) in &self.adj {
            for (b, label) in adj {
                if a < b {
                    out.push((a.clone(), b.clone(), *label));
                }
            }
        }
        out
    }

    /// The induced-subgraph edges among a set of node ids: every undirected edge
    /// whose BOTH endpoints are in `ids`, each returned once (`a < b`) with the
    /// strongest recorded label.
    pub fn edges_among(&self, ids: &BTreeSet<String>) -> Vec<(String, String, L)> {
        let mut out = Vec::new();
        for a in ids {
            let Some(adj) = self.adj.get(a) else { continue };
            for (b, label) in adj {
                if a < b && ids.contains(b) {
                    out.push((a.clone(), b.clone(), *label));
                }
            }
        }
        out
    }
}

impl<N, L: EdgeLabel> GraphQuery for MemGraph<N, L> {
    type Node = N;
    type Label = L;

    fn contains(&self, id: &str) -> bool {
        self.nodes.contains_key(id)
    }

    fn node(&self, id: &str) -> Option<&N> {
        self.nodes.get(id)
    }

    fn node_count(&self) -> usize {
        self.nodes.len()
    }

    fn neighbours(&self, id: &str) -> Vec<(String, L)> {
        self.adj
            .get(id)
            .map(|m| m.iter().map(|(k, v)| (k.clone(), *v)).collect())
            .unwrap_or_default()
    }

    fn degree(&self, id: &str) -> usize {
        self.adj.get(id).map(BTreeMap::len).unwrap_or(0)
    }

    fn pivot(&self, start: &str, depth: usize) -> Vec<Hit<'_, N, L>> {
        let mut out = Vec::new();
        if !self.nodes.contains_key(start) || depth == 0 {
            return out;
        }
        let mut seen: BTreeSet<&str> = BTreeSet::new();
        seen.insert(start);
        let mut q: VecDeque<(usize, &str)> = VecDeque::new();
        q.push_back((0, start));
        while let Some((d, id)) = q.pop_front() {
            if d == depth {
                continue;
            }
            if let Some(adj) = self.adj.get(id) {
                for (nb, label) in adj {
                    if seen.insert(nb.as_str()) {
                        if let Some(node) = self.nodes.get(nb) {
                            out.push(Hit {
                                hop: d + 1,
                                via: *label,
                                node,
                            });
                            q.push_back((d + 1, nb.as_str()));
                        }
                    }
                }
            }
        }
        out
    }

    fn shortest_path(&self, a: &str, b: &str) -> Option<Vec<&N>> {
        if !self.nodes.contains_key(a) || !self.nodes.contains_key(b) {
            return None;
        }
        if a == b {
            return self.nodes.get(a).map(|n| vec![n]);
        }
        let mut prev: BTreeMap<&str, &str> = BTreeMap::new();
        let mut seen: BTreeSet<&str> = BTreeSet::new();
        seen.insert(a);
        let mut q: VecDeque<&str> = VecDeque::new();
        q.push_back(a);
        while let Some(id) = q.pop_front() {
            if id == b {
                break;
            }
            if let Some(adj) = self.adj.get(id) {
                for nb in adj.keys() {
                    if seen.insert(nb.as_str()) {
                        prev.insert(nb.as_str(), id);
                        q.push_back(nb.as_str());
                    }
                }
            }
        }
        if !seen.contains(b) {
            return None;
        }
        let mut path = Vec::new();
        let mut cur = b;
        loop {
            path.push(self.nodes.get(cur)?);
            if cur == a {
                break;
            }
            cur = prev.get(cur)?;
        }
        path.reverse();
        Some(path)
    }
}

impl<N, L: EdgeLabel> GraphStore for MemGraph<N, L> {
    /// In-memory writes cannot fail.
    type Error = Infallible;

    fn put_node(&mut self, id: &str, node: N) -> Result<(), Infallible> {
        self.nodes.insert(id.to_string(), node);
        Ok(())
    }

    fn add_edge(&mut self, from: &str, to: &str, label: L) -> Result<(), Infallible> {
        self.adj
            .entry(from.to_string())
            .or_default()
            .entry(to.to_string())
            .and_modify(|k| *k = (*k).max(label))
            .or_insert(label);
        Ok(())
    }
}

impl<N, L: EdgeLabel> BulkGraph for MemGraph<N, L> {
    type Label = L;

    fn nodes(&self) -> Vec<String> {
        self.nodes.keys().cloned().collect()
    }

    /// Every DIRECTED edge. A graph built with [`GraphStore::link`] reports each
    /// undirected edge twice, once per direction — that is the honest directed view
    /// of what is stored.
    fn edges(&self) -> Vec<Edge<L>> {
        let mut out = Vec::new();
        for (from, adj) in &self.adj {
            for (to, label) in adj {
                out.push(Edge::labelled(from.clone(), to.clone(), *label));
            }
        }
        out
    }
}

/// `MemGraph<(), ()>` — the ids-only, unlabelled case, which is what a
/// publish-order / dependency graph is.
pub type IdGraph = MemGraph<(), ()>;

impl MemGraph<(), ()> {
    /// Build an ids-only DIRECTED graph from `(from, to)` pairs; endpoints become
    /// nodes with a `()` payload. The convenience constructor a dependency-graph
    /// consumer wants.
    pub fn from_edges<I, S>(edges: I) -> Self
    where
        I: IntoIterator<Item = (S, S)>,
        S: Into<String>,
    {
        let mut g = Self::new();
        for (a, b) in edges {
            let (a, b) = (a.into(), b.into());
            let _ = g.put_node(&a, ());
            let _ = g.put_node(&b, ());
            let _ = g.add_edge(&a, &b, ());
        }
        g
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(x: &str) -> String {
        x.to_string()
    }

    /// The same graph answers BOTH shapes.
    #[test]
    fn mem_graph_answers_both_shapes() {
        let g = IdGraph::from_edges([("a", "b"), ("a", "c"), ("b", "d"), ("c", "d")]);
        assert_eq!(g.topo().unwrap(), vec![s("d"), s("b"), s("c"), s("a")]);
        assert_eq!(g.node_count(), 4);
        assert_eq!(g.neighbours("a"), vec![(s("b"), ()), (s("c"), ())]);
        assert_eq!(g.degree("a"), 2);
        assert_eq!(g.degree("d"), 0);
        // Directed: `a` reaches everything downstream, `d` (a sink) reaches nothing.
        assert_eq!(g.pivot("a", 9).len(), 3);
        assert!(
            g.pivot("d", 9).is_empty(),
            "a sink must reach nothing following out-edges"
        );
        assert_eq!(
            g.release_closure(&[s("a")], None),
            ["a", "b", "c", "d"].iter().map(|x| s(x)).collect()
        );
    }

    /// Labels merge by `max` and are never downgraded — the "stronger link wins"
    /// contract every backend must reproduce.
    #[test]
    fn label_merge_keeps_the_stronger() {
        let mut g: MemGraph<(), u8> = MemGraph::new();
        g.put_node("a", ()).unwrap();
        g.put_node("b", ()).unwrap();
        g.link("a", "b", 5).unwrap();
        g.link("a", "b", 1).unwrap();
        assert_eq!(
            g.neighbours("a"),
            vec![(s("b"), 5)],
            "a weaker label downgraded the edge"
        );
        g.link("a", "b", 9).unwrap();
        assert_eq!(
            g.neighbours("a"),
            vec![(s("b"), 9)],
            "a stronger label failed to upgrade"
        );
    }

    /// Undirected `link` reaches both ways; `add_edge` reaches only forward. A
    /// backend that quietly made `add_edge` symmetric would go red here.
    #[test]
    fn link_is_undirected_and_add_edge_is_not() {
        let mut u: MemGraph<(), ()> = MemGraph::new();
        u.put_node("a", ()).unwrap();
        u.put_node("b", ()).unwrap();
        u.link("a", "b", ()).unwrap();
        assert_eq!(u.degree("a"), 1);
        assert_eq!(u.degree("b"), 1);
        assert_eq!(u.size(), (2, 1));

        let mut d: MemGraph<(), ()> = MemGraph::new();
        d.put_node("a", ()).unwrap();
        d.put_node("b", ()).unwrap();
        d.add_edge("a", "b", ()).unwrap();
        assert_eq!(d.degree("a"), 1);
        assert_eq!(d.degree("b"), 0, "add_edge must NOT be symmetric");
    }

    /// A self-link is a no-op (it would otherwise make every node its own neighbour
    /// and turn every SCC into a false cycle).
    #[test]
    fn self_link_is_a_noop() {
        let mut g: MemGraph<(), ()> = MemGraph::new();
        g.put_node("a", ()).unwrap();
        g.link("a", "a", ()).unwrap();
        assert_eq!(g.degree("a"), 0);
        assert!(g.cycles().is_empty());
    }

    /// An edge to an id with no payload is recorded but never yields a `Hit` — the
    /// BFS skips it, exactly as the traversal this was ported from does.
    #[test]
    fn an_edge_to_a_payloadless_id_yields_no_hit() {
        let mut g: MemGraph<String, ()> = MemGraph::new();
        g.put_node("a", "A".into()).unwrap();
        g.put_node("c", "C".into()).unwrap();
        g.link("a", "ghost", ()).unwrap(); // no payload for `ghost`
        g.link("a", "c", ()).unwrap();
        let hits: Vec<&str> = g.pivot("a", 3).iter().map(|h| h.node.as_str()).collect();
        assert_eq!(
            hits,
            vec!["C"],
            "a payloadless neighbour leaked into the pivot"
        );
    }

    #[test]
    fn pivot_and_path_over_an_undirected_graph() {
        let mut g: MemGraph<String, u8> = MemGraph::new();
        for id in ["a", "b", "c", "d"] {
            g.put_node(id, id.to_uppercase()).unwrap();
        }
        g.link("a", "b", 1).unwrap();
        g.link("b", "c", 0).unwrap();
        g.link("c", "d", 1).unwrap();

        let hits = g.pivot("a", 2);
        let got: Vec<(usize, u8, &str)> = hits
            .iter()
            .map(|h| (h.hop, h.via, h.node.as_str()))
            .collect();
        assert_eq!(got, vec![(1, 1, "B"), (2, 0, "C")]);
        assert!(g.pivot("a", 0).is_empty());
        assert!(g.pivot("nope", 5).is_empty());

        let path: Vec<&str> = g
            .shortest_path("a", "d")
            .expect("connected")
            .iter()
            .map(|n| n.as_str())
            .collect();
        assert_eq!(path, vec!["A", "B", "C", "D"]);
        assert_eq!(g.shortest_path("a", "a").map(|p| p.len()), Some(1));
        assert!(g.shortest_path("a", "ghost").is_none());
    }

    #[test]
    fn disconnected_has_no_path() {
        let mut g: MemGraph<String, ()> = MemGraph::new();
        for id in ["a", "b", "x", "y"] {
            g.put_node(id, id.into()).unwrap();
        }
        g.link("a", "b", ()).unwrap();
        g.link("x", "y", ()).unwrap();
        assert!(g.shortest_path("a", "y").is_none());
        assert!(g.pivot("a", 9).iter().all(|h| h.node != "y"));
    }

    #[test]
    fn undirected_edges_and_edges_among() {
        let mut g: MemGraph<(), u8> = MemGraph::new();
        for id in ["a", "b", "c"] {
            g.put_node(id, ()).unwrap();
        }
        g.link("a", "b", 1).unwrap();
        g.link("b", "c", 0).unwrap();
        assert_eq!(
            g.undirected_edges(),
            vec![(s("a"), s("b"), 1), (s("b"), s("c"), 0)],
            "each undirected edge must appear exactly once, a<b"
        );
        let subset: BTreeSet<String> = [s("b"), s("c")].into_iter().collect();
        assert_eq!(g.edges_among(&subset), vec![(s("b"), s("c"), 0)]);
        // The directed BulkGraph view keeps both directions.
        assert_eq!(BulkGraph::edges(&g).len(), 4);
    }
}
