// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! `cozo_graph` — garmr's CozoDB-backed entity graph (behind the `cozo` cargo
//! feature).
//!
//! # The implementation is not here any more
//!
//! The CozoDB backend MOVED to the shared `nornir-graph` seam, which owns every
//! graph-database implementation and is generic over the node payload and the edge
//! label. garmr instantiates it with its own [`Node`] and [`EdgeKind`]:
//!
//! ```text
//! nornir_graph::CozoGraph<Node, EdgeKind>
//! ```
//!
//! so this file is now only the thin domain wrapper — the `from_graph` mirror and
//! the `ensure_node(kind, name)` entity constructor, both of which are about
//! garmr's model, not about Cozo. There is no `cozo::` call anywhere in garmr any
//! more, and no `cozo` crate dependency in this manifest; the seam's off-by-default
//! `cozo` feature is what turns the backend on.
//!
//! # What it still is
//!
//! A drop-in twin of the in-memory [`Graph`](crate::Graph): the same typed nodes and
//! per-edge provenance, the same `pivot` / `shortest_path` result shapes
//! ([`Hit`], `Vec<&Node>`). The difference is where the traversal runs — the
//! reachability (`pivot`) is a bounded recursive Datalog query inside an embedded,
//! in-process Cozo `mem` database, no external service. Both types implement the
//! seam's `GraphQuery`, which is what makes "drop-in" a checked property rather
//! than a claim.
//!
//! ## Two behaviour notes, both carried over from the original
//!
//! * **`via` provenance.** The in-memory `pivot` reports `via` = the provenance of
//!   the edge that *first* reached each node in BFS visitation order. Datalog is
//!   set-oriented, so the Cozo pivot resolves `via` as the `min` edge kind among the
//!   node's shortest-path predecessor edges. On the realistic graph — where a given
//!   entity pair carries a single strongest provenance — the two agree; they can
//!   only differ when a node is reached at its minimum hop by two predecessors
//!   carrying *different* provenance in the same BFS layer, where the in-memory
//!   answer is itself traversal-order dependent. Hop distance and the reached-node
//!   set always match.
//! * **`shortest_path`.** The seam no longer delegates to Cozo's `ShortestPathBFS`
//!   fixed rule; it runs the in-memory BFS's own algorithm over Cozo-answered
//!   reachability. That makes the two backends agree tie-for-tie by construction
//!   rather than by coincidence of queue discipline.

use garmr_core::Case;
use nornir_graph::{CozoError, GraphQuery, GraphStore};

use crate::model::{EdgeKind, Hit, Node};

/// The seam's CozoDB backend instantiated with garmr's domain types.
type Backend = nornir_graph::CozoGraph<Node, EdgeKind>;

/// A CozoDB-backed entity graph — the same node/edge model and pivot /
/// shortest-path semantics as [`Graph`](crate::Graph), traversed with embedded
/// Datalog instead of the in-memory BFS.
pub struct CozoGraph {
    inner: Backend,
}

impl CozoGraph {
    /// Create an empty graph backed by a fresh in-memory Cozo database.
    pub fn new() -> Result<Self, CozoError> {
        Ok(Self {
            inner: Backend::new()?,
        })
    }

    /// Mirror an existing in-memory [`Graph`](crate::Graph) into a `CozoGraph`
    /// — every node and every (undirected, strongest-provenance) edge. Lets a
    /// caller build with the ergonomic in-memory builders (`from_cases`,
    /// `add_event_edges`, …) and then run the traversal in Cozo.
    pub fn from_graph(g: &crate::Graph) -> Result<Self, CozoError> {
        let mut cg = Self::new()?;
        for node in g.all_nodes() {
            cg.inner.put_node(&node.id.clone(), node.clone())?;
        }
        for (a, b, kind) in g.all_edges() {
            cg.link(&a, &b, kind)?;
        }
        Ok(cg)
    }

    /// Build straight from the case set, mirroring
    /// [`Graph::from_cases`](crate::Graph::from_cases).
    pub fn from_cases(cases: &[Case]) -> Result<Self, CozoError> {
        Self::from_graph(&crate::Graph::from_cases(cases))
    }

    /// Ensure an entity node exists (created with `label = name`, no meta, if
    /// absent). Mirrors [`Graph::ensure_node`](crate::Graph::ensure_node).
    pub fn ensure_node(&mut self, kind: &str, name: &str) -> Result<(), CozoError> {
        let name = name.trim();
        if name.is_empty() {
            return Ok(());
        }
        let id = crate::node_id(kind, name);
        if self.inner.contains(&id) {
            return Ok(());
        }
        let node = Node {
            id: id.clone(),
            kind: kind.to_string(),
            name: name.to_string(),
            label: name.to_string(),
            meta: std::collections::BTreeMap::new(),
        };
        self.inner.put_node(&id, node)
    }

    /// Add/strengthen an undirected edge between two node ids — a stronger kind
    /// (`case`) wins and is never downgraded, exactly like
    /// [`Graph`](crate::Graph).
    pub fn link(&mut self, a: &str, b: &str, kind: EdgeKind) -> Result<(), CozoError> {
        self.inner.link(a, b, kind)
    }

    /// Whether a node id is present.
    pub fn contains(&self, id: &str) -> bool {
        self.inner.contains(id)
    }

    /// Look up a node payload.
    pub fn node(&self, id: &str) -> Option<&Node> {
        self.inner.node(id)
    }

    /// Bounded-reachability pivot: everything reachable from `start` within
    /// `depth` hops (excluding `start`), as [`Hit`]s. Same shape as
    /// [`Graph::pivot`](crate::Graph::pivot).
    ///
    /// Results are ordered by `(hop, node id)` — deterministic, but note this is
    /// *not* the in-memory graph's raw BFS visitation order (the reached set and
    /// each node's hop/`via` are what match; see the module docs).
    pub fn pivot(&self, start: &str, depth: usize) -> Vec<Hit<'_>> {
        self.inner.pivot(start, depth)
    }

    /// Shortest undirected path between two nodes (inclusive), or `None` if
    /// either is unknown or they are disconnected. Same shape as
    /// [`Graph::shortest_path`](crate::Graph::shortest_path).
    pub fn shortest_path(&self, a: &str, b: &str) -> Option<Vec<&Node>> {
        self.inner.shortest_path(a, b)
    }
}

/// The Cozo graph satisfies the SAME seam as the in-memory one, which is what makes
/// the two genuinely interchangeable.
impl GraphQuery for CozoGraph {
    type Node = Node;
    type Label = EdgeKind;

    fn contains(&self, id: &str) -> bool {
        self.inner.contains(id)
    }
    fn node(&self, id: &str) -> Option<&Node> {
        self.inner.node(id)
    }
    fn node_count(&self) -> usize {
        self.inner.node_count()
    }
    fn neighbours(&self, id: &str) -> Vec<(String, EdgeKind)> {
        self.inner.neighbours(id)
    }
    fn pivot(&self, start: &str, depth: usize) -> Vec<Hit<'_>> {
        self.inner.pivot(start, depth)
    }
    fn shortest_path(&self, a: &str, b: &str) -> Option<Vec<&Node>> {
        self.inner.shortest_path(a, b)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use garmr_core::{Case, Detection, Event};

    use super::*;
    use crate::{node_id, Graph, KIND_HOST, KIND_IP};

    fn case(id: &str, rule: &str, host: &str, ip: &str, user: &str) -> Case {
        let mut fields = BTreeMap::new();
        if !ip.is_empty() {
            fields.insert("src_ip".to_string(), ip.to_string());
        }
        if !user.is_empty() {
            fields.insert("user".to_string(), user.to_string());
        }
        let mut c = Case::open(Detection {
            rule_id: rule.into(),
            rule_title: "t".into(),
            level: "medium".into(),
            attack: vec![],
            event: Event {
                ts: chrono::Utc::now(),
                host: host.into(),
                service: "sshd".into(),
                source: "journald".into(),
                environment: "test".into(),
                severity: "warning".into(),
                log_type: "system".into(),
                message: "m".into(),
                fields,
            },
            observed_at: chrono::Utc::now(),
            realert_secs: None,
        });
        c.id = id.into();
        c
    }

    /// `(id, hop, via)` triples of a pivot, sorted — an order-independent
    /// fingerprint to compare the two graph backends.
    fn pivot_key(hits: &[Hit<'_>]) -> Vec<(String, usize, EdgeKind)> {
        let mut v: Vec<_> = hits
            .iter()
            .map(|h| (h.node.id.clone(), h.hop, h.via))
            .collect();
        v.sort();
        v
    }

    #[test]
    fn cozo_pivot_matches_in_memory_graph() {
        // Fixture with mixed provenance and hop depths: one case ties ip↔pve
        // (through the case node) and links user:root; a raw event ties ip↔njord
        // directly. Every reached node has a single incoming provenance at its
        // minimum hop, so the `via` comparison is unambiguous.
        let mut g = Graph::from_cases(&[case("c1", "r", "pve", "203.0.113.7", "root")]);
        g.add_event_edges(&[("njord".into(), "203.0.113.7".into(), "".into())]);
        let cg = CozoGraph::from_graph(&g).expect("mirror into cozo");

        let ip = node_id(KIND_IP, "203.0.113.7");
        for depth in [1usize, 2, 3] {
            assert_eq!(
                pivot_key(&g.pivot(&ip, depth)),
                pivot_key(&cg.pivot(&ip, depth)),
                "pivot mismatch at depth {depth}"
            );
        }
        // Sanity: the fixture actually exercises both provenance kinds.
        let keys = pivot_key(&cg.pivot(&ip, 2));
        assert!(keys.iter().any(|(_, _, k)| *k == EdgeKind::Event));
        assert!(keys.iter().any(|(_, _, k)| *k == EdgeKind::Case));
        // depth 0 and unknown start are both empty, like the in-memory graph.
        assert!(cg.pivot(&ip, 0).is_empty());
        assert!(cg.pivot("ip:0.0.0.0", 3).is_empty());
    }

    #[test]
    fn cozo_shortest_path_matches_in_memory_graph() {
        // Two cases share an IP: the unique shortest path pve → c1 → ip → c2 →
        // njord has length 5.
        let g = Graph::from_cases(&[
            case("c1", "r", "pve", "203.0.113.7", ""),
            case("c2", "r", "njord", "203.0.113.7", ""),
        ]);
        let cg = CozoGraph::from_graph(&g).expect("mirror into cozo");

        let pve = node_id(KIND_HOST, "pve");
        let njord = node_id(KIND_HOST, "njord");

        let mem = g.shortest_path(&pve, &njord).expect("in-memory path");
        let cozo = cg.shortest_path(&pve, &njord).expect("cozo path");
        let ids = |p: &[&Node]| p.iter().map(|n| n.id.clone()).collect::<Vec<_>>();
        assert_eq!(ids(&mem), ids(&cozo), "shortest path differs");
        assert_eq!(cozo.len(), 5);

        // Same node returns a single-element path; unknown / disconnected → None.
        assert_eq!(cg.shortest_path(&pve, &pve).map(|p| p.len()), Some(1));
        assert!(cg.shortest_path(&pve, "host:ghost").is_none());
    }

    #[test]
    fn cozo_disconnected_is_none_like_in_memory() {
        let g = Graph::from_cases(&[
            case("c1", "r", "pve", "1.1.1.1", ""),
            case("c2", "r", "njord", "2.2.2.2", ""),
        ]);
        let cg = CozoGraph::from_graph(&g).expect("mirror into cozo");
        let pve = node_id(KIND_HOST, "pve");
        let njord = node_id(KIND_HOST, "njord");
        assert!(g.shortest_path(&pve, &njord).is_none());
        assert!(cg.shortest_path(&pve, &njord).is_none());
    }
}
