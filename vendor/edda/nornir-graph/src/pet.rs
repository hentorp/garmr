//! [`PetGraph`] — a [`petgraph`]-backed [`BulkGraph`] (behind the off-by-default
//! `petgraph` feature).
//!
//! Its reason to exist is NOT storage — [`MemGraph`](crate::MemGraph) already does
//! that with no dependency. It is that `petgraph` carries its OWN Tarjan, so this
//! type is an **independent second implementation** of the SCC math, and the
//! cross-backend test that compares it against the one in
//! [`bulk`](crate::BulkGraph) is a real guard rather than a tautology (LAW 2: a
//! comparison against yourself can never go red).

use std::collections::BTreeMap;

use crate::{BulkGraph, Edge};

/// Nodes + `from → to` edges held in a [`petgraph`] `DiGraph`.
#[derive(Debug, Clone, Default)]
pub struct PetGraph {
    graph: petgraph::graph::DiGraph<String, ()>,
    ids: BTreeMap<String, petgraph::graph::NodeIndex>,
}

impl PetGraph {
    /// Empty graph.
    pub fn new() -> Self {
        Self::default()
    }

    /// Assemble from `(from, to)` edges; endpoints become nodes.
    pub fn from_edges<I, S>(edges: I) -> Self
    where
        I: IntoIterator<Item = (S, S)>,
        S: Into<String>,
    {
        let mut g = Self::new();
        for (a, b) in edges {
            g.add_edge(a.into(), b.into());
        }
        g
    }

    /// Ensure a node exists, returning its index (idempotent).
    pub fn add_node(&mut self, name: impl Into<String>) -> petgraph::graph::NodeIndex {
        let name = name.into();
        if let Some(&ix) = self.ids.get(&name) {
            return ix;
        }
        let ix = self.graph.add_node(name.clone());
        self.ids.insert(name, ix);
        ix
    }

    /// Add a directed edge `from → to`; both endpoints are created if absent.
    /// Duplicate edges are collapsed (idempotent on the pair).
    pub fn add_edge(&mut self, from: impl Into<String>, to: impl Into<String>) {
        let f = self.add_node(from);
        let t = self.add_node(to);
        if self.graph.find_edge(f, t).is_none() {
            self.graph.add_edge(f, t, ());
        }
    }
}

impl BulkGraph for PetGraph {
    type Label = ();

    fn nodes(&self) -> Vec<String> {
        self.graph.node_weights().cloned().collect()
    }

    fn edges(&self) -> Vec<Edge> {
        use petgraph::visit::EdgeRef;
        self.graph
            .edge_references()
            .map(|e| {
                Edge::new(
                    self.graph[e.source()].clone(),
                    self.graph[e.target()].clone(),
                )
            })
            .collect()
    }

    /// Native override: `petgraph`'s Tarjan, re-sorted for the trait's determinism
    /// contract (member-sorted components, outer vector sorted by first member).
    fn scc(&self) -> Vec<Vec<String>> {
        let mut comps: Vec<Vec<String>> = petgraph::algo::tarjan_scc(&self.graph)
            .into_iter()
            .map(|comp| {
                let mut names: Vec<String> =
                    comp.into_iter().map(|ix| self.graph[ix].clone()).collect();
                names.sort();
                names
            })
            .collect();
        comps.sort_by(|a, b| a.first().cmp(&b.first()));
        comps
    }
}
