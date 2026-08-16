//! `nornir-graph` — the constellation's **ONE graph seam**: two traits, the pure
//! graph math behind them, and every graph-database backend that answers them.
//!
//! # Why TWO traits and not one
//!
//! A graph is asked two genuinely different kinds of question, and a single trait
//! covering both forces a bad implementation on one side:
//!
//! * **BULK** — [`BulkGraph`]: *hand over everything*. `nodes()` + `edges()`, and
//!   the whole-graph algorithms (SCC, topological order, reachability closure) fall
//!   out as pure, deterministic DEFAULT methods computed once, here. This is the
//!   shape the release doctor wants: it genuinely needs the entire publish-order
//!   graph in hand to answer "what are the cycles?" and "what is the publish order?".
//! * **QUERY** — [`GraphQuery`]: *ask the store, never materialise it*.
//!   `contains` / `node` / `neighbours` / `pivot` / `shortest_path` — bounded,
//!   local questions answered by the backend's own engine (Datalog recursion,
//!   Cypher, an index scan) touching only the region involved.
//!
//! Collapsing these into one trait would mean an Iceberg- or Cozo-backed store has
//! to materialise the entire graph to answer a one-node question. That is not
//! hypothetical: the constellation's `call_edges` table is ~2.3 GB. So a backend
//! implements whichever shape it can serve honestly, and may implement both —
//! [`MemGraph`] does, because it already holds everything in memory anyway.
//!
//! [`GraphStore`] is the mutation half of the QUERY shape, split out so a
//! read-only view of a store can implement [`GraphQuery`] alone.
//!
//! # Domain neutrality is a hard constraint
//!
//! Nothing in this crate names a crate, a symbol, a device, a case or a CVE. A node
//! is an **opaque string id**. Two knobs let a consumer carry its own domain
//! WITHOUT this crate learning about it:
//!
//! * [`GraphQuery::Node`] — an associated type for the node PAYLOAD. A release
//!   consumer sets it to `()` (ids are all there is); a detection consumer sets it
//!   to its own typed node struct. The trait only ever hands back
//!   `Option<&Self::Node>`, so the payload type stays entirely the consumer's.
//! * [`EdgeLabel`] — edges carry a label as an associated type constrained to a
//!   tiny `i64` codec. `()` is the no-label case and costs nothing; a consumer with
//!   edge provenance implements [`EdgeLabel`] for its own enum in four lines and
//!   gets it back losslessly.
//!
//! ## Why a codec trait and not `Option<&str>` or a free generic
//!
//! Three shapes were on the table:
//!
//! | shape | cost |
//! |---|---|
//! | `Option<String>` label | an allocation per edge on every read, and every consumer parses its own enum back out of a string at the boundary — the exact stringly-typed seam that loses information silently when a variant is renamed |
//! | free generic `L` with no bound | a database backend cannot store it: there is no way to get `L` into a column and back |
//! | [`EdgeLabel`] (chosen) | `Copy + Ord + Default` plus [`encode`](EdgeLabel::encode)/[`decode`](EdgeLabel::decode) to `i64` |
//!
//! [`EdgeLabel`] is what makes the label both **domain-owned** and **storable**.
//! `Ord` is load-bearing beyond ordering: merging two labels on the same pair is
//! defined as `max` — "the stronger link wins" — which is what a consumer whose
//! labels have a strength ranking (adjudicated > incidental) needs, and which is a
//! no-op for `()`. `Default` is the weakest/unlabelled label. The price is that a
//! label must be a small enumerable value, not free-form text; a backend that wants
//! free-form edge text should carry it in the node payload or a side table.
//!
//! # Leaf discipline
//!
//! The DEFAULT build of this crate is **std only** — no dependency of any kind, so
//! a consumer that wants the seam does not inherit a stack. Every backend that
//! drags a dependency is behind an OFF-by-default feature:
//!
//! * *(default)* [`MemGraph`] — pure-std in-memory, implements both traits. Zero deps.
//! * `serde` — derives on the plain-data types.
//! * `petgraph` — [`PetGraph`], a `petgraph::DiGraph`-backed [`BulkGraph`] whose
//!   [`scc`](BulkGraph::scc) is petgraph's Tarjan. Its value is as an INDEPENDENT
//!   second implementation of the SCC math to cross-check the one in this crate.
//! * `cozo` — [`CozoGraph`], an embedded-Datalog [`GraphQuery`]/[`GraphStore`],
//!   generic over the node payload and edge label.
//!
//! There is deliberately NO FalkorDB backend: it needs a live Redis-module server,
//! and a config-holder with `// TODO` query bodies that compiles and returns an
//! empty set is worse than nothing — it is a guard that can never report red. This
//! crate exists partly to DELETE two of those.
//!
//! # Determinism
//!
//! Everything is BTree-ordered and pure. No default method performs I/O, and no
//! observable output depends on hash iteration order or on a backend's insertion
//! order.

#![forbid(unsafe_code)]

mod bulk;
mod mem;
mod query;

pub use bulk::{tarjan_scc, Adj, BulkGraph, DepGraphError};
pub use mem::{IdGraph, MemGraph};
pub use query::{GraphQuery, GraphStore, Hit};

#[cfg(feature = "petgraph")]
mod pet;
#[cfg(feature = "petgraph")]
pub use pet::PetGraph;

#[cfg(feature = "cozo")]
pub mod cozo_graph;
#[cfg(feature = "cozo")]
pub use cozo_graph::{CozoError, CozoGraph};

/// A domain-owned edge label that a graph DATABASE can store and hand back.
///
/// Implement this on your own edge-provenance enum to carry it through the seam
/// losslessly; this crate never learns what the variants mean.
///
/// * `Copy + Ord` — labels are small values, and merging two labels recorded for
///   the same node pair is defined as `max` ("the stronger link wins").
/// * `Default` — the weakest / unlabelled label, used when an edge is added with
///   no provenance.
/// * [`encode`](Self::encode) / [`decode`](Self::decode) — the round-trip through
///   an `i64` column. `decode(l.encode()) == l` MUST hold for every value, and
///   distinct labels MUST get distinct codes; the backends store only the code.
///
/// `decode` is deliberately total (no `Result`): a backend reading a code it does
/// not recognise must produce *some* label, and saturating to the nearest sensible
/// variant keeps a read path from failing on data written by a newer writer.
pub trait EdgeLabel: Copy + Ord + Default {
    /// This label as the integer a backend stores.
    fn encode(self) -> i64;
    /// The label a stored integer denotes. Total — unknown codes saturate.
    fn decode(code: i64) -> Self;
}

/// The no-label case: every edge is just `(from, to)`. Costs nothing.
impl EdgeLabel for () {
    fn encode(self) -> i64 {
        0
    }
    fn decode(_code: i64) -> Self {}
}

impl EdgeLabel for i64 {
    fn encode(self) -> i64 {
        self
    }
    fn decode(code: i64) -> Self {
        code
    }
}

impl EdgeLabel for u8 {
    fn encode(self) -> i64 {
        i64::from(self)
    }
    fn decode(code: i64) -> Self {
        code.clamp(0, i64::from(u8::MAX)) as u8
    }
}

impl EdgeLabel for bool {
    fn encode(self) -> i64 {
        i64::from(self)
    }
    fn decode(code: i64) -> Self {
        code != 0
    }
}

/// A directed edge `from → to` carrying a domain-owned [`EdgeLabel`].
///
/// The direction's MEANING is the consumer's: the release doctor reads `A → B` as
/// "A depends on B" (so B publishes first); an undirected consumer stores both
/// directions and reads either. This crate only ever follows out-edges.
#[derive(Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Edge<L = ()> {
    /// Source node id.
    pub from: String,
    /// Target node id.
    pub to: String,
    /// Domain-owned provenance. `()` for the unlabelled case.
    pub label: L,
}

impl<L: Default> Edge<L> {
    /// An unlabelled edge (`label` = [`Default`]).
    pub fn new(from: impl Into<String>, to: impl Into<String>) -> Self {
        Self {
            from: from.into(),
            to: to.into(),
            label: L::default(),
        }
    }
}

impl<L> Edge<L> {
    /// An edge carrying an explicit label.
    pub fn labelled(from: impl Into<String>, to: impl Into<String>, label: L) -> Self {
        Self {
            from: from.into(),
            to: to.into(),
            label,
        }
    }

    /// The `(from, to)` pair, dropping the label.
    pub fn pair(&self) -> (&str, &str) {
        (&self.from, &self.to)
    }
}

impl<L: Default, A: Into<String>, B: Into<String>> From<(A, B)> for Edge<L> {
    fn from((a, b): (A, B)) -> Self {
        Edge::new(a, b)
    }
}

#[cfg(test)]
mod label_tests {
    use super::*;

    /// LAW 2: the codec contract is `decode(encode(x)) == x` for EVERY value AND
    /// distinct labels get distinct codes. The second half is the one that matters
    /// — a codec that collapsed two variants onto one code would still pass a naive
    /// single-value round-trip and would silently lose provenance in the database.
    #[test]
    fn every_builtin_label_round_trips() {
        assert_eq!(<() as EdgeLabel>::decode(().encode()), ());
        for v in [0u8, 1, 2, 7, 128, 255] {
            assert_eq!(u8::decode(v.encode()), v, "u8 {v} did not round-trip");
        }
        for v in [false, true] {
            assert_eq!(bool::decode(v.encode()), v, "bool {v} did not round-trip");
        }
        for v in [i64::MIN, -1, 0, 1, i64::MAX] {
            assert_eq!(i64::decode(v.encode()), v, "i64 {v} did not round-trip");
        }
        let codes: std::collections::BTreeSet<i64> = [0u8, 1, 2, 7, 128, 255]
            .iter()
            .map(|v| v.encode())
            .collect();
        assert_eq!(
            codes.len(),
            6,
            "u8 codec collapsed distinct labels: {codes:?}"
        );
    }

    /// `Default` is the weakest label, so `max` never downgrades a real one.
    #[test]
    fn default_is_the_weakest_label() {
        assert_eq!(u8::default().max(3), 3);
        assert!(!bool::default());
    }

    #[test]
    fn edge_construction_and_pair() {
        let e: Edge<u8> = Edge::labelled("a", "b", 3);
        assert_eq!(e.pair(), ("a", "b"));
        assert_eq!(e.label, 3);
        let u: Edge<u8> = Edge::from(("x", "y"));
        assert_eq!((u.from.as_str(), u.to.as_str(), u.label), ("x", "y", 0));
    }
}
