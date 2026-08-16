//! The **QUERY** shape — [`GraphQuery`] and its mutation half [`GraphStore`]: ask
//! the store a bounded, local question and let the store's own engine answer it.
//!
//! Nothing here materialises the graph. `pivot` is a *bounded* neighbourhood and
//! `shortest_path` is a *targeted* search, so a Datalog / Cypher / indexed backend
//! can answer both by touching only the region involved. That is precisely what
//! [`BulkGraph`](crate::BulkGraph) cannot promise, and why the two shapes are two
//! traits.
//!
//! # The borrowed-return decision
//!
//! [`GraphQuery::node`], [`GraphQuery::pivot`] and [`GraphQuery::shortest_path`]
//! hand back `&Self::Node` — BORROWED from the store, not owned.
//!
//! * **Why.** The consumers that motivated this trait pivot over a graph and then
//!   walk the hits repeatedly (risk ranking, rendering, path display). Returning
//!   owned payloads would clone every reached node on every query, on the hot path,
//!   for callers that overwhelmingly only read. `Cow` would push that decision onto
//!   every call site and infect the result types with a lifetime anyway.
//! * **What it costs.** An implementor MUST own its payloads for as long as `&self`
//!   lives. A backend that streams payloads out of a remote store per query cannot
//!   satisfy this without caching them first — which is exactly what
//!   [`CozoGraph`](crate::CozoGraph) does: Cozo owns the *traversal*, and a payload
//!   mirror satisfies the borrow. A future backend that genuinely cannot hold
//!   payloads should grow a sibling owned-return trait rather than force every
//!   existing caller to clone.
//!
//! The label rides in [`Hit::via`] BY VALUE, because
//! [`EdgeLabel`](crate::EdgeLabel) is `Copy` — no borrow, no allocation.

use crate::EdgeLabel;

/// One neighbourhood hit: a reachable node, its hop distance from the pivot start,
/// and the provenance of the edge that reached it.
///
/// Generic in both the payload `N` and the label `L` so this crate never learns a
/// consumer's domain: a consumer whose nodes are `MyNode` and whose edges are
/// `MyKind` gets back a `Hit<'_, MyNode, MyKind>` whose fields are exactly
/// `{ hop, via: MyKind, node: &MyNode }`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Hit<'a, N, L> {
    /// Hop distance from the pivot start (never 0 — the start is excluded).
    pub hop: usize,
    /// Provenance of the edge that reached this node.
    pub via: L,
    /// The node payload, borrowed from the store.
    pub node: &'a N,
}

/// The backend-agnostic QUERY graph: bounded, local reads.
pub trait GraphQuery {
    /// The node PAYLOAD type. `()` when ids are all there is. The trait only ever
    /// hands back `Option<&Self::Node>` / `&Self::Node`, so the payload stays
    /// entirely the consumer's — this crate never constructs or inspects one.
    type Node;
    /// Domain-owned edge provenance.
    type Label: EdgeLabel;

    /// Whether a node id is present.
    fn contains(&self, id: &str) -> bool;

    /// The payload of a node id, borrowed from the store.
    fn node(&self, id: &str) -> Option<&Self::Node>;

    /// How many nodes the store holds.
    fn node_count(&self) -> usize;

    /// A node's out-neighbours with the strongest recorded label for each, sorted
    /// by neighbour id. Empty for an unknown id (never an error — an absent node
    /// simply has no neighbourhood).
    fn neighbours(&self, id: &str) -> Vec<(String, Self::Label)>;

    /// A node's out-degree. Default: the length of [`neighbours`](Self::neighbours);
    /// override when the backend can count without materialising them.
    fn degree(&self, id: &str) -> usize {
        self.neighbours(id).len()
    }

    /// Bounded-reachability pivot: everything reachable from `start` within `depth`
    /// hops, EXCLUDING `start`. `via` is the provenance of the edge that reached
    /// each node at its minimum hop.
    ///
    /// `depth == 0` and an unknown `start` both yield an empty result.
    fn pivot(&self, start: &str, depth: usize) -> Vec<Hit<'_, Self::Node, Self::Label>>;

    /// Shortest path between two nodes INCLUSIVE of both ends, or `None` if either
    /// is unknown or they are disconnected. `a == b` yields the single-node path.
    fn shortest_path(&self, a: &str, b: &str) -> Option<Vec<&Self::Node>>;
}

/// The mutation half of the QUERY shape, split out so a read-only view of a store
/// can implement [`GraphQuery`] alone.
///
/// `Error` is associated because a backend's failure mode is its own: the in-memory
/// store cannot fail ([`Infallible`](std::convert::Infallible)), an embedded
/// database returns its own error type.
pub trait GraphStore: GraphQuery {
    /// This backend's write failure.
    type Error;

    /// Insert or replace the payload at `id`. Idempotent on the id.
    fn put_node(&mut self, id: &str, node: Self::Node) -> Result<(), Self::Error>;

    /// Add a DIRECTED edge `from → to`. If the pair already carries a label, the
    /// stronger of the two wins (`max`) and is never downgraded.
    fn add_edge(&mut self, from: &str, to: &str, label: Self::Label) -> Result<(), Self::Error>;

    /// Add an UNDIRECTED edge — [`add_edge`](Self::add_edge) in both directions, so
    /// a traversal that follows out-edges reaches either end from the other. A
    /// self-link (`a == b`) is a no-op.
    fn link(&mut self, a: &str, b: &str, label: Self::Label) -> Result<(), Self::Error> {
        if a == b {
            return Ok(());
        }
        self.add_edge(a, b, label)?;
        self.add_edge(b, a, label)
    }
}
