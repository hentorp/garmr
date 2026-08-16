//! [`CozoGraph`] — an embedded-Datalog [`GraphQuery`] / [`GraphStore`] backed by
//! CozoDB (behind the off-by-default `cozo` feature).
//!
//! This is a MOVE of a working implementation, not a rewrite: the storage layout,
//! the merge rule and the `pivot` Datalog are the ones that were already running in
//! a detection product, lifted here and made **generic over the domain** so the
//! backend lives in one place and every consumer instantiates it with its own node
//! payload and edge label. Two things changed, both deliberate and both stated:
//!
//! 1. **Generic payload.** The original stored `(id, kind, name, label)` columns
//!    for its own node type. A domain-neutral backend cannot know those columns, so
//!    the Cozo side stores ids + the labelled adjacency and the PAYLOADS are
//!    mirrored in a Rust map — which the original already did anyway, because
//!    [`GraphQuery`] hands back `&Self::Node` and the columns it wrote were never
//!    read back. Cozo owns the *traversal*; the mirror is the payload
//!    materialization the borrow-returning API needs.
//! 2. **`ShortestPathBFS` is gone.** The original delegated `shortest_path` to
//!    cozo's built-in `ShortestPathBFS` fixed rule, which lives behind cozo's
//!    `graph-algo` feature. [`shortest_path`](CozoGraph::shortest_path) is now
//!    written out instead — it is EXACTLY the in-memory BFS driven off
//!    Cozo-answered reachability, so it agrees with [`MemGraph`](crate::MemGraph)
//!    tie-for-tie rather than merely claiming to.
//!
//! # ⚠ rayon
//!
//! This feature puts rayon in the dependency tree, and that is a measured fact
//! rather than a choice: cozo 0.7.6 declares `rayon` optional (only `graph-algo`
//! turns it on) but uses `rayon::spawn` and `par_iter` UNCONDITIONALLY in its own
//! source, so it does not compile without it. See the extended note on the `cozo`
//! dependency line in `Cargo.toml` for the exact compiler errors. The feature is
//! OFF by default and no crate in this workspace enables it, so no default build
//! gains rayon; none of the code in this module calls rayon; and dropping
//! `graph-algo` becomes possible the moment cozo gates its own use of it.
//!
//! # Storage layout
//!
//! Two Cozo stored relations:
//!
//! * `node {id}` — one row per node id. Ids only: payloads are opaque to this crate.
//! * `edge {src, dst => kind}` — the labelled adjacency, DIRECTED. An undirected
//!   consumer records both directions via [`GraphStore::link`], exactly as the
//!   in-memory backend does. `kind` is [`EdgeLabel::encode`]'s `i64`, so a numeric
//!   comparison reproduces the label's own `Ord` and the "stronger link wins" merge.
//!
//! # Provenance (`via`) note — carried over unchanged
//!
//! The in-memory `pivot` reports `via` = the label of the edge that *first* reached
//! each node in BFS visitation order. Datalog is set-oriented, so [`CozoGraph::pivot`]
//! resolves `via` deterministically as the `min` label among the node's
//! shortest-path predecessor edges. On a realistic graph — where a given node pair
//! carries a single strongest provenance — the two agree; they can only differ when
//! a node is reached at its minimum hop by two predecessors carrying *different*
//! labels in the same BFS layer, where the in-memory answer is itself
//! traversal-order dependent. Hop distance and the reached-node set always match.

use std::collections::{BTreeMap, BTreeSet};
use std::marker::PhantomData;

use cozo::{DataValue, DbInstance, ScriptMutability};

use crate::{EdgeLabel, GraphQuery, GraphStore, Hit};

/// This backend's failure type, re-exported so a CONSUMER never has to name the
/// `cozo` crate itself. That is the point of centralising the backend here: a
/// consumer depends on `nornir-graph` and turns on its `cozo` feature, and the
/// database crate stays an implementation detail of this module.
pub type CozoError = cozo::Error;

/// A CozoDB-backed graph: the adjacency and the traversal live in an embedded,
/// in-process, pure-Rust Cozo `mem` database; the node payloads are mirrored in a
/// Rust map so the borrow-returning [`GraphQuery`] surface can be satisfied.
///
/// Generic in the payload `N` and the label `L`, so this crate never learns a
/// consumer's domain — a detection product instantiates
/// `CozoGraph<MyNode, MyEdgeKind>`, a release tool `CozoGraph<(), ()>`.
pub struct CozoGraph<N, L = ()> {
    db: DbInstance,
    /// Node payloads, mirrored so the borrow-returning API can hand back `&N` with
    /// the same shape as the in-memory backend.
    nodes: BTreeMap<String, N>,
    _label: PhantomData<L>,
}

impl<N, L> CozoGraph<N, L> {
    /// Create an empty graph backed by a fresh in-memory Cozo database.
    pub fn new() -> Result<Self, cozo::Error> {
        let db = DbInstance::new("mem", "", "")?;
        db.run_script(
            ":create node {id: String}",
            BTreeMap::new(),
            ScriptMutability::Mutable,
        )?;
        db.run_script(
            ":create edge {src: String, dst: String => kind: Int}",
            BTreeMap::new(),
            ScriptMutability::Mutable,
        )?;
        Ok(Self {
            db,
            nodes: BTreeMap::new(),
            _label: PhantomData,
        })
    }

    fn run(
        &self,
        script: &str,
        params: BTreeMap<String, DataValue>,
        mutable: bool,
    ) -> Result<cozo::NamedRows, cozo::Error> {
        let m = if mutable {
            ScriptMutability::Mutable
        } else {
            ScriptMutability::Immutable
        };
        self.db.run_script(script, params, m)
    }

    /// Every node payload, in id order.
    pub fn payloads(&self) -> impl Iterator<Item = &N> {
        self.nodes.values()
    }

    /// Every `(id, payload)` pair, in id order.
    pub fn entries(&self) -> impl Iterator<Item = (&String, &N)> {
        self.nodes.iter()
    }

    /// Sorted out-neighbour ids of `id`, straight out of the `edge` relation.
    fn out_ids(&self, id: &str) -> Vec<String> {
        let rows = self
            .run(
                "?[dst] := *edge{src: $s, dst}",
                BTreeMap::from([("s".to_string(), DataValue::from(id))]),
                false,
            )
            .expect("cozo neighbour query")
            .rows;
        let mut out: Vec<String> = rows
            .iter()
            .filter_map(|r| r[0].get_str().map(str::to_string))
            .collect();
        out.sort();
        out
    }

    /// `node → minimum hop distance from start`, computed by a recursive Datalog
    /// meet(min) aggregation run to fixpoint.
    fn distances(&self, start: &str) -> BTreeMap<String, usize> {
        let script = "\
            sd[node, min(dist)] := node = $start, dist = 0\n\
            sd[node, min(dist)] := sd[prev, pd], *edge{src: prev, dst: node}, dist = pd + 1\n\
            ?[node, dist] := sd[node, dist]";
        let params = BTreeMap::from([("start".to_string(), DataValue::from(start))]);
        let rows = self
            .run(script, params, false)
            .expect("cozo distance query")
            .rows;
        rows.iter()
            .filter_map(|r| {
                let id = r[0].get_str()?.to_string();
                let d = r[1].get_int()? as usize;
                Some((id, d))
            })
            .collect()
    }
}

impl<N, L> Default for CozoGraph<N, L> {
    /// Panics if the embedded database cannot be created — use [`CozoGraph::new`]
    /// when you want to handle that.
    fn default() -> Self {
        Self::new().expect("in-memory cozo database")
    }
}

impl<N, L: EdgeLabel> GraphQuery for CozoGraph<N, L> {
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
        let rows = self
            .run(
                "?[dst, kind] := *edge{src: $s, dst, kind}",
                BTreeMap::from([("s".to_string(), DataValue::from(id))]),
                false,
            )
            .expect("cozo neighbour query")
            .rows;
        let mut out: Vec<(String, L)> = rows
            .iter()
            .filter_map(|r| {
                let dst = r[0].get_str()?.to_string();
                Some((dst, L::decode(r[1].get_int()?)))
            })
            .collect();
        out.sort_by(|a, b| a.0.cmp(&b.0));
        out
    }

    /// Bounded-reachability pivot as a **recursive Datalog query**: each reached
    /// node's minimum hop distance via a meet(min) aggregation, with `via` = the
    /// `min` label among the edges from a predecessor exactly one hop closer.
    ///
    /// Results are ordered by `(hop, node id)` — deterministic, but note this is
    /// *not* the in-memory backend's raw BFS visitation order (the reached SET and
    /// each node's hop/`via` are what match; see the module docs). A node with no
    /// mirrored payload is skipped, exactly as in-memory.
    fn pivot(&self, start: &str, depth: usize) -> Vec<Hit<'_, N, L>> {
        if depth == 0 || !self.nodes.contains_key(start) {
            return Vec::new();
        }
        let script = "\
            sd[node, min(dist)] := node = $start, dist = 0\n\
            sd[node, min(dist)] := sd[prev, pd], *edge{src: prev, dst: node}, dist = pd + 1, dist <= $depth\n\
            via[node, min(kind)] := sd[node, d], d > 0, sd[prev, pd], pd = d - 1, *edge{src: prev, dst: node, kind}\n\
            ?[node, dist, kind] := sd[node, dist], node != $start, via[node, kind]\n\
            :order dist\n\
            :order node";
        let params = BTreeMap::from([
            ("start".to_string(), DataValue::from(start)),
            ("depth".to_string(), DataValue::from(depth as i64)),
        ]);
        let rows = self
            .run(script, params, false)
            .expect("cozo pivot query")
            .rows;

        let mut out = Vec::with_capacity(rows.len());
        for row in &rows {
            let id = row[0].get_str().expect("pivot node id is a string");
            let hop = row[1].get_int().expect("pivot hop is an int") as usize;
            let via = L::decode(row[2].get_int().expect("pivot label is an int"));
            if let Some(node) = self.nodes.get(id) {
                out.push(Hit { hop, via, node });
            }
        }
        out
    }

    /// Shortest path between two nodes (inclusive), or `None` if either is unknown
    /// or they are disconnected.
    ///
    /// # Why this is written out rather than delegated to a fixed rule
    ///
    /// Cozo ships a `ShortestPathBFS` fixed rule, but it lives behind cozo's
    /// `graph-algo` feature, and `graph-algo` pulls **rayon** (via `graph` +
    /// `graph_builder`) — forbidden. So the search runs here, and running it here
    /// buys a guarantee the fixed rule only *claimed*: it is LITERALLY the
    /// in-memory backend's algorithm, so the two agree tie-for-tie.
    ///
    /// * Cozo answers the reachability half — one recursive Datalog query returns
    ///   the minimum hop distance of every node reachable from `a`. That is where
    ///   the engine earns its keep, and it settles disconnection immediately.
    /// * The predecessor half then replays the in-memory BFS's exact discovery
    ///   order: layer by layer, parents in the order they were themselves
    ///   discovered, each parent's neighbours in sorted id order, first parent to
    ///   reach a node wins. Adjacency for each parent comes from Cozo. Only the
    ///   layers up to the target are walked.
    fn shortest_path(&self, a: &str, b: &str) -> Option<Vec<&N>> {
        if !self.nodes.contains_key(a) || !self.nodes.contains_key(b) {
            return None;
        }
        if a == b {
            return self.nodes.get(a).map(|n| vec![n]);
        }
        let dist = self.distances(a);
        let target_d = *dist.get(b)?; // unreachable ⇒ disconnected ⇒ None

        // Replay the in-memory BFS's discovery order to get the SAME predecessors.
        let mut prev: BTreeMap<String, String> = BTreeMap::new();
        let mut assigned: BTreeSet<String> = BTreeSet::new();
        assigned.insert(a.to_string());
        let mut layer: Vec<String> = vec![a.to_string()];
        for d in 1..=target_d {
            let mut next: Vec<String> = Vec::new();
            for parent in &layer {
                for nb in self.out_ids(parent) {
                    if dist.get(&nb) == Some(&d) && assigned.insert(nb.clone()) {
                        prev.insert(nb.clone(), parent.clone());
                        next.push(nb);
                    }
                }
            }
            layer = next;
        }

        let mut path = Vec::new();
        let mut cur = b.to_string();
        loop {
            path.push(self.nodes.get(&cur)?);
            if cur == a {
                break;
            }
            cur = prev.get(&cur)?.clone();
        }
        path.reverse();
        Some(path)
    }
}

impl<N, L: EdgeLabel> GraphStore for CozoGraph<N, L> {
    type Error = CozoError;

    fn put_node(&mut self, id: &str, node: N) -> Result<(), CozoError> {
        self.run(
            "?[id] <- [[$id]] :put node {id}",
            BTreeMap::from([("id".to_string(), DataValue::from(id))]),
            true,
        )?;
        self.nodes.insert(id.to_string(), node);
        Ok(())
    }

    /// Add/strengthen a DIRECTED edge — a stronger label wins and is never
    /// downgraded, exactly like the in-memory backend. Implemented as a read of the
    /// current label followed by a `:put`.
    fn add_edge(&mut self, from: &str, to: &str, label: L) -> Result<(), CozoError> {
        let existing = self.run(
            "?[k] := *edge{src: $a, dst: $b, kind: k}",
            BTreeMap::from([
                ("a".to_string(), DataValue::from(from)),
                ("b".to_string(), DataValue::from(to)),
            ]),
            false,
        )?;
        // Merge by the LABEL's own Ord, not by raw code order, so a consumer whose
        // codec is not monotone still gets "the stronger link wins".
        let merged = match existing.rows.first().and_then(|r| r[0].get_int()) {
            Some(c) => L::decode(c).max(label).encode(),
            None => label.encode(),
        };
        self.run(
            "?[src, dst, kind] <- [[$a, $b, $k]] :put edge {src, dst => kind}",
            BTreeMap::from([
                ("a".to_string(), DataValue::from(from)),
                ("b".to_string(), DataValue::from(to)),
                ("k".to_string(), DataValue::from(merged)),
            ]),
            true,
        )?;
        Ok(())
    }
}
