// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! `cozo_graph` — an OPTIONAL CozoDB-backed entity graph (behind the `cozo`
//! cargo feature).
//!
//! This is a drop-in twin of the in-memory [`Graph`](crate::Graph): the same
//! typed nodes and per-edge provenance, the same `pivot` / `shortest_path`
//! result shapes ([`Hit`], `Vec<&Node>`). The difference is where the traversal
//! runs — instead of the hand-rolled BFS in the crate root, the reachability
//! (`pivot`) is a **bounded recursive Datalog query** and the path
//! (`shortest_path`) is Cozo's built-in `ShortestPathBFS` fixed rule. Both run
//! inside an embedded, in-process, pure-Rust Cozo `mem` database — no external
//! service, no C dependency (`default-features = false` in `Cargo.toml`), which
//! keeps garmr single-binary while letting the datalog engine scale the
//! traversal past the in-memory adjacency map.
//!
//! Storage layout (two Cozo stored relations):
//!
//! * `node {id => kind, name, label}` — one row per entity.
//! * `edge {src, dst => kind}` — the adjacency, stored **both directions**
//!   (`a→b` and `b→a`) so the undirected graph is a directed relation Cozo can
//!   recurse over. `kind` is `0 = event`, `1 = case`, matching [`EdgeKind`]'s
//!   ordering so a numeric `max` is the "stronger link wins" merge.
//!
//! The [`Node`] payloads are also mirrored into a Rust map so `pivot` /
//! `shortest_path` can hand back `&Node` with the exact same shape as the
//! in-memory graph. Cozo owns the *traversal*; the map is just the payload
//! materialization the borrow-returning API needs.
//!
//! ## Provenance (`via`) note
//!
//! The in-memory `pivot` reports `via` = the provenance of the edge that
//! *first* reached each node in BFS visitation order. Datalog is set-oriented,
//! so `CozoGraph::pivot` instead resolves `via` deterministically as the
//! `min` edge kind among the node's shortest-path predecessor edges. On the
//! realistic graph — where a given entity pair carries a single strongest
//! provenance — the two agree; they can only differ when a node is reached at
//! its minimum hop by two predecessors carrying *different* provenance in the
//! same BFS layer, where the in-memory answer is itself traversal-order
//! dependent. Hop distance and the reached-node set always match.

use std::collections::BTreeMap;

use cozo::{DataValue, DbInstance, ScriptMutability};

use crate::model::{EdgeKind, Hit, Node};

/// `EdgeKind` as the integer stored in Cozo (`event = 0`, `case = 1`), so a
/// numeric `max` reproduces the "stronger link wins" merge and the ordering
/// matches [`EdgeKind`]'s `Ord`.
fn kind_to_int(kind: EdgeKind) -> i64 {
    match kind {
        EdgeKind::Event => 0,
        EdgeKind::Case => 1,
    }
}

fn kind_from_int(v: i64) -> EdgeKind {
    if v >= 1 {
        EdgeKind::Case
    } else {
        EdgeKind::Event
    }
}

/// A CozoDB-backed entity graph — the same node/edge model and pivot /
/// shortest-path semantics as [`Graph`](crate::Graph), traversed with embedded
/// Datalog instead of a hand-rolled BFS.
pub struct CozoGraph {
    db: DbInstance,
    /// Node payloads, mirrored so the borrow-returning API can hand back
    /// `&Node` with the same shape as the in-memory graph.
    nodes: BTreeMap<String, Node>,
}

impl CozoGraph {
    /// Create an empty graph backed by a fresh in-memory Cozo database.
    pub fn new() -> Result<Self, cozo::Error> {
        let db = DbInstance::new("mem", "", "")?;
        db.run_script(
            ":create node {id: String => kind: String, name: String, label: String}",
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
        })
    }

    /// Mirror an existing in-memory [`Graph`](crate::Graph) into a `CozoGraph`
    /// — every node and every (undirected, strongest-provenance) edge. Lets a
    /// caller build with the ergonomic in-memory builders (`from_cases`,
    /// `add_event_edges`, …) and then run the traversal in Cozo.
    pub fn from_graph(g: &crate::Graph) -> Result<Self, cozo::Error> {
        let mut cg = Self::new()?;
        for node in g.all_nodes() {
            cg.insert_node(node)?;
        }
        for (a, b, kind) in g.all_edges() {
            cg.link(&a, &b, kind)?;
        }
        Ok(cg)
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

    /// Put a full [`Node`] — mirrors it into the payload map and `:put`s its
    /// `(id, kind, name, label)` into the `node` relation.
    fn insert_node(&mut self, node: &Node) -> Result<(), cozo::Error> {
        let params = BTreeMap::from([
            ("id".to_string(), DataValue::from(node.id.as_str())),
            ("kind".to_string(), DataValue::from(node.kind.as_str())),
            ("name".to_string(), DataValue::from(node.name.as_str())),
            ("label".to_string(), DataValue::from(node.label.as_str())),
        ]);
        self.run(
            "?[id, kind, name, label] <- [[$id, $kind, $name, $label]] \
             :put node {id => kind, name, label}",
            params,
            true,
        )?;
        self.nodes.insert(node.id.clone(), node.clone());
        Ok(())
    }

    /// Ensure an entity node exists (created with `label = name`, no meta, if
    /// absent). Mirrors [`Graph::ensure_node`](crate::Graph::ensure_node) —
    /// implemented as a `:put` transaction.
    pub fn ensure_node(&mut self, kind: &str, name: &str) -> Result<(), cozo::Error> {
        let name = name.trim();
        if name.is_empty() {
            return Ok(());
        }
        let id = crate::node_id(kind, name);
        if self.nodes.contains_key(&id) {
            return Ok(());
        }
        let node = Node {
            id,
            kind: kind.to_string(),
            name: name.to_string(),
            label: name.to_string(),
            meta: BTreeMap::new(),
        };
        self.insert_node(&node)
    }

    /// Add/strengthen an undirected edge between two node ids — a stronger kind
    /// (`case`) wins and is never downgraded, exactly like
    /// [`Graph`](crate::Graph). Stored both directions as a `:put` transaction.
    pub fn link(&mut self, a: &str, b: &str, kind: EdgeKind) -> Result<(), cozo::Error> {
        if a == b {
            return Ok(());
        }
        let want = kind_to_int(kind);
        // Read the current provenance (if any) and keep the stronger of the two.
        let existing = self.run(
            "?[k] := *edge{src: $a, dst: $b, kind: k}",
            BTreeMap::from([
                ("a".to_string(), DataValue::from(a)),
                ("b".to_string(), DataValue::from(b)),
            ]),
            false,
        )?;
        let current = existing.rows.first().and_then(|r| r[0].get_int());
        let merged = current.map_or(want, |c| c.max(want));

        let params = BTreeMap::from([
            ("a".to_string(), DataValue::from(a)),
            ("b".to_string(), DataValue::from(b)),
            ("k".to_string(), DataValue::from(merged)),
        ]);
        self.run(
            "?[src, dst, kind] <- [[$a, $b, $k], [$b, $a, $k]] \
             :put edge {src, dst => kind}",
            params,
            true,
        )?;
        Ok(())
    }

    /// Whether a node id is present.
    pub fn contains(&self, id: &str) -> bool {
        self.nodes.contains_key(id)
    }

    /// Look up a node payload.
    pub fn node(&self, id: &str) -> Option<&Node> {
        self.nodes.get(id)
    }

    /// Bounded-reachability pivot: everything reachable from `start` within
    /// `depth` hops (excluding `start`), as [`Hit`]s. Same shape as
    /// [`Graph::pivot`](crate::Graph::pivot); the traversal is a recursive
    /// Datalog query computing each reached node's minimum hop distance, with
    /// `via` = the (min) provenance among its shortest-path predecessor edges.
    ///
    /// Results are ordered by `(hop, node id)` — deterministic, but note this
    /// is *not* the in-memory graph's raw BFS visitation order (the reached set
    /// and each node's hop/`via` are what match; see the module docs).
    pub fn pivot(&self, start: &str, depth: usize) -> Vec<Hit<'_>> {
        if depth == 0 || !self.nodes.contains_key(start) {
            return Vec::new();
        }
        // `sd`: shortest hop distance from `start` (start itself at 0), bounded
        //       by `depth`, via a recursive meet(min) aggregation.
        // `via`: for each reached node, the min provenance on an edge from a
        //        predecessor exactly one hop closer.
        let script = "\
            sd[node, min(dist)] := node = $start, dist = 0
            sd[node, min(dist)] := sd[prev, pd], *edge{src: prev, dst: node}, dist = pd + 1, dist <= $depth
            via[node, min(kind)] := sd[node, d], d > 0, sd[prev, pd], pd = d - 1, *edge{src: prev, dst: node, kind}
            ?[node, dist, kind] := sd[node, dist], node != $start, via[node, kind]
            :order dist
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
            let via = kind_from_int(row[2].get_int().expect("pivot kind is an int"));
            if let Some(node) = self.nodes.get(id) {
                out.push(Hit { hop, via, node });
            }
        }
        out
    }

    /// Shortest undirected path between two nodes (inclusive), or `None` if
    /// either is unknown or they are disconnected. Same shape as
    /// [`Graph::shortest_path`](crate::Graph::shortest_path); the search is
    /// Cozo's built-in `ShortestPathBFS`, whose FIFO + sorted-neighbour order
    /// matches the in-memory BFS (so ties break the same way).
    pub fn shortest_path(&self, a: &str, b: &str) -> Option<Vec<&Node>> {
        if !self.nodes.contains_key(a) || !self.nodes.contains_key(b) {
            return None;
        }
        if a == b {
            return self.nodes.get(a).map(|n| vec![n]);
        }
        let script = "\
            edges[fr, to] := *edge{src: fr, dst: to}
            start[] <- [[$a]]
            end[] <- [[$b]]
            ?[fr, to, path] <~ ShortestPathBFS(edges[fr, to], start[], end[])";
        let params = BTreeMap::from([
            ("a".to_string(), DataValue::from(a)),
            ("b".to_string(), DataValue::from(b)),
        ]);
        let rows = self
            .run(script, params, false)
            .expect("cozo shortest_path query")
            .rows;

        // One row: (start, end, path) — `path` is a list of ids, or Null if
        // unreachable.
        let path_val = rows.first().map(|r| &r[2])?;
        let list = path_val.get_slice()?; // Null → None → disconnected.
        let mut path = Vec::with_capacity(list.len());
        for item in list {
            let id = item.get_str()?;
            path.push(self.nodes.get(id)?);
        }
        Some(path)
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