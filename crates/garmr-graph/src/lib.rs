// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! `garmr-graph` — an in-memory entity graph for pivot / link-analysis (M5).
//!
//! garmr is embedded and single-binary, so this is a pure-Rust adjacency graph
//! (no FalkorDB, no external server): hosts, IPs, users and cases as typed
//! nodes. It gives the one move a SQL-only SIEM makes clumsy — "show everything
//! connected to this IP", and the multi-hop path between two entities.
//!
//! Edges carry provenance ([`EdgeKind`]): a **case** edge means the entities
//! co-occur in an adjudicated case (the strong signal); an **event** edge means
//! they merely co-occur in raw log activity (an IP seen on a host with no case
//! — the low-and-slow link cases miss). A case edge outranks an event edge, and
//! [`pivot`](Graph::pivot) reports which kind first reached each node, so the
//! analyst can tell adjudicated links from raw ones.
//!
//! The graph is built on demand (cheap at home-lab scale). The pure core takes
//! cases + event triples; the `store` feature adds [`build`], which pulls both
//! straight from the store. The data types live in [`model`] and the RBA-style
//! attack-path ranking in [`risk`]; this file is the graph structure + its
//! traversal (build / pivot / shortest_path / edges_among).

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use garmr_core::Case;

#[cfg(feature = "store")]
mod build;
/// Optional CozoDB-backed twin of [`Graph`] (behind the `cozo` feature).
#[cfg(feature = "cozo")]
pub mod cozo_graph;
mod model;
mod risk;

#[cfg(feature = "store")]
pub use build::{build, GraphCache, TimeWindow};
#[cfg(feature = "cozo")]
pub use cozo_graph::CozoGraph;
pub use model::{
    node_device_type, node_id, EdgeKind, Hit, Node, RankedPath, KIND_CASE, KIND_HOST, KIND_IP,
    KIND_PERSON, KIND_STAFF, KIND_USER,
};

/// An undirected entity graph with per-edge provenance.
#[derive(Default)]
pub struct Graph {
    nodes: BTreeMap<String, Node>,
    /// node → (neighbour → strongest edge kind).
    adj: BTreeMap<String, BTreeMap<String, EdgeKind>>,
    /// True if event-edge enrichment was skipped (scan slow/failed) — the graph
    /// is case-only and may miss raw-activity links.
    degraded: bool,
}

impl Graph {
    /// Build from the case set: each case node is linked (case edges) to its
    /// host, source IP and user.
    pub fn from_cases(cases: &[Case]) -> Self {
        let mut g = Graph::default();
        for c in cases {
            let case_node = node_id(KIND_CASE, &c.id);
            let mut meta = BTreeMap::new();
            meta.insert("rule".into(), c.trigger.rule_id.clone());
            meta.insert("level".into(), c.trigger.level.clone());
            meta.insert("state".into(), format!("{:?}", c.state).to_lowercase());
            if let Some(v) = &c.verdict {
                meta.insert(
                    "disposition".into(),
                    format!("{:?}", v.disposition).to_lowercase(),
                );
            }
            g.upsert(Node {
                id: case_node.clone(),
                kind: KIND_CASE.into(),
                name: c.id.clone(),
                label: c.trigger.rule_id.clone(),
                meta,
            });

            let ev = &c.trigger.event;
            let host = ev.host.trim();
            if !host.is_empty() {
                let n = g.entity(KIND_HOST, host);
                g.link(&case_node, &n, EdgeKind::Case);
            }
            if let Some(ip) = ev.src_ip().map(str::trim).filter(|s| !s.is_empty()) {
                let n = g.entity(KIND_IP, ip);
                g.link(&case_node, &n, EdgeKind::Case);
            }
            if let Some(user) = ev.field("user").map(str::trim).filter(|s| !s.is_empty()) {
                let n = g.entity(KIND_USER, user);
                g.link(&case_node, &n, EdgeKind::Case);
            }
            // Register lookups: a lookup-audit case links to the acting
            // caseworker (db_user) and the looked-up person (target_person), so
            // the staff↔person relationship is reachable THROUGH the adjudicated
            // case (staff—case—person).
            if let Some(du) = ev.field("db_user").map(str::trim).filter(|s| !s.is_empty()) {
                let n = g.entity(KIND_STAFF, du);
                g.link(&case_node, &n, EdgeKind::Case);
            }
            if let Some(tp) = ev
                .field("target_person")
                .map(str::trim)
                .filter(|s| !s.is_empty())
            {
                let n = g.entity(KIND_PERSON, tp);
                g.link(&case_node, &n, EdgeKind::Case);
            }
        }
        g
    }

    /// Add event-co-occurrence edges from `(host, ip, user)` triples — link the
    /// present pairs (host↔ip, host↔user, ip↔user) with an `event` edge. An
    /// existing case edge is not downgraded. Empty components are skipped.
    pub fn add_event_edges(&mut self, triples: &[(String, String, String)]) {
        for (host, ip, user) in triples {
            let h = non_empty(host).map(|v| self.entity(KIND_HOST, v));
            let i = non_empty(ip).map(|v| self.entity(KIND_IP, v));
            let u = non_empty(user).map(|v| self.entity(KIND_USER, v));
            for (a, b) in [(&h, &i), (&h, &u), (&i, &u)] {
                if let (Some(a), Some(b)) = (a, b) {
                    self.link(a, b, EdgeKind::Event);
                }
            }
        }
    }

    /// Add staff↔person "looked-up" edges from `(db_user, target_person)` pairs
    /// — the raw register lookups. An `event` edge (the direct
    /// who-looked-up-whom link exists even with no adjudicated case); an existing
    /// case edge is not downgraded. Empty components are skipped.
    pub fn add_lookup_edges(&mut self, pairs: &[(String, String)]) {
        for (staff, person) in pairs {
            if let (Some(s), Some(p)) = (non_empty(staff), non_empty(person)) {
                let a = self.entity(KIND_STAFF, s);
                let b = self.entity(KIND_PERSON, p);
                self.link(&a, &b, EdgeKind::Event);
            }
        }
    }

    /// Ensure an entity node exists (created with no edges if absent) — for
    /// including something in the graph even when it has no edges yet, e.g. a
    /// monitored host seen only in firehose telemetry that the edge scan skips.
    pub fn ensure_node(&mut self, kind: &str, name: &str) {
        if let Some(n) = non_empty(name) {
            self.entity(kind, n);
        }
    }

    /// Like [`ensure_node`](Self::ensure_node) but tags the node with a device
    /// type (from build-time event signals), stored in `meta["device_type"]` and
    /// surfaced by [`node_device_type`](crate::node_device_type).
    pub fn ensure_node_typed(&mut self, kind: &str, name: &str, device_type: &str) {
        if let Some(n) = non_empty(name) {
            let id = self.entity(kind, n);
            if let Some(node) = self.nodes.get_mut(&id) {
                node.meta
                    .insert("device_type".into(), device_type.to_string());
            }
        }
    }

    fn upsert(&mut self, node: Node) {
        self.adj.entry(node.id.clone()).or_default();
        self.nodes.insert(node.id.clone(), node);
    }

    fn entity(&mut self, kind: &str, name: &str) -> String {
        let id = node_id(kind, name);
        if !self.nodes.contains_key(&id) {
            self.upsert(Node {
                id: id.clone(),
                kind: kind.into(),
                name: name.into(),
                label: name.into(),
                meta: BTreeMap::new(),
            });
        }
        id
    }

    /// Add/strengthen an undirected edge. A stronger kind (case) wins.
    fn link(&mut self, a: &str, b: &str, kind: EdgeKind) {
        if a == b {
            return;
        }
        for (x, y) in [(a, b), (b, a)] {
            self.adj
                .entry(x.to_string())
                .or_default()
                .entry(y.to_string())
                .and_modify(|k| *k = (*k).max(kind))
                .or_insert(kind);
        }
    }

    pub fn node(&self, id: &str) -> Option<&Node> {
        self.nodes.get(id)
    }
    pub fn contains(&self, id: &str) -> bool {
        self.nodes.contains_key(id)
    }

    /// Whether event-edge enrichment was skipped (case-only graph).
    pub fn degraded(&self) -> bool {
        self.degraded
    }
    /// Mark the graph as degraded (event enrichment skipped). Set by the builder.
    pub fn set_degraded(&mut self, v: bool) {
        self.degraded = v;
    }

    /// (node count, undirected edge count).
    pub fn size(&self) -> (usize, usize) {
        let half: usize = self.adj.values().map(BTreeMap::len).sum();
        (self.nodes.len(), half / 2)
    }

    /// Every node in the graph (for a whole-topology export, not a pivot).
    pub fn all_nodes(&self) -> impl Iterator<Item = &Node> {
        self.nodes.values()
    }

    /// A node's degree (neighbour count) — the caller sizes topology nodes by it.
    pub fn degree(&self, id: &str) -> usize {
        self.adj.get(id).map(BTreeMap::len).unwrap_or(0)
    }

    /// Every undirected edge once (`a < b`) with its strongest provenance — the
    /// whole graph's edge list, for the topology map.
    pub fn all_edges(&self) -> Vec<(String, String, EdgeKind)> {
        let mut out = Vec::new();
        for (a, adj) in &self.adj {
            for (b, kind) in adj {
                if a < b {
                    out.push((a.clone(), b.clone(), *kind));
                }
            }
        }
        out
    }

    /// The induced-subgraph edges among a set of node ids: every undirected edge
    /// whose BOTH endpoints are in `ids`, each returned once (as `(a, b, kind)`
    /// with `a < b`), carrying the strongest recorded provenance for the pair.
    /// Lets a caller draw a node-link view of a pivot result — which reached
    /// nodes are actually linked, and how (case vs event).
    pub fn edges_among(&self, ids: &BTreeSet<String>) -> Vec<(String, String, EdgeKind)> {
        let mut out = Vec::new();
        for a in ids {
            let Some(adj) = self.adj.get(a) else { continue };
            for (b, kind) in adj {
                // Each undirected edge once (a < b), both endpoints in the set.
                if a < b && ids.contains(b) {
                    out.push((a.clone(), b.clone(), *kind));
                }
            }
        }
        out
    }

    /// BFS pivot: everything reachable from `start` within `depth` hops, as
    /// [`Hit`]s in BFS order (excluding `start`). `via` is the provenance of the
    /// edge that first reached each node.
    pub fn pivot(&self, start: &str, depth: usize) -> Vec<Hit<'_>> {
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
                for (nb, kind) in adj {
                    if seen.insert(nb.as_str()) {
                        if let Some(node) = self.nodes.get(nb) {
                            out.push(Hit {
                                hop: d + 1,
                                via: *kind,
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

    /// Shortest undirected path between two nodes (inclusive), or `None` if
    /// either is unknown or they are disconnected.
    pub fn shortest_path(&self, a: &str, b: &str) -> Option<Vec<&Node>> {
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

fn non_empty(s: &str) -> Option<&str> {
    let t = s.trim();
    (!t.is_empty()).then_some(t)
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use garmr_core::{Case, Detection, Disposition, Event, Verdict};

    use super::*;

    fn verdict(d: Disposition) -> Verdict {
        Verdict {
            disposition: d,
            severity: 5,
            confidence: 0.8,
            rationale: "r".into(),
            proposed_action: None,
        }
    }

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

    #[test]
    fn pivot_on_ip_reaches_both_hosts_via_shared_cases() {
        let cases = vec![
            case("c1", "ssh-brute", "pve", "203.0.113.7", "root"),
            case("c2", "ssh-invalid", "njord", "203.0.113.7", "admin"),
            case("c3", "unrelated", "wazuh", "10.0.0.9", ""),
        ];
        let g = Graph::from_cases(&cases);
        let ip = node_id(KIND_IP, "203.0.113.7");
        let reached: Vec<&str> = g.pivot(&ip, 2).iter().map(|h| h.node.id.as_str()).collect();
        assert!(reached.contains(&node_id(KIND_HOST, "pve").as_str()));
        assert!(reached.contains(&node_id(KIND_HOST, "njord").as_str()));
        assert!(!reached.contains(&node_id(KIND_HOST, "wazuh").as_str()));
        // Direct case edges report `via = case`.
        assert!(g.pivot(&ip, 1).iter().all(|h| h.via == EdgeKind::Case));
    }

    #[test]
    fn event_edges_link_entities_with_no_case() {
        // One case ties ip↔pve. A raw event shows the SAME ip also touched njord
        // (no case) — event enrichment must surface njord, marked `via = event`.
        let mut g = Graph::from_cases(&[case("c1", "r", "pve", "203.0.113.7", "root")]);
        g.add_event_edges(&[("njord".into(), "203.0.113.7".into(), "".into())]);
        let ip = node_id(KIND_IP, "203.0.113.7");
        // From_cases links entities THROUGH the case node, so ip→pve is 2 hops
        // (ip→case→pve). The event edge ip↔njord is a DIRECT 1-hop link.
        let hits = g.pivot(&ip, 2);
        let njord = hits
            .iter()
            .find(|h| h.node.id == node_id(KIND_HOST, "njord"))
            .expect("njord reached");
        assert_eq!(njord.hop, 1, "the event edge is a direct link");
        assert_eq!(
            njord.via,
            EdgeKind::Event,
            "raw-activity link is an event edge"
        );
        let pve = hits
            .iter()
            .find(|h| h.node.id == node_id(KIND_HOST, "pve"))
            .expect("pve reached");
        assert_eq!(
            pve.via,
            EdgeKind::Case,
            "adjudicated link stays a case edge"
        );
    }

    #[test]
    fn case_edge_is_not_downgraded_by_a_later_event_edge() {
        let mut g = Graph::from_cases(&[case("c1", "r", "pve", "1.1.1.1", "")]);
        g.add_event_edges(&[("pve".into(), "1.1.1.1".into(), "".into())]); // same pair, event
        let host = node_id(KIND_HOST, "pve");
        assert_eq!(
            g.pivot(&node_id(KIND_IP, "1.1.1.1"), 1)[0].via,
            EdgeKind::Case
        );
        // (host still one hop from the ip)
        assert!(g.contains(&host));
    }

    #[test]
    fn shortest_path_links_two_hosts_through_the_ip() {
        let cases = vec![
            case("c1", "r", "pve", "203.0.113.7", ""),
            case("c2", "r", "njord", "203.0.113.7", ""),
        ];
        let g = Graph::from_cases(&cases);
        let path = g
            .shortest_path(&node_id(KIND_HOST, "pve"), &node_id(KIND_HOST, "njord"))
            .expect("a path exists");
        assert_eq!(path.len(), 5);
        assert!(path
            .iter()
            .any(|n| n.kind == KIND_IP && n.name == "203.0.113.7"));
    }

    #[test]
    fn rank_paths_orders_attack_paths_by_risk_and_drops_benign() {
        let mut crit = case("crit", "r", "pve", "9.9.9.9", "");
        crit.trigger.level = "critical".into();
        crit.verdict = Some(verdict(Disposition::Malicious));
        let mut ben = case("ben", "r", "pve", "9.9.9.9", "");
        ben.trigger.level = "low".into();
        ben.verdict = Some(verdict(Disposition::Benign));
        let mut med = case("med", "r", "pve", "9.9.9.9", ""); // untriaged medium
        med.trigger.level = "medium".into();

        let g = Graph::from_cases(&[crit, ben, med]);
        let ranked = g.rank_paths(&node_id(KIND_IP, "9.9.9.9"), 1);
        // benign (score 0) dropped; critical-malicious ranks above untriaged-medium.
        assert_eq!(ranked.len(), 2);
        assert_eq!(ranked[0].target.name, "crit");
        assert!(
            (ranked[0].score - 26.0).abs() < 0.01,
            "13×2, got {}",
            ranked[0].score
        );
        assert_eq!(ranked[1].target.name, "med");
        assert!(
            (ranked[1].score - 2.0).abs() < 0.01,
            "4×0.5, got {}",
            ranked[1].score
        );
        // The path starts at the ip and ends at the case.
        assert_eq!(
            ranked[0].path.first().map(String::as_str),
            Some("ip:9.9.9.9")
        );
        assert_eq!(ranked[0].path.last().map(String::as_str), Some("case:crit"));
    }

    #[test]
    fn edges_among_returns_each_induced_edge_once() {
        // Two cases share an IP (c1↔pve, c2↔njord, both↔ip). The induced
        // subgraph over {ip, c1, c2, pve} keeps the case↔entity links whose both
        // ends are in the set — and drops the c2↔njord edge (njord excluded).
        let cases = vec![
            case("c1", "r", "pve", "203.0.113.7", ""),
            case("c2", "r", "njord", "203.0.113.7", ""),
        ];
        let g = Graph::from_cases(&cases);
        let ip = node_id(KIND_IP, "203.0.113.7");
        let c1 = node_id(KIND_CASE, "c1");
        let c2 = node_id(KIND_CASE, "c2");
        let pve = node_id(KIND_HOST, "pve");
        let njord = node_id(KIND_HOST, "njord");
        let ids: BTreeSet<String> = [ip.clone(), c1.clone(), c2.clone(), pve.clone()]
            .into_iter()
            .collect();

        let edges = g.edges_among(&ids);
        // All three surviving edges are adjudicated (case) edges.
        assert!(edges.iter().all(|(_, _, k)| *k == EdgeKind::Case));
        // Every edge is undirected-unique (a < b) and appears once.
        assert!(edges.iter().all(|(a, b, _)| a < b));
        let mut pairs: Vec<(&str, &str)> = edges
            .iter()
            .map(|(a, b, _)| (a.as_str(), b.as_str()))
            .collect();
        let n = pairs.len();
        pairs.sort();
        pairs.dedup();
        assert_eq!(pairs.len(), n, "no duplicate undirected edge");
        // ip↔c1, ip↔c2 and pve↔c1 are present; nothing touches the excluded njord.
        let has = |x: &str, y: &str| {
            edges
                .iter()
                .any(|(a, b, _)| (a == x && b == y) || (a == y && b == x))
        };
        assert!(has(&ip, &c1));
        assert!(has(&ip, &c2));
        assert!(has(&pve, &c1));
        assert!(!edges.iter().any(|(a, b, _)| *a == njord || *b == njord));
    }

    #[test]
    fn disconnected_and_unknown_return_none() {
        let cases = vec![
            case("c1", "r", "pve", "1.1.1.1", ""),
            case("c2", "r", "njord", "2.2.2.2", ""),
        ];
        let g = Graph::from_cases(&cases);
        assert!(g
            .shortest_path(&node_id(KIND_HOST, "pve"), &node_id(KIND_HOST, "njord"))
            .is_none());
        assert!(g
            .shortest_path(&node_id(KIND_HOST, "pve"), "host:ghost")
            .is_none());
        assert!(g.pivot("ip:0.0.0.0", 3).is_empty());
    }

    #[test]
    fn registerkontroll_links_staff_and_person() {
        // A lookup-audit case ties the caseworker and the person THROUGH the
        // case (staff—case—person, 2 hops via case edges).
        let mut c = case("c1", "reg_watchlist_target_lookup", "pgserver", "", "");
        c.trigger
            .event
            .fields
            .insert("db_user".into(), "anna.h".into());
        c.trigger
            .event
            .fields
            .insert("target_person".into(), "19701231-5678".into());
        let mut g = Graph::from_cases(&[c]);
        let staff = node_id(KIND_STAFF, "anna.h");
        let person = node_id(KIND_PERSON, "19701231-5678");
        assert!(g.contains(&staff) && g.contains(&person));
        let via_case = g.pivot(&staff, 2);
        let reached = via_case
            .iter()
            .find(|h| h.node.id == person)
            .expect("person reached from staff");
        assert_eq!(reached.hop, 2, "staff → case → person");
        assert_eq!(reached.via, EdgeKind::Case);

        // A raw lookup with no case adds a DIRECT staff↔person event edge.
        g.add_lookup_edges(&[("bob.k".into(), "19850101-1234".into())]);
        let bob = node_id(KIND_STAFF, "bob.k");
        let p2 = node_id(KIND_PERSON, "19850101-1234");
        let hit = g
            .pivot(&bob, 1)
            .into_iter()
            .find(|h| h.node.id == p2)
            .expect("direct lookup edge");
        assert_eq!(hit.hop, 1);
        assert_eq!(hit.via, EdgeKind::Event);
    }
}
