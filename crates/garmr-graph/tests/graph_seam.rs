// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! Guard tests for garmr's adoption of the shared `nornir-graph` seam.
//!
//! The existing unit tests in `src/lib.rs` and `src/cozo_graph.rs` are unchanged by
//! that adoption and still pass; these are the NEW claims the refactor makes, and
//! each is written so it can report red:
//!
//! 1. [`EdgeKind`] round-trips losslessly through the seam's label codec, for
//!    EVERY variant, including through the Cozo database.
//! 2. The in-memory [`Graph`] and the Cozo-backed one give identical `pivot` and
//!    `shortest_path` answers — checked against a fixture whose expected answers
//!    are pinned as literals, so "both backends returned nothing" cannot pass.
//! 3. Both types satisfy the same `GraphQuery` trait, checked GENERICALLY (one
//!    function run over both), which is what "drop-in twin" has to mean.
//!
//! The Cozo-backed halves are `#[cfg(feature = "cozo")]` on the ITEM, never on the
//! file: the codec and fixture tests run in every build, so a default `cargo test`
//! still exercises real assertions rather than quietly compiling to nothing. Run
//! `cargo test -p garmr-graph --features cozo` for the cross-backend halves.

use std::collections::BTreeMap;

use garmr_core::{Case, Detection, Event};
#[cfg(feature = "cozo")]
use garmr_graph::CozoGraph;
use garmr_graph::{node_id, EdgeKind, Graph, Node, KIND_HOST, KIND_IP};
use nornir_graph::{EdgeLabel, GraphQuery};

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

/// EVERY `EdgeKind` variant, so a codec that grew a third variant and forgot it
/// goes red rather than silently losing it.
const ALL_KINDS: [EdgeKind; 2] = [EdgeKind::Event, EdgeKind::Case];

/// The codec contract: `decode(encode(k)) == k` for every variant, distinct
/// variants get distinct codes, and the codes preserve `EdgeKind`'s own ordering
/// (which is what makes the backends' numeric `max` reproduce "the stronger link
/// wins").
#[test]
fn edge_kind_round_trips_through_the_label_codec() {
    for k in ALL_KINDS {
        assert_eq!(EdgeKind::decode(k.encode()), k, "{k:?} did not round-trip");
    }
    let codes: Vec<i64> = ALL_KINDS.iter().map(|k| k.encode()).collect();
    assert_eq!(
        codes,
        vec![0, 1],
        "the stored codes must stay event=0, case=1"
    );
    assert!(
        EdgeKind::Event.encode() < EdgeKind::Case.encode(),
        "the codes must preserve EdgeKind's ordering, or `max` stops meaning 'stronger wins'"
    );
    assert_eq!(
        EdgeKind::default(),
        EdgeKind::Event,
        "the default must be the WEAKER kind"
    );
}

/// …and round-trips through the actual DATABASE, not just the codec in isolation.
#[cfg(feature = "cozo")]
#[test]
fn edge_kind_round_trips_through_the_cozo_database() {
    let mut g = CozoGraph::new().expect("embedded cozo");
    for (i, k) in ALL_KINDS.iter().enumerate() {
        let (a, b) = (format!("host:h{i}"), format!("ip:i{i}"));
        g.ensure_node(KIND_HOST, &format!("h{i}")).unwrap();
        g.ensure_node(KIND_IP, &format!("i{i}")).unwrap();
        g.link(&a, &b, *k).unwrap();
    }
    for (i, k) in ALL_KINDS.iter().enumerate() {
        let a = format!("host:h{i}");
        let hits = g.pivot(&a, 1);
        assert_eq!(
            hits.len(),
            1,
            "{k:?}: expected exactly one neighbour of {a}"
        );
        assert_eq!(
            hits[0].via, *k,
            "{k:?} came back out of the database as {:?}",
            hits[0].via
        );
        assert_eq!(hits[0].node.id, format!("ip:i{i}"));
    }
    // Merge: a Case edge must not be downgraded by a later Event edge, through the
    // database, exactly as in memory.
    let mut g = CozoGraph::new().unwrap();
    g.ensure_node(KIND_HOST, "h").unwrap();
    g.ensure_node(KIND_IP, "1.1.1.1").unwrap();
    let (h, ip) = (node_id(KIND_HOST, "h"), node_id(KIND_IP, "1.1.1.1"));
    g.link(&h, &ip, EdgeKind::Case).unwrap();
    g.link(&h, &ip, EdgeKind::Event).unwrap();
    assert_eq!(
        g.pivot(&h, 1)[0].via,
        EdgeKind::Case,
        "an Event edge downgraded an adjudicated Case edge in the database"
    );
}

/// The fixture both backends are compared over, plus its answers pinned as
/// LITERALS — without this, "the two agree" would also be satisfied by two
/// backends that agree on nothing.
fn fixture() -> Graph {
    let mut g = Graph::from_cases(&[
        case("c1", "r", "pve", "203.0.113.7", "root"),
        case("c2", "r", "njord", "203.0.113.7", ""),
    ]);
    g.add_event_edges(&[("heimdall".into(), "203.0.113.7".into(), "".into())]);
    g
}

fn pivot_key<G: GraphQuery<Node = Node, Label = EdgeKind>>(
    g: &G,
    start: &str,
    depth: usize,
) -> Vec<(String, usize, EdgeKind)> {
    let mut v: Vec<_> = g
        .pivot(start, depth)
        .iter()
        .map(|h| (h.node.id.clone(), h.hop, h.via))
        .collect();
    v.sort();
    v
}

#[test]
fn the_fixture_has_real_answers() {
    let g = fixture();
    let ip = node_id(KIND_IP, "203.0.113.7");
    assert_eq!(
        pivot_key(&g, &ip, 1),
        vec![
            ("case:c1".to_string(), 1, EdgeKind::Case),
            ("case:c2".to_string(), 1, EdgeKind::Case),
            ("host:heimdall".to_string(), 1, EdgeKind::Event),
        ],
        "the reference pivot must be a specific non-empty set spanning BOTH provenances"
    );
    let path: Vec<String> = g
        .shortest_path(&node_id(KIND_HOST, "pve"), &node_id(KIND_HOST, "njord"))
        .expect("connected")
        .iter()
        .map(|n| n.id.clone())
        .collect();
    assert_eq!(
        path,
        vec![
            "host:pve",
            "case:c1",
            "ip:203.0.113.7",
            "case:c2",
            "host:njord"
        ]
    );
}

/// The in-memory BFS and the embedded Datalog must agree, at every depth, from
/// every start.
#[cfg(feature = "cozo")]
#[test]
fn in_memory_and_cozo_agree_on_the_whole_fixture() {
    let g = fixture();
    let cg = CozoGraph::from_graph(&g).expect("mirror into cozo");
    assert_eq!(
        cg.node_count(),
        g.node_count(),
        "cozo lost nodes on the way in"
    );

    let starts: Vec<String> = g.all_nodes().map(|n| n.id.clone()).collect();
    assert!(
        starts.len() >= 6,
        "fixture too small to be a real comparison: {starts:?}"
    );
    for start in &starts {
        for depth in 0..=4 {
            assert_eq!(
                pivot_key(&g, start, depth),
                pivot_key(&cg, start, depth),
                "pivot mismatch from {start} at depth {depth}"
            );
        }
        for target in &starts {
            let ids = |p: Option<Vec<&Node>>| {
                p.map(|v| v.iter().map(|n| n.id.clone()).collect::<Vec<_>>())
            };
            assert_eq!(
                ids(g.shortest_path(start, target)),
                ids(cg.shortest_path(start, target)),
                "shortest_path({start}, {target}) differs"
            );
        }
    }
}

/// "Drop-in twin" means substitutable, so prove it the only way that counts:
/// ONE generic function, run over both backends, with the answers pinned.
#[cfg(feature = "cozo")]
#[test]
fn both_backends_satisfy_the_same_trait_generically() {
    fn interrogate<G: GraphQuery<Node = Node, Label = EdgeKind>>(g: &G) -> (usize, usize, String) {
        let ip = node_id(KIND_IP, "203.0.113.7");
        let hops = g.pivot(&ip, 2).len();
        let deg = g.degree(&ip);
        let path = g
            .shortest_path(&node_id(KIND_HOST, "pve"), &node_id(KIND_HOST, "njord"))
            .map(|p| {
                p.iter()
                    .map(|n| n.id.as_str())
                    .collect::<Vec<_>>()
                    .join(" -> ")
            })
            .unwrap_or_default();
        (hops, deg, path)
    }
    let g = fixture();
    let cg = CozoGraph::from_graph(&g).unwrap();
    // ip reaches {c1, c2, heimdall} at hop 1 and {pve, root, njord} at hop 2.
    let expected = (
        6,
        3,
        "host:pve -> case:c1 -> ip:203.0.113.7 -> case:c2 -> host:njord".to_string(),
    );
    assert_eq!(interrogate(&g), expected, "in-memory backend");
    assert_eq!(interrogate(&cg), expected, "cozo backend");
}
