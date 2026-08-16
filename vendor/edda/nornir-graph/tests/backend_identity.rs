//! **The cross-backend identity law.** The same graph, loaded through every
//! backend, must produce IDENTICAL answers — the whole point of having one seam.
//!
//! LAW 2 discipline throughout: every assertion is on APPLIED OUTPUT (the actual
//! node ids, the actual orderings, the actual labels), never on "the call returned
//! `Ok`" or "the result was non-empty". In particular:
//!
//! * [`fixture_is_not_degenerate`] pins the reference answers as literals. A
//!   backend that returned an EMPTY node set — precisely how the two `// TODO` stubs
//!   this crate replaces managed to pass for months — cannot survive it, and neither
//!   can a comparison-only suite where both sides are empty together.
//! * The comparisons are *between different implementations*: the Datalog recursion
//!   in Cozo against the hand-written BFS in `MemGraph`, and petgraph's Tarjan
//!   against this crate's. Comparing an implementation with itself can never go red.

use std::collections::BTreeSet;

use nornir_graph::{
    BulkGraph, CozoGraph, EdgeLabel, GraphQuery, GraphStore, IdGraph, MemGraph, PetGraph,
};

/// A three-valued label with a strength ranking, standing in for any consumer's
/// edge-provenance enum. `Weak` is `Default`, so `max` upgrades and never
/// downgrades.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Default)]
enum Prov {
    #[default]
    Weak,
    Medium,
    Strong,
}

impl EdgeLabel for Prov {
    fn encode(self) -> i64 {
        match self {
            Prov::Weak => 0,
            Prov::Medium => 1,
            Prov::Strong => 2,
        }
    }
    fn decode(code: i64) -> Self {
        match code {
            c if c <= 0 => Prov::Weak,
            1 => Prov::Medium,
            _ => Prov::Strong,
        }
    }
}

/// The shared fixture, as `(a, b, label)` UNDIRECTED links. Deliberately shaped so
/// the comparisons have teeth:
///
/// * mixed labels, so a backend that dropped or flattened provenance goes red;
/// * a UNIQUE shortest path `h1 → c1 → ip → c2 → h2` (length 5), so path equality
///   is a real assertion and not a coin flip between equally valid answers;
/// * a node (`iso`) connected to nothing, so "the reached set" is not "everything";
/// * a second component (`far`), so disconnection is exercised.
const LINKS: &[(&str, &str, Prov)] = &[
    ("h1", "c1", Prov::Strong),
    ("c1", "ip", Prov::Strong),
    ("ip", "c2", Prov::Strong),
    ("c2", "h2", Prov::Strong),
    ("ip", "u1", Prov::Medium),
    ("h2", "u2", Prov::Weak),
    ("far", "far2", Prov::Medium),
];

const NODES: &[&str] = &[
    "h1", "c1", "ip", "c2", "h2", "u1", "u2", "iso", "far", "far2",
];

fn build<S: GraphStore<Node = String, Label = Prov>>(g: &mut S) {
    for id in NODES {
        g.put_node(id, id.to_uppercase()).ok().expect("put_node");
    }
    for (a, b, p) in LINKS {
        g.link(a, b, *p).ok().expect("link");
    }
}

fn mem() -> MemGraph<String, Prov> {
    let mut g = MemGraph::new();
    build(&mut g);
    g
}

fn cozo() -> CozoGraph<String, Prov> {
    let mut g = CozoGraph::new().expect("embedded cozo");
    build(&mut g);
    g
}

/// `(payload, hop, label)` triples of a pivot, sorted — an order-independent
/// fingerprint, so the two backends can be compared without demanding they agree on
/// BFS visitation order (which they explicitly do not; see `cozo_graph`'s docs).
fn pivot_key<G: GraphQuery<Node = String, Label = Prov>>(
    g: &G,
    start: &str,
    depth: usize,
) -> Vec<(String, usize, Prov)> {
    let mut v: Vec<_> = g
        .pivot(start, depth)
        .iter()
        .map(|h| (h.node.clone(), h.hop, h.via))
        .collect();
    v.sort();
    v
}

fn path_ids<G: GraphQuery<Node = String, Label = Prov>>(
    g: &G,
    a: &str,
    b: &str,
) -> Option<Vec<String>> {
    g.shortest_path(a, b)
        .map(|p| p.into_iter().cloned().collect())
}

// ───────────────────────────── the anti-vacuity guard ─────────────────────────────

/// The reference answers, pinned as LITERALS.
///
/// This is the test that makes every comparison below meaningful. Two backends that
/// both return nothing agree perfectly; the `cozo_stub` / `falkordb_stub` this crate
/// replaces returned `Vec::new()` from every method and were "green" for months on
/// exactly that. Nothing here can be satisfied by an empty result.
#[test]
fn fixture_is_not_degenerate() {
    let m = mem();
    assert_eq!(m.node_count(), 10);
    assert_eq!(
        m.size(),
        (10, 7),
        "10 nodes and 7 undirected edges must actually be stored"
    );

    let hits = pivot_key(&m, "ip", 2);
    assert_eq!(
        hits,
        vec![
            ("C1".to_string(), 1, Prov::Strong),
            ("C2".to_string(), 1, Prov::Strong),
            ("H1".to_string(), 2, Prov::Strong),
            ("H2".to_string(), 2, Prov::Strong),
            ("U1".to_string(), 1, Prov::Medium),
        ],
        "the pivot reference answer must be a specific non-empty set"
    );
    assert_eq!(
        path_ids(&m, "h1", "h2"),
        Some(vec![
            "H1".to_string(),
            "C1".to_string(),
            "IP".to_string(),
            "C2".to_string(),
            "H2".to_string()
        ]),
        "the shortest-path reference answer must be a specific 5-node path"
    );
    // Both label ranks are genuinely exercised by the pivot, so a backend that
    // flattened every label to its Default would go red on the comparison tests.
    assert!(hits.iter().any(|(_, _, p)| *p == Prov::Strong));
    assert!(hits.iter().any(|(_, _, p)| *p == Prov::Medium));
    // The isolated node exists but is unreachable — "reached" is not "all".
    assert!(m.contains("iso"));
    assert!(m.pivot("ip", 99).iter().all(|h| h.node != "ISO"));
}

// ───────────────────────── QUERY: cozo vs the in-memory BFS ─────────────────────────

/// The Datalog recursion and the hand-written BFS must reach the same nodes at the
/// same hops with the same provenance, at every depth.
#[test]
fn cozo_pivot_matches_the_in_memory_bfs() {
    let (m, c) = (mem(), cozo());
    assert_eq!(
        c.node_count(),
        m.node_count(),
        "cozo lost nodes on the way in"
    );
    for start in ["ip", "h1", "u2", "far"] {
        for depth in 0..=5 {
            assert_eq!(
                pivot_key(&m, start, depth),
                pivot_key(&c, start, depth),
                "pivot mismatch from {start} at depth {depth}"
            );
        }
    }
    // An unknown start is empty in both, and the reference above proves "empty" is
    // not simply what this backend always says.
    assert!(c.pivot("nope", 3).is_empty());
    assert!(c.pivot("ip", 0).is_empty());
}

#[test]
fn cozo_shortest_path_matches_the_in_memory_bfs() {
    let (m, c) = (mem(), cozo());
    for (a, b) in [
        ("h1", "h2"),
        ("h2", "h1"),
        ("h1", "u1"),
        ("u2", "c1"),
        ("h1", "h1"),
        ("h1", "far"),   // disconnected
        ("h1", "iso"),   // isolated
        ("h1", "ghost"), // unknown
    ] {
        assert_eq!(
            path_ids(&m, a, b),
            path_ids(&c, a, b),
            "shortest_path({a}, {b}) differs"
        );
    }
    // …and the answer for the connected pair is the real path, not None==None.
    assert_eq!(path_ids(&c, "h1", "h2").map(|p| p.len()), Some(5));
    assert_eq!(path_ids(&c, "h1", "far"), None);
}

#[test]
fn cozo_neighbours_and_degree_match() {
    let (m, c) = (mem(), cozo());
    for id in NODES.iter().chain(["ghost"].iter()) {
        assert_eq!(
            m.neighbours(id),
            c.neighbours(id),
            "neighbours({id}) differ"
        );
        assert_eq!(m.degree(id), c.degree(id), "degree({id}) differs");
    }
    // Applied output, not just agreement: `ip` really has three labelled neighbours.
    assert_eq!(
        c.neighbours("ip"),
        vec![
            ("c1".to_string(), Prov::Strong),
            ("c2".to_string(), Prov::Strong),
            ("u1".to_string(), Prov::Medium),
        ]
    );
}

/// EVERY label variant must survive a write/read round-trip through the DATABASE,
/// and the "stronger wins" merge must behave identically in both backends.
#[test]
fn every_label_variant_round_trips_through_cozo() {
    let variants = [Prov::Weak, Prov::Medium, Prov::Strong];

    let mut c: CozoGraph<String, Prov> = CozoGraph::new().unwrap();
    let mut m: MemGraph<String, Prov> = MemGraph::new();
    for (i, p) in variants.iter().enumerate() {
        let (a, b) = (format!("n{i}a"), format!("n{i}b"));
        for id in [&a, &b] {
            c.put_node(id, id.clone()).unwrap();
            m.put_node(id, id.clone()).unwrap();
        }
        c.link(&a, &b, *p).unwrap();
        m.link(&a, &b, *p).unwrap();
    }
    for (i, p) in variants.iter().enumerate() {
        let (a, b) = (format!("n{i}a"), format!("n{i}b"));
        assert_eq!(
            c.neighbours(&a),
            vec![(b.clone(), *p)],
            "label {p:?} did not survive the cozo round-trip"
        );
        assert_eq!(c.neighbours(&a), m.neighbours(&a));
    }

    // Merge: a weaker write must NOT downgrade, a stronger one MUST upgrade — in
    // both backends, identically.
    for (write, expect) in [
        (Prov::Weak, Prov::Medium),
        (Prov::Medium, Prov::Medium),
        (Prov::Strong, Prov::Strong),
    ] {
        let mut c: CozoGraph<String, Prov> = CozoGraph::new().unwrap();
        let mut m: MemGraph<String, Prov> = MemGraph::new();
        for id in ["a", "b"] {
            c.put_node(id, id.to_string()).unwrap();
            m.put_node(id, id.to_string()).unwrap();
        }
        c.link("a", "b", Prov::Medium).unwrap();
        m.link("a", "b", Prov::Medium).unwrap();
        c.link("a", "b", write).unwrap();
        m.link("a", "b", write).unwrap();
        assert_eq!(
            c.neighbours("a"),
            vec![("b".to_string(), expect)],
            "cozo merge of {write:?}"
        );
        assert_eq!(
            m.neighbours("a"),
            vec![("b".to_string(), expect)],
            "mem merge of {write:?}"
        );
    }
}

// ───────────────────────── BULK: petgraph vs this crate's Tarjan ─────────────────────────

/// petgraph's Tarjan and the one in this crate are INDEPENDENT implementations, so
/// this comparison can genuinely go red.
#[test]
fn petgraph_and_mem_agree_on_the_bulk_algorithms() {
    let cases: &[&[(&str, &str)]] = &[
        &[("a", "b"), ("a", "c"), ("b", "d"), ("c", "d")],
        &[("a", "b"), ("b", "c"), ("c", "a"), ("a", "d")],
        &[("a", "b"), ("b", "a"), ("c", "a"), ("d", "c")],
        &[("x", "y")],
    ];
    for (i, edges) in cases.iter().enumerate() {
        let pet = PetGraph::from_edges(edges.iter().copied());
        let mem = IdGraph::from_edges(edges.iter().copied());
        assert_eq!(pet.scc(), mem.scc(), "case {i}: SCC differs");
        assert_eq!(pet.cycles(), mem.cycles(), "case {i}: cycles differ");
        assert_eq!(pet.topo(), mem.topo(), "case {i}: topo differs");
        assert_eq!(
            pet.all_nodes(),
            mem.all_nodes(),
            "case {i}: node set differs"
        );
        let roots: Vec<String> = pet.all_nodes().into_iter().take(1).collect();
        for depth in [Some(0), Some(1), Some(2), None] {
            assert_eq!(
                pet.release_closure(&roots, depth),
                mem.release_closure(&roots, depth),
                "case {i}: closure differs at depth {depth:?}"
            );
        }
    }
    // Applied output, so "they agree" is not "they are both empty".
    let cyc = PetGraph::from_edges([("a", "b"), ("b", "c"), ("c", "a"), ("a", "d")]);
    assert_eq!(
        cyc.cycles(),
        vec![vec!["a".to_string(), "b".to_string(), "c".to_string()]]
    );
    assert!(cyc.topo().is_err());
}

/// The BULK shape over the SAME graph the QUERY tests use: the undirected fixture
/// is one big SCC per connected component (every link is bidirectional), which is a
/// specific, checkable answer.
#[test]
fn bulk_view_of_the_undirected_fixture() {
    let m = mem();
    let comps: Vec<BTreeSet<String>> = m
        .scc()
        .into_iter()
        .map(|c| c.into_iter().collect())
        .collect();
    let main: BTreeSet<String> = ["c1", "c2", "h1", "h2", "ip", "u1", "u2"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    let far: BTreeSet<String> = ["far", "far2"].iter().map(|s| s.to_string()).collect();
    let iso: BTreeSet<String> = ["iso"].iter().map(|s| s.to_string()).collect();
    assert!(
        comps.contains(&main),
        "the connected component is not one SCC: {comps:?}"
    );
    assert!(comps.contains(&far));
    assert!(comps.contains(&iso));
    assert_eq!(comps.len(), 3);
    // A bidirectional graph has no total order.
    assert!(m.topo().is_err(), "an undirected graph must not linearize");
}
