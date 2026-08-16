// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! The entity-graph data model: the typed node, the edge provenance, the id
//! convention, and the two result shapes ([`Hit`], [`RankedPath`]). Pure types
//! with no graph logic — [`crate::Graph`] and its algorithms live in the crate
//! root, and risk ranking in [`crate::risk`].

use std::collections::BTreeMap;

use serde::Serialize;

pub const KIND_HOST: &str = "host";
pub const KIND_IP: &str = "ip";
pub const KIND_USER: &str = "user";
pub const KIND_CASE: &str = "case";
/// Register lookup: a register caseworker (a `db_user`).
pub const KIND_STAFF: &str = "staff";
/// Register lookup: a person whose record was looked up (a `target_person`).
pub const KIND_PERSON: &str = "person";

/// Edge provenance. Ordered so `Case > Event` (a stronger link wins on merge).
///
/// `Default` is `Event`, the WEAKER of the two: the shared seam merges two labels
/// recorded for the same pair with `max`, so the default can never downgrade a
/// real one.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Default, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum EdgeKind {
    #[default]
    Event,
    Case,
}

impl EdgeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            EdgeKind::Event => "event",
            EdgeKind::Case => "case",
        }
    }
}

/// Carry `EdgeKind` through the shared graph seam losslessly.
///
/// [`nornir_graph::EdgeLabel`] is the seam's domain-owned edge label: the graph
/// backends store `encode`'s `i64` and hand it back through `decode`, and never
/// learn what the variants mean. The codes are `event = 0`, `case = 1`, matching
/// this enum's own `Ord` — which is what makes the backends' numeric "stronger
/// link wins" merge reproduce [`EdgeKind`]'s ordering exactly. These are the same
/// two integers the old hand-written `kind_to_int` / `kind_from_int` pair used, so
/// nothing about the stored representation changed.
///
/// `decode` saturates rather than failing, per the trait's contract: any code at or
/// below 0 reads as `Event`, anything above as `Case`.
impl nornir_graph::EdgeLabel for EdgeKind {
    fn encode(self) -> i64 {
        match self {
            EdgeKind::Event => 0,
            EdgeKind::Case => 1,
        }
    }
    fn decode(code: i64) -> Self {
        if code >= 1 {
            EdgeKind::Case
        } else {
            EdgeKind::Event
        }
    }
}

/// Canonical node id — `"<kind>:<name>"`, e.g. `"ip:203.0.113.7"`.
pub fn node_id(kind: &str, name: &str) -> String {
    format!("{kind}:{name}")
}

/// The device / entity type of a node — the map's colour + symbol + filter key.
/// Host nodes carry a build-time `device_type` in their `meta` (derived from
/// their dominant event source/log_type + hostname, see the graph builder);
/// every other kind maps trivially here. `ip` → network, people → user, a case
/// → finding, a host with no build tag → server, anything unknown →
/// unidentified.
pub fn node_device_type(node: &Node) -> &str {
    if let Some(dt) = node.meta.get("device_type") {
        return dt;
    }
    match node.kind.as_str() {
        KIND_IP => "network",
        KIND_USER | KIND_STAFF | KIND_PERSON => "user",
        KIND_CASE => "case",
        KIND_HOST => "server",
        _ => "unidentified",
    }
}

/// A typed entity node.
#[derive(Clone, Debug, Serialize)]
pub struct Node {
    pub id: String,
    pub kind: String,
    pub name: String,
    pub label: String,
    pub meta: BTreeMap<String, String>,
}

/// One pivot result: a reachable node, its hop distance, and the provenance of
/// the edge that first reached it.
///
/// This is the shared seam's [`nornir_graph::Hit`] instantiated with garmr's own
/// payload and label, so the fields are exactly what they always were —
/// `{ hop: usize, via: EdgeKind, node: &Node }` — and every call site is
/// unchanged. The type is generic in the seam precisely so a consumer's domain
/// types ride through without the seam naming them.
pub type Hit<'a> = nornir_graph::Hit<'a, Node, EdgeKind>;

/// One attack path: a case reachable from the pivot start, with the risk it
/// carries (its level × disposition, like RBA) and the shortest route to it.
pub struct RankedPath<'a> {
    pub score: f64,
    /// The case node at the end of the path.
    pub target: &'a Node,
    /// start → … → case (node ids, for display).
    pub path: Vec<String>,
}
