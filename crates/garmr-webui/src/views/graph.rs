// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! The SVG radial node-link graph — a reusable relationship visual over an
//! `/api/graph/pivot` response (host↔ip↔user↔case, with attack paths). It is an
//! *accompaniment* to the accessible relationship table, never the only way to
//! read relationships.

use std::collections::BTreeMap;

use leptos::prelude::*;
use serde_json::Value;

use crate::api;

struct GNode {
    id: String,
    kind: String,
    name: String,
    hop: usize,
}

/// Render the graph section for a pivot response. Returns an empty note when the
/// entity is not in the case graph yet.
pub fn graph_section(g: &Value) -> AnyView {
    if !g.get("found").and_then(Value::as_bool).unwrap_or(false) {
        let start = api::s(g, "start");
        return view! {
            <div class="sub">{format!("{start} is not in the case graph yet — no linked entities in the current window.")}</div>
        }
        .into_any();
    }
    let degraded = g.get("degraded").and_then(Value::as_bool).unwrap_or(false);
    let start = api::s(g, "start");
    let connected = g
        .get("connected")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let edges = g
        .get("edges")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let edges_truncated = g
        .get("edges_truncated")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let paths = g
        .get("attack_paths")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();

    const CAP: usize = 40;
    let truncated = connected.len() > CAP;
    let (skind, sname) = split_id(&start);
    let mut nodes = vec![GNode {
        id: start.clone(),
        kind: skind,
        name: sname,
        hop: 0,
    }];
    for c in connected.iter().take(CAP) {
        nodes.push(GNode {
            id: api::s(c, "id"),
            kind: api::s(c, "kind"),
            name: api::s(c, "name"),
            hop: api::num(c, "hop") as usize,
        });
    }
    let (rel, outer) = layout(&nodes);
    let margin = 80.0;
    let size = (2.0 * (outer + margin)).max(360.0);
    let c = size / 2.0;
    let pos: BTreeMap<String, (f64, f64)> = rel
        .into_iter()
        .map(|(id, (x, y))| (id, (c + x, c + y)))
        .collect();

    let edge_views = edges
        .iter()
        .filter_map(|e| {
            let (x1, y1) = *pos.get(&api::s(e, "source"))?;
            let (x2, y2) = *pos.get(&api::s(e, "target"))?;
            let stroke = if api::s(e, "via") == "case" {
                "var(--warn)"
            } else {
                "var(--ink-mute)"
            };
            Some(view! {
                <line x1=x1 y1=y1 x2=x2 y2=y2 stroke=stroke stroke-width="1.5" opacity="0.65"/>
            })
        })
        .collect_view();

    let node_views = nodes
        .iter()
        .filter_map(|n| {
            let (x, y) = *pos.get(&n.id)?;
            let start_node = n.hop == 0;
            let r = if start_node { 10.0 } else { 7.0 };
            let ring = if start_node {
                "var(--accent)"
            } else {
                "var(--bg)"
            };
            let rw = if start_node { "2.5" } else { "2" };
            Some(view! {
                <g>
                    <circle cx=x cy=y r=r fill=kind_color(&n.kind) stroke=ring stroke-width=rw/>
                    <text x=x y={y + 18.0} text-anchor="middle" font-size="9"
                        fill="var(--ink-dim)">{short_label(&n.name)}</text>
                </g>
            })
        })
        .collect_view();

    view! {
        {degraded.then(|| view! {
            <div class="sub">"⚠ the graph is degraded — event edges were skipped (case-only)"</div>
        })}
        <div class="legend">
            <span><span style="color:#5cc8ff">"●"</span>" host"</span>
            <span><span style="color:#4bd6a0">"●"</span>" ip"</span>
            <span><span style="color:#b98cff">"●"</span>" user"</span>
            <span><span style="color:#f2b64c">"●"</span>" case"</span>
            <span><span style="color:#ff8f6b">"●"</span>" staff"</span>
            <span><span style="color:#e05c9e">"●"</span>" subject"</span>
            <span class="dimtext">"amber edge = case link · grey = event link"</span>
        </div>
        <div class="graphbox">
            <svg viewBox=format!("0 0 {size} {size}") width=size height=size role="img"
                aria-label="Entity relationship graph">
                {edge_views}
                {node_views}
            </svg>
        </div>
        {truncated.then(|| view! {
            <div class="dimtext">{format!("[graph capped to {CAP} nearest nodes]")}</div>
        })}
        {edges_truncated.then(|| view! {
            <div class="dimtext">"[edge list capped by the server — very dense graph]"</div>
        })}
        {(!paths.is_empty()).then(|| view! {
            <h3>{format!("Attack paths ({})", paths.len())}</h3>
            <div class="rows">
                {paths.into_iter().map(|p| {
                    let score = p.get("score").and_then(Value::as_f64).unwrap_or(0.0);
                    let sc = if score >= 12.0 { "bad" } else if score >= 4.0 { "warn" } else { "dim" };
                    let route = p.get("path").and_then(Value::as_array).map(|a| {
                        a.iter().filter_map(Value::as_str).collect::<Vec<_>>().join(" → ")
                    }).unwrap_or_default();
                    view! {
                        <div class="tline">
                            <span class=format!("pill {sc}")>{format!("{score:.0}")}</span>
                            <span class="mono grow">{route}</span>
                            <span class="dimtext">{api::s(&p, "rule")}</span>
                        </div>
                    }
                }).collect_view()}
            </div>
        })}
    }
    .into_any()
}

/// The connected entities as an accessible table (the non-visual alternative).
pub fn relationship_table(g: &Value) -> AnyView {
    let connected = g
        .get("connected")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    if connected.is_empty() {
        return crate::ui::empty("no linked entities in the current window");
    }
    super::table(
        &["hop", "kind", "entity"],
        connected
            .into_iter()
            .map(|c| {
                view! {
                    <tr>
                        <td class="mono dimtext">{api::num(&c, "hop").to_string()}</td>
                        <td>{crate::ui::pill("dim", api::s(&c, "kind"))}</td>
                        <td class="mono">{api::clean(&api::s(&c, "name"))}</td>
                    </tr>
                }
            })
            .collect_view()
            .into_any(),
    )
}

fn layout(nodes: &[GNode]) -> (BTreeMap<String, (f64, f64)>, f64) {
    const MIN_CHORD: f64 = 30.0;
    const HOP_GAP: f64 = 92.0;
    const SUB_GAP: f64 = 34.0;
    let mut by_hop: BTreeMap<usize, Vec<&GNode>> = BTreeMap::new();
    for n in nodes {
        by_hop.entry(n.hop).or_default().push(n);
    }
    let mut pos = BTreeMap::new();
    let mut outer = 0.0_f64;
    for (hop, group) in &by_hop {
        if *hop == 0 {
            for n in group {
                pos.insert(n.id.clone(), (0.0, 0.0));
            }
            continue;
        }
        let mut r = outer + HOP_GAP;
        let mut placed = 0usize;
        let mut sub = 0usize;
        while placed < group.len() {
            let cap = ((std::f64::consts::TAU * r) / MIN_CHORD).floor().max(1.0) as usize;
            let take = (group.len() - placed).min(cap);
            for j in 0..take {
                let ang = std::f64::consts::TAU * (j as f64) / (take as f64)
                    + (*hop as f64) * 0.6
                    + (sub as f64) * 0.35;
                pos.insert(group[placed + j].id.clone(), (r * ang.cos(), r * ang.sin()));
            }
            placed += take;
            outer = outer.max(r);
            r += SUB_GAP;
            sub += 1;
        }
    }
    (pos, outer)
}

fn kind_color(kind: &str) -> &'static str {
    match kind {
        "host" => "#5cc8ff",
        "ip" => "#4bd6a0",
        "user" => "#b98cff",
        "case" => "#f2b64c",
        "staff" => "#ff8f6b",
        "person" => "#e05c9e",
        _ => "#8fa1b8",
    }
}

fn split_id(id: &str) -> (String, String) {
    match id.split_once(':') {
        Some((k, n)) => (k.to_string(), n.to_string()),
        None => (String::new(), id.to_string()),
    }
}

fn short_label(s: &str) -> String {
    let s = api::clean(s);
    if s.chars().count() > 14 {
        format!("{}…", s.chars().take(13).collect::<String>())
    } else {
        s
    }
}