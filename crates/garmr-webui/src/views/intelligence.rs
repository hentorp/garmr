// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! Intelligence — relationships (table + 2D graph), the embedded 3D topology map,
//! ATT&CK coverage, the environment model, and threat hunts. The relationship
//! view leads with an accessible table + the graph as an accompaniment (never
//! graph-only), per the accessibility mandate; the 3D map is a sibling tab so
//! both views of the same host↔ip↔user↔case graph live in one place.

use leptos::prelude::*;
use serde_json::Value;

use crate::route::Area;
use crate::{api, timerange, ui, Store};

pub fn view(store: Store) -> impl IntoView {
    let tab = move || {
        store
            .nav
            .param("tab")
            .unwrap_or_else(|| "relationships".into())
    };
    let set_tab = move |t: &'static str| go_tab(store, t);
    view! {
        <div class="page">
            {ui::page_header("Intelligence", Area::Intelligence.blurb())}
            {super::tabs(&[
                ("relationships", "Relationships"),
                ("map", "3D map"),
                ("attack", "ATT&CK coverage"),
                ("environment", "Environment model"),
                ("hunts", "Threat hunts"),
            ], tab(), set_tab)}
            // Built once per render rather than on every query write: each tab
            // body fetches on construction, and a query write already re-renders
            // this view, so a reactive body here would fetch a second time.
            {match tab().as_str() {
                "map" => map_tab(store),
                "attack" => attack_tab(),
                "environment" => environment_tab(store),
                "hunts" => hunts_tab(),
                _ => relationships_tab(store),
            }}
        </div>
    }
}

/// Switch tab.
///
/// Publishes quietly: a tab is not a destination, so it must not scroll to the
/// top or throw focus to `<main>` the way a navigation does — that would break
/// Arrow-key movement along the tab strip. And it carries the global range,
/// which the old bare `tab={t}` dropped: changing tab silently widened the
/// window the analyst had chosen back out.
fn go_tab(store: Store, tab: &str) {
    store.nav.set_query_quiet(timerange::carry(
        &store.nav.query.get_untracked(),
        &format!("tab={tab}"),
    ));
}

/// The query string a submitted pivot publishes: the entity, its kind and the
/// hop depth, plus whether the graph is drawn — with the global time range
/// carried through untouched.
///
/// An empty entity publishes only the tab: there is no pivot to reproduce, and
/// a `name=` in the link would promise one. The graph flag is whatever the
/// toggle read at submit time — it drives no request, so toggling it afterwards
/// stays local rather than costing a round trip to say so.
fn pivot_query(kind: &str, name: &str, depth: u32, graph: bool, current: &str) -> String {
    let name = name.trim();
    let mut pairs = vec![("tab", "relationships".to_string())];
    if !name.is_empty() {
        pairs.extend([
            ("kind", kind.to_string()),
            ("name", name.to_string()),
            ("depth", depth.to_string()),
            ("graph", if graph { "1" } else { "" }.to_string()),
        ]);
    }
    super::publish_query(&pairs, current)
}

fn relationships_tab(store: Store) -> AnyView {
    // The pivot lives in the URL. Any query write (a time-range chip, a tab) re-
    // renders this tab and rebuilds these signals from scratch, so a pivot held
    // only here was erased mid-investigation — box cleared, results gone. In the
    // URL it survives, and an attack path worth tracing is worth a link that
    // reproduces it.
    let from_url = move |k: &str| store.nav.param_untracked(k).unwrap_or_default();
    let name = RwSignal::new(from_url("name"));
    let kind = RwSignal::new(
        store
            .nav
            .param_untracked("kind")
            .unwrap_or_else(|| "host".into()),
    );
    let depth = RwSignal::new(from_url("depth").parse().unwrap_or(2u32));
    let show_graph = RwSignal::new(from_url("graph") == "1");
    let f = super::Fetch::new();

    // Submit publishes and nothing else; the re-render reads the pivot back out
    // of the URL and issues the single request below.
    let submit = move || {
        store.nav.set_query_quiet(pivot_query(
            &kind.get_untracked(),
            &name.get_untracked(),
            depth.get_untracked(),
            show_graph.get_untracked(),
            &store.nav.query.get_untracked(),
        ));
    };

    // Whatever the URL asks for: a deep link, a reload, Back/Forward, a submit.
    let entity = name.get_untracked().trim().to_string();
    if !entity.is_empty() {
        f.load(format!(
            "/api/graph/pivot?kind={}&name={}&depth={}",
            api::enc(&kind.get_untracked()),
            api::enc(&entity),
            depth.get_untracked()
        ));
    }
    view! {
        <div>
            <p class="sub">"Pivot on an entity "{ui::help_tip("Relationships map how entities connect — which hosts, IPs, users and investigations touch each other. Pivoting on one entity pulls back everything linked to it, so you can trace an attack path from a single starting point.")}" to see everything linked to it (host↔ip↔user↔case) and any attack paths — as a table first, with the node-link graph as an option."</p>
            <div class="searchbar">
                <select on:change=move |ev| kind.set(event_target_value(&ev))>
                    {["host", "ip", "user", "staff", "person", "case"].into_iter().map(|k| view! { <option value=k selected=move || kind.get()==k>{k}</option> }).collect_view()}
                </select>
                <input type="search" class="grow" placeholder="entity name / id" prop:value=move || name.get()
                    on:input=move |ev| name.set(event_target_value(&ev)) on:keydown=move |ev| if ev.key()=="Enter" { submit() }/>
                <select on:change=move |ev| depth.set(event_target_value(&ev).parse().unwrap_or(2))>
                    {[1u32,2,3].into_iter().map(|d| view! { <option value=d.to_string() selected=move || depth.get()==d>{format!("{d} hops")}</option> }).collect_view()}
                </select>
                <button class="btn primary" on:click=move |_| submit()>"Pivot"</button>
                <label class="toggle"><input type="checkbox" prop:checked=move || show_graph.get() on:change=move |ev| show_graph.set(event_target_checked(&ev))/>" graph"</label>
                <button class="btn ghost" on:click=move |_| go_tab(store, "map")>"Open the 3D map →"</button>
            </div>
            {move || {
                if let Some(e) = f.err.get() { return super::error_state(e); }
                match f.data.get() {
                    None => ui::empty("pivot on an entity to explore its relationships"),
                    Some(g) => view! {
                        <section class="sect"><h3>"Linked entities"</h3>{crate::views::graph::relationship_table(&g)}</section>
                        {show_graph.get().then(|| view! { <section class="sect"><h3>"Graph"</h3>{crate::views::graph::graph_section(&g)}</section> })}
                    }.into_any(),
                }
            }}
        </div>
    }.into_any()
}

/// The embedded 3D entity topology (host↔ip↔user↔case), served by the backend at
/// `/map/` and shown in an iframe. Case nodes glow red as findings; clicking a
/// node posts a same-origin message that the shell turns into an entity-drawer
/// peek or a jump to the investigation (see `install_message_bridge` in
/// `lib.rs`). Never the *only* way to read relationships — the accessible
/// table lives in the Relationships tab. Follows the global time range.
fn map_tab(store: Store) -> AnyView {
    // The map reads the same time window as the rest of the console; pass it on
    // the iframe URL so a preset/absolute range scopes the graph.
    let src = move || format!("/map/{}", store.time_range.get().graph_query());
    view! {
        <div>
            <div class="row">
                <p class="sub grow">"The same host↔ip↔user↔case links as the Relationships tab, drawn as a live 3D graph — investigation nodes glow red as findings. Click a node to peek the entity or open its investigation."</p>
                <button
                    class="btn ghost"
                    title="Accessible alternative: the same relationships as a table + attack paths"
                    on:click=move |_| go_tab(store, "relationships")
                >
                    "Accessible relationship table →"
                </button>
            </div>
            <div class="map-embed">
                <iframe
                    class="map-frame"
                    title="3D topology"
                    src=src
                    referrerpolicy="no-referrer"
                ></iframe>
            </div>
            <p class="sub map-note">
                "The 3D view is not keyboard-navigable; use the Relationships tab for the same links as an accessible table."
            </p>
        </div>
    }
    .into_any()
}

fn attack_tab() -> AnyView {
    let f = super::Fetch::new();
    f.load("/api/attack/coverage".into());
    let body = move || {
        if let Some(e) = f.err.get() {
            return super::error_state(e);
        }
        let Some(v) = f.data.get() else {
            return ui::loading("loading coverage…");
        };
        let total = v.get("rules_total").and_then(Value::as_i64).unwrap_or(0);
        let tactics = super::arr(&v, "tactics");
        let rows = tactics
            .iter()
            .map(|t| {
                let rules = api::num(t, "rules");
                let pill = if rules > 0 {
                    ui::pill("pass", format!("{rules}"))
                } else {
                    ui::pill("dim", "0")
                };
                view! {
                    <tr>
                        <td>{api::s(t, "name")}</td>
                        <td>{pill}</td>
                        <td class="mono dimtext">{api::num(t, "techniques").to_string()}</td>
                    </tr>
                }
            })
            .collect_view()
            .into_any();
        let meta = format!("{total} rules across {} tactics", tactics.len());
        view! {
            <div class="row resultmeta"><span class="dimtext">{meta}</span></div>
            {super::table(&["tactic", "rules", "techniques"], rows)}
        }
        .into_any()
    };
    view! {
        <div>
            <p class="sub">"MITRE ATT&CK coverage of the active ruleset — which tactics and techniques the detections span. "<ui::InfoPopover heading="ATT&CK coverage" body="MITRE ATT&CK is an industry catalogue of attacker tactics (the goals, like Persistence or Exfiltration) and techniques (the specific methods). Coverage counts how many of your active detection rules map to each tactic. A tactic with zero rules is a blind spot — attacker behaviour there would go undetected."/></p>
            {body}
        </div>
    }
    .into_any()
}

fn environment_tab(store: Store) -> AnyView {
    let facts = super::Fetch::new();
    let cands = super::Fetch::new();
    facts.load("/api/env/facts".into());
    cands.load("/api/env/candidates".into());
    view! {
        <div>
            <p class="sub">"The temporal environment model "{ui::help_tip("The environment model is garmr's learned picture of what is normal here — which users sign in where, which services talk to which, and so on. New observations are quarantined as candidates first (so an attacker cannot quietly poison what counts as normal) until an operator promotes them to Trusted.")}" — the learned, gated picture of what is normal. Candidates age through an anti-poisoning quarantine before an operator promotes them to Trusted."</p>
            {move || store.caps.get().and_then(|c| { let fs = c.feature("environment_model"); (fs.state != "healthy").then(|| ui::banner(fs.class(), fs.reason.clone().unwrap_or_default())) })}
            <section class="sect"><h3>"Trusted facts"</h3>
                {facts.framed("facts", "No environment facts have been trusted yet — observations start as quarantined candidates below, and the ones you promote become trusted parts of the model.", env_table)}
            </section>
            <section class="sect"><h3>"Candidates (quarantine)"</h3>
                {cands.framed("candidates", "no candidate facts — the learner promotes observations here before an operator trusts them", env_table)}
            </section>
        </div>
    }.into_any()
}

fn env_table(rows: Vec<Value>) -> AnyView {
    super::table(
        &["state", "attribute", "entity", "value"],
        rows.into_iter()
            .map(|r| {
                let state = api::s(&r, "state");
                let cls = if state == "trusted" { "pass" } else { "warn" };
                let ent = {
                    let k = r
                        .get("entity")
                        .map(|e| api::s(e, "kind"))
                        .unwrap_or_default();
                    let i = r.get("entity").map(|e| api::s(e, "id")).unwrap_or_default();
                    if k.is_empty() {
                        i
                    } else {
                        format!("{k}:{i}")
                    }
                };
                view! {
                    <tr>
                        <td>{ui::pill(cls, if state.is_empty() { "—".into() } else { crate::status::humanize(&state) })}</td>
                        <td class="mono">{api::s(&r, "attribute")}</td>
                        <td class="mono dimtext">{api::clean(&ent)}</td>
                        <td class="mono">{api::clean(&api::s(&r, "value"))}</td>
                    </tr>
                }
            })
            .collect_view()
            .into_any(),
    )
}

fn hunts_tab() -> AnyView {
    let f = super::Fetch::new();
    f.load("/api/hunts".into());
    view! {
        <div>
            <p class="sub">"Threat-hunt reports "{ui::help_tip("A threat hunt is a hypothesis-driven investigation: you pose a question — is anyone exfiltrating data over DNS? — and the agent searches your data read-only to confirm or clear it. Each run is priced by the model tokens it uses.")}" — ad-hoc, model-priced hypothesis runs over the read-only tool loop. Scheduled hunts live as TOML in the detect hunts dir."</p>
            {f.framed("hunts", "No threat-hunt reports yet — start a hypothesis-driven hunt over your data to generate one (CLI: garmr hunt, or a scheduled hunt).", |rows| {
                super::table(&["id", "outcome", "findings", "cost", "hypothesis"],
                    rows.into_iter().map(|r| view! {
                        <tr>
                            <td class="mono dimtext">{api::short(&r, "id")}</td>
                            <td>{ui::pill(crate::status::outcome_class(&api::s(&r, "outcome")), crate::status::humanize(&api::s(&r, "outcome")))}</td>
                            <td class="mono dimtext">{api::num(&r, "findings").to_string()}</td>
                            <td class="mono dimtext">{format!("${:.4}", r.get("cost_usd").and_then(Value::as_f64).unwrap_or(0.0))}</td>
                            <td class="msg">{api::clean(&api::s(&r, "hypothesis"))}</td>
                        </tr>
                    }).collect_view().into_any())
            })}
        </div>
    }.into_any()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::route::param_of;
    use crate::TimeRange;

    /// The bug: the pivot lived only in view-local signals, so one click on a
    /// time-range chip cleared the entity box and dropped the results table —
    /// mid-investigation, with no way back but retyping.
    #[test]
    fn a_submitted_pivot_is_carried_by_the_url() {
        let q = pivot_query("ip", "10.0.0.7", 3, false, "tab=relationships&t=24h");
        assert_eq!(param_of(&q, "kind"), Some("ip".into()));
        assert_eq!(param_of(&q, "name"), Some("10.0.0.7".into()));
        assert_eq!(param_of(&q, "depth"), Some("3".into()));
        assert_eq!(param_of(&q, "tab"), Some("relationships".into()));
        // …and the window the analyst chose comes along.
        assert_eq!(timerange::read_param(&q), Some(TimeRange::Last(24)));
    }

    /// Switching tab used to publish a bare `tab=…`, which dropped the range.
    #[test]
    fn switching_tab_keeps_the_chosen_range() {
        let q = timerange::carry("tab=relationships&name=pve&t=72h", "tab=map");
        assert_eq!(timerange::read_param(&q), Some(TimeRange::Last(72)));
        assert_eq!(param_of(&q, "tab"), Some("map".into()));
        // The pivot does not follow you to another tab.
        assert_eq!(param_of(&q, "name"), None);
    }

    /// Nothing to pivot on means nothing to promise: no `name=` in the link.
    #[test]
    fn an_empty_pivot_publishes_only_the_tab() {
        for entity in ["", "   "] {
            let q = pivot_query("host", entity, 2, false, "t=24h");
            assert_eq!(param_of(&q, "name"), None, "{entity:?} published a name");
            assert_eq!(param_of(&q, "kind"), None);
            assert_eq!(param_of(&q, "tab"), Some("relationships".into()));
            assert_eq!(timerange::read_param(&q), Some(TimeRange::Last(24)));
        }
    }

    /// The graph is a display choice, so it rides along only when it is on —
    /// an absent `graph=` is the off state, not a missing one.
    #[test]
    fn the_graph_toggle_rides_along_only_when_on() {
        let on = pivot_query("host", "pve", 2, true, "");
        assert_eq!(param_of(&on, "graph"), Some("1".into()));
        let off = pivot_query("host", "pve", 2, false, "");
        assert_eq!(param_of(&off, "graph"), None);
    }

    /// Entity ids are arbitrary — a Windows account, a path-like case id — and
    /// must round-trip exactly, or a shared link pivots on something else.
    #[test]
    fn awkward_entity_ids_survive_the_url() {
        for raw in [
            "domain\\user",
            "a/b",
            "host with spaces",
            "user@example.com",
            "unicode-ÅÄÖ",
            "q?x=1&y=2",
        ] {
            let q = pivot_query("user", raw, 2, false, "t=24h");
            assert_eq!(
                param_of(&q, "name").as_deref(),
                Some(raw),
                "{raw} did not round-trip"
            );
            // …and cannot smuggle in or clobber another parameter.
            assert_eq!(param_of(&q, "tab"), Some("relationships".into()));
            assert_eq!(param_of(&q, "depth"), Some("2".into()));
            assert_eq!(timerange::read_param(&q), Some(TimeRange::Last(24)));
        }
    }
}
