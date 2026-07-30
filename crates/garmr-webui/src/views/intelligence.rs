// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! Intelligence — relationships, ATT&CK coverage, the environment model, and
//! threat hunts. The relationship view leads with an accessible table + the graph
//! as an accompaniment (never graph-only), per the accessibility mandate.

use leptos::prelude::*;
use serde_json::Value;

use crate::route::Area;
use crate::{api, ui, Store};

pub fn view(store: Store) -> impl IntoView {
    let tab = move || {
        store
            .nav
            .param("tab")
            .unwrap_or_else(|| "relationships".into())
    };
    let set_tab = move |t: &'static str| store.nav.set_query(format!("tab={t}"));
    view! {
        <div class="page">
            {ui::page_header("Intelligence", Area::Intelligence.blurb())}
            {super::tabs(&[
                ("relationships", "Relationships"),
                ("attack", "ATT&CK"),
                ("environment", "Environment"),
                ("hunts", "Hunts"),
            ], tab(), set_tab)}
            {move || match tab().as_str() {
                "attack" => attack_tab(),
                "environment" => environment_tab(store),
                "hunts" => hunts_tab(),
                _ => relationships_tab(store),
            }}
        </div>
    }
}

fn relationships_tab(store: Store) -> AnyView {
    let query = RwSignal::new(String::new());
    let kind = RwSignal::new("host".to_string());
    let depth = RwSignal::new(2u32);
    let show_graph = RwSignal::new(false);
    let f = super::Fetch::new();
    let run = move || {
        let n = query.get_untracked().trim().to_string();
        if n.is_empty() {
            return;
        }
        f.load(format!(
            "/api/graph/pivot?kind={}&name={}&depth={}",
            api::enc(&kind.get_untracked()),
            api::enc(&n),
            depth.get_untracked()
        ));
    };
    view! {
        <div>
            <p class="sub">"Pivot on an entity "{ui::help_tip("Relationships map how entities connect — which hosts, IPs, users and investigations touch each other. Pivoting on one entity pulls back everything linked to it, so you can trace an attack path from a single starting point.")}" to see everything linked to it (host↔ip↔user↔case) and any attack paths — as a table first, with the node-link graph as an option."</p>
            <div class="searchbar">
                <select on:change=move |ev| kind.set(event_target_value(&ev))>
                    {["host", "ip", "user", "staff", "person", "case"].into_iter().map(|k| view! { <option value=k selected=move || kind.get()==k>{k}</option> }).collect_view()}
                </select>
                <input type="search" class="grow" placeholder="entity name / id" prop:value=move || query.get()
                    on:input=move |ev| query.set(event_target_value(&ev)) on:keydown=move |ev| if ev.key()=="Enter" { run() }/>
                <select on:change=move |ev| depth.set(event_target_value(&ev).parse().unwrap_or(2))>
                    {[1u32,2,3].into_iter().map(|d| view! { <option value=d.to_string() selected=move || depth.get()==d>{format!("{d} hops")}</option> }).collect_view()}
                </select>
                <button class="btn primary" on:click=move |_| run()>"Pivot"</button>
                <label class="toggle"><input type="checkbox" prop:checked=move || show_graph.get() on:change=move |ev| show_graph.set(event_target_checked(&ev))/>" graph"</label>
                <button class="btn ghost" on:click=move |_| store.nav.go(crate::route::View::Map)>"Open 3D Map →"</button>
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