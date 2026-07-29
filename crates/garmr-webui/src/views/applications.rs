// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! Applications — the reconciled application inventory (DoD 4). It matches the
//! declared applications (catalog) against the observed ones (behavioral
//! baselines plus recent activity), so an operator sees governance gaps: shadow
//! apps that are active but undeclared, and dormant apps that are declared but
//! idle, rather than just a host event-count. Per-application detail shows the
//! declaration, the baseline footprint (what the app touches), its top users and
//! objects, and recent activity. Read-only: declaring an application is a governed
//! registry promotion.

use leptos::prelude::*;
use serde_json::Value;

use crate::route::{Area, View};
use crate::{api, status, ui, Store};

/// Trim an RFC3339 timestamp to `YYYY-MM-DD HH:MM:SS`.
fn fmt_ts(v: &str) -> String {
    if v.is_empty() {
        return "—".into();
    }
    let t = v.split('.').next().unwrap_or(v);
    t.trim_end_matches('Z').replace('T', " ")
}

/// The governance badges for a row/detail (declared / shadow / dormant / active).
fn governance_badges(r: &Value) -> AnyView {
    let declared = r.get("declared").and_then(Value::as_bool).unwrap_or(false);
    let dormant = r.get("dormant").and_then(Value::as_bool).unwrap_or(false);
    view! {
        <span class="row">
            {if declared { ui::pill("pass", "declared") } else { ui::pill("bad", "shadow") }}
            {dormant.then(|| ui::pill("warn", "dormant"))}
            {(declared && !dormant).then(|| ui::pill("dim", "active"))}
        </span>
    }
    .into_any()
}

pub fn list_view(store: Store) -> impl IntoView {
    let f = super::Fetch::new();
    let reload = move || f.load("/api/applications".into());
    reload();
    let text = RwSignal::new(String::new());
    view! {
        <div class="page">
            <div class="page-header row">
                <div class="grow"><h1>"Applications"</h1><div class="sub">{Area::Applications.blurb()}</div></div>
                <button class="btn ghost" on:click=move |_| reload()>"↻ Refresh"</button>
            </div>
            <p class="sub">"Declared applications (catalog) reconciled with observed activity. Shadow = active but undeclared; dormant = declared but idle. Declaring an app is a governed registry promotion, not a console write. "{ui::help_tip("An application here is a service or app that talks to your data — a reporting tool, an API, a batch job — together with the host it runs on. garmr groups activity by application so you can see what each one is doing and touching.")}</p>
            {move || store.caps.get().and_then(|c| {
                let fs = c.feature("app_audit");
                (fs.state == "disabled").then(|| ui::disabled_panel("Application audit", &fs))
            })}
            <div class="filterbar">
                <input type="search" class="grow" placeholder="filter by name, owner or team…"
                    prop:value=move || text.get() on:input=move |ev| text.set(event_target_value(&ev))/>
            </div>
            {move || {
                if let Some(e) = f.err.get() {
                    if e.status == 404 { return ui::empty("Application audit is turned off, so there is no application inventory. An administrator can enable it to start reconciling declared apps against observed activity."); }
                    return super::error_state(e);
                }
                let tq = text.get().to_lowercase();
                let rows: Vec<Value> = f.rows("applications").into_iter()
                    .filter(|r| {
                        if tq.is_empty() { return true; }
                        [api::s(r, "name"), api::s(r, "owner"),
                         super::arr(r, "team").iter().filter_map(|t| t.as_str()).collect::<Vec<_>>().join(" ")]
                            .iter().any(|s| s.to_lowercase().contains(&tq))
                    })
                    .collect();
                if rows.is_empty() {
                    if f.loading.get() { return ui::loading("loading application inventory…"); }
                    return ui::empty("No applications declared or observed yet. Declared apps come from the governed catalog; observed ones appear here automatically as garmr sees them touch your data.");
                }
                let meta = f.data.get();
                let (dec, obs, scanned) = meta.as_ref()
                    .map(|v| (api::num(v, "declared_total"), api::num(v, "observed_total"), api::num(v, "scanned")))
                    .unwrap_or((0, 0, 0));
                view! {
                    <div class="row resultmeta"><span class="dimtext">{format!("{} applications · {} declared · {} observed · {} events scanned", rows.len(), dec, obs, scanned)}</span></div>
                    {super::table(&["application", "governance", "activity", "baseline"],
                        rows.into_iter().map(|r| {
                            let name = api::s(&r, "name");
                            let nc = name.clone();
                            let owner = api::s(&r, "owner");
                            let team = super::arr(&r, "team").iter().filter_map(|t| t.as_str().map(String::from)).collect::<Vec<_>>().join(", ");
                            let act = r.get("activity").cloned().unwrap_or(Value::Null);
                            let bl = r.get("baseline").cloned().unwrap_or(Value::Null);
                            let last = fmt_ts(&api::s(&act, "last"));
                            view! {
                                <tr class="rowlink" on:click=move |_| store.nav.go(View::Application(nc.clone()))>
                                    <td>
                                        <div class="mono">{if name.is_empty() { "—".into() } else { name.clone() }}</div>
                                        <div class="dimtext">{if owner.is_empty() && team.is_empty() { "—".to_string() } else if team.is_empty() { owner } else { format!("{owner} · {team}") }}</div>
                                    </td>
                                    <td>{governance_badges(&r)}</td>
                                    <td>
                                        <div class="mono">{format!("{} ev · {} users · {} objs", api::num(&act, "events"), api::num(&act, "distinct_users"), api::num(&act, "distinct_objects"))}</div>
                                        <div class="dimtext">{format!("last {last}")}</div>
                                    </td>
                                    <td>{if bl.is_null() { ui::pill("dim", "—") } else { ui::pill(status::baseline_class(&api::s(&bl, "state")), api::s(&bl, "state")) }}</td>
                                </tr>
                            }
                        }).collect_view().into_any())}
                }.into_any()
            }}
        </div>
    }
}

pub fn detail_view(_store: Store, name: String) -> impl IntoView {
    let f = super::Fetch::new();
    f.load(format!("/api/applications/{}", api::enc(&name)));
    view! {
        <div class="page">
            {move || {
                if let Some(e) = f.err.get() {
                    if e.status == 404 { return ui::empty(api::clean(&e.message)); }
                    return super::error_state(e);
                }
                match f.data.get() {
                    None => ui::loading("loading application…"),
                    Some(d) => app_detail(&d),
                }
            }}
        </div>
    }
}

fn app_detail(d: &Value) -> AnyView {
    let name = api::s(d, "name");
    let declared = d.get("declared").and_then(Value::as_bool).unwrap_or(false);
    let decl = d.get("declaration").cloned().unwrap_or(Value::Null);
    let bl = d.get("baseline").cloned().unwrap_or(Value::Null);
    let fp = d.get("footprint").cloned().unwrap_or(Value::Null);
    let sum = d.get("activity_summary").cloned().unwrap_or(Value::Null);
    let truncated = d.get("truncated").and_then(Value::as_bool).unwrap_or(false);
    view! {
        {ui::page_header(if name.is_empty() { "—".into() } else { name.clone() }, "Application — declaration, footprint, users and activity.")}
        <div class="row">{governance_badges(d)}</div>

        {(!declared).then(|| ui::banner("bad", "Shadow application — active but not declared in the catalog. Declare it (a governed registry promotion) to bring it under governance."))}

        <div class="card">
            <div class="card-head"><h3>"Declaration"</h3></div>
            {if declared && !decl.is_null() {
                ui::kv_list(vec![
                    ("Owner", opt(&decl, "owner")),
                    ("Team", super::arr(&decl, "team").iter().filter_map(|t| t.as_str().map(String::from)).collect::<Vec<_>>().join(", ")),
                    ("Business purpose", opt(&decl, "business_purpose")),
                    ("Description", opt(&decl, "description")),
                ])
            } else {
                ui::empty("not declared in the catalog")
            }}
        </div>

        {(!bl.is_null()).then(|| view! {
            <div class="card">
                <div class="row">
                    {ui::pill(status::baseline_class(&api::s(&bl, "state")), api::s(&bl, "state"))}
                    <span class="dimtext">"Maturity"</span><span class="mono">{api::s(&bl, "maturity")}</span>
                    <span class="dimtext">"Observations"</span><span class="mono">{api::num(&bl, "observations").to_string()}</span>
                    <span class="dimtext">"Span"</span><span class="mono">{format!("{}d", api::num(&bl, "span_days"))}</span>
                </div>
                <h4 style="margin:12px 0 4px">"Footprint — what this application touches"{ui::help_tip("The databases, tables, operations and clients this application has actually been observed using. It is how you tell at a glance whether an app is reaching sensitive data it has no business touching.")}</h4>
                {footprint_cards(&fp)}
            </div>
        })}

        <h4 style="margin:14px 0 4px">{format!("Activity ({} events)", api::num(&sum, "events"))}{ui::help_tip("A recent, bounded snapshot of what this application has done — the total events plus how many were exports, privileged, denied or failed — not all-time totals.")}</h4>
        {truncated.then(|| ui::banner("warn", "Partial — the activity scan hit its cap; older activity in the window may be omitted."))}
        <div class="tiles">
            {ui::metric("distinct users", api::num(&sum, "distinct_users").to_string(), "dim", None)}
            {atile(&sum, "exports", false)}
            {atile(&sum, "privileged", false)}
            {atile(&sum, "denied", true)}
            {atile(&sum, "failed", true)}
        </div>

        <div class="row">
            <section class="sect grow"><h3>"Top users"</h3>{top_list(&super::arr(d, "top_users"))}</section>
            <section class="sect grow"><h3>"Top objects"</h3>{top_list(&super::arr(d, "top_objects"))}</section>
        </div>

        <section class="sect">
            <h3>"Recent access"</h3>
            {let recent = super::arr(d, "recent");
             if recent.is_empty() {
                ui::empty("no activity for this application in the window")
             } else {
                super::table(&["time", "actor", "object", "operation", "outcome", "flags"],
                    recent.iter().map(|a| {
                        let outcome = api::s(a, "outcome");
                        let oc = if outcome == "success" { "pass" } else if outcome == "denied" || outcome == "failure" || outcome == "error" { "bad" } else { "dim" };
                        let flags = super::arr(a, "flags").iter().filter_map(|x| x.as_str().map(String::from)).collect::<Vec<_>>().join(", ");
                        view! {
                            <tr>
                                <td class="mono dimtext">{fmt_ts(&api::s(a, "ts"))}</td>
                                <td class="mono">{api::s(a, "actor")}</td>
                                <td class="mono dimtext">{api::s(a, "object")}</td>
                                <td class="dimtext">{api::s(a, "operation")}</td>
                                <td>{ui::pill(oc, if outcome.is_empty() { "—".into() } else { outcome })}</td>
                                <td class="dimtext">{flags}</td>
                            </tr>
                        }
                    }).collect_view().into_any())
             }}
        </section>
    }
    .into_any()
}

/// One card per footprint dimension with any values.
fn footprint_cards(fp: &Value) -> AnyView {
    const DIMS: &[(&str, &str)] = &[
        ("objects", "Objects / tables"),
        ("schemas", "Schemas"),
        ("databases", "Databases"),
        ("operations", "Operations"),
        ("query_fingerprints", "Query fingerprints"),
        ("clients", "Clients"),
        ("source_hosts", "Source hosts"),
    ];
    let cards: Vec<AnyView> = DIMS.iter().filter_map(|(key, label)| {
        let dim = fp.get(*key).cloned().unwrap_or(Value::Null);
        let distinct = api::num(&dim, "distinct");
        if distinct == 0 { return None; }
        let top = super::arr(&dim, "top");
        Some(view! {
            <div class="card" style="flex:1; min-width:200px">
                <div class="row"><strong>{*label}</strong><span class="mono dimtext">{format!("{distinct} distinct")}</span></div>
                <dl class="fields">
                    {top.into_iter().take(6).map(|t| {
                        let v = api::s(&t, "value");
                        view! { <dt class="mono">{if v.is_empty() { "—".into() } else { v }}</dt><dd class="mono dimtext">{api::num(&t, "count").to_string()}</dd> }
                    }).collect_view()}
                </dl>
            </div>
        }.into_any())
    }).collect();
    if cards.is_empty() {
        return ui::empty("no learned footprint yet");
    }
    view! { <div class="row" style="flex-wrap:wrap; align-items:stretch; gap:10px">{cards}</div> }
        .into_any()
}

fn top_list(rows: &[Value]) -> AnyView {
    if rows.is_empty() {
        return ui::empty("none");
    }
    super::table(&["value", "count"],
        rows.iter().map(|r| view! {
            <tr><td class="mono">{api::s(r, "value")}</td><td class="mono dimtext">{api::num(r, "count").to_string()}</td></tr>
        }).collect_view().into_any())
}

fn atile(sum: &Value, key: &str, bad: bool) -> AnyView {
    let n = api::num(sum, key);
    let cls = if n == 0 {
        "pass"
    } else if bad {
        "bad"
    } else {
        "warn"
    };
    ui::metric(key.to_string(), n.to_string(), cls, None)
}

fn opt(v: &Value, k: &str) -> String {
    let s = api::s(v, k);
    if s.is_empty() {
        "—".into()
    } else {
        s
    }
}