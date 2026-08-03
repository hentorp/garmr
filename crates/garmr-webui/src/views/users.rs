// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! Users — the people and accounts directory (db users, staff/caseworkers, data
//! subjects, service accounts) and per-user detail: behaviour, risk, baseline
//! maturity, cases, and the available monitoring lifecycle.
//!
//! There is no dedicated user-CRUD API; the directory is derived from the
//! application-audit behavioral baselines + the RBA risk axis (the entities garmr
//! actually knows about), and each user resolves to its entity page. The one
//! genuine monitoring control today is the baseline trust lifecycle
//! (heighten / clear), which the server admin surface exposes.

use leptos::prelude::*;
use serde_json::Value;

use crate::route::{Area, View};
use crate::{api, ui, Store};

/// Kinds from the baseline plane that represent people/accounts.
fn is_user_kind(kind: &str) -> bool {
    matches!(
        kind,
        "User" | "Staff" | "Person" | "DbUser" | "ServiceAccount" | "user" | "staff" | "person"
    )
}

pub fn list_view(store: Store) -> impl IntoView {
    let baselines = super::Fetch::new();
    let risk = super::Fetch::new();
    let reload = move || {
        baselines.load("/api/appaudit/baselines".into());
        risk.load("/api/risk".into());
    };
    reload();
    let text = RwSignal::new(String::new());

    view! {
        <div class="page">
            <div class="page-header row">
                <div class="grow"><h1>"Users"</h1><div class="sub">{Area::Users.blurb()}</div></div>
                <button class="btn ghost" on:click=move |_| reload()>"↻ Refresh"</button>
            </div>
            <p class="sub">"Every person or account garmr has observed, each with its learned behavioral baseline and current risk score. "{ui::help_tip("The risk score is a running total kept by the risk-based-alerting engine: routine, expected activity barely moves it, while unusual or sensitive actions add to it. \"over\" means it has crossed the review threshold and is worth a look — a prompt to check, not a verdict of wrongdoing.")}</p>
            {move || store.caps.get().and_then(|c| {
                let fs = c.feature("app_audit");
                (fs.state == "disabled").then(|| ui::disabled_panel("Application audit", &fs))
            })}
            <div class="filterbar">
                <input type="search" class="grow" placeholder="filter by name…"
                    prop:value=move || text.get() on:input=move |ev| text.set(event_target_value(&ev))/>
            </div>
            {move || {
                if let Some(e) = baselines.err.get() {
                    if e.status == 404 {
                        return ui::empty("Application audit is turned off, so there are no user baselines to show. An administrator can enable it to start profiling accounts.");
                    }
                    return super::error_state(e);
                }
                // Risk-by-subject lookup for the staff/user axis.
                let risk_of: std::collections::HashMap<String, (f64, bool)> = risk.rows("risk")
                    .into_iter()
                    .filter(|r| matches!(api::s(r, "kind").as_str(), "staff" | "user"))
                    .map(|r| (api::s(&r, "host"),
                        (r.get("score").and_then(Value::as_f64).unwrap_or(0.0),
                         r.get("over_threshold").and_then(Value::as_bool).unwrap_or(false))))
                    .collect();
                let tq = text.get().to_lowercase();
                let rows: Vec<Value> = baselines.rows("baselines").into_iter()
                    .filter(|b| is_user_kind(&api::s(b, "kind")))
                    .filter(|b| tq.is_empty() || api::s(b, "id").to_lowercase().contains(&tq))
                    .collect();
                if rows.is_empty() {
                    if baselines.loading.get() { return ui::loading("loading users…"); }
                    return ui::empty("No user profiles yet. garmr builds these automatically as it observes account activity — check back once some has been ingested.");
                }
                super::table(&["user", "kind", "baseline", "maturity", "observations", "risk"],
                    rows.into_iter().map(|b| {
                        let id = api::s(&b, "id");
                        let idc = id.clone();
                        let kind = api::s(&b, "kind");
                        let state = api::s(&b, "state");
                        let (score, over) = risk_of.get(&id).copied().unwrap_or((0.0, false));
                        view! {
                            <tr class="rowlink" on:click=move |_| store.nav.go(View::User(idc.clone()))>
                                <td class="mono">
                                    <ui::ViewLink view=View::User(id.clone()) class="rowtarget">
                                        {id.clone()}
                                    </ui::ViewLink>
                                </td>
                                <td>{ui::pill("dim", crate::status::humanize(&kind))}</td>
                                <td>{ui::pill(crate::status::baseline_class(&state), if state.is_empty() { "—".into() } else { state })}</td>
                                <td>{api::s(&b, "maturity")}</td>
                                <td class="mono dimtext">{api::num(&b, "observations").to_string()}</td>
                                <td>{if over { ui::pill("bad", format!("{score:.0} over")) } else { ui::pill("dim", format!("{score:.0}")) }}</td>
                            </tr>
                        }
                    }).collect_view().into_any())
            }}
        </div>
    }
}

pub fn detail_view(store: Store, name: String) -> impl IntoView {
    let entity = super::Fetch::new();
    let baselines = super::Fetch::new();
    // Probe the most specific kind first; keep whichever resolves.
    let resolved = RwSignal::new(Option::<String>::None);
    {
        let name = name.clone();
        leptos::task::spawn_local(async move {
            for kind in ["staff", "person", "user"] {
                if let Ok(v) =
                    api::send_get(&format!("/api/entity/{}/{}", kind, api::enc(&name))).await
                {
                    // has data if any cases or activity
                    let has = !super::arr(&v, "cases").is_empty()
                        || !super::arr(&v, "recent_events").is_empty()
                        || v.get("activity").is_some();
                    if has {
                        resolved.set(Some(kind.to_string()));
                        entity.data.set(Some(v));
                        return;
                    }
                }
            }
            // Fall back to user even if empty, so the page renders something.
            if let Ok(v) = api::send_get(&format!("/api/entity/user/{}", api::enc(&name))).await {
                resolved.set(Some("user".into()));
                entity.data.set(Some(v));
            } else {
                entity.err.set(Some(api::ApiError {
                    status: 404,
                    message: "user not found".into(),
                }));
            }
        });
    }
    baselines.load("/api/appaudit/baselines".into());
    let name_hdr = name.clone();

    view! {
        <div class="page">
            {ui::page_header(name_hdr.clone(), "User — behaviour, risk, monitoring and investigations.")}
            {behavioral_panel(name.clone())}
            {monitoring_panel(store, name.clone(), baselines)}
            {peer_panel(name.clone())}
            {move || {
                if let Some(e) = entity.err.get() { return super::error_state(e); }
                match (resolved.get(), entity.data.get()) {
                    (Some(kind), Some(p)) => crate::views::entity::entity_page(store, &kind, &name, &p),
                    _ => ui::loading("resolving user…"),
                }
            }}
        </div>
    }
}

/// Behavioral profile (Phase B / DoD 3): the learned per-dimension footprint (the
/// apps/objects/schemas/databases/fingerprints/operations/clients the user
/// touches), the hour-of-day + weekday activity, the rows/bytes-read volume, and a
/// bounded sensitive-activity summary (exports / privilege / bulk / admin / denied).
/// Read-only — from `GET /api/users/:id`.
fn behavioral_panel(name: String) -> AnyView {
    let f = super::Fetch::new();
    f.load(format!("/api/users/{}", api::enc(&name)));
    view! {
        <div class="card">
            <div class="card-head"><h3>"Behavioral profile"</h3>
                <ui::InfoPopover heading="Behavioral profile & baseline"
                    body="A baseline is the picture of normal that garmr learns for this account by watching what it actually does — the apps and tables it touches, the hours it is active, and how much it reads. While there is too little history it stays a Candidate and is not yet trusted; once there is enough it becomes Trusted, and detectors can then flag activity that falls outside this learned footprint."/>
            </div>
            {move || {
                if let Some(e) = f.err.get() {
                    if e.status == 404 {
                        return ui::empty("no learned baseline for this user yet — it needs to observe some activity first");
                    }
                    return super::error_state(e);
                }
                match f.data.get() {
                    None => ui::loading("loading behavioral profile…"),
                    Some(d) => profile_body(&d),
                }
            }}
        </div>
    }
    .into_any()
}

fn profile_body(d: &Value) -> AnyView {
    let state = api::s(d, "state");
    let maturity = api::s(d, "maturity");
    let degraded = d
        .get("data_quality_degraded")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let tod = d.get("time_of_day").cloned().unwrap_or(Value::Null);
    let vol = d.get("volume").cloned().unwrap_or(Value::Null);
    let sa = d.get("sensitive_activity").cloned().unwrap_or(Value::Null);
    view! {
        <div class="row">
            {ui::pill(crate::status::baseline_class(&state), if state.is_empty() { "—".into() } else { state })}
            <span class="dimtext">"Maturity"</span><span class="mono">{maturity}</span>
            <span class="dimtext">"Observations"</span><span class="mono">{api::num(d, "observations").to_string()}</span>
            <span class="dimtext">"Span"</span><span class="mono">{format!("{}d", api::num(d, "span_days"))}</span>
            <span class="dimtext">"Sources"</span><span class="mono">{api::num(d, "distinct_sources").to_string()}</span>
            {degraded.then(|| ui::pill("warn", "data quality degraded"))}
        </div>

        <h4 style="margin:14px 0 4px">"Footprint"</h4>
        {footprint_cards(d)}

        {(!tod.is_null()).then(|| view! {
            <h4 style="margin:14px 0 4px">"Activity by hour (UTC)"</h4>
            {hour_hist(&tod)}
        })}

        {(!vol.is_null() && (vol.get("rows_read").is_some() || vol.get("bytes_read").is_some())).then(|| view! {
            <h4 style="margin:14px 0 4px">"Volume"</h4>
            <div class="row">
                {vol.get("rows_read").map(|r| view! { <span class="dimtext">"rows/read (mean·max)"</span><span class="mono">{format!("{:.0} · {:.0}", fnum(r, "mean"), fnum(r, "max"))}</span> })}
                {vol.get("bytes_read").map(|r| view! { <span class="dimtext">"bytes/read (mean·max)"</span><span class="mono">{format!("{:.0} · {:.0}", fnum(r, "mean"), fnum(r, "max"))}</span> })}
            </div>
        })}

        {(!sa.is_null()).then(|| sensitive_section(&sa))}
    }
    .into_any()
}

/// One card per categorical dimension with any values: its cardinality + top values.
fn footprint_cards(d: &Value) -> AnyView {
    const DIMS: &[(&str, &str)] = &[
        ("clients", "Clients / apps"),
        ("objects", "Objects / tables"),
        ("schemas", "Schemas"),
        ("databases", "Databases"),
        ("query_fingerprints", "Query fingerprints"),
        ("operations", "Operations"),
        ("source_hosts", "Source hosts"),
        ("subject_types", "Subject types"),
    ];
    let fp = d.get("footprint").cloned().unwrap_or(Value::Null);
    let cards: Vec<AnyView> = DIMS
        .iter()
        .filter_map(|(key, label)| {
            let dim = fp.get(*key).cloned().unwrap_or(Value::Null);
            let distinct = api::num(&dim, "distinct");
            if distinct == 0 {
                return None;
            }
            let dropped = api::num(&dim, "dropped");
            let top = super::arr(&dim, "top");
            Some(view! {
                <div class="card" style="flex:1; min-width:200px">
                    <div class="row"><strong>{*label}</strong>
                        <span class="mono dimtext">{if dropped > 0 { format!("{distinct} distinct (+{dropped} dropped)") } else { format!("{distinct} distinct") }}</span>
                    </div>
                    <dl class="fields">
                        {top.into_iter().take(6).map(|t| {
                            let v = api::s(&t, "value");
                            view! { <dt class="mono">{if v.is_empty() { "—".into() } else { v }}</dt><dd class="mono dimtext">{api::num(&t, "count").to_string()}</dd> }
                        }).collect_view()}
                    </dl>
                </div>
            }.into_any())
        })
        .collect();
    if cards.is_empty() {
        return ui::empty("no learned footprint yet");
    }
    view! { <div class="row" style="flex-wrap:wrap; align-items:stretch; gap:10px">{cards}</div> }
        .into_any()
}

/// A 24-bar hour-of-day histogram (inline styling; the bar colour is a neutral data
/// hue, and every bar carries its own hour+count label on hover).
fn hour_hist(tod: &Value) -> AnyView {
    let hours: Vec<i64> = super::arr(tod, "hour")
        .iter()
        .map(|v| v.as_i64().unwrap_or(0))
        .collect();
    let max = hours.iter().copied().max().unwrap_or(0).max(1);
    view! {
        <div style="display:flex; align-items:flex-end; gap:2px; height:52px; margin:6px 0">
            {(0..24).map(|h| {
                let c = hours.get(h).copied().unwrap_or(0);
                let pct = (c as f64 / max as f64 * 100.0).max(3.0);
                view! {
                    <span title=format!("{h:02}:00 · {c} events")
                        style=format!("flex:1; background:var(--accent); opacity:0.7; border-radius:2px 2px 0 0; height:{pct}%")></span>
                }
            }).collect_view()}
        </div>
    }
    .into_any()
}

/// A JSON float field (the volume stats are `f64`; `api::num` is integer-only).
fn fnum(v: &Value, k: &str) -> f64 {
    v.get(k).and_then(Value::as_f64).unwrap_or(0.0)
}

fn sensitive_section(sa: &Value) -> AnyView {
    let hours = api::num(sa, "window_hours");
    let window = if hours < 24 {
        format!("{hours}h")
    } else {
        format!("{}d", hours / 24)
    };
    let user_events = api::num(sa, "user_events");
    let truncated = sa
        .get("truncated")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let recent = super::arr(sa, "recent");
    let tile = |k: &str, key: &str, bad: bool| {
        let n = api::num(sa, key);
        let cls = if n == 0 {
            "pass"
        } else if bad {
            "bad"
        } else {
            "warn"
        };
        ui::metric(k.to_string(), n.to_string(), cls, None)
    };
    view! {
        <h4 style="margin:14px 0 4px">{format!("Sensitive activity ({window} · {user_events} events)")}</h4>
        {truncated.then(|| ui::banner("warn", "Partial — the recent-event scan hit its cap, so older activity in this window may be omitted (the footprint above is complete)."))}
        <div class="tiles">
            {tile("exports", "exports", false)}
            {tile("privilege", "privileged", false)}
            {tile("administrative", "administrative", false)}
            {tile("bulk", "bulk", false)}
            {tile("denied", "denied", true)}
            {tile("failed", "failed", true)}
        </div>
        {if recent.is_empty() {
            ui::empty("no export / privilege / denied activity in the window")
        } else {
            super::table(&["time", "operation", "object", "outcome", "flags"],
                recent.into_iter().map(|r| {
                    let outcome = api::s(&r, "outcome");
                    let oc = if outcome == "success" { "pass" } else if outcome == "denied" || outcome == "failure" || outcome == "error" { "bad" } else { "dim" };
                    let flags = super::arr(&r, "flags").iter().filter_map(|f| f.as_str().map(String::from)).collect::<Vec<_>>().join(", ");
                    view! {
                        <tr>
                            <td class="mono dimtext">{let t = api::s(&r, "ts"); t.split('.').next().unwrap_or(&t).replace('T', " ")}</td>
                            <td class="dimtext">{api::s(&r, "operation")}</td>
                            <td class="mono dimtext">{api::s(&r, "object")}</td>
                            <td>{ui::pill(oc, if outcome.is_empty() { "—".into() } else { outcome })}</td>
                            <td class="dimtext">{flags}</td>
                        </tr>
                    }
                }).collect_view().into_any())
        }}
    }
    .into_any()
}

/// Peer comparison (Phase 9): compare this user against a peer group (a role) via
/// `GET /api/appaudit/peers`. Shows values the user uses that no trusted peer does,
/// and is explicit about abstaining when either baseline is not yet Trusted.
fn peer_panel(name: String) -> AnyView {
    let group = RwSignal::new(String::new());
    let out = RwSignal::new(Option::<Result<Value, api::ApiError>>::None);
    let busy = RwSignal::new(false);
    let run = move |_| {
        let g = group.get();
        if g.trim().is_empty() {
            return;
        }
        let url = format!(
            "/api/appaudit/peers?user={}&group={}&kind=role",
            api::enc(&name),
            api::enc(g.trim())
        );
        busy.set(true);
        out.set(None);
        leptos::task::spawn_local(async move {
            let r = api::send_get(&url).await;
            busy.set(false);
            out.set(Some(r));
        });
    };
    view! {
        <div class="card">
            <div class="card-head"><h3>"Peer comparison"</h3>
                {ui::help_tip("Compares this account with others in the same role and lists the apps, tables or operations it uses that none of its trusted peers do — a way to spot an account drifting away from what its group normally does.")}
            </div>
            <p class="dimtext">"Compare this user against a peer group (a role) — the values they use that no trusted peer does. Authoritative only when both baselines are Trusted; otherwise it says why it abstains (candidate data is never treated as a peer norm)."</p>
            <div class="row">
                <input type="text" class="grow" placeholder="peer group — a role id…"
                    prop:value=move || group.get() on:input=move |ev| group.set(event_target_value(&ev))/>
                <button class="btn primary" on:click=run prop:disabled=move || busy.get()>
                    {move || if busy.get() { "Comparing…" } else { "Compare" }}
                </button>
            </div>
            {move || out.get().map(|r| match r {
                Err(e) => super::error_state(e),
                Ok(v) => peer_result(&v),
            })}
        </div>
    }
    .into_any()
}

fn peer_result(v: &Value) -> AnyView {
    let authoritative = v
        .get("authoritative")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let pg = v.get("peer_group").cloned().unwrap_or(Value::Null);
    let peer_mat = api::s(&pg, "maturity");
    let user_mat = v
        .get("user")
        .map(|u| api::s(u, "maturity"))
        .unwrap_or_default();
    let reason = v
        .get("abstain_reason")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    view! {
        <div>
            <div class="row resultmeta">
                <span class="dimtext">{format!("user {user_mat} · peer {peer_mat}")}</span>
                {if authoritative { ui::pill("pass", "authoritative") } else { ui::pill("warn", "abstaining") }}
            </div>
            {(!authoritative).then(|| view! { <p class="dimtext">{reason.clone()}</p> })}
            {authoritative.then(|| {
                let dims = super::arr(v, "dimensions");
                super::table(&["dimension", "values unique to this user"],
                    dims.into_iter().map(|d| {
                        let dim = api::s(&d, "dimension");
                        let vals = super::arr(&d, "user_only").iter()
                            .filter_map(|x| x.as_str().map(String::from)).collect::<Vec<_>>();
                        let shown = if vals.is_empty() { "—".to_string() } else { vals.join(", ") };
                        view! { <tr><td>{dim}</td><td class="mono">{shown}</td></tr> }
                    }).collect_view().into_any())
            })}
        </div>
    }.into_any()
}

/// The monitoring panel: baseline trust state + the heighten/clear lifecycle
/// (the real, server-authorized monitoring controls available today).
fn monitoring_panel(store: Store, name: String, baselines: super::Fetch) -> AnyView {
    let note = RwSignal::new(Option::<Result<String, api::ApiError>>::None);
    // Capture only Copy values so `act` is Copy and usable from several buttons;
    // the entity name and kind are passed per-call.
    let act = move |path: &'static str, kind: String, name: String| {
        note.set(None);
        leptos::task::spawn_local(async move {
            let body = serde_json::json!({ "kind": kind, "id": name.clone() });
            match api::send_post(path, body).await {
                Ok(_) => {
                    store.log_activity(format!("Monitoring: {path}"), true, name.clone(), None);
                    note.set(Some(Ok(format!("{path} ✓"))));
                    baselines.load("/api/appaudit/baselines".into());
                }
                Err(e) => {
                    store.log_activity("Monitoring action failed", false, e.to_string(), None);
                    note.set(Some(Err(e)));
                }
            }
        });
    };

    view! {
        <div class="card">
            <div class="card-head"><h3>"Monitoring"</h3>
                <ui::InfoPopover heading="What monitoring does"
                    body="Heightened monitoring raises how closely garmr watches this one account: its detectors stop assuming the recent activity is normal, so borderline actions are surfaced for review instead of being quietly trusted. It applies only to this account and stays in place until you return it to normal — it does not expire on its own. It is a decision to look more closely, not a finding that the person did anything wrong."/>
            </div>
            {move || {
                let b = baselines.rows("baselines").into_iter()
                    .find(|b| api::s(b, "id") == name && is_user_kind(&api::s(b, "kind")));
                match b {
                    None => ui::empty("No behavioral baseline for this account yet, so there is nothing to monitor. garmr starts one automatically once it has observed some of the account's activity.").into_any(),
                    Some(b) => {
                        let kind = api::s(&b, "kind");
                        let state = api::s(&b, "state");
                        let can_heighten = state == "Candidate" || state == "Trusted";
                        let can_clear = state == "Suspicious";
                        let (k1, k2) = (kind.clone(), kind.clone());
                        let (n1, n2) = (name.clone(), name.clone());
                        view! {
                            <div class="row">
                                <span class="dimtext">"Baseline trust:"</span>
                                {ui::pill(crate::status::baseline_class(&state), if state.is_empty() { "—".into() } else { state.clone() })}
                                {ui::help_tip("Whether detectors currently treat this account's learned baseline as the norm. \"Candidate\" is still learning; \"Trusted\" is used as the yardstick to compare new activity against; \"Suspicious\" means it is under heightened monitoring and is no longer treated as normal.")}
                                <span class="dimtext">{format!("obs={} · span={}d", api::num(&b, "observations"), api::num(&b, "span_days"))}</span>
                            </div>
                            <p class="dimtext">"Heightening monitoring tells the detectors to stop treating this account's recent behaviour as normal, so more of what it does is surfaced for review. Returning to normal restores that trust once you have reviewed. Both actions need operator authorization and are recorded in the audit ledger."</p>
                            <div class="row">
                                {can_heighten.then(move || view! {
                                    <button class="btn warn" on:click=move |_| act("/admin/appaudit/baselines/suspect", k1.clone(), n1.clone())>"Heighten monitoring"</button>
                                })}
                                {can_clear.then(move || view! {
                                    <button class="btn primary" on:click=move |_| act("/admin/appaudit/baselines/clear", k2.clone(), n2.clone())>"Return to normal monitoring"</button>
                                })}
                                {move || note.get().map(|r| match r {
                                    Ok(m) => ui::pill("pass", m),
                                    Err(e) => super::error_state(e),
                                })}
                            </div>
                        }.into_any()
                    }
                }
            }}
        </div>
    }
    .into_any()
}
