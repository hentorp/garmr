// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! Detections — the detection surface, kept distinct from Policies. Four tabs:
//! Findings (behavioral detector output, with the detector + baseline context),
//! Rule proposals (agent-drafted rules → human approve/reject), Baselines (the
//! grant-of-trust lifecycle), and Silences (active throttles). Every write is a
//! server-authorized, audited admin action.

use leptos::prelude::*;
use serde_json::{json, Value};

use crate::route::Area;
use crate::{api, ui, Store};

pub fn view(store: Store) -> impl IntoView {
    let tab = move || store.nav.param("tab").unwrap_or_else(|| "findings".into());
    let set_tab = move |t: &'static str| store.nav.set_query(format!("tab={t}"));

    view! {
        <div class="page">
            {ui::page_header("Detections", Area::Detections.blurb())}
            {super::tabs(&[
                ("findings", "Findings"),
                ("proposals", "Rule proposals"),
                ("baselines", "Baselines"),
                ("silences", "Silences"),
            ], tab(), set_tab)}
            {move || match tab().as_str() {
                "proposals" => proposals_tab(store),
                "baselines" => baselines_tab(store),
                "silences" => silences_tab(store),
                _ => findings_tab(),
            }}
        </div>
    }
}

fn findings_tab() -> AnyView {
    let f = super::Fetch::new();
    f.load("/api/findings".into());
    view! {
        <div>
            <p class="sub">"Behavioral-detector findings "{ui::help_tip("A finding is one behavioral anomaly a detector flagged — activity that departs from an entity's learned-normal baseline. Treat it as a lead to review, not a confirmed incident.")}" — a finding fires only against a "<b>"Trusted"</b>" baseline. An empty list usually means no baseline is mature yet (see the Baselines tab), not that nothing happened."</p>
            <p class="sub">"The "<b>"band"</b>" column is this finding's "<b>"severity"</b>" — how serious it is on its own "{ui::help_tip("Severity rates a single finding in isolation. A host's risk is different: it is the accumulated picture across many signals over time, so a high-severity finding does not always mean a high-risk host.")}". The "<b>"score"</b>" is the detector's confidence that the activity is anomalous (0 = normal, 1 = highly unusual)."</p>
            {f.framed("findings", "no detector findings", |rows| {
                super::table(&["host", "band", "level", "score", "detector"],
                    rows.into_iter().map(|r| {
                        let host = r.get("event").map(|e| api::s(e, "host")).unwrap_or_default();
                        view! {
                            <tr>
                                <td class="mono">{if host.is_empty() { "—".into() } else { host }}</td>
                                <td>{ui::sev_badge(&api::s(&r, "band"))}</td>
                                <td>{api::s(&r, "level")}</td>
                                <td class="mono dimtext">{format!("{:.2}", r.get("score").and_then(Value::as_f64).unwrap_or(0.0))}</td>
                                <td class="dimtext">{api::clean(&api::s(&r, "detector"))}</td>
                            </tr>
                        }
                    }).collect_view().into_any())
            })}
        </div>
    }.into_any()
}

fn proposals_tab(store: Store) -> AnyView {
    let f = super::Fetch::new();
    f.load("/api/rules/proposals".into());
    let note = RwSignal::new(Option::<Result<String, api::ApiError>>::None);
    let act = move |path: &'static str, id: String| {
        note.set(None);
        leptos::task::spawn_local(async move {
            match api::send_post(path, json!({ "id": id })).await {
                Ok(_) => {
                    store.log_activity(format!("Rule {path}"), true, String::new(), None);
                    let msg = match path {
                        "/admin/rules/approve" => "Rule proposal approved",
                        "/admin/rules/reject" => "Rule proposal rejected",
                        _ => "Rule proposal updated",
                    };
                    note.set(Some(Ok(msg.into())));
                    f.load("/api/rules/proposals".into());
                }
                Err(e) => {
                    store.log_activity("Rule action failed", false, e.to_string(), None);
                    note.set(Some(Err(e)));
                }
            }
        });
    };
    view! {
        <div>
            <p class="sub">"Agent-drafted detection rules "{ui::help_tip("A rule proposal is a new detection rule the agent drafted from real log data. It is inert until you approve it — approving adds it to the active ruleset, rejecting discards it. The backtest column shows how many past events the draft rule would have matched.")}", grounded in real log data. Propose ≠ act — you approve a proposal into the ruleset or reject it."</p>
            {move || note.get().map(|r| match r { Ok(m) => ui::pill("pass", m), Err(e) => super::error_state(e) })}
            {f.framed("proposals", "No rule proposals yet — the agent drafts these while investigating, so run a threat hunt from Intelligence › Hunts to generate some. (The CLI can draft them too.)", move |rows| {
                super::table(&["id", "status", "kind", "backtest", "title", ""],
                    rows.into_iter().map(|r| {
                        let id = api::s(&r, "id");
                        let st = api::s(&r, "status");
                        let hits = r.get("backtest").and_then(|b| b.get("hits")).and_then(Value::as_u64).unwrap_or(0);
                        let pending = st != "approved" && st != "rejected";
                        let (ia, ir) = (id.clone(), id.clone());
                        view! {
                            <tr>
                                <td class="mono dimtext">{api::short(&r, "id")}</td>
                                <td>{ui::pill(crate::status::proposal_class(&st), crate::status::humanize(&st))}</td>
                                <td class="mono dimtext">{api::s(&r, "kind")}</td>
                                <td class="mono dimtext">{format!("{hits} hits")}</td>
                                <td class="msg">{api::clean(&api::s(&r, "title"))}</td>
                                <td>{pending.then(move || view! {
                                    <button class="btn primary sm" on:click=move |_| act("/admin/rules/approve", ia.clone())>"Approve"</button>
                                    <button class="btn ghost sm" on:click=move |_| act("/admin/rules/reject", ir.clone())>"Reject"</button>
                                })}</td>
                            </tr>
                        }
                    }).collect_view().into_any())
            })}
        </div>
    }.into_any()
}

fn baselines_tab(store: Store) -> AnyView {
    let f = super::Fetch::new();
    f.load("/api/appaudit/baselines".into());
    let note = RwSignal::new(Option::<Result<String, api::ApiError>>::None);
    let act = move |path: &'static str, kind: String, id: String| {
        note.set(None);
        leptos::task::spawn_local(async move {
            match api::send_post(path, json!({ "kind": kind, "id": id })).await {
                Ok(_) => {
                    store.log_activity(format!("Baseline {path}"), true, id.clone(), None);
                    let msg = match path {
                        "/admin/appaudit/baselines/promote" => "Baseline promoted to Trusted",
                        "/admin/appaudit/baselines/suspect" => "Baseline marked suspicious",
                        "/admin/appaudit/baselines/clear" => "Baseline suspicion cleared",
                        _ => "Baseline updated",
                    };
                    note.set(Some(Ok(msg.into())));
                    f.load("/api/appaudit/baselines".into());
                }
                Err(e) => {
                    store.log_activity("Baseline action failed", false, e.to_string(), None);
                    note.set(Some(Err(e)));
                }
            }
        });
    };
    view! {
        <div>
            <p class="sub">"Behavioral baselines per entity "{ui::help_tip("A baseline is the learned-normal profile for one entity. Its maturity moves through Candidate (still learning, never queried), Trusted (mature enough to detect against), and Suspicious (tainted, so it is ignored). Only a Trusted baseline produces findings.")}". A detector only queries a "<b>"Trusted"</b>" baseline — promote to grant trust (the server re-checks the hard blocks: open investigation, prior violation, suspicious mark), suspect to taint, clear after review."</p>
            {move || note.get().map(|r| match r { Ok(m) => ui::pill("pass", m), Err(e) => super::error_state(e) })}
            {move || {
                if let Some(e) = f.err.get() {
                    if e.status == 404 { return ui::disabled_panel("Application audit", &crate::caps::FeatureState{ state:"disabled".into(), reason: Some("turn on Application audit in System → Configuration → Detection".into())}); }
                    return super::error_state(e);
                }
                let rows = f.rows("baselines");
                if rows.is_empty() { return if f.loading.get() { ui::loading("loading…") } else { ui::empty("No behavioral baselines have formed yet — they build automatically as entities accumulate observed activity, so check back once your sources have been delivering events for a while.") }; }
                super::table(&["kind", "entity", "state", "maturity", "stats", ""],
                    rows.into_iter().map(|b| {
                        let kind = api::s(&b, "kind");
                        let id = api::s(&b, "id");
                        let state = api::s(&b, "state");
                        let stats = format!("obs={} span={}d src={}", api::num(&b,"observations"), api::num(&b,"span_days"), api::num(&b,"distinct_sources"));
                        let can_p = state == "Candidate";
                        let can_s = state == "Candidate" || state == "Trusted";
                        let can_c = state == "Suspicious";
                        let (kp, ip) = (kind.clone(), id.clone());
                        let (ks, is_) = (kind.clone(), id.clone());
                        let (kc, ic) = (kind.clone(), id.clone());
                        view! {
                            <tr>
                                <td>{ui::pill("dim", kind)}</td>
                                <td class="mono">{id}</td>
                                <td>{ui::pill(crate::status::baseline_class(&state), if state.is_empty() { "—".into() } else { state })}</td>
                                <td class="dimtext">{api::s(&b, "maturity")}</td>
                                <td class="mono dimtext">{stats}</td>
                                <td>
                                    {can_p.then(move || { let (k,i)=(kp.clone(),ip.clone()); view! { <button class="btn primary sm" on:click=move |_| act("/admin/appaudit/baselines/promote", k.clone(), i.clone())>"Promote to Trusted"</button> } })}
                                    {can_s.then(move || { let (k,i)=(ks.clone(),is_.clone()); view! { <button class="btn ghost sm" on:click=move |_| act("/admin/appaudit/baselines/suspect", k.clone(), i.clone())>"Mark suspicious"</button> } })}
                                    {can_c.then(move || { let (k,i)=(kc.clone(),ic.clone()); view! { <button class="btn ghost sm" on:click=move |_| act("/admin/appaudit/baselines/clear", k.clone(), i.clone())>"Clear suspicion"</button> } })}
                                </td>
                            </tr>
                        }
                    }).collect_view().into_any())
            }}
        </div>
    }.into_any()
}

fn silences_tab(store: Store) -> AnyView {
    let f = super::Fetch::new();
    f.load("/admin/silences".into());
    view! {
        <div>
            <p class="sub">"Active notification silences "{ui::help_tip("A silence temporarily stops a specific rule from alerting, without disabling detection. Its scope narrows it to a host or set of hosts, and every silence is time-bounded and recorded in the audit ledger.")}" — a bounded, audited quieting of a noisy rule. Requires operator authorization (System › Access)."</p>
            {move || {
                if let Some(e) = f.err.get() {
                    if e.is_authz() { return super::error_state(e); }
                    return super::error_state(e);
                }
                let rows = f.rows("silences");
                let _ = &store;
                if rows.is_empty() { return if f.loading.get() { ui::loading("loading…") } else { ui::empty("no active silences") }; }
                super::table(&["rule", "scope", "until"],
                    rows.into_iter().map(|s| view! {
                        <tr>
                            <td class="mono">{api::s(&s, "rule")}</td>
                            <td class="dimtext">{api::s(&s, "host")}</td>
                            <td class="mono dimtext">{api::s(&s, "until")}</td>
                        </tr>
                    }).collect_view().into_any())
            }}
        </div>
    }.into_any()
}