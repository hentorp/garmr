// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! Policies — access policies, their scope, and their violations, kept distinct
//! from behavioral Detections. Read-only: policy authoring is a reviewed file +
//! audited registry-promotion flow, not a console write (surfaced as such).

use leptos::prelude::*;
use serde_json::{json, Value};

use crate::route::{Area, View};
use crate::{api, ui, Store};

fn effect_class(effect: &str) -> &'static str {
    match effect {
        "deny" => "bad",
        "require_justification" => "warn",
        "allow" => "pass",
        _ => "dim",
    }
}

/// Registry lifecycle `effective_state` → reserved status class.
fn lifecycle_class(state: &str) -> &'static str {
    match state {
        "Approved" => "pass",
        "Draft" => "warn",
        "Rejected" | "Deprecated" => "bad",
        _ => "dim",
    }
}

pub fn list_view(store: Store) -> impl IntoView {
    let f = super::Fetch::new();
    f.load("/api/policies".into());
    view! {
        <div class="page">
            {ui::page_header("Policies", Area::Policies.blurb())}
            <p class="sub">"Access policies are authored as reviewed files and promoted through the audited registry — the console shows them read-only. Violations are materialised as investigations. "{ui::help_tip("A policy's scope is which subjects and resources it applies to — for example specific database users acting on specific objects. A violation is an access that breaks the policy (say, a denied or unjustified read); garmr turns each one into an investigation you can work.")}</p>
            {move || {
                if let Some(e) = f.err.get() { return super::error_state(e); }
                let rows = f.rows("policies");
                if rows.is_empty() {
                    if f.loading.get() { return ui::loading("loading policies…"); }
                    return ui::empty("No access policies are configured yet — policies are authored as reviewed files and promoted through the registry, and once promoted they appear here read-only.");
                }
                let digest = f.data.get().as_ref().and_then(|v| v.get("digest")).and_then(Value::as_str).unwrap_or("").chars().take(16).collect::<String>();
                view! {
                    <div class="row resultmeta"><span class="dimtext">{format!("{} policies · set digest ", rows.len())}</span><span class="mono dimtext">{digest}</span></div>
                    {super::table(&["policy", "effect", "priority", "scope", "enabled"],
                        rows.into_iter().map(|p| {
                            let id = api::s(&p, "id");
                            let idc = id.clone();
                            let effect = api::s(&p, "effect");
                            let objects = super::arr(p.get("resource").unwrap_or(&Value::Null), "objects")
                                .iter().filter_map(|o| o.as_str().map(String::from)).collect::<Vec<_>>().join(", ");
                            let enabled = p.get("enabled").and_then(Value::as_bool).unwrap_or(true);
                            view! {
                                <tr class="rowlink" on:click=move |_| store.nav.go(View::Policy(idc.clone()))>
                                    <td><div>{api::clean(&api::s(&p, "title"))}</div><div class="mono dimtext">{id}</div></td>
                                    <td>{ui::pill(effect_class(&effect), effect.replace('_', " "))}</td>
                                    <td class="mono dimtext">{api::num(&p, "priority").to_string()}</td>
                                    <td class="mono dimtext">{objects}</td>
                                    <td>{if enabled { ui::pill("pass", "enabled") } else { ui::pill("dim", "disabled") }}</td>
                                </tr>
                            }
                        }).collect_view().into_any())}
                }.into_any()
            }}
        </div>
    }
}

pub fn detail_view(store: Store, id: String) -> impl IntoView {
    let f = super::Fetch::new();
    f.load(format!("/api/policies/{}", api::enc(&id)));
    let cases = super::Fetch::new();
    cases.load("/api/cases".into());
    let id2 = id.clone();
    view! {
        <div class="page">
            {move || {
                if let Some(e) = f.err.get() { return super::error_state(e); }
                match f.data.get().as_ref().and_then(|v| v.get("policy").cloned()) {
                    None => ui::loading("loading policy…"),
                    Some(p) => policy_detail(store, &p, cases, &id2),
                }
            }}
        </div>
    }
}

fn policy_detail(store: Store, p: &Value, cases: super::Fetch, id: &str) -> AnyView {
    let effect = api::s(p, "effect");
    let subject = p.get("subject").cloned().unwrap_or(Value::Null);
    let resource = p.get("resource").cloned().unwrap_or(Value::Null);
    let condition = p.get("condition").cloned().unwrap_or(Value::Null);
    let objects = super::arr(&resource, "objects")
        .iter()
        .filter_map(|o| o.as_str().map(String::from))
        .collect::<Vec<_>>()
        .join(", ");
    let subj = super::arr(&subject, "db_users")
        .iter()
        .filter_map(|o| o.as_str().map(String::from))
        .collect::<Vec<_>>()
        .join(", ");
    let id_owned = id.to_string();
    view! {
        {ui::page_header(api::s(p, "title"), api::s(p, "description"))}
        <div class="card">
            <div class="row"><span class="dimtext">"Effect"</span>{ui::pill(effect_class(&effect), effect.replace('_', " "))}
                <span class="dimtext">"Priority"</span><span class="mono">{api::num(p, "priority").to_string()}</span>
                <span class="dimtext">"Version"</span><span class="mono">{api::num(p, "version").to_string()}</span></div>
            {ui::kv_list(vec![
                ("Policy id", api::s(p, "id")),
                ("Resources", if objects.is_empty() { "(any)".into() } else { objects }),
                ("Subjects", if subj.is_empty() { "(any)".into() } else { subj }),
                ("Created by", api::s(p, "created_by")),
                ("Approved by", api::s(p, "approved_by")),
            ])}
            {(!condition.is_null()).then(|| view! { <div class="dimtext">{format!("Conditions: {}", api::clean(&condition.to_string()))}</div> })}
        </div>

        // Backtest: replay this policy over recent audit history (non-mutating).
        {simulate_section(p)}

        // Governed lifecycle: versions, activate/rollback/retire, draft a new version.
        {lifecycle_panel(p, id)}

        // Cross-linked violations: cases whose rule references this policy family.
        <section class="sect">
            <h3>"Related violations "{ui::help_tip("Violations are accesses that broke this policy — for example a forbidden read or one missing required justification. Each becomes an investigation; the ones tied to this policy are listed here.")}</h3>
            {move || {
                let idl = id_owned.to_lowercase();
                let hits: Vec<Value> = cases.rows("cases").into_iter().filter(|c| {
                    let trig = c.get("trigger").cloned().unwrap_or(Value::Null);
                    let rule = api::s(&trig, "rule_id").to_lowercase();
                    // policy-driven cases: forbidden access, missing justification, or the policy id itself
                    rule.contains("forbidden") || rule.contains("justification") || rule.contains(&idl)
                }).collect();
                if hits.is_empty() { return ui::empty("no policy-violation investigations in the current window"); }
                super::table(&["id", "state", "rule", "host"],
                    hits.into_iter().map(|c| {
                        let cid = api::s(&c, "id"); let cidc = cid.clone();
                        let trig = c.get("trigger").cloned().unwrap_or(Value::Null);
                        view! {
                            <tr class="rowlink" on:click=move |_| store.nav.go(View::Investigation(cidc.clone()))>
                                <td class="mono dimtext">{api::short(&c, "id")}</td>
                                <td>{ui::state_badge(&api::s(&c, "state"))}</td>
                                <td>{api::s(&trig, "rule_id")}</td>
                                <td class="mono">{trig.get("event").map(|e| api::s(e, "host")).unwrap_or_default()}</td>
                            </tr>
                        }
                    }).collect_view().into_any())
            }}
        </section>
    }.into_any()
}

/// The governed policy lifecycle (Phase B / DoD 6): the versioned registry records
/// for this policy (draft → active → deprecated), and the admin actions — activate
/// (promote), rollback (re-promote a prior version), retire, and draft a new
/// version. All on the Phase-A registry; every action is admin-gated and audited.
fn lifecycle_panel(p: &Value, id: &str) -> AnyView {
    let idv = StoredValue::new(id.to_string());
    let reg = super::Fetch::new();
    let load_reg = move || {
        reg.load(format!(
            "/api/registry/policy/{}",
            api::enc(&idv.get_value())
        ))
    };
    load_reg();
    let out = RwSignal::new(Option::<Result<Value, api::ApiError>>::None);
    let busy = RwSignal::new(false);
    let draft_json = RwSignal::new(serde_json::to_string_pretty(p).unwrap_or_default());
    let rationale = RwSignal::new(String::new());

    // Run an admin POST, then refresh the version list on success.
    let run = move |url: String, body: Value| {
        busy.set(true);
        out.set(None);
        leptos::task::spawn_local(async move {
            let r = api::send_post(&url, body).await;
            busy.set(false);
            let ok = r.is_ok();
            out.set(Some(r));
            if ok {
                load_reg();
            }
        });
    };
    let promote = move |version: String| {
        run(
            "/admin/registry/promote".into(),
            json!({ "kind": "policy", "name": idv.get_value(), "version": version, "reason": "activate via console" }),
        )
    };
    // Retire CLEARS the channel pointer (deactivates the whole policy) — only valid
    // on the active version. Reject marks a specific NON-active version rejected
    // WITHOUT touching the pointer, for discarding a draft.
    let retire = move |version: String| {
        run(
            "/admin/registry/retire".into(),
            json!({ "kind": "policy", "name": idv.get_value(), "version": version, "reason": "deactivate via console" }),
        )
    };
    let reject = move |version: String| {
        run(
            "/admin/registry/reject".into(),
            json!({ "kind": "policy", "name": idv.get_value(), "version": version, "reason": "discard draft via console" }),
        )
    };
    let submit_draft = move |_| match serde_json::from_str::<Value>(&draft_json.get()) {
        Err(e) => out.set(Some(Err(api::ApiError {
            status: 400,
            message: format!("invalid JSON: {e}"),
        }))),
        Ok(pol) => run(
            "/admin/policies/draft".into(),
            json!({ "policy": pol, "rationale": rationale.get() }),
        ),
    };

    view! {
        <section class="sect">
            <h3>"Lifecycle & versions"</h3>
            <p class="sub">"Policies are governed as versioned registry records: draft → simulate → activate (promote) → rollback (re-promote a prior version) → retire. Actions are admin-gated and audited. "{ui::help_tip("The lifecycle is the set of states a policy version moves through. Draft is written but inert; Approved (active) is the version being enforced; Rejected or Deprecated are retired. Only one version is active at a time, and rolling back just re-activates an earlier one.")}</p>
            {move || {
                if let Some(e) = reg.err.get() {
                    return super::error_state(e);
                }
                // Compare on the active VERSION (two records can share a digest).
                let active_ver = reg.data.get().as_ref().and_then(|v| v.get("active_version")).and_then(Value::as_str).unwrap_or("").to_string();
                let records = reg.rows("records");
                if records.is_empty() {
                    if reg.loading.get() { return ui::loading("loading versions…"); }
                    return ui::empty("no governed registry versions yet — draft one below");
                }
                super::table(&["version", "state", "active", "by", "actions"],
                    records.into_iter().map(|r| {
                        let ver = api::s(&r, "version");
                        let (v1, v2, v3) = (ver.clone(), ver.clone(), ver.clone());
                        let state = api::s(&r, "effective_state");
                        let is_active = !active_ver.is_empty() && ver == active_ver;
                        view! {
                            <tr>
                                <td class="mono">{ver}</td>
                                <td>{ui::pill(lifecycle_class(&state), state)}</td>
                                <td>{if is_active { ui::pill("pass", "active") } else { ui::pill("dim", "—") }}</td>
                                <td class="dimtext">{api::s(&r, "registered_by")}</td>
                                <td>
                                    // Activate + Reject apply to a non-active version; Retire (a
                                    // channel-wide deactivate) only to the active one.
                                    {(!is_active).then(|| view! {
                                        <button class="btn sm" prop:disabled=move || busy.get() on:click=move |_| promote(v1.clone())>"Activate"</button>
                                        <button class="btn ghost sm" prop:disabled=move || busy.get() on:click=move |_| reject(v3.clone())>"Reject"</button>
                                    })}
                                    {is_active.then(|| view! {
                                        <button class="btn warn sm" prop:disabled=move || busy.get() on:click=move |_| retire(v2.clone())>"Retire (deactivate)"</button>
                                    })}
                                </td>
                            </tr>
                        }
                    }).collect_view().into_any())
            }}

            <div class="card" style="margin-top:10px">
                <div class="card-head"><h4>"Draft a new version"</h4></div>
                <p class="dimtext">"Edit the policy JSON and submit a governed Draft — it is validated server-side and inert until you Activate it. Backtest it with Simulate above first."</p>
                <textarea class="mono" style="width:100%; min-height:160px; box-sizing:border-box"
                    prop:value=move || draft_json.get() on:input=move |ev| draft_json.set(event_target_value(&ev))></textarea>
                <div class="row">
                    <input type="text" class="grow" placeholder="rationale for this draft…"
                        prop:value=move || rationale.get() on:input=move |ev| rationale.set(event_target_value(&ev))/>
                    <button class="btn primary sm" on:click=submit_draft prop:disabled=move || busy.get()>
                        {move || if busy.get() { "Working…" } else { "Submit draft" }}
                    </button>
                </div>
            </div>
            {move || out.get().map(|r| match r {
                Err(e) => super::error_state(e),
                Ok(v) => {
                    let outcome = v.get("outcome").and_then(Value::as_str).map(String::from)
                        .or_else(|| v.get("promotion").map(|_| "promoted".to_string()))
                        .unwrap_or_else(|| "done".to_string());
                    ui::banner("pass", format!("✓ {outcome}"))
                }
            })}
        </section>
    }
    .into_any()
}

/// Backtest a policy over recent audit history via `POST /api/policies/simulate`
/// — the real endpoint, over real data. Non-mutating: it enforces and saves
/// nothing, so it is safe to run against any (even enabled) policy.
fn simulate_section(p: &Value) -> AnyView {
    let policy = p.clone();
    let out = RwSignal::new(Option::<Result<Value, api::ApiError>>::None);
    let busy = RwSignal::new(false);
    let run = move |_| {
        let body = json!({ "policy": policy.clone(), "hours": 168 });
        busy.set(true);
        out.set(None);
        leptos::task::spawn_local(async move {
            let r = api::send_post("/api/policies/simulate", body).await;
            busy.set(false);
            out.set(Some(r));
        });
    };
    view! {
        <section class="sect">
            <h3>"Simulate (backtest)"</h3>
            <p class="sub">"Replay this policy over the last 7 days of audit history. Shows its blast radius — matches, effects, affected users/objects, and a rough false-positive estimate. Nothing is enforced or saved."</p>
            <button class="btn primary sm" on:click=run prop:disabled=move || busy.get()>
                {move || if busy.get() { "Simulating…" } else { "Backtest over last 7 days" }}
            </button>
            {move || out.get().map(|r| match r {
                Err(e) => super::error_state(e),
                Ok(v) => {
                    let rep = v.get("report").cloned().unwrap_or(Value::Null);
                    let scanned = api::num(&v, "scanned");
                    let audit = api::num(&v, "audit_accesses");
                    let stamped = v.get("stamped").and_then(Value::as_bool).unwrap_or(false);
                    view! {
                        <div class="card">
                            <div class="row resultmeta"><span class="dimtext">{format!("{audit} audit accesses evaluated (of {scanned} scanned, last 7d)")}</span>
                                {(!stamped).then(|| ui::pill("warn", "catalog off — classification conditions not applied"))}</div>
                            {ui::kv_list(vec![
                                ("Matched", api::num(&rep, "matched").to_string()),
                                ("Would deny", api::num(&rep, "deny").to_string()),
                                ("Require justification", api::num(&rep, "require_justification").to_string()),
                                ("Require approval", api::num(&rep, "require_approval").to_string()),
                                ("Alert", api::num(&rep, "alert").to_string()),
                                ("Affected users", super::arr(&rep, "affected_users").len().to_string()),
                                ("Affected objects", super::arr(&rep, "affected_objects").len().to_string()),
                                ("Likely false positives", api::num(&rep, "likely_false_positives").to_string()),
                            ])}
                        </div>
                    }.into_any()
                }
            })}
        </section>
    }.into_any()
}