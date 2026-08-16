// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! Resources — the data-resource inventory (DoD 5): each classified catalog
//! resource with its recent access history and the policies that govern it. The
//! catalog is authored as reviewed files and promoted through the audited registry
//! (the `catalog` kind), so the console shows it read-only; the value here is the
//! join with the lakehouse — who accessed each resource, from where, under which
//! justification — and the per-resource policy coverage.

use leptos::prelude::*;
use serde_json::Value;

use crate::route::{Area, View};
use crate::{api, status, ui, Store};

/// Policy effect → reserved status class (kept in step with the Policies view).
fn effect_class(effect: &str) -> &'static str {
    match effect {
        "deny" => "bad",
        "require_justification" => "warn",
        "allow" => "pass",
        _ => "dim",
    }
}

/// Access outcome label → reserved status class.
fn outcome_class(outcome: &str) -> &'static str {
    match outcome {
        "success" => "pass",
        "denied" | "failure" | "error" => "bad",
        _ => "dim",
    }
}

/// Trim an RFC3339 timestamp to `YYYY-MM-DD HH:MM:SS` for display.
fn fmt_ts(v: &str) -> String {
    if v.is_empty() {
        return "—".into();
    }
    let t = v.split('.').next().unwrap_or(v);
    t.trim_end_matches('Z').replace('T', " ")
}

/// The classification badge (colour paired with its own label), plus a sensitive
/// marker when the resource is flagged sensitive.
fn classification_cell(cls: &str, sensitive: bool) -> AnyView {
    let label = if cls.is_empty() { "unclassified" } else { cls };
    view! {
        <span class="row">
            {ui::pill(status::classification_class(cls), label.to_string())}
            {sensitive.then(|| ui::pill("bad", "sensitive"))}
        </span>
    }
    .into_any()
}

pub fn list_view(store: Store) -> impl IntoView {
    let f = super::Fetch::new();
    let reload = move || f.load("/api/resources".into());
    reload();
    // The text filter lives in the URL: it still narrows the list as you type,
    // but committing it — Enter, or moving focus away — publishes, so the next
    // query write (a time-range chip) cannot quietly erase it, and a filtered
    // list is a link worth sharing.
    let text = RwSignal::new(store.nav.param_untracked("q").unwrap_or_default());
    let commit_text = move || {
        store.nav.record_query(super::publish_query(
            &[("q", text.get_untracked())],
            &store.nav.query.get_untracked(),
        ));
    };

    view! {
        <div class="page">
            <div class="page-header row">
                <div class="grow"><h1>"Resources"</h1><div class="sub">{Area::Resources.blurb()}</div></div>
                <button class="btn ghost" on:click=move |_| reload()>"↻ Refresh"</button>
            </div>
            <p class="sub">"The resource catalog is authored as reviewed files and promoted through the audited registry — shown read-only. Access tallies cover a recent bounded window. "{ui::help_tip("Data classification is the sensitivity label each resource carries — public, internal, confidential, restricted or secret. It sets how alarming access to the resource looks and which policies apply; \"sensitive\" additionally flags resources that need extra care.")}" "{ui::help_tip("A trusted resource is one whose catalog entry has been reviewed, approved and promoted through the audited registry. An entry that is not yet trusted shows its pending approval state instead — its classification has not been signed off.")}</p>
            {move || store.caps.get().and_then(|c| {
                let fs = c.feature("app_audit");
                (fs.state == "disabled").then(|| ui::disabled_panel("Application audit", &fs))
            })}
            <div class="filterbar">
                <input type="search" class="grow" placeholder="filter by object, application, owner or classification…"
                    prop:value=move || text.get() on:input=move |ev| text.set(event_target_value(&ev))
                    on:change=move |_| commit_text()/>
            </div>
            {move || {
                if let Some(e) = f.err.get() {
                    if e.status == 404 {
                        return ui::empty("Application audit is turned off, so there is no resource catalog. An administrator can enable it to inventory and classify your data resources.");
                    }
                    return super::error_state(e);
                }
                let tq = text.get().to_lowercase();
                let rows: Vec<Value> = f.rows("resources").into_iter()
                    .filter(|r| {
                        if tq.is_empty() { return true; }
                        [api::s(r, "object"), api::s(r, "application"), api::s(r, "owner"),
                         api::s(r, "classification"), api::s(r, "kind")]
                            .iter().any(|s| s.to_lowercase().contains(&tq))
                    })
                    .collect();
                if rows.is_empty() {
                    if f.loading.get() { return ui::loading("loading resources…"); }
                    return ui::empty("No data-bearing resources in the catalog yet. These appear once tables, views or endpoints are added to the reviewed catalog and promoted.");
                }
                let meta = f.data.get();
                let (scanned, hours) = meta.as_ref().map(|v| (api::num(v, "scanned"), api::num(v, "window_hours"))).unwrap_or((0, 0));
                view! {
                    <div class="row resultmeta"><span class="dimtext">{format!("{} resources · {} accesses scanned over {}d", rows.len(), scanned, hours / 24)}</span></div>
                    {super::table(&["resource", "classification", "access", "application", "owner", "trusted"],
                        rows.into_iter().map(|r| {
                            let id = api::s(&r, "id");
                            let idc = id.clone();
                            let object = api::s(&r, "object");
                            let kind = api::s(&r, "kind");
                            let cls = api::s(&r, "classification");
                            let sensitive = r.get("sensitive").and_then(Value::as_bool).unwrap_or(false);
                            let access = r.get("access").cloned().unwrap_or(Value::Null);
                            let count = api::num(&access, "count");
                            let users = api::num(&access, "distinct_users");
                            let failed = api::num(&access, "failed");
                            let last = fmt_ts(&api::s(&access, "last_access"));
                            let trusted = r.get("trusted").and_then(Value::as_bool).unwrap_or(false);
                            let approval = api::s(&r, "approval");
                            let link_id = idc.clone();
                            view! {
                                <tr class="rowlink" on:click=move |_| store.nav.go(View::Resource(idc.clone()))>
                                    <td>
                                        <div class="mono">
                                            <ui::ViewLink view=View::Resource(link_id) class="rowtarget">{object}</ui::ViewLink>
                                        </div>
                                        <div class="dimtext">{status::humanize(&kind)}</div>
                                    </td>
                                    <td>{classification_cell(&cls, sensitive)}</td>
                                    <td>
                                        <div class="mono">{format!("{count} · {users} users")}</div>
                                        <div class="dimtext">{if failed > 0 { format!("{failed} failed · last {last}") } else { format!("last {last}") }}</div>
                                    </td>
                                    <td class="dimtext">{if r.get("application").map(Value::is_null).unwrap_or(true) { "—".to_string() } else { api::s(&r, "application") }}</td>
                                    <td class="dimtext">{if r.get("owner").map(Value::is_null).unwrap_or(true) { "—".to_string() } else { api::s(&r, "owner") }}</td>
                                    <td>{if trusted { ui::pill("pass", "trusted") } else { ui::pill("dim", if approval.is_empty() { "—".into() } else { status::humanize(&approval) }) }}</td>
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
    f.load(format!("/api/resources/{}", api::enc(&id)));
    view! {
        <div class="page">
            {move || {
                if let Some(e) = f.err.get() {
                    if e.status == 404 { return ui::empty(api::clean(&e.message)); }
                    return super::error_state(e);
                }
                match f.data.get() {
                    None => ui::loading("loading resource…"),
                    Some(d) => resource_detail(store, &d),
                }
            }}
        </div>
    }
}

fn resource_detail(store: Store, d: &Value) -> AnyView {
    let sm = d.get("summary").cloned().unwrap_or(Value::Null);
    let object = api::s(d, "object");
    // Data-bearing entries carry kind inside `summary`; hierarchy/identity entries
    // have a null summary, so fall back to the top-level `kind`.
    let kind = {
        let k = api::s(&sm, "kind");
        if k.is_empty() {
            api::s(d, "kind")
        } else {
            k
        }
    };
    let cls = api::s(&sm, "classification");
    let sensitive = sm
        .get("sensitive")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let trusted = d.get("trusted").and_then(Value::as_bool).unwrap_or(false);
    let approval = api::s(d, "approval");
    let data_bearing = d
        .get("data_bearing")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let summ = d.get("access_summary").cloned().unwrap_or(Value::Null);
    let hours = api::num(d, "window_hours");

    let coverage = super::arr(d, "policy_coverage");
    let top_users = super::arr(d, "top_users");
    let top_clients = super::arr(d, "top_clients");
    let history = super::arr(d, "history");

    view! {
        {ui::page_header(if object.is_empty() { api::s(d, "id") } else { object.clone() },
            format!("{} · resource", status::humanize(&kind)))}

        <div class="card">
            <div class="row">
                {classification_cell(&cls, sensitive)}
                {ui::help_tip("Data classification is the sensitivity label the catalog assigns — public, internal, confidential, restricted or secret. It drives how alarming access looks and which policies apply; the \"sensitive\" marker additionally flags resources that need extra care.")}
                {if trusted { ui::pill("pass", "trusted") } else { ui::pill("dim", if approval.is_empty() { "—".into() } else { status::humanize(&approval) }) }}
                <span class="dimtext">"Version"</span><span class="mono">{api::num(d, "version").to_string()}</span>
                <span class="dimtext">"Source"</span><span class="mono">{api::s(d, "source")}</span>
            </div>
            {ui::kv_list(vec![
                ("Resource id", api::s(d, "id")),
                ("Object", object.clone()),
                ("Kind", status::humanize(&kind)),
                ("Application", opt(&sm, "application")),
                ("Owner", opt(&sm, "owner")),
                ("Expected users", api::num(&sm, "expected_users").to_string()),
                ("Created by", opt(d, "created_by")),
                ("Approved by", opt(d, "approved_by")),
            ])}
        </div>

        {(!data_bearing).then(|| ui::banner("warn", "This catalog entry is a hierarchy/identity kind (application, schema, role …) — it accrues no direct access history."))}

        {data_bearing.then(|| {
            let total = api::num(&summ, "total");
            let users = api::num(&summ, "distinct_users");
            let failed = api::num(&summ, "failed");
            let last = fmt_ts(&api::s(&summ, "last_access"));
            let truncated = summ.get("history_truncated").and_then(Value::as_bool).unwrap_or(false);
            view! {
                <div class="tiles">
                    {ui::metric(format!("accesses ({}d)", hours / 24), total.to_string(), "dim", None)}
                    {ui::metric("distinct users", users.to_string(), "dim", None)}
                    {ui::metric("failed", failed.to_string(), if failed > 0 { "warn" } else { "pass" }, None)}
                    {ui::metric("last access", last, "dim", None)}
                </div>
                {truncated.then(|| ui::banner("dim", format!("Showing the most recent {} accesses of {} in the window.", history.len(), total)))}
            }.into_any()
        })}

        // Which policies govern this resource.
        <section class="sect">
            <h3>"Policy coverage"{ui::help_tip("The policies that apply to this resource and what each one does — allow, deny, or require a justification — so you can see the rules governing access to it, and where a sensitive resource has none.")}</h3>
            {if coverage.is_empty() {
                ui::empty("no policy governs this resource in the current set")
            } else {
                super::table(&["policy", "effect", "enabled", "match"],
                    coverage.iter().map(|p| {
                        let pid = api::s(p, "id");
                        let pidc = pid.clone();
                        let effect = api::s(p, "effect");
                        let enabled = p.get("enabled").and_then(Value::as_bool).unwrap_or(true);
                        let reasons = super::arr(p, "match").iter()
                            .filter_map(|m| m.as_str().map(String::from)).collect::<Vec<_>>().join(", ");
                        let title = api::s(p, "title");
                        let link_pid = pid.clone();
                        let pid_text = pid.clone();
                        let head = if title.is_empty() { pid.clone() } else { title };
                        view! {
                            <tr class="rowlink" on:click=move |_| store.nav.go(View::Policy(pidc.clone()))>
                                <td>
                                    <div>
                                        <ui::ViewLink view=View::Policy(link_pid) class="rowtarget">
                                            {head}
                                        </ui::ViewLink>
                                    </div>
                                    <div class="mono dimtext">{pid_text}</div>
                                </td>
                                <td>{ui::pill(effect_class(&effect), effect.replace('_', " "))}</td>
                                <td>{if enabled { ui::pill("pass", "enabled") } else { ui::pill("dim", "disabled") }}</td>
                                <td class="dimtext">{reasons}</td>
                            </tr>
                        }
                    }).collect_view().into_any())
            }}
        </section>

        {data_bearing.then(|| view! {
            <div class="row">
                <section class="sect grow">
                    <h3>"Top users"</h3>
                    {top_list(&top_users)}
                </section>
                <section class="sect grow">
                    <h3>"Top sources"</h3>
                    {top_list(&top_clients)}
                </section>
            </div>

            <section class="sect">
                <h3>"Recent access"{ui::help_tip("The access history for this resource — who touched it, from where, under which justification and with what outcome — over a recent bounded window. It is the audit trail you use to check whether access was appropriate.")}</h3>
                {if history.is_empty() {
                    ui::empty("no access to this resource in the window")
                } else {
                    super::table(&["time", "actor", "from", "operation", "outcome", "object", "justification", "evidence"],
                        history.iter().map(access_row).collect_view().into_any())
                }}
            </section>
        })}
    }.into_any()
}

/// A `(value, count)` top-N list rendered as a compact table.
fn top_list(rows: &[Value]) -> AnyView {
    if rows.is_empty() {
        return ui::empty("none");
    }
    super::table(
        &["value", "count"],
        rows.iter()
            .map(|r| {
                view! {
                    <tr>
                        <td class="mono">{api::s(r, "value")}</td>
                        <td class="mono dimtext">{api::num(r, "count").to_string()}</td>
                    </tr>
                }
            })
            .collect_view()
            .into_any(),
    )
}

/// One access-history row.
fn access_row(a: &Value) -> AnyView {
    let outcome = api::s(a, "outcome");
    let role = api::s(a, "actor_role");
    let just = a.get("justification").cloned().unwrap_or(Value::Null);
    let just_txt = if just.is_null() {
        "—".to_string()
    } else {
        let ticket = api::s(&just, "ticket_ref");
        let case = api::s(&just, "case_ref");
        let purpose = api::s(&just, "purpose");
        [ticket, case, purpose]
            .into_iter()
            .filter(|s| !s.is_empty())
            .collect::<Vec<_>>()
            .join(" · ")
    };
    let eid = api::s(a, "event_id");
    view! {
        <tr>
            <td class="mono dimtext">{fmt_ts(&api::s(a, "ts"))}</td>
            <td><div class="mono">{api::s(a, "actor")}</div>{(!role.is_empty()).then(|| view! { <div class="dimtext">{role}</div> })}</td>
            <td class="mono dimtext">{let c = api::s(a, "client"); if c.is_empty() { api::s(a, "source_host") } else { c }}</td>
            <td class="dimtext">{api::s(a, "operation")}</td>
            <td>{ui::pill(outcome_class(&outcome), if outcome.is_empty() { "—".into() } else { outcome })}</td>
            <td class="mono dimtext">{api::s(a, "object")}</td>
            <td class="dimtext">{if just_txt.is_empty() { "—".to_string() } else { just_txt }}</td>
            <td class="mono dimtext">{eid.chars().take(12).collect::<String>()}</td>
        </tr>
    }
    .into_any()
}

/// A string field, or "—" when absent/null (for detail key/value rows).
fn opt(v: &Value, k: &str) -> String {
    let s = api::s(v, k);
    if s.is_empty() {
        "—".into()
    } else {
        s
    }
}
