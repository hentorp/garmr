// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! Investigations — the canonical home for security cases. The queue (list) and
//! an evidence-driven detail that keeps **agent prediction** and **analyst
//! decision** visually and conceptually separate, links every claim to its
//! evidence, and lets the analyst record a decision (audited).

use leptos::prelude::*;
use serde_json::{json, Value};

use crate::route::{Area, View};
use crate::{api, ui, Store, TimeRange};

// ---- queue ----------------------------------------------------------------

pub fn list_view(store: Store) -> impl IntoView {
    let f = super::Fetch::new();
    f.load("/api/cases".into());
    let reload = move || f.load("/api/cases".into());

    // The state filter lives in the URL (`?state=needs_human`), so a filtered
    // queue is a shareable link and survives refresh.
    let state_filter = move || store.nav.param("state").unwrap_or_default();
    let text = RwSignal::new(String::new());

    let set_state = move |s: &'static str| {
        store.nav.set_query(if s.is_empty() {
            String::new()
        } else {
            format!("state={s}")
        });
    };

    view! {
        <div class="page">
            <div class="page-header row">
                <div class="grow">
                    <h1>"Investigations"</h1>
                    <div class="sub">{Area::Investigations.blurb()}</div>
                </div>
                <button class="btn ghost" on:click=move |_| reload()>"↻ Refresh"</button>
            </div>

            <div class="filterbar">
                {["", "needs_human", "escalated", "investigating", "triaged", "closed"].into_iter().map(|s| {
                    let label = if s.is_empty() { "all".to_string() } else { s.replace('_', " ") };
                    let active = move || state_filter() == s;
                    view! {
                        <button class="chip" class:active=active on:click=move |_| set_state(s)>{label}</button>
                    }
                }).collect_view()}
                <input type="search" class="grow" placeholder="filter by rule or host…"
                    prop:value=move || text.get()
                    on:input=move |ev| text.set(event_target_value(&ev))/>
                {ui::help_tip("Filter by lifecycle state. Needs human: automated triage could not decide, an analyst must rule. Escalated: judged serious enough to surface immediately. Investigating: the agent is still gathering evidence. Triaged: the agent reached a verdict. Closed: decided and done.")}
            </div>

            {move || {
                if let Some(e) = f.err.get() {
                    return super::error_state(e);
                }
                let sf = state_filter();
                let tq = text.get().to_lowercase();
                let rows: Vec<Value> = f.rows("cases").into_iter().filter(|c| {
                    let st = api::s(c, "state");
                    let trig = c.get("trigger").cloned().unwrap_or(Value::Null);
                    let rule = format!("{} {}", api::s(&trig, "rule_id"),
                        trig.get("event").map(|e| api::s(e, "host")).unwrap_or_default()).to_lowercase();
                    (sf.is_empty() || st == sf) && (tq.is_empty() || rule.contains(&tq))
                }).collect();
                if rows.is_empty() {
                    if f.loading.get() { return ui::loading("loading investigations…"); }
                    return ui::empty("no investigations match this filter");
                }
                let count = rows.len();
                view! {
                    <div class="dimtext listcount">{format!("{count} investigation(s)")}</div>
                    {super::table(&["id", "state", "severity", "rule", "host", "events", "updated"],
                        rows.into_iter().map(|c| case_row(store, &c)).collect_view().into_any())}
                }.into_any()
            }}
        </div>
    }
}

fn case_row(store: Store, c: &Value) -> impl IntoView {
    let id = api::s(c, "id");
    let idc = id.clone();
    let state = api::s(c, "state");
    let trig = c.get("trigger").cloned().unwrap_or(Value::Null);
    let level = api::s(&trig, "level");
    let rule = api::s(&trig, "rule_id");
    let host = trig
        .get("event")
        .map(|e| api::s(e, "host"))
        .unwrap_or_default();
    // A real link on the id: the row stays clickable for convenience, but the
    // destination is now copyable, middle-clickable and reachable by keyboard.
    let short_id = api::short(c, "id");
    let row_target = View::Investigation(idc.clone());
    view! {
        <tr class="rowlink" on:click=move |_| store.nav.go(View::Investigation(idc.clone()))>
            <td class="mono dimtext">
                <ui::ViewLink view=row_target class="rowtarget">{short_id}</ui::ViewLink>
            </td>
            <td>{ui::state_badge(&state)}</td>
            <td>{ui::sev_badge(&level)}</td>
            <td>{api::clean(&rule)}</td>
            <td class="mono">{host}</td>
            <td class="mono dimtext">{api::num(c, "event_count").to_string()}</td>
            <td class="mono dimtext">{api::s(c, "updated_at")}</td>
        </tr>
    }
}

// ---- detail ---------------------------------------------------------------

pub fn detail_view(store: Store, id: String) -> impl IntoView {
    let detail = super::Fetch::new();
    let history = super::Fetch::new();
    let explain = super::Fetch::new();
    let load = {
        let id = id.clone();
        move || {
            detail.load(format!("/api/cases/{}", api::enc(&id)));
            history.load(format!("/api/cases/{}/history", api::enc(&id)));
            explain.load(format!("/api/cases/{}/explain", api::enc(&id)));
        }
    };
    load();
    let id_for_reload = id.clone();

    view! {
        <div class="page">
            {move || {
                if let Some(e) = detail.err.get() {
                    return super::error_state(e);
                }
                match detail.data.get() {
                    None => ui::loading("loading investigation…"),
                    Some(c) => render_case(store, &id_for_reload, &c, history, explain).into_any(),
                }
            }}
        </div>
    }
}

fn render_case(
    store: Store,
    id: &str,
    c: &Value,
    history: super::Fetch,
    explain: super::Fetch,
) -> AnyView {
    let trig = c.get("trigger").cloned().unwrap_or(Value::Null);
    let event = trig.get("event").cloned().unwrap_or(Value::Null);
    let state = api::s(c, "state");
    let level = api::s(&trig, "level");
    let title = {
        let t = api::s(&trig, "rule_title");
        if t.is_empty() {
            api::s(&trig, "rule_id")
        } else {
            t
        }
    };
    let host = api::s(&event, "host");
    let verdict = c.get("verdict").filter(|v| !v.is_null()).cloned();
    let conf = verdict
        .as_ref()
        .and_then(|v| v.get("confidence").and_then(Value::as_f64))
        .unwrap_or(0.0);

    let attack: Vec<String> = super::arr(&trig, "attack")
        .iter()
        .filter_map(|v| v.as_str().map(String::from))
        .collect();

    let transcript = super::arr(c, "transcript");

    // Related entities from the trigger event.
    let related = related_entities(&event);

    // Reproduce: pivot to Audit Explorer scoped to this case's host + window.
    let repro_host = host.clone();
    let reproduce = move || {
        let q = if repro_host.is_empty() {
            String::new()
        } else {
            format!("q={}&mode=text", api::enc(&repro_host))
        };
        store.time_range.set(TimeRange::Last(72));
        store.nav.go_query(View::Audit, q);
    };
    let pivot_host = host.clone();
    let to_audit = move || {
        let q = format!("q={}&mode=text", api::enc(&pivot_host));
        store.nav.go_query(View::Audit, q);
    };

    view! {
        // Header.
        <div class="case-head">
            <div class="row">
                <h1 class="grow">{api::clean(&title)}</h1>
                {ui::state_badge(&state)}
                {ui::sev_badge(&level)}
                {ui::help_tip("Severity rates how damaging this activity would be if it turns out to be a real threat, on a 0–10 scale. Weighed against how likely it is to be real, it sets the overall risk and how soon to act.")}
            </div>
            <div class="case-meta">
                {ui::kv_list(vec![
                    ("Investigation", api::short(c, "id")),
                    ("Rule", api::s(&trig, "rule_id")),
                    ("Host", host.clone()),
                    ("Events", api::num(c, "event_count").to_string()),
                    ("Opened", api::s(c, "opened_at")),
                    ("Updated", api::s(c, "updated_at")),
                ])}
                {(!attack.is_empty()).then(|| view! {
                    <div class="row"><span class="dimtext">"ATT&CK:"</span>
                        <span class="tags">{attack.iter().map(|t| {
                            let t = t.clone();
                            view! { <span class="tag">{t}</span> }
                        }).collect_view()}</span>
                    </div>
                })}
            </div>
            <div class="row case-actions">
                <button class="btn ghost" on:click=move |_| to_audit()>"⤷ Pivot to Audit Explorer"</button>
                <button class="btn ghost" on:click=move |_| reproduce()>"↻ Reproduce evidence query"</button>
            </div>
        </div>

        // 1. Evidence timeline.
        <section class="sect">
            <h3>"Evidence timeline"{ui::help_tip("The facts this investigation is built on, in time order. The first entry is the event that triggered the alert — the reason it was flagged — followed by anything the system or agent added while working the case.")}</h3>
            <div class="timeline">
                <div class="tl-item">
                    <span class="tl-dot bad"></span>
                    <div class="tl-body">
                        <div class="row"><strong>"Trigger event"</strong>
                            <span class="mono dimtext">{api::s(&event, "event_ts")}</span></div>
                        <div class="mono evidence">{api::clean(&api::s(&event, "message"))}</div>
                    </div>
                </div>
                {transcript.into_iter().map(|t| {
                    let actor = api::s(&t, "actor");
                    let dot = match actor.as_str() { "agent" | "router" => "warn", "system" => "dim", _ => "pass" };
                    view! {
                        <div class="tl-item">
                            <span class=format!("tl-dot {dot}")></span>
                            <div class="tl-body">
                                <div class="row">
                                    <span class="pill dim">{actor}</span>
                                    <span class="mono dimtext">{api::s(&t, "at")}</span>
                                </div>
                                <div>{api::clean(&api::s(&t, "detail"))}</div>
                            </div>
                        </div>
                    }
                }).collect_view()}
            </div>
        </section>

        // 2. Agent analysis (AI) — clearly fenced from human judgement.
        <section class="sect">
            <h3>"Agent analysis"<span class="ai-tag" title="Model-generated — verify against evidence">"AI"</span>
                <ui::InfoPopover heading="What the agent concluded"
                    body="Everything in this section is the AI's assessment — its best reading of what happened and how likely it is to be a genuine threat. It is a recommendation, not a ruling: the binding call is the analyst decision recorded further down. Always check it against the evidence timeline before acting on it."/>
            </h3>
            {agent_analysis(&verdict, conf, explain)}
        </section>

        // 3. Analyst decision (human) — separate, and how you record one.
        <section class="sect">
            <h3>"Analyst decision"<span class="human-tag">"human"</span>{ui::help_tip("Your ruling on this investigation — this is the decision of record. Saving it overrides the agent's assessment above and is written to the tamper-evident audit ledger.")}</h3>
            {decision_panel(store, id, history)}
        </section>

        // 4. Related entities — fast pivots.
        {(!related.is_empty()).then(|| view! {
            <section class="sect">
                <h3>"Related entities"</h3>
                <div class="chips">
                    {related.into_iter().map(|(kind, name)| {
                        let (k1, n1) = (kind.clone(), name.clone());
                        let (k2, n2) = (kind.clone(), name.clone());
                        view! {
                            <span class="entity-chip">
                                <span class="pill dim">{kind.clone()}</span>
                                <button class="linkish" on:click=move |_| store.peek(k1.clone(), n1.clone())>{name.clone()}</button>
                                <button class="linkish subtle" title="open full page"
                                    on:click=move |_| open_entity(store, &k2, &n2)>"↗"</button>
                            </span>
                        }
                    }).collect_view()}
                </div>
            </section>
        })}

        // 5. Record history (revisions).
        <section class="sect">
            <h3>"Record history"</h3>
            {record_history(history)}
        </section>
    }
    .into_any()
}

/// The agent-prediction card. When there is no prediction (e.g. the model router
/// fenced confidential data), say so plainly rather than showing a blank verdict.
fn agent_analysis(verdict: &Option<Value>, conf: f64, explain: super::Fetch) -> AnyView {
    match verdict {
        Some(v) => {
            let disp = api::s(v, "disposition");
            let dc = match disp.as_str() {
                "malicious" | "needs_human" => "bad",
                "suspicious" => "warn",
                "benign" => "pass",
                _ => "dim",
            };
            let rationale = api::s(v, "rationale");
            view! {
                <div class="ai-card">
                    <div class="row">
                        <span class="dimtext">"Predicted disposition"</span>
                        {ui::help_tip("The verdict the agent proposes for this activity: benign (normal), suspicious (worth a closer look), malicious (a real threat), or needs human (the agent is not confident enough to decide).")}
                        {ui::pill(dc, if disp.is_empty() { "—".into() } else { disp })}
                        <span class="dimtext">"confidence"</span>
                        {ui::help_tip("How sure the agent is of its proposed verdict, from 0 to 100%. Lower confidence means lean harder on the evidence and your own judgement before deciding.")}
                        {ui::confidence(conf)}
                    </div>
                    {(!rationale.is_empty()).then(|| view! { <p class="answer">{api::clean(&rationale)}</p> })}
                    {move || explain.data.get().map(|e| explain_block(&e))}
                    <div class="ai-note dimtext">
                        "Model-generated. Always verify against the evidence timeline before deciding."
                    </div>
                </div>
            }
            .into_any()
        }
        None => view! {
            <div class="ai-card">
                {ui::banner("warn", "No agent prediction was recorded for this investigation.")}
                {move || explain.data.get().map(|e| {
                    let ts = api::s(&e, "trust_source");
                    view! {
                        <p class="dimtext">
                            <strong>"Trust source"</strong>
                            {ui::help_tip("Where the agent is allowed to draw its conclusion from under policy. If policy blocked triage — for example the model router fenced confidential data from an outside model, or no model was reachable — no verdict is produced and the case is held for a person.")}
                            {format!(": {}. This usually means triage could not run — e.g. the model \
                             router fenced confidential data from an external model (see the transcript), \
                             or no LLM was reachable. The investigation is held for a human.", if ts.is_empty() { "unresolved".into() } else { ts })}
                        </p>
                    }
                })}
            </div>
        }
        .into_any(),
    }
}

/// The explainability block from `/explain` — provenance + audit tokens.
fn explain_block(e: &Value) -> AnyView {
    let prov = super::arr(e, "provenance");
    let audit_ids = super::arr(e, "audit_ids");
    view! {
        <div class="explain">
            {(!prov.is_empty()).then(|| view! {
                <div class="row"><span class="dimtext">"Reasoning chain:"</span></div>
                <ul class="prov">{prov.into_iter().map(|p| view! {
                    <li>{api::clean(&p.as_str().map(String::from).unwrap_or_else(|| p.to_string()))}</li>
                }).collect_view()}</ul>
            })}
            {(!audit_ids.is_empty()).then(|| view! {
                <div class="row">
                    {audit_ids.into_iter().map(|a| ui::audit_ref(a.as_str().unwrap_or_default())).collect_view()}
                </div>
            })}
        </div>
    }
    .into_any()
}

/// The analyst-decision panel: shows the recorded decision if any, else a form
/// to record one (POST /api/cases/:id/decision — analyst-tier, audited).
fn decision_panel(store: Store, id: &str, history: super::Fetch) -> AnyView {
    let id = id.to_string();
    let disp = RwSignal::new("benign".to_string());
    let narrative = RwSignal::new(String::new());
    let severity = RwSignal::new(3u8);
    let busy = RwSignal::new(false);
    let result = RwSignal::new(Option::<Result<String, api::ApiError>>::None);

    let submit = {
        let id = id.clone();
        move || {
            if busy.get_untracked() {
                return;
            }
            busy.set(true);
            result.set(None);
            let body = json!({
                "disposition": disp.get_untracked(),
                "severity": severity.get_untracked(),
                "narrative": narrative.get_untracked(),
            });
            let id = id.clone();
            leptos::task::spawn_local(async move {
                let r =
                    api::send_post(&format!("/api/cases/{}/decision", api::enc(&id)), body).await;
                busy.set(false);
                match r {
                    Ok(v) => {
                        let audit = v
                            .get("decision")
                            .and_then(|d| d.get("audit_id"))
                            .and_then(Value::as_str)
                            .map(String::from);
                        store.log_activity(
                            "Analyst decision recorded",
                            true,
                            format!("case {}", crate::api::enc(&id)),
                            audit.clone(),
                        );
                        result.set(Some(Ok(audit.unwrap_or_default())));
                        // Refresh the history so the new decision shows.
                        history.load(format!("/api/cases/{}/history", api::enc(&id)));
                    }
                    Err(e) => {
                        store.log_activity("Analyst decision failed", false, e.to_string(), None);
                        result.set(Some(Err(e)));
                    }
                }
            });
        }
    };

    // If a decision already exists, show it (still allow recording a superseding one).
    let existing = move || {
        history
            .data
            .get()
            .as_ref()
            .and_then(|h| h.get("current"))
            .and_then(|c| c.get("decision"))
            .filter(|d| !d.is_null())
            .cloned()
    };

    view! {
        <div class="human-card">
            {move || existing().map(|d| {
                view! {
                    <div class="banner pass">
                        {format!("Recorded: {} by {} — {}",
                            api::s(&d, "disposition"),
                            api::s(&d, "principal"),
                            api::s(&d, "created_at"))}
                    </div>
                }
            })}
            <div class="form-grid">
                <label>"Disposition"{ui::help_tip("Your verdict for this investigation: benign, suspicious, malicious, or needs human. Records what you concluded about the activity.")}
                    <select on:change=move |ev| disp.set(event_target_value(&ev))>
                        {["benign", "suspicious", "malicious", "needs_human"].into_iter().map(|d| view! {
                            <option value=d selected=move || disp.get() == d>{crate::status::humanize(d)}</option>
                        }).collect_view()}
                    </select>
                </label>
                <label>"Severity (0–10)"{ui::help_tip("How serious this is if it is a real threat, from 0 (none) to 10 (critical). Sets how the investigation is prioritised.")}
                    <input type="number" min="0" max="10" prop:value=move || severity.get().to_string()
                        on:input=move |ev| severity.set(event_target_value(&ev).parse().unwrap_or(3))/>
                </label>
                <label class="wide">"Narrative"
                    <textarea rows="2" placeholder="why this disposition — cite the evidence"
                        prop:value=move || narrative.get()
                        on:input=move |ev| narrative.set(event_target_value(&ev))></textarea>
                </label>
            </div>
            <div class="row">
                <button class="btn primary" prop:disabled=move || busy.get()
                    on:click=move |_| submit()>
                    {move || if busy.get() { "Recording…" } else { "Record decision" }}
                </button>
                {move || result.get().map(|r| match r {
                    Ok(audit) => view! { <span class="row">{ui::pill("pass", "recorded")}{ui::audit_ref(&audit)}</span> }.into_any(),
                    Err(e) => super::error_state(e),
                })}
            </div>
        </div>
    }
    .into_any()
}

/// Prediction / decision / outcome revisions from `/history`.
fn record_history(history: super::Fetch) -> AnyView {
    view! {
        {move || {
            let preds = history.rows("predictions").len();
            let decs = history.rows("decisions").len();
            let outs = history.rows("incident_outcomes").len();
            let fns = history.rows("false_negatives").len();
            if preds + decs + outs + fns == 0 {
                return ui::empty("no recorded revisions yet — agent predictions, analyst decisions and sealed outcomes appear here");
            }
            view! {
                <div class="row hist-counts">
                    {ui::pill("dim", format!("{preds} predictions"))}
                    {ui::pill("dim", format!("{decs} decisions"))}
                    {ui::pill("dim", format!("{outs} outcomes"))}
                    {ui::pill(if fns > 0 { "bad" } else { "dim" }, format!("{fns} dangerous misses"))}
                </div>
            }.into_any()
        }}
    }
    .into_any()
}

/// Pull related entities `(kind, name)` out of a trigger event.
fn related_entities(event: &Value) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut push = |kind: &str, key: &str| {
        let v = api::s(event, key);
        if !v.is_empty() {
            out.push((kind.to_string(), v));
        }
    };
    push("host", "host");
    push("user", "db_user");
    push("user", "user");
    push("person", "target_person");
    push("ip", "client_addr");
    push("ip", "src_ip");
    // De-dup by (kind,name).
    out.sort();
    out.dedup();
    out
}

/// Open the right detail page for an entity kind.
fn open_entity(store: Store, kind: &str, name: &str) {
    match kind {
        "user" | "staff" | "person" => store.nav.go(View::User(name.to_string())),
        "host" => store.nav.go(View::Application(name.to_string())),
        _ => store
            .nav
            .go(View::Entity(kind.to_string(), name.to_string())),
    }
}
