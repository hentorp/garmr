// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! Investigations — the canonical home for security cases. The queue (list) and
//! an evidence-driven detail that keeps **agent prediction** and **analyst
//! decision** visually and conceptually separate, links every claim to its
//! evidence, and lets the analyst record a decision (audited).
//!
//! The queue is a two-analyst work surface: ownership lanes (mine /
//! unassigned), tag and lifecycle filters — all applied server-side and kept
//! in the URL so a lane is a shareable link — plus SLA badges with breached
//! cases sorted to the top. The detail adds the collaboration substrate:
//! assignee picker (fed by `/api/principals`), tags, case links and analyst
//! notes, every write analyst-gated and audited by the server.

use leptos::prelude::*;
use serde_json::{json, Value};

use crate::route::{Area, View};
use crate::{api, ui, Store, TimeRange};

// ---- queue ----------------------------------------------------------------

/// Build the queue request from the server-side filters. Empty values are
/// omitted; `"(unassigned)"` is the API's name for the unowned lane.
fn cases_url(state: &str, assignee: &str, tag: &str) -> String {
    let mut q = Vec::new();
    for (k, v) in [("state", state), ("assignee", assignee), ("tag", tag)] {
        if !v.is_empty() {
            q.push(format!("{k}={}", api::enc(v)));
        }
    }
    if q.is_empty() {
        "/api/cases".into()
    } else {
        format!("/api/cases?{}", q.join("&"))
    }
}

/// Did either SLA clock breach?
fn sla_breached(c: &Value) -> bool {
    c.get("sla")
        .map(|s| {
            s.get("ack_breached")
                .and_then(Value::as_bool)
                .unwrap_or(false)
                || s.get("resolve_breached")
                    .and_then(Value::as_bool)
                    .unwrap_or(false)
        })
        .unwrap_or(false)
}

/// The SLA badge for one case's `sla` block: status class + its own text label
/// (never colour-alone). "no clock" is a case no clock applies to (e.g. closed).
fn sla_class_label(sla: &Value) -> (&'static str, &'static str) {
    let ack = sla
        .get("ack_breached")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let resolve = sla
        .get("resolve_breached")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    match (ack, resolve) {
        (true, true) => ("bad", "ack+resolve overdue"),
        (true, false) => ("bad", "ack overdue"),
        (false, true) => ("bad", "resolve overdue"),
        (false, false) => {
            let has_clock = sla.get("ack_deadline").is_some_and(|v| !v.is_null())
                || sla.get("resolve_deadline").is_some_and(|v| !v.is_null());
            if has_clock {
                ("pass", "within SLA")
            } else {
                ("dim", "no clock")
            }
        }
    }
}

/// Breached cases first, otherwise in the order the server returned (newest
/// first). A breached clock is the queue's loudest fact — it must not sit
/// below the fold because the case is old.
fn breached_first(mut rows: Vec<Value>) -> Vec<Value> {
    // Stable sort on "not breached", so breached rows float without reordering
    // anything else.
    rows.sort_by_key(|c| !sla_breached(c));
    rows
}

pub fn list_view(store: Store) -> impl IntoView {
    let f = super::Fetch::new();
    // Who am I? Drives the "mine" lane; on an open-loopback deployment there is
    // no signed-in user and the chip simply does not render.
    let whoami = super::Fetch::new();
    whoami.load("/auth/status".into());

    // All filters live in the URL (`?state=needs_human&assignee=alice&tag=x&q=sshd`),
    // so a filtered queue is a shareable link and survives a refresh. Publishing
    // every pair together is what keeps them from wiping each other. The
    // state/assignee/tag filters are applied server-side (one request per lane);
    // only the free-text filter narrows client-side over the fetched rows.
    let state_filter = move || store.nav.param("state").unwrap_or_default();
    let assignee_filter = move || store.nav.param("assignee").unwrap_or_default();
    let tag_filter = move || store.nav.param("tag").unwrap_or_default();
    let text = RwSignal::new(store.nav.param_untracked("q").unwrap_or_default());
    let tag_input = RwSignal::new(store.nav.param_untracked("tag").unwrap_or_default());

    // Refetch when — and only when — a server-side filter changes. The memo
    // fences off `q` commits: they rewrite the same query signal, and without
    // it every text commit would refetch a list it is about to filter locally.
    let server_filters = Memo::new(move |_| (state_filter(), assignee_filter(), tag_filter()));
    Effect::new(move |_| {
        let (s, a, t) = server_filters.get();
        f.load(cases_url(&s, &a, &t));
    });
    let reload = move || {
        let (s, a, t) = server_filters.get_untracked();
        f.load(cases_url(&s, &a, &t));
    };

    let publish = move |state: String, assignee: String, tag: String| {
        store.nav.record_query(super::publish_query(
            &[
                ("state", state),
                ("assignee", assignee),
                ("tag", tag),
                ("q", text.get_untracked()),
            ],
            &store.nav.query.get_untracked(),
        ));
    };
    let cur = move |k: &str| store.nav.param_untracked(k).unwrap_or_default();
    let set_state = move |s: &'static str| publish(s.to_string(), cur("assignee"), cur("tag"));
    // Ownership chips toggle: clicking the active lane returns to "everyone's".
    let toggle_assignee = move |a: &str| {
        let next = if cur("assignee") == a {
            String::new()
        } else {
            a.to_string()
        };
        publish(cur("state"), next, cur("tag"));
    };
    let commit_tag = move || {
        publish(
            cur("state"),
            cur("assignee"),
            tag_input.get_untracked().trim().to_lowercase(),
        )
    };
    let commit_text = move || publish(cur("state"), cur("assignee"), cur("tag"));

    view! {
        <div class="page">
            <div class="page-header row">
                <div class="grow">
                    <h1>"Investigations"</h1>
                    <div class="sub">{Area::Investigations.blurb()}</div>
                </div>
                <button class="btn ghost" on:click=move |_| reload()>"↻ Refresh"</button>
            </div>

            // The disabled-panel convention: if the deployment reports the case
            // plane off, say what is missing instead of showing a dead queue.
            {move || store.caps.get().and_then(|caps| {
                let fs = caps.feature("cases");
                (fs.state == "disabled").then(|| ui::disabled_panel("Case management", &fs))
            })}

            <div class="filterbar">
                {["", "needs_human", "escalated", "investigating", "triaged", "closed"].into_iter().map(|s| {
                    let label = if s.is_empty() { "all".to_string() } else { s.replace('_', " ") };
                    let active = move || state_filter() == s;
                    view! {
                        <button class="chip" class:active=active on:click=move |_| set_state(s)>{label}</button>
                    }
                }).collect_view()}
                // Ownership lanes. "mine" needs a signed-in identity to mean
                // anything, so it renders only once /auth/status names one.
                {move || {
                    let me = whoami.data.get().map(|v| api::s(&v, "user")).unwrap_or_default();
                    (!me.is_empty()).then(|| {
                        let m = me.clone();
                        let active = move || assignee_filter() == m;
                        view! {
                            <button class="chip" class:active=active
                                on:click=move |_| toggle_assignee(&me)>"mine"</button>
                        }
                    })
                }}
                <button class="chip" class:active=move || assignee_filter() == "(unassigned)"
                    on:click=move |_| toggle_assignee("(unassigned)")>"unassigned"</button>
                <input type="search" class="tagbox" placeholder="tag…"
                    prop:value=move || tag_input.get()
                    on:input=move |ev| tag_input.set(event_target_value(&ev))
                    on:change=move |_| commit_tag()/>
                <input type="search" class="grow" placeholder="filter by rule or host…"
                    prop:value=move || text.get()
                    on:input=move |ev| text.set(event_target_value(&ev))
                    on:change=move |_| commit_text()/>
                {ui::help_tip("Filter by lifecycle state, ownership or tag. Needs human: automated triage could not decide, an analyst must rule. Escalated: judged serious enough to surface immediately. Investigating: the agent is still gathering evidence. Triaged: the agent reached a verdict. Closed: decided and done. Mine: cases assigned to you; unassigned: cases nobody owns yet; tag narrows to labelled cases.")}
            </div>

            {move || {
                if let Some(e) = f.err.get() {
                    return super::error_state(e);
                }
                let tq = text.get().to_lowercase();
                let rows: Vec<Value> = f.rows("cases").into_iter().filter(|c| {
                    // Only the free-text filter is client-side; the rest was
                    // applied by the server before these rows arrived.
                    let trig = c.get("trigger").cloned().unwrap_or(Value::Null);
                    let hay = format!("{} {}", api::s(&trig, "rule_id"),
                        trig.get("event").map(|e| api::s(e, "host")).unwrap_or_default()).to_lowercase();
                    tq.is_empty() || hay.contains(&tq)
                }).collect();
                if rows.is_empty() {
                    if f.loading.get() { return ui::loading("loading investigations…"); }
                    return ui::empty("no investigations match this filter");
                }
                let rows = breached_first(rows);
                // The sla column exists only when the deployment computes SLAs
                // at all (the all-zero default config sends no sla block).
                let has_sla = rows.iter().any(|c| c.get("sla").is_some());
                let count = rows.len();
                let mut headers = vec!["id", "state"];
                if has_sla { headers.push("sla"); }
                headers.extend(["severity", "rule", "host", "owner", "events", "updated"]);
                view! {
                    <div class="dimtext listcount">{format!("{count} investigation(s)")}</div>
                    {super::table(&headers,
                        rows.into_iter().map(|c| case_row(store, &c, has_sla)).collect_view().into_any())}
                }.into_any()
            }}
        </div>
    }
}

fn case_row(store: Store, c: &Value, with_sla: bool) -> impl IntoView {
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
    let owner = api::s(c, "assignee");
    let owner_cell = if owner.is_empty() {
        view! { <td class="dimtext">"—"</td> }.into_any()
    } else {
        view! { <td class="mono">{owner}</td> }.into_any()
    };
    let sla_cell = with_sla.then(|| match c.get("sla") {
        Some(sla) => {
            let (cls, label) = sla_class_label(sla);
            view! { <td>{ui::pill(cls, label)}</td> }.into_any()
        }
        None => view! { <td class="dimtext">"—"</td> }.into_any(),
    });
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
            {sla_cell}
            <td>{ui::sev_badge(&level)}</td>
            <td>{api::clean(&rule)}</td>
            <td class="mono">{host}</td>
            {owner_cell}
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
    // The assignee picker's directory. One fetch per visit; an empty or
    // unauthorized directory degrades to free-text assignment (the open-
    // loopback dev posture, where the server accepts unknown names).
    let principals = super::Fetch::new();
    principals.load("/api/principals".into());
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
                    Some(c) => {
                        render_case(store, &id_for_reload, &c, detail, history, explain, principals)
                            .into_any()
                    }
                }
            }}
        </div>
    }
}

#[allow(clippy::too_many_arguments)]
fn render_case(
    store: Store,
    id: &str,
    c: &Value,
    detail: super::Fetch,
    history: super::Fetch,
    explain: super::Fetch,
    principals: super::Fetch,
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
        // Name the window in the query rather than leaning on `go_query`'s
        // carry: what that carries is the window of the URL being left, which
        // matches this case's 72 h only by accident. A reproduce link has to
        // reopen the window the button means.
        let tr = TimeRange::Last(72);
        store.time_range.set(tr);
        store
            .nav
            .go_query(View::Audit, crate::timerange::write_param(&q, tr));
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
            // Ownership + collaboration: who owns it, how it is labelled, what
            // it is connected to. Every control POSTs an analyst-gated, audited
            // route and reloads the case.
            {collab_panel(store, id, c, detail, principals)}
            <div class="row case-actions">
                <button class="btn ghost" on:click=move |_| to_audit()>"⤷ Pivot to Audit Explorer"</button>
                <button class="btn ghost" on:click=move |_| reproduce()>"↻ Reproduce evidence query"</button>
            </div>
        </div>

        // 1. Evidence timeline.
        <section class="sect">
            <h3>"Evidence timeline"{ui::help_tip("The facts this investigation is built on, in time order. The first entry is the event that triggered the alert — the reason it was flagged — followed by anything the system or agent added while working the case, and any analyst notes.")}</h3>
            <div class="timeline">
                <div class="tl-item">
                    <span class="tl-dot bad"></span>
                    <div class="tl-body">
                        <div class="row"><strong>"Trigger event"</strong>
                            <span class="mono dimtext">{api::s(&event, "event_ts")}</span></div>
                        <div class="mono evidence">{api::clean(&api::s(&event, "message"))}</div>
                    </div>
                </div>
                {transcript.into_iter().map(|t| transcript_item(&t)).collect_view()}
            </div>
            {note_composer(store, id, detail)}
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

/// The analyst name when a transcript entry was written by a person (the server
/// stamps analyst writes `analyst:<name>`); `None` for agent/tool/system rows.
fn analyst_name(actor: &str) -> Option<&str> {
    actor.strip_prefix("analyst:").filter(|n| !n.is_empty())
}

/// One transcript entry. Analyst entries are visually distinct from agent and
/// tool entries — same fence as the AI card vs the human card: a person's words
/// must never read as the machine's, or the other way around.
fn transcript_item(t: &Value) -> AnyView {
    let actor = api::s(t, "actor");
    let at = api::s(t, "at");
    let detail = api::clean(&api::s(t, "detail"));
    if let Some(name) = analyst_name(&actor) {
        let name = name.to_string();
        return view! {
            <div class="tl-item human">
                <span class="tl-dot human"></span>
                <div class="tl-body">
                    <div class="row">
                        <span class="human-tag">"human"</span>
                        <strong>{name}</strong>
                        <span class="mono dimtext">{at}</span>
                    </div>
                    <div>{detail}</div>
                </div>
            </div>
        }
        .into_any();
    }
    let dot = match actor.as_str() {
        "agent" | "router" => "warn",
        "system" => "dim",
        _ => "pass",
    };
    view! {
        <div class="tl-item">
            <span class=format!("tl-dot {dot}")></span>
            <div class="tl-body">
                <div class="row">
                    <span class="pill dim">{actor}</span>
                    <span class="mono dimtext">{at}</span>
                </div>
                <div>{detail}</div>
            </div>
        </div>
    }
    .into_any()
}

/// Ownership + collaboration controls: assignee picker, tag editor, linked-case
/// chips. Each action POSTs its analyst-gated route and reloads the case, so
/// the screen always shows what the store holds — never an optimistic guess.
fn collab_panel(
    store: Store,
    id: &str,
    c: &Value,
    detail: super::Fetch,
    principals: super::Fetch,
) -> AnyView {
    let case_id = StoredValue::new(id.to_string());
    let busy = RwSignal::new(false);
    let err = RwSignal::new(Option::<api::ApiError>::None);

    // One shared runner: POST, log to the activity center, reload the case.
    let act = move |title: &'static str, route: &'static str, body: Value| {
        if busy.get_untracked() {
            return;
        }
        busy.set(true);
        err.set(None);
        let id = case_id.get_value();
        leptos::task::spawn_local(async move {
            let path = format!("/api/cases/{}/{}", api::enc(&id), route);
            let r = api::send_post(&path, body).await;
            busy.set(false);
            match r {
                Ok(_) => {
                    store.log_activity(title, true, format!("case {}", api::enc(&id)), None);
                    detail.load(format!("/api/cases/{}", api::enc(&id)));
                }
                Err(e) => {
                    store.log_activity(title, false, e.to_string(), None);
                    err.set(Some(e));
                }
            }
        });
    };

    let owner = api::s(c, "assignee");
    let owner_for_opts = owner.clone();
    let free_assignee = RwSignal::new(owner.clone());
    let assign = move |name: String| {
        let body = if name.is_empty() {
            json!({ "assignee": null })
        } else {
            json!({ "assignee": name })
        };
        act("Case owner changed", "assign", body);
    };

    let tags: Vec<String> = super::arr(c, "tags")
        .iter()
        .filter_map(|v| v.as_str().map(String::from))
        .collect();
    let tag_new = RwSignal::new(String::new());
    let add_tag = move || {
        let t = tag_new.get_untracked().trim().to_lowercase();
        if t.is_empty() {
            return;
        }
        tag_new.set(String::new());
        act("Case tag added", "tags", json!({ "add": [t] }));
    };

    let linked: Vec<String> = super::arr(c, "linked_cases")
        .iter()
        .filter_map(|v| v.as_str().map(String::from))
        .collect();
    let link_new = RwSignal::new(String::new());
    let add_link = move || {
        let other = link_new.get_untracked().trim().to_string();
        if other.is_empty() {
            return;
        }
        link_new.set(String::new());
        act("Cases linked", "link", json!({ "other": other }));
    };

    view! {
        <div class="collab">
            // A follower can read everything but change nothing — say so once
            // instead of letting each control fail with a 403.
            {move || store.caps.get().and_then(|caps| (!caps.writes_enabled()).then(|| {
                ui::banner("warn", "Read-only follower — ownership, tags, notes and links cannot be changed here.")
            }))}
            <div class="row collab-row">
                <span class="dimtext">"Owner"</span>
                {ui::help_tip("The analyst who owns this investigation. Taking ownership stops the acknowledge SLA clock; (unassigned) returns the case to the shared queue.")}
                {move || {
                    let mut names: Vec<String> = principals.rows("principals").iter()
                        .map(|p| api::s(p, "user"))
                        .filter(|u| !u.is_empty())
                        .collect();
                    if names.is_empty() {
                        // No identity directory (open-loopback dev) — the server
                        // accepts free-text names there, so offer exactly that.
                        return view! {
                            <input class="assignbox" placeholder="assign to…"
                                prop:value=move || free_assignee.get()
                                prop:disabled=move || busy.get()
                                on:input=move |ev| free_assignee.set(event_target_value(&ev))/>
                            <button class="btn ghost" prop:disabled=move || busy.get()
                                on:click=move |_| assign(free_assignee.get_untracked().trim().to_string())>
                                "Assign"
                            </button>
                        }.into_any();
                    }
                    // The current owner may be unknown to the directory (assigned
                    // in the dev posture) — keep them selectable rather than
                    // silently showing someone else.
                    if !owner_for_opts.is_empty() && !names.contains(&owner_for_opts) {
                        names.insert(0, owner_for_opts.clone());
                    }
                    let current = owner_for_opts.clone();
                    view! {
                        <select prop:disabled=move || busy.get()
                            aria-label="Case owner"
                            on:change=move |ev| assign(event_target_value(&ev))>
                            <option value="" selected=current.is_empty()>"(unassigned)"</option>
                            {names.into_iter().map(|n| {
                                let sel = n == current;
                                let value = n.clone();
                                view! { <option value=value selected=sel>{n}</option> }
                            }).collect_view()}
                        </select>
                    }.into_any()
                }}
            </div>
            <div class="row collab-row">
                <span class="dimtext">"Tags"</span>
                {ui::help_tip("Free labels for triage workflow — e.g. escalation, false-positive-candidate, customer-x. The tag filter on the queue matches these.")}
                <span class="tags">
                    {tags.into_iter().map(|t| {
                        let t_removed = t.clone();
                        let aria = format!("remove tag {t}");
                        view! {
                            <span class="tag">{t}
                                <button class="linkish subtle" aria-label=aria
                                    prop:disabled=move || busy.get()
                                    on:click=move |_| act("Case tag removed", "tags",
                                        json!({ "remove": [t_removed.clone()] }))>"✕"</button>
                            </span>
                        }
                    }).collect_view()}
                </span>
                <input class="tagbox" placeholder="add tag…"
                    prop:value=move || tag_new.get()
                    prop:disabled=move || busy.get()
                    on:input=move |ev| tag_new.set(event_target_value(&ev))
                    on:keydown=move |ev: web_sys::KeyboardEvent| if ev.key() == "Enter" { add_tag() }/>
                <button class="btn ghost" prop:disabled=move || busy.get()
                    on:click=move |_| add_tag()>"+ Tag"</button>
            </div>
            <div class="row collab-row">
                <span class="dimtext">"Linked"</span>
                {ui::help_tip("Investigations connected to this one — same incident seen from different rules or hosts. Links are bidirectional; click a chip to open the other case.")}
                {(!linked.is_empty()).then(|| view! {
                    <span class="chips">
                        {linked.into_iter().map(|other| {
                            let short: String = other.chars().take(8).collect();
                            view! {
                                <ui::ViewLink view=View::Investigation(other) class="tag mono">
                                    {short}
                                </ui::ViewLink>
                            }
                        }).collect_view()}
                    </span>
                })}
                <input class="linkbox mono" placeholder="case id…"
                    prop:value=move || link_new.get()
                    prop:disabled=move || busy.get()
                    on:input=move |ev| link_new.set(event_target_value(&ev))
                    on:keydown=move |ev: web_sys::KeyboardEvent| if ev.key() == "Enter" { add_link() }/>
                <button class="btn ghost" prop:disabled=move || busy.get()
                    on:click=move |_| add_link()>"⇄ Link"</button>
            </div>
            {move || err.get().map(super::error_state)}
        </div>
    }
    .into_any()
}

/// The analyst-note composer under the evidence timeline. A note is a
/// transcript entry stamped `analyst:<name>` by the server, with an entry id so
/// it survives a concurrent agent snapshot; the audit ledger records who and
/// when (the transcript holds the content).
fn note_composer(store: Store, id: &str, detail: super::Fetch) -> AnyView {
    let case_id = StoredValue::new(id.to_string());
    let text = RwSignal::new(String::new());
    let busy = RwSignal::new(false);
    let err = RwSignal::new(Option::<api::ApiError>::None);
    let submit = move || {
        let t = text.get_untracked().trim().to_string();
        if t.is_empty() || busy.get_untracked() {
            return;
        }
        busy.set(true);
        err.set(None);
        let id = case_id.get_value();
        leptos::task::spawn_local(async move {
            let path = format!("/api/cases/{}/comment", api::enc(&id));
            let r = api::send_post(&path, json!({ "text": t })).await;
            busy.set(false);
            match r {
                Ok(_) => {
                    store.log_activity(
                        "Analyst note added",
                        true,
                        format!("case {}", api::enc(&id)),
                        None,
                    );
                    text.set(String::new());
                    detail.load(format!("/api/cases/{}", api::enc(&id)));
                }
                Err(e) => {
                    store.log_activity("Analyst note failed", false, e.to_string(), None);
                    err.set(Some(e));
                }
            }
        });
    };
    view! {
        <div class="human-card note-composer">
            <label class="wide">"Add analyst note"<span class="human-tag">"human"</span>
                {ui::help_tip("A note in the evidence timeline, recorded under your name. The audit ledger records that you commented; the timeline holds what you wrote.")}
                <textarea rows="2" placeholder="what you checked, what you concluded — becomes part of the case record"
                    prop:value=move || text.get()
                    on:input=move |ev| text.set(event_target_value(&ev))></textarea>
            </label>
            <div class="row">
                <button class="btn" prop:disabled=move || busy.get() || text.get().trim().is_empty()
                    on:click=move |_| submit()>
                    {move || if busy.get() { "Adding…" } else { "Add note" }}
                </button>
                {move || err.get().map(super::error_state)}
            </div>
        </div>
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

#[cfg(test)]
mod tests {
    use super::*;

    /// The queue request carries exactly the filters that are set — an empty
    /// filter must not appear, or the server would match the empty string.
    #[test]
    fn cases_url_carries_only_set_filters() {
        assert_eq!(cases_url("", "", ""), "/api/cases");
        assert_eq!(
            cases_url("needs_human", "", ""),
            "/api/cases?state=needs_human"
        );
        assert_eq!(
            cases_url("escalated", "alice", "escalation"),
            "/api/cases?state=escalated&assignee=alice&tag=escalation"
        );
    }

    /// The unowned lane's sentinel survives percent-encoding round-trip intact
    /// (parens are reserved-ish characters; the server matches the literal).
    #[test]
    fn unassigned_lane_is_percent_encoded() {
        assert_eq!(
            cases_url("", "(unassigned)", ""),
            "/api/cases?assignee=%28unassigned%29"
        );
    }

    /// Every SLA badge pairs a status class with its own text label — and a
    /// breach is always `bad`, whatever combination of clocks tripped.
    #[test]
    fn sla_badges_name_the_breached_clock() {
        let both = serde_json::json!({ "ack_breached": true, "resolve_breached": true });
        assert_eq!(sla_class_label(&both), ("bad", "ack+resolve overdue"));
        let ack = serde_json::json!({ "ack_breached": true, "resolve_breached": false });
        assert_eq!(sla_class_label(&ack), ("bad", "ack overdue"));
        let resolve = serde_json::json!({ "ack_breached": false, "resolve_breached": true });
        assert_eq!(sla_class_label(&resolve), ("bad", "resolve overdue"));
        let running = serde_json::json!({
            "ack_breached": false, "resolve_breached": false,
            "resolve_deadline": "2026-08-15T12:00:00Z"
        });
        assert_eq!(sla_class_label(&running), ("pass", "within SLA"));
        // A closed case under an SLA config: block present, no clock applies.
        let idle = serde_json::json!({
            "ack_breached": false, "resolve_breached": false,
            "ack_deadline": null, "resolve_deadline": null
        });
        assert_eq!(sla_class_label(&idle), ("dim", "no clock"));
    }

    /// Breached cases float to the top; everything else keeps the server's
    /// newest-first order — including relative order among the breached.
    #[test]
    fn breached_cases_sort_first_and_stably() {
        let row = |id: &str, breached: bool| serde_json::json!({ "id": id, "sla": { "ack_breached": breached } });
        let rows = vec![
            row("a", false),
            row("b", true),
            serde_json::json!({ "id": "c" }), // no sla block at all
            row("d", true),
        ];
        let sorted: Vec<String> = breached_first(rows)
            .iter()
            .map(|c| api::s(c, "id"))
            .collect();
        assert_eq!(sorted, ["b", "d", "a", "c"]);
    }

    /// The server stamps analyst writes `analyst:<name>`; everything else in a
    /// transcript is a machine actor and must not render as a person.
    #[test]
    fn analyst_entries_are_recognized_by_actor_prefix() {
        assert_eq!(analyst_name("analyst:alice"), Some("alice"));
        assert_eq!(analyst_name("agent"), None);
        assert_eq!(analyst_name("router"), None);
        assert_eq!(analyst_name("system"), None);
        // Degenerate stamp: empty name is not a person.
        assert_eq!(analyst_name("analyst:"), None);
        // A tool that happens to contain the word is not an analyst.
        assert_eq!(analyst_name("log_analyst_tool"), None);
    }
}
