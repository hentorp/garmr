// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! Audit Explorer — one search surface over every audit event, in three modes
//! that share the same result table and never make the analyst learn the backend:
//!   - **Simple** — full-text (Tantivy) or the time-range feed when the box is empty.
//!   - **Advanced** — the safe hybrid Query-IR (structured filter + full-text +
//!     meaning), each result carrying its per-signal provenance.
//!   - **Natural language** — ask a question; the model plans a read-only query,
//!     garmr runs it, and the answer is grounded in cited rows.
//!
//! Results pivot to entities and expand to a structured event detail (never a
//! raw JSON blob by default).

use leptos::prelude::*;
use serde_json::{json, Value};

use crate::route::{Area, View};
use crate::{api, ui, Store};

pub fn view(store: Store) -> impl IntoView {
    // Mode + query live in the URL so a search is a shareable, reload-safe link.
    let mode = move || store.nav.param("mode").unwrap_or_else(|| "text".into());
    let q0 = store.nav.param_untracked("q").unwrap_or_default();

    let query = RwSignal::new(q0.clone());
    let results = RwSignal::new(Vec::<Value>::new());
    let meta = RwSignal::new(String::new());
    let err = RwSignal::new(Option::<api::ApiError>::None);
    let loading = RwSignal::new(false);
    let nl_answer = RwSignal::new(Option::<Value>::None);
    let expanded = RwSignal::new(Option::<usize>::None);
    // Advanced structured filter fields.
    let f_host = RwSignal::new(String::new());
    let f_service = RwSignal::new(String::new());
    let f_severity = RwSignal::new(String::new());

    let set_mode = move |m: &'static str| {
        let q = query.get_untracked();
        store.nav.set_query(crate::route::build_query(&[
            ("mode", m.to_string()),
            ("q", q),
        ]));
    };

    // ---- runners ----
    let run_text = move || {
        let q = query.get_untracked().trim().to_string();
        loading.set(true);
        err.set(None);
        nl_answer.set(None);
        expanded.set(None);
        leptos::task::spawn_local(async move {
            let (url, src) = if q.is_empty() {
                match store.time_range.get_untracked().events_predicate() {
                    None => ("/api/tail?limit=300".to_string(), "live tail".to_string()),
                    Some(pred) => (
                        format!(
                            "/api/query?sql={}",
                            api::enc(&format!(
                                "SELECT event_ts, host, service, severity, message FROM events \
                                 WHERE {pred} ORDER BY event_ts DESC LIMIT 300"
                            ))
                        ),
                        store.time_range.get_untracked().label(),
                    ),
                }
            } else {
                (
                    format!("/api/search?q={}", api::enc(&q)),
                    format!("full-text: {q}"),
                )
            };
            match api::send_get(&url).await {
                Ok(v) => {
                    let key = if v.get("hits").is_some() {
                        "hits"
                    } else {
                        "rows"
                    };
                    results.set(normalize(super::arr(&v, key)));
                    meta.set(src);
                }
                Err(e) => err.set(Some(e)),
            }
            loading.set(false);
        });
    };

    let run_advanced = move || {
        loading.set(true);
        err.set(None);
        nl_answer.set(None);
        expanded.set(None);
        let mut filter = json!({});
        let vecify = |s: String| -> Vec<String> {
            s.split(',')
                .map(|x| x.trim().to_string())
                .filter(|x| !x.is_empty())
                .collect()
        };
        let host = vecify(f_host.get_untracked());
        let service = vecify(f_service.get_untracked());
        let severity = vecify(f_severity.get_untracked());
        if !host.is_empty() {
            filter["host"] = json!(host);
        }
        if !service.is_empty() {
            filter["service"] = json!(service);
        }
        if !severity.is_empty() {
            filter["severity"] = json!(severity);
        }
        let text = query.get_untracked().trim().to_string();
        let mut body = json!({ "filter": filter, "fusion": {} });
        if !text.is_empty() {
            body["text"] = json!({ "query": text });
            // A meaning clause too — the server ignores it if semantic is off.
            body["semantic"] = json!({ "query": text });
        }
        leptos::task::spawn_local(async move {
            match api::send_post("/api/hsearch", body).await {
                Ok(v) => {
                    results.set(normalize(super::arr(&v, "items")));
                    meta.set("structured + full-text + meaning search".into());
                }
                Err(e) => err.set(Some(e)),
            }
            loading.set(false);
        });
    };

    let run_nl = move || {
        let q = query.get_untracked().trim().to_string();
        if q.is_empty() {
            return;
        }
        loading.set(true);
        err.set(None);
        results.set(Vec::new());
        leptos::task::spawn_local(async move {
            match api::send_get(&format!("/api/ask?q={}", api::enc(&q))).await {
                Ok(v) => nl_answer.set(Some(v)),
                Err(e) => err.set(Some(e)),
            }
            loading.set(false);
        });
    };

    let run = move || match mode().as_str() {
        "advanced" => run_advanced(),
        "nl" => run_nl(),
        _ => run_text(),
    };

    // Initial run for the current mode/query (deep link).
    run();

    view! {
        <div class="page">
            {ui::page_header("Audit Explorer", Area::Audit.blurb())}

            {super::tabs(
                &[("text", "Simple"), ("advanced", "Advanced"), ("nl", "Natural language")],
                mode(),
                set_mode,
            )}

            <div class="row searchmode-help dimtext">
                <span class="modehelp">"Simple"{ui::help_tip("Plain keyword search across every audit event — type words to find matching events, or leave the box empty to browse the current time range.")}</span>
                <span class="modehelp">"Advanced"{ui::help_tip("Combine exact filters (host, service, severity) with keyword and meaning-based matching for a precise, structured search.")}</span>
                <span class="modehelp">"Natural language"{ui::help_tip("Ask a question in plain English; the assistant plans a safe read-only query and answers with the specific events it cites.")}</span>
            </div>

            <div class="searchbar">
                {move || match mode().as_str() {
                    "nl" => view! {
                        <input type="search" class="grow" placeholder="Ask a question — e.g. which users read person data off-hours?"
                            prop:value=move || query.get()
                            on:input=move |ev| query.set(event_target_value(&ev))
                            on:keydown=move |ev| if ev.key() == "Enter" { run() }/>
                        <button class="btn primary" on:click=move |_| run()>"Ask"</button>
                    }.into_any(),
                    "advanced" => view! {
                        <div class="adv-grid">
                            <input type="text" placeholder="host (comma-sep)" prop:value=move || f_host.get()
                                on:input=move |ev| f_host.set(event_target_value(&ev))/>
                            <input type="text" placeholder="service" prop:value=move || f_service.get()
                                on:input=move |ev| f_service.set(event_target_value(&ev))/>
                            <input type="text" placeholder="severity" prop:value=move || f_severity.get()
                                on:input=move |ev| f_severity.set(event_target_value(&ev))/>
                            <input type="search" class="grow" placeholder="text / meaning (optional)"
                                prop:value=move || query.get()
                                on:input=move |ev| query.set(event_target_value(&ev))
                                on:keydown=move |ev| if ev.key() == "Enter" { run() }/>
                            <button class="btn primary" on:click=move |_| run()>"Search"</button>
                        </div>
                    }.into_any(),
                    _ => view! {
                        <input type="search" class="grow" placeholder="full-text search (empty = the time-range feed)"
                            prop:value=move || query.get()
                            on:input=move |ev| query.set(event_target_value(&ev))
                            on:keydown=move |ev| if ev.key() == "Enter" { run() }/>
                        <button class="btn primary" on:click=move |_| run()>"Search"</button>
                        <button class="btn ghost" on:click=move |_| { query.set(String::new()); run() }>"Clear"</button>
                    }.into_any(),
                }}
            </div>

            // NL capability gate.
            {move || (mode() == "nl").then(|| {
                store.caps.get().map(|c| {
                    let fs = c.feature("nl_ask");
                    (fs.state != "healthy").then(|| ui::disabled_panel("AI natural-language search", &fs))
                })
            })}

            // Results / answer.
            {move || {
                if let Some(e) = err.get() {
                    return super::error_state(e);
                }
                if loading.get() {
                    return ui::loading("searching…");
                }
                if mode() == "nl" {
                    return match nl_answer.get() {
                        Some(a) => view! { <div class="results">{super::ask::answer_card(&a)}</div> }.into_any(),
                        None => ui::empty("ask a question to search in plain language"),
                    };
                }
                let rows = results.get();
                if rows.is_empty() {
                    return ui::empty("no matching events");
                }
                let n = rows.len();
                let semantic_ready = store
                    .caps
                    .get()
                    .map(|c| c.feature("semantic_search").state == "healthy")
                    .unwrap_or(false);
                let explain_body = search_explanation(mode(), semantic_ready, n >= 300);
                view! {
                    <div class="row resultmeta">
                        <span class="dimtext">{format!("{n} event(s) · {}", meta.get())}</span>
                        {(n >= 300).then(|| ui::pill("warn", "capped at 300"))}
                        <ui::InfoPopover heading="How these results were found" body=explain_body/>
                    </div>
                    {results_table(store, rows, expanded)}
                }.into_any()
            }}
        </div>
    }
}

/// Plain-language explanation of how the current search ran, surfaced behind an
/// InfoPopover so the analyst never has to know the retrieval internals. Covers
/// which modes ran, whether meaning-based search was available, whether the
/// result set was truncated, and that the query is reproducible from the link.
fn search_explanation(mode: String, semantic_ok: bool, capped: bool) -> String {
    let ran = match mode.as_str() {
        "advanced" => "This was a structured search: your exact filters (host, service, severity) combined \
             with full-text keyword matching and, where available, meaning-based (semantic) matching — \
             each result is tagged with which of those signals matched it.",
        _ => "This was a plain full-text keyword search over the audit events, or the current \
             time-range feed when the search box is empty.",
    };
    let sem = if semantic_ok {
        "Meaning-based search is available on this deployment, so results can match on intent as well \
         as the exact words used."
    } else {
        "Meaning-based search is not available here, so matching relied on keywords and filters only."
    };
    let cap = if capped {
        "Results were capped at 300 events; narrow the query to be sure you are seeing everything that matches."
    } else {
        "Every matching event is shown."
    };
    format!(
        "{ran} {sem} {cap} The search is captured in this page's link, so the same query and results \
         can be reproduced by reopening or sharing the URL."
    )
}

/// Normalize search/tail/query/hsearch rows to `{event_ts, host, service,
/// severity, message}` while keeping the whole raw object for the detail view.
fn normalize(rows: Vec<Value>) -> Vec<Value> {
    rows.into_iter()
        .map(|r| {
            let ts = if let Some(m) = r.get("ts_micros").and_then(Value::as_i64) {
                api::ts_iso(m)
            } else {
                api::s(&r, "event_ts")
            };
            json!({
                "event_ts": ts,
                "host": api::s(&r, "host"),
                "service": api::s(&r, "service"),
                "severity": api::s(&r, "severity"),
                "message": api::s(&r, "message"),
                "provenance": r.get("provenance").cloned().unwrap_or(Value::Null),
                "_raw": r,
            })
        })
        .collect()
}

fn results_table(store: Store, rows: Vec<Value>, expanded: RwSignal<Option<usize>>) -> AnyView {
    super::table(
        &["time", "host", "service", "sev", "message", ""],
        rows.into_iter().enumerate().map(|(i, e)| {
            let sev = api::s(&e, "severity");
            let sc = crate::status::severity_class(&sev);
            let prov = provenance_badges(&e);
            let is_open = move || expanded.get() == Some(i);
            let raw = e.get("_raw").cloned().unwrap_or(Value::Null);
            let host = api::s(&e, "host");
            let hostc = host.clone();
            view! {
                <tr class="rowlink" on:click=move |_| expanded.update(|x| *x = if *x == Some(i) { None } else { Some(i) })>
                    <td class="mono dimtext">{api::s(&e, "event_ts")}</td>
                    <td class="mono">{host}</td>
                    <td>{api::s(&e, "service")}</td>
                    <td class=format!("sev {sc}")>{sev}</td>
                    <td class="msg">{api::clean(&api::clip(&api::s(&e, "message"), 2000))}{prov}</td>
                    <td class="mono dimtext">{move || if is_open() { "▾" } else { "▸" }}</td>
                </tr>
                {move || is_open().then(|| view! {
                    <tr class="detailrow"><td colspan="6">{event_detail(store, &raw, &hostc)}</td></tr>
                })}
            }
        }).collect_view().into_any(),
    )
}

/// Per-result provenance chips ([S]/[F]/[V]) — which signals matched.
fn provenance_badges(e: &Value) -> AnyView {
    let prov = super::arr(e, "provenance");
    if prov.is_empty() {
        return view! { <span></span> }.into_any();
    }
    view! {
        <span class="prov-chips">
            {prov.into_iter().map(|p| {
                let (label, cls) = match api::s(&p, "signal").as_str() {
                    "structured" => ("S", "dim"),
                    "full_text" => ("F", "warn"),
                    "semantic" => ("V", "pass"),
                    _ => ("?", "dim"),
                };
                view! { <span class=format!("provchip {cls}") title=format!("matched via {}", api::s(&p, "signal"))>{label}</span> }
            }).collect_view()}
        </span>
    }
    .into_any()
}

/// A structured event detail: normalized fields, provenance, pivots, raw payload
/// last (collapsed by default) — never a raw JSON blob as the primary view.
fn event_detail(store: Store, raw: &Value, host: &str) -> AnyView {
    let mut pairs: Vec<(String, String)> = Vec::new();
    if let Some(obj) = raw.as_object() {
        for (k, v) in obj {
            if k == "provenance" || k == "_raw" {
                continue;
            }
            let val = match v {
                Value::String(s) => s.clone(),
                other => other.to_string(),
            };
            if !val.is_empty() && val != "\"\"" {
                pairs.push((k.clone(), val));
            }
        }
    }
    pairs.sort_by(|a, b| a.0.cmp(&b.0));
    let host_owned = host.to_string();
    let host_search = host.to_string();
    let raw_pretty = serde_json::to_string_pretty(raw).unwrap_or_default();
    view! {
        <div class="event-detail">
            <div class="row detail-actions">
                {(!host_owned.is_empty()).then(|| {
                    let h1 = host_owned.clone();
                    let h2 = host_search.clone();
                    view! {
                        <button class="btn ghost" on:click=move |_| store.peek("host", h1.clone())>"Peek host"</button>
                        <button class="btn ghost" on:click=move |_| {
                            store.nav.go(View::Application(h2.clone()))
                        }>"Open host"</button>
                    }
                })}
            </div>
            <dl class="fields dense">
                {pairs.into_iter().map(|(k, v)| view! {
                    <dt>{k}</dt><dd class="mono">{api::clean(&v)}</dd>
                }).collect_view()}
            </dl>
            <details class="rawblock">
                <summary>"Raw payload"</summary>
                <pre class="plan mono">{api::clean(&raw_pretty)}</pre>
            </details>
        </div>
    }
    .into_any()
}
