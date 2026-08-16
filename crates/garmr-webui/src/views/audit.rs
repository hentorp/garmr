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
use crate::{api, ui, Store, TimeRange};

/// How many rows the feed and Simple search ask for.
const TEXT_LIMIT: usize = 300;
/// How many the Advanced (hybrid) search can: the planner clamps a fusion limit
/// to `garmr_query::ir::MAX_LIMIT`, so asking for the feed's 300 would come back
/// as 200 and the footer would under-report the cap.
const ADVANCED_LIMIT: usize = 200;

/// The row ceiling for a mode, so the results footer names the cap that
/// actually applied rather than one mode's number for all three.
fn row_limit(mode: &str) -> usize {
    match mode {
        "advanced" => ADVANCED_LIMIT,
        _ => TEXT_LIMIT,
    }
}

pub fn view(store: Store) -> impl IntoView {
    // The whole search — mode, text, and Advanced's structured filters — lives in
    // the URL. That makes it a shareable, reload-safe link, and it is also the only
    // way the search survives: every query write re-renders this view from the URL,
    // so anything held only in a view-local signal is discarded. Before, typing a
    // search and then touching the time-range chips cleared the box and dropped
    // back to the plain time-range feed.
    let mode = move || store.nav.param("mode").unwrap_or_else(|| "text".into());
    let mode_now = move || {
        store
            .nav
            .param_untracked("mode")
            .unwrap_or_else(|| "text".into())
    };
    let from_url = move |k: &str| store.nav.param_untracked(k).unwrap_or_default();

    let query = RwSignal::new(from_url("q"));
    let results = RwSignal::new(Vec::<Value>::new());
    let meta = RwSignal::new(String::new());
    let err = RwSignal::new(Option::<api::ApiError>::None);
    let loading = RwSignal::new(false);
    let nl_answer = RwSignal::new(Option::<Value>::None);
    let expanded = RwSignal::new(Option::<usize>::None);
    // Advanced structured filter fields — in the URL for the same reason as the
    // text: a time-range chip used to wipe them mid-search.
    let f_host = RwSignal::new(from_url("host"));
    let f_service = RwSignal::new(from_url("service"));
    let f_severity = RwSignal::new(from_url("severity"));

    // Publish the search to the URL, quietly: no scroll to top and no focus jump
    // out of the search box, which is what a real navigation would do. The
    // re-render that follows reads the search back out of the URL and issues
    // exactly one request — so submitting must publish and nothing more, or the
    // same search would be sent twice.
    let publish = move |m: &str, asked: bool| {
        store.nav.set_query_quiet(search_query(
            m,
            &query.get_untracked(),
            &f_host.get_untracked(),
            &f_service.get_untracked(),
            &f_severity.get_untracked(),
            &store.nav.query.get_untracked(),
            asked,
        ));
    };
    let submit = move || {
        let m = mode_now();
        // An explicit Ask must reach the model even when the question has not
        // changed, or the button looks dead. Dropping the cached answer is what
        // makes the rebuild below ask instead of restoring it — see `nl_action`.
        if m == "nl" {
            store.nl_answer.set(None);
        }
        publish(&m, true);
    };
    // Switching tabs is not asking. It publishes the same text under a new mode,
    // so without this the Natural-language tab would send whatever sat in the
    // Simple box straight to the model, and bill for it.
    let set_mode = move |m: &'static str| publish(m, false);

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
                    None => (
                        format!("/api/tail?limit={TEXT_LIMIT}"),
                        "live tail".to_string(),
                    ),
                    Some(pred) => (
                        format!(
                            "/api/query?sql={}",
                            api::enc(&format!(
                                "SELECT event_ts, host, service, severity, message FROM events \
                                 WHERE {pred} ORDER BY event_ts DESC LIMIT {TEXT_LIMIT}"
                            ))
                        ),
                        store.time_range.get_untracked().label(),
                    ),
                }
            } else {
                // The global range governs full-text search exactly as it
                // governs the feed — the results header names the window so a
                // capped result set is never mistaken for "all time".
                let tr = store.time_range.get_untracked();
                let src = match tr {
                    TimeRange::Live => format!("full-text: {q}"),
                    _ => format!("full-text: {q} · {}", tr.label()),
                };
                (
                    format!(
                        "/api/search?q={}&limit={TEXT_LIMIT}{}",
                        api::enc(&q),
                        tr.search_params()
                    ),
                    src,
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
        // The global range bounds every leg of the hybrid query — structured,
        // full-text and meaning alike — so Advanced search obeys the picker that
        // claims to govern this area, exactly as Simple search does. Live sends
        // no time clause (the IR's unbounded default).
        let tr = store.time_range.get_untracked();
        if let Some(time) = tr.hsearch_time() {
            filter["time"] = time;
        }
        let text = query.get_untracked().trim().to_string();
        // Nothing to retrieve by — no filter, no text, no window — would be the
        // server's "empty query" 400. Show the empty state instead, the same way
        // NL declines an empty question.
        if text.is_empty() && filter.as_object().is_none_or(|f| f.is_empty()) {
            results.set(Vec::new());
            meta.set(String::new());
            return;
        }
        // Ask for the planner's ceiling rather than letting the server's
        // default of 20 truncate silently: the footer can only be honest about
        // a cap whose size it knows.
        let mut body = json!({ "filter": filter, "fusion": { "limit": ADVANCED_LIMIT } });
        if !text.is_empty() {
            body["text"] = json!({ "query": text });
            // A meaning clause too — the server ignores it if semantic is off.
            body["semantic"] = json!({ "query": text });
        }
        loading.set(true);
        let src = match tr {
            TimeRange::Live => "structured + full-text + meaning search".to_string(),
            _ => format!("structured + full-text + meaning search · {}", tr.label()),
        };
        leptos::task::spawn_local(async move {
            match api::send_post("/api/hsearch", body).await {
                Ok(v) => {
                    results.set(normalize(super::arr(&v, "items")));
                    meta.set(src);
                }
                Err(e) => err.set(Some(e)),
            }
            loading.set(false);
        });
    };

    let run_nl = move || {
        let q = query.get_untracked().trim().to_string();
        let cached = store.nl_answer.get_untracked();
        match nl_action(
            &q,
            store.nav.param_untracked("ask").is_some(),
            cached.as_ref().map(|(asked, _)| asked.as_str()),
        ) {
            // Nobody asked for this — a tab click, or a link with no `ask`.
            NlAction::Wait => return,
            // Already paid for. Put it straight back on screen.
            NlAction::Restore => {
                nl_answer.set(cached.map(|(_, answer)| answer));
                return;
            }
            NlAction::Ask => {}
        }
        loading.set(true);
        err.set(None);
        results.set(Vec::new());
        leptos::task::spawn_local(async move {
            match api::send_get(&format!("/api/ask?q={}", api::enc(&q))).await {
                Ok(v) => {
                    // Cache before displaying: the next rebuild — a range chip,
                    // Back, a return to this view — then restores instead of
                    // asking again.
                    store.nl_answer.set(Some((q.clone(), v.clone())));
                    nl_answer.set(Some(v));
                }
                Err(e) => err.set(Some(e)),
            }
            loading.set(false);
        });
    };

    // The single place a request is issued: whatever the URL currently asks for.
    // A deep link, a reload, Back/Forward and a submission all arrive here —
    // every one of them republishes the query, which rebuilds this view.
    //
    // It runs in an effect, not at construction, for ordering: the global range
    // is restored from the URL by the picker's OWN effect, so a synchronous run
    // would read the default window and search it — a shared `…&t=168h` link
    // would quietly answer for Live and never correct itself. Effects run after
    // the render pass, so by here the restored range is in the signal.
    //
    // The effect tracks nothing (the range is read untracked inside the
    // runners), so it fires exactly once per rebuild. A range change does not
    // need it to re-run: the picker publishes the range to the URL, and that
    // write rebuilds the view — one request, not two.
    Effect::new(move |_| match mode_now().as_str() {
        "advanced" => run_advanced(),
        "nl" => run_nl(),
        _ => run_text(),
    });

    view! {
        <div class="page">
            {ui::page_header("Audit Explorer", Area::Audit.blurb())}

            {super::tabs(
                &[("text", "Simple"), ("advanced", "Advanced"), ("nl", "Natural language")],
                mode(),
                set_mode,
            )}

            <div class="row searchmode-help dimtext">
                <span class="modehelp">"Simple"{ui::help_tip("Plain keyword search across the audit events in the selected time range — type words to find matching events, or leave the box empty to browse the range as a feed.")}</span>
                <span class="modehelp">"Advanced"{ui::help_tip("Combine exact filters (host, service, severity) with keyword and meaning-based matching for a precise, structured search of the selected time range.")}</span>
                <span class="modehelp">"Natural language"{ui::help_tip("Ask a question in plain English; the assistant plans a safe read-only query and answers with the specific events it cites. It picks its own time window from your question, so the range above does not apply here — and it only runs when you press Ask.")}</span>
            </div>

            <div class="searchbar">
                {move || match mode().as_str() {
                    "nl" => view! {
                        <input type="search" class="grow" placeholder="Ask a question — e.g. which users read person data off-hours?"
                            prop:value=move || query.get()
                            on:input=move |ev| query.set(event_target_value(&ev))
                            on:keydown=move |ev| if ev.key() == "Enter" { submit() }/>
                        <button class="btn primary" on:click=move |_| submit()>"Ask"</button>
                    }.into_any(),
                    "advanced" => view! {
                        <div class="adv-grid">
                            <input type="text" placeholder="host (comma-sep)" prop:value=move || f_host.get()
                                on:input=move |ev| f_host.set(event_target_value(&ev))
                                on:keydown=move |ev| if ev.key() == "Enter" { submit() }/>
                            <input type="text" placeholder="service" prop:value=move || f_service.get()
                                on:input=move |ev| f_service.set(event_target_value(&ev))
                                on:keydown=move |ev| if ev.key() == "Enter" { submit() }/>
                            <input type="text" placeholder="severity" prop:value=move || f_severity.get()
                                on:input=move |ev| f_severity.set(event_target_value(&ev))
                                on:keydown=move |ev| if ev.key() == "Enter" { submit() }/>
                            <input type="search" class="grow" placeholder="text / meaning (optional)"
                                prop:value=move || query.get()
                                on:input=move |ev| query.set(event_target_value(&ev))
                                on:keydown=move |ev| if ev.key() == "Enter" { submit() }/>
                            <button class="btn primary" on:click=move |_| submit()>"Search"</button>
                        </div>
                    }.into_any(),
                    _ => view! {
                        <input type="search" class="grow" placeholder="full-text search (empty = the time-range feed)"
                            prop:value=move || query.get()
                            on:input=move |ev| query.set(event_target_value(&ev))
                            on:keydown=move |ev| if ev.key() == "Enter" { submit() }/>
                        <button class="btn primary" on:click=move |_| submit()>"Search"</button>
                        <button class="btn ghost" on:click=move |_| { query.set(String::new()); submit() }>"Clear"</button>
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
                let limit = row_limit(&mode());
                let explain_body = search_explanation(
                    mode(),
                    semantic_ready,
                    (n >= limit).then_some(limit),
                    store.time_range.get(),
                );
                view! {
                    <div class="row resultmeta">
                        <span class="dimtext">{format!("{n} event(s) · {}", meta.get())}</span>
                        {(n >= limit).then(|| ui::pill("warn", format!("capped at {limit}")))}
                        <ui::InfoPopover heading="How these results were found" body=explain_body/>
                    </div>
                    {results_table(store, rows, expanded)}
                }.into_any()
            }}
        </div>
    }
}

/// The query string a submitted search publishes: the mode, the search text, and
/// (in Advanced only) the structured filters — with the global time range carried
/// through from `current` untouched.
///
/// Carrying the range matters as much as publishing the search: submitting must
/// never silently widen the window the analyst chose. And the filters ride along
/// only in the mode that applies them, so a URL never advertises a filter the
/// search it names does not use.
#[allow(clippy::too_many_arguments)]
fn search_query(
    mode: &str,
    q: &str,
    host: &str,
    service: &str,
    severity: &str,
    current: &str,
    asked: bool,
) -> String {
    let advanced = mode == "advanced";
    let filter = |v: &str| {
        if advanced {
            v.trim().to_string()
        } else {
            String::new()
        }
    };
    super::publish_query(
        &[
            ("mode", mode.to_string()),
            ("q", q.trim().to_string()),
            ("host", filter(host)),
            ("service", filter(service)),
            ("severity", filter(severity)),
            // Only Natural language carries it: it is the one mode where running
            // the search costs model budget, so the URL has to say whether a
            // human asked for it. Every other mode re-runs freely and keeps a
            // cleaner link.
            (
                "ask",
                if asked && mode == "nl" {
                    "1".to_string()
                } else {
                    String::new()
                },
            ),
        ],
        current,
    )
}

/// What a rebuild of this view should do in Natural-language mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NlAction {
    /// Call `/api/ask` — a human asked for this and no answer is on hand.
    Ask,
    /// Show the answer already paid for; the question has not changed.
    Restore,
    /// Do nothing. No question, or a question nobody submitted.
    Wait,
}

/// Decide whether a rebuild in Natural-language mode may spend model budget.
///
/// Every query-string write rebuilds the Audit Explorer, so this is reached by a
/// time-range chip, a tab click and Back/Forward as well as by a submission —
/// and unlike Simple and Advanced, running here bills an LLM call. Two things
/// gate it, and nothing else may:
///
///   - `asked` — the URL's `ask=1`, written only by the Ask button or Enter. A
///     tab click publishes the same text without it, so trying the tab cannot
///     send the leftover contents of the Simple box to the model.
///   - `cached_question` — the question the answer on hand already answers.
///     `/api/ask` takes no time range (the assistant plans its own window from
///     the question), so a range change cannot change that answer: restore it
///     rather than buy it twice. An explicit Ask clears the cache first, so
///     re-asking the same question on purpose still reaches the model.
///
/// The bias is deliberate: when the analyst's intent is unclear, wait. An
/// unwanted wait costs a click, an unwanted ask costs money.
fn nl_action(question: &str, asked: bool, cached_question: Option<&str>) -> NlAction {
    if question.is_empty() {
        NlAction::Wait
    } else if cached_question == Some(question) {
        NlAction::Restore
    } else if asked {
        NlAction::Ask
    } else {
        NlAction::Wait
    }
}

/// Plain-language explanation of how the current search ran, surfaced behind an
/// InfoPopover so the analyst never has to know the retrieval internals. Covers
/// which modes ran, whether meaning-based search was available, whether the
/// result set was truncated, and that the query is reproducible from the link.
fn search_explanation(
    mode: String,
    semantic_ok: bool,
    capped_at: Option<usize>,
    range: TimeRange,
) -> String {
    // Live sends no bound at all, so a sentence naming "the selected time
    // range" would claim a filter that was not applied — the failure this
    // console refuses elsewhere too (see [`crate::timerange::governs`]).
    let ran = match (mode.as_str(), range) {
        ("advanced", TimeRange::Live) => "This was a structured search: your exact filters (host, \
             service, severity) combined with full-text keyword matching and, where available, \
             meaning-based (semantic) matching — each result is tagged with which of those signals \
             matched it. The time range is set to Live, so no window bounded any of them."
            .to_string(),
        ("advanced", _) => "This was a structured search: your exact filters (host, service, \
             severity) combined with full-text keyword matching and, where available, \
             meaning-based (semantic) matching — each result is tagged with which of those signals \
             matched it. The selected time range bounds all three, so nothing outside it is \
             returned."
            .to_string(),
        (_, TimeRange::Live) => "This was a plain full-text keyword search over every audit event \
             in the history: the time range is set to Live, so no window bounded the search. (With \
             the box empty, Live shows the most recent events as a feed, which the server draws \
             from the last hour.)"
            .to_string(),
        _ => "This was a plain full-text keyword search over the audit events in the selected \
             time range, or the range's feed when the search box is empty."
            .to_string(),
    };
    let sem = if semantic_ok {
        "Meaning-based search is available on this deployment, so results can match on intent as well \
         as the exact words used."
    } else {
        "Meaning-based search is not available here, so matching relied on keywords and filters only."
    };
    let cap = match capped_at {
        Some(n) => format!(
            "Results were capped at {n} events; narrow the query to be sure you are seeing \
             everything that matches."
        ),
        None => "Every matching event is shown.".to_string(),
    };
    format!(
        "{ran} {sem} {cap} A submitted search is written into this page's link — the mode, the search \
         text, any filters and the time range — so reopening or sharing the URL runs the same search \
         over the same window."
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::route::param_of;
    use crate::TimeRange;

    /// The bug this exists to prevent: a search that is only in a view-local
    /// signal is erased the moment anything else writes the query string. If the
    /// submitted text is not in the URL, clicking a time-range chip clears the box
    /// and quietly falls back to the plain time-range feed.
    #[test]
    fn a_submitted_search_is_carried_by_the_url() {
        let q = search_query("text", "pvefw", "", "", "", "t=live", true);
        assert_eq!(param_of(&q, "q"), Some("pvefw".into()));
        assert_eq!(param_of(&q, "mode"), Some("text".into()));
    }

    /// Publishing the search must not widen the window the analyst chose — the
    /// range travels with it, unchanged.
    #[test]
    fn publishing_a_search_keeps_the_chosen_time_range() {
        let q = search_query("text", "pvefw", "", "", "", "mode=text&t=24h", true);
        assert_eq!(crate::timerange::read_param(&q), Some(TimeRange::Last(24)));
        assert_eq!(q.matches("t=").count(), 1, "duplicate range params in {q}");

        let abs = TimeRange::Absolute(1_754_179_200_000, 1_754_265_600_000);
        let q = search_query(
            "text",
            "pvefw",
            "",
            "",
            "",
            &format!("t={}", abs.to_slug()),
            true,
        );
        assert_eq!(crate::timerange::read_param(&q), Some(abs));
    }

    /// No range in the URL yet (the picker is still on its default) is not a
    /// reason to invent one.
    #[test]
    fn no_range_in_the_url_stays_no_range() {
        let q = search_query("text", "pvefw", "", "", "", "", true);
        assert_eq!(param_of(&q, "t"), None);
    }

    // ---- Natural language must not spend budget unbidden --------------------

    /// Pressing Ask is the only thing that marks the URL as asked — and only in
    /// the mode that bills for it.
    #[test]
    fn only_a_submitted_nl_search_is_marked_as_asked() {
        let asked = search_query("nl", "who read person data?", "", "", "", "", true);
        assert_eq!(param_of(&asked, "ask"), Some("1".into()));
        // Switching to the tab publishes the same text WITHOUT the marker, so
        // the leftover contents of the Simple box are never sent to the model.
        let tab = search_query("nl", "who read person data?", "", "", "", "", false);
        assert_eq!(param_of(&tab, "ask"), None);
        // The other modes cost a query, not budget — no marker to carry.
        for mode in ["text", "advanced"] {
            let q = search_query(mode, "pvefw", "", "", "", "", true);
            assert_eq!(param_of(&q, "ask"), None, "{mode} should not carry ask=");
        }
    }

    /// A range chip rewrites the query string; the asked marker has to survive
    /// it, or Back/Forward through an asked link would land on a dead page.
    #[test]
    fn a_range_change_keeps_the_asked_marker() {
        let asked = search_query("nl", "who read person data?", "", "", "", "", true);
        let after = crate::timerange::write_param(&asked, TimeRange::Last(24));
        assert_eq!(param_of(&after, "ask"), Some("1".into()));
        assert_eq!(
            crate::timerange::read_param(&after),
            Some(TimeRange::Last(24))
        );
    }

    /// The gate itself. Only an explicit ask reaches the model, and only when no
    /// answer to that exact question is already on hand.
    #[test]
    fn nl_only_asks_when_a_human_asked_and_nothing_is_cached() {
        // A human pressed Ask and we hold nothing for this question.
        assert_eq!(nl_action("brute force?", true, None), NlAction::Ask);
        // …or hold an answer to a DIFFERENT question.
        assert_eq!(
            nl_action("brute force?", true, Some("who read person data?")),
            NlAction::Ask
        );
        // The answer on hand already answers it: show it, don't buy it twice.
        // This is the range-chip path — `/api/ask` takes no range, so the answer
        // cannot have changed.
        assert_eq!(
            nl_action("brute force?", true, Some("brute force?")),
            NlAction::Restore
        );
        assert_eq!(
            nl_action("brute force?", false, Some("brute force?")),
            NlAction::Restore
        );
        // Nobody asked: a tab click, or a hand-written link without `ask=1`.
        assert_eq!(nl_action("brute force?", false, None), NlAction::Wait);
        // Nothing to ask about.
        assert_eq!(nl_action("", true, None), NlAction::Wait);
        assert_eq!(nl_action("", false, Some("brute force?")), NlAction::Wait);
    }

    /// An empty box means "the time-range feed", and the URL has to say that by
    /// carrying no query at all — otherwise reopening the link would search for
    /// the empty string.
    #[test]
    fn an_empty_search_publishes_no_query() {
        for text in ["", "   "] {
            let q = search_query("text", text, "", "", "", "t=24h", true);
            assert_eq!(param_of(&q, "q"), None, "{text:?} should publish no q=");
            assert_eq!(param_of(&q, "mode"), Some("text".into()));
        }
    }

    /// Advanced's structured filters survive the same re-render as the text, and
    /// only in the mode that actually applies them — a URL must never advertise a
    /// filter its search does not use.
    #[test]
    fn advanced_filters_ride_along_only_in_advanced_mode() {
        let q = search_query(
            "advanced",
            "ssh",
            "pve, node2",
            "sshd",
            "high",
            "t=24h",
            true,
        );
        assert_eq!(param_of(&q, "host"), Some("pve, node2".into()));
        assert_eq!(param_of(&q, "service"), Some("sshd".into()));
        assert_eq!(param_of(&q, "severity"), Some("high".into()));

        let q = search_query("text", "ssh", "pve", "sshd", "high", "t=24h", true);
        assert_eq!(param_of(&q, "host"), None);
        assert_eq!(param_of(&q, "service"), None);
        assert_eq!(param_of(&q, "severity"), None);
    }

    /// Search text is arbitrary operator input: it must round-trip through the
    /// URL exactly, or a reopened link runs a different search than the one that
    /// was shared.
    #[test]
    fn awkward_search_text_survives_the_url() {
        for raw in [
            "user=root & host=pve",
            "a/b?c#d",
            "kunai OR pvefw",
            "unicode-ÅÄÖ",
            "percent%20already",
            "plus+sign",
        ] {
            let q = search_query("text", raw, "", "", "", "t=24h", true);
            assert_eq!(
                param_of(&q, "q").as_deref(),
                Some(raw),
                "{raw} did not round-trip"
            );
            // …and it cannot smuggle in or clobber another parameter.
            assert_eq!(crate::timerange::read_param(&q), Some(TimeRange::Last(24)));
            assert_eq!(param_of(&q, "mode"), Some("text".into()));
        }
    }

    /// Re-submitting the same search produces the same URL — that identity is
    /// what lets the router replace the history entry instead of stacking a new
    /// one per Enter press.
    #[test]
    fn the_same_search_produces_the_same_url() {
        let a = search_query("advanced", "ssh", "pve", "", "high", "t=24h", true);
        let b = search_query("advanced", " ssh ", " pve ", "", " high ", "t=24h", true);
        assert_eq!(a, b);
    }

    // The popover speaks about the search that just ran, so it must not assert a
    // window that was not applied — the console's standing rule about the range
    // control (see timerange::governs).
    #[test]
    fn the_explanation_claims_a_window_only_when_one_applied() {
        let bounded = search_explanation("text".into(), false, None, TimeRange::Last(24));
        assert!(bounded.contains("selected"), "{bounded}");
        assert!(!bounded.contains("no window bounded"), "{bounded}");

        // Live sends no bound at all, in either mode: the search really does
        // cover everything, and saying otherwise claims an unapplied filter.
        for mode in ["text", "advanced"] {
            let live = search_explanation(mode.into(), false, None, TimeRange::Live);
            assert!(!live.contains("selected time range"), "{mode}: {live}");
            assert!(live.contains("no window bounded"), "{mode}: {live}");
        }
        // …but the empty-box feed under Live IS server-bounded, so the Simple
        // sentence has to own that rather than imply nothing was applied.
        let live_text = search_explanation("text".into(), false, None, TimeRange::Live);
        assert!(live_text.contains("last hour"), "{live_text}");
    }

    #[test]
    fn each_mode_reports_the_cap_that_actually_applies() {
        // Advanced is clamped by the hybrid planner (garmr_query MAX_LIMIT), so
        // reporting the feed's 300 would promise 100 events that can never
        // arrive — and `n >= 300` could never fire, leaving the popover
        // claiming completeness over a set the server had already truncated.
        assert_eq!(row_limit("advanced"), ADVANCED_LIMIT);
        assert_eq!(row_limit("text"), TEXT_LIMIT);
        assert_eq!(row_limit("nl"), TEXT_LIMIT);

        let full = search_explanation("text".into(), false, None, TimeRange::Live);
        assert!(full.contains("Every matching event is shown"), "{full}");

        let adv = search_explanation(
            "advanced".into(),
            false,
            Some(ADVANCED_LIMIT),
            TimeRange::Last(24),
        );
        assert!(adv.contains("capped at 200"), "{adv}");
        assert!(!adv.contains("capped at 300"), "{adv}");
        assert!(!adv.contains("Every matching event is shown"), "{adv}");

        let txt = search_explanation("text".into(), false, Some(TEXT_LIMIT), TimeRange::Last(24));
        assert!(txt.contains("capped at 300"), "{txt}");
    }
}
