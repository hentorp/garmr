// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! Ask — natural-language answers ("ask, don't SPL"). The daemon's model plans
//! a read-only query, runs it, and answers grounded in the rows with `[n]`
//! citations. No longer a standalone route: the investigate hub calls `/api/ask`
//! and renders the result with [`answer_card`], the reusable card kept here.

use leptos::prelude::*;
use serde_json::Value;

use crate::api;

pub(crate) fn answer_card(a: &Value) -> impl IntoView {
    let rows = a
        .get("rows")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let plan = a
        .get("query")
        .filter(|v| !v.is_null())
        .map(|p| p.to_string());
    let sem_unavailable =
        a.get("semantic_status").and_then(Value::as_str) == Some("requested_but_unavailable");
    let truncated = a.get("truncated").and_then(Value::as_bool).unwrap_or(false);
    let cost = a.get("cost_usd").and_then(Value::as_f64);
    let query_id = a.get("query_id").and_then(Value::as_str).map(String::from);

    view! {
        <div class="card">
            <h2>{api::clean(&api::s(a, "question"))}</h2>
            <p class="answer">{api::clean(&api::s(a, "answer"))}</p>
            {plan.map(|p| view! { <pre class="plan mono">{api::clean(&p)}</pre> })}
            {query_id.map(|qid| {
                // Reproduce the retrieval DETERMINISTICALLY — replays the stored
                // plan through /api/reproduce with no model call.
                let out = RwSignal::new(Option::<Result<Value, api::ApiError>>::None);
                let busy = RwSignal::new(false);
                let run = move |_| {
                    let url = format!("/api/reproduce?query_id={}", api::enc(&qid));
                    busy.set(true);
                    out.set(None);
                    leptos::task::spawn_local(async move {
                        let r = api::send_get(&url).await;
                        busy.set(false);
                        out.set(Some(r));
                    });
                };
                view! {
                    <div class="row">
                        <button class="btn ghost sm" on:click=run prop:disabled=move || busy.get()>
                            {move || if busy.get() { "Reproducing…".to_string() } else { "↻ Reproduce (no LLM)".to_string() }}
                        </button>
                        {move || out.get().map(|r| match r {
                            Err(e) => view! { <span class="bad">{e.to_string()}</span> }.into_any(),
                            Ok(v) => {
                                let n = v.get("rows").and_then(Value::as_array).map(|a| a.len()).unwrap_or(0);
                                view! { <span class="dimtext">{format!("reproduced deterministically — {n} rows, no model call")}</span> }.into_any()
                            }
                        })}
                    </div>
                }
            })}
            {sem_unavailable.then(|| view! {
                <div class="dimtext">"semantic requested but unavailable — structured + full-text only"</div>
            })}
            <h3>{format!("Rows ({})", rows.len())}</h3>
            <div class="rows">
                {rows.into_iter().enumerate().map(|(i, r)| view! {
                    <div class="tline">
                        <span class="mono dimtext">{format!("[{i}]")}</span>
                        <span class="mono">{api::clean(&r.to_string())}</span>
                    </div>
                }).collect_view()}
            </div>
            {truncated.then(|| view! { <div class="dimtext">"[… truncated]"</div> })}
            {cost.map(|c| view! { <div class="dimtext">{format!("cost: ${c:.4}")}</div> })}
        </div>
    }
}