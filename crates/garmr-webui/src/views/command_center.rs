// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! Command Center — what needs attention now. Not a wall of cards: a single
//! prioritised feed (critical cases, high-risk subjects, source failures, audit
//! integrity, degraded capabilities), each item linking to where you act, above
//! a compact health strip.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use leptos::prelude::*;
use serde_json::Value;

use crate::route::{Area, View};
use crate::srcstate::{self, AuditIntegrity, SourceState};
use crate::{api, ui, Store};

/// How often the board refetches while it is visible. One constant, one place —
/// a monitoring console's poll rate should be obvious and trivial to change.
const REFRESH_SECS: u32 = 30;

/// Data older than this stops counting as current and the board says "stale"
/// instead of presenting it as the situation right now. Deliberately a little
/// over twice [`REFRESH_SECS`], so one missed poll is tolerated but a source
/// that has genuinely stopped answering is called out.
const FRESHNESS_BUDGET_SECS: u64 = 90;

/// Local wall-clock `HH:MM:SS` for an epoch-millis instant — the "last updated"
/// stamp. Uses the browser's `Date`, so the wasm bundle needs no date crate.
fn clock(ms: f64) -> String {
    let d = js_sys::Date::new(&wasm_bindgen::JsValue::from_f64(ms));
    format!(
        "{:02}:{:02}:{:02}",
        d.get_hours(),
        d.get_minutes(),
        d.get_seconds()
    )
}

/// Schedule the next automatic refresh, then reschedule itself.
///
/// A self-rescheduling timeout rather than an `Interval` for two reasons: the
/// chain simply stops when `alive` goes false (no handle to keep `Send`-alive
/// across `on_cleanup`), and a poll is never queued behind one that is still in
/// flight. The tab-visibility check is what pauses polling in a background tab —
/// a hidden console must not keep querying the SOC API.
fn schedule_poll<F: Fn() + Clone + 'static>(
    alive: Arc<AtomicBool>,
    tick: RwSignal<u32>,
    reload: F,
) {
    gloo_timers::callback::Timeout::new(REFRESH_SECS * 1000, move || {
        // A plain atomic, NOT a signal: when the view unmounts its signals are
        // disposed, and reading a disposed signal panics the wasm module. The
        // liveness flag has to outlive the reactive graph, and it must be checked
        // before anything reactive is touched.
        if !alive.load(Ordering::Relaxed) {
            return; // unmounted: stop the chain, touch nothing reactive
        }
        let hidden = web_sys::window()
            .and_then(|w| w.document())
            .map(|d| d.hidden())
            .unwrap_or(false);
        if !hidden {
            reload();
            tick.update(|t| *t += 1);
        }
        schedule_poll(alive.clone(), tick, reload.clone());
    })
    .forget();
}

/// One attention item: a ranked, actionable signal.
struct Attn {
    rank: u8, // 0 = highest
    sev: &'static str,
    kind: String,
    title: String,
    why: String,
    go: View,
}

pub fn view(store: Store) -> impl IntoView {
    let cases = super::Fetch::new();
    let risk = super::Fetch::new();
    let ingest = super::Fetch::new();
    let audit = super::Fetch::new();
    let reload = move || {
        cases.load("/api/cases".into());
        risk.load("/api/risk".into());
        ingest.load("/api/ingest/health".into());
        audit.load("/api/audit/status".into());
    };
    reload();

    // Every source that must answer before the board may draw a conclusion, in
    // the order they are reported to the operator.
    let sources = move || {
        [
            ("cases", cases.state(FRESHNESS_BUDGET_SECS)),
            ("risk", risk.state(FRESHNESS_BUDGET_SECS)),
            ("ingest health", ingest.state(FRESHNESS_BUDGET_SECS)),
            ("audit integrity", audit.state(FRESHNESS_BUDGET_SECS)),
        ]
    };

    // Any request in flight — drives the visible progress on manual Refresh.
    let busy = move || {
        cases.loading.get() || risk.loading.get() || ingest.loading.get() || audit.loading.get()
    };

    // A tick that advances on every automatic refresh, so time-derived reads
    // ("last updated", the staleness budget) re-render without each of them
    // having to own a timer.
    let tick = RwSignal::new(0u32);

    // Controlled automatic refresh, stopped when the view unmounts — otherwise
    // navigating away leaves a timer hammering the SOC API for the rest of the
    // session. `Fetch::load` already carries a generation guard, so overlapping
    // polls resolve to the newest and a slow response can never overwrite a
    // newer one.
    let alive = Arc::new(AtomicBool::new(true));
    let unmounted = alive.clone();
    on_cleanup(move || unmounted.store(false, Ordering::Relaxed));
    schedule_poll(alive, tick, reload);

    // Recompute the ranked feed whenever any source updates.
    let feed = move || {
        let mut items: Vec<Attn> = Vec::new();

        // Cases needing a human / escalated.
        for c in cases.rows("cases") {
            let state = api::s(&c, "state");
            let id = api::s(&c, "id");
            let trig = c.get("trigger").cloned().unwrap_or(Value::Null);
            let rule = api::s(&trig, "rule_title");
            let rule = if rule.is_empty() {
                api::s(&trig, "rule_id")
            } else {
                rule
            };
            let level = api::s(&trig, "level");
            match state.as_str() {
                "needs_human" => items.push(Attn {
                    rank: 0,
                    sev: "bad",
                    kind: "Investigation · needs human".into(),
                    title: rule,
                    why: format!("triage could not decide ({level}) — awaiting an analyst"),
                    go: View::Investigation(id),
                }),
                "escalated" => items.push(Attn {
                    rank: 0,
                    sev: "bad",
                    kind: "Investigation · escalated".into(),
                    title: rule,
                    why: format!("escalated ({level})"),
                    go: View::Investigation(id),
                }),
                _ => {}
            }
        }

        // Risk subjects over budget.
        for r in risk.rows("risk") {
            if r.get("over_threshold")
                .and_then(Value::as_bool)
                .unwrap_or(false)
            {
                let host = api::s(&r, "host");
                let kind = api::s(&r, "kind");
                let score = r.get("score").and_then(Value::as_f64).unwrap_or(0.0);
                let go = if kind == "staff" || kind == "user" {
                    View::User(host.clone())
                } else {
                    View::Application(host.clone())
                };
                items.push(Attn {
                    rank: 1,
                    sev: "bad",
                    kind: format!("Risk · {}", if kind.is_empty() { "host" } else { &kind }),
                    title: host,
                    why: format!("risk score {score:.0} over the alerting budget"),
                    go,
                });
            }
        }

        // Silent / stale sources.
        for s in ingest.rows("sources") {
            let stale = api::num(&s, "staleness_secs");
            if stale > 3600 {
                items.push(Attn {
                    rank: 2,
                    sev: "warn",
                    kind: "Source · stale".into(),
                    title: api::s(&s, "source"),
                    why: format!("no ingest for {}m — possible silent loss", stale / 60),
                    go: Area::DataSources.home(),
                });
            }
        }

        // Audit integrity.
        {
            let st = audit.state(FRESHNESS_BUDGET_SECS);
            let d = audit.data.get();
            let enabled = d
                .as_ref()
                .and_then(|a| a.get("enabled").and_then(Value::as_bool));
            let ok = d
                .as_ref()
                .and_then(|a| a.get("ok").and_then(Value::as_bool));
            // Only a real, fresh verification failure becomes an attention row.
            // "We could not check" is not silence — it surfaces in the degraded
            // banner instead, so the two are never conflated.
            if srcstate::audit_integrity(st, enabled, ok) == AuditIntegrity::Failed {
                items.push(Attn {
                    rank: 0,
                    sev: "bad",
                    kind: "Audit · integrity".into(),
                    title: "Audit ledger verification failed".into(),
                    why: "the tamper-evident ledger did not verify".into(),
                    go: Area::System.home(),
                });
            }
        }

        // Degraded / disabled capabilities worth surfacing.
        if let Some(c) = store.caps.get() {
            for (key, label) in [
                ("app_audit", "Application audit"),
                ("environment_model", "Environment model"),
                ("nl_ask", "AI assistant"),
            ] {
                let fs = c.feature(key);
                if fs.state == "disabled" {
                    items.push(Attn {
                        rank: 3,
                        sev: "dim",
                        kind: "Capability · off".into(),
                        title: label.into(),
                        why: fs.reason.clone().unwrap_or_default(),
                        go: Area::System.home(),
                    });
                }
            }
        }

        items.sort_by_key(|a| a.rank);
        items
    };

    // Health strip metrics.
    let health = move || {
        let cs = cases.rows("cases");
        let open = cs
            .iter()
            .filter(|c| {
                let s = api::s(c, "state");
                s != "closed" && s != "triaged"
            })
            .count();
        let needs = cs
            .iter()
            .filter(|c| api::s(c, "state") == "needs_human")
            .count();
        let over = risk
            .rows("risk")
            .iter()
            .filter(|r| {
                r.get("over_threshold")
                    .and_then(Value::as_bool)
                    .unwrap_or(false)
            })
            .count();
        let stale = ingest
            .rows("sources")
            .iter()
            .filter(|s| api::num(s, "staleness_secs") > 3600)
            .count();
        (open, needs, over, stale)
    };

    // Audit integrity as an honest three-valued answer. The old board did
    // `…get("ok").unwrap_or(true)`, so an absent or failed response rendered as
    // a green "verified" — the single most dangerous thing this console could
    // say. Now anything short of a fresh response that explicitly says `ok` is
    // reported as Unknown.
    let audit_state = move || {
        let st = audit.state(FRESHNESS_BUDGET_SECS);
        let d = audit.data.get();
        let enabled = d
            .as_ref()
            .and_then(|a| a.get("enabled").and_then(Value::as_bool));
        let ok = d
            .as_ref()
            .and_then(|a| a.get("ok").and_then(Value::as_bool));
        srcstate::audit_integrity(st, enabled, ok)
    };

    view! {
        <div class="page">
            <div class="page-header row">
                <div class="grow">
                    <h1>"Command Center"</h1>
                    <div class="sub">{Area::CommandCenter.blurb()}</div>
                </div>
                <div class="dimtext" style="font-size:12px; text-align:right;">
                    {move || {
                        // Reading `tick` keeps this label live between fetches.
                        tick.get();
                        let newest = [cases, risk, ingest, audit]
                            .iter()
                            .filter_map(|f| f.fetched_at.get())
                            .fold(None::<f64>, |acc, t| Some(acc.map_or(t, |a: f64| a.max(t))));
                        match newest {
                            Some(t) => format!("Last updated {}", clock(t)),
                            None => "Not yet updated".to_string(),
                        }
                    }}
                    <div>{format!("Auto-refresh every {REFRESH_SECS}s while visible")}</div>
                </div>
                <button class="btn ghost" on:click=move |_| reload()
                    aria-label="Refresh the board now">
                    {move || if busy() { "⟳ Refreshing…" } else { "↻ Refresh" }}
                </button>
            </div>

            // Partial failures must be prominent, not a silent gap in a tile.
            {move || {
                let d = srcstate::degraded(&sources());
                if d.is_empty() {
                    return ().into_any();
                }
                let n = d.len();
                view! {
                    <div class="banner warn" role="status">
                        <strong>{format!("Degraded data — {n} of 4 sources are not current. \
                            Metrics below are incomplete and must not be read as all-clear.")}</strong>
                        <ul style="margin:6px 0 0; padding-left:18px;">
                            {d.into_iter().map(|(name, st)| view! {
                                <li>
                                    <strong>{name}</strong>": "{st.label()}
                                    " — "{st.recovery()}
                                </li>
                            }).collect_view()}
                        </ul>
                    </div>
                }.into_any()
            }}

            <div class="tiles">
                {move || {
                    let (open, needs, over, stale) = health();
                    let cs = cases.state(FRESHNESS_BUDGET_SECS);
                    let rs = risk.state(FRESHNESS_BUDGET_SECS);
                    let is = ingest.state(FRESHNESS_BUDGET_SECS);
                    let ai = audit_state();
                    // Each tile is bound to the state of the source that produced
                    // it: a source that is not fresh renders "Unknown" in a
                    // neutral tone, never a `0` in green. An operator must not be
                    // able to read reassurance out of a request that failed.
                    view! {
                        {ui::metric("open investigations",
                            srcstate::metric_value(cs, open as i64).text(),
                            srcstate::metric_tone(cs, needs as i64, "warn"), {
                            Some(Box::new(move || store.nav.go(View::Investigations)) as Box<dyn Fn()>)
                        })}
                        {ui::metric("needs human",
                            srcstate::metric_value(cs, needs as i64).text(),
                            srcstate::metric_tone(cs, needs as i64, "bad"),
                            Some(Box::new(move || store.nav.go(View::Investigations)) as Box<dyn Fn()>))}
                        {ui::metric("risk over budget",
                            srcstate::metric_value(rs, over as i64).text(),
                            srcstate::metric_tone(rs, over as i64, "bad"),
                            Some(Box::new(move || store.nav.go(Area::Users.home())) as Box<dyn Fn()>))}
                        {ui::metric("stale sources",
                            srcstate::metric_value(is, stale as i64).text(),
                            srcstate::metric_tone(is, stale as i64, "warn"),
                            Some(Box::new(move || store.nav.go(Area::DataSources.home())) as Box<dyn Fn()>))}
                        {ui::metric("audit integrity", ai.text(), ai.tone(),
                            Some(Box::new(move || store.nav.go(Area::System.home())) as Box<dyn Fn()>))}
                    }
                }}
            </div>

            <section class="sect">
                <h3>"Needs attention"
                    <ui::InfoPopover heading="How to read this board"
                        body="The tiles above are live counts: investigations that are open, ones waiting on an analyst, users or hosts whose accumulated risk crossed the review threshold, sources that have gone silent, and whether the tamper-evident audit ledger still verifies. This list ranks everything that currently needs a person — the most urgent first — and each row links straight to where you act on it. When it shows all clear, nothing is waiting on you."/>
                </h3>
                {move || {
                    let items = feed();
                    if items.is_empty() {
                        let states: Vec<SourceState> =
                            sources().iter().map(|(_, s)| *s).collect();

                        // "All clear" is a positive claim about the whole estate,
                        // so it requires every source to have answered and be
                        // current. An empty feed on its own proves nothing — it
                        // is exactly what four failed requests also produce.
                        if srcstate::all_clear_permitted(&states, true) {
                            return view! {
                                <div class="state empty allclear">
                                    <span class="state-glyph">"✓"</span>
                                    <span>"All clear — no investigations need a human, no subject is over budget, all sources are fresh."</span>
                                </div>
                            }.into_any();
                        }
                        if srcstate::any_loading(&states) {
                            return ui::loading("assessing the board…");
                        }
                        // Sources answered but not all of them usefully: say so
                        // plainly instead of implying quiet.
                        return view! {
                            <div class="state error" role="status">
                                <span class="state-glyph">"⚠"</span>
                                <span>"Nothing to show, but the board is incomplete — \
                                    see the degraded-data notice above. This is NOT an all-clear."</span>
                            </div>
                        }.into_any();
                    }
                    view! {
                        <div class="attn-list">
                            {items.into_iter().map(|a| {
                                let go = a.go.clone();
                                view! {
                                    <button class="attn" on:click=move |_| store.nav.go(go.clone())>
                                        <span class=format!("attn-bar {}", a.sev)></span>
                                        <span class=format!("pill {}", a.sev)>{a.kind}</span>
                                        <span class="attn-title grow">{api::clean(&a.title)}</span>
                                        <span class="attn-why dimtext">{api::clean(&a.why)}</span>
                                        <span class="attn-go" aria-hidden="true">"→"</span>
                                    </button>
                                }
                            }).collect_view()}
                        </div>
                    }.into_any()
                }}
            </section>
        </div>
    }
}
