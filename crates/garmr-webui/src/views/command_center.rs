// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! Command Center — what needs attention now. Not a wall of cards: a single
//! prioritised feed (critical cases, high-risk subjects, source failures, audit
//! integrity, degraded capabilities), each item linking to where you act, above
//! a compact health strip.

use leptos::prelude::*;
use serde_json::Value;

use crate::route::{Area, View};
use crate::{api, ui, Store};

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
        if let Some(a) = audit.data.get() {
            let ok = a.get("ok").and_then(Value::as_bool).unwrap_or(true);
            let enabled = a.get("enabled").and_then(Value::as_bool).unwrap_or(false);
            if enabled && !ok {
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
        let audit_ok = audit
            .data
            .get()
            .as_ref()
            .and_then(|a| a.get("ok").and_then(Value::as_bool))
            .unwrap_or(true);
        (open, needs, over, stale, audit_ok)
    };

    view! {
        <div class="page">
            <div class="page-header row">
                <div class="grow">
                    <h1>"Command Center"</h1>
                    <div class="sub">{Area::CommandCenter.blurb()}</div>
                </div>
                <button class="btn ghost" on:click=move |_| reload()>"↻ Refresh"</button>
            </div>

            <div class="tiles">
                {move || {
                    let (open, needs, over, stale, audit_ok) = health();
                    view! {
                        {ui::metric("open investigations", open.to_string(), if needs > 0 { "warn" } else { "pass" }, {
                            Some(Box::new(move || store.nav.go(View::Investigations)) as Box<dyn Fn()>)
                        })}
                        {ui::metric("needs human", needs.to_string(), if needs > 0 { "bad" } else { "pass" },
                            Some(Box::new(move || store.nav.go(View::Investigations)) as Box<dyn Fn()>))}
                        {ui::metric("risk over budget", over.to_string(), if over > 0 { "bad" } else { "pass" },
                            Some(Box::new(move || store.nav.go(Area::Users.home())) as Box<dyn Fn()>))}
                        {ui::metric("stale sources", stale.to_string(), if stale > 0 { "warn" } else { "pass" },
                            Some(Box::new(move || store.nav.go(Area::DataSources.home())) as Box<dyn Fn()>))}
                        {ui::metric("audit integrity", if audit_ok { "verified".into() } else { "FAILED".to_string() },
                            if audit_ok { "pass" } else { "bad" },
                            Some(Box::new(move || store.nav.go(Area::System.home())) as Box<dyn Fn()>))}
                    }
                }}
            </div>

            <section class="sect">
                <h3>"Needs attention"</h3>
                {move || {
                    let items = feed();
                    if items.is_empty() {
                        // Distinguish "loading" from a genuinely quiet board.
                        if cases.loading.get() {
                            return ui::loading("assessing the board…");
                        }
                        return view! {
                            <div class="state empty allclear">
                                <span class="state-glyph">"✓"</span>
                                <span>"All clear — no investigations need a human, no subject is over budget, all sources are fresh."</span>
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