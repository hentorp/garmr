// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! The global command palette (Ctrl/Cmd-K): navigate to any area, jump to a case
//! / user / application / policy, or launch a search — over real backend
//! entities, respecting capability availability. A keyboard-first pivot surface.

use leptos::prelude::*;
use serde_json::Value;

use crate::route::{Area, View};
use crate::views::Fetch;
use crate::{api, Store};

/// One palette result.
struct Cmd {
    label: String,
    hint: String,
    go: View,
}

#[component]
pub fn CommandPalette() -> impl IntoView {
    let store = expect_context::<Store>();
    let q = RwSignal::new(String::new());
    let cases = Fetch::new();

    // Load the (small) case list when the palette opens, for id/rule matching.
    Effect::new(move |_| {
        if store.cmd_open.get() {
            cases.load("/api/cases".into());
            q.set(String::new());
        }
    });

    let results = move || {
        let query = q.get();
        let ql = query.trim().to_lowercase();
        let mut out: Vec<Cmd> = Vec::new();

        // Areas matching the query.
        for a in Area::ALL {
            if ql.is_empty() || a.label().to_lowercase().contains(&ql) {
                out.push(Cmd {
                    label: a.label().to_string(),
                    hint: a.blurb().to_string(),
                    go: a.home(),
                });
            }
        }

        if !ql.is_empty() {
            // Search audit for the text.
            out.insert(
                0,
                Cmd {
                    label: format!("Search audit for “{query}”"),
                    hint: "full-text over every audit event".into(),
                    go: View::Audit,
                },
            );
            // Matching cases (by short id or rule/host).
            for c in cases.rows("cases") {
                let id = api::s(&c, "id");
                let trig = c.get("trigger").cloned().unwrap_or(Value::Null);
                let rule = api::s(&trig, "rule_id");
                let host = trig
                    .get("event")
                    .map(|e| api::s(e, "host"))
                    .unwrap_or_default();
                let hay = format!("{id} {rule} {host}").to_lowercase();
                if hay.contains(&ql) {
                    out.push(Cmd {
                        label: format!("Investigation: {rule}"),
                        hint: format!("{host} · {}", &id[..id.len().min(8)]),
                        go: View::Investigation(id),
                    });
                }
                if out.len() > 24 {
                    break;
                }
            }
            // Direct entity jumps.
            out.push(Cmd {
                label: format!("Open user “{query}”"),
                hint: "user / staff / person page".into(),
                go: View::User(query.trim().to_string()),
            });
            out.push(Cmd {
                label: format!("Open host “{query}”"),
                hint: "application / host page".into(),
                go: View::Application(query.trim().to_string()),
            });
        }
        out
    };

    let run_first = move || {
        if let Some(c) = results().into_iter().next() {
            let is_search = c.label.starts_with("Search audit");
            store.cmd_open.set(false);
            if is_search {
                store.nav.go_query(
                    View::Audit,
                    format!("mode=text&q={}", api::enc(q.get_untracked().trim())),
                );
            } else {
                store.nav.go(c.go);
            }
        }
    };

    view! {
        {move || store.cmd_open.get().then(|| {
            view! {
                <div class="cmd-scrim" on:click=move |_| store.cmd_open.set(false)>
                    <div class="cmd-modal" on:click=move |ev| ev.stop_propagation()>
                        <input class="cmd-input" type="text" autofocus=true
                            placeholder="Type to search investigations, users, apps, events — or a page name"
                            prop:value=move || q.get()
                            on:input=move |ev| q.set(event_target_value(&ev))
                            on:keydown=move |ev| if ev.key() == "Enter" { run_first() }/>
                        <div class="cmd-results">
                            {move || {
                                let rs = results();
                                if rs.is_empty() {
                                    return view! { <div class="cmd-empty">"no matches"</div> }.into_any();
                                }
                                rs.into_iter().map(|c| {
                                    let go = c.go.clone();
                                    let is_search = c.label.starts_with("Search audit");
                                    let qv = q.get_untracked();
                                    view! {
                                        <button class="cmd-item" on:click=move |_| {
                                            store.cmd_open.set(false);
                                            if is_search {
                                                store.nav.go_query(View::Audit, format!("mode=text&q={}", api::enc(qv.trim())));
                                            } else {
                                                store.nav.go(go.clone());
                                            }
                                        }>
                                            <span class="cmd-label">{c.label}</span>
                                            <span class="cmd-hint dimtext">{c.hint}</span>
                                        </button>
                                    }
                                }).collect_view().into_any()
                            }}
                        </div>
                        <div class="cmd-foot dimtext">"Enter to run · Esc to close"</div>
                    </div>
                </div>
            }
        })}
    }
}