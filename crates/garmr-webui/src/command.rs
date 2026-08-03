// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! The global command palette (Ctrl/Cmd-K): a keyboard-first pivot to any area,
//! investigation, user, application, resource or policy — over REAL backend rows.
//!
//! It used to append two fabricated results to every search: `Open user "<text>"`
//! and `Open host "<text>"`, built from whatever had been typed. Typing `asdf`
//! produced a confident-looking user and host that navigated to pages for
//! entities that do not exist. See [`crate::palette`] for the rule that replaced
//! it: an entity result may only exist because a backend row produced it, and
//! free text may only produce an explicitly-labelled *search action*.

use leptos::prelude::*;
use serde_json::Value;
use wasm_bindgen::JsCast;

use crate::palette::{self, ResultKind, SourceStatus};
use crate::route::{Area, View};
use crate::views::Fetch;
use crate::{api, Store};

/// One palette result. `query` carries a sub-tab (or other) query string so a
/// destination behind a tab is directly reachable from the palette.
#[derive(Clone)]
struct Cmd {
    kind: ResultKind,
    label: String,
    hint: String,
    go: View,
    query: String,
    /// Set for the search action, which navigates with the typed text.
    search_text: Option<String>,
}

/// Destinations that live behind a sub-tab — findable by name even though they
/// are not top-level areas.
const TAB_CMDS: &[(&str, &str, &str)] = &[
    (
        "3D map",
        "the host↔ip↔user↔case topology as a live 3D graph",
        "intelligence:tab=map",
    ),
    (
        "Learning",
        "champion / challenger detector configs and dangerous misses",
        "detections:tab=learning",
    ),
    (
        "ATT&CK coverage",
        "which tactics the active ruleset covers",
        "intelligence:tab=attack",
    ),
    (
        "Threat hunts",
        "hypothesis-driven hunt reports",
        "intelligence:tab=hunts",
    ),
    (
        "Environment model",
        "trusted facts and quarantined candidates",
        "intelligence:tab=environment",
    ),
    (
        "Setup checklist",
        "what is configured and what is left",
        "system:tab=setup",
    ),
    (
        "Configuration",
        "every setting, its value, source and reload class",
        "system:tab=config",
    ),
    (
        "Model provider",
        "the configured model and a real connection test",
        "system:tab=llm",
    ),
    (
        "Access & credentials",
        "passkeys, API credentials, secrets, operator token",
        "system:tab=access",
    ),
];

/// Resolve a `area:query` spec from [`TAB_CMDS`] to a navigable pair.
fn tab_cmd_target(spec: &str) -> Option<(View, String)> {
    let (area, query) = spec.split_once(':')?;
    let view = match area {
        "intelligence" => View::Intelligence,
        "detections" => View::Detections,
        "system" => View::System,
        _ => return None,
    };
    Some((view, query.to_string()))
}

/// A source's status for the palette's honesty line.
fn status_of(f: &Fetch) -> SourceStatus {
    if f.err.get().is_some() {
        SourceStatus::Failed
    } else if f.data.get().is_some() {
        SourceStatus::Ok
    } else {
        SourceStatus::Loading
    }
}

#[component]
pub fn CommandPalette() -> impl IntoView {
    let store = expect_context::<Store>();
    let q = RwSignal::new(String::new());
    let highlight = RwSignal::new(0usize);

    // Every source is fetched with an explicit bound: the palette narrows what
    // the server already limited, so a broad query can never pull a whole table
    // into the browser. (This lab holds 817 investigations; the old palette
    // loaded all of them.)
    // Remember what had focus so it can be handed back when the palette closes.
    let opener = StoredValue::new_local(None::<web_sys::HtmlElement>);
    Effect::new(move |_| {
        crate::ui::manage_modal_focus(store.cmd_open.get(), "cmd-input", opener);
    });

    // One backend-backed search instead of five collections pulled into the
    // browser: /api/entities/search returns only entities that exist, bounded per
    // kind on the server, and reports what it truncated.
    let entities = Fetch::new();

    Effect::new(move |_| {
        if store.cmd_open.get() {
            q.set(String::new());
            highlight.set(0);
        }
    });

    // Re-query on every keystroke. `Fetch::load` carries a generation guard, so a
    // slow answer for an earlier prefix can never overwrite the current one —
    // which is what a debounce would otherwise be protecting against.
    Effect::new(move |_| {
        let text = q.get();
        let trimmed = text.trim();
        if !store.cmd_open.get() || trimmed.is_empty() {
            return;
        }
        entities.load(format!(
            "/api/entities/search?q={}&limit={}",
            api::enc(trimmed),
            palette::PER_GROUP_CAP
        ));
    });

    let sources = move || [("Search", status_of(&entities))];

    let results = move || {
        let query = q.get();
        let ql = query.trim().to_lowercase();
        let mut out: Vec<Cmd> = Vec::new();

        // The ONLY thing built from typed text — and it is labelled as an action,
        // never as an entity.
        if !ql.is_empty() {
            out.push(Cmd {
                kind: ResultKind::SearchAction,
                label: format!("Search audit for “{query}”"),
                hint: "full-text over every audit event".into(),
                go: View::Audit,
                query: String::new(),
                search_text: Some(query.trim().to_string()),
            });
        }

        // ---- real backend rows, straight from the server --------------------
        // Every entity here exists because the backend returned it. The console
        // no longer decides what an entity is; it only renders what came back.
        for g in entities.rows("groups") {
            let kind = match api::s(&g, "kind").as_str() {
                "investigation" => ResultKind::Investigation,
                "user" => ResultKind::User,
                "application" => ResultKind::Application,
                "resource" => ResultKind::Resource,
                "policy" => ResultKind::Policy,
                _ => continue,
            };
            let total = api::num(&g, "total") as usize;
            let items = g
                .get("items")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            let shown = items.len();
            for it in items {
                let path = api::s(&it, "path");
                let Some(view) = path_to_view(&path) else {
                    continue;
                };
                out.push(Cmd {
                    kind,
                    label: api::clean(&api::s(&it, "label")),
                    hint: api::clean(&api::s(&it, "hint")),
                    go: view,
                    query: String::new(),
                    search_text: None,
                });
            }
            // Say what is not shown rather than truncating in silence.
            if total > shown {
                out.push(Cmd {
                    kind,
                    label: format!(
                        "… {} more {} not shown",
                        total - shown,
                        kind.group().to_lowercase()
                    ),
                    hint: "narrow the query".into(),
                    go: View::Audit,
                    query: String::new(),
                    search_text: None,
                });
            }
        }

        // ---- console destinations ----------------------------------------
        for a in Area::ALL {
            if ql.is_empty() || palette::matches(a.label(), &ql) {
                out.push(Cmd {
                    kind: ResultKind::Page,
                    label: a.label().to_string(),
                    hint: a.blurb().to_string(),
                    go: a.home(),
                    query: String::new(),
                    search_text: None,
                });
            }
        }
        for (label, hint, spec) in TAB_CMDS {
            if !ql.is_empty() && palette::matches(&format!("{label} {hint}"), &ql) {
                if let Some((view, query)) = tab_cmd_target(spec) {
                    out.push(Cmd {
                        kind: ResultKind::Page,
                        label: (*label).to_string(),
                        hint: (*hint).to_string(),
                        go: view,
                        query,
                        search_text: None,
                    });
                }
            }
        }

        // Stable grouping in the declared display order.
        out.sort_by_key(|c| {
            ResultKind::ORDER
                .iter()
                .position(|k| *k == c.kind)
                .unwrap_or(usize::MAX)
        });
        out
    };

    let run = move |c: &Cmd| {
        store.cmd_open.set(false);
        if let Some(text) = &c.search_text {
            store
                .nav
                .go_query(View::Audit, format!("mode=text&q={}", api::enc(text)));
        } else if !c.query.is_empty() {
            store.nav.go_query(c.go.clone(), c.query.clone());
        } else {
            store.nav.go(c.go.clone());
        }
    };

    view! {
        {move || store.cmd_open.get().then(|| {
            let rs = results();
            let len = rs.len();
            view! {
                <div class="cmd-scrim" on:click=move |_| store.cmd_open.set(false)></div>
                <div class="cmd-modal" id="cmd-modal" role="dialog" aria-modal="true"
                    aria-label="Search and commands"
                    on:keydown=move |ev: web_sys::KeyboardEvent| crate::ui::trap_tab(&ev, "cmd-modal")
                    on:click=move |ev| ev.stop_propagation()>
                    <input class="cmd-input" type="text" autofocus=true
                        id="cmd-input"
                        role="combobox" aria-expanded="true" aria-controls="cmd-listbox"
                        aria-autocomplete="list"
                        aria-activedescendant=move || format!("cmd-opt-{}", highlight.get())
                        aria-label="Search investigations, users, applications, resources, policies and pages"
                        placeholder="Type to search investigations, users, apps, events — or a page name"
                        prop:value=move || q.get()
                        on:input=move |ev| { q.set(event_target_value(&ev)); highlight.set(0); }
                        on:keydown=move |ev: web_sys::KeyboardEvent| {
                            match ev.key().as_str() {
                                "ArrowDown" => { ev.prevent_default();
                                    highlight.set(palette::move_highlight(highlight.get_untracked(), 1, len)); }
                                "ArrowUp" => { ev.prevent_default();
                                    highlight.set(palette::move_highlight(highlight.get_untracked(), -1, len)); }
                                "Home" => { ev.prevent_default(); highlight.set(0); }
                                "End" => { ev.prevent_default(); highlight.set(len.saturating_sub(1)); }
                                "Enter" => { ev.prevent_default();
                                    if let Some(c) = results().get(highlight.get_untracked()) { run(c); } }
                                "Escape" => { ev.prevent_default(); store.cmd_open.set(false); }
                                _ => {}
                            }
                            // Keep the highlighted option in view for long lists.
                            if let Some(el) = web_sys::window().and_then(|w| w.document())
                                .and_then(|d| d.get_element_by_id(
                                    &format!("cmd-opt-{}", highlight.get_untracked())))
                                .and_then(|e| e.dyn_into::<web_sys::HtmlElement>().ok())
                            { el.scroll_into_view_with_bool(false); }
                        }/>

                    // Honest status: what is still loading, and what failed.
                    {move || {
                        let srcs = sources();
                        let note = palette::partial_failure_note(&srcs);
                        let loading = palette::any_loading(&srcs);
                        view! {
                            {note.map(|n| view! { <div class="banner warn" role="status">{n}</div> })}
                            {loading.then(|| view! {
                                <div class="cmd-status dimtext" role="status">"searching…"</div>
                            })}
                        }
                    }}

                    <div class="cmd-results" id="cmd-listbox" role="listbox"
                        aria-label="Search results">
                        {if rs.is_empty() {
                            view! { <div class="cmd-empty" role="status">
                                "No matches. Only real investigations, users, applications, \
                                 resources and policies are listed — nothing is invented from \
                                 what you typed."
                            </div> }.into_any()
                        } else {
                            let mut last_group: Option<ResultKind> = None;
                            rs.into_iter().enumerate().map(|(i, c)| {
                                let header = (last_group != Some(c.kind)).then(|| c.kind.group());
                                last_group = Some(c.kind);
                                let cmd = c.clone();
                                view! {
                                    {header.map(|h| view! {
                                        <div class="cmd-group" role="presentation">{h}</div>
                                    })}
                                    <button class="cmd-item" role="option"
                                        class:cmd-action=!c.kind.is_entity()
                                        id=format!("cmd-opt-{i}")
                                        class:highlighted=move || highlight.get() == i
                                        aria-selected=move || if highlight.get() == i { "true" } else { "false" }
                                        on:mouseenter=move |_| highlight.set(i)
                                        on:click=move |_| run(&cmd)>
                                        <span class="cmd-label">{c.label}</span>
                                        <span class="cmd-hint dimtext">{c.hint}</span>
                                    </button>
                                }
                            }).collect_view().into_any()
                        }}
                    </div>
                    <div class="cmd-foot dimtext">
                        "↑↓ to select · Enter to open · Esc to close"
                    </div>
                </div>
            }
        })}
    }
}

/// Map a server-provided entity path back to a routed [`View`].
///
/// The endpoint returns real paths, but the console still decides what it can
/// route to: an unrecognised shape is DROPPED, never coerced into some nearby
/// view. That keeps the "nothing is invented" rule true on the client side too.
fn path_to_view(path: &str) -> Option<View> {
    let rest = path.strip_prefix('/')?;
    let (head, tail) = rest.split_once('/')?;
    let id = crate::route::decode_path_segment(tail);
    Some(match head {
        "investigations" => View::Investigation(id),
        "users" => View::User(id),
        "applications" => View::Application(id),
        "resources" => View::Resource(id),
        "policies" => View::Policy(id),
        _ => return None,
    })
}
