// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! The task-area views + the render dispatch, plus the shared data-fetch and
//! table helpers every area composes on.

use leptos::prelude::*;
use serde_json::Value;
use wasm_bindgen::JsCast;

use crate::api::{self, ApiError};
use crate::route::View;
use crate::srcstate::{self, SourceState};
use crate::{ui, Store};

pub mod applications;
pub mod ask;
pub mod audit;
pub mod command_center;
pub mod data_sources;
pub mod detections;
pub mod entity;
pub mod graph;
pub mod intelligence;
pub mod investigations;
pub mod learning;
pub mod policies;
pub mod resources;
pub mod system;
pub mod users;

/// Map the routed [`View`] to its rendered area. The single place path → screen.
pub fn render(store: Store, view: View) -> AnyView {
    match view {
        View::CommandCenter => command_center::view(store).into_any(),
        View::Investigations => investigations::list_view(store).into_any(),
        View::Investigation(id) => investigations::detail_view(store, id).into_any(),
        View::Audit => audit::view(store).into_any(),
        View::Users => users::list_view(store).into_any(),
        View::User(name) => users::detail_view(store, name).into_any(),
        View::Applications => applications::list_view(store).into_any(),
        View::Application(name) => applications::detail_view(store, name).into_any(),
        View::Resources => resources::list_view(store).into_any(),
        View::Resource(id) => resources::detail_view(store, id).into_any(),
        View::Detections => detections::view(store).into_any(),
        View::Policies => policies::list_view(store).into_any(),
        View::Policy(id) => policies::detail_view(store, id).into_any(),
        View::Intelligence => intelligence::view(store).into_any(),
        View::DataSources => data_sources::view(store).into_any(),
        View::System => system::view(store).into_any(),
        View::Entity(kind, name) => entity::deep_link_view(store, kind, name).into_any(),
        View::NotFound(path) => not_found(store, path).into_any(),
    }
}

fn not_found(store: Store, path: String) -> impl IntoView {
    view! {
        <div class="page">
            {ui::page_header("Page not found", "This URL does not name a console view.")}
            <div class="card">
                <p>"No view is registered for "<code>{path}</code>"."</p>
                <button class="btn primary" on:click=move |_| store.nav.go(View::CommandCenter)>
                    "Go to Command Center"
                </button>
            </div>
        </div>
    }
}

// ---- shared fetch resource ------------------------------------------------

/// A small reactive fetch resource: the last response `Value`, an error, and a
/// loading flag, plus a monotonic generation so a slow response can never
/// overwrite a newer one. Views call [`Fetch::load`] with a URL.
#[derive(Clone, Copy)]
pub struct Fetch {
    pub data: RwSignal<Option<Value>>,
    pub err: RwSignal<Option<ApiError>>,
    pub loading: RwSignal<bool>,
    /// Epoch millis of the last SUCCESSFUL response, so a view can show "last
    /// updated" and decide whether the data is still inside its freshness budget.
    /// `None` until something has actually been received — never treated as "now".
    pub fetched_at: RwSignal<Option<f64>>,
    /// The last URL requested, so a failed view can offer a Retry that repeats
    /// exactly the request that failed.
    url: RwSignal<String>,
    gen: RwSignal<u64>,
}

impl Fetch {
    pub fn new() -> Self {
        Self {
            data: RwSignal::new(None),
            err: RwSignal::new(None),
            loading: RwSignal::new(false),
            fetched_at: RwSignal::new(None),
            url: RwSignal::new(String::new()),
            gen: RwSignal::new(0),
        }
    }

    /// This source's state for a monitoring board, given how old its data may be
    /// before it stops counting as current. See [`crate::srcstate`] for why the
    /// board may not draw a conclusion from anything but [`SourceState::Fresh`].
    pub fn state(&self, budget_secs: u64) -> SourceState {
        let age = self
            .fetched_at
            .get()
            .map(|t| (((js_sys::Date::now() - t) / 1000.0).max(0.0)) as u64);
        srcstate::derive(
            self.loading.get(),
            self.data.get().is_some(),
            self.err.get().map(|e| e.status),
            age,
            budget_secs,
        )
    }

    /// Kick off a GET; publishes the result only if still the newest request.
    pub fn load(&self, url: String) {
        let me = *self;
        me.url.set(url.clone());
        let g = me.gen.get_untracked() + 1;
        me.gen.set(g);
        me.loading.set(true);
        me.err.set(None);
        leptos::task::spawn_local(async move {
            let res = api::send_get(&url).await;
            // `try_`: navigating away disposes the view that owns this Fetch
            // while the request is still in flight, and reading a disposed
            // signal outright panics — taking the whole wasm module with it.
            if me.gen.try_get_untracked() != Some(g) {
                return; // superseded, or the view is gone
            }
            match res {
                Ok(v) => {
                    me.data.set(Some(v));
                    me.err.set(None);
                    me.fetched_at.set(Some(js_sys::Date::now()));
                }
                Err(e) => me.err.set(Some(e)),
            }
            me.loading.set(false);
        });
    }

    /// The array under `key` in the last response (empty if absent).
    pub fn rows(&self, key: &str) -> Vec<Value> {
        self.data
            .get()
            .as_ref()
            .and_then(|v| v.get(key))
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default()
    }

    /// Render the standard states around a body that consumes the rows. `empty`
    /// is shown when the response has no rows under `key`.
    pub fn framed(
        &self,
        key: &'static str,
        empty_msg: &'static str,
        body: impl Fn(Vec<Value>) -> AnyView + Send + 'static,
    ) -> AnyView {
        let me = *self;
        view! {
            {move || {
                if let Some(e) = me.err.get() {
                    // Retry repeats exactly the request that failed.
                    return error_state_retry(e, move || {
                        let u = me.url.get_untracked();
                        if !u.is_empty() {
                            me.load(u);
                        }
                    });
                }
                if me.data.get().is_none() && me.loading.get() {
                    return ui::loading("loading…");
                }
                let rows = me.rows(key);
                if rows.is_empty() {
                    return ui::empty(empty_msg);
                }
                body(rows)
            }}
        }
        .into_any()
    }
}

impl Default for Fetch {
    fn default() -> Self {
        Self::new()
    }
}

/// Render an [`ApiError`] as the right state: an authz failure explains how to
/// authorize; everything else is a plain error box.
pub fn error_state(e: ApiError) -> AnyView {
    authz_or_error(e, None::<fn()>)
}

/// Like [`error_state`], but with a Retry that re-runs the request.
///
/// This is what makes a token-only deployment usable: the operator sets a token
/// in System › Access and comes back to a view that can actually retry, instead
/// of a dead panel that only a full page reload clears.
pub fn error_state_retry(e: ApiError, retry: impl Fn() + Copy + Send + Sync + 'static) -> AnyView {
    authz_or_error(e, Some(retry))
}

fn authz_or_error(e: ApiError, retry: Option<impl Fn() + Copy + Send + Sync + 'static>) -> AnyView {
    if !e.is_authz() {
        return match retry {
            Some(r) => view! {
                <div class="state error">
                    <span class="state-glyph">"⚠"</span>
                    <div class="grow">
                        <div><strong>{format!("{} — {}", e.kind(), api::clean(&e.message))}</strong></div>
                    </div>
                    <button class="btn" on:click=move |_| r()>"Retry"</button>
                </div>
            }
            .into_any(),
            None => ui::error_box(format!("{} — {}", e.kind(), e.message)),
        };
    }

    let store = expect_context::<Store>();
    let forbidden = e.status == 403;
    // 403 means "authenticated but not permitted" — offering a token prompt there
    // would send the operator somewhere that cannot help.
    let guidance = if forbidden {
        "You are signed in, but this principal may not do that. It needs a role \
         with more privilege — check the principal in System \u{203a} Access."
    } else {
        "This view needs operator authorization. Sign in with a passkey, or paste \
         an operator token in System \u{203a} Access, then retry."
    };
    view! {
        <div class="state error">
            <span class="state-glyph">"🔒"</span>
            <div class="grow">
                <div><strong>{format!("{} — {}", e.kind(), api::clean(&e.message))}</strong></div>
                <div class="dimtext">{guidance}</div>
            </div>
            <div class="row">
                // A direct route to the one place this is fixed.
                <button class="btn" on:click=move |_| {
                    store.nav.go(crate::route::Area::System.home());
                    store.nav.set_query("tab=access".to_string());
                }>"Open System \u{203a} Access"</button>
                {retry.map(|r| view! {
                    <button class="btn primary" on:click=move |_| r()>"Retry"</button>
                })}
            </div>
        </div>
    }
    .into_any()
}

/// The query string a view publishes for its own filters, with the global time
/// range carried through untouched.
///
/// Filters kept only in view-local signals do not survive: every query write
/// re-renders the view and rebuilds those signals from the URL, so a time-range
/// chip or a lifecycle chip silently erased whatever had been typed. Publishing
/// through here puts them where they last — and makes the filtered screen a link
/// worth sharing. Empty values are omitted, so "no filter" reads as no parameter.
pub fn publish_query(pairs: &[(&str, String)], current: &str) -> String {
    crate::timerange::carry(current, &crate::route::build_query(pairs))
}

// ---- small render helpers -------------------------------------------------

/// The array under `key` of a JSON value.
pub fn arr(v: &Value, key: &str) -> Vec<Value> {
    v.get(key)
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
}

/// A data table from headers + row views.
pub fn table(headers: &[&str], body: AnyView) -> AnyView {
    let hs: Vec<String> = headers.iter().map(|s| s.to_string()).collect();
    view! {
        <div class="tablewrap">
            <table>
                <thead><tr>{hs.into_iter().map(|h| view! { <th>{h}</th> }).collect_view()}</tr></thead>
                <tbody>{body}</tbody>
            </table>
        </div>
    }
    .into_any()
}

/// A tab bar: `(id, label)` pairs; `current` is the active id; `on_select`
/// navigates. Renders as accessible buttons.
/// The System view's tab ids, so an unknown `?tab=` still labels its panel
/// against a real tab rather than a dangling id.
pub const TAB_IDS: [&str; 7] = [
    "setup", "audit", "registry", "config", "posture", "access", "llm",
];

pub fn tabs(
    items: &[(&'static str, &'static str)],
    current: String,
    on_select: impl Fn(&'static str) + Copy + 'static,
) -> AnyView {
    let items = items.to_vec();
    let order: Vec<&'static str> = items.iter().map(|(id, _)| *id).collect();
    view! {
        <div class="tabs" role="tablist">
            {items.into_iter().map(|(id, label)| {
                let active = current == id;
                let order = order.clone();
                view! {
                    // Full tab semantics: the tablist is ONE tab stop (roving
                    // tabindex — only the selected tab is reachable by Tab), and
                    // Arrow keys move between tabs, which is what a screen-reader
                    // user expects and what this list previously did not do.
                    <button class="tab" class:active=active
                        role="tab"
                        // A string, not a bool: Leptos renders a `true` bool as a
                        // bare attribute and omits `false`, but assistive tech
                        // needs an explicit aria-selected="true"/"false".
                        aria-selected=if active { "true" } else { "false" }
                        id=format!("tab-{id}")
                        aria-controls=format!("tabpanel-{id}")
                        tabindex=if active { "0" } else { "-1" }
                        on:click=move |_| on_select(id)
                        on:keydown=move |ev: web_sys::KeyboardEvent| {
                            let k = ev.key();
                            let step: i32 = match k.as_str() {
                                "ArrowRight" | "ArrowDown" => 1,
                                "ArrowLeft" | "ArrowUp" => -1,
                                "Home" => i32::MIN,
                                "End" => i32::MAX,
                                _ => return,
                            };
                            ev.prevent_default();
                            let n = order.len() as i32;
                            let cur = order.iter().position(|x| *x == id).unwrap_or(0) as i32;
                            let next = match step {
                                i32::MIN => 0,
                                i32::MAX => n - 1,
                                d => (cur + d).rem_euclid(n),
                            };
                            if let Some(target) = order.get(next as usize) {
                                on_select(target);
                                // Follow-focus: selection and focus move together.
                                if let Some(el) = web_sys::window()
                                    .and_then(|w| w.document())
                                    .and_then(|d| d.get_element_by_id(&format!("tab-{target}")))
                                    .and_then(|e| e.dyn_into::<web_sys::HtmlElement>().ok())
                                {
                                    let _ = el.focus();
                                }
                            }
                        }>{label}</button>
                }
            }).collect_view()}
        </div>
    }
    .into_any()
}

/// The panel a tablist controls. Pairs with [`tabs`]: same `id` on both sides, so
/// assistive tech can move from the selected tab to its content and back.
pub fn tab_panel(id: &str, body: AnyView) -> AnyView {
    view! {
        <div role="tabpanel" id=format!("tabpanel-{id}") aria-labelledby=format!("tab-{id}")
            tabindex="0">
            {body}
        </div>
    }
    .into_any()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::route::param_of;
    use crate::TimeRange;

    /// The bug this builder exists to prevent: two filters on one screen wiping
    /// each other. The Investigations queue publishes its lifecycle chip and its
    /// text box together, so clicking a chip keeps what was typed and committing
    /// the text keeps the chip.
    #[test]
    fn filters_on_one_screen_do_not_wipe_each_other() {
        let q = publish_query(
            &[("state", "closed".into()), ("q", "sshd".into())],
            "state=needs_human&q=old&t=24h",
        );
        assert_eq!(param_of(&q, "state"), Some("closed".into()));
        assert_eq!(param_of(&q, "q"), Some("sshd".into()));
        // …and neither displaces the window the analyst chose.
        assert_eq!(crate::timerange::read_param(&q), Some(TimeRange::Last(24)));
        assert_eq!(q.matches("t=").count(), 1, "duplicate range params in {q}");
    }

    /// The queue publishes four filters as one pair set — lifecycle, ownership
    /// lane, tag and text — so switching lanes keeps the rest. This is the
    /// two-analyst contract: "my escalation-tagged needs-human cases" is one
    /// shareable URL.
    #[test]
    fn ownership_and_tag_filters_share_the_url() {
        let q = publish_query(
            &[
                ("state", "needs_human".into()),
                ("assignee", "(unassigned)".into()),
                ("tag", "escalation".into()),
                ("q", "sshd".into()),
            ],
            "state=closed&t=24h",
        );
        assert_eq!(param_of(&q, "state"), Some("needs_human".into()));
        assert_eq!(param_of(&q, "assignee"), Some("(unassigned)".into()));
        assert_eq!(param_of(&q, "tag"), Some("escalation".into()));
        assert_eq!(param_of(&q, "q"), Some("sshd".into()));
        assert_eq!(crate::timerange::read_param(&q), Some(TimeRange::Last(24)));
    }

    /// "No filter" must read as no parameter, or a shared link would filter on
    /// the empty string and show nothing.
    #[test]
    fn an_empty_filter_leaves_no_parameter() {
        let q = publish_query(&[("state", String::new()), ("q", String::new())], "t=24h");
        assert_eq!(param_of(&q, "state"), None);
        assert_eq!(param_of(&q, "q"), None);
        assert_eq!(crate::timerange::read_param(&q), Some(TimeRange::Last(24)));
    }

    /// Filter text is arbitrary operator input and must round-trip exactly.
    #[test]
    fn awkward_filter_text_survives_the_url() {
        for raw in ["rule=ssh & host=pve", "a/b?c", "unicode-ÅÄÖ", "50%"] {
            let q = publish_query(&[("q", raw.to_string())], "t=72h");
            assert_eq!(
                param_of(&q, "q").as_deref(),
                Some(raw),
                "{raw} did not round-trip"
            );
            assert_eq!(crate::timerange::read_param(&q), Some(TimeRange::Last(72)));
        }
    }
}
