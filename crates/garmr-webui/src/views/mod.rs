// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! The task-area views + the render dispatch, plus the shared data-fetch and
//! table helpers every area composes on.

use leptos::prelude::*;
use serde_json::Value;

use crate::api::{self, ApiError};
use crate::route::View;
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
pub mod map;
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
        View::Map => map::view(store).into_any(),
        View::Learning => learning::view(store).into_any(),
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
    gen: RwSignal<u64>,
}

impl Fetch {
    pub fn new() -> Self {
        Self {
            data: RwSignal::new(None),
            err: RwSignal::new(None),
            loading: RwSignal::new(false),
            gen: RwSignal::new(0),
        }
    }

    /// Kick off a GET; publishes the result only if still the newest request.
    pub fn load(&self, url: String) {
        let me = *self;
        let g = me.gen.get_untracked() + 1;
        me.gen.set(g);
        me.loading.set(true);
        me.err.set(None);
        leptos::task::spawn_local(async move {
            let res = api::send_get(&url).await;
            if me.gen.get_untracked() != g {
                return; // superseded
            }
            match res {
                Ok(v) => {
                    me.data.set(Some(v));
                    me.err.set(None);
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
                    return error_state(e);
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
    if e.is_authz() {
        view! {
            <div class="state error">
                <span class="state-glyph">"🔒"</span>
                <div>
                    <div><strong>{format!("{} — {}", e.kind(), api::clean(&e.message))}</strong></div>
                    <div class="dimtext">
                        "This action needs operator authorization. Sign in with a passkey, or set an operator token in System \u{203a} Access."
                    </div>
                </div>
            </div>
        }
        .into_any()
    } else {
        ui::error_box(format!("{} — {}", e.kind(), e.message))
    }
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
pub fn tabs(
    items: &[(&'static str, &'static str)],
    current: String,
    on_select: impl Fn(&'static str) + Copy + 'static,
) -> AnyView {
    let items = items.to_vec();
    view! {
        <div class="tabs" role="tablist">
            {items.into_iter().map(|(id, label)| {
                let active = current == id;
                view! {
                    <button class="tab" class:active=active role="tab" aria-selected=active
                        on:click=move |_| on_select(id)>{label}</button>
                }
            }).collect_view()}
        </div>
    }
    .into_any()
}