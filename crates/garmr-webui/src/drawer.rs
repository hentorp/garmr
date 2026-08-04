// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! The universal entity drawer — a fast pivot surface. From any table, timeline,
//! graph or case, `store.peek(kind, name)` slides in a compact panel with the
//! entity's identity, recent cases and activity, plus a link to its full page.
//! It never re-implements a full page; it is a peek.

use leptos::prelude::*;
use serde_json::Value;

use crate::route::View;
use crate::views::Fetch;
use crate::{api, ui, Store};

#[component]
pub fn EntityDrawer() -> impl IntoView {
    let store = expect_context::<Store>();
    let f = Fetch::new();

    // Focus moves into the drawer when it opens and returns to the control that
    // opened it when it closes, so pivoting into an entity and back does not
    // strand a keyboard user at the top of the document.
    let opener = StoredValue::new_local(None::<web_sys::HtmlElement>);
    Effect::new(move |_| {
        crate::ui::manage_modal_focus(store.drawer.get().is_some(), "entity-drawer", opener);
    });

    // Refetch whenever the drawer target changes.
    Effect::new(move |_| {
        if let Some((kind, name)) = store.drawer.get() {
            f.load(format!(
                "/api/entity/{}/{}",
                api::enc(&kind),
                api::enc(&name)
            ));
        }
    });

    view! {
        {move || store.drawer.get().map(|(kind, name)| {
            let (k_open, n_open) = (kind.clone(), name.clone());
            let open_full = move || {
                store.drawer.set(None);
                match k_open.as_str() {
                    "user" | "staff" | "person" => store.nav.go(View::User(n_open.clone())),
                    "host" => store.nav.go(View::Application(n_open.clone())),
                    _ => store.nav.go(View::Entity(k_open.clone(), n_open.clone())),
                }
            };
            view! {
                <div class="drawer-scrim" on:click=move |_| store.drawer.set(None)></div>
                <aside class="drawer" id="entity-drawer" tabindex="-1"
                    role="dialog" aria-modal="true" aria-label="Entity details"
                    on:keydown=move |ev: web_sys::KeyboardEvent| crate::ui::trap_tab(&ev, "entity-drawer")>
                    <div class="drawer-head">
                        <div>
                            <span class="pill dim">{kind.clone()}</span>
                            <span class="drawer-name mono">{name.clone()}</span>
                        </div>
                        <button class="iconbtn" aria-label="Close" on:click=move |_| store.drawer.set(None)>"✕"</button>
                    </div>
                    <div class="drawer-body">
                        {move || {
                            if let Some(e) = f.err.get() { return super::views::error_state(e); }
                            match f.data.get() {
                                None => ui::loading("resolving…"),
                                Some(p) => drawer_body(&p),
                            }
                        }}
                    </div>
                    <div class="drawer-foot">
                        <button class="btn primary" on:click=move |_| open_full()>"Open full page →"</button>
                    </div>
                </aside>
            }
        })}
    }
}

fn drawer_body(p: &Value) -> AnyView {
    let cases = super::views::arr(p, "cases");
    let recent = super::views::arr(p, "recent_events");
    let n_cases = cases.len();
    view! {
        <div class="drawer-stats">
            {ui::pill(if n_cases > 0 { "warn" } else { "pass" }, format!("{n_cases} investigations"))}
            {ui::pill("dim", format!("{} recent events", recent.len()))}
        </div>
        <h4>"Investigations"</h4>
        {if cases.is_empty() { ui::empty("none") } else {
            view! {
                <div class="drawer-list">
                    {cases.into_iter().take(6).map(|c| view! {
                        <div class="drawer-row">
                            {ui::state_badge(&api::s(&c, "state"))}
                            <span class="grow">{api::clean(&api::s(&c, "rule"))}</span>
                            <span class="mono dimtext">{api::short(&c, "id")}</span>
                        </div>
                    }).collect_view()}
                </div>
            }.into_any()
        }}
        <h4>"Recent events"</h4>
        {if recent.is_empty() { ui::empty("none") } else {
            view! {
                <div class="drawer-list">
                    {recent.into_iter().take(8).map(|e| view! {
                        <div class="drawer-evt mono">
                            <span class="dimtext">{api::s(&e, "event_ts")}</span>
                            <span>{api::clean(&api::s(&e, "message"))}</span>
                        </div>
                    }).collect_view()}
                </div>
            }.into_any()
        }}
    }
    .into_any()
}
