// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! Map — the CodeVault 3D entity topology (host↔ip↔user↔case), embedded from the
//! backend-served `/map/` sub-app (garmr-map, eframe/WASM) in an iframe. Case nodes
//! glow red as findings; clicking a node posts a same-origin message that the
//! shell turns into an entity-drawer peek or a jump to the case (see the
//! `install_message_bridge` in `lib.rs`).
//!
//! The 3D view is never the *only* way to read relationships: an accessible
//! relationship table + attack paths live in Intelligence › Relationships, linked
//! prominently here. The iframe follows the global time range.

use leptos::prelude::*;

use crate::route::{Area, View};
use crate::Store;

pub fn view(store: Store) -> impl IntoView {
    // The map reads the same time window as the rest of the console; pass it on
    // the iframe URL so a preset/absolute range scopes the graph.
    let src = move || format!("/map/{}", store.time_range.get().graph_query());

    view! {
        <div class="page mappage">
            <div class="page-header row">
                <div class="grow">
                    <h1>"Map"</h1>
                    <div class="sub">{Area::Map.blurb()}</div>
                </div>
                <button
                    class="btn ghost"
                    title="Accessible alternative: the same relationships as a table + attack paths"
                    on:click=move |_| store.nav.go_query(View::Intelligence, "tab=relationships")
                >
                    "Accessible relationship table →"
                </button>
            </div>
            <div class="map-embed">
                <iframe
                    class="map-frame"
                    title="3D topology"
                    src=src
                    referrerpolicy="no-referrer"
                ></iframe>
            </div>
            <p class="sub map-note">
                "Neon 3D topology fed live from garmr — investigation nodes glow red as findings. \
                 Click a node to peek the entity or open its investigation. Not keyboard-navigable; \
                 use the accessible relationship table for the same links."
            </p>
        </div>
    }
}