// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! WASM entry point for the garmr web console: install the panic hook (so a
//! Rust panic surfaces in the browser console) and mount the Leptos [`App`]
//! into the document body. All UI logic lives in the library crate.

fn main() {
    console_error_panic_hook::set_once();
    leptos::mount::mount_to_body(garmr_webui::App);
}