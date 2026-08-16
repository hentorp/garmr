// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! garmr analyst command center — Leptos CSR (WASM) frontend over the `serve` API.
//!
//! A task-oriented single-page console: `garmr serve` hosts the bundle and the SPA
//! calls the same `/api/*` endpoints. Navigation is real URL routing (History
//! API — see [`route`]); a server-provided capability manifest (see [`caps`])
//! decides which features are live; the design system lives in [`ui`]. Views fetch
//! their own data on demand — there is no fixed global poll — and the human-paced
//! surfaces refresh only when visible.

use leptos::prelude::*;

mod api;
mod auth;
mod caps;
mod command;
mod confirm;
mod drawer;
mod palette;
mod route;
mod setup;
mod shell;
mod srcstate;
mod status;
mod timerange;
mod ui;
mod views;

use caps::Caps;
use route::{Nav, View};

/// The global dashboard time range (Splunk/Elastic-style): live tail, a
/// last-N-hours preset, or an absolute `[from, to)` epoch-millis range.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TimeRange {
    Live,
    Last(u32),
    Absolute(i64, i64),
}

impl TimeRange {
    /// SQL predicate over `event_ts` for `/api/query`, or `None` (= live tail).
    pub fn events_predicate(self) -> Option<String> {
        match self {
            TimeRange::Live => None,
            TimeRange::Last(h) => Some(format!("event_ts >= now() - INTERVAL '{h} hours'")),
            TimeRange::Absolute(from, to) => Some(format!(
                "event_ts >= '{}' AND event_ts < '{}'",
                api::iso_ms(from),
                api::iso_ms(to)
            )),
        }
    }
    pub fn graph_query(self) -> String {
        match self {
            TimeRange::Live => String::new(),
            TimeRange::Last(h) => format!("?hours={h}"),
            TimeRange::Absolute(from, to) => format!("?from={from}&to={to}"),
        }
    }
    /// Extra `/api/search` parameters carrying this range (appended after
    /// `?q=`). Empty for Live: an unbounded full-text search, the endpoint's
    /// default — not a filter the picker would then have to claim.
    pub fn search_params(self) -> String {
        match self {
            TimeRange::Live => String::new(),
            TimeRange::Last(h) => format!("&hours={h}"),
            TimeRange::Absolute(from, to) => format!("&from={from}&to={to}"),
        }
    }
    /// This range as the hybrid Query-IR's `filter.time` (`POST /api/hsearch`),
    /// or `None` for Live — an unbounded hybrid query, the IR's default. The IR
    /// counts in MICROS while the picker (and `/map`, `/api/search`) count in
    /// millis, so an absolute range is converted here, once.
    ///
    /// A `t=` slug wild enough to overflow the conversion saturates to an empty
    /// window and finds nothing — the fail-closed direction. Silently dropping
    /// the bound would run an unbounded search under a picker still claiming the
    /// range, which is exactly the dishonesty this parameter exists to remove.
    pub fn hsearch_time(self) -> Option<serde_json::Value> {
        match self {
            TimeRange::Live => None,
            TimeRange::Last(h) => Some(serde_json::json!({ "last_hours": h })),
            TimeRange::Absolute(from, to) => Some(serde_json::json!({
                "from_micros": from.saturating_mul(1000),
                "to_micros": to.saturating_mul(1000),
            })),
        }
    }
    pub fn label(self) -> String {
        match self {
            TimeRange::Live => "Live".to_string(),
            TimeRange::Last(24) => "Last 24h".to_string(),
            TimeRange::Last(72) => "Last 72h".to_string(),
            TimeRange::Last(168) => "Last 7d".to_string(),
            TimeRange::Last(720) => "Last 30d".to_string(),
            TimeRange::Last(h) => format!("Last {h}h"),
            TimeRange::Absolute(from, to) => {
                format!("{} → {}", api::local_dt(from), api::local_dt(to))
            }
        }
    }
    /// Short slug for the URL (`live`, `24h`, `from-to`).
    pub fn to_slug(self) -> String {
        match self {
            TimeRange::Live => "live".into(),
            TimeRange::Last(h) => format!("{h}h"),
            TimeRange::Absolute(f, t) => format!("{f}-{t}"),
        }
    }
    pub fn from_slug(s: &str) -> Option<TimeRange> {
        if s == "live" {
            return Some(TimeRange::Live);
        }
        if let Some(h) = s.strip_suffix('h').and_then(|n| n.parse().ok()) {
            return Some(TimeRange::Last(h));
        }
        if let Some((f, t)) = s.split_once('-') {
            if let (Ok(f), Ok(t)) = (f.parse(), t.parse()) {
                return Some(TimeRange::Absolute(f, t));
            }
        }
        None
    }
}

/// One entry in the activity center — a completed/failed operation or a
/// long-running task, with its audit reference when a protected change produced
/// one.
#[derive(Clone)]
pub struct Activity {
    pub at: String,
    pub title: String,
    pub ok: bool,
    pub detail: String,
    pub audit: Option<String>,
}

/// The shared reactive model. Lean by design: cross-cutting state (routing,
/// capabilities, the drawer, the command palette, the activity center) lives
/// here; each view fetches its own data locally.
#[derive(Clone, Copy)]
pub struct Store {
    pub nav: Nav,
    /// The capability manifest (`None` until the first fetch resolves).
    pub caps: RwSignal<Option<Caps>>,
    /// Whether the last completed request reached the API.
    pub api_ok: RwSignal<bool>,
    /// Per-source error text (source → message), newest write wins per source.
    pub errors: RwSignal<Vec<(String, String)>>,
    /// The global dashboard time range (drives Audit Explorer + Command Center).
    pub time_range: RwSignal<TimeRange>,
    /// The universal entity drawer: `Some((kind, name))` when open.
    pub drawer: RwSignal<Option<(String, String)>>,
    /// Command palette open state.
    pub cmd_open: RwSignal<bool>,
    /// The activity center feed (newest first, bounded).
    pub activity: RwSignal<Vec<Activity>>,
    /// Whether an operator token is held this session (mirrors `api::has_operator_token`
    /// reactively so controls update when it changes).
    pub operator: RwSignal<bool>,
    /// Whether the off-canvas navigation drawer is open. Only meaningful below the
    /// layout breakpoint, where the sidebar is not permanently on screen.
    pub nav_open: RwSignal<bool>,
    /// The last natural-language answer, with the question it answers.
    ///
    /// It lives on the Store rather than in the Audit view because every
    /// query-string write REBUILDS that view: with no home that outlives the
    /// rebuild, clicking a time-range chip would re-ask the model and pay again
    /// for the answer already on screen. `/api/ask` takes no range — the
    /// assistant plans its own window from the question — so the answer to the
    /// same question cannot have changed.
    pub nl_answer: RwSignal<Option<(String, serde_json::Value)>>,
    /// Whether first-run setup is complete. `None` until `/api/setup/status`
    /// answers — deliberately not defaulted, so the console neither nags before it
    /// knows nor claims readiness it has not confirmed.
    pub setup_complete: RwSignal<Option<bool>>,
}

impl Store {
    fn new() -> Self {
        Self {
            nav: Nav::new(),
            caps: RwSignal::new(None),
            api_ok: RwSignal::new(false),
            errors: RwSignal::new(Vec::new()),
            time_range: RwSignal::new(TimeRange::Live),
            drawer: RwSignal::new(None),
            cmd_open: RwSignal::new(false),
            activity: RwSignal::new(Vec::new()),
            operator: RwSignal::new(false),
            nav_open: RwSignal::new(false),
            nl_answer: RwSignal::new(None),
            setup_complete: RwSignal::new(None),
        }
    }

    pub fn set_err(&self, source: &str, err: Option<String>) {
        self.errors.update(|es| {
            es.retain(|(s, _)| s != source);
            if let Some(e) = err {
                es.push((source.to_string(), e));
            }
        });
    }

    /// Open the universal entity drawer for `(kind, name)`.
    pub fn peek(&self, kind: impl Into<String>, name: impl Into<String>) {
        self.drawer.set(Some((kind.into(), name.into())));
    }

    /// Record an activity-center entry (a completed/failed protected action, a
    /// long task). Keeps the feed bounded.
    pub fn log_activity(
        &self,
        title: impl Into<String>,
        ok: bool,
        detail: impl Into<String>,
        audit: Option<String>,
    ) {
        let entry = Activity {
            at: api::now_hms(),
            title: title.into(),
            ok,
            detail: detail.into(),
            audit,
        };
        self.activity.update(|a| {
            a.insert(0, entry);
            a.truncate(50);
        });
    }
}

#[component]
pub fn App() -> impl IntoView {
    let store = Store::new();
    provide_context(store);

    // Fetch the capability manifest once, up front — it decides what the shell
    // shows. A failure leaves it `None` (fail-open: views still render, the
    // server still authorizes).
    leptos::task::spawn_local(async move {
        match api::get("/api/capabilities").await {
            Ok(v) => {
                let c = Caps::from_value(v);
                // Teach the request layer how this deployment authenticates, so
                // a 401 bounces to the passkey login page only when that page
                // can actually resolve it (otherwise: an actionable operator
                // prompt, never a console↔login loop).
                api::set_auth_mode(auth::AuthMode::from_caps(
                    c.auth_enabled(),
                    c.passkey_enabled(),
                ));
                store.caps.set(Some(c));
                store.api_ok.set(true);
            }
            Err(e) => store.set_err("capabilities", Some(e)),
        }
    });

    // Setup readiness, fetched once alongside capabilities: it decides the
    // persistent banner and which System tab opens by default.
    leptos::task::spawn_local(async move {
        if let Ok(v) = api::get("/api/setup/status").await {
            store
                .setup_complete
                .set(v.get("complete").and_then(|c| c.as_bool()));
        }
    });

    // The document title follows the route, so browser history, bookmarks and the
    // window switcher all name the actual screen instead of repeating "garmr".
    Effect::new(move |_| {
        let v = store.nav.view.get();
        if let Some(d) = web_sys::window().and_then(|w| w.document()) {
            d.set_title(&format!("{} — garmr", v.title()));
        }
    });

    install_popstate(store);
    install_keyboard(store);
    install_message_bridge(store);
    restore_session(store);

    view! {
        // First thing in the tab order: a way past the twelve navigation items
        // straight to the content, for keyboard and screen-reader users.
        <a class="skip-link" href="#main">"Skip to main content"</a>
        <div class="app">
            <shell::Sidebar/>
            <div class="workspace">
                <shell::TopBar/>
                <shell::SetupBanner/>
                <main id="main" tabindex="-1">
                    {move || views::render(store, store.nav.view.get())}
                </main>
                <shell::StatusBar/>
            </div>
            <drawer::EntityDrawer/>
            <command::CommandPalette/>
            <shell::ActivityToast/>
        </div>
    }
}

/// Restore session-scoped UI state on load: a held operator token (sessionStorage)
/// and the saved light/dark theme (localStorage). The token is re-applied to the
/// API client so protected controls keep working across a reload within the
/// session; it is never written to disk by the app.
fn restore_session(store: Store) {
    if let Some(s) = web_sys::window()
        .and_then(|w| w.session_storage().ok())
        .flatten()
    {
        if let Ok(Some(tok)) = s.get_item("garmr-operator") {
            if !tok.is_empty() {
                api::set_operator_token(Some(tok));
                store.operator.set(true);
            }
        }
    }
    let saved_theme = web_sys::window()
        .and_then(|w| w.local_storage().ok())
        .flatten()
        .and_then(|s| s.get_item("garmr-theme").ok().flatten());
    if let (Some(theme), Some(root)) = (
        saved_theme,
        web_sys::window()
            .and_then(|w| w.document())
            .and_then(|d| d.document_element()),
    ) {
        let _ = root.set_attribute("data-theme", &theme);
    }
}

/// Listen for browser back/forward and re-sync the view from the URL.
fn install_popstate(store: Store) {
    use wasm_bindgen::JsCast;
    let cb = wasm_bindgen::closure::Closure::<dyn FnMut(wasm_bindgen::JsValue)>::new(
        move |_ev: wasm_bindgen::JsValue| {
            store.nav.sync_from_location();
        },
    );
    if let Some(w) = web_sys::window() {
        let _ = w.add_event_listener_with_callback("popstate", cb.as_ref().unchecked_ref());
    }
    cb.forget();
}

/// Global keyboard shortcuts: Ctrl/Cmd-K opens the command palette; Escape closes
/// the palette or the drawer.
fn install_keyboard(store: Store) {
    use wasm_bindgen::JsCast;
    let cb = wasm_bindgen::closure::Closure::<dyn FnMut(web_sys::KeyboardEvent)>::new(
        move |ev: web_sys::KeyboardEvent| {
            let k = ev.key();
            if (ev.ctrl_key() || ev.meta_key()) && (k == "k" || k == "K") {
                ev.prevent_default();
                store.cmd_open.update(|o| *o = !*o);
            } else if k == "Escape" {
                // Innermost surface first, so Escape peels one layer at a time.
                if store.cmd_open.get_untracked() {
                    store.cmd_open.set(false);
                } else if store.drawer.get_untracked().is_some() {
                    store.drawer.set(None);
                } else if store.nav_open.get_untracked() {
                    store.nav_open.set(false);
                }
            }
        },
    );
    if let Some(doc) = web_sys::window().and_then(|w| w.document()) {
        let _ = doc.add_event_listener_with_callback("keydown", cb.as_ref().unchecked_ref());
    }
    cb.forget();
}

/// Same-origin `postMessage` bridge from the embedded relationship canvas (the
/// optional 3D map iframe): open an entity in the drawer, or navigate to a case.
fn install_message_bridge(store: Store) {
    use wasm_bindgen::JsCast;
    let cb = wasm_bindgen::closure::Closure::<dyn FnMut(wasm_bindgen::JsValue)>::new(
        move |ev: wasm_bindgen::JsValue| {
            let self_origin = web_sys::window()
                .and_then(|w| w.location().origin().ok())
                .unwrap_or_default();
            let origin = js_sys::Reflect::get(&ev, &wasm_bindgen::JsValue::from_str("origin"))
                .ok()
                .and_then(|o| o.as_string())
                .unwrap_or_default();
            if self_origin.is_empty() || origin != self_origin {
                return;
            }
            let Ok(data) = js_sys::Reflect::get(&ev, &wasm_bindgen::JsValue::from_str("data"))
            else {
                return;
            };
            let Some(s) = data.as_string() else { return };
            let Ok(v) = serde_json::from_str::<serde_json::Value>(&s) else {
                return;
            };
            if v.get("garmr").and_then(|x| x.as_str()) != Some("open-node") {
                return;
            }
            let kind = v
                .get("kind")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string();
            let id = v
                .get("id")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string();
            let name = v
                .get("name")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string();
            if kind == "case" {
                store.nav.go(View::Investigation(id));
            } else if !kind.is_empty() && !name.is_empty() {
                store.peek(kind, name);
            }
        },
    );
    if let Some(w) = web_sys::window() {
        let _ = w.add_event_listener_with_callback("message", cb.as_ref().unchecked_ref());
    }
    cb.forget();
}
