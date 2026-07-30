// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! Task-oriented information architecture + real URL routing.
//!
//! The console is a client-rendered SPA, but every meaningful state has a stable
//! URL: navigating pushes a History entry, browser back/forward and a hard
//! refresh all restore the same view (the server serves `index.html` for any
//! unmatched path, so a deep link cold-loads correctly). Filters, the time range,
//! the active sub-tab and the search query live in the query string, so a shared
//! link reproduces the exact screen.
//!
//! [`View`] is the parsed *path* (which area + which entity). Query parameters are
//! kept separately (a reactive `nav_search` signal) so a filter change re-renders
//! without changing the `View`. Sensitive values are never placed in the URL.

use leptos::prelude::*;

/// A top-level task area — one primary sidebar destination. The IA is organised
/// around what an analyst wants to *do*, not around backend crates.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Area {
    CommandCenter,
    Investigations,
    Audit,
    Users,
    Applications,
    Resources,
    Detections,
    Policies,
    Intelligence,
    Map,
    Learning,
    DataSources,
    System,
}

impl Area {
    pub const ALL: [Area; 13] = [
        Area::CommandCenter,
        Area::Investigations,
        Area::Audit,
        Area::Users,
        Area::Applications,
        Area::Resources,
        Area::Detections,
        Area::Policies,
        Area::Intelligence,
        Area::Map,
        Area::Learning,
        Area::DataSources,
        Area::System,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Area::CommandCenter => "Command Center",
            Area::Investigations => "Investigations",
            Area::Audit => "Audit Explorer",
            Area::Users => "Users",
            Area::Applications => "Applications",
            Area::Resources => "Resources",
            Area::Detections => "Detections",
            Area::Policies => "Policies",
            Area::Intelligence => "Intelligence",
            Area::Map => "Map",
            Area::Learning => "Learning",
            Area::DataSources => "Data Sources",
            Area::System => "System",
        }
    }

    /// One-line description of the analyst job this area serves — shown as a
    /// tooltip and on the page header, so no navigation label is unexplained.
    pub fn blurb(self) -> &'static str {
        match self {
            Area::CommandCenter => "What needs attention now",
            Area::Investigations => {
                "Investigations: evidence, agent analysis and analyst decisions"
            }
            Area::Audit => {
                "Search every audit event — structured, text, meaning, or plain language"
            }
            Area::Users => "People and accounts: behaviour, risk, monitoring",
            Area::Applications => "Applications, databases and the sensitive resources they touch",
            Area::Resources => "Data resources: classification, access history and policy coverage",
            Area::Detections => "Detectors, rules, behavioral baselines and their proposals",
            Area::Policies => "Access policies, their scope and their violations",
            Area::Intelligence => "Relationships, ATT&CK, threat hunts and the environment model",
            Area::Map => "The whole host↔ip↔user↔case topology as a live 3D graph",
            Area::Learning => "Champion, challengers, feedback and dangerous misses",
            Area::DataSources => "Collectors, ingest health, source silence and freshness",
            Area::System => "Audit integrity, models, registry, backup, HA and air-gap",
        }
    }

    /// The capability key (from `/api/capabilities`) whose *disabled* state means
    /// this whole area is inert. `None` = always available. Used only to badge the
    /// nav item — server authorization is always independent.
    pub fn gating_feature(self) -> Option<&'static str> {
        match self {
            Area::Users | Area::Applications | Area::Resources => Some("app_audit"),
            Area::Policies => Some("policies"),
            _ => None,
        }
    }

    /// Landing view for this area.
    pub fn home(self) -> View {
        match self {
            Area::CommandCenter => View::CommandCenter,
            Area::Investigations => View::Investigations,
            Area::Audit => View::Audit,
            Area::Users => View::Users,
            Area::Applications => View::Applications,
            Area::Resources => View::Resources,
            Area::Detections => View::Detections,
            Area::Policies => View::Policies,
            Area::Intelligence => View::Intelligence,
            Area::Map => View::Map,
            Area::Learning => View::Learning,
            Area::DataSources => View::DataSources,
            Area::System => View::System,
        }
    }
}

/// The parsed path — which screen the URL names.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum View {
    CommandCenter,
    Investigations,
    Investigation(String),
    Audit,
    Users,
    User(String),
    Applications,
    Application(String),
    Resources,
    Resource(String),
    Detections,
    Policies,
    Policy(String),
    Intelligence,
    Map,
    Learning,
    DataSources,
    System,
    /// Universal entity deep-link (kind, name) — resolves to the right detail.
    Entity(String, String),
    /// Unknown path — a useful not-found state that keeps the URL.
    NotFound(String),
}

impl View {
    /// Which sidebar area owns this view (for the active highlight + breadcrumbs).
    pub fn area(&self) -> Option<Area> {
        Some(match self {
            View::CommandCenter => Area::CommandCenter,
            View::Investigations | View::Investigation(_) => Area::Investigations,
            View::Audit => Area::Audit,
            View::Users | View::User(_) => Area::Users,
            View::Applications | View::Application(_) => Area::Applications,
            View::Resources | View::Resource(_) => Area::Resources,
            View::Detections => Area::Detections,
            View::Policies | View::Policy(_) => Area::Policies,
            View::Intelligence => Area::Intelligence,
            View::Map => Area::Map,
            View::Learning => Area::Learning,
            View::DataSources => Area::DataSources,
            View::System => Area::System,
            View::Entity(..) => return None,
            View::NotFound(_) => return None,
        })
    }

    /// The URL path (no query string). Entity ids are percent-encoded.
    pub fn to_path(&self) -> String {
        match self {
            View::CommandCenter => "/".into(),
            View::Investigations => "/investigations".into(),
            View::Investigation(id) => format!("/investigations/{}", enc(id)),
            View::Audit => "/audit".into(),
            View::Users => "/users".into(),
            View::User(n) => format!("/users/{}", enc(n)),
            View::Applications => "/applications".into(),
            View::Application(n) => format!("/applications/{}", enc(n)),
            View::Resources => "/resources".into(),
            View::Resource(n) => format!("/resources/{}", enc(n)),
            View::Detections => "/detections".into(),
            View::Policies => "/policies".into(),
            View::Policy(id) => format!("/policies/{}", enc(id)),
            View::Intelligence => "/intelligence".into(),
            // NB: NOT "/map" — that path is the backend-served CodeVault 3D
            // sub-app (ServeDir mount); the SPA Map view iframes it.
            View::Map => "/topology".into(),
            View::Learning => "/learning".into(),
            View::DataSources => "/data-sources".into(),
            View::System => "/system".into(),
            View::Entity(k, n) => format!("/entity/{}/{}", enc(k), enc(n)),
            View::NotFound(p) => p.clone(),
        }
    }

    /// Parse a URL path (no query) into a `View`.
    pub fn from_path(path: &str) -> View {
        let segs: Vec<String> = path.split('/').filter(|s| !s.is_empty()).map(dec).collect();
        match segs.as_slice() {
            [] => View::CommandCenter,
            [a] if a == "investigations" => View::Investigations,
            [a, id] if a == "investigations" => View::Investigation(id.clone()),
            [a] if a == "audit" => View::Audit,
            [a] if a == "users" => View::Users,
            [a, n] if a == "users" => View::User(n.clone()),
            [a] if a == "applications" => View::Applications,
            [a, n] if a == "applications" => View::Application(n.clone()),
            [a] if a == "resources" => View::Resources,
            [a, id] if a == "resources" => View::Resource(id.clone()),
            [a] if a == "detections" => View::Detections,
            [a] if a == "policies" => View::Policies,
            [a, id] if a == "policies" => View::Policy(id.clone()),
            [a] if a == "intelligence" => View::Intelligence,
            [a] if a == "topology" => View::Map,
            [a] if a == "learning" => View::Learning,
            [a] if a == "data-sources" => View::DataSources,
            [a] if a == "system" => View::System,
            [a, k, n] if a == "entity" => View::Entity(k.clone(), n.clone()),
            _ => View::NotFound(path.to_string()),
        }
    }

    /// Human title for the breadcrumb tail / document title.
    pub fn title(&self) -> String {
        match self {
            View::Investigation(id) => format!("Investigation {}", short(id)),
            View::User(n) => n.clone(),
            View::Application(n) => n.clone(),
            View::Resource(id) => id.clone(),
            View::Policy(id) => id.clone(),
            View::Entity(k, n) => format!("{k}: {n}"),
            View::NotFound(_) => "Not found".into(),
            other => other
                .area()
                .map(|a| a.label().to_string())
                .unwrap_or_default(),
        }
    }
}

/// The router handle: the reactive current `View`, the reactive query string, and
/// the navigation primitives. Cloned into every component via context.
#[derive(Clone, Copy)]
pub struct Nav {
    pub view: RwSignal<View>,
    /// The current `location.search` (leading `?` stripped) — reactive, so a view
    /// that reads filters/tabs from the query re-renders when they change.
    pub query: RwSignal<String>,
}

impl Nav {
    pub fn new() -> Self {
        let (path, query) = current_location();
        Self {
            view: RwSignal::new(View::from_path(&path)),
            query: RwSignal::new(query),
        }
    }

    /// Navigate to a view (no query). Pushes a History entry and updates the
    /// reactive state.
    pub fn go(&self, view: View) {
        self.push(&view.to_path(), view, String::new());
    }

    /// Navigate to a view carrying a query string (already `key=val&…`, no `?`).
    pub fn go_query(&self, view: View, query: impl Into<String>) {
        let q = query.into();
        let url = if q.is_empty() {
            view.to_path()
        } else {
            format!("{}?{q}", view.to_path())
        };
        self.push(&url, view, q);
    }

    /// Replace only the query string, keeping the current view/path (a filter or
    /// tab change). Pushes a History entry so back undoes the filter.
    pub fn set_query(&self, query: impl Into<String>) {
        let q = query.into();
        let view = self.view.get_untracked();
        self.go_query(view, q);
    }

    /// Read one query parameter from the current (reactive) query string.
    pub fn param(&self, key: &str) -> Option<String> {
        param_of(&self.query.get(), key)
    }
    /// Non-reactive read (inside event handlers).
    pub fn param_untracked(&self, key: &str) -> Option<String> {
        param_of(&self.query.get_untracked(), key)
    }

    fn push(&self, url: &str, view: View, query: String) {
        if let Some(h) = web_sys::window().and_then(|w| w.history().ok()) {
            let _ = h.push_state_with_url(&wasm_bindgen::JsValue::NULL, "", Some(url));
        }
        self.view.set(view);
        self.query.set(query);
        // Return focus/scroll to the top of the main region on navigation.
        if let Some(doc) = web_sys::window().and_then(|w| w.document()) {
            if let Some(main) = doc.query_selector("main").ok().flatten() {
                main.set_scroll_top(0);
            }
        }
    }

    /// Re-sync from the actual location (called on `popstate`).
    pub fn sync_from_location(&self) {
        let (path, query) = current_location();
        self.view.set(View::from_path(&path));
        self.query.set(query);
    }
}

impl Default for Nav {
    fn default() -> Self {
        Self::new()
    }
}

/// `(pathname, search-without-`?`)` from the browser location.
fn current_location() -> (String, String) {
    let loc = web_sys::window().map(|w| w.location());
    let path = loc
        .as_ref()
        .and_then(|l| l.pathname().ok())
        .unwrap_or_else(|| "/".into());
    let query = loc
        .as_ref()
        .and_then(|l| l.search().ok())
        .unwrap_or_default()
        .trim_start_matches('?')
        .to_string();
    (path, query)
}

/// Parse one `key` out of a `k=v&k2=v2` query string (values percent-decoded).
pub fn param_of(query: &str, key: &str) -> Option<String> {
    query.split('&').find_map(|kv| {
        let (k, v) = kv.split_once('=')?;
        (k == key).then(|| dec(v))
    })
}

/// Build a `k=v&…` query string from pairs, skipping empties, percent-encoding.
pub fn build_query(pairs: &[(&str, String)]) -> String {
    pairs
        .iter()
        .filter(|(_, v)| !v.is_empty())
        .map(|(k, v)| format!("{k}={}", enc(v)))
        .collect::<Vec<_>>()
        .join("&")
}

/// Percent-encode a path/query component (path/query safe).
fn enc(v: &str) -> String {
    crate::api::enc(v)
}
/// Percent-decode via the browser (no url crate in the wasm bundle).
fn dec(v: &str) -> String {
    js_sys::decode_uri_component(v)
        .map(String::from)
        .unwrap_or_else(|_| v.to_string())
}
/// First 8 chars (short id).
fn short(v: &str) -> String {
    v.chars().take(8).collect()
}