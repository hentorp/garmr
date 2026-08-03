// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! Task-oriented information architecture + real URL routing.
//!
//! The console is a client-rendered SPA, but every meaningful state has a stable
//! URL: navigating pushes a History entry, browser back/forward and a hard
//! refresh all restore the same view (the server serves `index.html` for any
//! unmatched path, so a deep link cold-loads correctly). Filters, the active
//! sub-tab and the search query live in the query string, so a shared link
//! reproduces the exact screen. The global time range rides in the query too (as
//! `t=`) and is the one parameter [`Nav::go`] carries across areas, so narrowing
//! to a window and pivoting elsewhere keeps that window. Sensitive values are
//! never placed in the URL.
//!
//! [`View`] is the parsed *path* (which area + which entity). Query parameters
//! are kept separately (the reactive [`Nav::query`] signal) so a filter change
//! re-renders without changing the `View`.

use leptos::prelude::*;
use wasm_bindgen::JsCast;

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
    DataSources,
    System,
}

impl Area {
    pub const ALL: [Area; 11] = [
        Area::CommandCenter,
        Area::Investigations,
        Area::Audit,
        Area::Users,
        Area::Applications,
        Area::Resources,
        Area::Detections,
        Area::Policies,
        Area::Intelligence,
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
            Area::Detections => {
                "Detectors, rules, baselines, silences — and the champion/challenger learning loop"
            }
            Area::Policies => "Access policies, their scope and their violations",
            Area::Intelligence => {
                "Relationships and the 3D map, ATT&CK coverage, threat hunts and the environment model"
            }
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
            // Legacy paths from when these were top-level areas; normalize_legacy
            // also maps them to the right sub-tab when the query is empty.
            [a] if a == "topology" => View::Intelligence,
            [a] if a == "learning" => View::Detections,
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
        let (path, query) = normalize_legacy(&path, query);
        Self {
            view: RwSignal::new(View::from_path(&path)),
            query: RwSignal::new(query),
        }
    }

    /// Navigate to a view, dropping the previous view's filters but CARRYING the
    /// global time range.
    ///
    /// The range is the one query parameter that is not a property of the view
    /// being left: an analyst who narrows to a two-hour window and then opens
    /// another area means to stay in that window. Dropping it silently widened
    /// the investigation back out — and left the URL unshareable.
    pub fn go(&self, view: View) {
        let carried = param_of(&self.query.get_untracked(), crate::timerange::PARAM)
            .map(|v| format!("{}={v}", crate::timerange::PARAM))
            .unwrap_or_default();
        self.go_query(view, carried);
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
        // Return focus AND scroll to the top of the main region on navigation.
        // Without the focus move, a keyboard user who activates a nav link stays
        // parked in the sidebar and a screen reader never announces the new page.
        if let Some(doc) = web_sys::window().and_then(|w| w.document()) {
            if let Some(main) = doc.query_selector("main").ok().flatten() {
                main.set_scroll_top(0);
                if let Some(el) = main.dyn_ref::<web_sys::HtmlElement>() {
                    let _ = el.focus();
                }
            }
        }
    }

    /// Re-sync from the actual location (called on `popstate`).
    pub fn sync_from_location(&self) {
        let (path, query) = current_location();
        let (path, query) = normalize_legacy(&path, query);
        self.view.set(View::from_path(&path));
        self.query.set(query);
    }
}

/// Map legacy top-level paths (from when Map and Learning were their own areas)
/// onto the merged area + sub-tab, so old bookmarks land on the same content.
fn normalize_legacy(path: &str, query: String) -> (String, String) {
    match path.trim_end_matches('/') {
        "/topology" => (
            "/intelligence".into(),
            if query.is_empty() {
                "tab=map".into()
            } else {
                query
            },
        ),
        "/learning" => (
            "/detections".into(),
            if query.is_empty() {
                "tab=learning".into()
            } else {
                query
            },
        ),
        _ => (path.to_string(), query),
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
pub(crate) fn param_of(query: &str, key: &str) -> Option<String> {
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
/// Percent-decode one path segment (public wrapper over [`dec`]).
pub(crate) fn decode_path_segment(v: &str) -> String {
    dec(v)
}

/// Percent-decode a path/query component.
///
/// Implemented in plain Rust rather than via `js_sys::decode_uri_component` so
/// the routing layer has no JS dependency and can therefore be unit-tested on the
/// host target — the round-trip between `to_path` and `from_path` is exactly the
/// kind of thing that silently breaks a deep link, so it needs tests that run in
/// CI without a browser. Invalid escapes are left verbatim, matching the
/// browser's lenient behaviour rather than dropping characters.
fn dec(v: &str) -> String {
    let b = v.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            let hex = |c: u8| match c {
                b'0'..=b'9' => Some(c - b'0'),
                b'a'..=b'f' => Some(c - b'a' + 10),
                b'A'..=b'F' => Some(c - b'A' + 10),
                _ => None,
            };
            if let (Some(h), Some(l)) = (hex(b[i + 1]), hex(b[i + 2])) {
                out.push(h * 16 + l);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8(out).unwrap_or_else(|_| v.to_string())
}
/// First 8 chars (short id).
fn short(v: &str) -> String {
    v.chars().take(8).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every view must survive the round trip its URL implies: a deep link that
    /// cold-loads has to land on exactly the screen that produced it.
    #[test]
    fn every_view_round_trips_through_its_path() {
        let views = [
            View::CommandCenter,
            View::Investigations,
            View::Investigation("1da42587-ef93-4efc".into()),
            View::Audit,
            View::Users,
            View::User("root@pam".into()),
            View::Applications,
            View::Application("pve-daemon".into()),
            View::Resources,
            View::Resource("res-1".into()),
            View::Detections,
            View::Policies,
            View::Policy("pol1".into()),
            View::Intelligence,
            View::DataSources,
            View::System,
            View::Entity("host".into(), "pve".into()),
        ];
        for v in views {
            let path = v.to_path();
            assert_eq!(View::from_path(&path), v, "path {path} did not round-trip");
        }
    }

    /// Ids that contain URL-significant characters must survive encoding, or a
    /// deep link to them silently resolves to the wrong entity.
    #[test]
    fn awkward_entity_ids_survive_the_url() {
        for raw in [
            "user with spaces",
            "domain\\user",
            "a/b",
            "q?x=1",
            "hash#frag",
            "unicode-ÅÄÖ",
            "plus+sign",
            "percent%20already",
        ] {
            let v = View::User(raw.to_string());
            let path = v.to_path();
            assert!(
                !path[7..].contains('/'),
                "unescaped separator in {path} for {raw}"
            );
            assert_eq!(View::from_path(&path), v, "{raw} did not round-trip");
        }
    }

    #[test]
    fn an_unknown_path_becomes_a_not_found_that_keeps_the_url() {
        let v = View::from_path("/no/such/place");
        assert_eq!(v, View::NotFound("/no/such/place".into()));
        // The URL is preserved so the address bar keeps naming what was asked for.
        assert_eq!(v.to_path(), "/no/such/place");
    }

    #[test]
    fn every_area_home_belongs_to_that_area() {
        for a in Area::ALL {
            assert_eq!(
                a.home().area(),
                Some(a),
                "{a:?}'s home view reports a different area"
            );
        }
    }

    #[test]
    fn detail_views_belong_to_their_list_area() {
        assert_eq!(
            View::Investigation("x".into()).area(),
            Some(Area::Investigations)
        );
        assert_eq!(View::User("x".into()).area(), Some(Area::Users));
        assert_eq!(
            View::Application("x".into()).area(),
            Some(Area::Applications)
        );
        assert_eq!(View::Resource("x".into()).area(), Some(Area::Resources));
        assert_eq!(View::Policy("x".into()).area(), Some(Area::Policies));
    }

    // ---- query-state parsing ------------------------------------------------

    #[test]
    fn query_parameters_are_read_by_exact_key() {
        let q = "tab=access&mode=text&q=ssh";
        assert_eq!(param_of(q, "tab"), Some("access".into()));
        assert_eq!(param_of(q, "mode"), Some("text".into()));
        assert_eq!(param_of(q, "q"), Some("ssh".into()));
        assert_eq!(param_of(q, "missing"), None);
        // A key must not match a prefix of another key.
        assert_eq!(param_of("tabby=1", "tab"), None);
    }

    #[test]
    fn query_parsing_survives_odd_shapes() {
        assert_eq!(param_of("", "tab"), None);
        assert_eq!(param_of("tab=", "tab"), Some(String::new()));
        assert_eq!(param_of("&&tab=x&&", "tab"), Some("x".into()));
        assert_eq!(param_of("flag", "flag"), None, "a bare key has no value");
        // First occurrence wins, deterministically.
        assert_eq!(param_of("t=1&t=2", "t"), Some("1".into()));
    }

    #[test]
    fn a_title_exists_for_every_view() {
        for v in [
            View::CommandCenter,
            View::Investigations,
            View::Investigation("abcdef1234".into()),
            View::Audit,
            View::System,
            View::NotFound("/x".into()),
        ] {
            assert!(!v.title().trim().is_empty(), "{v:?} has no title");
        }
    }
}
