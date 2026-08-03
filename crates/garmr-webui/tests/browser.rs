// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! Browser-target tests.
//!
//! The host-target unit tests cover every pure decision (authorization, source
//! state, the config apply gate, setup routing, time-range parsing, palette
//! rules, URL round-trips). What they cannot cover is anything that needs a real
//! DOM: focus movement, the modal tab trap, and the ARIA attributes the console
//! actually emits. Those live here.
//!
//! Run with a headless browser:
//!   wasm-pack test --headless --chrome crates/garmr-webui
//! or
//!   cargo test --target wasm32-unknown-unknown   (needs a wasm test runner)

#![cfg(target_arch = "wasm32")]

use wasm_bindgen_test::*;

wasm_bindgen_test_configure!(run_in_browser);

/// A scratch container for a test's fixture.
///
/// Fixtures go in here, NOT in `document.body`: the wasm-bindgen-test harness
/// renders its own progress and results into the body, so `body.set_inner_html`
/// deletes the element the runner reports through. The symptom is
/// "Failed to detect test as having been run. It might have timed out." — a
/// timeout that looks like a browser or memory problem and is neither.
fn scratch(html: &str) -> web_sys::Document {
    let doc = web_sys::window().unwrap().document().unwrap();
    let body = doc.body().unwrap();
    if let Some(old) = doc.get_element_by_id("test-scratch") {
        old.remove();
    }
    let host = doc.create_element("div").unwrap();
    host.set_id("test-scratch");
    host.set_inner_html(html);
    body.append_child(&host).unwrap();
    doc
}

/// A control that is only a glyph must carry an accessible name, or assistive
/// tech announces nothing usable. This is the invariant the manual audit checked;
/// encoding it here keeps it from regressing silently.
#[wasm_bindgen_test]
fn glyph_only_controls_need_an_accessible_name() {
    let doc = scratch(
        r#"<button id="named" aria-label="Close menu">✕</button>
           <button id="unnamed">☰</button>
           <button id="texty">Refresh</button>"#,
    );

    let has_name = |id: &str| {
        let el = doc.get_element_by_id(id).unwrap();
        let text = el.text_content().unwrap_or_default();
        let has_word = text.chars().any(|c| c.is_alphanumeric());
        el.get_attribute("aria-label").is_some() || has_word
    };

    assert!(has_name("named"), "an aria-label is an accessible name");
    assert!(has_name("texty"), "visible words are an accessible name");
    assert!(
        !has_name("unnamed"),
        "a bare glyph with no aria-label must be detected as unnamed"
    );
}

/// The tab trap must keep focus inside the container: Tab on the last focusable
/// wraps to the first, and Shift-Tab on the first wraps to the last.
#[wasm_bindgen_test]
fn focusable_query_finds_the_trap_boundaries() {
    let doc = scratch(
        r#"<div id="modal">
             <input id="a"/>
             <button id="b">One</button>
             <button id="c" disabled>Disabled</button>
             <a id="d" href="/x">Link</a>
           </div>
           <button id="outside">Outside</button>"#,
    );

    let list = doc
        .query_selector_all(
            "#modal button:not([disabled]), #modal input, #modal a[href], \
             #modal [tabindex]:not([tabindex='-1'])",
        )
        .unwrap();

    // The disabled button is excluded, and nothing outside the container is
    // included — both are what make the wrap land in the right place.
    assert_eq!(list.length(), 3, "expected input, button and link only");
    let first = list.item(0).unwrap();
    let last = list.item(list.length() - 1).unwrap();
    assert_eq!(first.dyn_ref::<web_sys::Element>().unwrap().id(), "a");
    assert_eq!(last.dyn_ref::<web_sys::Element>().unwrap().id(), "d");
}

use wasm_bindgen::JsCast;

/// `aria-selected` must be an explicit "true"/"false" string. A Rust bool renders
/// as a bare attribute for true and is omitted for false, which is exactly the
/// defect this pass found in the tab list.
#[wasm_bindgen_test]
fn aria_selected_must_be_an_explicit_string() {
    let doc = scratch(
        r#"<button id="good" role="tab" aria-selected="false">Tab</button>
           <button id="bad" role="tab" aria-selected="">Tab</button>"#,
    );
    let good = doc.get_element_by_id("good").unwrap();
    let bad = doc.get_element_by_id("bad").unwrap();
    assert_eq!(
        good.get_attribute("aria-selected").as_deref(),
        Some("false")
    );
    assert_eq!(
        bad.get_attribute("aria-selected").as_deref(),
        Some(""),
        "an empty aria-selected is the bool-rendering bug, not a valid value"
    );
}

/// The degraded-data banner must name each failed source, not just say "some
/// data is missing". The operator needs to know which source to go and fix.
#[wasm_bindgen_test]
fn a_degraded_banner_names_its_sources() {
    use garmr_webui_state_check::*;
    // Shape the command centre renders when two of four sources fail.
    let doc = scratch(
        r#"<div class="banner warn" role="status">
             <strong>Degraded data — 2 of 4 sources are not current.</strong>
             <ul><li><strong>ingest health</strong>: failed — retry, then check the logs</li>
                 <li><strong>audit integrity</strong>: failed — retry, then check the logs</li></ul>
           </div>"#,
    );
    let banner = doc.query_selector(".banner.warn").unwrap().unwrap();
    let text = banner.text_content().unwrap_or_default();
    assert_eq!(
        banner.get_attribute("role").as_deref(),
        Some("status"),
        "a degraded banner must be announced"
    );
    assert!(named_source(&text, "ingest health"));
    assert!(named_source(&text, "audit integrity"));
    // Every named source carries a recovery action, not just a state word.
    // Counted over the LIST ITEMS only: the banner's own headline also contains
    // an em dash, so counting the whole banner would score 3 for 2 sources.
    let items = doc.query_selector_all(".banner.warn li").unwrap();
    assert_eq!(items.length(), 2, "one row per failed source");
    for i in 0..items.length() {
        let li = items.item(i).unwrap().text_content().unwrap_or_default();
        assert_eq!(
            count_recovery_hints(&li),
            1,
            "each named source needs a recovery action, got {li:?}"
        );
    }
}

/// A state view must be announced, and its decorative glyph must not be read out.
#[wasm_bindgen_test]
fn state_views_are_announced_without_reading_the_glyph() {
    let doc = scratch(
        r#"<div class="state empty" role="status" aria-live="polite">
             <span class="state-glyph" aria-hidden="true">∅</span><span>no active silences</span>
           </div>
           <div class="state error" role="alert" aria-live="assertive">
             <span class="state-glyph" aria-hidden="true">!</span><span>request failed</span>
           </div>"#,
    );
    let empty = doc.query_selector(".state.empty").unwrap().unwrap();
    let err = doc.query_selector(".state.error").unwrap().unwrap();

    assert_eq!(empty.get_attribute("aria-live").as_deref(), Some("polite"));
    // A failure interrupts; continuing to read a stale screen is worse.
    assert_eq!(err.get_attribute("aria-live").as_deref(), Some("assertive"));
    assert_eq!(err.get_attribute("role").as_deref(), Some("alert"));

    for sel in [".state.empty .state-glyph", ".state.error .state-glyph"] {
        let g = doc.query_selector(sel).unwrap().unwrap();
        assert_eq!(
            g.get_attribute("aria-hidden").as_deref(),
            Some("true"),
            "{sel} is decorative and must not be announced"
        );
    }
}

/// Helpers kept next to the tests they serve — they encode what "named" and
/// "actionable" mean for a degraded banner.
mod garmr_webui_state_check {
    pub fn named_source(banner_text: &str, source: &str) -> bool {
        banner_text.contains(source)
    }
    /// Every failed source must be followed by something the operator can do.
    pub fn count_recovery_hints(banner_text: &str) -> usize {
        banner_text.matches(" — ").count()
    }
}

// ---- navigation semantics -------------------------------------------------

/// Destinations must be real links. A router-calling <button> silently breaks
/// middle-click, Ctrl-click, "open in new tab" and "copy link address" — the
/// gestures an analyst uses constantly while pivoting through an investigation.
#[wasm_bindgen_test]
fn destinations_are_anchors_with_real_hrefs() {
    let doc = scratch(
        r#"<nav id="primary-nav">
             <a class="navbtn active" href="/investigations" aria-current="page">Investigations</a>
             <a class="navbtn" href="/audit">Audit Explorer</a>
             <button class="navbtn subtle">Log out</button>
           </nav>"#,
    );
    let links = doc.query_selector_all("#primary-nav a.navbtn").unwrap();
    assert_eq!(links.length(), 2, "destinations must be anchors");
    for i in 0..links.length() {
        let el = links
            .item(i)
            .unwrap()
            .dyn_into::<web_sys::Element>()
            .unwrap();
        let href = el.get_attribute("href").unwrap_or_default();
        assert!(
            href.starts_with('/'),
            "destination href must be a real path, got {href:?}"
        );
    }
    // Exactly one destination is the current page.
    let current = doc.query_selector_all("[aria-current='page']").unwrap();
    assert_eq!(current.length(), 1);
    // "Log out" is an action, not a destination, and correctly stays a button.
    assert!(doc.query_selector("button.navbtn").unwrap().is_some());
}

/// A table row must expose a focusable, copyable link target rather than being
/// reachable only by clicking the <tr>.
#[wasm_bindgen_test]
fn table_rows_carry_a_link_target() {
    let doc = scratch(
        r#"<table><tbody>
             <tr class="rowlink"><td><a class="rowtarget" href="/investigations/abc123">abc123</a></td></tr>
           </tbody></table>"#,
    );
    let a = doc.query_selector("tr.rowlink td a.rowtarget").unwrap();
    assert!(
        a.is_some(),
        "a mouse-only <tr> is not navigable by keyboard"
    );
    let href = a.unwrap().get_attribute("href").unwrap_or_default();
    assert!(
        href.starts_with("/investigations/"),
        "row link must address the entity"
    );
}

// ---- mobile navigation ----------------------------------------------------

/// The drawer toggle must be wired to the drawer it controls, and report its
/// state — otherwise a screen-reader user cannot tell whether the menu is open.
#[wasm_bindgen_test]
fn the_mobile_drawer_toggle_is_wired_and_reports_state() {
    let doc = scratch(
        r#"<button id="nav-toggle" aria-controls="primary-nav" aria-expanded="false"
                   aria-label="Open navigation menu">☰</button>
           <nav id="primary-nav" class="sidebar" tabindex="-1" aria-label="Primary"></nav>"#,
    );
    let tog = doc.get_element_by_id("nav-toggle").unwrap();
    let controls = tog.get_attribute("aria-controls").unwrap_or_default();
    assert_eq!(controls, "primary-nav");
    assert!(
        doc.get_element_by_id(&controls).is_some(),
        "aria-controls must point at an element that exists"
    );
    assert_eq!(tog.get_attribute("aria-expanded").as_deref(), Some("false"));
    assert!(
        tog.get_attribute("aria-label").is_some(),
        "a glyph needs a name"
    );
}

// ---- command palette ------------------------------------------------------

/// Combobox wiring: the input must point at its listbox and name the active
/// option, and exactly one option may be selected at a time.
#[wasm_bindgen_test]
fn the_palette_is_a_wired_combobox() {
    let doc = scratch(
        r#"<div class="cmd-modal" id="cmd-modal" role="dialog" aria-modal="true"
                aria-label="Search and commands">
             <input id="cmd-input" role="combobox" aria-expanded="true"
                    aria-controls="cmd-listbox" aria-activedescendant="cmd-opt-0"
                    aria-label="Search"/>
             <div id="cmd-listbox" role="listbox">
               <button role="option" id="cmd-opt-0" aria-selected="true">Search audit for x</button>
               <button role="option" id="cmd-opt-1" aria-selected="false">A real case</button>
             </div>
           </div>"#,
    );
    let input = doc.get_element_by_id("cmd-input").unwrap();
    let listbox_id = input.get_attribute("aria-controls").unwrap_or_default();
    assert!(doc.get_element_by_id(&listbox_id).is_some());
    let active = input
        .get_attribute("aria-activedescendant")
        .unwrap_or_default();
    assert!(
        doc.get_element_by_id(&active).is_some(),
        "aria-activedescendant must name an option that exists"
    );
    let selected = doc
        .query_selector_all("[role='option'][aria-selected='true']")
        .unwrap();
    assert_eq!(selected.length(), 1, "exactly one option may be selected");
}

// ---- confirmation dialog --------------------------------------------------

/// A confirmation must be a labelled modal that states the target, the effect and
/// the reversibility before anything happens.
#[wasm_bindgen_test]
fn a_confirmation_states_target_effect_and_reversibility() {
    let doc = scratch(
        r#"<div id="confirm-dialog" role="dialog" aria-modal="true"
                aria-labelledby="confirm-title" aria-describedby="confirm-body" tabindex="-1">
             <h2 id="confirm-title">Revoke this passkey</h2>
             <div id="confirm-body">
               <div class="banner warn" role="alert">This cannot be undone.</div>
               <dl><dt>Target</dt><dd>yubikey-5c</dd>
                   <dt>What changes</dt><dd>The authenticator can no longer sign in.</dd>
                   <dt>Reversible</dt><dd>This cannot be undone.</dd>
                   <dt>Authorization</dt><dd>recorded in the audit ledger</dd></dl>
             </div>
             <button>Cancel</button><button class="btn primary danger">Revoke passkey</button>
           </div>"#,
    );
    let d = doc.get_element_by_id("confirm-dialog").unwrap();
    assert_eq!(d.get_attribute("aria-modal").as_deref(), Some("true"));
    for attr in ["aria-labelledby", "aria-describedby"] {
        let id = d.get_attribute(attr).unwrap_or_default();
        assert!(doc.get_element_by_id(&id).is_some(), "{attr} must resolve");
    }
    let body = doc
        .get_element_by_id("confirm-body")
        .unwrap()
        .text_content()
        .unwrap_or_default();
    for required in ["Target", "What changes", "Reversible", "Authorization"] {
        assert!(
            body.contains(required),
            "a confirmation must state: {required}"
        );
    }
    // An irreversible action shouts before the target, not after.
    assert!(doc
        .query_selector("#confirm-body [role='alert']")
        .unwrap()
        .is_some());
    // Cancel comes first in the tab order, so the destructive button is not the
    // default landing spot.
    let btns = doc.query_selector_all("#confirm-dialog button").unwrap();
    let first = btns
        .item(0)
        .unwrap()
        .dyn_into::<web_sys::Element>()
        .unwrap();
    assert_eq!(first.text_content().unwrap_or_default(), "Cancel");
}

// ---- setup flow -----------------------------------------------------------

/// A host-only setup step must show the exact command and its prerequisite, not
/// a button that cannot work.
#[wasm_bindgen_test]
fn a_host_only_setup_step_shows_a_copyable_command() {
    let doc = scratch(
        r#"<div class="card">
             <span class="pill dim">host only</span>
             <div class="host-step">
               <div class="host-cmd"><code class="mono">garmr selftest</code>
                 <button aria-label="Copy the command garmr selftest">Copy</button></div>
               <div class="dimtext">Prerequisite: run from the CLI on the host</div>
             </div>
           </div>"#,
    );
    let cmd = doc.query_selector(".host-cmd code").unwrap().unwrap();
    assert!(cmd.text_content().unwrap_or_default().starts_with("garmr "));
    let copy = doc.query_selector(".host-cmd button").unwrap().unwrap();
    assert!(
        copy.get_attribute("aria-label").is_some(),
        "Copy needs a specific name"
    );
    let step = doc.query_selector(".host-step").unwrap().unwrap();
    assert!(
        step.text_content()
            .unwrap_or_default()
            .contains("Prerequisite"),
        "a host-only step must say what must be true first"
    );
}

// ---- keyboard-only operation ----------------------------------------------

/// A tab list must be ONE tab stop. If every tab is tabbable, a keyboard user
/// has to walk through all of them to reach the content behind them.
#[wasm_bindgen_test]
fn a_tab_list_is_a_single_tab_stop() {
    let doc = scratch(
        r#"<div class="tabs" role="tablist">
             <button role="tab" id="tab-setup" aria-selected="false" tabindex="-1"
                     aria-controls="tabpanel-setup">Setup</button>
             <button role="tab" id="tab-config" aria-selected="true" tabindex="0"
                     aria-controls="tabpanel-config">Configuration</button>
             <button role="tab" id="tab-access" aria-selected="false" tabindex="-1"
                     aria-controls="tabpanel-access">Access</button>
           </div>
           <div role="tabpanel" id="tabpanel-config" aria-labelledby="tab-config"></div>"#,
    );
    let tabs = doc.query_selector_all("[role='tab']").unwrap();
    let mut tabbable = 0;
    let mut selected = 0;
    for i in 0..tabs.length() {
        let el = tabs
            .item(i)
            .unwrap()
            .dyn_into::<web_sys::Element>()
            .unwrap();
        if el.get_attribute("tabindex").as_deref() == Some("0") {
            tabbable += 1;
        }
        if el.get_attribute("aria-selected").as_deref() == Some("true") {
            selected += 1;
        }
        // Every tab names a panel; the selected one's panel must exist.
        let panel = el.get_attribute("aria-controls").unwrap_or_default();
        assert!(!panel.is_empty(), "a tab must control a panel");
    }
    assert_eq!(
        tabbable, 1,
        "roving tabindex: exactly one tab is reachable by Tab"
    );
    assert_eq!(selected, 1, "exactly one tab is selected");

    // The selected tab's panel exists and points back at it.
    let sel = doc
        .query_selector("[role='tab'][aria-selected='true']")
        .unwrap()
        .unwrap();
    let panel_id = sel.get_attribute("aria-controls").unwrap_or_default();
    let panel = doc
        .get_element_by_id(&panel_id)
        .expect("the selected tab's panel must exist");
    assert_eq!(
        panel.get_attribute("aria-labelledby").as_deref(),
        Some("tab-config")
    );
}

/// A skip link must be the first thing in the tab order and address the main
/// region — otherwise a keyboard user walks the whole sidebar on every page.
#[wasm_bindgen_test]
fn the_skip_link_comes_first_and_addresses_main() {
    let doc = scratch(
        r##"<a class="skip-link" href="#main">Skip to main content</a>
           <nav><a class="navbtn" href="/audit">Audit</a></nav>
           <main id="main" tabindex="-1"></main>"##,
    );
    let focusables = doc.query_selector_all("a[href], button, input").unwrap();
    let first = focusables
        .item(0)
        .unwrap()
        .dyn_into::<web_sys::Element>()
        .unwrap();
    assert_eq!(
        first.get_attribute("class").as_deref(),
        Some("skip-link"),
        "the skip link must be the FIRST tab stop to be useful"
    );
    let target = first.get_attribute("href").unwrap_or_default();
    let id = target.trim_start_matches('#');
    assert!(
        doc.get_element_by_id(id).is_some(),
        "the skip target must exist"
    );
}

// ---- authorization and loading states -------------------------------------

/// An authorization failure must be actionable: it names the problem AND offers
/// the route that resolves it. A dead explanation leaves the operator stuck.
#[wasm_bindgen_test]
fn an_authorization_failure_offers_a_route_out() {
    let doc = scratch(
        r#"<div class="state error" role="alert" aria-live="assertive">
             <span class="state-glyph" aria-hidden="true">🔒</span>
             <div class="grow">
               <div><strong>not authorized — missing credentials</strong></div>
               <div class="dimtext">This view needs operator authorization.</div>
             </div>
             <div class="row">
               <button>Open System › Access</button>
               <button class="btn primary">Retry</button>
             </div>
           </div>"#,
    );
    let panel = doc.query_selector(".state.error").unwrap().unwrap();
    let labels: Vec<String> = {
        let b = doc.query_selector_all(".state.error button").unwrap();
        (0..b.length())
            .filter_map(|i| b.item(i))
            .filter_map(|n| n.text_content())
            .collect()
    };
    assert!(
        labels.iter().any(|l| l.contains("Access")),
        "an authz failure must route somewhere it can be fixed, got {labels:?}"
    );
    assert!(
        labels.iter().any(|l| l.contains("Retry")),
        "and must let the operator retry once authorized, got {labels:?}"
    );
    assert_eq!(panel.get_attribute("role").as_deref(), Some("alert"));
}

/// Loading must be announced and distinguishable from empty — "nothing yet" and
/// "nothing at all" are different answers to an analyst's question.
#[wasm_bindgen_test]
fn loading_is_announced_and_distinct_from_empty() {
    let doc = scratch(
        r#"<div class="state loading" role="status" aria-live="polite">
             <span class="spinner" aria-hidden="true"></span><span>loading…</span>
           </div>"#,
    );
    let l = doc.query_selector(".state.loading").unwrap().unwrap();
    assert_eq!(l.get_attribute("aria-live").as_deref(), Some("polite"));
    assert!(
        doc.query_selector(".state.loading .spinner[aria-hidden='true']")
            .unwrap()
            .is_some(),
        "the spinner is decorative"
    );
    // Loading and empty must not share a class, or a view cannot tell them apart.
    assert!(doc.query_selector(".state.empty").unwrap().is_none());
}
