// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! The design-system primitives — one place for the reserved severity/status
//! vocabulary, evidence/audit references, and the non-happy-path states (empty,
//! error, loading, disabled, degraded). Every view composes these so the same
//! concept looks the same everywhere and colour is always paired with a text
//! label (never colour-alone — WCAG 1.4.1).

use leptos::prelude::*;
use wasm_bindgen::JsCast;

use std::rc::Rc;

use crate::caps::FeatureState;
use crate::{api, status};

/// A labelled status pill (reserved class + its own text). The atom of the
/// severity/status/confidence system.
pub fn pill(class: &str, label: impl Into<String>) -> AnyView {
    let label = label.into();
    view! { <span class=format!("pill {class}")>{label}</span> }.into_any()
}

/// Severity → labelled pill (critical/high/warning/info/…).
pub fn sev_badge(sev: &str) -> AnyView {
    let s = if sev.is_empty() { "—" } else { sev };
    pill(status::severity_class(sev), s.to_string())
}

/// Investigation / action lifecycle state → labelled pill, with the raw value
/// humanised so snake_case (e.g. "needs_human") never shows.
pub fn state_badge(state: &str) -> AnyView {
    pill(status::state_class(state), status::humanize(state))
}

/// A confidence indicator: a bar plus its own percentage text.
pub fn confidence(v: f64) -> AnyView {
    let pct = (v.clamp(0.0, 1.0) * 100.0).round() as i64;
    view! {
        <span class="conf" title=format!("confidence {pct}%")>
            <span class="bar"><i style=format!("width:{pct}%")></i></span>
            <span class="mono dimtext">{format!("{pct}%")}</span>
        </span>
    }
    .into_any()
}

/// An audit-ledger reference (a short token that ties an action to the
/// tamper-evident ledger). Rendered mono + tagged so it reads as evidence.
pub fn audit_ref(id: &str) -> AnyView {
    if id.is_empty() {
        return view! { <span class="dimtext">"no audit token"</span> }.into_any();
    }
    let short: String = id.chars().take(16).collect();
    view! {
        <span class="auditref" title=format!("audit ledger record {id}")>
            <span class="auditref-k">"audit"</span>
            <span class="mono">{short}</span>
        </span>
    }
    .into_any()
}

/// The empty state — no data (distinct from an error).
pub fn empty(msg: impl Into<String>) -> AnyView {
    let msg = msg.into();
    // A polite live region: a screen-reader user hears "no results" when a filter
    // empties a list, instead of silence they have to go looking for.
    view! { <div class="state empty" role="status" aria-live="polite">
    <span class="state-glyph" aria-hidden="true">"∅"</span><span>{msg}</span></div> }
    .into_any()
}

/// The error state.
pub fn error_box(msg: impl Into<String>) -> AnyView {
    let msg = api::clean(&msg.into());
    // assertive: a failure interrupts, because continuing to read a stale screen
    // is worse than the interruption.
    view! { <div class="state error" role="alert" aria-live="assertive">
    <span class="state-glyph" aria-hidden="true">"!"</span><span>{msg}</span></div> }
    .into_any()
}

/// The loading state (skeleton-ish).
pub fn loading(msg: impl Into<String>) -> AnyView {
    let msg = msg.into();
    view! { <div class="state loading" role="status" aria-live="polite">
    <span class="spinner" aria-hidden="true"></span><span>{msg}</span></div> }
    .into_any()
}

/// A feature-disabled / not-configured panel: explains exactly what is missing
/// rather than showing a broken control. Used whenever a capability is off.
pub fn disabled_panel(title: &str, fs: &FeatureState) -> AnyView {
    let title = title.to_string();
    let label = fs.label().to_string();
    let cls = fs.class();
    let reason = fs
        .reason
        .clone()
        .unwrap_or_else(|| "This capability is not available on this deployment.".into());
    view! {
        <div class="disabled-panel">
            <div class="row">
                <strong>{title}</strong>
                {pill(cls, label)}
            </div>
            <p class="dimtext">{reason}</p>
        </div>
    }
    .into_any()
}

/// A small metric tile (label + big value + optional status pill + optional
/// click). The dashboard atom.
pub fn metric(
    k: impl Into<String>,
    v: impl Into<String>,
    cls: &'static str,
    on_click: Option<Box<dyn Fn()>>,
) -> AnyView {
    let k = k.into();
    let v = v.into();
    let label = match cls {
        "pass" => "ok",
        "warn" => "watch",
        "bad" => "attention",
        _ => "—",
    };
    let inner = move || {
        view! {
            <div class="k">{k.clone()}</div>
            <div class="v">{v.clone()}</div>
            <div class="foot"><span class=format!("pill {cls}")>{label}</span></div>
        }
    };
    match on_click.map(Rc::<dyn Fn()>::from) {
        Some(cb) => {
            let cb_kb = cb.clone();
            // A clickable tile is a real button to assistive tech: focusable and
            // operable with Enter/Space, not a mouse-only div (WCAG 2.1.1).
            view! {
                <div class="tile click" role="button" tabindex="0"
                    on:click=move |_| { let f = &*cb; f(); }
                    on:keydown=move |ev| {
                        let key = ev.key();
                        if key == "Enter" || key == " " {
                            ev.prevent_default();
                            let f = &*cb_kb; f();
                        }
                    }>
                    {inner()}
                </div>
            }
            .into_any()
        }
        None => view! { <div class="tile">{inner()}</div> }.into_any(),
    }
}

/// A page header: the area/view title + its one-line purpose, so the screen is
/// self-describing.
pub fn page_header(title: impl Into<String>, blurb: impl Into<String>) -> AnyView {
    let title = title.into();
    let blurb = blurb.into();
    view! {
        <div class="page-header">
            <h1>{title}</h1>
            <div class="sub">{blurb}</div>
        </div>
    }
    .into_any()
}

/// A key/value detail row list from pairs.
pub fn kv_list(pairs: Vec<(&'static str, String)>) -> AnyView {
    view! {
        <dl class="fields">
            {pairs.into_iter().map(|(k, v)| view! {
                <dt>{k}</dt><dd>{api::clean(&v)}</dd>
            }).collect_view()}
        </dl>
    }
    .into_any()
}

/// A degraded/info banner (e.g. "the model is fenced by air-gap").
pub fn banner(class: &str, msg: impl Into<String>) -> AnyView {
    let msg = msg.into();
    view! { <div class=format!("banner {class}")>{msg}</div> }.into_any()
}

/// A small "?" affordance that reveals a one- or two-sentence explanation on
/// hover, keyboard focus, or tap. The help text is *also* the trigger's
/// accessible name, so screen-reader users get the explanation without needing
/// the visual bubble, and it is never the only place the information lives. For
/// richer help (a heading, consequences, a docs link) use [`InfoPopover`].
pub fn help_tip(text: impl Into<String>) -> AnyView {
    let text = text.into();
    let name = text.clone();
    view! {
        <button type="button" class="helptip" aria-label=name>
            <span class="helptip-glyph" aria-hidden="true">"?"</span>
            <span class="helptip-bubble" role="tooltip" aria-hidden="true">{text}</span>
        </button>
    }
    .into_any()
}

/// A click/keyboard-activated help popover: an "ⓘ" trigger that opens a small
/// dialog with a heading, an explanation, and an optional docs link. Closes on
/// Escape or an outside click, moves focus into the dialog on open, and restores
/// nothing the caller relies on. Use for explanations that need more than a
/// sentence — consequences, security implications, dependencies.
#[component]
pub fn InfoPopover(
    #[prop(into)] heading: String,
    #[prop(into)] body: String,
    #[prop(optional)] doc: Option<String>,
) -> impl IntoView {
    let open = RwSignal::new(false);
    let close_ref = NodeRef::<leptos::html::Button>::new();
    // Move focus onto the close button when the dialog opens, so keyboard and
    // screen-reader users land inside it and Escape/Tab behave predictably.
    Effect::new(move |_| {
        if open.get() {
            if let Some(btn) = close_ref.get() {
                let _ = btn.focus();
            }
        }
    });
    let head_btn = heading.clone();
    view! {
        <span class="infopop-wrap">
            <button type="button" class="helpbtn" aria-haspopup="dialog"
                aria-expanded=move || open.get().to_string()
                aria-label=format!("More about {head_btn}")
                on:click=move |_| open.update(|o| *o = !*o)>
                <span aria-hidden="true">"ⓘ"</span>
            </button>
            {move || {
                if !open.get() {
                    return None;
                }
                let (h, b, d) = (heading.clone(), body.clone(), doc.clone());
                let h_label = h.clone();
                Some(view! {
                    <div class="infopop-scrim" on:click=move |_| open.set(false)></div>
                    <div class="infopop" role="dialog" aria-label=h_label tabindex="-1"
                        on:keydown=move |ev| { if ev.key() == "Escape" { open.set(false); } }>
                        <div class="infopop-head">
                            <strong>{h}</strong>
                            <button type="button" class="iconbtn sm" node_ref=close_ref
                                aria-label="Close" on:click=move |_| open.set(false)>"✕"</button>
                        </div>
                        <p class="infopop-body">{b}</p>
                        {d.map(|href| view! {
                            <a class="infopop-doc" href=href target="_blank" rel="noopener">"Documentation ↗"</a>
                        })}
                    </div>
                })
            }}
        </span>
    }
}

/// A modal confirmation for a consequential action.
///
/// Rendered inline by the view that owns the action, driven by a local
/// `RwSignal<Option<ConfirmSpec>>`: setting the signal opens the dialog, and the
/// operator's answer runs `on_confirm` or simply clears it. Keeping the callback
/// at the call site (rather than storing it in a global signal) avoids boxing a
/// non-`Send` closure into shared state.
///
/// Dialog semantics are the point: `role="dialog"` + `aria-modal`, a label tied
/// to the heading, focus moved in on open and restored to the invoking element on
/// close, Tab cycling confined to the dialog, and Escape to cancel. The most
/// disruptive actions additionally require the operator to type an exact phrase,
/// so muscle memory cannot carry them through.
#[component]
pub fn ConfirmDialog<F>(
    spec: RwSignal<Option<crate::confirm::ConfirmSpec>>,
    on_confirm: F,
) -> impl IntoView
where
    F: Fn() + Copy + Send + Sync + 'static,
{
    let typed = RwSignal::new(String::new());
    // Remember what had focus so it can be handed back on close.
    let opener = StoredValue::new_local(None::<web_sys::HtmlElement>);

    Effect::new(move |_| {
        let open = spec.get().is_some();
        let doc = web_sys::window().and_then(|w| w.document());
        if open {
            if let Some(d) = doc.as_ref() {
                opener.set_value(
                    d.active_element()
                        .and_then(|e| e.dyn_into::<web_sys::HtmlElement>().ok()),
                );
                if let Some(el) = d
                    .get_element_by_id("confirm-dialog")
                    .and_then(|e| e.dyn_into::<web_sys::HtmlElement>().ok())
                {
                    let _ = el.focus();
                }
            }
            typed.set(String::new());
        } else if let Some(el) = opener.get_value() {
            let _ = el.focus();
        }
    });

    let close = move || spec.set(None);

    view! {
        {move || spec.get().map(|s| {
            let ready = { let s = s.clone(); move || s.typed_input_ok(&typed.get()) };
            let phrase = s.typed_phrase.clone();
            let confirm_cls = if s.danger { "btn primary danger" } else { "btn primary" };
            view! {
                <div class="cmd-scrim confirm-scrim" on:click=move |_| close()></div>
                <div class="confirm-modal" id="confirm-dialog" tabindex="-1"
                    role="dialog" aria-modal="true" aria-labelledby="confirm-title"
                    aria-describedby="confirm-body"
                    on:keydown=move |ev: web_sys::KeyboardEvent| {
                        if ev.key() == "Escape" { ev.stop_propagation(); close(); }
                        // Confine Tab to the dialog: a modal the keyboard can walk
                        // out of is not modal.
                        if ev.key() == "Tab" {
                            if let Some(d) = web_sys::window().and_then(|w| w.document()) {
                                let f = d.query_selector_all(
                                    "#confirm-dialog button:not([disabled]), #confirm-dialog input"
                                ).ok();
                                if let Some(list) = f {
                                    let n = list.length();
                                    if n > 0 {
                                        let first = list.item(0).and_then(|e| e.dyn_into::<web_sys::HtmlElement>().ok());
                                        let last = list.item(n - 1).and_then(|e| e.dyn_into::<web_sys::HtmlElement>().ok());
                                        let active = d.active_element();
                                        let is = |a: &Option<web_sys::Element>, b: &Option<web_sys::HtmlElement>| {
                                            match (a, b) { (Some(x), Some(y)) => x == y.as_ref(), _ => false }
                                        };
                                        if ev.shift_key() && is(&active, &first) {
                                            ev.prevent_default();
                                            if let Some(l) = last { let _ = l.focus(); }
                                        } else if !ev.shift_key() && is(&active, &last) {
                                            ev.prevent_default();
                                            if let Some(f) = first { let _ = f.focus(); }
                                        }
                                    }
                                }
                            }
                        }
                    }>
                    <h2 id="confirm-title" class="confirm-title">{s.title.clone()}</h2>
                    <div id="confirm-body" class="confirm-body">
                        {s.reversible.is_irreversible().then(|| view! {
                            <div class="banner warn" role="alert">
                                <strong>"This cannot be undone."</strong>
                                " Check the target below before confirming."
                            </div>
                        })}
                        <dl class="fields dense">
                            <dt>"Target"</dt><dd class="mono">{s.target.clone()}</dd>
                            <dt>"What changes"</dt><dd>{s.what_changes.clone()}</dd>
                            <dt>"Reversible"</dt><dd>{s.reversible.text()}</dd>
                            {s.restart_required.then(|| view! {
                                <dt>"Restart"</dt>
                                <dd><strong>"Takes effect only after the service restarts."</strong></dd>
                            })}
                            <dt>"Authorization"</dt><dd>{s.authz_note.clone()}</dd>
                        </dl>
                        {phrase.map(|p| {
                            let p2 = p.clone();
                            view! {
                                <label class="confirm-typed">
                                    <span>"Type "<code>{p.clone()}</code>" to confirm"</span>
                                    <input type="text" autocomplete="off" spellcheck="false"
                                        aria-label=format!("Type {p2} to confirm")
                                        prop:value=move || typed.get()
                                        on:input=move |ev| typed.set(event_target_value(&ev))/>
                                </label>
                            }
                        })}
                    </div>
                    <div class="confirm-actions row">
                        <button class="btn" on:click=move |_| close()>"Cancel"</button>
                        <button class=confirm_cls prop:disabled=move || !ready()
                            on:click=move |_| { on_confirm(); close(); }>
                            {s.confirm_label.clone()}
                        </button>
                    </div>
                </div>
            }
        })}
    }
}

/// A real link to an in-app destination.
///
/// Renders an `<a href>` carrying the destination's actual URL, and intercepts
/// only the plain left click to keep SPA routing. Ctrl/Cmd/Shift-click, middle
/// click, "Open in new tab" and "Copy link address" all fall through to the
/// browser, because the href is genuine. That is the whole point: an analyst
/// pivoting through an investigation opens things in tabs, and a `<button>` that
/// calls a router silently breaks every one of those gestures.
///
/// The global time range rides along, so a link copied out of a narrowed
/// investigation reproduces that window.
#[component]
pub fn ViewLink(
    view: crate::route::View,
    #[prop(optional, into)] class: String,
    /// Reactive "this is the current destination" state, appended as `active`
    /// and exposed to assistive tech as `aria-current="page"`.
    #[prop(optional, into)]
    active: Signal<bool>,
    children: Children,
) -> impl IntoView {
    let store = expect_context::<crate::Store>();
    let target = view.clone();
    let href = move || {
        let base = target.to_path();
        match crate::route::param_of(&store.nav.query.get(), crate::timerange::PARAM) {
            Some(t) => format!("{base}?{}={t}", crate::timerange::PARAM),
            None => base,
        }
    };
    let go = view.clone();
    let cls = move || {
        if active.get() {
            format!("{class} active")
        } else {
            class.clone()
        }
    };
    view! {
        <a class=cls href=href
            aria-current=move || active.get().then_some("page")
            on:click=move |ev: web_sys::MouseEvent| {
                // Let the browser handle any gesture that means "somewhere else":
                // a new tab, a new window, a download.
                if ev.ctrl_key() || ev.meta_key() || ev.shift_key() || ev.alt_key()
                    || ev.button() != 0 {
                    return;
                }
                ev.prevent_default();
                store.nav.go(go.clone());
            }>
            {children()}
        </a>
    }
}

/// Confine Tab and Shift-Tab to the element with `container_id`.
///
/// A modal the keyboard can walk out of is not modal: focus lands on the page
/// behind it, which a sighted mouse user never notices and a screen-reader user
/// cannot recover from. Call this from the container's `on:keydown`.
pub fn trap_tab(ev: &web_sys::KeyboardEvent, container_id: &str) {
    if ev.key() != "Tab" {
        return;
    }
    let Some(d) = web_sys::window().and_then(|w| w.document()) else {
        return;
    };
    let sel = format!(
        "#{container_id} button:not([disabled]), #{container_id} input, \
         #{container_id} select, #{container_id} textarea, #{container_id} a[href], \
         #{container_id} [tabindex]:not([tabindex='-1'])"
    );
    let Ok(list) = d.query_selector_all(&sel) else {
        return;
    };
    let n = list.length();
    if n == 0 {
        return;
    }
    let el = |i: u32| {
        list.item(i)
            .and_then(|e| e.dyn_into::<web_sys::HtmlElement>().ok())
    };
    let (first, last) = (el(0), el(n - 1));
    let active = d.active_element();
    let is = |a: &Option<web_sys::Element>, b: &Option<web_sys::HtmlElement>| match (a, b) {
        (Some(x), Some(y)) => x == y.as_ref(),
        _ => false,
    };
    if ev.shift_key() && is(&active, &first) {
        ev.prevent_default();
        if let Some(l) = last {
            let _ = l.focus();
        }
    } else if !ev.shift_key() && is(&active, &last) {
        ev.prevent_default();
        if let Some(f) = first {
            let _ = f.focus();
        }
    }
}

/// Move focus into `container_id` when a surface opens, and back to whatever had
/// it when the surface closes. Returns nothing; call it inside an `Effect`.
pub fn manage_modal_focus(
    open: bool,
    container_id: &'static str,
    opener: StoredValue<Option<web_sys::HtmlElement>, LocalStorage>,
) {
    let Some(d) = web_sys::window().and_then(|w| w.document()) else {
        return;
    };
    if open {
        opener.set_value(
            d.active_element()
                .and_then(|e| e.dyn_into::<web_sys::HtmlElement>().ok()),
        );
        if let Some(el) = d
            .get_element_by_id(container_id)
            .and_then(|e| e.dyn_into::<web_sys::HtmlElement>().ok())
        {
            let _ = el.focus();
        }
    } else if let Some(el) = opener.get_value() {
        let _ = el.focus();
    }
}
