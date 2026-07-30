// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! The design-system primitives — one place for the reserved severity/status
//! vocabulary, evidence/audit references, and the non-happy-path states (empty,
//! error, loading, disabled, degraded). Every view composes these so the same
//! concept looks the same everywhere and colour is always paired with a text
//! label (never colour-alone — WCAG 1.4.1).

use leptos::prelude::*;

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
    view! { <div class="state empty"><span class="state-glyph">"∅"</span><span>{msg}</span></div> }
        .into_any()
}

/// The error state.
pub fn error_box(msg: impl Into<String>) -> AnyView {
    let msg = api::clean(&msg.into());
    view! { <div class="state error"><span class="state-glyph">"!"</span><span>{msg}</span></div> }
        .into_any()
}

/// The loading state (skeleton-ish).
pub fn loading(msg: impl Into<String>) -> AnyView {
    let msg = msg.into();
    view! { <div class="state loading"><span class="spinner"></span><span>{msg}</span></div> }
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