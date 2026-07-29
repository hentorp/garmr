// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! The application shell: the task-oriented sidebar, the top command bar
//! (breadcrumbs + global search trigger + time range + session), the bottom
//! status bar, and the activity toast. All navigation goes through [`Nav`], so
//! every destination is a real URL.

use leptos::prelude::*;

use crate::route::{Area, View};
use crate::{api, ui, Store, TimeRange};

/// Sidebar nav grouped by the analyst's phase of work, so the destinations read
/// as four intents rather than a flat wall.
const GROUPS: [(&str, &[Area]); 4] = [
    ("Monitor", &[Area::CommandCenter]),
    (
        "Investigate",
        &[
            Area::Investigations,
            Area::Audit,
            Area::Users,
            Area::Applications,
            Area::Resources,
        ],
    ),
    (
        "Detect & govern",
        &[
            Area::Detections,
            Area::Policies,
            Area::Intelligence,
            Area::Map,
        ],
    ),
    (
        "Improve & operate",
        &[Area::Learning, Area::DataSources, Area::System],
    ),
];

#[component]
pub fn Sidebar() -> impl IntoView {
    let store = expect_context::<Store>();
    view! {
        <nav class="sidebar" aria-label="Primary">
            <div class="brand">
                <span class="brand-mark" aria-hidden="true">"◈"</span>
                <span class="brand-name">"garmr"</span>
            </div>
            {GROUPS.into_iter().map(|(group, areas)| view! {
                <div class="nav-group">
                    <div class="nav-group-label">{group}</div>
                    {areas.iter().copied().map(|a| nav_item(store, a)).collect_view()}
                </div>
            }).collect_view()}
            <div class="nav-spacer"></div>
            {move || {
                // Operator/session footer: identity of the auth posture + logout.
                let caps = store.caps.get();
                let op = store.operator.get();
                view! {
                    <div class="nav-foot">
                        {caps.map(|c| {
                            let (word, cls) = if op { ("operator", "warn") }
                                else if c.passkey_enabled() { ("passkey", "pass") }
                                else if c.auth_enabled() { ("token", "pass") }
                                else { ("open (loopback)", "dim") };
                            view! { <div class="row nav-auth">{ui::pill(cls, word)}</div> }
                        })}
                        <button class="navbtn subtle" on:click=move |_| logout()>"Log out"</button>
                    </div>
                }
            }}
        </nav>
    }
}

/// One sidebar destination, with a capability badge when its plane is off.
fn nav_item(store: Store, area: Area) -> impl IntoView {
    let active = move || store.nav.view.get().area() == Some(area);
    // If the area's gating feature is disabled, badge it (but keep it clickable —
    // the area still explains what to configure).
    let badge = move || {
        area.gating_feature().and_then(|f| {
            store.caps.get().and_then(|c| {
                let fs = c.feature(f);
                (fs.state == "disabled").then(|| ui::pill("dim", "off"))
            })
        })
    };
    view! {
        <button class="navbtn" class:active=active title=area.blurb()
            on:click=move |_| store.nav.go(area.home())>
            <span class="navbtn-label">{area.label()}</span>
            {badge}
        </button>
    }
}

#[component]
pub fn TopBar() -> impl IntoView {
    let store = expect_context::<Store>();
    view! {
        <header class="topbar">
            <Breadcrumbs/>
            <button class="cmd-trigger" title="Search & commands (Ctrl/Cmd-K)"
                on:click=move |_| store.cmd_open.set(true)>
                <span class="cmd-glyph" aria-hidden="true">"⌕"</span>
                <span class="cmd-text">"Search investigations, users, apps, events…"</span>
                <span class="kbd">"Ctrl K"</span>
            </button>
            <TimePicker/>
            <ThemeToggle/>
        </header>
    }
}

#[component]
fn Breadcrumbs() -> impl IntoView {
    let store = expect_context::<Store>();
    view! {
        <nav class="crumbs" aria-label="Breadcrumb">
            {move || {
                let v = store.nav.view.get();
                let area = v.area();
                let is_detail = area.map(|a| a.home() != v).unwrap_or(true);
                view! {
                    <button class="crumb" on:click=move |_| store.nav.go(View::CommandCenter)>"garmr"</button>
                    {area.map(|a| {
                        let home = a.home();
                        view! {
                            <span class="crumb-sep" aria-hidden="true">"/"</span>
                            <button class="crumb" class:current=move || !is_detail
                                on:click=move |_| store.nav.go(home.clone())>{a.label()}</button>
                        }
                    })}
                    {is_detail.then(|| view! {
                        <span class="crumb-sep" aria-hidden="true">"/"</span>
                        <span class="crumb current">{v.title()}</span>
                    })}
                }
            }}
        </nav>
    }
}

/// The global time-range picker (drives Audit Explorer, Command Center,
/// Intelligence). Live / presets / an absolute range.
#[component]
fn TimePicker() -> impl IntoView {
    let store = expect_context::<Store>();
    let from = RwSignal::new(String::new());
    let to = RwSignal::new(String::new());
    let show_custom = RwSignal::new(false);

    let apply = move |tr: TimeRange| store.time_range.set(tr);
    let apply_custom = move || {
        if let (Some(f), Some(t)) = (
            api::parse_local(&from.get_untracked()),
            api::parse_local(&to.get_untracked()),
        ) {
            if f < t {
                apply(TimeRange::Absolute(f, t));
                show_custom.set(false);
            }
        }
    };

    view! {
        <div class="timebar" role="group" aria-label="Time range">
            <span class="tb-label">{move || store.time_range.get().label()}</span>
            <button class="chip" class:active=move || store.time_range.get() == TimeRange::Live
                on:click=move |_| apply(TimeRange::Live)>"Live"</button>
            {[(24u32, "24h"), (72, "72h"), (168, "7d"), (720, "30d")].into_iter().map(|(h, l)| {
                let active = move || store.time_range.get() == TimeRange::Last(h);
                view! {
                    <button class="chip" class:active=active
                        on:click=move |_| apply(TimeRange::Last(h))>{l}</button>
                }
            }).collect_view()}
            <button class="chip" class:active=move || show_custom.get()
                on:click=move |_| show_custom.update(|v| *v = !*v)>"Custom…"</button>
            {move || show_custom.get().then(|| view! {
                <span class="tb-custom">
                    <input type="datetime-local" aria-label="From"
                        prop:value=move || from.get()
                        on:input=move |ev| from.set(event_target_value(&ev))/>
                    "→"
                    <input type="datetime-local" aria-label="To"
                        prop:value=move || to.get()
                        on:input=move |ev| to.set(event_target_value(&ev))/>
                    <button class="btn primary" on:click=move |_| apply_custom()>"Apply range"</button>
                </span>
            })}
        </div>
    }
}

/// Light/dark toggle. Persists to localStorage and flips the `data-theme` on the
/// document root.
#[component]
fn ThemeToggle() -> impl IntoView {
    let dark = RwSignal::new(current_theme_dark());
    let toggle = move || {
        let now_dark = !dark.get_untracked();
        dark.set(now_dark);
        set_theme(now_dark);
    };
    view! {
        <button class="iconbtn" title="Toggle light / dark"
            aria-label=move || if dark.get() { "Switch to light theme" } else { "Switch to dark theme" }
            on:click=move |_| toggle()>
            {move || if dark.get() { "☾" } else { "☀" }}
        </button>
    }
}

#[component]
pub fn StatusBar() -> impl IntoView {
    let store = expect_context::<Store>();
    view! {
        <footer class="statusbar">
            {move || {
                let errs = store.errors.get();
                if let Some((src, e)) = errs.first() {
                    return view! { <span class="sb-err">{format!("● {src}: {}", api::clean(e))}</span> }.into_any();
                }
                let caps = store.caps.get();
                view! {
                    <span class="sb-ok">
                        {if store.api_ok.get() { "● connected" } else { "○ connecting…" }}
                    </span>
                    {caps.map(|c| {
                        let air = c.airgap();
                        let role = c.ha_role();
                        view! {
                            <span class="sb-meta">{format!("garmr {}", c.backend_version())}</span>
                            <span class="sb-meta">
                                {format!("role: {role}")}
                                <ui::InfoPopover heading="Deployment role"
                                    body="The writer is the primary node that ingests and serves. A follower is a read-only standby — restored from a backup or replicating a writer — and never becomes writable on its own, so promotion is always a deliberate, audited step."/>
                            </span>
                            {air.then(|| view! {
                                <span class="sb-air">
                                    "AIR-GAPPED"
                                    {ui::help_tip("Air-gap mode blocks every external call: model providers, model downloads, IOC feeds, remote MCP, webhooks, SMTP, Matrix, S3, telemetry and update checks. Local models keep working.")}
                                </span>
                            })}
                        }
                    })}
                }.into_any()
            }}
        </footer>
    }
}

/// Transient toasts for the newest activity-center entries; the full feed opens
/// from the command palette / System.
#[component]
pub fn ActivityToast() -> impl IntoView {
    let store = expect_context::<Store>();
    view! {
        <div class="toasts" aria-live="polite">
            {move || {
                store.activity.get().into_iter().take(3).map(|a| {
                    let cls = if a.ok { "pass" } else { "bad" };
                    view! {
                        <div class=format!("toast {cls}")>
                            <div class="row">
                                <span class=format!("pill {cls}")>{if a.ok { "done" } else { "failed" }}</span>
                                <strong>{a.title}</strong>
                                <span class="mono dimtext">{a.at}</span>
                            </div>
                            {(!a.detail.is_empty()).then(|| view! { <div class="dimtext">{api::clean(&a.detail)}</div> })}
                            {a.audit.map(|id| ui::audit_ref(&id))}
                        </div>
                    }
                }).collect_view()
            }}
        </div>
    }
}

/// End the passkey session then bounce to the login page (a no-op on token-only
/// deployments).
fn logout() {
    leptos::task::spawn_local(async {
        let _ = api::post("/auth/logout", serde_json::Value::Null, None).await;
        if let Some(w) = web_sys::window() {
            let _ = w.location().set_href("/login");
        }
    });
}

fn current_theme_dark() -> bool {
    let doc = web_sys::window().and_then(|w| w.document());
    let root = doc.and_then(|d| d.document_element());
    root.and_then(|r| r.get_attribute("data-theme"))
        .map(|t| t != "light")
        .unwrap_or(true)
}

fn set_theme(dark: bool) {
    if let Some(root) = web_sys::window()
        .and_then(|w| w.document())
        .and_then(|d| d.document_element())
    {
        let _ = root.set_attribute("data-theme", if dark { "dark" } else { "light" });
    }
    if let Some(storage) = web_sys::window()
        .and_then(|w| w.local_storage().ok())
        .flatten()
    {
        let _ = storage.set_item("garmr-theme", if dark { "dark" } else { "light" });
    }
}