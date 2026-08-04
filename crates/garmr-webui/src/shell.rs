// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! The application shell: the task-oriented sidebar, the top command bar
//! (breadcrumbs + global search trigger + time range + session), the bottom
//! status bar, and the activity toast. All navigation goes through [`Nav`], so
//! every destination is a real URL.

use leptos::prelude::*;
use wasm_bindgen::JsCast;

use crate::route::{Area, View};
use crate::timerange;
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
        &[Area::Detections, Area::Policies, Area::Intelligence],
    ),
    ("Operate", &[Area::DataSources, Area::System]),
];

#[component]
pub fn Sidebar() -> impl IntoView {
    let store = expect_context::<Store>();

    // Below the layout breakpoint the sidebar is an off-canvas drawer. Closing it
    // on navigation is what makes it usable on a phone: tapping a destination
    // should take you there, not leave the menu covering it.
    Effect::new(move |_| {
        store.nav.view.get();
        store.nav_open.set(false);
    });

    // Lock background scrolling while the drawer covers the page, so a swipe
    // scrolls the menu rather than the content behind it.
    Effect::new(move |_| {
        let open = store.nav_open.get();
        if let Some(b) = web_sys::window()
            .and_then(|w| w.document())
            .and_then(|d| d.body())
        {
            let _ = if open {
                b.class_list().add_1("nav-locked")
            } else {
                b.class_list().remove_1("nav-locked")
            };
        }
        // Move focus into the drawer when it opens, and back to the toggle when it
        // closes, so a keyboard or screen-reader user is never stranded.
        let id = if open { "primary-nav" } else { "nav-toggle" };
        if let Some(el) = web_sys::window()
            .and_then(|w| w.document())
            .and_then(|d| d.get_element_by_id(id))
            .and_then(|e| e.dyn_into::<web_sys::HtmlElement>().ok())
        {
            let _ = el.focus();
        }
    });

    view! {
        // The backdrop only exists while the drawer is open; clicking it closes.
        {move || store.nav_open.get().then(|| view! {
            <div class="nav-scrim" on:click=move |_| store.nav_open.set(false)
                aria-hidden="true"></div>
        })}
        <nav class="sidebar" id="primary-nav" tabindex="-1" aria-label="Primary"
            class:open=move || store.nav_open.get()>
            <div class="brand">
                <span class="brand-mark" aria-hidden="true">"◈"</span>
                <span class="brand-name">"garmr"</span>
                <button class="iconbtn sm nav-close" aria-label="Close navigation menu"
                    on:click=move |_| store.nav_open.set(false)>"✕"</button>
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
    // A real <a>, so an analyst can middle-click an area into a new tab and copy
    // its link — gestures a router-calling <button> silently swallowed.
    view! {
        <ui::ViewLink view=area.home() class="navbtn" active=Signal::derive(active)>
            <span class="navbtn-label" title=area.blurb()>{area.label()}</span>
            {badge}
        </ui::ViewLink>
    }
}

#[component]
pub fn TopBar() -> impl IntoView {
    let store = expect_context::<Store>();
    view! {
        <header class="topbar">
            // The drawer's only affordance. CSS hides it at desktop widths, where
            // the sidebar is permanently on screen; below the breakpoint it is the
            // one thing standing between the operator and unreachable navigation.
            <button class="iconbtn nav-toggle" id="nav-toggle"
                aria-controls="primary-nav"
                aria-expanded=move || store.nav_open.get().to_string()
                aria-label="Open navigation menu"
                on:click=move |_| store.nav_open.update(|o| *o = !*o)>
                <span aria-hidden="true">"☰"</span>
            </button>
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
                    <ui::ViewLink view=View::CommandCenter class="crumb">"garmr"</ui::ViewLink>
                    {area.map(|a| {
                        let home = a.home();
                        view! {
                            <span class="crumb-sep" aria-hidden="true">"/"</span>
                            <ui::ViewLink view=home.clone() class="crumb"
                                active=Signal::derive(move || !is_detail)>
                                {a.label()}
                            </ui::ViewLink>
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
    let err = RwSignal::new(Option::<timerange::RangeError>::None);

    // Restore the range from the URL — on first load, on reload, and on browser
    // Back/Forward (the popstate handler republishes `nav.query`). Without this
    // the picker was memory-only: a shared link showed a colleague a different
    // window of time than the one being discussed.
    Effect::new(move |_| {
        if let Some(tr) = timerange::read_param(&store.nav.query.get()) {
            if tr != store.time_range.get_untracked() {
                store.time_range.set(tr);
            }
        }
    });

    // Every change publishes to the URL, so the range is shareable and survives a
    // reload. Views that read `time_range` re-run on the signal, so dependent data
    // refreshes without a manual reload.
    let apply = move |tr: TimeRange| {
        store.time_range.set(tr);
        err.set(None);
        let q = timerange::write_param(&store.nav.query.get_untracked(), tr);
        store.nav.set_query(q);
    };
    let apply_custom = move || {
        let (rf, rt) = (from.get_untracked(), to.get_untracked());
        match timerange::validate_custom(&rf, &rt, api::parse_local(&rf), api::parse_local(&rt)) {
            Ok(tr) => {
                apply(tr);
                show_custom.set(false);
            }
            // Previously this branch did nothing at all — the operator pressed
            // Apply and the console silently ignored them.
            Err(e) => err.set(Some(e)),
        }
    };

    // The picker governs only the time-aware areas. Where it does nothing, it is
    // hidden rather than left implying a filter that is not applied.
    let applies = move || {
        store
            .nav
            .view
            .get()
            .area()
            .map(|a| timerange::governs(a.label()))
            .unwrap_or(false)
    };

    view! {
        {move || {
            if !applies() { return ().into_any(); }
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
                aria-expanded=move || show_custom.get().to_string()
                on:click=move |_| show_custom.update(|v| *v = !*v)>"Custom…"</button>
            {move || show_custom.get().then(|| view! {
                <span class="tb-custom">
                    <input type="datetime-local" aria-label="Range start (local time)"
                        aria-invalid=move || err.get().is_some().to_string()
                        aria-describedby="tr-err"
                        prop:value=move || from.get()
                        on:input=move |ev| { from.set(event_target_value(&ev)); err.set(None); }/>
                    "→"
                    <input type="datetime-local" aria-label="Range end (local time)"
                        aria-invalid=move || err.get().is_some().to_string()
                        aria-describedby="tr-err"
                        prop:value=move || to.get()
                        on:input=move |ev| { to.set(event_target_value(&ev)); err.set(None); }/>
                    <button class="btn primary" on:click=move |_| apply_custom()>"Apply range"</button>
                    // Times are entered and displayed in the browser's zone; say so
                    // rather than leaving the operator to guess against UTC data.
                    <span class="dimtext tz-note">{local_zone_label()}</span>
                </span>
            })}
            <span id="tr-err" role="alert" class="tr-err">
                {move || err.get().map(|e| e.message())}
            </span>
        </div>
            }.into_any()
        }}
    }
}

/// A plain label for the browser's current UTC offset, e.g. "times in UTC+02:00".
/// Uses `Date::getTimezoneOffset` so the bundle needs no timezone database.
fn local_zone_label() -> String {
    // getTimezoneOffset returns minutes to ADD to local to reach UTC, so the sign
    // is inverted relative to how offsets are written.
    let mins = -(js_sys::Date::new_0().get_timezone_offset() as i32);
    let sign = if mins < 0 { '-' } else { '+' };
    let a = mins.abs();
    format!("times in UTC{sign}{:02}:{:02}", a / 60, a % 60)
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

/// A persistent, non-blocking reminder that first-run setup is unfinished.
///
/// Non-blocking on purpose: an operator with an incomplete setup still needs the
/// console to investigate with. It appears only for someone who can actually
/// resolve it — a read-only viewer cannot, so for them it would be pure noise —
/// and it disappears the moment setup completes rather than nagging forever.
#[component]
pub fn SetupBanner() -> impl IntoView {
    let store = expect_context::<Store>();
    let may_administer = move || {
        store
            .caps
            .get()
            .map(|c| c.writes_enabled() && !c.read_only())
            .unwrap_or(false)
    };
    view! {
        {move || {
            if !crate::setup::show_setup_banner(store.setup_complete.get(), may_administer()) {
                return ().into_any();
            }
            view! {
                <div class="setup-banner" role="status">
                    <span class="pill warn">"setup incomplete"</span>
                    <span class="grow">
                        "Some first-run steps are unfinished. The console works, but \
                         detection coverage or recovery may be incomplete."
                    </span>
                    <button class="btn sm" on:click=move |_| {
                        store.nav.go(Area::System.home());
                        store.nav.set_query("tab=setup".to_string());
                    }>"Finish setup"</button>
                </div>
            }
            .into_any()
        }}
    }
}
