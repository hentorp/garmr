// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! System — audit integrity, the versioned registry (models/prompts/toolsets),
//! security posture / HA / air-gap, and operator access. The operational and
//! governance surface in one place.

use std::collections::HashMap;

use leptos::prelude::*;
use serde_json::Value;

use crate::route::Area;
use crate::{api, ui, Store};

pub fn view(store: Store) -> impl IntoView {
    let tab = move || store.nav.param("tab").unwrap_or_else(|| "audit".into());
    let set_tab = move |t: &'static str| store.nav.set_query(format!("tab={t}"));
    view! {
        <div class="page">
            {ui::page_header("System", Area::System.blurb())}
            {super::tabs(&[
                ("setup", "Setup"),
                ("audit", "Audit integrity"),
                ("registry", "Models & registry"),
                ("config", "Configuration"),
                ("posture", "Posture & HA"),
                ("access", "Access"),
                ("llm", "Model provider"),
            ], tab(), set_tab)}
            {move || match tab().as_str() {
                "setup" => setup_tab(store),
                "registry" => registry_tab(),
                "config" => config_tab(store),
                "posture" => posture_tab(store),
                "access" => access_tab(store),
                "llm" => llm_tab(store),
                _ => audit_tab(),
            }}
        </div>
    }
}

/// First-run setup checklist. Renders `/api/setup/status`: overall readiness +
/// each of the 11 steps with a status badge, guidance, and a jump to the tab that
/// fixes it. Live (never inferred from empty events); resumable = it just reflects
/// current state on each load.
fn setup_tab(store: Store) -> AnyView {
    let setup = super::Fetch::new();
    setup.load("/api/setup/status".into());
    view! {
        <div>
            <p class="sub">"What's configured and what's left — computed live from the running system, never from an empty event store. Required steps that aren't complete hold back readiness; optional and info steps don't."</p>
            {move || {
                let Some(d) = setup.data.get() else {
                    if let Some(e) = setup.err.get() { return super::error_state(e); }
                    return ui::loading("checking setup…");
                };
                let complete = d.get("complete").and_then(Value::as_bool).unwrap_or(false);
                let mode = api::s(&d, "mode");
                let n_left = super::arr(&d, "required_incomplete").len();
                let header = if complete {
                    view! { <div class="row">{ui::pill("pass", "setup complete")}<span class="dimtext">{format!("deployment mode: {mode}")}</span></div> }.into_any()
                } else {
                    view! { <div class="row">{ui::pill("warn", format!("{n_left} required step(s) incomplete"))}<span class="dimtext">{format!("deployment mode: {mode}")}</span></div> }.into_any()
                };
                let rows = super::arr(&d, "steps").into_iter().map(|s| setup_step_row(store, &s)).collect_view();
                view! { <section class="sect">{header}{rows}</section> }.into_any()
            }}
        </div>
    }.into_any()
}

/// One setup step: status badge + title + guidance, and a jump to the tab that
/// addresses it (where one applies).
fn setup_step_row(store: Store, s: &Value) -> AnyView {
    let id = api::s(s, "id");
    let title = api::s(s, "title");
    let status = api::s(s, "status");
    let detail = api::s(s, "detail");
    let required = s.get("required").and_then(Value::as_bool).unwrap_or(false);
    let (cls, label) = match status.as_str() {
        "complete" => ("pass", "complete"),
        "failed" => ("bad", "failed"),
        "incomplete" => ("warn", "incomplete"),
        "optional" => ("dim", "optional"),
        _ => ("dim", "info"),
    };
    // Where the operator fixes this step (a System tab), if applicable.
    let goto: Option<(&'static str, &'static str)> = match id.as_str() {
        "admin" | "passkeys" | "llm" | "llm_reachable" | "notifications" => {
            Some(("access", "Go to Access"))
        }
        "storage" | "deployment_mode" | "detection" => Some(("config", "Go to Configuration")),
        _ => None,
    };
    view! {
        <div class="card">
            <div class="row">
                {ui::pill(cls, label)}
                <strong>{title}</strong>
                {required.then(|| ui::pill("dim", "required"))}
            </div>
            <div class="dimtext">{detail}</div>
            {goto.map(|(t, lbl)| view! {
                <button class="btn ghost" on:click=move |_| store.nav.set_query(format!("tab={t}"))>{lbl}</button>
            })}
        </div>
    }.into_any()
}

/// LLM & AI provider view: the configured provider's state + a REAL test-model
/// probe (airgap-aware). Keys are set in Access; never shown here.
fn llm_tab(store: Store) -> AnyView {
    let status = super::Fetch::new();
    status.load("/api/llm/status".into());
    let result = RwSignal::new(Option::<Value>::None);
    let busy = RwSignal::new(false);
    let do_test = move || {
        busy.set(true);
        leptos::task::spawn_local(async move {
            let r = api::send_post("/admin/llm/test", serde_json::json!({})).await;
            busy.set(false);
            match r {
                Ok(v) => {
                    let ok = v.get("ok").and_then(Value::as_bool).unwrap_or(false);
                    store.log_activity(
                        "LLM test",
                        ok,
                        api::s(&v, if ok { "reply" } else { "error" }),
                        None,
                    );
                    result.set(Some(v));
                }
                Err(e) => {
                    store.log_activity("LLM test failed", false, api::clean(&e.message), None);
                    result.set(Some(serde_json::json!({ "ok": false, "stage": "request", "error": api::clean(&e.message) })));
                }
            }
        });
    };
    view! {
        <div>
            <p class="sub">"The configured model provider. Test connection runs a real round-trip; an external provider is refused under air-gap — never a silent fallback. Credentials are set in Access and never shown here."</p>
            {move || {
                let Some(d) = status.data.get() else {
                    if let Some(e) = status.err.get() { return super::error_state(e); }
                    return ui::loading("loading provider…");
                };
                let external = d.get("external").and_then(Value::as_bool).unwrap_or(false);
                let key = d.get("key_configured").and_then(Value::as_bool).unwrap_or(false);
                let blocked = d.get("blocked_by_airgap").and_then(Value::as_bool).unwrap_or(false);
                let rows: [(&str, String, &str); 6] = [
                    ("Provider type", api::s(&d, "backend"), ""),
                    ("Model", api::s(&d, "model"), ""),
                    ("Prefilter model", show_val(d.get("prefilter_model").unwrap_or(&Value::Null)),
                        "A smaller, cheaper model that pre-screens events first, so routine traffic doesn't spend the full budget on the main model."),
                    ("Base URL", show_val(d.get("base_url").unwrap_or(&Value::Null)),
                        "The API endpoint requests are sent to. Point it at a self-hosted or on-network endpoint instead of the provider's default when needed."),
                    ("Daily budget (USD)", show_val(d.get("daily_budget_usd").unwrap_or(&Value::Null)),
                        "A hard daily spending cap on model calls; once it's reached, further requests are refused rather than billed."),
                    ("Max tokens", show_val(d.get("max_tokens").unwrap_or(&Value::Null)), ""),
                ];
                view! {
                    <section class="sect">
                        <div class="row">
                            {ui::pill(if external { "warn" } else { "pass" }, if external { "external" } else { "local" })}
                            {if key { ui::pill("pass", "key set") } else { ui::pill("bad", "no key") }}
                            {blocked.then(|| ui::pill("bad", "blocked by airgap"))}
                            {d.get("no_silent_external_fallback").and_then(Value::as_bool).unwrap_or(false).then(|| ui::pill("dim", "no silent external fallback"))}
                            <ui::InfoPopover heading="Air-gap and external providers" body="On an air-gapped deployment, calling a hosted provider over the internet is refused outright rather than falling back silently, so an isolated system stays isolated. Keep a local or on-network model to remain eligible; a hosted provider is only reachable when air-gap is turned off."/>
                        </div>
                        {super::table(&["Setting", "Value"], rows.into_iter().map(|(k, v, help)| view! {
                            <tr><td class="dimtext">{k}{(!help.is_empty()).then(|| ui::help_tip(help))}</td><td class="mono">{v}</td></tr>
                        }).collect_view().into_any())}
                        <div class="row">
                            <button class="btn primary" prop:disabled=move || busy.get() on:click=move |_| do_test()>"Test model connection"</button>
                            {ui::help_tip("Sends one real request to the provider and waits for a reply, so you confirm the key, network path, and model all work before relying on them.")}
                            {move || busy.get().then(|| view! { <span class="dimtext">"calling the model…"</span> })}
                        </div>
                        {move || result.get().map(|r| {
                            let ok = r.get("ok").and_then(Value::as_bool).unwrap_or(false);
                            if ok {
                                let lat = r.get("latency_ms").and_then(Value::as_u64).unwrap_or(0);
                                view! { <div class="row">{ui::pill("pass", "ok")}<span class="dimtext">{format!("reply \"{}\" · {lat} ms", api::s(&r, "reply"))}</span></div> }
                            } else {
                                view! { <div class="row">{ui::pill("bad", format!("{} failed", api::s(&r, "stage")))}<span class="dimtext">{api::s(&r, "error")}</span></div> }
                            }
                        })}
                    </section>
                }.into_any()
            }}
        </div>
    }.into_any()
}

fn audit_tab() -> AnyView {
    let f = super::Fetch::new();
    // The FULL verification report (kind/sequence/detail), so a failed ledger
    // shows WHAT broke — not just a count. Same summary fields as /status.
    f.load("/api/audit/verify".into());
    view! {
        <div>
            <p class="sub">"The tamper-evident audit ledger records every protected action. Verification is offline + fail-closed; this runs it and shows any findings."</p>
            {move || {
                if let Some(e) = f.err.get() { return super::error_state(e); }
                match f.data.get() {
                    None => ui::loading("verifying ledger…"),
                    Some(v) => {
                        let enabled = v.get("enabled").and_then(Value::as_bool).unwrap_or(false);
                        let ok = v.get("ok").and_then(Value::as_bool).unwrap_or(false);
                        if !enabled {
                            return ui::disabled_panel("Audit ledger", &crate::caps::FeatureState{ state: "disabled".into(), reason: Some("The audit ledger is turned off, so protected actions like approvals and promotions aren't being recorded tamper-evidently. Turn it on in the Configuration tab to start an append-only, verifiable record.".into())});
                        }
                        let findings = super::arr(&v, "findings");
                        let total = api::num(&v, "findings_total");
                        let truncated = v.get("findings_truncated").and_then(Value::as_bool).unwrap_or(false);
                        let shown = findings.len();
                        view! {
                            <div class="row"><span class="dimtext">"Integrity"</span>
                                <ui::InfoPopover heading="Ledger verification and checkpoints" body="Verification recomputes the ledger's hash chain offline and fails closed — any missing, reordered, or altered record shows up as a finding below instead of being ignored. Checkpoints are periodic signed markers along the chain; they let verification confirm long histories quickly and pinpoint exactly where a break occurred."/>
                                {if ok { ui::pill("pass", "verified") } else { ui::pill("bad", "FAILED") }}</div>
                            {ui::kv_list(vec![
                                ("Records", api::num(&v, "records").to_string()),
                                ("Head sequence", api::num(&v, "head_sequence").to_string()),
                                ("Last verified sequence", api::num(&v, "last_sequence").to_string()),
                                ("Checkpoints", api::num(&v, "checkpoints").to_string()),
                                ("Segments", api::num(&v, "segments").to_string()),
                                ("Signing key", api::s(&v, "key_id")),
                                ("Findings", total.to_string()),
                            ])}
                            {(!findings.is_empty()).then(move || view! {
                                <section class="sect">
                                    <h3>"Verification findings"</h3>
                                    {truncated.then(|| view! { <p class="dimtext">{format!("showing the first {shown} of {total}")}</p> })}
                                    {super::table(&["kind", "sequence", "detail"],
                                        findings.into_iter().map(|fd| {
                                            let seq = fd.get("sequence").and_then(Value::as_i64)
                                                .map(|s| s.to_string()).unwrap_or_else(|| "—".into());
                                            view! {
                                                <tr>
                                                    <td>{ui::pill("bad", api::s(&fd, "kind"))}</td>
                                                    <td class="mono dimtext">{seq}</td>
                                                    <td class="msg">{api::clean(&api::s(&fd, "detail"))}</td>
                                                </tr>
                                            }
                                        }).collect_view().into_any())}
                                </section>
                            })}
                        }.into_any()
                    }
                }
            }}
        </div>
    }.into_any()
}

fn registry_tab() -> AnyView {
    let active = super::Fetch::new();
    let verify = super::Fetch::new();
    active.load("/api/registry/active".into());
    verify.load("/api/registry/verify".into());
    view! {
        <div>
            <p class="sub">"Versioned registries — models, prompts, toolsets, detector configs. Register + promote are audited admin actions; the console shows the active set and verification."</p>
            {move || verify.data.get().map(|v| {
                let ok = v.get("ok").and_then(Value::as_bool).unwrap_or(false);
                view! {
                    <div class="row"><span class="dimtext">"Registry verification"</span>
                        {if ok { ui::pill("pass", "ok") } else { ui::pill("bad", "issues") }}
                        <span class="dimtext">{format!("{} records · {} promotions", api::num(&v, "records"), api::num(&v, "promotions"))}</span></div>
                }
            })}
            <section class="sect"><h3>"Active records"</h3>
                {active.framed("active", "nothing promoted to active — the observed built-ins are serving", crate::views::learning::reg_table)}
            </section>
        </div>
    }.into_any()
}

/// Read-only Configuration Center: every curated setting joined to its live
/// effective value + source + reload class, plus classified diagnostics. Secrets
/// are shown as configured/not-set only — never a value. Editing is a later cycle.
fn config_tab(store: Store) -> AnyView {
    let schema = super::Fetch::new();
    let effective = super::Fetch::new();
    let status = super::Fetch::new();
    let revisions = super::Fetch::new();
    schema.load("/api/config/schema".into());
    effective.load("/api/config/effective".into());
    status.load("/api/config/status".into());
    revisions.load("/api/config/revisions".into());
    let offline = super::Fetch::new();
    offline.load("/api/config/offline-ops".into());
    let q = RwSignal::new(String::new());
    let env_only = RwSignal::new(false);
    let secrets_only = RwSignal::new(false);
    // Staged edits: editable key → raw string, present only when it differs from
    // the effective value (so `edits` empty ⇔ nothing pending). The console builds
    // the override from the FULL editable surface (all editable fields at their
    // staged-or-effective value), so an apply never silently reverts a field.
    let edits = RwSignal::new(HashMap::<String, String>::new());
    let report = RwSignal::new(Option::<Value>::None);
    let busy = RwSignal::new(false);
    let ts = |sec: i64| {
        if sec > 0 {
            api::ts_iso(sec * 1_000_000)
        } else {
            "—".into()
        }
    };

    let build = move || -> Option<String> {
        let sc = schema.data.get()?;
        let ef = effective.data.get()?;
        Some(build_override_toml(&sc, &ef, &edits.get()))
    };
    let do_validate = move || {
        let Some(body) = build() else { return };
        busy.set(true);
        leptos::task::spawn_local(async move {
            let r = api::send_post(
                "/admin/config/validate",
                serde_json::json!({ "override_toml": body }),
            )
            .await;
            busy.set(false);
            match r {
                Ok(v) => report.set(Some(v)),
                Err(e) => report.set(Some(serde_json::json!({ "error": api::clean(&e.message) }))),
            }
        });
    };
    let do_apply = move || {
        let Some(body) = build() else { return };
        busy.set(true);
        leptos::task::spawn_local(async move {
            let r = api::send_post(
                "/admin/config/apply",
                serde_json::json!({ "override_toml": body, "note": "applied from console" }),
            )
            .await;
            busy.set(false);
            match r {
                Ok(v) => {
                    store.log_activity(
                        "Configuration applied",
                        true,
                        "restart required to take effect",
                        None,
                    );
                    report.set(Some(v));
                    edits.set(HashMap::new());
                    effective.load("/api/config/effective".into());
                    revisions.load("/api/config/revisions".into());
                    status.load("/api/config/status".into());
                }
                Err(e) => {
                    store.log_activity(
                        "Configuration apply refused",
                        false,
                        api::clean(&e.message),
                        None,
                    );
                    report.set(Some(serde_json::json!({ "error": api::clean(&e.message) })));
                }
            }
        });
    };
    let do_rollback = move |seq: u64| {
        leptos::task::spawn_local(async move {
            match api::send_post("/admin/config/rollback", serde_json::json!({ "seq": seq })).await
            {
                Ok(_) => {
                    store.log_activity(
                        "Configuration rolled back",
                        true,
                        format!("to revision {seq}"),
                        None,
                    );
                    effective.load("/api/config/effective".into());
                    revisions.load("/api/config/revisions".into());
                    status.load("/api/config/status".into());
                }
                Err(e) => {
                    store.log_activity("Rollback refused", false, api::clean(&e.message), None)
                }
            }
        });
    };

    view! {
        <div>
            <p class="sub">"Every configured setting: effective value, source, and reload class. Safe operational settings are editable — stage a change, validate to preview the diff and restart impact, then apply (saved as a versioned revision; a restart loads it). Capability, identity, path, egress, audit-ledger and secret settings are not editable from the console."</p>

            <div class="row">
                <span class="dimtext">"Reading this table:"</span>
                <span class="dimtext">"Value"{ui::help_tip("The value actually in force right now, after environment variables, the saved config file, and built-in defaults are merged together.")}</span>
                <span class="dimtext">"Source"{ui::help_tip("Where that effective value came from — an environment variable, the config file, or a built-in default.")}</span>
                <span class="dimtext">"Reload"{ui::help_tip("Whether a change takes effect immediately (hot-reload) or only after the service is restarted.")}</span>
            </div>

            {move || status.data.get()
                .and_then(|s| s.get("restart_pending").and_then(Value::as_bool))
                .filter(|p| *p)
                .map(|_| view! {
                    <section class="sect"><div class="row">
                        {ui::pill("warn", "restart pending")}
                        <span class="dimtext">"Applied configuration changes are saved but not yet loaded — run "</span>
                        <code class="mono">"systemctl restart garmr"</code>
                        <span class="dimtext">" to apply them."</span>
                    </div></section>
                })}

            {move || {
                let n = edits.get().len();
                if n == 0 { return ().into_any(); }
                view! {
                    <section class="sect"><div class="row">
                        {ui::pill("warn", format!("{n} pending change(s)"))}
                        <button class="btn" prop:disabled=move || busy.get() on:click=move |_| do_validate()>"Validate changes"</button>
                        <button class="btn primary" prop:disabled=move || busy.get() on:click=move |_| do_apply()>"Apply changes"</button>
                        <button class="btn ghost" on:click=move |_| { edits.set(HashMap::new()); report.set(None); }>"Discard changes"</button>
                        {move || busy.get().then(|| view! { <span class="dimtext">"working…"</span> })}
                    </div></section>
                }.into_any()
            }}

            {move || report.get().map(|r| {
                let err = r.get("error").and_then(Value::as_str).filter(|s| !s.is_empty()).map(str::to_string);
                let applied = r.get("ok").and_then(Value::as_bool).unwrap_or(false);
                let restart = r.get("restart_required").and_then(Value::as_bool).unwrap_or(false);
                let revseq = r.get("revision").and_then(|v| v.get("seq")).and_then(Value::as_u64).unwrap_or(0);
                let changes = super::arr(&r, "changes");
                let warnings = super::arr(&r, "warnings");
                let nchg = changes.len();
                view! {
                    <section class="sect"><h3>{if applied { "Applied" } else { "Validation" }}</h3>
                        {err.map(|e| view! { <div class="row">{ui::pill("bad", "refused")}<span class="dimtext">{e}</span></div> })}
                        {applied.then(|| view! { <div class="row">{ui::pill("pass", "applied")}<span class="dimtext">{format!("saved as revision {revseq}")}</span></div> })}
                        {restart.then(|| view! { <div class="row">{ui::pill("warn", "restart required")}<span class="dimtext">"persisted; restart garmr to load it"</span></div> })}
                        {(!changes.is_empty()).then(move || view! {
                            <div>
                                <div class="dimtext">{format!("{nchg} change(s):")}</div>
                                {super::table(&["Setting", "From", "To", "Reload"], changes.into_iter().map(|c| {
                                    let old = c.get("old").cloned().unwrap_or(Value::Null);
                                    let new = c.get("new").cloned().unwrap_or(Value::Null);
                                    view! { <tr><td class="mono">{api::s(&c, "key")}</td><td class="mono">{show_val(&old)}</td><td class="mono">{show_val(&new)}</td><td>{ui::pill("dim", crate::status::humanize(&api::s(&c, "reload")))}</td></tr> }
                                }).collect_view().into_any())}
                            </div>
                        })}
                        {warnings.into_iter().map(|w| view! { <div class="row">{ui::pill("warn", "note")}<span class="dimtext">{w.as_str().unwrap_or("").to_string()}</span></div> }).collect_view()}
                    </section>
                }
            })}
            {move || status.data.get().map(|s| {
                let diags = super::arr(&s, "diagnostics");
                if diags.is_empty() {
                    return view! { <div class="row"><span class="dimtext">"No configuration issues detected."</span></div> }.into_any();
                }
                view! {
                    <section class="sect"><h3>"Diagnostics"</h3>
                        {diags.into_iter().map(|d| {
                            let sev = api::s(&d, "severity");
                            let cls = match sev.as_str() {
                                "security_critical" => "bad",
                                "operational" | "degraded" => "warn",
                                _ => "dim",
                            };
                            view! {
                                <div class="row">
                                    {ui::pill(cls, crate::status::humanize(&sev))}
                                    <strong>{api::s(&d, "title")}</strong>
                                    <span class="dimtext">{api::clean(&api::s(&d, "detail"))}</span>
                                </div>
                            }
                        }).collect_view()}
                    </section>
                }.into_any()
            })}
            <div class="searchbar">
                <input type="search" class="grow" placeholder="filter settings…"
                    prop:value=move || q.get() on:input=move |ev| q.set(event_target_value(&ev))/>
                <label class="chk"><input type="checkbox" prop:checked=move || env_only.get()
                    on:change=move |ev| env_only.set(event_target_checked(&ev))/>" env-overridden only"</label>
                {ui::help_tip("An environment variable set on the host wins over the same setting in the config file. This shows only the rows an environment variable is currently overriding.")}
                <label class="chk"><input type="checkbox" prop:checked=move || secrets_only.get()
                    on:change=move |ev| secrets_only.set(event_target_checked(&ev))/>" secrets only"</label>
                {ui::help_tip("Sensitive settings such as keys and passwords. Their values are never shown here — only whether each one is configured or not set.")}
            </div>
            {move || {
                let (Some(sc), Some(ef)) = (schema.data.get(), effective.data.get()) else {
                    if let Some(e) = schema.err.get().or_else(|| effective.err.get()) {
                        return super::error_state(e);
                    }
                    return ui::loading("loading configuration…");
                };
                let sections = super::arr(&sc, "sections");
                let sfields = super::arr(&sc, "fields");
                let mut eff_by_key: HashMap<String, Value> = HashMap::new();
                for e in super::arr(&ef, "fields") {
                    eff_by_key.insert(api::s(&e, "key"), e);
                }
                let needle = q.get().to_lowercase();
                let eo = env_only.get();
                let so = secrets_only.get();
                let out = sections.into_iter().map(|secv| {
                    let sec = secv.as_str().unwrap_or("").to_string();
                    let rows: Vec<AnyView> = sfields.iter()
                        .filter(|f| api::s(f, "section") == sec)
                        .filter(|f| {
                            let hay = format!("{} {} {}", api::s(f, "key"), api::s(f, "label"), api::s(f, "description")).to_lowercase();
                            let matches = needle.is_empty() || hay.contains(&needle);
                            let secret = f.get("secret").and_then(Value::as_bool).unwrap_or(false);
                            let overridden = eff_by_key.get(&api::s(f, "key"))
                                .and_then(|e| e.get("overridden_by_env")).and_then(Value::as_bool).unwrap_or(false);
                            matches && (!so || secret) && (!eo || overridden)
                        })
                        .map(|f| config_field_row(f, eff_by_key.get(&api::s(f, "key")), edits))
                        .collect();
                    (sec, rows)
                }).filter(|(_, rows)| !rows.is_empty()).map(|(sec, rows)| {
                    view! {
                        <section class="sect"><h3>{sec}</h3>
                            {super::table(&["Setting", "Value", "Source", "Reload", "Notes"], rows.into_iter().collect_view().into_any())}
                        </section>
                    }.into_any()
                }).collect::<Vec<_>>();
                if out.is_empty() {
                    return ui::empty("No settings match the current filter — clear the search box or the checkboxes above to see more.");
                }
                view! { <div>{out.into_iter().collect_view()}</div> }.into_any()
            }}

            {move || {
                let mut revs = revisions.rows("revisions");
                if revs.is_empty() { return ().into_any(); }
                revs.reverse(); // newest first
                view! {
                    <section class="sect"><h3>"Revision history"</h3>
                        <p class="dimtext">"Each apply/rollback is a versioned override revision. Roll back re-applies an earlier one as a new revision; a restart loads it."</p>
                        {super::table(&["#", "when", "by", "note", "", ""], revs.into_iter().map(|r| {
                            let seq = r.get("seq").and_then(Value::as_u64).unwrap_or(0);
                            let is_cur = r.get("is_current").and_then(Value::as_bool).unwrap_or(false);
                            let when = ts(r.get("ts").and_then(Value::as_i64).unwrap_or(0));
                            view! { <tr>
                                <td class="mono">{seq.to_string()}</td>
                                <td class="mono dimtext">{when}</td>
                                <td class="dimtext">{api::s(&r, "author")}</td>
                                <td class="dimtext">{api::clean(&api::s(&r, "note"))}</td>
                                <td>{is_cur.then(|| ui::pill("pass", "current"))}</td>
                                <td>{(!is_cur).then(move || view! { <button class="btn ghost" on:click=move |_| do_rollback(seq)>"Roll back"</button> })}</td>
                            </tr> }
                        }).collect_view().into_any())}
                    </section>
                }.into_any()
            }}

            {move || {
                let Some(d) = offline.data.get() else { return ().into_any(); };
                let ops = super::arr(&d, "operations");
                if ops.is_empty() { return ().into_any(); }
                let writer = d.get("writer").and_then(Value::as_bool).unwrap_or(true);
                view! {
                    <section class="sect"><h3>"Offline maintenance operations"</h3>
                        <p class="dimtext">"These run on the host with the daemon stopped — the console can't run them. Each shows the exact command + prerequisites; nothing here executes. A restored, unpromoted node won't be serving this panel, so its restore/promote state is observed from the CLI while the daemon is down."</p>
                        {(!writer).then(|| view! { <div class="row">{ui::pill("warn", "read-only follower")}<span class="dimtext">"this node is a read-only follower"</span>{ui::help_tip("A follower replicates from the writer and refuses changes; only the single writer node accepts edits and event ingest. A follower can be promoted to writer during a failover.")}</div> })}
                        {ops.into_iter().map(|o| {
                            let prereqs = super::arr(&o, "prerequisites").into_iter()
                                .filter_map(|p| p.as_str().map(str::to_string)).collect::<Vec<_>>().join("; ");
                            view! {
                                <div class="card">
                                    <div class="row"><strong>{api::s(&o, "title")}</strong>{ui::pill("dim", crate::status::humanize(&api::s(&o, "status")))}</div>
                                    <div class="dimtext">{api::s(&o, "why_offline")}</div>
                                    <div><code class="mono">{api::s(&o, "command")}</code></div>
                                    <div class="dimtext">{format!("prerequisites: {prereqs}")}</div>
                                </div>
                            }
                        }).collect_view()}
                    </section>
                }.into_any()
            }}
        </div>
    }.into_any()
}

/// Stringify a JSON config value for display (bools as yes/no, lists joined,
/// null as an em-dash).
fn show_val(v: &Value) -> String {
    match v {
        Value::Null => "—".into(),
        Value::Bool(b) => {
            if *b {
                "yes".into()
            } else {
                "no".into()
            }
        }
        Value::String(s) if s.is_empty() => "—".into(),
        Value::String(s) => s.clone(),
        Value::Array(a) if a.is_empty() => "[]".into(),
        Value::Array(a) => a
            .iter()
            .map(|x| {
                x.as_str()
                    .map(str::to_string)
                    .unwrap_or_else(|| x.to_string())
            })
            .collect::<Vec<_>>()
            .join(", "),
        other => other.to_string(),
    }
}

/// The raw string an editor input shows for an effective JSON value.
fn effective_raw(v: &Value) -> String {
    match v {
        Value::Bool(b) => {
            if *b {
                "true".into()
            } else {
                "false".into()
            }
        }
        Value::String(s) => s.clone(),
        Value::Null => String::new(),
        other => other.to_string(),
    }
}

/// Format a raw editor string as a TOML scalar of the field's kind (so a float
/// field gets a decimal, a string is quoted+escaped, a bool is true/false).
fn toml_scalar(kind: &str, raw: &str) -> String {
    let raw = raw.trim();
    match kind {
        "bool" => {
            if matches!(raw, "true" | "yes" | "1" | "on") {
                "true".into()
            } else {
                "false".into()
            }
        }
        "int" => {
            if raw.is_empty() {
                "0".into()
            } else {
                raw.to_string()
            }
        }
        "float" => {
            if raw.is_empty() {
                "0.0".into()
            } else if raw.contains(['.', 'e', 'E']) {
                raw.to_string()
            } else {
                format!("{raw}.0") // a plain integer for a float field must carry a decimal
            }
        }
        _ => format!("\"{}\"", raw.replace('\\', "\\\\").replace('"', "\\\"")),
    }
}

/// Build the full-editable-surface override TOML: every `editable` field at its
/// staged value (or its current effective value if untouched), grouped by section.
/// Including all editable fields — not just the changed ones — means an apply can
/// never silently revert a previously-persisted editable field.
fn build_override_toml(sc: &Value, ef: &Value, edits: &HashMap<String, String>) -> String {
    let mut eff_by_key: HashMap<String, Value> = HashMap::new();
    for e in super::arr(ef, "fields") {
        eff_by_key.insert(api::s(&e, "key"), e);
    }
    let mut by_section: std::collections::BTreeMap<String, Vec<(String, String)>> =
        std::collections::BTreeMap::new();
    for f in super::arr(sc, "fields") {
        if !f.get("editable").and_then(Value::as_bool).unwrap_or(false) {
            continue;
        }
        let key = api::s(&f, "key");
        let kind = api::s(&f, "kind");
        let Some((section, field)) = key.split_once('.') else {
            continue;
        };
        let raw = edits.get(&key).cloned().unwrap_or_else(|| {
            eff_by_key
                .get(&key)
                .and_then(|e| e.get("value"))
                .map(effective_raw)
                .unwrap_or_default()
        });
        by_section
            .entry(section.to_string())
            .or_default()
            .push((field.to_string(), toml_scalar(&kind, &raw)));
    }
    let mut out = String::new();
    for (sec, fields) in by_section {
        out.push_str(&format!("[{sec}]\n"));
        for (field, val) in fields {
            out.push_str(&format!("{field} = {val}\n"));
        }
    }
    out
}

/// One settings row: label + description; the value cell is a staged input for an
/// `editable` field (else read-only); source / reload-class badges; and notes.
fn config_field_row(
    f: &Value,
    eff: Option<&Value>,
    edits: RwSignal<HashMap<String, String>>,
) -> AnyView {
    let label = api::s(f, "label");
    let key = api::s(f, "key");
    let desc = api::s(f, "description");
    let secret = f.get("secret").and_then(Value::as_bool).unwrap_or(false);
    let editable = f.get("editable").and_then(Value::as_bool).unwrap_or(false);
    let kind = api::s(f, "kind");
    let reload = api::s(f, "reload");
    let restart = api::s(f, "restart_impact");
    let airgap = api::s(f, "airgap_impact");
    let source = eff.map(|e| api::s(e, "source")).unwrap_or_default();
    let overridden = eff
        .and_then(|e| e.get("overridden_by_env"))
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let eff_value = eff
        .and_then(|e| e.get("value"))
        .cloned()
        .unwrap_or(Value::Null);
    let eff_raw = effective_raw(&eff_value);

    let value_cell = if secret {
        let configured = eff
            .and_then(|e| e.get("configured"))
            .and_then(Value::as_bool)
            .unwrap_or(false);
        if configured {
            ui::pill("pass", "configured")
        } else {
            ui::pill("dim", "not set")
        }
    } else if editable {
        if kind == "bool" {
            let (k1, k2) = (key.clone(), key.clone());
            let (e1, e2) = (eff_raw.clone(), eff_raw.clone());
            view! {
                <input type="checkbox"
                    prop:checked=move || edits.get().get(&k2).cloned().unwrap_or_else(|| e2.clone()) == "true"
                    on:change=move |ev| {
                        let v = if event_target_checked(&ev) { "true" } else { "false" }.to_string();
                        let mut m = edits.get();
                        if v == e1 { m.remove(&k1); } else { m.insert(k1.clone(), v); }
                        edits.set(m);
                    }/>
            }.into_any()
        } else {
            let (k1, k2) = (key.clone(), key.clone());
            let (e1, e2) = (eff_raw.clone(), eff_raw.clone());
            view! {
                <input type="text" class="mono grow"
                    prop:value=move || edits.get().get(&k2).cloned().unwrap_or_else(|| e2.clone())
                    on:input=move |ev| {
                        let v = event_target_value(&ev);
                        let mut m = edits.get();
                        if v == e1 { m.remove(&k1); } else { m.insert(k1.clone(), v); }
                        edits.set(m);
                    }/>
            }
            .into_any()
        }
    } else {
        view! { <span class="mono">{show_val(&eff_value)}</span> }.into_any()
    };
    let source_badge = match source.as_str() {
        "env" => ui::pill("warn", "environment"),
        "file_or_default" => ui::pill("dim", "file / default"),
        _ => ui::pill("dim", "unset"),
    };
    let reload_badge = {
        // Map the raw reload class to a label the operator can act on.
        let (cls, label) = match reload.as_str() {
            "governed" => ("pass", "Governed"),
            "hot" => ("pass", "Hot-reload"),
            "restart" => ("warn", "Restart required"),
            _ => ("dim", "—"),
        };
        ui::pill(cls, label)
    };
    let notes = {
        let mut parts: Vec<String> = Vec::new();
        if editable {
            parts.push("editable".into());
        }
        if overridden {
            parts.push("configured in file but overridden by environment".into());
        }
        if !restart.is_empty() {
            parts.push(format!("restart: {restart}"));
        }
        if !airgap.is_empty() {
            parts.push(format!("airgap: {airgap}"));
        }
        parts.join(" · ")
    };
    view! {
        <tr>
            <td><div><strong>{label}</strong></div><div class="dimtext mono">{key}</div><div class="dimtext">{desc}</div></td>
            <td>{value_cell}</td>
            <td>{source_badge}</td>
            <td>{reload_badge}</td>
            <td class="msg dimtext">{notes}</td>
        </tr>
    }.into_any()
}

fn posture_tab(_store: Store) -> AnyView {
    let posture = super::Fetch::new();
    let ha = super::Fetch::new();
    posture.load("/api/security/posture".into());
    ha.load("/api/ha/status".into());
    view! {
        <div>
            <p class="sub">"Security posture, HA role and air-gap state — so a loopback-open dev deployment is never invisible, and a follower's read-only stance is explicit."</p>
            {move || posture.data.get().map(|p| {
                let bool_pill = |k: &str, good_true: bool| {
                    let v = p.get(k).and_then(Value::as_bool).unwrap_or(false);
                    let good = v == good_true;
                    let cls = if good { "pass" } else { "warn" };
                    ui::pill(cls, format!("{}: {}", k.replace('_', " "), if v { "yes" } else { "no" }))
                };
                view! {
                    <div class="chips">
                        {bool_pill("auth_enabled", true)}
                        {bool_pill("passkey_enabled", true)}
                        {bool_pill("audit_ledger_enabled", true)}
                        {bool_pill("csrf_guard", true)}
                        {bool_pill("security_headers", true)}
                        {bool_pill("read_only", false)}
                        {bool_pill("airgap", true)}
                    </div>
                }
            })}
            {move || ha.data.get().map(|h| view! {
                <div class="card">
                    <div class="row"><strong>"High-availability role"</strong>
                        <ui::InfoPopover heading="Writer vs follower" body="Exactly one node is the writer: it accepts configuration changes and ingests events. Every other node is a follower that replicates the writer's data read-only and refuses write actions until it is promoted to writer during a failover."/>
                    </div>
                    {ui::kv_list(vec![
                        ("HA role", crate::status::humanize(&api::s(&h, "role"))),
                        ("Read-only follower", if h.get("read_only").and_then(Value::as_bool).unwrap_or(false) { "yes".into() } else { "no".into() }),
                    ])}
                    <div class="row"><strong>"Backups"</strong>
                        {ui::help_tip("A backup is only useful if it can be restored. Verification re-reads a backup end-to-end and checks its integrity, so a corrupt or incomplete backup is caught now instead of during a real recovery.")}
                    </div>
                    {ui::disabled_panel("Backup status", &crate::caps::FeatureState{ state: "not_configured".into(), reason: Some("Backups and their integrity checks aren't surfaced in the console yet — create and verify them from the host for now. Whether a restore would succeed, and how far a follower is behind replication, are only visible there too.".into())})}
                </div>
            })}
        </div>
    }.into_any()
}

/// Operator access: hold an admin token this session so protected controls
/// resolve to an Admin principal (mirrors a CLI/machine caller; a passkey session
/// supersedes it in production). Never persisted to disk.
fn access_tab(store: Store) -> AnyView {
    let tok = RwSignal::new(String::new());
    let set = move || {
        let t = tok.get_untracked();
        api::set_operator_token(Some(t.clone()));
        store.operator.set(api::has_operator_token());
        // Session-scoped only (cleared when the tab closes), never localStorage.
        if let Some(s) = web_sys::window()
            .and_then(|w| w.session_storage().ok())
            .flatten()
        {
            let _ = s.set_item("garmr-operator", &t);
        }
        tok.set(String::new());
        store.log_activity(
            "Operator token set",
            true,
            "admin actions enabled this session",
            None,
        );
    };
    let clear = move || {
        api::set_operator_token(None);
        store.operator.set(false);
        if let Some(s) = web_sys::window()
            .and_then(|w| w.session_storage().ok())
            .flatten()
        {
            let _ = s.remove_item("garmr-operator");
        }
        store.log_activity("Operator token cleared", true, String::new(), None);
    };
    view! {
        <div>
            <p class="sub">"Protected actions (approve/reject, promote, monitor, silence) require operator authorization. In production a passkey login resolves to an Admin principal automatically. On a token-only or lab deployment, hold the admin token here for this browser session — it is sent as a bearer, never placed in a URL and never written to disk."</p>
            <div class="card">
                <div class="row">
                    <span class="dimtext">"Operator status:"</span>
                    {move || if store.operator.get() { ui::pill("warn", "operator token held") } else { ui::pill("dim", "no operator token") }}
                </div>
                <div class="form-grid">
                    <label class="wide">"Admin token"
                        <input type="password" placeholder="Paste the admin token" prop:value=move || tok.get()
                            on:input=move |ev| tok.set(event_target_value(&ev))/>
                    </label>
                </div>
                <div class="row">
                    <button class="btn primary" on:click=move |_| set()>"Hold token (this session)"</button>
                    <button class="btn ghost" on:click=move |_| clear()>"Clear token"</button>
                </div>
            </div>
            {passkeys_section(store)}
            {api_credentials_section(store)}
            {secrets_section(store)}
        </div>
    }.into_any()
}

/// Scoped machine API credentials: issue (token shown once), list, revoke. Issue
/// and revoke require step-up server-side.
fn api_credentials_section(store: Store) -> AnyView {
    let creds = super::Fetch::new();
    creds.load("/api/credentials".into());
    let name = RwSignal::new(String::new());
    // Least-privilege default. Bound to the <option> `selected` attributes below so
    // the rendered selection always matches what `issue()` submits (a bare `prop:value`
    // on <select> can fail to paint the initial selection, minting a higher role than shown).
    let role = RwSignal::new("viewer".to_string());
    let scopes = RwSignal::new(String::new());
    let issued = RwSignal::new(Option::<String>::None);
    let issue = move || {
        let n = name.get_untracked();
        if n.trim().is_empty() {
            return;
        }
        let sc: Vec<String> = scopes
            .get_untracked()
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        let body = serde_json::json!({"name": n, "role": role.get_untracked(), "scopes": sc});
        leptos::task::spawn_local(async move {
            match api::send_post("/admin/credentials", body).await {
                Ok(v) => {
                    issued.set(v.get("token").and_then(Value::as_str).map(str::to_string));
                    store.log_activity("API credential issued", true, "copy the token now", None);
                    creds.load("/api/credentials".into());
                }
                Err(e) => store.log_activity(
                    "Credential issue refused",
                    false,
                    api::clean(&e.message),
                    None,
                ),
            }
        });
        name.set(String::new());
    };
    let revoke = move |id: String, label: String| {
        leptos::task::spawn_local(async move {
            match api::send_post("/admin/credentials/revoke", serde_json::json!({"id": id})).await {
                Ok(_) => {
                    store.log_activity("Credential revoked", true, label, None);
                    creds.load("/api/credentials".into());
                }
                Err(e) => store.log_activity(
                    "Credential revoke refused",
                    false,
                    api::clean(&e.message),
                    None,
                ),
            }
        });
    };
    view! {
        <section class="sect">
            <h3>"API credentials"</h3>
            <p class="dimtext">"Individually scoped machine tokens for collectors, CLI automation, and integrations. The token is shown once at issue and never retrievable again; only a keyed digest is stored. Issue and revoke require step-up."{ui::help_tip("Step-up means the action needs a fresh identity check: you must have signed in with your passkey very recently, not just hold an older session, before a sensitive change is allowed.")}</p>
            <div class="form-grid">
                <input type="text" placeholder="name (e.g. pgaudit-shipper)" prop:value=move || name.get() on:input=move |ev| name.set(event_target_value(&ev))/>
                <select on:change=move |ev| role.set(event_target_value(&ev))>
                    <option value="viewer" selected=move || role.get() == "viewer">"viewer"</option>
                    <option value="analyst" selected=move || role.get() == "analyst">"analyst"</option>
                    <option value="admin" selected=move || role.get() == "admin">"admin"</option>
                </select>
                <input type="text" class="wide" placeholder="scopes (comma-separated)" prop:value=move || scopes.get() on:input=move |ev| scopes.set(event_target_value(&ev))/>
                {ui::help_tip("Scopes are the specific things this token may do — for example which sources it can write to. Grant only what the integration needs; leave blank to fall back to the role's defaults.")}
                <button class="btn primary" on:click=move |_| issue()>"Issue credential"</button>
            </div>
            {move || issued.get().map(|t| view! {
                <div class="card">
                    <div class="dimtext">"Copy this token now — it will not be shown again:"</div>
                    <input type="text" class="wide mono" prop:value=t readonly=true/>
                    <button class="btn ghost" on:click=move |_| issued.set(None)>"Hide token"</button>
                </div>
            })}
            {move || {
                if let Some(e) = creds.err.get() { return super::error_state(e); }
                let rows = creds.rows("credentials");
                let legacy = creds.data.get().map(|d| super::arr(&d, "legacy")).unwrap_or_default();
                if rows.is_empty() && legacy.is_empty() { return ui::empty("No API credentials issued yet — fill in a name and scopes above and choose Issue credential to create one for a collector, script, or integration."); }
                let body = rows.into_iter().map(|c| {
                    let id = api::s(&c, "id");
                    let label = api::s(&c, "name");
                    let status = api::s(&c, "status");
                    let active = status == "active";
                    let rev = revoke;
                    let id2 = id.clone(); let l2 = label.clone();
                    view! {
                        <tr>
                            <td>{api::s(&c, "name")}</td>
                            <td class="mono">{api::s(&c, "principal")}</td>
                            <td>{ui::pill("dim", api::s(&c, "role"))}</td>
                            <td class="dimtext">{super::arr(&c, "scopes").into_iter().filter_map(|s| s.as_str().map(str::to_string)).collect::<Vec<_>>().join(", ")}</td>
                            <td>{if active { ui::pill("pass", "active") } else { ui::pill("warn", status) }}</td>
                            <td>{active.then(move || view! { <button class="btn ghost" on:click=move |_| rev(id2.clone(), l2.clone())>"Revoke"</button> })}</td>
                        </tr>
                    }
                }).collect_view();
                let legacy_body = legacy.into_iter().map(|l| view! {
                    <tr class="dimtext">
                        <td>{api::s(&l, "principal")}</td><td colspan="4">{api::clean(&api::s(&l, "note"))}</td><td></td>
                    </tr>
                }).collect_view();
                super::table(&["name", "principal", "role", "scopes", "status", ""],
                    view! { {body}{legacy_body} }.into_any())
            }}
        </section>
    }.into_any()
}

/// Write-only secret management: per-secret source + fingerprint (never a value),
/// set/replace for the sealed-store-writable ones, and an airgap-aware LLM key
/// test. Setting requires step-up server-side.
fn secrets_section(store: Store) -> AnyView {
    let secrets = super::Fetch::new();
    secrets.load("/api/secrets".into());
    view! {
        <section class="sect">
            <h3>"Secrets"</h3>
            <p class="dimtext">"External-integration secrets. Values are write-only — never shown here. Setting or replacing one requires a recent user-verified passkey (step-up) and takes effect after a restart. Environment-configured secrets cannot be replaced from the UI."{ui::help_tip("Rotate a secret by entering a new value and saving it — the new value overwrites the old one in place. Rotate on a schedule, and immediately if a secret might have leaked.")}<ui::InfoPopover heading="Write-only secret store" body="Secrets you set here are encrypted into a sealed store and can never be read back through the console — you can overwrite a value but never view it. Only a short fingerprint is shown, so you can tell two values apart without exposing them; that way a stolen console session can't exfiltrate your secrets."/></p>
            {move || {
                if let Some(e) = secrets.err.get() { return super::error_state(e); }
                let Some(data) = secrets.data.get() else { return ui::loading("loading secrets…"); };
                let writable_store = data.get("writable_store").and_then(Value::as_bool).unwrap_or(false);
                let rows = super::arr(&data, "secrets");
                view! {
                    <div>
                        {(!writable_store).then(|| view! {
                            <p class="dimtext">"⚠ No encryption master key is configured, so the secret store can't be written and secrets can only come from the environment for now. Configure a master key on the host to enable setting secrets from here."</p>
                        })}
                        {super::table(&["secret", "source", "fingerprint", "set / replace", ""],
                            rows.into_iter().map(|s| secret_row(store, s, secrets)).collect_view().into_any())}
                    </div>
                }.into_any()
            }}
        </section>
    }.into_any()
}

fn secret_row(store: Store, s: Value, secrets: super::Fetch) -> AnyView {
    let name = api::s(&s, "name");
    let source = api::s(&s, "source");
    let fp = api::s(&s, "fingerprint");
    let writable = s.get("writable").and_then(Value::as_bool).unwrap_or(false);
    let overridden = s
        .get("overridden_by_env")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let is_llm = name == "ANTHROPIC_API_KEY" || name == "GARMR_OPENAI_API_KEY";
    let val = RwSignal::new(String::new());
    let set_name = name.clone();
    let set = move || {
        let name = set_name.clone();
        let v = val.get_untracked();
        if v.is_empty() {
            return;
        }
        leptos::task::spawn_local(async move {
            match api::send_post(
                "/admin/secrets",
                serde_json::json!({"name": name, "value": v}),
            )
            .await
            {
                Ok(_) => {
                    store.log_activity("Secret set", true, "restart to apply", None);
                    secrets.load("/api/secrets".into());
                }
                Err(e) => {
                    store.log_activity("Secret set refused", false, api::clean(&e.message), None)
                }
            }
        });
        val.set(String::new());
    };
    let test_name = name.clone();
    let test = move || {
        let name = test_name.clone();
        leptos::task::spawn_local(async move {
            match api::send_post("/admin/secrets/test", serde_json::json!({"name": name})).await {
                Ok(v) => store.log_activity(
                    "Secret test",
                    v.get("ok").and_then(Value::as_bool).unwrap_or(false),
                    api::clean(&api::s(&v, "note")),
                    None,
                ),
                Err(e) => {
                    store.log_activity("Secret test failed", false, api::clean(&e.message), None)
                }
            }
        });
    };
    let src_badge = match source.as_str() {
        "env" => ui::pill("warn", "environment"),
        "sealed" => ui::pill("pass", "encrypted store"),
        _ => ui::pill("dim", "unset"),
    };
    view! {
        <tr>
            <td class="mono">{name}</td>
            <td>{src_badge}{overridden.then(|| ui::pill("warn", "env override"))}</td>
            <td class="mono dimtext">{if fp.is_empty() { "—".to_string() } else { fp }}</td>
            <td>
                {if writable {
                    view! { <input type="password" placeholder="new value" prop:value=move || val.get()
                        on:input=move |ev| val.set(event_target_value(&ev))/> }.into_any()
                } else {
                    view! { <span class="dimtext">"env-managed"</span> }.into_any()
                }}
            </td>
            <td>
                {writable.then(move || view! { <button class="btn ghost" on:click=move |_| set()>"Save secret"</button> })}
                {is_llm.then(move || view! { <button class="btn ghost" on:click=move |_| test()>"Test connection"</button> })}
            </td>
        </tr>
    }.into_any()
}

/// Passkey credential administration: the registered authenticators, the named
/// identity + role each logs in as, revoke (step-up + last-admin protected), and
/// the log-out-everywhere control. Registration itself is the WebAuthn ceremony
/// on the /login page (needs navigator.credentials.create).
fn passkeys_section(store: Store) -> AnyView {
    let creds = super::Fetch::new();
    creds.load("/auth/passkey/credentials".into());
    let ts = |sec: i64| {
        if sec > 0 {
            api::ts_iso(sec * 1_000_000)
        } else {
            "—".into()
        }
    };
    let revoke = move |id: String, label: String| {
        leptos::task::spawn_local(async move {
            match api::send_post(
                "/auth/passkey/credentials/revoke",
                serde_json::json!({"id": id}),
            )
            .await
            {
                Ok(_) => {
                    store.log_activity("Passkey revoked", true, label, None);
                    creds.load("/auth/passkey/credentials".into());
                }
                Err(e) => store.log_activity(
                    "Passkey revoke refused",
                    false,
                    api::clean(&e.message),
                    None,
                ),
            }
        });
    };
    let revoke_all = move || {
        leptos::task::spawn_local(async move {
            match api::send_post("/auth/sessions/revoke-all", serde_json::json!({})).await {
                Ok(_) => store.log_activity(
                    "All sessions logged out",
                    true,
                    "you will be signed out",
                    None,
                ),
                Err(e) => {
                    store.log_activity("Log-out-all failed", false, api::clean(&e.message), None)
                }
            }
        });
    };
    view! {
        <section class="sect">
            <h3>"Passkey credentials"{ui::help_tip("A passkey signs you in with your device or security key instead of a password. It is phishing-resistant — the secret never leaves the authenticator and can't be typed into a fake page.")}</h3>
            <p class="dimtext">"Registered authenticators and the named identity + role each logs in as. Revoking the last enabled Admin key is refused; revoke requires a recent user-verified passkey session (step-up). Register new keys on the login page."</p>
            {move || {
                if let Some(e) = creds.err.get() { return super::error_state(e); }
                let rows = creds.rows("credentials");
                if rows.is_empty() { return ui::empty("No passkeys registered yet — register one from the login page to sign in without a password."); }
                super::table(&["user", "role", "label", "created", "last used", ""],
                    rows.into_iter().map(|c| {
                        let id = api::s(&c, "id");
                        let label = api::s(&c, "label");
                        let disabled = c.get("disabled").and_then(Value::as_bool).unwrap_or(false);
                        let created = api::num(&c, "created");
                        let last = c.get("last_used").and_then(Value::as_i64).unwrap_or(0);
                        let rev = revoke;
                        let id2 = id.clone();
                        let label2 = label.clone();
                        view! {
                            <tr>
                                <td class="mono">{api::s(&c, "user")}</td>
                                <td>{ui::pill("dim", api::s(&c, "role"))}</td>
                                <td>{label}{disabled.then(|| ui::pill("warn", "disabled"))}</td>
                                <td class="mono dimtext">{ts(created)}</td>
                                <td class="mono dimtext">{ts(last)}</td>
                                <td><button class="btn ghost" on:click=move |_| rev(id2.clone(), label2.clone())>"Revoke"</button></td>
                            </tr>
                        }
                    }).collect_view().into_any())
            }}
            <div class="row">
                <button class="btn ghost" on:click=move |_| revoke_all()>"Log out all sessions"</button>
                <span class="dimtext">"Invalidates every passkey session immediately (including yours)."</span>
            </div>
        </section>
    }.into_any()
}