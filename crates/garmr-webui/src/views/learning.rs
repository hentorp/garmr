// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! Learning — the safe learning plane, shown as the Learning tab of Detections:
//! the live champion detector-config, its challengers (versions awaiting
//! evaluation/approval), and the dangerous-miss register. The lifecycle stages
//! (suggested → evaluated → approved → active → rolled back) are shown by each
//! registry record's approval/active state; a challenger goes live only via an
//! audited `registry promote`.

use leptos::prelude::*;
use serde_json::Value;

use crate::{api, ui, Store};

pub fn tab(store: Store) -> AnyView {
    let _ = &store;
    let active = super::Fetch::new();
    let detectors = super::Fetch::new();
    let misses = super::Fetch::new();
    let shadow = super::Fetch::new();
    let shadow_scores = super::Fetch::new();
    active.load("/api/registry/active".into());
    detectors.load("/api/registry/detector_config".into());
    misses.load("/api/false-negatives".into());
    shadow.load("/api/shadow/summary".into());
    shadow_scores.load("/api/shadow/scores".into());

    view! {
        <div>
            <p class="sub">"Champion / challenger "{ui::help_tip("The champion is the detector configuration serving live right now. A challenger is a proposed alternative, evaluated safely without touching live decisions; it becomes champion only when an operator promotes it, and a bad promotion can be rolled back to the previous version.")}" over an immutable dataset "{ui::help_tip("Challengers are scored against a frozen, versioned copy of the data — a dataset — so every version is judged on exactly the same evidence and the results are reproducible.")}" — nothing here mutates the serving policy. A challenger goes live only through an audited registry promotion, so "<b>"suggested"</b>", "<b>"approved"</b>" and "<b>"active"</b>" are always distinct."</p>

            <section class="sect">
                <h3>"Champion — active detector configuration"</h3>
                {move || {
                    let champ: Vec<Value> = active.rows("active").into_iter().filter(|r| api::s(r, "kind") == "detector_config").collect();
                    if champ.is_empty() {
                        return ui::empty("No detector configuration has been promoted to active, so garmr is serving on its built-in observed default. Promote a challenger below to make it the champion.");
                    }
                    reg_table(champ)
                }}
            </section>

            <section class="sect">
                <h3>"Challengers — detector-config versions"</h3>
                {detectors.framed("records", "No challenger configurations have been registered yet — train one offline from recorded data, then register it here to evaluate it against the champion (CLI: garmr learn).", reg_table)}
            </section>

            <section class="sect">
                <h3>"Shadow evaluation — live champion vs challenger "<ui::InfoPopover heading="Shadow mode" body="In shadow mode a challenger scores every live event alongside the champion, but its verdicts are recorded only — they never affect real alerting. This measures how the two disagree on real traffic. The recommendation weighs that disagreement against the alert budget (how many extra alerts the challenger would raise) and calibration (whether its confidence scores match reality), but it is advisory only: a human still promotes."/></h3>
                <p class="sub">"A challenger registered on the "<b>"shadow"</b>" channel (with "<code>"GARMR_SHADOW"</code>" set) is scored against the champion on every event. This is the LIVE, label-free disagreement signal; the recommendation is "<b>"advisory"</b>" — promotion stays a governed registry action. Labelled recall/FPR comes from "<code>"garmr synth-eval"</code>"."</p>
                {move || {
                    if let Some(e) = shadow.err.get() {
                        return super::error_state(e);
                    }
                    let Some(v) = shadow.data.get() else {
                        return ui::loading("loading…");
                    };
                    let enabled = v.get("enabled").and_then(Value::as_bool).unwrap_or(false);
                    let has_challenger = v
                        .get("active_challenger")
                        .map(|c| !c.is_null())
                        .unwrap_or(false);
                    if !enabled || !has_challenger {
                        return ui::empty("No challenger is being shadow-tested right now — enable shadow evaluation and promote a challenger onto the shadow channel to compare it against the live champion here. (Set GARMR_SHADOW to enable.)");
                    }
                    let ch = v.get("active_challenger").cloned().unwrap_or_default();
                    let rec = api::s(&v, "recommendation");
                    let rc = if rec.starts_with("REJECT") {
                        "bad"
                    } else if rec.starts_with("REVIEW") {
                        "warn"
                    } else if rec.starts_with("PROMOTE") {
                        "pass"
                    } else {
                        "dim"
                    };
                    view! {
                        <p>{ui::pill(rc, rec)}</p>
                        {ui::kv_list(vec![
                            ("challenger", format!("{} v{}", api::s(&ch, "name"), api::s(&ch, "version"))),
                            ("events scored", api::num(&v, "events_scored").to_string()),
                            ("diff events", api::num(&v, "diff_events").to_string()),
                            ("challenger-only", api::num(&v, "challenger_only").to_string()),
                            ("champion-only", api::num(&v, "champion_only").to_string()),
                            ("dangerous misses", api::num(&v, "dangerous_misses").to_string()),
                        ])}
                    }
                    .into_any()
                }}
                {shadow_scores.framed("rows", "no champion-vs-challenger disagreements recorded yet", |rows| {
                    super::table(&["when", "actor", "object", "challenger-only", "champion-only", ""],
                        rows.into_iter().map(|r| {
                            let joined = |k: &str| r.get(k).and_then(Value::as_array)
                                .map(|a| a.iter().filter_map(Value::as_str).collect::<Vec<_>>().join(", "))
                                .unwrap_or_default();
                            let dangerous = r.get("dangerous_miss").and_then(Value::as_bool).unwrap_or(false);
                            view! {
                                <tr>
                                    <td class="mono dimtext">{api::s(&r, "at")}</td>
                                    <td class="mono">{api::clean(&api::s(&r, "actor"))}</td>
                                    <td class="mono dimtext">{api::clean(&api::s(&r, "object"))}</td>
                                    <td class="mono">{joined("added")}</td>
                                    <td class="mono">{joined("removed")}</td>
                                    <td>{if dangerous { ui::pill("bad", "dangerous") } else { ui::pill("dim", "—") }}</td>
                                </tr>
                            }
                        }).collect_view().into_any())
                })}
            </section>

            <section class="sect">
                <h3>"Dangerous misses (false negatives) "{ui::help_tip("A dangerous miss is a false negative that mattered — a genuinely malicious event the detectors failed to flag. Each one is logged here so it can be turned into a test case and never slip through the same way again.")}</h3>
                {misses.framed("false_negatives", "no dangerous misses registered — a clean record, or none have been reported", |rows| {
                    super::table(&["when", "disposition", "severity", "note"],
                        rows.into_iter().map(|r| view! {
                            <tr>
                                <td class="mono dimtext">{api::s(&r, "created_at")}</td>
                                <td>{ui::pill("bad", crate::status::humanize(&api::s(&r, "disposition")))}</td>
                                <td class="mono dimtext">{api::num(&r, "severity").to_string()}</td>
                                <td class="msg">{api::clean(&api::s(&r, "narrative"))}</td>
                            </tr>
                        }).collect_view().into_any())
                })}
            </section>
        </div>
    }
    .into_any()
}

/// A registry-record table showing the promotion lifecycle state.
pub fn reg_table(rows: Vec<Value>) -> AnyView {
    super::table(&["name", "version", "approval", "active", "digest"],
        rows.into_iter().map(|r| {
            let approval = api::s(&r, "approval");
            let approval = if approval.is_empty() { api::s(&r, "state") } else { approval };
            let active = r.get("active").and_then(Value::as_bool).unwrap_or(false);
            let ac = match approval.as_str() { "approved" | "active" => "pass", "rejected" | "retired" => "bad", "draft" | "suggested" => "warn", _ => "dim" };
            view! {
                <tr>
                    <td class="mono">{api::clean(&api::s(&r, "name"))}</td>
                    <td class="mono dimtext">{api::clean(&api::s(&r, "version"))}</td>
                    <td>{ui::pill(ac, if approval.is_empty() { "—".into() } else { crate::status::humanize(&approval) })}</td>
                    <td>{if active { ui::pill("pass", "active") } else { ui::pill("dim", "—") }}</td>
                    <td class="mono dimtext">{api::short(&r, "content_digest")}</td>
                </tr>
            }
        }).collect_view().into_any())
}
