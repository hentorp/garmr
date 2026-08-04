// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! The shared entity renderer — a host, IP, user, staff member or data subject
//! as one page: volume tiles, the cases it triggered (institutional memory), and
//! recent events. Used by the Users and Applications detail pages, the universal
//! entity drawer, and the `/entity/:kind/:name` deep link.

use leptos::prelude::*;
use serde_json::Value;

use crate::route::View;
use crate::{api, status, ui, Store};

/// The `/entity/:kind/:name` deep-link page: fetch + render + a relationship
/// pivot. A useful not-found / access-denied state on failure.
pub fn deep_link_view(store: Store, kind: String, name: String) -> impl IntoView {
    let f = super::Fetch::new();
    f.load(format!(
        "/api/entity/{}/{}",
        api::enc(&kind),
        api::enc(&name)
    ));
    let (k, n) = (kind.clone(), name.clone());
    view! {
        {ui::page_header(format!("{kind}: {name}"), "Entity page — activity, investigations and recent events.")}
        <p class="sub">"The full page for this entity. "{ui::help_tip("This is the full entity page, reachable by a stable link you can share. The same tiles, investigations and recent events also open as a quick side drawer when you click an entity elsewhere in the console — the full page just gives them more room.")}</p>
        {move || {
            if let Some(e) = f.err.get() {
                return super::error_state(e);
            }
            match f.data.get() {
                None => ui::loading("resolving entity…"),
                Some(p) => entity_page(store, &k, &n, &p).into_any(),
            }
        }}
    }
}

/// Render an entity page body. `page` is an `/api/entity/*` response. The name is
/// shown by the caller's page header, so it is not repeated here.
pub fn entity_page(store: Store, kind: &str, _name: &str, page: &Value) -> AnyView {
    let cases = super::arr(page, "cases");
    let recent = super::arr(page, "recent_events");

    let mut tiles: Vec<(String, f64)> = match kind {
        "host" => vec![
            ("events · total".into(), count(page, &["events_total"])),
            ("events · 24h".into(), count(page, &["events_24h"])),
        ],
        "ip" => vec![("sightings".into(), count(page, &["sightings", "n"]))],
        _ => vec![("activity".into(), count(page, &["activity", "n"]))],
    };
    let n_cases = cases.len() as f64;
    tiles.push(("open investigations".into(), n_cases));
    let cases_cls = if n_cases > 0.0 { "warn" } else { "pass" };

    view! {
        <div class="tiles">
            {tiles.into_iter().map(|(k, v)| {
                let cls = if k == "open investigations" { cases_cls } else { "pass" };
                ui::metric(k, (v as i64).to_string(), cls, None)
            }).collect_view()}
        </div>

        <section class="sect">
            <h3>{format!("Investigations ({})", cases.len())}{ui::help_tip("Past and open investigations that named this entity — garmr's institutional memory, so you can see whether it has come up before and how those investigations were resolved.")}</h3>
            {if cases.is_empty() {
                ui::empty("no investigations reference this entity")
            } else {
                super::table(&["id", "state", "rule", "events", "updated"],
                    cases.into_iter().map(|c| {
                        let id = api::s(&c, "id");
                        let idc = id.clone();
                        let short_id = api::short(&c, "id");
                        let st = api::s(&c, "state");
                        view! {
                            <tr class="rowlink" on:click=move |_| store.nav.go(View::Investigation(idc.clone()))>
                                <td class="mono dimtext">
                                    <ui::ViewLink view=View::Investigation(id) class="rowtarget">
                                        {short_id}
                                    </ui::ViewLink>
                                </td>
                                <td>{ui::state_badge(&st)}</td>
                                <td>{api::clean(&api::s(&c, "rule"))}</td>
                                <td class="mono dimtext">{api::num(&c, "event_count").to_string()}</td>
                                <td class="mono dimtext">{api::s(&c, "updated_at")}</td>
                            </tr>
                        }
                    }).collect_view().into_any())
            }}
        </section>

        <section class="sect">
            <h3>{format!("Recent events ({})", recent.len())}{ui::help_tip("The most recent log lines that mention this entity — a bounded, newest-first slice for quick context, not its full history. Use the Audit explorer to search everything.")}</h3>
            {if recent.is_empty() {
                ui::empty("no recent events")
            } else {
                super::table(&["time", "service", "sev", "message"],
                    recent.into_iter().map(|e| {
                        let sev = api::s(&e, "severity");
                        let sc = status::severity_class(&sev);
                        view! {
                            <tr>
                                <td class="mono dimtext">{api::s(&e, "event_ts")}</td>
                                <td>{api::s(&e, "service")}</td>
                                <td class=format!("sev {sc}")>{sev}</td>
                                <td class="msg">{api::clean(&api::s(&e, "message"))}</td>
                            </tr>
                        }
                    }).collect_view().into_any())
            }}
        </section>
    }
    .into_any()
}

/// Read a count that may be a JSON int or a stringly int, at a nested path.
pub fn count(v: &Value, path: &[&str]) -> f64 {
    let mut cur = v;
    for p in path {
        cur = &cur[*p];
    }
    cur.as_str()
        .and_then(|s| s.parse().ok())
        .or_else(|| cur.as_i64().map(|n| n as f64))
        .unwrap_or(0.0)
}
