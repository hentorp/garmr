// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! Data Sources — collectors, ingest health, freshness, and the retention/cold
//! tier. The health of the pipeline that everything else depends on, in one place.

use leptos::prelude::*;

use crate::route::Area;
use crate::{api, ui, Store};

pub fn view(store: Store) -> impl IntoView {
    let ingest = super::Fetch::new();
    ingest.load("/api/ingest/health".into());
    let collectors = super::Fetch::new();
    collectors.load("/api/collectors".into());
    let reload = move || {
        ingest.load("/api/ingest/health".into());
        collectors.load("/api/collectors".into());
    };

    view! {
        <div class="page">
            <div class="page-header row">
                <div class="grow"><h1>"Data Sources"</h1><div class="sub">{Area::DataSources.blurb()}</div></div>
                <button class="btn ghost" on:click=move |_| reload()>"↻ Refresh"</button>
            </div>

            <section class="sect">
                <h3>"Collectors & ingest health "{ui::help_tip("Collector health is whether each source is still delivering events and how current its data is. A healthy source is fresh (delivering recently); one that falls silent goes stale, which usually means a broken collector or an outage worth investigating.")}</h3>
                <p class="sub">"Per source: how many events it has delivered, how far behind real time it is, and whether it is still current. "<b>"Freshness"</b>" is how recently a source last delivered; a "<b>"STALE"</b>" source has gone silent."</p>
                {ingest.framed("sources", "No source has delivered any events yet — point a collector or log source at garmr (for example a syslog forwarder or the garmr agent) and its events will appear here.", |rows| {
                    super::table(&["source", "events", "ingest lag", "staleness", "freshness"],
                        rows.into_iter().map(|s| {
                            let stale = api::num(&s, "staleness_secs");
                            let (word, cls) = if stale > 3600 { ("STALE", "bad") } else if stale > 600 { ("slow", "warn") } else { ("fresh", "pass") };
                            view! {
                                <tr>
                                    <td class="mono">{api::s(&s, "source")}</td>
                                    <td class="mono dimtext">{api::num(&s, "events").to_string()}</td>
                                    <td class="mono dimtext">{format!("{}s", api::num(&s, "ingest_lag_secs"))}</td>
                                    <td class="mono dimtext">{format!("{}s", stale)}</td>
                                    <td>{ui::pill(cls, word)}</td>
                                </tr>
                            }
                        }).collect_view().into_any())
                })}
            </section>

            <section class="sect">
                <h3>"Collector delivery (sequence integrity)"</h3>
                <p class="sub">"Per authenticated collector + epoch: confirmed gaps (lost batches), still-outstanding sequences (lost or in flight), and replays (duplicate delivery). Distinct from the event-lag view above. "{ui::help_tip("Sequence integrity checks that every batch a collector sent actually arrived, in order — it is how you know the data is complete. Gaps mean batches were confirmed lost, outstanding means some are unaccounted for, and replays mean duplicates were received.")}</p>
                {collectors.framed("collectors", "no authenticated collector has reported a delivery sequence yet", |rows| {
                    super::table(&["collector", "epoch", "high seq", "gaps", "outstanding", "replays", "delivery"],
                        rows.into_iter().map(|c| {
                            let gaps = api::num(&c, "gaps");
                            let outstanding = api::num(&c, "outstanding");
                            let replays = api::num(&c, "replays");
                            let (word, cls) = if gaps > 0 { ("gaps", "bad") }
                                else if outstanding > 0 { ("outstanding", "warn") }
                                else if replays > 0 { ("replays", "warn") }
                                else { ("clean", "pass") };
                            view! {
                                <tr>
                                    <td class="mono">{api::s(&c, "collector_id")}</td>
                                    <td class="mono dimtext">{api::num(&c, "epoch").to_string()}</td>
                                    <td class="mono dimtext">{api::num(&c, "high_seq").to_string()}</td>
                                    <td class="mono dimtext">{gaps.to_string()}</td>
                                    <td class="mono dimtext">{outstanding.to_string()}</td>
                                    <td class="mono dimtext">{replays.to_string()}</td>
                                    <td>{ui::pill(cls, word)}</td>
                                </tr>
                            }
                        }).collect_view().into_any())
                })}
            </section>

            <section class="sect">
                <h3>"Retention & cold storage"</h3>
                {move || store.caps.get().map(|c| {
                    let fs = c.feature("cold_storage");
                    if fs.state == "healthy" {
                        view! { <div class="row">{ui::pill("pass", "cold tier configured")}</div> }.into_any()
                    } else {
                        ui::disabled_panel("Cold storage / retention", &fs)
                    }
                })}
            </section>
        </div>
    }
}