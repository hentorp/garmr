// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! Host baselines — "what is normal for this host?".
//!
//! For M1 the baseline is computed on demand from the events table (distinct
//! services, source IPs, and ports seen for the host over the retention
//! window). A periodic rollup into the redb `baselines` table is a follow-up;
//! the tool contract (`get_host_baseline`) is stable either way.

use garmr_core::Result;
use garmr_store::Store;

use crate::tools::format_batches;

/// Describe a host's normal over the last 30 days: top services, source IPs,
/// and users. Matches the `get_host_baseline` tool contract.
pub async fn describe(store: &Store, host: &str) -> Result<String> {
    let h = host.replace('\'', "''");
    let window = "event_ts >= now() - INTERVAL '30 days'";

    let services = store
        .events
        .sql(format!(
            "SELECT service, count(*) AS n FROM events \
             WHERE host = '{h}' AND {window} GROUP BY service ORDER BY n DESC LIMIT 15"
        ))
        .await?;
    // Extract the JSON field value with regexp_replace (a default DataFusion
    // function — no JSON extension needed). The LIKE filter guarantees the key
    // is present, so the replace always yields the value.
    let src_ips = store
        .events
        .sql(format!(
            "SELECT regexp_replace(fields, '.*\"src_ip\":\"([^\"]+)\".*', '$1') AS src_ip, \
             count(*) AS n FROM events \
             WHERE host = '{h}' AND {window} AND fields LIKE '%\"src_ip\"%' \
             GROUP BY 1 ORDER BY n DESC LIMIT 15"
        ))
        .await
        .unwrap_or_default();
    let users = store
        .events
        .sql(format!(
            "SELECT regexp_replace(fields, '.*\"user\":\"([^\"]+)\".*', '$1') AS \"user\", \
             count(*) AS n FROM events \
             WHERE host = '{h}' AND {window} AND fields LIKE '%\"user\"%' \
             GROUP BY 1 ORDER BY n DESC LIMIT 15"
        ))
        .await
        .unwrap_or_default();

    Ok(format!(
        "Baseline for {host} (last 30 days)\n\nMost common services:\n{}\nMost common source IPs:\n{}\nMost common users:\n{}",
        format_batches(&services),
        if src_ips.is_empty() { "(none)\n".into() } else { format_batches(&src_ips) },
        if users.is_empty() { "(none)\n".into() } else { format_batches(&users) },
    ))
}
