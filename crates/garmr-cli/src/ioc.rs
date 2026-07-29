// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! Online threat-intel feed refresh: the default free IP-IOC feeds, the
//! GARMR_IOC_FEED_URLS config, and the background loop that hot-swaps the
//! enricher IOC set (auto-detecting STIX bundles vs plain IP lists). Every feed
//! is routed through the egress chokepoint: under GARMR_AIRGAP all EXTERNAL feeds
//! are dropped (so `configured_ioc_feeds` returns empty for the usual external
//! defaults), but a feed at a loopback/LAN mirror is retained (invariant #6).

use super::*;

/// Free, key-less, IP-per-line IOC feeds refreshed online by default.
const DEFAULT_IOC_FEEDS: &[(&str, &str)] = &[
    (
        "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
        "abuse.ch-feodo",
    ),
    ("https://lists.blocklist.de/lists/all.txt", "blocklist.de"),
];

/// The online IOC feeds to refresh: `GARMR_IOC_FEED_URLS` (comma-separated
/// `url` or `url|label`) overrides the defaults; an explicitly empty value
/// disables online feeds (local `ioc_feeds` only). The label delimiter is `|`
/// (not `=`) because feed URLs routinely carry `?token=…` query strings.
pub(crate) fn configured_ioc_feeds() -> Vec<(String, String)> {
    let raw: Vec<(String, String)> = match std::env::var("GARMR_IOC_FEED_URLS") {
        Ok(s) => s
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|entry| match entry.split_once('|') {
                Some((u, l)) => (u.trim().to_string(), l.trim().to_string()),
                None => (entry.to_string(), ioc_url_label(entry)),
            })
            .collect(),
        Err(_) => DEFAULT_IOC_FEEDS
            .iter()
            .map(|(u, l)| (u.to_string(), l.to_string()))
            .collect(),
    };
    // Egress chokepoint (invariant #1): drop any feed the policy denies —
    // unifying on the ONE gate instead of a bespoke airgap branch. Under airgap
    // every external feed is dropped (behavior preserved), but a loopback/LAN
    // mirror now works; each drop is audited inside check().
    raw.into_iter()
        .filter(|(u, _)| {
            garmr_core::egress::global()
                .check(garmr_core::EgressClass::IocFeed, u)
                .is_ok()
        })
        .collect()
}

/// A short feed label derived from a URL host (fallback when none is given).
fn ioc_url_label(url: &str) -> String {
    url.split("://")
        .nth(1)
        .and_then(|rest| rest.split('/').next())
        .unwrap_or(url)
        .to_string()
}

/// Periodically fetch the online IOC feeds, merge with the local static files,
/// and atomically replace the enricher's IOC set. Runs immediately, then every
/// `interval`.
///
/// Resilience: a per-feed last-good cache means a feed that fails a round
/// retains its previous IOCs (a transient timeout no longer drops that feed's
/// entries until it recovers), and a round that yields nothing keeps the
/// previous set. Bodies are size-capped while streaming (chunked responses
/// included), and local files reuse the capped, stem-labeled loader.
///
/// Feed format is auto-detected per round: a STIX 2.1 bundle (a JSON object
/// with an `objects` array — what a TAXII 2.1 collection returns) yields both
/// IP and domain indicators; anything else is parsed as plain IP-per-line.
pub(crate) async fn ioc_refresh_loop(
    enricher: std::sync::Arc<garmr_enrich::Enricher>,
    local_files: Vec<String>,
    feeds: Vec<(String, String)>,
    interval: std::time::Duration,
) {
    use std::collections::HashMap;
    const MAX_FEED_BYTES: usize = 128 * 1024 * 1024;
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        // Egress chokepoint (invariant #1): the destination host is egress-checked
        // ONCE at the configured URL. Following a 3xx would send bytes to an
        // un-checked, un-audited host (a compromised LAN mirror answering
        // `302 Location: https://attacker/…` escapes the air-gap), so redirects
        // are refused outright — a feed must be a direct URL.
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("build reqwest client");
    // url -> last successfully-fetched feed contribution, kept across rounds.
    struct FeedCache {
        ips: Vec<(String, String)>,
        domains: Vec<(String, String)>,
        /// Was the last good body parsed as a STIX bundle? Distinguishes a
        /// structured feed that legitimately returned 0 domains (a retraction —
        /// must clear) from a plain-text feed that never carries domains (must
        /// not touch the domain set).
        stix: bool,
    }
    let mut cache: HashMap<String, FeedCache> = HashMap::new();
    loop {
        for (url, label) in &feeds {
            match fetch_capped(&client, url, MAX_FEED_BYTES).await {
                Ok(body) => {
                    let stix = looks_like_stix(&body);
                    let (ips, domains) = if stix {
                        garmr_enrich::parse_stix_bundle(&body, label)
                    } else {
                        (garmr_enrich::parse_feed_text(&body, label), Vec::new())
                    };
                    tracing::info!(feed = %label, ips = ips.len(), domains = domains.len(), stix, "IOC feed fetched");
                    cache.insert(url.clone(), FeedCache { ips, domains, stix });
                }
                // Keep the last-good contribution for this feed on failure.
                Err(e) => {
                    tracing::warn!(feed = %label, error = %e, cached = cache.contains_key(url), "IOC feed fetch failed")
                }
            }
        }
        // Merge: local static files (capped + stem-labeled) + every feed's
        // last-good set. First writer wins per IP (local, then feed order).
        let mut map = garmr_enrich::load_ioc_files(&local_files);
        let mut domain_map: HashMap<String, String> = HashMap::new();
        // Do we have authority over the domain set this round? Only if at least
        // one currently-cached feed is STIX-parsed — otherwise domains are not
        // ours to touch (there are no local domain files as a floor).
        let mut have_domain_authority = false;
        for (url, _) in &feeds {
            if let Some(fc) = cache.get(url) {
                for (ip, label) in &fc.ips {
                    map.entry(ip.clone()).or_insert_with(|| label.clone());
                }
                if fc.stix {
                    have_domain_authority = true;
                    for (d, label) in &fc.domains {
                        domain_map.entry(d.clone()).or_insert_with(|| label.clone());
                    }
                }
            }
        }
        if map.is_empty() {
            tracing::warn!("IOC refresh produced 0 IP entries — keeping the previous IP set");
        } else {
            let total = map.len();
            enricher.set_iocs(map);
            tracing::info!(total, "IP IOC set refreshed from feeds");
        }
        // Replace the domain set iff a STIX feed is in play — even with an empty
        // map, so a retracted indicator is actually cleared (and can't linger and
        // keep flagging its subdomains). A round with no STIX feed leaves the
        // previous domains untouched.
        if have_domain_authority {
            let total = domain_map.len();
            enricher.set_domains(domain_map);
            tracing::info!(total, "domain IOC set refreshed from feeds");
        }
        tokio::time::sleep(interval).await;
    }
}

/// Cheap sniff: does this body look like a STIX 2.1 bundle? A bundle is a JSON
/// object whose first meaningful characters open an object and which mentions an
/// `"objects"` array. Avoids a full parse of every plain-text feed each round.
fn looks_like_stix(body: &str) -> bool {
    let head = body.trim_start();
    head.starts_with('{') && head.contains("\"objects\"")
}

/// GET `url` into a String, aborting once the streamed body exceeds `max` bytes
/// (bounds memory even for chunked / no-Content-Length responses).
async fn fetch_capped(client: &reqwest::Client, url: &str, max: usize) -> Result<String> {
    // reqwest attaches the full URL (with any `?token=…`) to its errors' Display;
    // strip it here so a fetch failure can never leak the feed secret into the
    // logs — which garmr itself ingests. The label alone identifies the feed.
    let strip = |e: reqwest::Error| anyhow::anyhow!("{}", e.without_url());
    let mut resp = client
        .get(url)
        .send()
        .await
        .map_err(strip)?
        .error_for_status()
        .map_err(strip)?;
    let mut buf: Vec<u8> = Vec::new();
    while let Some(chunk) = resp.chunk().await.map_err(strip)? {
        if buf.len() + chunk.len() > max {
            anyhow::bail!("feed body exceeds {max} bytes");
        }
        buf.extend_from_slice(&chunk);
    }
    Ok(String::from_utf8_lossy(&buf).into_owned())
}