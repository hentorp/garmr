// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! Batch IOC tagging for an ingested event batch.
//!
//! A whole batch of [`Event`]s has its `src_ip`s checked against the loaded IOC
//! feeds in ONE consolidated pass — never a lookup per event. An event whose
//! source IP is on a feed gets an [`IOC_FEED_FIELD`] field stamped with the feed
//! label; an event with no `src_ip`, a non-IPv4 `src_ip`, or a clean IP is left
//! untouched.
//!
//! The step is opt-in and cheap: it only runs when an [`Enricher`] carrying IOC
//! feeds is supplied, and it returns immediately when no IP-IOC feed is loaded,
//! so the default ingest path (no feeds) is byte-identical to before.

use std::collections::HashMap;
use std::net::Ipv4Addr;

use garmr_core::Event;
use garmr_enrich::Enricher;

/// The field stamped onto an event whose `src_ip` is on an IOC feed. Its value
/// is the feed label (e.g. `feodo`, `blocklist-de`).
pub const IOC_FEED_FIELD: &str = "ioc_feed";

/// Tag `events` in place only when an enricher is present — the opt-in wrapper
/// for a call site that carries `Option<&Enricher>` (feeds may be unconfigured).
pub fn tag_ioc_batch_opt(events: &mut [Event], enricher: Option<&Enricher>) {
    if let Some(e) = enricher {
        tag_ioc_batch(events, e);
    }
}

/// Check every event's IPv4 `src_ip` against the enricher's IOC feeds in one
/// batch pass and stamp [`IOC_FEED_FIELD`] on the hits.
///
/// Batch, not per-event: the DISTINCT source IPs in the batch are extracted to
/// `u32` once and resolved in a single [`resolve_ipv4_batch`] call, whose result
/// is fanned back onto the events. A firehose of repeated IPs therefore costs
/// one resolution per distinct address, not one per row. A batch with no IP-IOC
/// feed loaded, or with no parseable IPv4 `src_ip`, returns early and touches
/// nothing.
pub fn tag_ioc_batch(events: &mut [Event], enricher: &Enricher) {
    // Off the critical path entirely when no IP-IOC feed is loaded.
    if enricher.ioc_count() == 0 {
        return;
    }

    // 1) Extract the distinct parseable IPv4 `src_ip`s of the batch to `u32`,
    //    keeping each address's slot index so the result can be fanned back on.
    let mut slot_of: HashMap<u32, usize> = HashMap::new();
    let mut ips: Vec<u32> = Vec::new();
    for ev in events.iter() {
        if let Some(ip) = ev.src_ip().and_then(parse_ipv4_u32) {
            slot_of.entry(ip).or_insert_with(|| {
                let i = ips.len();
                ips.push(ip);
                i
            });
        }
    }
    if ips.is_empty() {
        return;
    }

    // 2) ONE batch resolution for the whole event batch.
    let labels = resolve_ipv4_batch(enricher, &ips);

    // 3) Stamp hits back onto every event carrying a flagged address.
    for ev in events.iter_mut() {
        let Some(ip) = ev.src_ip().and_then(parse_ipv4_u32) else {
            continue;
        };
        if let Some(&slot) = slot_of.get(&ip) {
            if let Some(label) = &labels[slot] {
                ev.fields.insert(IOC_FEED_FIELD.to_string(), label.clone());
            }
        }
    }
}

/// Resolve a batch of IPv4 addresses (as `u32`) to their IOC feed label — one
/// `Option<String>` per input, in order (`None` = not on any feed).
///
/// Delegates to the firehose-scale `Enricher::tag_ipv4_batch(&[u32])` — the
/// Ragnar `RangeStree32` pipelined range index (batch floor, ~22M IPs/s), which
/// resolves the whole batch of distinct addresses in one pass and covers CIDR
/// ranges the string map cannot.
fn resolve_ipv4_batch(enricher: &Enricher, ips: &[u32]) -> Vec<Option<String>> {
    enricher.tag_ipv4_batch(ips)
}

/// Parse a `src_ip` string to a `u32` IPv4 address, or `None` when it is absent,
/// an IPv6 address, or garbage — those are left untouched for other tooling.
fn parse_ipv4_u32(ip: &str) -> Option<u32> {
    ip.parse::<Ipv4Addr>().ok().map(u32::from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use std::collections::BTreeMap;

    /// Build a minimal event carrying just an optional `src_ip`.
    fn ev(src_ip: Option<&str>) -> Event {
        let mut fields = BTreeMap::new();
        if let Some(ip) = src_ip {
            fields.insert("src_ip".to_string(), ip.to_string());
        }
        Event {
            ts: Utc::now(),
            host: "h".into(),
            service: "sshd".into(),
            source: "syslog".into(),
            environment: "prod".into(),
            severity: "info".into(),
            log_type: "security_alert".into(),
            message: "m".to_string(),
            fields,
        }
    }

    /// A small enricher built from a HashMap of known-bad IPs.
    fn enricher_with(bad: &[(&str, &str)]) -> Enricher {
        let e = Enricher::empty();
        let mut m = HashMap::new();
        for (ip, label) in bad {
            m.insert((*ip).to_string(), (*label).to_string());
        }
        e.set_iocs(m);
        e
    }

    #[test]
    fn stamps_ioc_feed_on_known_bad_ip_only() {
        let enricher = enricher_with(&[("203.0.113.7", "feodo")]);
        let mut events = vec![
            ev(Some("203.0.113.7")), // known-bad -> stamped
            ev(Some("8.8.8.8")),     // clean -> untouched
            ev(None),                // no src_ip -> untouched
        ];
        tag_ioc_batch(&mut events, &enricher);

        assert_eq!(events[0].field(IOC_FEED_FIELD), Some("feodo"));
        assert_eq!(events[1].field(IOC_FEED_FIELD), None);
        assert_eq!(events[2].field(IOC_FEED_FIELD), None);
    }

    #[test]
    fn non_ipv4_and_empty_enricher_are_left_untouched() {
        // An IPv6 src_ip is not extracted, even if the enricher lists it.
        let enricher = enricher_with(&[("2001:db8::1", "v6feed")]);
        let mut events = vec![ev(Some("2001:db8::1")), ev(Some("not-an-ip"))];
        tag_ioc_batch(&mut events, &enricher);
        assert_eq!(events[0].field(IOC_FEED_FIELD), None);
        assert_eq!(events[1].field(IOC_FEED_FIELD), None);

        // An enricher with no feeds loaded is a no-op regardless of src_ip.
        let empty = Enricher::empty();
        let mut clean = vec![ev(Some("203.0.113.7"))];
        tag_ioc_batch(&mut clean, &empty);
        assert_eq!(clean[0].field(IOC_FEED_FIELD), None);
    }

    #[test]
    fn repeated_bad_ip_is_stamped_on_every_row() {
        // Dedup must not drop stamps: two events share one flagged address.
        let enricher = enricher_with(&[("45.9.148.99", "blocklist-de")]);
        let mut events = vec![ev(Some("45.9.148.99")), ev(Some("45.9.148.99"))];
        tag_ioc_batch(&mut events, &enricher);
        assert_eq!(events[0].field(IOC_FEED_FIELD), Some("blocklist-de"));
        assert_eq!(events[1].field(IOC_FEED_FIELD), Some("blocklist-de"));
    }

    #[test]
    fn opt_wrapper_no_enricher_is_a_noop() {
        let mut events = vec![ev(Some("203.0.113.7"))];
        tag_ioc_batch_opt(&mut events, None);
        assert_eq!(events[0].field(IOC_FEED_FIELD), None);
    }
}