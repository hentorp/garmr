// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! IPv4 IOC / CIDR **batch** membership — the firehose-scale enrichment path.
//!
//! Backed by the 3rd Ragnar variant ([`znippy_zoomies::stree32_range::RangeStree32`]):
//! build the index once from a feed snapshot, tag a whole event-batch of `src_ip`
//! values in one software-pipelined pass (Ragnar's ~2M+ lookups/s regime), and
//! hot-swap it on feed refresh. It covers individual IPs **and CIDR blocks** — a
//! `HashMap<String,_>` cannot do CIDR range membership at all, which is why
//! per-event IOC tagging on the firehose was previously infeasible. IPv6 and
//! unparseable entries stay in the existing string map.

use std::collections::HashMap;
use std::net::Ipv4Addr;

use znippy_zoomies::gatling_forkjoin;
use znippy_zoomies::stree32_range::{ipv4_cidr_range, RangeStree32};

/// Pipeline depth for the batch floor descent (Ragnar's prefetch overlap).
const BATCH_P: usize = 32;

/// At/above this many probes, [`Ipv4IocIndex::tag_batch`] chunks the slice across
/// cores (each core runs its OWN pipelined `lookup_batch`); below it a single
/// pass is cheaper than fanning scoped-thread workers. Chosen so every chunk is
/// wide enough to keep the `BATCH_P` prefetch pipeline full even at 32 cores.
const PARALLEL_TAG_THRESHOLD: usize = 8_192;

/// Immutable IPv4 IOC index over merged, non-overlapping `u32` ranges → a
/// feed-label id. Rebuild + swap on feed refresh (mirrors the string map).
#[derive(Default)]
pub struct Ipv4IocIndex {
    index: Option<RangeStree32<u32>>,
    labels: Vec<String>,
}

impl Ipv4IocIndex {
    /// Build from the string IOC map (`ip-or-cidr -> feed label`). IPv4 and CIDR
    /// entries become `u32` ranges; IPv6 / unparseable entries are skipped (they
    /// remain covered by the caller's string map). Overlapping/adjacent ranges
    /// are merged (keeping the first label) so the tree's non-overlap invariant
    /// holds even for messy real feeds.
    pub fn from_ioc_map(iocs: &HashMap<String, String>) -> Self {
        let mut label_ids: HashMap<&str, u32> = HashMap::new();
        let mut labels: Vec<String> = Vec::new();
        let mut ranges: Vec<(u32, u32, u32)> = Vec::new();
        for (entry, label) in iocs {
            if let Some((s, e)) = parse_ipv4_entry(entry) {
                let id = *label_ids.entry(label.as_str()).or_insert_with(|| {
                    labels.push(label.clone());
                    (labels.len() - 1) as u32
                });
                ranges.push((s, e, id));
            }
        }
        if ranges.is_empty() {
            return Self {
                index: None,
                labels,
            };
        }
        ranges.sort_by_key(|r| r.0);
        // Merge overlaps/adjacency; keep the first label of an overlapping run.
        let mut merged: Vec<(u32, u32, u32)> = Vec::with_capacity(ranges.len());
        for (s, e, id) in ranges {
            if let Some(last) = merged.last_mut() {
                if s <= last.1.saturating_add(1) {
                    last.1 = last.1.max(e);
                    continue;
                }
            }
            merged.push((s, e, id));
        }
        Self {
            index: Some(RangeStree32::new(merged)),
            labels,
        }
    }

    /// The feed label for a single IPv4 `ip` (as `u32`), or `None`.
    pub fn tag(&self, ip: u32) -> Option<&str> {
        self.index
            .as_ref()?
            .lookup(ip)
            .map(|&id| self.labels[id as usize].as_str())
    }

    /// **Batch tag** — resolve a whole slice of IPv4 `u32`s. The firehose path:
    /// one call per ingest batch.
    ///
    /// Ragnar's floor descent is latency-bound pointer-chasing; `lookup_batch`
    /// hides that latency with a `BATCH_P`-deep software prefetch pipeline — but
    /// on ONE core. A firehose ingest batch of `src_ip`s is far wider than one
    /// core can saturate, so at/above [`PARALLEL_TAG_THRESHOLD`] the slice is
    /// split into contiguous chunks and each core runs its own pipelined
    /// `lookup_batch` over a disjoint chunk. The tree is read-only and shared
    /// (`Send`+`Sync`, no clone); the chunks are independent; gatling returns
    /// them in index order, so the tagged output is byte-for-byte the serial
    /// result (ROOT LAW #0 — no rayon). Below the threshold one pass avoids the
    /// scoped-thread spawn.
    pub fn tag_batch(&self, ips: &[u32]) -> Vec<Option<&str>> {
        let idx = match &self.index {
            None => return vec![None; ips.len()],
            Some(idx) => idx,
        };
        let n = ips.len();
        if n < PARALLEL_TAG_THRESHOLD {
            return idx
                .lookup_batch::<BATCH_P>(ips)
                .into_iter()
                .map(|o| o.map(|&id| self.labels[id as usize].as_str()))
                .collect();
        }
        // One chunk per core, each at least `4 * BATCH_P` wide so the prefetch
        // pipeline stays full; fewer, fatter chunks beat many thin ones (per-chunk
        // pipeline warm-up is amortized). `gatling_for_each` hands back the chunk
        // results in index order — concatenation reproduces the serial ordering.
        let workers = std::thread::available_parallelism()
            .map(|x| x.get())
            .unwrap_or(1)
            .max(1);
        let chunk = n.div_ceil(workers).max(4 * BATCH_P);
        let n_chunks = n.div_ceil(chunk);
        let parts: Vec<Vec<Option<u32>>> = gatling_forkjoin::gatling_for_each(n_chunks, 0, |c| {
            let lo = c * chunk;
            let hi = (lo + chunk).min(n);
            idx.lookup_batch::<BATCH_P>(&ips[lo..hi])
                .into_iter()
                .map(|o| o.copied())
                .collect()
        });
        let mut out = Vec::with_capacity(n);
        for part in parts {
            out.extend(
                part.into_iter()
                    .map(|o| o.map(|id| self.labels[id as usize].as_str())),
            );
        }
        out
    }

    /// Number of merged ranges indexed (0 if empty).
    pub fn len(&self) -> usize {
        self.index.as_ref().map(|i| i.len()).unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Parse an IOC feed entry as an IPv4 point (`1.2.3.4`) or CIDR (`1.2.3.0/24`)
/// range. `None` for IPv6 / unparseable entries.
fn parse_ipv4_entry(s: &str) -> Option<(u32, u32)> {
    let s = s.trim();
    if let Some((base, plen)) = s.split_once('/') {
        let addr: Ipv4Addr = base.trim().parse().ok()?;
        let p: u8 = plen.trim().parse().ok()?;
        Some(ipv4_cidr_range(addr, p))
    } else {
        let addr: Ipv4Addr = s.parse().ok()?;
        let v = u32::from(addr);
        Some((v, v))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(a: u8, b: u8, c: u8, d: u8) -> u32 {
        u32::from(Ipv4Addr::new(a, b, c, d))
    }

    #[test]
    fn tags_ips_and_cidrs_skips_ipv6() {
        let mut m = HashMap::new();
        m.insert("203.0.113.7".to_string(), "abuse".to_string());
        m.insert("10.0.0.0/24".to_string(), "internal".to_string());
        m.insert("2001:db8::1".to_string(), "v6feed".to_string()); // skipped
        let idx = Ipv4IocIndex::from_ioc_map(&m);

        assert_eq!(idx.tag(ip(203, 0, 113, 7)), Some("abuse"));
        assert_eq!(idx.tag(ip(10, 0, 0, 200)), Some("internal"));
        assert_eq!(idx.tag(ip(10, 0, 1, 0)), None); // outside the /24
        assert_eq!(idx.tag(ip(8, 8, 8, 8)), None); // not on any feed
        assert!(idx.len() >= 2);
    }

    #[test]
    fn batch_matches_single() {
        let mut m = HashMap::new();
        for i in 0..500u32 {
            m.insert(
                format!("{}.{}.0.0/16", 1 + i / 256, i % 256),
                format!("feed{}", i % 7),
            );
        }
        let idx = Ipv4IocIndex::from_ioc_map(&m);
        let probes: Vec<u32> = (0..2000u32)
            .map(|i| {
                ip(
                    (1 + (i % 200)) as u8,
                    (i % 256) as u8,
                    (i % 7) as u8,
                    (i % 251) as u8,
                )
            })
            .collect();
        let batch: Vec<Option<String>> = idx
            .tag_batch(&probes)
            .into_iter()
            .map(|o| o.map(str::to_string))
            .collect();
        let single: Vec<Option<String>> = probes
            .iter()
            .map(|&p| idx.tag(p).map(str::to_string))
            .collect();
        assert_eq!(batch, single, "batch tag must equal single tag");
    }

    /// The gatling chunk fan-out must produce EXACTLY the serial `lookup_batch`
    /// result, in order. Drives a probe slice safely past
    /// `PARALLEL_TAG_THRESHOLD` so the multi-core path runs, then asserts it
    /// equals the per-IP serial tag. Red the instant the fan-out reorders,
    /// drops, or mis-chunks a row.
    #[test]
    fn parallel_batch_matches_serial_in_order() {
        let mut m = HashMap::new();
        for i in 0..1000u32 {
            m.insert(
                format!("{}.{}.0.0/16", 1 + i / 256, i % 256),
                format!("feed{}", i % 11),
            );
        }
        let idx = Ipv4IocIndex::from_ioc_map(&m);
        let n = PARALLEL_TAG_THRESHOLD * 3 + 137; // safely into the parallel regime
        assert!(
            n >= PARALLEL_TAG_THRESHOLD,
            "must exercise the fan-out path"
        );
        // xorshift probes: a mix of hits and misses, deterministic.
        let mut x = 0x9E37_79B9u32;
        let probes: Vec<u32> = (0..n)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 17;
                x ^= x << 5;
                x
            })
            .collect();
        let batch: Vec<Option<String>> = idx
            .tag_batch(&probes)
            .into_iter()
            .map(|o| o.map(str::to_string))
            .collect();
        let serial: Vec<Option<String>> = probes
            .iter()
            .map(|&p| idx.tag(p).map(str::to_string))
            .collect();
        assert_eq!(batch.len(), n);
        assert_eq!(
            batch, serial,
            "parallel batch tag must equal serial tag, in order"
        );
    }
}
