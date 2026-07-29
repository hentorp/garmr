// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! `garmr-enrich` — on-demand IP intel for the agent's `ip_reputation` tool.
//!
//! Fills the M1 stub with real context: is the address private (RFC1918 /
//! loopback), where does it geolocate (offline MaxMind / DB-IP `mmdb` — no key,
//! no network), and does it appear on a known-bad IOC list. Everything is
//! local: GeoIP is a memory-mapped file, IOC feeds are parsed from local files
//! at startup. Online feed refresh and landing intel in a lakehouse dimension
//! table (for correlation JOINs) are follow-ups; this is the per-IP lookup the
//! triage loop needs.
//!
//! Loading is best-effort and degrades gracefully: a missing mmdb or feed file
//! is logged, and lookups simply return less — never an error.

use std::collections::HashMap;
use std::net::IpAddr;
use std::path::Path;
use std::sync::RwLock;

use maxminddb::Reader;

/// What we know about an IP.
pub mod ipv4_index;
pub use ipv4_index::Ipv4IocIndex;

#[derive(Debug, Clone, Default)]
pub struct Enrichment {
    /// RFC1918 / loopback / link-local — i.e. not a public address.
    pub private: bool,
    /// ISO country code from GeoIP, if a country db is loaded and matches.
    pub country: String,
    /// `AS<n> <org>` from GeoIP, if an ASN db is loaded and matches.
    pub asn: String,
    /// The IOC feed label the IP was found on, if any (empty = not on a list).
    pub ioc_source: String,
}

impl Enrichment {
    /// True if the IP is on at least one IOC feed.
    pub fn is_ioc(&self) -> bool {
        !self.ioc_source.is_empty()
    }
}

/// Holds the loaded GeoIP databases and IOC set; cheap to share (`Arc`).
pub struct Enricher {
    country_db: Option<Reader<Vec<u8>>>,
    asn_db: Option<Reader<Vec<u8>>>,
    /// ip -> feed label. Behind an `RwLock` so a background task can hot-swap
    /// the set (online feed refresh) without rebuilding the Enricher the agent's
    /// ToolBox already holds. Reads (lookups) are frequent + brief; writes
    /// (refresh) are rare, so contention is negligible.
    iocs: RwLock<HashMap<String, String>>,
    /// domain -> feed label (from STIX/structured feeds). Same hot-swap rationale.
    domains: RwLock<HashMap<String, String>>,
    /// IPv4 IOC/CIDR batch index (RangeStree32), rebuilt in lock-step with
    /// `iocs` — for firehose-scale per-event tagging incl. CIDR ranges the string
    /// map can't express. IPv6/unparseable IOCs remain covered by `iocs`.
    ipv4_iocs: RwLock<Ipv4IocIndex>,
}

impl Enricher {
    /// Load GeoIP `country.mmdb` / `asn.mmdb` from `geoip_dir` (if set) and
    /// parse IOC feeds from the given local file paths. Never fails.
    pub fn load(geoip_dir: Option<&Path>, ioc_files: &[String]) -> Self {
        let (country_db, asn_db) = match geoip_dir {
            Some(dir) => (
                open_mmdb(&dir.join("country.mmdb")),
                open_mmdb(&dir.join("asn.mmdb")),
            ),
            None => (None, None),
        };
        let iocs = load_ioc_files(ioc_files);
        let ipv4_iocs = Ipv4IocIndex::from_ioc_map(&iocs);
        tracing::info!(
            geoip = country_db.is_some() || asn_db.is_some(),
            iocs = iocs.len(),
            ipv4_ranges = ipv4_iocs.len(),
            "enricher loaded"
        );
        Self {
            country_db,
            asn_db,
            iocs: RwLock::new(iocs),
            domains: RwLock::new(HashMap::new()),
            ipv4_iocs: RwLock::new(ipv4_iocs),
        }
    }

    /// An empty enricher (no GeoIP, no IOCs) — still classifies private/public.
    pub fn empty() -> Self {
        Self {
            country_db: None,
            asn_db: None,
            iocs: RwLock::new(HashMap::new()),
            domains: RwLock::new(HashMap::new()),
            ipv4_iocs: RwLock::new(Ipv4IocIndex::default()),
        }
    }

    /// Replace the IP-IOC set (online feed refresh). Lock-poisoning-tolerant: a
    /// panicked prior holder can't wedge the enricher.
    pub fn set_iocs(&self, iocs: HashMap<String, String>) {
        // Rebuild the IPv4 batch index in lock-step so the firehose path never
        // sees a stale/mismatched set (build before we move `iocs` into the map).
        let ipv4 = Ipv4IocIndex::from_ioc_map(&iocs);
        *self.ipv4_iocs.write().unwrap_or_else(|e| e.into_inner()) = ipv4;
        *self.iocs.write().unwrap_or_else(|e| e.into_inner()) = iocs;
    }

    /// Batch-tag a slice of IPv4 addresses (as `u32`) against the IPv4 IOC/CIDR
    /// index — the firehose path (Ragnar batch floor, ~2M+ IPs/s). Returns the
    /// feed label per hit, `None` per miss, in input order. For IPv6 or a single
    /// string lookup use [`lookup`](Self::lookup).
    pub fn tag_ipv4_batch(&self, ips: &[u32]) -> Vec<Option<String>> {
        let g = self.ipv4_iocs.read().unwrap_or_else(|e| e.into_inner());
        g.tag_batch(ips).into_iter().map(|o| o.map(str::to_string)).collect()
    }

    /// Replace the domain-IOC set (structured / STIX feeds).
    pub fn set_domains(&self, domains: HashMap<String, String>) {
        *self.domains.write().unwrap_or_else(|e| e.into_inner()) = domains;
    }

    /// Current IP-IOC count.
    pub fn ioc_count(&self) -> usize {
        self.iocs.read().unwrap_or_else(|e| e.into_inner()).len()
    }

    /// Current domain-IOC count.
    pub fn domain_count(&self) -> usize {
        self.domains.read().unwrap_or_else(|e| e.into_inner()).len()
    }

    /// Is `domain` (case-insensitive) on a loaded domain-IOC feed? Returns the
    /// feed label. Matches the exact domain and any parent (so `a.evil.com`
    /// hits a `evil.com` indicator).
    pub fn domain_ioc(&self, domain: &str) -> Option<String> {
        let d = domain.trim().trim_end_matches('.').to_ascii_lowercase();
        if d.is_empty() {
            return None;
        }
        let map = self.domains.read().unwrap_or_else(|e| e.into_inner());
        // exact, then walk parent domains (a.b.evil.com -> b.evil.com -> evil.com)
        let mut cur = d.as_str();
        loop {
            if let Some(src) = map.get(cur) {
                return Some(src.clone());
            }
            match cur.split_once('.') {
                Some((_, parent)) if parent.contains('.') => cur = parent,
                _ => return None,
            }
        }
    }

    /// Look up everything known about an IP.
    pub fn lookup(&self, ip: &str) -> Enrichment {
        let mut e = Enrichment {
            private: is_private(ip),
            ..Default::default()
        };
        if let Some(src) = self.iocs.read().unwrap_or_else(|e| e.into_inner()).get(ip) {
            e.ioc_source = src.clone();
        }
        if let Ok(addr) = ip.parse::<IpAddr>() {
            e.country = self
                .country_db
                .as_ref()
                .and_then(|db| db.lookup::<maxminddb::geoip2::Country>(addr).ok())
                .and_then(|c| c.country)
                .and_then(|c| c.iso_code)
                .map(str::to_string)
                .unwrap_or_default();
            e.asn = self
                .asn_db
                .as_ref()
                .and_then(|db| db.lookup::<maxminddb::geoip2::Asn>(addr).ok())
                .map(|a| {
                    let num = a
                        .autonomous_system_number
                        .map(|n| format!("AS{n}"))
                        .unwrap_or_default();
                    let org = a.autonomous_system_organization.unwrap_or_default();
                    if org.is_empty() {
                        num
                    } else {
                        format!("{num} {org}")
                    }
                })
                .unwrap_or_default();
        }
        e
    }
}

fn open_mmdb(path: &Path) -> Option<Reader<Vec<u8>>> {
    match Reader::open_readfile(path) {
        Ok(r) => Some(r),
        Err(e) => {
            tracing::debug!(path = %path.display(), error = %e, "geoip mmdb not loaded");
            None
        }
    }
}

/// Parse "one IP per line" IOC feeds (abuse.ch / blocklist.de shape) from local
/// files. Handles IPv4 and IPv6, tolerates comments and a trailing `:port` on
/// IPv4, and is bounded so a pathological path (`/dev/zero`, a FIFO, a
/// multi-GB file) can't hang or OOM startup.
pub fn load_ioc_files(files: &[String]) -> HashMap<String, String> {
    const MAX_FEED_BYTES: u64 = 128 * 1024 * 1024;
    let mut map = HashMap::new();
    for path in files {
        let label = feed_label(path);
        let body = match read_capped(path, MAX_FEED_BYTES) {
            Ok(t) => t,
            Err(e) => {
                tracing::warn!(file = %path, error = %e, "IOC feed not read");
                continue;
            }
        };
        let mut n = 0usize;
        for (ip, _) in parse_feed_text(&body, &label) {
            map.entry(ip).or_insert_with(|| label.clone());
            n += 1;
        }
        tracing::info!(feed = %label, ips = n, "IOC feed loaded");
    }
    map
}

/// Parse a STIX 2.1 bundle (what a TAXII 2.1 collection returns) into
/// `(ip_indicators, domain_indicators)` as `(value, label)` pairs. Reads every
/// `type: "indicator"` object's `pattern` and extracts the `ipv4-addr:value`,
/// `ipv6-addr:value`, and `domain-name:value` comparisons — enough for the
/// common single-observable indicator patterns without a full STIX-pattern
/// grammar. IPs are validated; domains are lowercased. Bounded object count.
#[allow(clippy::type_complexity)] // (ip, domain) indicator lists — a named struct would not read clearer
pub fn parse_stix_bundle(
    json: &str,
    label: &str,
) -> (Vec<(String, String)>, Vec<(String, String)>) {
    const MAX_OBJECTS: usize = 2_000_000;
    let mut ips = Vec::new();
    let mut domains = Vec::new();
    let Ok(v) = serde_json::from_str::<serde_json::Value>(json) else {
        return (ips, domains);
    };
    let objects = v.get("objects").and_then(|o| o.as_array());
    for obj in objects.into_iter().flatten().take(MAX_OBJECTS) {
        if obj.get("type").and_then(|t| t.as_str()) != Some("indicator") {
            continue;
        }
        let Some(pattern) = obj.get("pattern").and_then(|p| p.as_str()) else {
            continue;
        };
        let name = obj.get("name").and_then(|n| n.as_str()).unwrap_or(label);
        for key in ["ipv4-addr:value", "ipv6-addr:value"] {
            for val in stix_pattern_values(pattern, key) {
                if val.parse::<IpAddr>().is_ok() {
                    ips.push((val, name.to_string()));
                }
            }
        }
        for val in stix_pattern_values(pattern, "domain-name:value") {
            let d = val.trim().trim_end_matches('.').to_ascii_lowercase();
            if d.contains('.') && !d.contains(char::is_whitespace) {
                domains.push((d, name.to_string()));
            }
        }
    }
    (ips, domains)
}

/// Extract the quoted values of every `<key> = '…'` comparison in a STIX
/// pattern string (e.g. `[ipv4-addr:value = '1.2.3.4' OR ipv4-addr:value = '5.6.7.8']`).
fn stix_pattern_values(pattern: &str, key: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = pattern;
    while let Some(i) = rest.find(key) {
        rest = &rest[i + key.len()..];
        // The value is the next single-quoted token after the key.
        let Some(q) = rest.find('\'') else { break };
        let after = &rest[q + 1..];
        let Some(end) = after.find('\'') else { break };
        let val = &after[..end];
        if !val.is_empty() {
            out.push(val.to_string());
        }
        rest = &after[end + 1..];
    }
    out
}

/// Parse an "one IP per line" IOC feed body (abuse.ch / blocklist.de shape) into
/// `(ip, label)` pairs: skips blank/`#`/`;` comment lines, takes the first
/// whitespace/comma token, keeps IPv4/IPv6 (dropping a trailing `:port` on v4).
/// Bounded to `MAX_FEED_LINES` so a pathological online feed can't OOM. Shared
/// by the file loader and the online-refresh fetcher.
pub fn parse_feed_text(body: &str, _label: &str) -> Vec<(String, String)> {
    const MAX_FEED_LINES: usize = 5_000_000;
    let mut out = Vec::new();
    for line in body.lines().take(MAX_FEED_LINES) {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        let token = line.split([' ', '\t', ',']).next().unwrap_or("");
        if let Some(ip) = parse_ioc_token(token) {
            out.push((ip, _label.to_string()));
        }
    }
    out
}

/// Read a file into a string, capped at `max` bytes (protects against
/// unbounded/pathological feed paths). Truncation past the cap is silent — a
/// real IOC list is a few MB.
fn read_capped(path: &str, max: u64) -> std::io::Result<String> {
    use std::io::Read;
    let file = std::fs::File::open(path)?;
    let mut s = String::new();
    file.take(max).read_to_string(&mut s)?;
    Ok(s)
}

/// Parse one IOC token to a canonical IP string: a bare IPv4/IPv6, or an
/// `IPv4:port` (the port is dropped). Returns `None` for anything else.
fn parse_ioc_token(token: &str) -> Option<String> {
    if let Ok(addr) = token.parse::<IpAddr>() {
        return Some(addr.to_string());
    }
    // IPv4:port — drop the port. (Bracketed [v6]:port is rare in these feeds.)
    token
        .rsplit_once(':')
        .and_then(|(host, _)| host.parse::<std::net::Ipv4Addr>().ok())
        .map(|v4| v4.to_string())
}

/// A short label for a feed, from its file stem.
fn feed_label(path: &str) -> String {
    Path::new(path)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("ioc")
        .to_string()
}

/// Not-public: RFC1918 / loopback / link-local for IPv4, and loopback /
/// unspecified / link-local (fe80::/10) / unique-local (fc00::/7) / IPv4-mapped
/// for IPv6. An unparseable string is treated as public (`false`) — better to
/// under-claim "private" than to hide a garbage value from triage as trusted.
pub fn is_private(ip: &str) -> bool {
    match ip.parse::<IpAddr>() {
        Ok(IpAddr::V4(v4)) => {
            v4.is_private() || v4.is_loopback() || v4.is_link_local() || v4.is_unspecified()
        }
        Ok(IpAddr::V6(v6)) => {
            if v6.is_loopback() || v6.is_unspecified() {
                return true;
            }
            if let Some(v4) = v6.to_ipv4_mapped() {
                return v4.is_private() || v4.is_loopback() || v4.is_link_local();
            }
            let seg0 = v6.segments()[0];
            (seg0 & 0xffc0) == 0xfe80 || (seg0 & 0xfe00) == 0xfc00 // fe80::/10 | fc00::/7
        }
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_feed_text_extracts_ips_and_skips_noise() {
        let body = "# comment\n\n203.0.113.7\n198.51.100.9:22\n; semicolon comment\nnot-an-ip\n2001:db8::1\n8.8.8.8 extra tokens\n";
        let got = parse_feed_text(body, "test");
        let ips: Vec<&str> = got.iter().map(|(ip, _)| ip.as_str()).collect();
        assert_eq!(
            ips,
            vec!["203.0.113.7", "198.51.100.9", "2001:db8::1", "8.8.8.8"]
        );
        assert!(got.iter().all(|(_, l)| l == "test"));
    }

    #[test]
    fn set_iocs_hot_swaps_the_lookup_set() {
        let e = Enricher::empty();
        assert_eq!(e.ioc_count(), 0);
        assert!(!e.lookup("203.0.113.7").is_ioc());
        let mut m = HashMap::new();
        m.insert("203.0.113.7".to_string(), "feodo".to_string());
        e.set_iocs(m);
        assert_eq!(e.ioc_count(), 1);
        let hit = e.lookup("203.0.113.7");
        assert!(hit.is_ioc());
        assert_eq!(hit.ioc_source, "feodo");
        // a fresh swap replaces (not merges) the set
        e.set_iocs(HashMap::new());
        assert!(!e.lookup("203.0.113.7").is_ioc());
    }

    #[test]
    fn classifies_private_vs_public() {
        assert!(is_private("10.0.0.5"));
        assert!(is_private("192.168.1.1"));
        assert!(is_private("172.16.5.4")); // 172.16/12
        assert!(is_private("127.0.0.1"));
        assert!(!is_private("203.0.113.7"));
        assert!(!is_private("8.8.8.8"));
        assert!(!is_private("172.32.0.1")); // just outside 172.16/12
    }

    #[test]
    fn classifies_ipv6() {
        assert!(is_private("::1")); // loopback
        assert!(is_private("fe80::1")); // link-local
        assert!(is_private("fd12:3456::5")); // unique-local
        assert!(is_private("::ffff:10.0.0.1")); // IPv4-mapped private
        assert!(!is_private("2001:db8::1")); // documentation/global
        assert!(!is_private("not-an-ip")); // garbage → public, not private
    }

    #[test]
    fn ioc_membership_from_file() {
        let dir = std::env::temp_dir();
        let path = dir.join("garmr-test-ioc.txt");
        std::fs::write(&path, "# bad ips\n203.0.113.7\n45.9.148.99 comment\n").unwrap();
        let e = Enricher::load(None, &[path.to_string_lossy().to_string()]);
        assert_eq!(e.lookup("203.0.113.7").ioc_source, "garmr-test-ioc");
        assert!(e.lookup("203.0.113.7").is_ioc());
        assert!(!e.lookup("8.8.8.8").is_ioc());
        // Public IOC IP is not private.
        assert!(!e.lookup("203.0.113.7").private);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn ioc_parses_ipv6_and_v4_port() {
        let dir = std::env::temp_dir();
        let path = dir.join("garmr-test-ioc6.txt");
        std::fs::write(&path, "2001:db8:dead::1\n203.0.113.8:4444\n").unwrap();
        let e = Enricher::load(None, &[path.to_string_lossy().to_string()]);
        assert!(e.lookup("2001:db8:dead::1").is_ioc()); // IPv6 IOC no longer dropped
        assert!(e.lookup("203.0.113.8").is_ioc()); // IPv4:port → port stripped
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn parse_stix_bundle_extracts_ips_and_domains() {
        // A minimal STIX 2.1 bundle with three indicators: an IPv4, an IPv6,
        // a domain, plus a non-indicator object that must be ignored.
        let bundle = r#"{
          "type": "bundle",
          "id": "bundle--1",
          "objects": [
            {"type":"identity","name":"Acme"},
            {"type":"indicator","name":"c2-ipv4","pattern":"[ipv4-addr:value = '203.0.113.55']","pattern_type":"stix"},
            {"type":"indicator","name":"c2-ipv6","pattern":"[ipv6-addr:value = '2001:db8:beef::9']","pattern_type":"stix"},
            {"type":"indicator","name":"phish","pattern":"[domain-name:value = 'Evil.Example.COM']","pattern_type":"stix"},
            {"type":"indicator","name":"junk","pattern":"[file:hashes.'SHA-256' = 'abc']","pattern_type":"stix"}
          ]
        }"#;
        let (ips, domains) = parse_stix_bundle(bundle, "test-taxii");
        assert!(ips
            .iter()
            .any(|(v, l)| v == "203.0.113.55" && l == "c2-ipv4"));
        assert!(ips.iter().any(|(v, _)| v == "2001:db8:beef::9"));
        assert_eq!(ips.len(), 2, "only valid IPs, hash ignored");
        assert_eq!(
            domains,
            vec![("evil.example.com".to_string(), "phish".to_string())]
        );
    }

    #[test]
    fn parse_stix_bundle_handles_multi_value_or_pattern() {
        let bundle = r#"{"objects":[
          {"type":"indicator","name":"multi","pattern":"[ipv4-addr:value = '198.51.100.1' OR ipv4-addr:value = '198.51.100.2']"}
        ]}"#;
        let (ips, _) = parse_stix_bundle(bundle, "l");
        assert_eq!(ips.len(), 2);
        assert!(ips.iter().any(|(v, _)| v == "198.51.100.1"));
        assert!(ips.iter().any(|(v, _)| v == "198.51.100.2"));
    }

    #[test]
    fn domain_ioc_matches_exact_and_parent() {
        let e = Enricher::empty();
        let mut m = HashMap::new();
        m.insert("evil.example.com".to_string(), "feedX".to_string());
        e.set_domains(m);
        assert_eq!(e.domain_ioc("evil.example.com").as_deref(), Some("feedX"));
        assert_eq!(e.domain_ioc("Evil.Example.Com").as_deref(), Some("feedX")); // case-insensitive
        assert_eq!(
            e.domain_ioc("a.b.evil.example.com").as_deref(),
            Some("feedX")
        ); // subdomain
        assert_eq!(e.domain_ioc("example.com"), None); // parent of the IOC, not a match
        assert_eq!(e.domain_ioc("notevil.com"), None);
        assert_eq!(e.domain_count(), 1);
    }
}