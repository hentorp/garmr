// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! Phase 12 — authenticated collectors. A per-collector shared-secret bearer
//! binds a native ingest connection to a TRUSTED source identity, so a
//! compromised collector can forge only its OWN bound sources. The Phase-5
//! anti-poisoning gate keys its distinct-source count on the collector id (not
//! the shipper-self-declared `event.source`), closing the poisoning vector that
//! otherwise lets one collector fake N sources.
//!
//! Mirrors [`crate::AuthRegistry`]: constant-time token resolution (via the
//! shared `ct_eq`, so neither a token's bytes nor its length leaks by timing).
//! Default-off: an empty registry means unauthenticated ingest, exactly as today.

use serde::Deserialize;

use crate::auth::ct_eq;

/// One configured collector: a bearer token → a trusted identity + the
/// self-declared `source` values it is permitted to assert.
#[derive(Debug, Clone, Deserialize)]
pub struct Collector {
    pub id: String,
    pub token: String,
    /// The `event.source` values this collector may assert. EMPTY = any (the
    /// collector id is the trust anchor regardless of the self-declared source).
    #[serde(default)]
    pub sources: Vec<String>,
}

impl Collector {
    /// May this collector assert this self-declared `source`?
    pub fn may_assert(&self, source: &str) -> bool {
        self.sources.is_empty() || self.sources.iter().any(|s| s == source)
    }

    /// The TRUSTED source id stamped on this collector's events: the collector id
    /// itself — a compromised collector can only ever speak for its own id, so
    /// the anti-poisoning distinct-source count reflects real collectors.
    pub fn trusted_source_id(&self) -> &str {
        &self.id
    }
}

/// Resolves a presented bearer token to a [`Collector`], constant-time over the
/// whole set (checks every entry so timing never reveals which token matched).
#[derive(Debug, Clone, Default)]
pub struct CollectorRegistry {
    collectors: Vec<Collector>,
}

impl CollectorRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_empty(&self) -> bool {
        self.collectors.is_empty()
    }

    pub fn len(&self) -> usize {
        self.collectors.len()
    }

    /// Merge collectors from a JSON array: `[{"id","token","sources":[..]}, …]`.
    /// Empty/whitespace input is a no-op (default-off). Returns how many added.
    pub fn add_json(&mut self, json: &str) -> Result<usize, String> {
        if json.trim().is_empty() {
            return Ok(0);
        }
        let list: Vec<Collector> =
            serde_json::from_str(json).map_err(|e| format!("GARMR_COLLECTORS parse error: {e}"))?;
        if list.iter().any(|c| c.token.trim().is_empty()) {
            return Err("GARMR_COLLECTORS: token must not be empty".into());
        }
        let n = list.len();
        self.collectors.extend(list);
        Ok(n)
    }

    /// Is `id` a configured collector id? (For operator diagnostics — not an
    /// auth path, so no constant-time requirement.)
    pub fn contains_id(&self, id: &str) -> bool {
        self.collectors.iter().any(|c| c.id == id)
    }

    /// Resolve a token to its collector, or `None`. Constant-time: every entry is
    /// compared even after a match.
    pub fn resolve(&self, presented: &str) -> Option<&Collector> {
        if presented.is_empty() {
            return None;
        }
        let mut found: Option<&Collector> = None;
        for c in &self.collectors {
            if ct_eq(presented.as_bytes(), c.token.as_bytes()) {
                found = Some(c);
            }
        }
        found
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reg() -> CollectorRegistry {
        let mut r = CollectorRegistry::new();
        r.add_json(r#"[{"id":"fw-collector","token":"s3cr3t","sources":["firewall","fw2"]},{"id":"open","token":"tok2"}]"#)
            .unwrap();
        r
    }

    #[test]
    fn empty_registry_is_default_off() {
        assert!(CollectorRegistry::new().is_empty());
        assert_eq!(CollectorRegistry::new().add_json("  ").unwrap(), 0);
    }

    #[test]
    fn resolve_matches_only_the_exact_token() {
        let r = reg();
        assert_eq!(r.resolve("s3cr3t").unwrap().id, "fw-collector");
        assert!(r.resolve("wrong").is_none());
        assert!(r.resolve("").is_none());
    }

    #[test]
    fn source_binding_restricts_assertable_sources() {
        let r = reg();
        let fw = r.resolve("s3cr3t").unwrap();
        assert!(fw.may_assert("firewall"));
        assert!(!fw.may_assert("router")); // not in its allowlist
                                           // The trusted id is the collector id — one collector = one distinct source.
        assert_eq!(fw.trusted_source_id(), "fw-collector");
        // An empty allowlist may assert anything (id remains the trust anchor).
        assert!(r.resolve("tok2").unwrap().may_assert("anything"));
    }

    #[test]
    fn add_json_rejects_empty_token() {
        let mut r = CollectorRegistry::new();
        assert!(r.add_json(r#"[{"id":"c","token":""}]"#).is_err());
        assert!(r.add_json(r#"[{"id":"c","token":"   "}]"#).is_err());
        assert!(r.is_empty());
    }
}