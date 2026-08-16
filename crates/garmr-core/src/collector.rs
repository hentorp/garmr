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

use serde::{Deserialize, Serialize};

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
    /// Minted credentials: digest-only, with expiry and revocation.
    records: Vec<CollectorRecord>,
    /// Key for the record digests. `None` until a registry is loaded from a
    /// file, in which case no minted credential can resolve — which is the safe
    /// direction: without the key a digest cannot be verified, so refusing is
    /// the only honest answer.
    digest_key: Option<[u8; 32]>,
    /// One [`Collector`] per record, built at load time so `resolve` can hand
    /// back a reference with the registry's lifetime. Its `token` is empty and
    /// is never compared — a minted credential is verified against the digest.
    bridged: Vec<Collector>,
}

impl CollectorRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Is the registry devoid of credentials from EITHER source (env plaintext
    /// or minted records)?
    ///
    /// Both halves matter: this answer decides whether collector auth is
    /// considered enabled at startup. Counting only the env list — as an
    /// earlier version did — made a file-only deployment read as "no auth
    /// configured" and start with UNAUTHENTICATED ingest despite its minted
    /// credentials. The invariant test caught it; this is the fix.
    pub fn is_empty(&self) -> bool {
        self.collectors.is_empty() && self.records.is_empty()
    }

    pub fn len(&self) -> usize {
        self.collectors.len() + self.records.len()
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
        self.collectors.iter().any(|c| c.id == id) || self.records.iter().any(|r| r.id == id)
    }

    /// Install minted records and the key their digests were made with.
    pub fn load_records(&mut self, key: [u8; 32], records: Vec<CollectorRecord>) {
        self.digest_key = Some(key);
        self.bridged = records
            .iter()
            .map(|r| Collector {
                id: r.id.clone(),
                // Deliberately empty: a minted credential authenticates by
                // digest, and an empty token can never match a presented secret
                // (`resolve` refuses an empty presented value outright), so this
                // cannot become a backdoor even if the plaintext scan sees it.
                token: String::new(),
                sources: r.sources.clone(),
            })
            .collect();
        self.records = records;
    }

    /// Every known credential and its current usability, for operator listings.
    /// Never includes a secret — [`CollectorRecord`] holds only a digest.
    pub fn records(&self) -> &[CollectorRecord] {
        &self.records
    }

    /// Resolve a token to its collector, or `None`. Constant-time: every entry is
    /// compared even after a match.
    ///
    /// Legacy plaintext entries and minted digests are both scanned in full, and
    /// an inactive (revoked or expired) record is compared and then discarded
    /// rather than skipped — skipping early would make a revoked credential
    /// answer faster than a live one, which is a timing oracle for exactly the
    /// credential an attacker most wants to probe.
    pub fn resolve(&self, presented: &str) -> Option<&Collector> {
        self.resolve_at(presented, chrono::Utc::now().timestamp())
    }

    /// [`resolve`](Self::resolve) at an explicit time, so expiry is testable.
    pub fn resolve_at(&self, presented: &str, now: i64) -> Option<&Collector> {
        if presented.is_empty() {
            return None;
        }
        let mut found: Option<&Collector> = None;
        for c in &self.collectors {
            if ct_eq(presented.as_bytes(), c.token.as_bytes()) {
                found = Some(c);
            }
        }
        if let Some(key) = self.digest_key.as_ref() {
            let presented_digest = keyed_digest(key, presented);
            for (i, r) in self.records.iter().enumerate() {
                let Some(stored) = r.digest_hex.as_deref().and_then(unhex) else {
                    continue;
                };
                let matches = ct_eq(&presented_digest, &stored);
                if matches && r.is_active(now) {
                    // `bridged` is built index-aligned with `records`, so this is
                    // the collector for exactly this record — not a by-id lookup,
                    // which would pick the wrong one if an id were ever reused
                    // across a revoked and a live credential.
                    if let Some(c) = self.bridged.get(i) {
                        found = Some(c);
                    }
                }
            }
        }
        found
    }
}

/// A collector credential with a lifecycle: when it was made, when it stops
/// working, and whether an operator has pulled it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollectorRecord {
    pub id: String,
    /// Hex keyed-digest of the token, for minted credentials. Absent for legacy
    /// plaintext entries, which never reach the on-disk file.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub digest_hex: Option<String>,
    #[serde(default)]
    pub sources: Vec<String>,
    pub created_at: i64,
    /// Unix seconds after which this credential stops authenticating. `None` =
    /// no expiry, which an operator must choose deliberately.
    #[serde(default)]
    pub expires_at: Option<i64>,
    /// Soft revocation. The record is KEPT so the audit history of a compromised
    /// collector survives its removal — deleting the row would erase the very
    /// evidence an incident review needs.
    #[serde(default)]
    pub revoked: bool,
    /// A short non-reversible prefix of the digest, so an operator can tell two
    /// credentials apart in a listing without either being usable.
    #[serde(default)]
    pub fingerprint: String,
}

impl CollectorRecord {
    /// Is this credential usable right now?
    pub fn is_active(&self, now: i64) -> bool {
        !self.revoked && self.expires_at.is_none_or(|e| now < e)
    }

    /// Why this credential is not usable, for operator diagnostics. `None` when
    /// it is active.
    pub fn inactive_reason(&self, now: i64) -> Option<&'static str> {
        if self.revoked {
            return Some("revoked");
        }
        if self.expires_at.is_some_and(|e| now >= e) {
            return Some("expired");
        }
        None
    }
}

/// The on-disk registry file. Versioned from the first byte: a format that has
/// to be read by a future garmr — possibly after the operator has forgotten it
/// exists — must be able to say what it is rather than be guessed at.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollectorFile {
    pub version: u32,
    #[serde(default)]
    pub collectors: Vec<CollectorRecord>,
}

/// The only format version this build writes.
pub const COLLECTOR_FILE_VERSION: u32 = 1;

impl CollectorFile {
    pub fn new() -> Self {
        Self {
            version: COLLECTOR_FILE_VERSION,
            collectors: Vec::new(),
        }
    }

    /// Parse, refusing a version this build does not understand.
    ///
    /// Refusing beats best-effort: a newer file may express a restriction (a
    /// scope, a narrower binding) that this build cannot see, and silently
    /// ignoring it would grant more access than the operator wrote down.
    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        let f: CollectorFile = serde_json::from_slice(bytes)
            .map_err(|e| format!("collector file parse error: {e}"))?;
        if f.version > COLLECTOR_FILE_VERSION {
            return Err(format!(
                "collector file version {} is newer than this build understands ({}); \
                 refusing rather than ignoring restrictions it may express",
                f.version, COLLECTOR_FILE_VERSION
            ));
        }
        Ok(f)
    }
}

impl Default for CollectorFile {
    fn default() -> Self {
        Self::new()
    }
}

/// A freshly minted credential: the record to persist, and the secret to show
/// the operator exactly once.
pub struct Minted {
    pub record: CollectorRecord,
    /// The bearer token. Never stored — after this value is dropped, only the
    /// digest remains and the token cannot be recovered from it.
    pub token: String,
}

/// The single place a collector credential is created.
///
/// One mint path rather than several is a security property, not tidiness:
/// every credential then has the same entropy (32 CSPRNG bytes), the same
/// storage shape (keyed digest, never the secret), and the same lifecycle
/// fields. A second creation path is how a weaker one gets added later without
/// anyone noticing.
pub fn mint(
    id: &str,
    sources: Vec<String>,
    expires_at: Option<i64>,
    key: &[u8; 32],
    now: i64,
) -> Result<Minted, String> {
    if id.trim().is_empty() {
        return Err("collector id must not be empty".into());
    }
    let mut raw = [0u8; 32];
    raw[..16].copy_from_slice(uuid::Uuid::new_v4().as_bytes());
    raw[16..].copy_from_slice(uuid::Uuid::new_v4().as_bytes());
    let token = hex(&raw);
    let digest = keyed_digest(key, &token);
    let digest_hex = hex(&digest);
    // A prefix of the DIGEST, not of the token: a fingerprint is for telling
    // credentials apart in a listing, and must never narrow the search space of
    // the secret itself.
    let fingerprint = digest_hex[..12].to_string();
    Ok(Minted {
        record: CollectorRecord {
            id: id.to_string(),
            digest_hex: Some(digest_hex),
            sources,
            created_at: now,
            expires_at,
            revoked: false,
            fingerprint,
        },
        token,
    })
}

/// Keyed BLAKE3 over the token. Keyed so a stolen registry file cannot be
/// attacked with precomputed tables — the digest is only meaningful to a garmr
/// that holds the same key.
pub fn keyed_digest(key: &[u8; 32], token: &str) -> [u8; 32] {
    *blake3::keyed_hash(key, token.as_bytes()).as_bytes()
}

fn hex(b: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(b.len() * 2);
    for byte in b {
        let _ = write!(s, "{byte:02x}");
    }
    s
}

fn unhex(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
        let hi = (chunk[0] as char).to_digit(16)?;
        let lo = (chunk[1] as char).to_digit(16)?;
        out[i] = (hi * 16 + lo) as u8;
    }
    Some(out)
}

/// A hot-swappable collector registry, shared between the ingest listeners and
/// the reload watcher.
///
/// `enabled` is decided ONCE, at startup, and never changes on a swap. That is
/// the invariant that makes hot reload safe to have at all: the request path
/// treats "no registry" as the unauthenticated default-off posture, so if a
/// reload could produce an empty registry that reads as "auth off", a truncated
/// file — or a malicious one — would quietly open ingest to the world. With the
/// bit fixed at startup, an enabled listener with an empty registry rejects
/// every request (401) instead: an outage, loudly, never an open door.
#[derive(Debug)]
pub struct SharedCollectors {
    enabled: bool,
    inner: std::sync::RwLock<std::sync::Arc<CollectorRegistry>>,
}

impl SharedCollectors {
    pub fn new(initial: CollectorRegistry) -> std::sync::Arc<Self> {
        std::sync::Arc::new(Self {
            enabled: !initial.is_empty(),
            inner: std::sync::RwLock::new(std::sync::Arc::new(initial)),
        })
    }

    /// Was collector authentication enabled at startup? The request path keys
    /// off THIS, never off the current registry's emptiness.
    pub fn enabled(&self) -> bool {
        self.enabled
    }

    /// The current registry snapshot (cheap: an Arc clone under a read lock).
    pub fn get(&self) -> std::sync::Arc<CollectorRegistry> {
        self.inner.read().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// Install a new registry. In-flight requests keep the snapshot they took;
    /// the next request sees the new one — a revoke takes effect on the next
    /// request without bouncing the listener.
    pub fn swap(&self, next: CollectorRegistry) {
        *self.inner.write().unwrap_or_else(|e| e.into_inner()) = std::sync::Arc::new(next);
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

    fn key() -> [u8; 32] {
        [7u8; 32]
    }

    #[test]
    fn a_minted_credential_resolves_and_its_secret_is_not_stored() {
        let m = mint("fw", vec!["firewall".into()], None, &key(), 1_000).unwrap();
        let mut r = CollectorRegistry::new();
        r.load_records(key(), vec![m.record.clone()]);

        assert_eq!(
            r.resolve_at(&m.token, 1_000).map(|c| c.id.as_str()),
            Some("fw")
        );
        // The persisted record must not contain the token in any field.
        let json = serde_json::to_string(&m.record).unwrap();
        assert!(
            !json.contains(&m.token),
            "the minted token leaked into the stored record: {json}"
        );
    }

    #[test]
    fn revocation_and_expiry_stop_a_credential_working() {
        let m = mint("fw", vec![], Some(2_000), &key(), 1_000).unwrap();
        let mut r = CollectorRegistry::new();
        r.load_records(key(), vec![m.record.clone()]);
        // Live before the expiry instant.
        assert!(r.resolve_at(&m.token, 1_999).is_some());
        // Expiry is exclusive: at the instant itself it is already dead, so a
        // credential is never usable during the second it expires.
        assert!(r.resolve_at(&m.token, 2_000).is_none());
        assert_eq!(m.record.inactive_reason(2_000), Some("expired"));

        let mut revoked = m.record.clone();
        revoked.revoked = true;
        let mut r2 = CollectorRegistry::new();
        r2.load_records(key(), vec![revoked.clone()]);
        assert!(r2.resolve_at(&m.token, 1_000).is_none());
        assert_eq!(revoked.inactive_reason(1_000), Some("revoked"));
    }

    #[test]
    fn a_revoked_id_reused_by_a_live_credential_resolves_to_the_live_one() {
        // Rotation reuses the id: the old record stays for audit history. A
        // by-id lookup would be ambiguous here; resolution must follow the
        // digest that actually matched.
        let old = mint("fw", vec!["a".into()], None, &key(), 1_000).unwrap();
        let mut old_rec = old.record.clone();
        old_rec.revoked = true;
        let new = mint("fw", vec!["b".into()], None, &key(), 2_000).unwrap();

        let mut r = CollectorRegistry::new();
        r.load_records(key(), vec![old_rec, new.record.clone()]);
        assert!(
            r.resolve_at(&old.token, 3_000).is_none(),
            "revoked token must not work"
        );
        let got = r.resolve_at(&new.token, 3_000).expect("live token works");
        assert_eq!(got.sources, vec!["b".to_string()]);
    }

    #[test]
    fn without_the_key_no_minted_credential_can_resolve() {
        // A registry that has records but no key cannot verify a digest. The
        // safe answer is to refuse, never to admit.
        let m = mint("fw", vec![], None, &key(), 1_000).unwrap();
        let mut r = CollectorRegistry::new();
        r.records = vec![m.record.clone()];
        assert!(r.resolve_at(&m.token, 1_000).is_none());
    }

    #[test]
    fn legacy_plaintext_env_collectors_keep_working() {
        // The whole point of the two-arm secret: an operator on GARMR_COLLECTORS
        // must not be broken by the introduction of minted credentials.
        let mut r = reg();
        let m = mint("new", vec![], None, &key(), 1_000).unwrap();
        r.load_records(key(), vec![m.record]);
        assert_eq!(
            r.resolve_at("s3cr3t", 1_000).map(|c| c.id.as_str()),
            Some("fw-collector")
        );
        assert_eq!(
            r.resolve_at(&m.token, 1_000).map(|c| c.id.as_str()),
            Some("new")
        );
        assert!(r.resolve_at("", 1_000).is_none());
    }

    #[test]
    fn a_newer_file_version_is_refused_not_best_efforted() {
        let ok = CollectorFile::parse(br#"{"version":1,"collectors":[]}"#).unwrap();
        assert_eq!(ok.version, 1);
        let err = CollectorFile::parse(br#"{"version":99,"collectors":[]}"#).unwrap_err();
        assert!(err.contains("newer than this build"), "{err}");
    }

    #[test]
    fn the_fingerprint_reveals_nothing_about_the_token() {
        let m = mint("fw", vec![], None, &key(), 1_000).unwrap();
        assert_eq!(m.record.fingerprint.len(), 12);
        assert!(
            !m.token.contains(&m.record.fingerprint),
            "the fingerprint must derive from the digest, not the secret"
        );
    }

    #[test]
    fn a_hot_swap_takes_effect_and_enabled_never_changes() {
        // The invariant that makes hot reload safe to have: `enabled` is fixed
        // at startup, so a swapped-in EMPTY registry means "reject everyone"
        // (401s, an outage, loudly) — never "auth off" (an open door). A
        // truncated or malicious registry file can therefore only ever fail
        // closed.
        let m = mint("fw", vec![], None, &key(), 1_000).unwrap();
        let mut initial = CollectorRegistry::new();
        initial.load_records(key(), vec![m.record.clone()]);
        let shared = SharedCollectors::new(initial);
        assert!(shared.enabled());
        assert!(shared.get().resolve_at(&m.token, 1_000).is_some());

        // Revoke via swap: the next request sees the new registry.
        let mut revoked_rec = m.record.clone();
        revoked_rec.revoked = true;
        let mut next = CollectorRegistry::new();
        next.load_records(key(), vec![revoked_rec]);
        shared.swap(next);
        assert!(
            shared.get().resolve_at(&m.token, 1_000).is_none(),
            "the revoke takes effect without a restart"
        );

        // The empty swap: still enabled, resolves nothing.
        shared.swap(CollectorRegistry::new());
        assert!(shared.enabled(), "enabled NEVER changes on a swap");
        assert!(shared.get().resolve_at(&m.token, 1_000).is_none());

        // And a registry that starts empty is genuinely disabled — the
        // default-off posture is a startup decision, not a runtime one.
        let off = SharedCollectors::new(CollectorRegistry::new());
        assert!(!off.enabled());
    }
}
