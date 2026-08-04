// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! Secret management: the read-only environment baseline plus a writable,
//! encrypted-at-rest sealed store ([`SealedSecretStore`]), with [`source_of`]
//! reporting where each [`KNOWN_SECRETS`] entry currently resolves from.
//!
//! Design (the operator chose a writable encrypted store):
//! - Secrets have historically been environment variables only. That stays the
//!   read-only baseline: the UI can report configured / missing but cannot
//!   write an env secret.
//! - The [`SealedSecretStore`] adds a WRITABLE tier: AEAD-encrypted values on
//!   disk (`<state_dir>/secrets.sealed`, 0600), with the master key held
//!   SEPARATELY (env `GARMR_SECRET_KEY` or a key file, default
//!   `/etc/garmr/secret.key`) — never in the sealed file and never in a backup.
//!   Without a master key the writable tier is simply unavailable (env-only mode).
//!
//! Invariants:
//! - **Write-only**: there is no API that returns a stored secret. The UI shows
//!   only configured/missing/fingerprint/updated. Plaintext is decrypted solely
//!   inside the daemon (startup [`hydrate`] + connection tests) and zeroized after.
//! - AAD binds each ciphertext to its secret name, so a sealed row cannot be
//!   replayed under a different name.
//! - `GARMR_AIRGAP` is never a secret and is never overridable here.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use base64::Engine;
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, CHACHA20_POLY1305, NONCE_LEN};
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

const B64: base64::engine::general_purpose::GeneralPurpose =
    base64::engine::general_purpose::STANDARD;
const SEALED_FILE: &str = "secrets.sealed";

/// The secrets garmr knows how to consume — used for status listing and startup
/// hydration (env ← sealed when the env var is unset). Each names its provider
/// scope in the UI; all are external-integration secrets.
pub const KNOWN_SECRETS: &[&str] = &[
    "ANTHROPIC_API_KEY",
    "GARMR_OPENAI_API_KEY",
    "GARMR_MATRIX_TOKEN",
    "GARMR_WEBHOOK_URL",
    "GARMR_SMTP_PASSWORD",
    // Native-ingest collector bearer token. Hydrated into the env at startup
    // (before the ingest server reads it), so it can be managed from the console.
    "GARMR_COLLECTOR_TOKEN",
];

/// One sealed entry: a random nonce + AEAD ciphertext (tag appended) + display
/// metadata. The plaintext is never stored.
#[derive(Serialize, Deserialize, Clone)]
struct SealedEntry {
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
    fingerprint: String,
    updated: i64,
    version: u32,
}

/// Where a secret's value currently resolves from.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum SecretSource {
    Env,
    Sealed,
    Unset,
}

impl SecretSource {
    pub fn as_str(self) -> &'static str {
        match self {
            SecretSource::Env => "env",
            SecretSource::Sealed => "sealed",
            SecretSource::Unset => "unset",
        }
    }
}

/// The writable, encrypted-at-rest secret store.
pub struct SealedSecretStore {
    path: PathBuf,
    key: LessSafeKey,
    /// Key for the display fingerprint, derived from the master key so the
    /// fingerprint is NOT a preimage/dictionary oracle over a (possibly
    /// low-entropy) secret for anyone lacking the master key.
    fp_key: [u8; 32],
    rng: SystemRandom,
}

impl SealedSecretStore {
    /// Build from the master key (env `GARMR_SECRET_KEY` base64-32B, else the key
    /// file `GARMR_SECRET_KEY_FILE` / `/etc/garmr/secret.key`). `None` → no master
    /// key configured → the writable tier is unavailable (env-only mode).
    pub fn from_env(state_dir: &Path) -> Option<Self> {
        let mut master = load_master_key()?;
        let unbound = UnboundKey::new(&CHACHA20_POLY1305, &master).ok();
        let fp_key = blake3::derive_key("garmr sealed-secret fingerprint v1", &master);
        master.zeroize();
        let unbound = unbound?;
        Some(Self {
            path: state_dir.join(SEALED_FILE),
            key: LessSafeKey::new(unbound),
            fp_key,
            rng: SystemRandom::new(),
        })
    }

    /// A non-reversible short fingerprint of a secret value, KEYED with the
    /// master-derived key. The sealed file + audit ledger only ever carry this
    /// keyed tag (never the plaintext), and without the master key it reveals
    /// nothing about the secret — so it cannot be a dictionary/confirmation oracle
    /// even for a low-entropy value (e.g. an SMTP password).
    fn fingerprint(&self, secret: &str) -> String {
        let h = blake3::keyed_hash(&self.fp_key, secret.as_bytes());
        let hex: String = h
            .as_bytes()
            .iter()
            .take(4)
            .map(|b| format!("{b:02x}"))
            .collect();
        format!("fp_{hex}")
    }

    fn load_map(&self) -> BTreeMap<String, SealedEntry> {
        std::fs::read(&self.path)
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default()
    }

    fn save_map(&self, map: &BTreeMap<String, SealedEntry>) -> Result<(), String> {
        let bytes = serde_json::to_vec(map).map_err(|e| e.to_string())?;
        // Atomic write with restrictive permissions (never world/group readable).
        let tmp = self.path.with_extension("sealed.tmp");
        write_private(&tmp, &bytes)?;
        std::fs::rename(&tmp, &self.path).map_err(|e| e.to_string())
    }

    /// Store (or replace) a secret. Returns its fingerprint. Write-only — the
    /// plaintext is never returned. Bumps the version on replace.
    pub fn set(&self, name: &str, plaintext: &str) -> Result<String, String> {
        let mut map = self.load_map();
        let mut nonce = [0u8; NONCE_LEN];
        self.rng
            .fill(&mut nonce)
            .map_err(|_| "rng failure".to_string())?;
        let mut in_out = plaintext.as_bytes().to_vec();
        self.key
            .seal_in_place_append_tag(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(name.as_bytes()),
                &mut in_out,
            )
            .map_err(|_| "seal failed".to_string())?;
        let fp = self.fingerprint(plaintext);
        let version = map.get(name).map(|e| e.version + 1).unwrap_or(1);
        map.insert(
            name.to_string(),
            SealedEntry {
                nonce: nonce.to_vec(),
                ciphertext: in_out,
                fingerprint: fp.clone(),
                updated: chrono::Utc::now().timestamp(),
                version,
            },
        );
        self.save_map(&map)?;
        Ok(fp)
    }

    /// Remove a sealed secret. Returns whether it existed.
    pub fn remove(&self, name: &str) -> Result<bool, String> {
        let mut map = self.load_map();
        let existed = map.remove(name).is_some();
        if existed {
            self.save_map(&map)?;
        }
        Ok(existed)
    }

    /// Display status of a sealed secret (fingerprint, updated, version) — no value.
    pub fn status(&self, name: &str) -> Option<(String, i64, u32)> {
        self.load_map()
            .get(name)
            .map(|e| (e.fingerprint.clone(), e.updated, e.version))
    }

    /// INTERNAL ONLY — decrypt a sealed secret. Used by startup hydration and
    /// connection tests; never exposed through the API.
    pub fn get_plaintext(&self, name: &str) -> Option<String> {
        let e = self.load_map().get(name).cloned()?;
        let nonce_arr: [u8; NONCE_LEN] = e.nonce.as_slice().try_into().ok()?;
        let mut buf = e.ciphertext.clone();
        let pt = self
            .key
            .open_in_place(
                Nonce::assume_unique_for_key(nonce_arr),
                Aad::from(name.as_bytes()),
                &mut buf,
            )
            .ok()?;
        let s = String::from_utf8(pt.to_vec()).ok();
        buf.zeroize();
        s
    }
}

/// Resolve where a secret currently comes from, without revealing its value. Env
/// wins over the sealed store (an explicit env override), which the UI surfaces.
pub fn source_of(name: &str, sealed: Option<&SealedSecretStore>) -> SecretSource {
    if std::env::var(name).is_ok() {
        SecretSource::Env
    } else if sealed.and_then(|s| s.status(name)).is_some() {
        SecretSource::Sealed
    } else {
        SecretSource::Unset
    }
}

/// Startup hydration: for every known secret UNSET in the env, load it from a
/// secret provider so the existing env-reading construction paths (LLM client,
/// notifier, ingest, …) pick it up. Precedence: an explicit env var always wins,
/// then a systemd credential (opt-in — present in `$CREDENTIALS_DIRECTORY` when
/// the operator adds `LoadCredential=<NAME>:…` to the unit), then the console
/// sealed store. Runs single-threaded at startup before any task spawns. Returns
/// how many secrets were hydrated.
pub fn hydrate(state_dir: &Path) -> usize {
    let sealed = SealedSecretStore::from_env(state_dir);
    let creds_dir = std::env::var("CREDENTIALS_DIRECTORY")
        .ok()
        .map(std::path::PathBuf::from);
    let mut n = 0;
    let mut from_systemd = 0;
    for name in KNOWN_SECRETS {
        if std::env::var(name).is_ok() {
            continue; // an explicit env var always wins
        }
        // systemd credential (unit-provisioned) takes precedence over the sealed
        // store; both are read only when the env var is unset.
        let systemd = creds_dir
            .as_ref()
            .and_then(|d| std::fs::read_to_string(d.join(name)).ok())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());
        if systemd.is_some() {
            from_systemd += 1;
        }
        let val = systemd.or_else(|| sealed.as_ref().and_then(|s| s.get_plaintext(name)));
        if let Some(v) = val {
            // SAFETY: single-threaded startup, before the API/agent tasks spawn.
            std::env::set_var(name, v);
            n += 1;
        }
    }
    if n > 0 {
        tracing::info!(
            count = n,
            from_systemd,
            "hydrated secrets (systemd credentials / sealed store)"
        );
    }
    n
}

fn load_master_key() -> Option<[u8; 32]> {
    if let Ok(b64) = std::env::var("GARMR_SECRET_KEY") {
        return B64.decode(b64.trim()).ok().and_then(|b| b.try_into().ok());
    }
    let path =
        std::env::var("GARMR_SECRET_KEY_FILE").unwrap_or_else(|_| "/etc/garmr/secret.key".into());
    let raw = std::fs::read(&path).ok()?;
    // Accept 32 raw bytes or base64 text.
    if raw.len() == 32 {
        return raw.try_into().ok();
    }
    let text = String::from_utf8(raw).ok()?;
    B64.decode(text.trim()).ok().and_then(|b| b.try_into().ok())
}

/// Write bytes to `path` with 0600 permissions (owner read/write only).
fn write_private(path: &Path, bytes: &[u8]) -> Result<(), String> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| e.to_string())?;
    f.write_all(bytes).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store_with_key(dir: &Path, key: [u8; 32]) -> SealedSecretStore {
        let unbound = UnboundKey::new(&CHACHA20_POLY1305, &key).unwrap();
        SealedSecretStore {
            path: dir.join(SEALED_FILE),
            key: LessSafeKey::new(unbound),
            fp_key: blake3::derive_key("garmr sealed-secret fingerprint v1", &key),
            rng: SystemRandom::new(),
        }
    }

    fn tmpdir() -> PathBuf {
        let n = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let p = std::env::temp_dir().join(format!("garmr-secrets-test-{n}"));
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn seal_roundtrip_and_write_only_metadata() {
        let dir = tmpdir();
        let s = store_with_key(&dir, [1u8; 32]);
        let fp = s.set("ANTHROPIC_API_KEY", "sk-secret-123").unwrap();
        assert!(fp.starts_with("fp_"));
        assert!(!fp.contains("secret"));
        // status returns metadata only, never the value.
        let (sfp, _updated, version) = s.status("ANTHROPIC_API_KEY").unwrap();
        assert_eq!(sfp, fp);
        assert_eq!(version, 1);
        // internal decrypt recovers the plaintext.
        assert_eq!(
            s.get_plaintext("ANTHROPIC_API_KEY").as_deref(),
            Some("sk-secret-123")
        );
        // replace bumps the version.
        s.set("ANTHROPIC_API_KEY", "sk-secret-456").unwrap();
        assert_eq!(s.status("ANTHROPIC_API_KEY").unwrap().2, 2);
        assert_eq!(
            s.get_plaintext("ANTHROPIC_API_KEY").as_deref(),
            Some("sk-secret-456")
        );
    }

    #[test]
    fn wrong_master_key_cannot_decrypt() {
        let dir = tmpdir();
        store_with_key(&dir, [1u8; 32])
            .set("GARMR_WEBHOOK_URL", "https://hook/secret")
            .unwrap();
        // A different key over the same sealed file must fail to open (AEAD auth).
        let other = store_with_key(&dir, [2u8; 32]);
        assert!(other.get_plaintext("GARMR_WEBHOOK_URL").is_none());
    }

    #[test]
    fn aad_binds_ciphertext_to_its_name() {
        let dir = tmpdir();
        let s = store_with_key(&dir, [7u8; 32]);
        s.set("ANTHROPIC_API_KEY", "value-a").unwrap();
        // Corrupt the map by moving the ciphertext under a different name → open
        // must fail because the AAD (name) no longer matches.
        let mut map = s.load_map();
        let entry = map.remove("ANTHROPIC_API_KEY").unwrap();
        map.insert("GARMR_OPENAI_API_KEY".into(), entry);
        s.save_map(&map).unwrap();
        assert!(
            s.get_plaintext("GARMR_OPENAI_API_KEY").is_none(),
            "AAD mismatch must fail"
        );
    }

    #[test]
    fn fingerprint_is_keyed_not_a_raw_oracle() {
        let d1 = tmpdir();
        let d2 = tmpdir();
        let a = store_with_key(&d1, [1u8; 32]);
        let b = store_with_key(&d2, [2u8; 32]);
        // Same (low-entropy) secret under different master keys → different
        // fingerprints, so the tag cannot be a dictionary oracle over the secret.
        assert_ne!(a.fingerprint("Summer2026!"), b.fingerprint("Summer2026!"));
        // Stable + non-reversible under one key.
        assert_eq!(a.fingerprint("x"), a.fingerprint("x"));
        assert!(a.fingerprint("secret").starts_with("fp_"));
        assert!(!a.fingerprint("secret").contains("secret"));
    }

    #[test]
    fn remove_deletes_the_secret() {
        let dir = tmpdir();
        let s = store_with_key(&dir, [9u8; 32]);
        s.set("GARMR_SMTP_PASSWORD", "pw").unwrap();
        assert!(s.remove("GARMR_SMTP_PASSWORD").unwrap());
        assert!(s.status("GARMR_SMTP_PASSWORD").is_none());
        assert!(
            !s.remove("GARMR_SMTP_PASSWORD").unwrap(),
            "second remove is a no-op"
        );
    }
}
