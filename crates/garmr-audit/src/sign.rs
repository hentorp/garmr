// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! Signing interface + the default software (ed25519) signer.
//!
//! [`Signer`] is the interface a hardware-backed (PKCS#11/HSM) signer plugs into:
//! the ledger only ever calls `key_id`, `public_key`, and `sign`, so the private
//! key can live in an HSM and never enter process memory. The one concrete
//! implementation shipped today is [`SoftwareSigner`] (a local ed25519 key);
//! a PKCS#11 implementation is a documented follow-up behind the same trait, not
//! a hidden stub — the interface is complete and stable.

use std::path::Path;

use ed25519_dalek::{Signer as _, SigningKey, VerifyingKey};

use crate::error::{AuditError, Result};
use crate::event::Sig;

/// Anything that can sign audit checkpoints (and optionally records). The ledger
/// depends only on this trait, so software keys and HSM/PKCS#11 keys are
/// interchangeable.
pub trait Signer: Send + Sync {
    /// A stable identifier for the key (recorded in `signing_key_id`).
    fn key_id(&self) -> &str;
    /// The 32-byte ed25519 public key, for offline verification.
    fn public_key(&self) -> [u8; 32];
    /// Sign a message, returning the detached signature.
    fn sign(&self, msg: &[u8]) -> Sig;
}

/// A local ed25519 signing key. The 32-byte seed is the only secret; it is
/// persisted (0600 on unix) so the ledger's key is stable across restarts.
pub struct SoftwareSigner {
    signing_key: SigningKey,
    key_id: String,
    public_key: [u8; 32],
}

impl SoftwareSigner {
    /// Generate a fresh key from OS randomness.
    pub fn generate() -> Result<Self> {
        let mut seed = [0u8; 32];
        getrandom::getrandom(&mut seed).map_err(|e| AuditError::Random(e.to_string()))?;
        Ok(Self::from_seed(seed))
    }

    /// Build a signer from a known 32-byte seed (deterministic; for tests and
    /// key import).
    pub fn from_seed(seed: [u8; 32]) -> Self {
        let signing_key = SigningKey::from_bytes(&seed);
        let public_key = signing_key.verifying_key().to_bytes();
        let key_id = key_id_from_public(&public_key);
        SoftwareSigner {
            signing_key,
            key_id,
            public_key,
        }
    }

    /// Load the key seed from `path`, or generate + persist a new one if absent.
    pub fn load_or_create(path: &Path) -> Result<Self> {
        if path.exists() {
            let bytes = std::fs::read(path)?;
            let seed: [u8; 32] = bytes
                .as_slice()
                .try_into()
                .map_err(|_| AuditError::BadKey("key file must be exactly 32 bytes".into()))?;
            Ok(Self::from_seed(seed))
        } else {
            let signer = Self::generate()?;
            signer.save(path)?;
            Ok(signer)
        }
    }

    /// Persist the seed to `path` (creating parent dirs; 0600 on unix).
    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, self.signing_key.to_bytes())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        }
        Ok(())
    }
}

impl Signer for SoftwareSigner {
    fn key_id(&self) -> &str {
        &self.key_id
    }
    fn public_key(&self) -> [u8; 32] {
        self.public_key
    }
    fn sign(&self, msg: &[u8]) -> Sig {
        Sig(self.signing_key.sign(msg).to_bytes().to_vec())
    }
}

/// A key id derived from the public key: `ed25519-<first 8 bytes of BLAKE3(pk)>`.
pub fn key_id_from_public(public_key: &[u8; 32]) -> String {
    let h = blake3::hash(public_key);
    format!("ed25519-{}", hex::encode(&h.as_bytes()[..8]))
}

/// Verify a detached signature against a public key. Returns false on any
/// malformed input (wrong key/sig length, bad point) — never panics.
pub fn verify(public_key: &[u8; 32], msg: &[u8], sig: &Sig) -> bool {
    let vk = match VerifyingKey::from_bytes(public_key) {
        Ok(v) => v,
        Err(_) => return false,
    };
    let sig_bytes: [u8; 64] = match sig.0.as_slice().try_into() {
        Ok(b) => b,
        Err(_) => return false,
    };
    let signature = ed25519_dalek::Signature::from_bytes(&sig_bytes);
    vk.verify_strict(msg, &signature).is_ok()
}
