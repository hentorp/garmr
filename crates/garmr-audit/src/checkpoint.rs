// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! Signed checkpoints.
//!
//! A checkpoint commits, under a signature, that "at global sequence N the chain
//! head was hash H, and segment S then held C records". Two adversary moves are
//! caught only by checkpoints, not by the hash chain alone:
//!
//! - **Truncation** — dropping the most recent (incriminating) tail. A sealed
//!   checkpoint asserts the segment's final record count; a shorter segment is
//!   detected. A non-sealed checkpoint asserts a sequence that must still exist;
//!   a ledger truncated below it is detected.
//! - **Wholesale rollback** — replacing the ledger with a shorter valid chain.
//!   The highest checkpoint's sequence must be present.
//!
//! Checkpoints are signed with the ledger's key. Offline verification checks the
//! signature against a trust root supplied out-of-band, not against the ledger's
//! own published key (which an attacker who rewrote the ledger could also swap).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::event::{Digest, Sig};
use crate::sign::{verify, Signer};

/// Current checkpoint format version.
pub const CHECKPOINT_FORMAT: u16 = 1;

const CHECKPOINT_MAGIC: &[u8] = b"garmr-audit-checkpoint\x01";

/// A signed commitment to the chain state at a point in the sequence.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Checkpoint {
    pub format_version: u16,
    pub node_id: String,
    /// The segment this checkpoint refers to.
    pub segment_id: u64,
    /// The last global sequence covered.
    pub global_sequence: u64,
    /// The `record_hash` of the record at `global_sequence` (the chain head).
    pub record_hash: Digest,
    /// Records in `segment_id` up to and including `global_sequence`.
    pub segment_record_count: u64,
    /// True when the segment is closed at exactly `segment_record_count`.
    pub sealed: bool,
    pub created_at: DateTime<Utc>,
    pub signing_key_id: String,
    /// The signer's public key (hex) — a convenience copy; verification still
    /// requires an out-of-band trust root, never this field alone.
    pub public_key: String,
    pub signature: Sig,
}

impl Checkpoint {
    /// Create and sign a checkpoint over the given chain state.
    pub fn create(
        signer: &dyn Signer,
        node_id: &str,
        segment_id: u64,
        global_sequence: u64,
        record_hash: Digest,
        segment_record_count: u64,
        sealed: bool,
    ) -> Checkpoint {
        // Build the checkpoint with an empty signature, sign its own canonical
        // body, then fill the signature in.
        let mut cp = Checkpoint {
            format_version: CHECKPOINT_FORMAT,
            node_id: node_id.to_string(),
            segment_id,
            global_sequence,
            record_hash,
            segment_record_count,
            sealed,
            created_at: Utc::now(),
            signing_key_id: signer.key_id().to_string(),
            public_key: hex::encode(signer.public_key()),
            signature: Sig(Vec::new()),
        };
        cp.signature = signer.sign(&cp.signed_body());
        cp
    }

    /// The exact bytes this checkpoint's signature covers (excludes `signature`).
    fn signed_body(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(160);
        b.extend_from_slice(CHECKPOINT_MAGIC);
        b.extend_from_slice(&self.format_version.to_le_bytes());
        b.extend_from_slice(&(self.node_id.len() as u32).to_le_bytes());
        b.extend_from_slice(self.node_id.as_bytes());
        b.extend_from_slice(&self.segment_id.to_le_bytes());
        b.extend_from_slice(&self.global_sequence.to_le_bytes());
        b.extend_from_slice(&self.record_hash.0);
        b.extend_from_slice(&self.segment_record_count.to_le_bytes());
        b.push(self.sealed as u8);
        b.extend_from_slice(
            &self
                .created_at
                .timestamp_nanos_opt()
                .unwrap_or_else(|| self.created_at.timestamp().saturating_mul(1_000_000_000))
                .to_le_bytes(),
        );
        b.extend_from_slice(&(self.signing_key_id.len() as u32).to_le_bytes());
        b.extend_from_slice(self.signing_key_id.as_bytes());
        b.extend_from_slice(&(self.public_key.len() as u32).to_le_bytes());
        b.extend_from_slice(self.public_key.as_bytes());
        b
    }

    /// Verify the signature against an explicit trusted public key (the correct,
    /// offline path).
    pub fn verify_with(&self, trusted_public_key: &[u8; 32]) -> bool {
        verify(trusted_public_key, &self.signed_body(), &self.signature)
    }

    /// Verify against the checkpoint's own embedded public key. This proves
    /// internal consistency (the signature matches the stated key) but NOT
    /// authenticity — use only when the caller has already established that the
    /// embedded key is the trusted one.
    pub fn verify_self_consistent(&self) -> bool {
        match hex::decode(&self.public_key)
            .ok()
            .and_then(|v| <[u8; 32]>::try_from(v).ok())
        {
            Some(pk) => self.verify_with(&pk),
            None => false,
        }
    }
}
