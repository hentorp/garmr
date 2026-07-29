// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! Content-mode policy: how much record content the ledger persists.
//!
//! Default is digest-only + immutable evidence references: raw sensitive prompt
//! and log content is *not* stored in the envelope, only its digest and refs.
//! This bounds exfiltration risk if the ledger leaks while preserving integrity
//! proofs. `redacted`/`encrypted`/`full` are opt-in per policy, and in those
//! modes the caller is responsible for supplying content already redacted or
//! encrypted (the ledger does not invent a redaction of arbitrary payloads).

use crate::event::{digest_of, AuditRecord, ContentMode};

/// Enforce the record's content mode in place. In `off`/`digest_only` the raw
/// `content` is dropped; if a digest of it was not already provided, it is
/// captured as `input_digest` so the record still commits to what was there.
pub fn apply_content_mode(rec: &mut AuditRecord) {
    match rec.content_mode {
        ContentMode::Off | ContentMode::DigestOnly => {
            if let Some(c) = rec.content.take() {
                if rec.input_digest.is_none() {
                    rec.input_digest = Some(digest_of(c.as_bytes()));
                }
            }
        }
        ContentMode::Redacted | ContentMode::Encrypted | ContentMode::Full => {
            // Keep content as provided; the caller guarantees it is appropriate
            // for the mode.
        }
    }
}