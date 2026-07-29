// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! garmr-audit — a tamper-evident audit ledger.
//!
//! An append-only, single-writer ledger of security-relevant actions that can be
//! verified **offline**, after the fact, by a party who trusts neither the
//! running process nor the disk — only the offline verifier and the public half
//! of the signing key. See `docs/threat-model-audit-integrity.md`.
//!
//! # Guarantees
//! - **Append-only + monotonic sequence** — records carry a strictly increasing
//!   `global_sequence`; gaps, reorders, and inserts are detected.
//! - **BLAKE3 hash chain** — each record commits the previous record's hash, so
//!   any in-place mutation or deletion breaks the chain.
//! - **Signed checkpoints** — periodic ed25519-signed commitments make
//!   truncation and wholesale rollback detectable even against an attacker who
//!   re-hashes the forward chain.
//! - **Fail-closed durability** — [`AuditLedger::append`] fsyncs and, on failure,
//!   returns [`AuditError::DurabilityFailed`] without advancing the chain, so a
//!   protected state change can abort before it is acknowledged.
//! - **Content minimization** — by default only digests + evidence references are
//!   stored, never raw sensitive content (see [`ContentMode`]).
//!
//! # Example
//! ```no_run
//! use std::sync::Arc;
//! use garmr_audit::{AuditLedger, LedgerConfig, SoftwareSigner, AuditRecord,
//!     ActorType, Outcome, action, verify_dir, TrustRoot};
//!
//! let signer = Arc::new(SoftwareSigner::generate().unwrap());
//! let ledger = AuditLedger::open("/var/lib/garmr/audit", LedgerConfig::default(), signer).unwrap();
//! let pk = ledger.public_key(); // for the trust root used by offline verify
//!
//! ledger.append(
//!     AuditRecord::new(action::AUTH_LOGIN, "session")
//!         .actor(ActorType::Human, "operator", Some("admin"))
//!         .auth_method("passkey")
//!         .outcome(Outcome::Success)
//! ).unwrap();
//!
//! // Later, offline:
//! let report = verify_dir("/var/lib/garmr/audit", &TrustRoot::from_public_key(pk)).unwrap();
//! assert!(report.ok);
//! ```

mod canonical;
mod checkpoint;
mod content;
mod error;
mod event;
mod ledger;
mod segment;
mod sign;
mod verify;

pub use canonical::{canonical_body, compute_record_hash};
pub use checkpoint::{Checkpoint, CHECKPOINT_FORMAT};
pub use error::{AuditError, Result};
pub use event::{
    action, digest_of, ActorType, AuditRecord, ContentMode, DataClassification, Digest, Outcome,
    PolicyDecision, Sig,
};
pub use ledger::{AuditLedger, AuditReceipt, LedgerConfig};
pub use sign::{key_id_from_public, verify as verify_signature, Signer, SoftwareSigner};
pub use verify::{verify_dir, Finding, FindingKind, TrustRoot, VerifyReport};