// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! Error type for the audit ledger.

use thiserror::Error;

#[derive(Error, Debug)]
pub enum AuditError {
    #[error("audit i/o: {0}")]
    Io(#[from] std::io::Error),

    #[error("audit serialization: {0}")]
    Serde(#[from] serde_json::Error),

    #[error("could not gather randomness: {0}")]
    Random(String),

    #[error("invalid signing key: {0}")]
    BadKey(String),

    /// The ledger detected a tamper/corruption during recovery or verification.
    #[error("audit integrity failure: {0}")]
    Integrity(String),

    /// A durable audit write failed; the caller must fail the protected action
    /// closed (do not acknowledge the state change).
    #[error("durable audit write failed (fail closed): {0}")]
    DurabilityFailed(String),

    #[error("audit config: {0}")]
    Config(String),
}

pub type Result<T> = std::result::Result<T, AuditError>;
