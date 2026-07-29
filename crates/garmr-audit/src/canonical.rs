// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! Deterministic canonical encoding of an [`AuditRecord`], and the record hash.
//!
//! Integrity must not depend on JSON serialization: serde_json map order,
//! whitespace, and float/number formatting are not guaranteed stable across
//! versions or platforms, so hashing the JSON bytes would make verification
//! fragile. Instead every committed field is written here in a **fixed order**
//! with explicit length framing, producing the exact bytes that are hashed and
//! signed. The verifier reproduces these bytes independently from the parsed
//! record and recomputes the hash — so any mutation, reordering, insertion, or
//! deletion changes the bytes and is detected.
//!
//! Excluded from the canonical body: `record_hash` (cannot hash itself) and
//! `signature` (signs the hash). Everything else — including `previous_hash`,
//! `global_sequence`, timestamps, and all references — is committed.

use crate::event::{AuditRecord, Digest};

/// A domain-separation tag + format version, so canonical bytes from this format
/// can never be confused with any other hashed structure or a future format.
const CANON_MAGIC: &[u8] = b"garmr-audit-record\x01";

/// Append a length-prefixed byte string (u32 LE length + bytes).
fn put_bytes(buf: &mut Vec<u8>, b: &[u8]) {
    buf.extend_from_slice(&(b.len() as u32).to_le_bytes());
    buf.extend_from_slice(b);
}

fn put_str(buf: &mut Vec<u8>, s: &str) {
    put_bytes(buf, s.as_bytes());
}

fn put_u64(buf: &mut Vec<u8>, n: u64) {
    buf.extend_from_slice(&n.to_le_bytes());
}

fn put_i64(buf: &mut Vec<u8>, n: i64) {
    buf.extend_from_slice(&n.to_le_bytes());
}

/// Presence byte + value for an optional string.
fn put_opt_str(buf: &mut Vec<u8>, o: &Option<String>) {
    match o {
        Some(s) => {
            buf.push(1);
            put_str(buf, s);
        }
        None => buf.push(0),
    }
}

/// Presence byte + value for an optional digest (raw 32 bytes).
fn put_opt_digest(buf: &mut Vec<u8>, o: &Option<Digest>) {
    match o {
        Some(d) => {
            buf.push(1);
            buf.extend_from_slice(&d.0);
        }
        None => buf.push(0),
    }
}

/// Count-prefixed vector of strings.
fn put_vec_str(buf: &mut Vec<u8>, v: &[String]) {
    put_u64(buf, v.len() as u64);
    for s in v {
        put_str(buf, s);
    }
}

/// Nanoseconds since the Unix epoch, saturating (deterministic across platforms).
fn ts_nanos(t: &chrono::DateTime<chrono::Utc>) -> i64 {
    t.timestamp_nanos_opt().unwrap_or_else(|| {
        // Out of nanosecond range (year < 1677 or > 2262): fall back to a
        // stable seconds*1e9 approximation so the encoding never panics.
        t.timestamp().saturating_mul(1_000_000_000)
    })
}

/// The exact bytes hashed and signed for a record. Deterministic and independent
/// of serde. Excludes `record_hash` and `signature`.
pub fn canonical_body(r: &AuditRecord) -> Vec<u8> {
    let mut b = Vec::with_capacity(512);
    b.extend_from_slice(CANON_MAGIC);

    // identity / ordering
    put_str(&mut b, &r.audit_id);
    put_u64(&mut b, r.global_sequence);
    put_i64(&mut b, ts_nanos(&r.occurred_at));
    put_i64(&mut b, ts_nanos(&r.recorded_at));
    put_str(&mut b, &r.node_id);
    put_str(&mut b, &r.process_id);

    // actor
    put_str(&mut b, actor_type_tag(r));
    put_str(&mut b, &r.actor_id);
    put_opt_str(&mut b, &r.actor_role);
    put_opt_str(&mut b, &r.authentication_method);

    // action
    put_str(&mut b, &r.action);
    put_str(&mut b, &r.object_type);
    put_opt_str(&mut b, &r.object_id);
    put_str(&mut b, outcome_tag(r));
    put_opt_str(&mut b, &r.reason);

    // correlation
    put_opt_str(&mut b, &r.correlation_id);
    put_opt_str(&mut b, &r.causation_id);
    put_opt_str(&mut b, &r.trace_id);
    put_str(&mut b, policy_tag(r));

    // digests
    put_opt_digest(&mut b, &r.input_digest);
    put_opt_digest(&mut b, &r.output_digest);
    put_opt_digest(&mut b, &r.before_digest);
    put_opt_digest(&mut b, &r.after_digest);

    // references
    put_vec_str(&mut b, &r.evidence_refs);
    put_vec_str(&mut b, &r.event_refs);
    put_vec_str(&mut b, &r.case_refs);
    put_opt_str(&mut b, &r.query_ref);
    put_opt_str(&mut b, &r.model_ref);
    put_opt_str(&mut b, &r.prompt_ref);
    put_opt_str(&mut b, &r.toolset_ref);
    put_opt_str(&mut b, &r.detector_ref);
    put_opt_str(&mut b, &r.parser_ref);

    // classification + content
    put_str(&mut b, classification_tag(r));
    put_opt_str(&mut b, &r.redaction_profile);
    put_str(&mut b, content_mode_tag(r));
    put_opt_str(&mut b, &r.content);

    // chain
    b.extend_from_slice(&r.previous_hash.0);
    put_opt_str(&mut b, &r.signing_key_id);

    b
}

/// The record hash = BLAKE3(canonical_body). Because the body already commits
/// `previous_hash`, this single hash chains the whole ledger.
pub fn compute_record_hash(r: &AuditRecord) -> Digest {
    Digest(*blake3::hash(&canonical_body(r)).as_bytes())
}

// --- stable tags for the small closed enums (never rely on serde repr) --------

fn actor_type_tag(r: &AuditRecord) -> &'static str {
    use crate::event::ActorType::*;
    match r.actor_type {
        Human => "human",
        Agent => "agent",
        Executor => "executor",
        System => "system",
        Collector => "collector",
        Service => "service",
        Unknown => "unknown",
    }
}

fn outcome_tag(r: &AuditRecord) -> &'static str {
    use crate::event::Outcome::*;
    match r.outcome {
        Success => "success",
        Failure => "failure",
        Denied => "denied",
        Error => "error",
        Pending => "pending",
    }
}

fn policy_tag(r: &AuditRecord) -> &'static str {
    use crate::event::PolicyDecision::*;
    match r.policy_decision {
        Allowed => "allowed",
        Denied => "denied",
        NotApplicable => "n/a",
    }
}

fn classification_tag(r: &AuditRecord) -> &'static str {
    use crate::event::DataClassification::*;
    match r.data_classification {
        Public => "public",
        Internal => "internal",
        Confidential => "confidential",
        Restricted => "restricted",
        Secret => "secret",
    }
}

fn content_mode_tag(r: &AuditRecord) -> &'static str {
    use crate::event::ContentMode::*;
    match r.content_mode {
        Off => "off",
        DigestOnly => "digest_only",
        Redacted => "redacted",
        Encrypted => "encrypted",
        Full => "full",
    }
}