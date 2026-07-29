// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! Offline verification of a ledger directory.
//!
//! Runs with no daemon and no network, over exported segments + checkpoints + an
//! out-of-band trust root (the trusted public key(s)). It is the authoritative
//! check that the ledger has not been mutated, reordered, truncated, or forged.
//!
//! Detection strategy:
//! - **Hash chain** — each record's `previous_hash` must equal the prior record's
//!   `record_hash`, and the recomputed hash must equal the stored one. Catches
//!   in-place mutation and chain breaks.
//! - **Monotonic sequence** — `global_sequence` must increase by exactly 1.
//!   Catches deletion, insertion, and reordering.
//! - **Signed checkpoints** — an attacker who re-hashes the whole forward chain
//!   (no secret is in the chain) still cannot re-sign the checkpoints; a
//!   checkpoint whose committed `(sequence, record_hash, count)` disagrees with
//!   the ledger — or is missing/short — reveals truncation and rollback.

use std::collections::HashMap;
use std::path::Path;

use gatling::gatling_forkjoin::gatling_for_each;

use crate::canonical::compute_record_hash;
use crate::checkpoint::Checkpoint;
use crate::error::Result;
use crate::event::Digest;
use crate::segment::{list_checkpoint_paths, list_segment_ids, segment_filename};
use crate::sign::{key_id_from_public, verify};

/// The set of trusted signing keys (by key id). For a single-key deployment,
/// [`TrustRoot::from_public_key`] is enough.
#[derive(Clone, Default)]
pub struct TrustRoot {
    keys: HashMap<String, [u8; 32]>,
}

impl TrustRoot {
    pub fn new() -> Self {
        TrustRoot::default()
    }

    /// Trust a single public key (its id is derived the same way the signer does).
    pub fn from_public_key(pk: [u8; 32]) -> Self {
        let mut t = TrustRoot::new();
        t.keys.insert(key_id_from_public(&pk), pk);
        t
    }

    /// Add a trusted key under an explicit id.
    pub fn with_key(mut self, key_id: impl Into<String>, pk: [u8; 32]) -> Self {
        self.keys.insert(key_id.into(), pk);
        self
    }

    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    fn get(&self, key_id: &str) -> Option<&[u8; 32]> {
        self.keys.get(key_id)
    }
}

/// A single problem found during verification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Finding {
    pub kind: FindingKind,
    pub sequence: Option<u64>,
    pub detail: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FindingKind {
    /// A record's recomputed hash does not match its stored `record_hash`.
    HashMismatch,
    /// A record's `previous_hash` does not link to the prior record.
    ChainBreak,
    /// A gap, duplicate, or out-of-order `global_sequence`.
    SequenceGap,
    /// A complete line failed to parse (corruption).
    ParseError,
    /// A checkpoint or record signature failed verification.
    BadSignature,
    /// A checkpoint was signed by a key not in the trust root.
    Untrusted,
    /// A checkpoint commits a sequence/count the ledger no longer satisfies.
    Truncated,
    /// A checkpoint's committed record hash disagrees with the ledger.
    CheckpointMismatch,
    /// No trust root supplied; signatures were not authenticated.
    NoTrustRoot,
}

/// The outcome of verification.
#[derive(Clone, Debug)]
pub struct VerifyReport {
    pub ok: bool,
    pub records_checked: u64,
    pub segments: u64,
    pub checkpoints_checked: u64,
    pub last_sequence: u64,
    pub last_hash: Option<Digest>,
    pub findings: Vec<Finding>,
}

impl VerifyReport {
    fn push(&mut self, kind: FindingKind, sequence: Option<u64>, detail: impl Into<String>) {
        self.findings.push(Finding {
            kind,
            sequence,
            detail: detail.into(),
        });
        self.ok = false;
    }
}

struct WalkedRecord {
    sequence: u64,
    segment_id: u64,
    record_hash: Digest,
}

/// The result of the record signature check, computed per-record in parallel.
/// It captures exactly which (if any) finding the serial walk must emit, so the
/// parallel path is byte-for-byte equivalent to the old inline signature match.
#[derive(Clone, Copy)]
enum SignatureCheck {
    /// Signed, key trusted, signature verified — no finding.
    Valid,
    /// No signature, or signed by an unknown key with an empty trust root — no finding.
    Absent,
    /// Signed, key trusted, but the signature did not verify.
    Invalid,
    /// Signed by a key that is not in a non-empty trust root.
    Untrusted,
}

/// The independent, order-free crypto for a single record: its recomputed hash
/// and its signature verdict. Both are pure functions of the record alone, so a
/// worker pool computes them; the serial chain walk only consumes them.
struct RecordCrypto {
    recomputed: Digest,
    signature: SignatureCheck,
}

/// One parsed (or unparseable) segment line, kept in stream order so the serial
/// walk emits findings in the exact order the old inline loop did.
enum ParsedItem {
    Record {
        segment_id: u64,
        // Boxed so this variant does not dwarf the tiny `Unparseable` one — the
        // parse builds a `Vec<ParsedItem>` over a whole ledger, so a flat
        // `AuditRecord` here would size every slot (clippy::large_enum_variant).
        record: Box<crate::event::AuditRecord>,
    },
    Unparseable {
        segment_id: u64,
        error: String,
    },
}

/// Verify the ledger rooted at `dir` against `trust`.
pub fn verify_dir(dir: impl AsRef<Path>, trust: &TrustRoot) -> Result<VerifyReport> {
    let dir = dir.as_ref();
    let seg_dir = dir.join("segments");
    let ckpt_dir = dir.join("checkpoints");

    let mut report = VerifyReport {
        ok: true,
        records_checked: 0,
        segments: 0,
        checkpoints_checked: 0,
        last_sequence: 0,
        last_hash: None,
        findings: Vec::new(),
    };

    if trust.is_empty() {
        report.push(
            FindingKind::NoTrustRoot,
            None,
            "no trusted public key supplied; signatures cannot be authenticated",
        );
    }

    let ids = list_segment_ids(&seg_dir)?;
    report.segments = ids.len() as u64;

    // Verification runs in three passes. Only the last is order-dependent, so
    // only the last is serial; the crypto in between is fanned out over a pool.

    // Pass 1 (serial I/O): read every segment and parse each line into a flat,
    // index-ordered list. Parse failures are kept in stream position so the
    // finding order below is byte-for-byte identical to the old inline walk.
    let mut items: Vec<ParsedItem> = Vec::new();
    for id in &ids {
        let path = seg_dir.join(segment_filename(*id));
        let data = std::fs::read(&path)?;
        for line in data.split(|&b| b == b'\n') {
            if line.is_empty() {
                continue;
            }
            match serde_json::from_slice::<crate::event::AuditRecord>(line) {
                Ok(record) => items.push(ParsedItem::Record {
                    segment_id: *id,
                    record: Box::new(record),
                }),
                Err(e) => items.push(ParsedItem::Unparseable {
                    segment_id: *id,
                    error: e.to_string(),
                }),
            }
        }
    }

    // Pass 2 (parallel): the INDEPENDENT per-record crypto. Recomputing the
    // BLAKE3 record hash and verifying the Ed25519 record signature are pure
    // functions of one record, so they run across a no-barrier worker pool. The
    // result is index-ordered, so the serial walk sees exactly what the old
    // inline loop computed, in the same order.
    let crypto: Vec<RecordCrypto> = gatling_for_each(items.len(), 0, |i| match &items[i] {
        ParsedItem::Record { record, .. } => {
            let recomputed = compute_record_hash(record);
            let signature = match &record.signature {
                Some(sig) => match record.signing_key_id.as_deref().and_then(|kid| trust.get(kid)) {
                    Some(pk) => {
                        if verify(pk, &record.record_hash.0, sig) {
                            SignatureCheck::Valid
                        } else {
                            SignatureCheck::Invalid
                        }
                    }
                    None if !trust.is_empty() => SignatureCheck::Untrusted,
                    None => SignatureCheck::Absent,
                },
                None => SignatureCheck::Absent,
            };
            RecordCrypto {
                recomputed,
                signature,
            }
        }
        // Unused for unparseable lines (the walk skips them), but every slot must
        // be filled for the index-ordered collect.
        ParsedItem::Unparseable { .. } => RecordCrypto {
            recomputed: Digest::ZERO,
            signature: SignatureCheck::Absent,
        },
    });

    // Pass 3 (serial): the hash-chain walk. prev_hash linkage and sequence
    // monotonicity are order-dependent, so they stay serial — but they now
    // consume the pre-computed crypto rather than recomputing it. Findings are
    // pushed in the exact order, and with the exact messages, of the old walk.
    let mut walked: Vec<WalkedRecord> = Vec::new();
    let mut by_seq: HashMap<u64, Digest> = HashMap::new();
    let mut seg_counts: HashMap<u64, u64> = HashMap::new();
    let mut prev_hash = Digest::ZERO;
    let mut expected_seq: u64 = 1;

    for (item, rc) in items.iter().zip(crypto.iter()) {
        let (id, rec) = match item {
            ParsedItem::Unparseable { segment_id, error } => {
                report.push(
                    FindingKind::ParseError,
                    None,
                    format!("segment {segment_id:016x}: unparseable record: {error}"),
                );
                continue;
            }
            ParsedItem::Record { segment_id, record } => (*segment_id, record),
        };

        report.records_checked += 1;
        *seg_counts.entry(id).or_insert(0) += 1;

        // Hash integrity (recomputed in pass 2).
        if rc.recomputed != rec.record_hash {
            report.push(
                FindingKind::HashMismatch,
                Some(rec.global_sequence),
                format!(
                    "record body does not match its hash (stored {}, computed {})",
                    &rec.record_hash.to_hex()[..16],
                    &rc.recomputed.to_hex()[..16]
                ),
            );
        }

        // Chain linkage.
        if rec.previous_hash != prev_hash {
            report.push(
                FindingKind::ChainBreak,
                Some(rec.global_sequence),
                "previous_hash does not link to the prior record",
            );
        }

        // Monotonic sequence.
        if rec.global_sequence != expected_seq {
            report.push(
                FindingKind::SequenceGap,
                Some(rec.global_sequence),
                format!(
                    "expected sequence {expected_seq}, found {}",
                    rec.global_sequence
                ),
            );
        }

        // Optional per-record signature (verified in pass 2).
        match rc.signature {
            SignatureCheck::Invalid => report.push(
                FindingKind::BadSignature,
                Some(rec.global_sequence),
                "record signature invalid",
            ),
            SignatureCheck::Untrusted => report.push(
                FindingKind::Untrusted,
                Some(rec.global_sequence),
                "record signed by an untrusted key",
            ),
            SignatureCheck::Valid | SignatureCheck::Absent => {}
        }

        by_seq.insert(rec.global_sequence, rec.record_hash);
        walked.push(WalkedRecord {
            sequence: rec.global_sequence,
            segment_id: id,
            record_hash: rec.record_hash,
        });
        prev_hash = rec.record_hash;
        expected_seq = rec.global_sequence + 1;
    }

    if let Some(last) = walked.last() {
        report.last_sequence = last.sequence;
        report.last_hash = Some(last.record_hash);
    }

    // Checkpoints: authenticate, then cross-check against the walked ledger.
    for path in list_checkpoint_paths(&ckpt_dir)? {
        let bytes = std::fs::read(&path)?;
        let cp: Checkpoint = match serde_json::from_slice(&bytes) {
            Ok(c) => c,
            Err(e) => {
                report.push(
                    FindingKind::ParseError,
                    None,
                    format!("unparseable checkpoint {}: {e}", path.display()),
                );
                continue;
            }
        };
        report.checkpoints_checked += 1;
        verify_checkpoint(&cp, trust, &by_seq, &seg_counts, &walked, &mut report);
    }

    Ok(report)
}

fn verify_checkpoint(
    cp: &Checkpoint,
    trust: &TrustRoot,
    by_seq: &HashMap<u64, Digest>,
    seg_counts: &HashMap<u64, u64>,
    walked: &[WalkedRecord],
    report: &mut VerifyReport,
) {
    // Authenticate the signature against the trust root.
    match trust.get(&cp.signing_key_id) {
        Some(pk) => {
            if !cp.verify_with(pk) {
                report.push(
                    FindingKind::BadSignature,
                    Some(cp.global_sequence),
                    format!(
                        "checkpoint at sequence {} has an invalid signature",
                        cp.global_sequence
                    ),
                );
            }
        }
        None if !trust.is_empty() => {
            report.push(
                FindingKind::Untrusted,
                Some(cp.global_sequence),
                format!(
                    "checkpoint at sequence {} signed by an untrusted key",
                    cp.global_sequence
                ),
            );
        }
        None => {}
    }

    // The committed sequence must still be present with the committed hash.
    match by_seq.get(&cp.global_sequence) {
        None => report.push(
            FindingKind::Truncated,
            Some(cp.global_sequence),
            format!(
                "checkpoint commits sequence {} but it is absent (truncation/rollback)",
                cp.global_sequence
            ),
        ),
        Some(h) if *h != cp.record_hash => report.push(
            FindingKind::CheckpointMismatch,
            Some(cp.global_sequence),
            format!(
                "checkpoint record hash disagrees with the ledger at sequence {}",
                cp.global_sequence
            ),
        ),
        Some(_) => {}
    }

    // For a sealed checkpoint, the segment must hold exactly the committed count.
    if cp.sealed {
        let actual = seg_counts.get(&cp.segment_id).copied().unwrap_or(0);
        // Count records in that segment up to and including the committed seq.
        let counted_upto = walked
            .iter()
            .filter(|w| w.segment_id == cp.segment_id && w.sequence <= cp.global_sequence)
            .count() as u64;
        if counted_upto < cp.segment_record_count {
            report.push(
                FindingKind::Truncated,
                Some(cp.global_sequence),
                format!(
                    "sealed segment {:016x} truncated: sealed at {} records, found {}",
                    cp.segment_id, cp.segment_record_count, counted_upto
                ),
            );
        } else if actual > cp.segment_record_count {
            report.push(
                FindingKind::CheckpointMismatch,
                Some(cp.global_sequence),
                format!(
                    "sealed segment {:016x} grew after sealing: sealed at {}, now {}",
                    cp.segment_id, cp.segment_record_count, actual
                ),
            );
        }
    }
}