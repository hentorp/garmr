// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! The append-only, single-writer audit ledger.
//!
//! One [`AuditLedger`] owns the writer state behind a mutex, so all appends are
//! serialized and the hash chain is total. Records are stamped
//! (sequence/hashes/identity), written as a JSON line, flushed, and optionally
//! fsynced. State (`segment_id`, `next_seq`, `prev_hash`) is recovered by
//! scanning the last segment on open, so the files are authoritative — there is
//! no separate mutable pointer that could disagree with them after a crash.
//!
//! `append` is the durable, fail-closed path: on any persistence error it
//! returns [`AuditError::DurabilityFailed`] and does **not** advance the chain,
//! so a caller performing a protected state change can abort before
//! acknowledging it (the outbox / fail-closed invariant).

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use crate::canonical::compute_record_hash;
use crate::checkpoint::Checkpoint;
use crate::content::apply_content_mode;
use crate::error::{AuditError, Result};
use crate::event::{AuditRecord, ContentMode, Digest};
use crate::segment::{checkpoint_filename, list_segment_ids, read_segment, segment_filename};
use crate::sign::Signer;

/// Ledger tuning. Defaults are safe for a single-node deployment.
#[derive(Clone, Debug)]
pub struct LedgerConfig {
    /// This node's identity, stamped into every record.
    pub node_id: String,
    /// How much record content to persist (default: digest-only).
    pub content_mode: ContentMode,
    /// Sign every record individually (default false — checkpoints are always
    /// signed, which is sufficient for tamper-evidence and far cheaper).
    pub per_record_sign: bool,
    /// Seal + roll to a new segment after this many records.
    pub segment_max_records: u64,
    /// Emit a checkpoint after this many records.
    pub checkpoint_every: u64,
    /// fsync each append before returning (durable; required for fail-closed).
    pub fsync: bool,
}

impl Default for LedgerConfig {
    fn default() -> Self {
        LedgerConfig {
            node_id: "garmr".to_string(),
            content_mode: ContentMode::DigestOnly,
            per_record_sign: false,
            segment_max_records: 10_000,
            checkpoint_every: 1_000,
            fsync: true,
        }
    }
}

/// What an append returns: enough to reference the record and prove it landed.
#[derive(Clone, Debug)]
pub struct AuditReceipt {
    pub audit_id: String,
    pub global_sequence: u64,
    pub record_hash: Digest,
}

struct Inner {
    segment_id: u64,
    next_seq: u64,
    prev_hash: Digest,
    records_in_segment: u64,
    records_since_ckpt: u64,
    file: File,
}

/// The audit ledger. Cheap to clone (shares one writer via `Arc`).
#[derive(Clone)]
pub struct AuditLedger {
    dir: PathBuf,
    cfg: LedgerConfig,
    process_id: String,
    signer: Arc<dyn Signer>,
    inner: Arc<Mutex<Inner>>,
}

impl AuditLedger {
    fn segments_dir(dir: &Path) -> PathBuf {
        dir.join("segments")
    }
    fn checkpoints_dir(dir: &Path) -> PathBuf {
        dir.join("checkpoints")
    }

    /// Open (or initialize) a ledger rooted at `dir`, recovering writer state by
    /// scanning the last segment. A torn trailing record is healed; a corrupt
    /// complete record fails the open (fail closed).
    pub fn open(dir: impl AsRef<Path>, cfg: LedgerConfig, signer: Arc<dyn Signer>) -> Result<Self> {
        let dir = dir.as_ref().to_path_buf();
        let seg_dir = Self::segments_dir(&dir);
        let ckpt_dir = Self::checkpoints_dir(&dir);
        std::fs::create_dir_all(&seg_dir)?;
        std::fs::create_dir_all(&ckpt_dir)?;

        let ids = list_segment_ids(&seg_dir)?;
        let (segment_id, next_seq, prev_hash, records_in_segment) = if ids.is_empty() {
            // Fresh ledger: segment 1, sequence starts at 1, genesis prev-hash.
            (1u64, 1u64, Digest::ZERO, 0u64)
        } else {
            let last_id = *ids.last().unwrap();
            let path = seg_dir.join(segment_filename(last_id));
            let read = read_segment(&path)?;
            if read.torn_tail {
                // Heal a crash mid-append by truncating the partial trailing line.
                let f = OpenOptions::new().write(true).open(&path)?;
                f.set_len(read.valid_len)?;
                f.sync_all()?;
            }
            // Verify the recovered segment's internal chain so we never resume on
            // top of a tampered tail.
            Self::verify_recovered_chain(&read.records)?;
            let (next_seq, prev_hash) = match read.records.last() {
                Some(last) => (last.global_sequence + 1, last.record_hash),
                None => {
                    // Empty last segment; fall back to the previous segment's head
                    // if any, else genesis.
                    Self::head_before(&seg_dir, &ids, last_id)?
                }
            };
            (last_id, next_seq, prev_hash, read.records.len() as u64)
        };

        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(seg_dir.join(segment_filename(segment_id)))?;

        let process_id = std::process::id().to_string();
        Ok(AuditLedger {
            dir,
            cfg,
            process_id,
            signer,
            inner: Arc::new(Mutex::new(Inner {
                segment_id,
                next_seq,
                prev_hash,
                records_in_segment,
                records_since_ckpt: 0,
                file,
            })),
        })
    }

    /// Recompute the chain over recovered records to detect a tampered tail on
    /// open. Fails closed on any mismatch.
    fn verify_recovered_chain(records: &[AuditRecord]) -> Result<()> {
        let mut prev = Digest::ZERO;
        let mut expect_seq: Option<u64> = None;
        for r in records {
            if r.previous_hash != prev {
                return Err(AuditError::Integrity(format!(
                    "recovered segment chain broken at sequence {}",
                    r.global_sequence
                )));
            }
            if let Some(want) = expect_seq {
                if r.global_sequence != want {
                    return Err(AuditError::Integrity(format!(
                        "recovered segment sequence gap: expected {want}, got {}",
                        r.global_sequence
                    )));
                }
            }
            if compute_record_hash(r) != r.record_hash {
                return Err(AuditError::Integrity(format!(
                    "recovered record hash mismatch at sequence {}",
                    r.global_sequence
                )));
            }
            prev = r.record_hash;
            expect_seq = Some(r.global_sequence + 1);
        }
        Ok(())
    }

    /// The chain head implied by the segment before `last_id` (used when the last
    /// segment is empty).
    fn head_before(seg_dir: &Path, ids: &[u64], last_id: u64) -> Result<(u64, Digest)> {
        let prev_ids: Vec<u64> = ids.iter().copied().filter(|&i| i < last_id).collect();
        if let Some(&pid) = prev_ids.last() {
            let read = read_segment(&seg_dir.join(segment_filename(pid)))?;
            if let Some(last) = read.records.last() {
                return Ok((last.global_sequence + 1, last.record_hash));
            }
        }
        Ok((1, Digest::ZERO))
    }

    /// The signer's public key (for building a trust root / offline verification).
    pub fn public_key(&self) -> [u8; 32] {
        self.signer.public_key()
    }

    /// The signer's key id.
    pub fn key_id(&self) -> String {
        self.signer.key_id().to_string()
    }

    /// Write the public key (hex) to `dir/public_key.hex` for convenience export.
    /// This is a convenience copy only; trust must be established out-of-band.
    pub fn export_public_key(&self) -> Result<PathBuf> {
        let path = self.dir.join("public_key.hex");
        std::fs::write(&path, hex::encode(self.signer.public_key()))?;
        Ok(path)
    }

    /// Append a record durably. Fail-closed: on any persistence error the chain
    /// does not advance and the caller must abort the protected action.
    pub fn append(&self, mut rec: AuditRecord) -> Result<AuditReceipt> {
        let mut inner = self.inner.lock().unwrap();

        // Roll to a fresh segment first if the current one is full.
        if inner.records_in_segment >= self.cfg.segment_max_records {
            self.seal_locked(&mut inner)?;
            self.roll_locked(&mut inner)?;
        }

        // Stamp ledger-owned fields.
        rec.audit_id = random_id()?;
        rec.global_sequence = inner.next_seq;
        rec.recorded_at = chrono::Utc::now();
        rec.node_id = self.cfg.node_id.clone();
        rec.process_id = self.process_id.clone();
        rec.content_mode = self.cfg.content_mode;
        apply_content_mode(&mut rec);
        rec.previous_hash = inner.prev_hash;
        // signing_key_id is part of the canonical body, so set it before hashing.
        if self.cfg.per_record_sign {
            rec.signing_key_id = Some(self.signer.key_id().to_string());
        } else {
            rec.signing_key_id = None;
            rec.signature = None;
        }
        rec.record_hash = compute_record_hash(&rec);
        if self.cfg.per_record_sign {
            rec.signature = Some(self.signer.sign(&rec.record_hash.0));
        }

        // Serialize + append one line. On any I/O error, do not advance state.
        let mut line = serde_json::to_vec(&rec).map_err(AuditError::from)?;
        line.push(b'\n');
        self.write_line(&mut inner, &line)
            .map_err(|e| AuditError::DurabilityFailed(e.to_string()))?;

        // Advance the chain.
        inner.prev_hash = rec.record_hash;
        inner.next_seq += 1;
        inner.records_in_segment += 1;
        inner.records_since_ckpt += 1;

        // Periodic (unsealed) checkpoint.
        if inner.records_since_ckpt >= self.cfg.checkpoint_every {
            self.write_checkpoint_locked(&inner, false)?;
            inner.records_since_ckpt = 0;
        }

        Ok(AuditReceipt {
            audit_id: rec.audit_id,
            global_sequence: rec.global_sequence,
            record_hash: rec.record_hash,
        })
    }

    fn write_line(&self, inner: &mut Inner, line: &[u8]) -> std::io::Result<()> {
        inner.file.write_all(line)?;
        inner.file.flush()?;
        if self.cfg.fsync {
            inner.file.sync_data()?;
        }
        Ok(())
    }

    /// Force an (unsealed) checkpoint over the current chain head.
    pub fn checkpoint(&self) -> Result<()> {
        let mut inner = self.inner.lock().unwrap();
        if inner.next_seq == 1 {
            return Ok(()); // nothing recorded yet
        }
        self.write_checkpoint_locked(&inner, false)?;
        inner.records_since_ckpt = 0;
        Ok(())
    }

    /// Force-seal the current segment and roll to a new one.
    pub fn seal(&self) -> Result<()> {
        let mut inner = self.inner.lock().unwrap();
        if inner.records_in_segment == 0 {
            return Ok(());
        }
        self.seal_locked(&mut inner)?;
        self.roll_locked(&mut inner)?;
        Ok(())
    }

    fn seal_locked(&self, inner: &mut Inner) -> Result<()> {
        if inner.records_in_segment == 0 {
            return Ok(());
        }
        self.write_checkpoint_locked(inner, true)?;
        inner.records_since_ckpt = 0;
        Ok(())
    }

    fn roll_locked(&self, inner: &mut Inner) -> Result<()> {
        // Open the new segment before mutating any writer state, so a failed open
        // (e.g. a read-only directory) leaves the ledger exactly as it was and the
        // append fails closed.
        let new_id = inner.segment_id + 1;
        let path = Self::segments_dir(&self.dir).join(segment_filename(new_id));
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        inner.segment_id = new_id;
        inner.records_in_segment = 0;
        inner.file = file;
        Ok(())
    }

    fn write_checkpoint_locked(&self, inner: &Inner, sealed: bool) -> Result<()> {
        let last_seq = inner.next_seq - 1;
        let cp = Checkpoint::create(
            self.signer.as_ref(),
            &self.cfg.node_id,
            inner.segment_id,
            last_seq,
            inner.prev_hash,
            inner.records_in_segment,
            sealed,
        );
        let path = Self::checkpoints_dir(&self.dir).join(checkpoint_filename(last_seq));
        let bytes = serde_json::to_vec_pretty(&cp)?;
        std::fs::write(&path, &bytes)?;
        if self.cfg.fsync {
            // Best-effort durability for the checkpoint file itself.
            if let Ok(f) = File::open(&path) {
                let _ = f.sync_all();
            }
        }
        Ok(())
    }

    /// The current chain head (sequence of the last record, or 0 if empty).
    pub fn head_sequence(&self) -> u64 {
        let inner = self.inner.lock().unwrap();
        inner.next_seq.saturating_sub(1)
    }

    /// The ledger root directory.
    pub fn dir(&self) -> &Path {
        &self.dir
    }
}

/// A random 128-bit audit id, hex-encoded.
fn random_id() -> Result<String> {
    let mut b = [0u8; 16];
    getrandom::getrandom(&mut b).map_err(|e| AuditError::Random(e.to_string()))?;
    Ok(hex::encode(b))
}