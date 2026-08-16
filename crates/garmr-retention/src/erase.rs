// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! Cold-archive rewriting for targeted erasure: thaw → filter → reseal.
//!
//! Cold archives are immutable by design, which is exactly why erasure cannot
//! leave them alone: an archive holding an erased subject preserves that
//! subject for the archive's whole life. The rewrite replaces the archive with
//! one built from the SAME rows minus the tombstone matches, records the
//! checksum transition in the manifest, and — on S3 deployments — replaces the
//! remote object.
//!
//! The failure-ordering rule mirrors expiry: nothing destructive happens to an
//! archive until its REPLACEMENT is durably in place. A crash mid-rewrite
//! leaves either the old archive (rewrite not yet installed) or the new one
//! (install completed); never neither.

use std::path::PathBuf;

use garmr_core::{ColdArchive, Error, Result, Tombstone};
use garmr_store::TombstoneMatcher;
use skade::arrow_array::{Array, RecordBatch, StringArray, TimestampMicrosecondArray};

use crate::archiver::kind_from_str;
use crate::S3Cold;

/// What happened to one archive during a rewrite pass.
#[derive(Debug, Clone, serde::Serialize)]
pub struct RewriteOutcome {
    pub id: String,
    /// Rows removed from this archive. Zero means the archive was scanned and
    /// contained no match — reported so "we checked" is distinguishable from
    /// "we skipped".
    pub rows_erased: u64,
    /// The checksum transition, `old -> new`. Equal when nothing matched (the
    /// archive was not rewritten — rewriting identical content would change
    /// nothing but the timestamp and forfeit idempotence).
    pub old_checksum: String,
    pub new_checksum: String,
    /// Whether the S3 object was replaced (None = no object store configured).
    pub remote_replaced: Option<bool>,
}

/// Rewrite every archive that overlaps a tombstone's window, removing matching
/// rows. Returns one outcome per overlapping archive. OFFLINE — same contract
/// as the rest of `garmr erase`.
///
/// Held archives are the caller's responsibility to refuse BEFORE calling (the
/// CLI refuses the whole erasure); this function double-checks and errors on a
/// held overlap rather than trusting the caller — two independent checks on an
/// irreversible path are cheaper than one incident.
pub async fn rewrite_archives(
    state: &garmr_store::StateStore,
    cold_dir: &std::path::Path,
    compression_level: i32,
    tombstones: &[Tombstone],
) -> Result<Vec<RewriteOutcome>> {
    let matcher = TombstoneMatcher::new(tombstones.to_vec());
    if matcher.is_empty() {
        return Ok(Vec::new());
    }
    let overlapping: Vec<ColdArchive> = state
        .list_cold_archives()?
        .into_iter()
        .filter(|a| {
            tombstones.iter().any(|t| {
                t.from_us.is_none_or(|f| a.end_us > f) && t.to_us.is_none_or(|u| a.start_us < u)
            })
        })
        .collect();
    if overlapping.is_empty() {
        return Ok(Vec::new());
    }
    if let Some(held) = overlapping.iter().find(|a| a.legal_hold) {
        return Err(Error::store(format!(
            "archive {} is under legal hold and overlaps the erasure — refusing",
            held.id
        )));
    }
    let s3 = S3Cold::from_env()?;

    let mut outcomes = Vec::with_capacity(overlapping.len());
    for arc in overlapping {
        outcomes.push(rewrite_one(state, cold_dir, compression_level, &matcher, &s3, arc).await?);
    }
    Ok(outcomes)
}

async fn rewrite_one(
    state: &garmr_store::StateStore,
    cold_dir: &std::path::Path,
    compression_level: i32,
    matcher: &TombstoneMatcher,
    s3: &Option<S3Cold>,
    arc: ColdArchive,
) -> Result<RewriteOutcome> {
    let archiver = crate::make_archiver(kind_from_str(&arc.kind)?, compression_level)?;
    let local = arc.path(cold_dir);

    // 1. Materialise the archive locally (S3 deployments drop the local copy at
    //    seal time), then verify its checksum BEFORE trusting its contents: a
    //    rewrite of tampered bytes would launder the tampering into a fresh,
    //    correctly-checksummed archive.
    let fetched_from_s3 = !local.exists();
    if fetched_from_s3 {
        let Some(s3) = s3 else {
            return Err(Error::store(format!(
                "archive {} is not on disk and no object store is configured — cannot rewrite",
                arc.id
            )));
        };
        s3.download(&arc.file, &local).await?;
    }
    let have = crate::blake3_file(&local)?;
    if have != arc.checksum {
        return Err(Error::store(format!(
            "archive {} fails its checksum ({} != manifest {}) — refusing to rewrite \
             unverified bytes",
            arc.id, have, arc.checksum
        )));
    }

    // 2. Thaw and filter.
    let parquet = archiver.thaw(&local)?;
    let (filtered, kept_rows, erased_rows) = filter_parquet(&parquet, matcher)?;
    if erased_rows == 0 {
        // Nothing matched: leave the archive byte-identical. If we fetched it
        // only to check, drop the local copy again to restore the disk state.
        if fetched_from_s3 {
            let _ = std::fs::remove_file(&local);
        }
        return Ok(RewriteOutcome {
            id: arc.id,
            rows_erased: 0,
            old_checksum: arc.checksum.clone(),
            new_checksum: arc.checksum,
            remote_replaced: Some(false).filter(|_| s3.is_some()),
        });
    }

    // 3. Reseal to a staging path, then install: replacement-before-destruction.
    let staging: PathBuf = cold_dir.join(format!(".rewrite-{}.tmp", arc.id));
    let outcome = archiver.seal(&staging, filtered)?;
    std::fs::rename(&staging, &local).map_err(Error::store)?;

    // 4. Replace the remote object BEFORE updating the manifest: while the
    //    manifest still names the old checksum, a crash here is detectable
    //    (checksum mismatch on next read) rather than silent.
    let remote_replaced = match s3 {
        None => None,
        Some(s3) => {
            s3.upload(&local, &arc.file).await?;
            if fetched_from_s3 {
                let _ = std::fs::remove_file(&local);
            }
            Some(true)
        }
    };

    // 5. Manifest last: the new row count and checksum become authoritative.
    let mut updated = arc.clone();
    updated.rows = kept_rows;
    updated.bytes_out = outcome.bytes_out;
    updated.checksum = outcome.checksum.clone();
    state.put_cold_archive(&updated)?;

    Ok(RewriteOutcome {
        id: arc.id,
        rows_erased: erased_rows,
        old_checksum: arc.checksum,
        new_checksum: outcome.checksum,
        remote_replaced,
    })
}

/// Read a parquet payload, drop matcher rows, and re-encode. Returns the new
/// payload plus (kept, erased) row counts.
fn filter_parquet(parquet: &[u8], matcher: &TombstoneMatcher) -> Result<(Vec<u8>, u64, u64)> {
    use skade::parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
    use skade::parquet::arrow::ArrowWriter;
    use skade::parquet::basic::{Compression, ZstdLevel};
    use skade::parquet::file::properties::WriterProperties;

    let reader = ParquetRecordBatchReaderBuilder::try_new(bytes::Bytes::copy_from_slice(parquet))
        .map_err(Error::store)?
        .build()
        .map_err(Error::store)?;

    let mut kept = 0u64;
    let mut erased = 0u64;
    let mut out_batches: Vec<RecordBatch> = Vec::new();
    let mut schema = None;
    for batch in reader {
        let batch = batch.map_err(Error::store)?;
        schema.get_or_insert_with(|| batch.schema());
        let ts = batch
            .column_by_name("event_ts")
            .and_then(|c| c.as_any().downcast_ref::<TimestampMicrosecondArray>());
        let host = batch
            .column_by_name("host")
            .and_then(|c| c.as_any().downcast_ref::<StringArray>());
        let fields = batch
            .column_by_name("fields")
            .and_then(|c| c.as_any().downcast_ref::<StringArray>());
        let keep: skade::arrow_array::BooleanArray = (0..batch.num_rows())
            .map(|i| {
                let Some(ts) = ts.filter(|t| !t.is_null(i)).map(|t| t.value(i)) else {
                    return Some(true); // no timestamp — never guess a deletion
                };
                let h = host
                    .filter(|h| !h.is_null(i))
                    .map(|h| h.value(i))
                    .unwrap_or("");
                let f = fields.filter(|f| !f.is_null(i)).map(|f| f.value(i));
                Some(!matcher.matches(h, f, ts))
            })
            .collect();
        let filtered = skade::datafusion::arrow::compute::filter_record_batch(&batch, &keep)
            .map_err(|e| Error::store(e.to_string()))?;
        erased += (batch.num_rows() - filtered.num_rows()) as u64;
        kept += filtered.num_rows() as u64;
        if filtered.num_rows() > 0 {
            out_batches.push(filtered);
        }
    }
    let Some(schema) = schema else {
        return Ok((parquet.to_vec(), 0, 0)); // empty archive — nothing to do
    };

    let props = WriterProperties::builder()
        .set_compression(Compression::ZSTD(
            ZstdLevel::try_new(3).map_err(Error::store)?,
        ))
        .build();
    let mut buf = Vec::new();
    {
        let mut w = ArrowWriter::try_new(&mut buf, schema, Some(props)).map_err(Error::store)?;
        for b in &out_batches {
            w.write(b).map_err(Error::store)?;
        }
        w.close().map_err(Error::store)?;
    }
    Ok((buf, kept, erased))
}
