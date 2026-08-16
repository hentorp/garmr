// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! The retention pass: roll aged event windows out of the hot lakehouse into
//! the cold tier.
//!
//! One pass finds the **non-empty** `window_days`-sized `[start, end)` windows
//! of `event_ts` older than the cutoff (`now - retention_days`) and past the
//! watermark — one bucket query, so a sparse or very old history doesn't cost
//! one scan per empty window — then seals each into a cold archive and records
//! it in the manifest. The monotonic watermark advances past every sealed
//! window (and finally to the archive horizon), so a window is sealed exactly
//! once and re-running is a no-op — safe to call on a timer. If the process
//! dies mid-pass, the next pass re-seals at most the one window whose watermark
//! commit didn't land (the archive file and manifest entry are overwritten in
//! place — idempotent).
//!
//! The CPU-heavy part (parquet encode + compress + checksum) runs on the
//! blocking pool, not the async runtime, so a retention pass never stalls
//! ingest/triage under `serve`. A window is sealed BY STREAMING: an ordered
//! scan is piped batch-by-batch (through a small bounded channel) into a
//! parquet writer that spills straight to a staging file, so even a dense
//! firehose day (millions of rows, multi-GB of Arrow) never materialises in
//! RAM — peak memory is a handful of in-flight batches, independent of window
//! size. (This replaced a whole-window-in-RAM seal that OOM-thrashed a busy
//! `serve` at startup once the hot table held a migrated multi-month backlog.)
//!
//! Hot-store pruning is NOT done here: the seal only delivers the durable,
//! queryable cold copy (the Splunk *frozen→thawed* half), and archived rows
//! remain hot at seal time (`ColdArchive.hot_pruned = false`). Reclaiming hot
//! space happens later, at the store's compaction rebuild, which drops rows
//! whose `event_ts` falls inside a window this manifest records as sealed (see
//! `garmr-store::events::sealed_prune_hook` — the rebuild is the one safe
//! moment to shrink the hot table). Late-arriving events below the watermark
//! are not back-archived — real log streams are near-ordered — and because
//! pruning keys on sealed-window MEMBERSHIP, such rows stay hot forever rather
//! than being destroyed (an epoch-clock device's stream survives). The one
//! documented loss class: a row arriving >retention_days late into a window
//! that was already sealed is pruned without being in that archive — i.e.
//! re-imported history of an archived period should be re-sealed or thawed,
//! not replayed into hot ingest.

use std::sync::Arc;

use chrono::{DateTime, Duration, Utc};
use futures::StreamExt;
use garmr_core::{ColdArchive, Config, Error, Result};
use garmr_store::Store;
use skade::arrow_array::{Array, Int64Array, RecordBatch};
use skade::parquet::arrow::ArrowWriter;
use skade::parquet::basic::{Compression, ZstdLevel};
use skade::parquet::file::properties::WriterProperties;

use crate::archiver::{kind_str, make_archiver, ColdArchiver};

const MICROS_PER_DAY: i64 = 86_400_000_000;

/// What a retention pass did.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct RetentionRun {
    /// Windows newly sealed this pass.
    pub windows: u64,
    /// Rows sealed this pass.
    pub rows: u64,
    /// Archive bytes written this pass.
    pub bytes_out: u64,
    /// Watermark (`event_ts` micros) after the pass.
    pub watermark_us: Option<i64>,
}

/// Seals aged windows into the cold tier.
pub struct RetentionManager {
    store: Store,
    cold_dir: std::path::PathBuf,
    archiver: Arc<dyn ColdArchiver>,
    window_us: i64,
    retention_days: i64,
    /// zstd level for the parquet payload (clamped to parquet's 1..=22).
    parquet_level: i32,
    /// Sources excluded from sealing (`[[retention.class]]`): their rows never
    /// enter an archive, so class pruning of the hot copy is the end of them.
    excluded_sources: Vec<String>,
    /// Optional S3 cold tier (from GARMR_S3_* env). `None` = local-only cold.
    s3: Option<crate::s3::S3Cold>,
}

impl RetentionManager {
    /// Build from config. Errors if the configured archiver isn't compiled in
    /// or `window_days` overflows the microsecond math.
    pub fn new(store: Store, cfg: &Config) -> Result<Self> {
        let archiver: Arc<dyn ColdArchiver> =
            make_archiver(cfg.retention.archiver, cfg.retention.compression_level)?.into();
        let window_us = (cfg.retention.window_days.max(1) as i64)
            .checked_mul(MICROS_PER_DAY)
            .ok_or_else(|| Error::Config("retention.window_days is absurdly large".into()))?;
        Ok(Self {
            store,
            cold_dir: cfg.retention.cold_dir.clone(),
            excluded_sources: cfg
                .retention
                .class
                .iter()
                .map(|c| c.source.clone())
                .collect(),
            archiver,
            window_us,
            retention_days: cfg.store.retention_days as i64,
            parquet_level: cfg.retention.compression_level.clamp(1, 22),
            s3: crate::s3::S3Cold::from_env()?,
        })
    }

    /// Run one retention pass as of `now`.
    pub async fn run_once(&self, now: DateTime<Utc>) -> Result<RetentionRun> {
        std::fs::create_dir_all(&self.cold_dir).map_err(Error::store)?;

        let cutoff_us = (now - Duration::days(self.retention_days)).timestamp_micros();
        // Only whole windows strictly before this horizon are archived.
        let horizon_us = floor_to(cutoff_us, self.window_us);
        let watermark = self.store.state.cold_watermark_us()?;

        let mut run = RetentionRun {
            watermark_us: watermark,
            ..Default::default()
        };
        if watermark.is_some_and(|w| w >= horizon_us) {
            return Ok(run); // nothing has aged past the horizon since last pass
        }

        for bucket in self.nonempty_buckets(watermark, horizon_us).await? {
            let (Some(w), Some(end)) = (
                bucket.checked_mul(self.window_us),
                (bucket + 1).checked_mul(self.window_us),
            ) else {
                tracing::warn!(bucket, "skipping window with out-of-range timestamp");
                continue;
            };
            let (rows, bytes_out) = self.seal_window(w, end, now).await?;
            if rows > 0 {
                run.windows += 1;
                run.rows += rows;
                run.bytes_out += bytes_out;
            }
            self.store.state.set_cold_watermark_us(end)?;
            run.watermark_us = Some(end);
        }
        // Advance to the horizon even when the tail windows were empty, so the
        // next pass starts from here instead of rescanning.
        self.store.state.set_cold_watermark_us(horizon_us)?;
        run.watermark_us = run
            .watermark_us
            .map(|w| w.max(horizon_us))
            .or(Some(horizon_us));
        Ok(run)
    }

    /// The distinct non-empty window buckets (`event_ts_micros / window_us`) in
    /// `[watermark, horizon)`, ascending — ONE query regardless of how many
    /// empty windows the span contains (an epoch-0 stray or a long-idle store
    /// costs nothing extra). Assumes post-epoch timestamps (integer division
    /// truncates toward zero, which equals floor for non-negatives).
    async fn nonempty_buckets(&self, watermark: Option<i64>, horizon_us: i64) -> Result<Vec<i64>> {
        let lower = watermark
            .map(|w| format!("event_ts >= {} AND ", ts_literal(w)))
            .unwrap_or_default();
        let sql = format!(
            "SELECT DISTINCT CAST(event_ts AS BIGINT) / {w} AS bucket FROM events \
             WHERE {lower}event_ts < {hi} ORDER BY bucket",
            w = self.window_us,
            hi = ts_literal(horizon_us),
        );
        let batches = self.store.events.sql(&sql).await?;
        let mut buckets = Vec::new();
        for b in &batches {
            let col = b
                .column(0)
                .as_any()
                .downcast_ref::<Int64Array>()
                .ok_or_else(|| Error::store("bucket query returned a non-int64 column"))?;
            for i in 0..col.len() {
                if !col.is_null(i) {
                    buckets.push(col.value(i));
                }
            }
        }
        Ok(buckets)
    }

    /// Stream one window out of the hot store and seal it into the cold tier
    /// with BOUNDED memory. An ordered scan is piped batch-by-batch (through a
    /// small bounded channel) into a parquet writer on the blocking pool that
    /// spills straight to a staging file — so a dense firehose day (millions of
    /// rows, multi-GB of Arrow) never materialises in RAM. The staged parquet
    /// is then archived (checksum + optional S3 upload) and recorded in the
    /// manifest. Returns `(rows, archive bytes on disk)`; `rows == 0` is an
    /// empty window (nothing sealed).
    async fn seal_window(
        &self,
        start_us: i64,
        end_us: i64,
        now: DateTime<Utc>,
    ) -> Result<(u64, u64)> {
        // No ORDER BY: a sort is a pipeline breaker — DataFusion's SortExec
        // buffers the WHOLE window in RAM before emitting, which would defeat the
        // streaming seal and re-OOM on a multi-GB window (the very bug this
        // fixes). The archive doesn't need sorted rows: ColdQuery applies its own
        // ORDER BY on read. Keep it unordered so execute_stream truly streams.
        // Class-excluded sources are filtered at the SEAL, not merely pruned
        // later: an archive is immutable and outlives every policy change, so a
        // class row sealed by mistake would sit in cold storage for the archive's
        // whole life — the exact opposite of what the class asked for. Values are
        // single-quoted with `'` doubled; they come from configuration, but an
        // unescaped quote would still let a source name reshape the predicate.
        let excl = if self.excluded_sources.is_empty() {
            String::new()
        } else {
            let list: Vec<String> = self
                .excluded_sources
                .iter()
                .map(|s| format!("'{}'", s.replace('\'', "''")))
                .collect();
            format!(" AND source NOT IN ({})", list.join(", "))
        };
        let sql = format!(
            "SELECT event_ts, host, service, source, environment, severity, log_type, message, \
             fields FROM events WHERE event_ts >= {lo} AND event_ts < {hi}{excl}",
            lo = ts_literal(start_us),
            hi = ts_literal(end_us),
        );
        let mut stream = self.store.events.sql_stream(sql).await?;
        let schema = stream.schema();

        let id = window_id(start_us);
        let staging = self.cold_dir.join(format!(".staging-{id}.parquet"));
        let level = self.parquet_level;

        // Blocking parquet writer: owns the ArrowWriter over the staging file
        // and encodes+compresses each batch as it arrives — off the async
        // runtime. A bounded channel caps how many batches are in flight (the
        // memory bound): async `send().await` yields (never blocks the runtime),
        // the writer pulls with `blocking_recv`. The raw window is never fully
        // resident.
        let (tx, mut rx) = tokio::sync::mpsc::channel::<RecordBatch>(4);
        let staging_w = staging.clone();
        let writer = tokio::task::spawn_blocking(move || -> Result<u64> {
            let props = WriterProperties::builder()
                .set_compression(Compression::ZSTD(
                    ZstdLevel::try_new(level.clamp(1, 22)).map_err(Error::store)?,
                ))
                .build();
            let file = std::fs::File::create(&staging_w).map_err(Error::store)?;
            let mut w = ArrowWriter::try_new(file, schema, Some(props)).map_err(Error::store)?;
            let mut rows = 0u64;
            while let Some(batch) = rx.blocking_recv() {
                rows += batch.num_rows() as u64;
                w.write(&batch).map_err(Error::store)?;
            }
            w.close().map_err(Error::store)?;
            Ok(rows)
        });

        // Pump the async scan into the blocking writer.
        let mut scan_err = None;
        while let Some(item) = stream.next().await {
            match item {
                Ok(batch) => {
                    if tx.send(batch).await.is_err() {
                        break; // writer task died; its error surfaces below
                    }
                }
                Err(e) => {
                    scan_err = Some(Error::store(e.to_string()));
                    break;
                }
            }
        }
        drop(tx); // close the channel so the writer finishes and closes the file
        let rows = writer
            .await
            .map_err(|e| Error::store(format!("seal writer panicked: {e}")))??;

        if let Some(e) = scan_err {
            let _ = std::fs::remove_file(&staging);
            return Err(e);
        }
        if rows == 0 {
            let _ = std::fs::remove_file(&staging); // empty window: nothing to seal
            return Ok((0, 0));
        }

        // On-disk parquet size (the archiver's input); for a file-is-the-archive
        // backend this equals the final archive size.
        let bytes_in = std::fs::metadata(&staging).map_err(Error::store)?.len();

        // Archive the staged parquet. `seal_file` lets a plain backend rename it
        // into place (no second full copy in RAM); znippy reads the compressed
        // parquet (much smaller than the raw window) and wraps it.
        let file = format!("{id}.{}", self.archiver.extension());
        let out = self.cold_dir.join(&file);
        let archiver = Arc::clone(&self.archiver);
        let staging_a = staging.clone();
        let out_a = out.clone();
        let outcome = tokio::task::spawn_blocking(move || archiver.seal_file(&out_a, &staging_a))
            .await
            .map_err(|e| Error::store(format!("archive task panicked: {e}")))??;
        let _ = std::fs::remove_file(&staging); // no-op if seal_file renamed it away

        let arc = ColdArchive {
            id: id.clone(),
            kind: kind_str(self.archiver.kind()).to_string(),
            file,
            start_us,
            end_us,
            rows,
            bytes_in,
            bytes_out: outcome.bytes_out,
            checksum: outcome.checksum,
            hot_pruned: false,
            sealed_at: now,
            legal_hold: false,
        };
        let bytes_out = arc.bytes_out;
        self.store.state.put_cold_archive(&arc)?;
        // S3 cold tier: upload the sealed archive to object storage, then drop
        // the local copy to reclaim disk (ColdQuery fetches it back on read). The
        // manifest row is written first, so a crash between the two leaves a
        // recoverable state (re-seal overwrites; a missing object surfaces on
        // read, not silently). Local-only when S3 is unconfigured.
        if let Some(s3) = &self.s3 {
            let local = self.cold_dir.join(&arc.file);
            s3.upload(&local, &arc.file).await?;
            let _ = tokio::fs::remove_file(&local).await;
            tracing::debug!(key = %arc.file, "cold archive uploaded to S3; local copy dropped");
        }
        tracing::info!(
            window = %id,
            rows,
            bytes_in,
            bytes_out,
            kind = %arc.kind,
            "sealed cold window (streamed)"
        );
        Ok((rows, bytes_out))
    }
}

/// Floor `us` down to a multiple of `window_us` (window boundary). Assumes
/// positive timestamps (all real `event_ts` are post-epoch).
fn floor_to(us: i64, window_us: i64) -> i64 {
    (us / window_us) * window_us
}

/// A DataFusion timestamp literal for a micros value, e.g.
/// `TIMESTAMP '2026-04-08T00:00:00.000000'`. Comparing the `Timestamp(us)`
/// column against this coerces cleanly (no fragile int/timestamp cast).
pub fn ts_literal(us: i64) -> String {
    let dt = DateTime::from_timestamp_micros(us).unwrap_or(DateTime::UNIX_EPOCH);
    format!("TIMESTAMP '{}'", dt.format("%Y-%m-%dT%H:%M:%S%.6f"))
}

/// Stable window key: the UTC date of the window start. Unique per window (any
/// two window starts differ by at least one day).
fn window_id(start_us: i64) -> String {
    DateTime::from_timestamp_micros(start_us)
        .unwrap_or(DateTime::UNIX_EPOCH)
        .format("%Y-%m-%d")
        .to_string()
}
