// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! Querying the cold tier: the Splunk *thaw* half.
//!
//! Given a time range, find the cold archives whose window overlaps it, verify
//! each archive's BLAKE3 checksum against the manifest, thaw the parquet
//! payloads into a scratch directory, register that directory as the `events`
//! table in a throwaway DataFusion session, and run the caller's SQL over it.
//! The scratch directory is removed when the query returns; stale scratch dirs
//! orphaned by a crash are swept on the next query.
//!
//! Verification + decompression are CPU/IO-bound and run on the blocking pool
//! so a cold query on the daemon never stalls the async runtime. A checksum
//! mismatch is a hard error naming the archive — better a failed hunt than
//! silently querying corrupted history.
//!
//! The SQL is executed as given (the same contract as the hot `events.sql`
//! lane): the caller is responsible for read-only enforcement. The CLI
//! `cold-query` command and the daemon's `/api/cold-query` both apply the AST
//! guard before calling in.

use std::path::{Path, PathBuf};

use garmr_core::{Config, Error, Result};
use garmr_store::Store;
use skade::arrow_array::RecordBatch;
use skade::datafusion::prelude::{ParquetReadOptions, SessionContext};

use crate::archiver::{blake3_file, kind_from_str, make_archiver};

/// An unbounded (no `--from`/`--to`) query refuses to thaw more than this many
/// parquet bytes at once — a full-history query over years of archives would
/// otherwise silently duplicate the whole cold tier onto scratch disk. A
/// bounded query proceeds regardless: the operator named the range.
const UNBOUNDED_THAW_BUDGET: u64 = 4 * 1024 * 1024 * 1024;

/// Scratch dirs older than this are considered orphaned by a crash and swept.
const STALE_SCRATCH_SECS: u64 = 24 * 3600;

/// What a cold query touched and returned.
#[derive(Debug)]
pub struct ColdQueryResult {
    /// Cold archives overlapping the range (0 = the range hit no archive —
    /// distinct from a query that matched no rows).
    pub archives: usize,
    pub batches: Vec<RecordBatch>,
}

/// Reads the cold tier.
pub struct ColdQuery {
    store: Store,
    cold_dir: PathBuf,
    /// Optional S3 cold tier (from GARMR_S3_* env). When set, archives whose
    /// local copy was dropped after upload are fetched back on demand.
    s3: Option<crate::s3::S3Cold>,
}

impl ColdQuery {
    pub fn new(store: Store, cfg: &Config) -> Self {
        // S3 cold tier (optional). A build error (e.g. a bad endpoint) degrades
        // to local-only cold rather than failing construction — logged loudly.
        let s3 = match crate::s3::S3Cold::from_env() {
            Ok(s) => s,
            Err(e) => {
                tracing::error!(error = %e, "cold-query: S3 backend init failed; reading local cold only");
                None
            }
        };
        Self {
            store,
            cold_dir: cfg.retention.cold_dir.clone(),
            s3,
        }
    }

    /// Run `sql` over the cold archives overlapping `[from_us, to_us)` (either
    /// bound `None` = unbounded). The archives are exposed as the table
    /// `events`.
    pub async fn query(
        &self,
        sql: &str,
        from_us: Option<i64>,
        to_us: Option<i64>,
    ) -> Result<ColdQueryResult> {
        let arcs = self.store.state.cold_archives_overlapping(from_us, to_us)?;
        if arcs.is_empty() {
            return Ok(ColdQueryResult {
                archives: 0,
                batches: vec![],
            });
        }
        if from_us.is_none() && to_us.is_none() {
            let total: u64 = arcs.iter().map(|a| a.bytes_in).sum();
            if total > UNBOUNDED_THAW_BUDGET {
                return Err(Error::store(format!(
                    "unbounded cold query would thaw {} archives (~{} MB) to scratch disk — \
                     narrow it with --from/--to",
                    arcs.len(),
                    total / (1024 * 1024),
                )));
            }
        }

        sweep_stale_scratch(&self.cold_dir);
        let thaw_dir = self
            .cold_dir
            .join(format!(".thaw-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&thaw_dir).map_err(Error::store)?;
        let _guard = ScratchDir(thaw_dir.clone());

        // S3 cold tier: sealed archives live in object storage (the local copy was
        // dropped after upload), so fetch any that aren't present locally back to
        // cold_dir first. The existing checksum-verify + thaw loop below is then
        // unchanged — the S3 layer only restores bytes, it never trusts them.
        if let Some(s3) = &self.s3 {
            for a in &arcs {
                let path = a.path(&self.cold_dir);
                if !path.exists() {
                    s3.download(&a.file, &path).await?;
                }
            }
        }

        // Verify + thaw on the blocking pool (BLAKE3 over the file + decompress).
        {
            let arcs = arcs.clone();
            let cold_dir = self.cold_dir.clone();
            let thaw_dir = thaw_dir.clone();
            tokio::task::spawn_blocking(move || {
                for (i, a) in arcs.iter().enumerate() {
                    let path = a.path(&cold_dir);
                    let actual = blake3_file(&path)?;
                    if actual != a.checksum {
                        return Err(Error::store(format!(
                            "cold archive {} failed its integrity check (checksum mismatch) — \
                             refusing to query it",
                            path.display(),
                        )));
                    }
                    let archiver = make_archiver(kind_from_str(&a.kind)?, 0)?;
                    let bytes = archiver.thaw(&path)?;
                    std::fs::write(thaw_dir.join(format!("part-{i:05}.parquet")), &bytes)
                        .map_err(Error::store)?;
                }
                Ok::<_, Error>(())
            })
            .await
            .map_err(|e| Error::store(format!("thaw task panicked: {e}")))??;
        }

        let ctx = SessionContext::new();
        let path = thaw_dir
            .to_str()
            .ok_or_else(|| Error::store("non-UTF-8 cold_dir path"))?;
        ctx.register_parquet("events", path, ParquetReadOptions::default())
            .await
            .map_err(Error::store)?;
        let df = ctx.sql(sql).await.map_err(Error::store)?;
        let batches = df.collect().await.map_err(Error::store)?;
        Ok(ColdQueryResult {
            archives: arcs.len(),
            batches,
        })
    }
}

/// Removes a scratch directory (best-effort) when dropped.
struct ScratchDir(PathBuf);

impl Drop for ScratchDir {
    fn drop(&mut self) {
        remove_dir_all_quiet(&self.0);
    }
}

fn remove_dir_all_quiet(p: &Path) {
    if let Err(e) = std::fs::remove_dir_all(p) {
        if e.kind() != std::io::ErrorKind::NotFound {
            tracing::warn!(path = %p.display(), error = %e, "failed to remove cold thaw scratch dir");
        }
    }
}

/// Best-effort removal of `.thaw-*` dirs left behind by a crashed/killed query.
/// Only sweeps dirs untouched for [`STALE_SCRATCH_SECS`], so a concurrent
/// query's live scratch is never removed.
fn sweep_stale_scratch(cold_dir: &Path) {
    let Ok(entries) = std::fs::read_dir(cold_dir) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        if !name.to_string_lossy().starts_with(".thaw-") {
            continue;
        }
        let stale = entry
            .metadata()
            .and_then(|m| m.modified())
            .ok()
            .and_then(|t| t.elapsed().ok())
            .is_some_and(|age| age.as_secs() > STALE_SCRATCH_SECS);
        if stale {
            tracing::info!(dir = %entry.path().display(), "sweeping stale cold-query scratch dir");
            remove_dir_all_quiet(&entry.path());
        }
    }
}
