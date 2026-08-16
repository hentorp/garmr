// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! `garmr pgaudit-ship` — a durable PostgreSQL / pgAudit collector.
//!
//! Follows the newest pgAudit **csvlog**, reassembles multiline CSV records (a
//! record starts at a `YYYY-MM-DD HH:MM:SS` timestamped line), and ships the rows
//! containing `AUDIT:` to garmr's **native** ingest (`/ingest/v1/events`) with a
//! collector bearer token and per-batch **sequence headers** (`X-Garmr-Seq` /
//! `X-Garmr-Epoch`) so the receiver's gap detection works.
//!
//! Every record goes through a **bounded disk spool** first and is removed only
//! after a confirmed 2xx, so a receiver outage or a collector crash never drops an
//! audit record (at-least-once; the server's sequence tracking + idempotent event
//! ids handle any duplicate on a crash-after-deliver-before-commit). Delivery is
//! retried with a capped exponential backoff. This replaces the fire-and-forget
//! `scripts/garmr-pgaudit-ship.py` (which used the unauthenticated Loki path and
//! dropped records on any failure).

use std::collections::VecDeque;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result};

use crate::cli::Cli;

/// A pgAudit csvlog record begins at a `YYYY-MM-DD HH:MM:SS` timestamp.
fn is_stamp(line: &str) -> bool {
    let b = line.as_bytes();
    if b.len() < 19 {
        return false;
    }
    let d = |i: usize| b[i].is_ascii_digit();
    d(0) && d(1)
        && d(2)
        && d(3)
        && b[4] == b'-'
        && d(5)
        && d(6)
        && b[7] == b'-'
        && d(8)
        && d(9)
        && b[10] == b' '
        && d(11)
        && d(12)
        && b[13] == b':'
        && d(14)
        && d(15)
        && b[16] == b':'
        && d(17)
        && d(18)
}

/// A shipped record is a pgAudit row (contains `AUDIT:`).
fn is_audit(record: &str) -> bool {
    record.contains("AUDIT:")
}

/// Split accumulated csvlog text into COMPLETE records + the trailing partial (the
/// last record, still open because no following stamped line has arrived yet). A
/// record spans one stamped line up to — but not including — the next stamped line.
/// The caller carries the partial into the next read; on EOF/`--once` it flushes it.
fn reassemble(text: &str) -> (Vec<String>, String) {
    let mut records = Vec::new();
    let mut cur = String::new();
    for line in text.split_inclusive('\n') {
        if is_stamp(line) && !cur.is_empty() {
            records.push(cur.trim_end_matches(['\n', '\r']).to_string());
            cur.clear();
        }
        cur.push_str(line);
    }
    (records, cur)
}

/// Capped exponential backoff: `base * 2^attempt`, clamped to `cap` (ms).
fn backoff_ms(attempt: u32, base_ms: u64, cap_ms: u64) -> u64 {
    base_ms.saturating_mul(1u64 << attempt.min(20)).min(cap_ms)
}

// ---- durable spool --------------------------------------------------------
// frame: [u32 len][utf8 bytes]. The file holds ONLY undelivered records; `commit`
// rewrites it from what remains, so it stays bounded.

fn write_frame(buf: &mut Vec<u8>, rec: &str) {
    let b = rec.as_bytes();
    buf.extend_from_slice(&(b.len() as u32).to_le_bytes());
    buf.extend_from_slice(b);
}

fn decode_frames(bytes: &[u8]) -> VecDeque<String> {
    let mut out = VecDeque::new();
    let mut c = std::io::Cursor::new(bytes);
    loop {
        let mut lb = [0u8; 4];
        let mut got = 0;
        while got < 4 {
            match c.read(&mut lb[got..]) {
                Ok(0) => break,
                Ok(n) => got += n,
                Err(_) => return out,
            }
        }
        if got == 0 {
            break; // clean EOF
        }
        if got < 4 {
            break; // truncated tail
        }
        let len = u32::from_le_bytes(lb) as usize;
        let remaining = (c.get_ref().len() as u64).saturating_sub(c.position()) as usize;
        if len > remaining {
            break; // truncated tail — keep what we have
        }
        let mut b = vec![0u8; len];
        if c.read_exact(&mut b).is_err() {
            break;
        }
        out.push_back(String::from_utf8_lossy(&b).into_owned());
    }
    out
}

/// A crash-safe, bounded disk spool of undelivered records.
pub struct Spool {
    path: PathBuf,
    unsent: VecDeque<String>,
}

impl Spool {
    /// Open the spool, reloading any records left undelivered from a prior run.
    pub fn open(path: impl Into<PathBuf>) -> Result<Self> {
        let path = path.into();
        let unsent = if path.exists() {
            decode_frames(&std::fs::read(&path).context("read spool")?)
        } else {
            VecDeque::new()
        };
        Ok(Self { path, unsent })
    }

    pub fn len(&self) -> usize {
        self.unsent.len()
    }
    pub fn is_empty(&self) -> bool {
        self.unsent.is_empty()
    }

    /// Durably append a record (fsync) then mirror it in memory. A crash after this
    /// but before delivery leaves the record on disk → re-sent on the next open.
    pub fn append(&mut self, record: String) -> Result<()> {
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .context("open spool for append")?;
        let mut frame = Vec::new();
        write_frame(&mut frame, &record);
        f.write_all(&frame).context("append spool frame")?;
        f.sync_all().ok();
        self.unsent.push_back(record);
        Ok(())
    }

    /// The next up-to-`n` undelivered records (borrowed; delivered via `commit`).
    pub fn peek(&self, n: usize) -> Vec<&str> {
        self.unsent.iter().take(n).map(String::as_str).collect()
    }

    /// Mark the first `n` records delivered: drop them and rewrite the file from
    /// what remains, so the on-disk spool never grows past the undelivered backlog.
    pub fn commit(&mut self, n: usize) -> Result<()> {
        for _ in 0..n.min(self.unsent.len()) {
            self.unsent.pop_front();
        }
        self.rewrite()
    }

    fn rewrite(&self) -> Result<()> {
        if self.unsent.is_empty() {
            // Fully drained → remove the file (compaction to nothing).
            let _ = std::fs::remove_file(&self.path);
            return Ok(());
        }
        let mut buf = Vec::new();
        for r in &self.unsent {
            write_frame(&mut buf, r);
        }
        let tmp = self.path.with_extension("tmp");
        {
            let mut f = std::fs::File::create(&tmp).context("create spool tmp")?;
            f.write_all(&buf).context("write spool tmp")?;
            f.sync_all().ok();
        }
        std::fs::rename(&tmp, &self.path).context("rename spool")?;
        if let Some(parent) = self.path.parent() {
            if let Ok(d) = std::fs::File::open(parent) {
                d.sync_all().ok();
            }
        }
        Ok(())
    }
}

// ---- shipping loop (I/O glue) ---------------------------------------------

/// Runtime config, from env with sane defaults (see the packaging doc).
struct Config {
    ingest_url: String,
    token: Option<String>,
    logdir: PathBuf,
    host_label: String,
    environment: String,
    spool_path: PathBuf,
    batch: usize,
    poll: Duration,
}

impl Config {
    fn from_env() -> Self {
        let env = |k: &str, d: &str| std::env::var(k).unwrap_or_else(|_| d.to_string());
        Config {
            ingest_url: env(
                "GARMR_INGEST_URL",
                "http://127.0.0.1:3100/ingest/v1/events",
            ),
            token: std::env::var("GARMR_COLLECTOR_TOKEN")
                .ok()
                .filter(|s| !s.trim().is_empty()),
            logdir: PathBuf::from(env("PG_LOGDIR", "/var/lib/postgresql/17/main/log")),
            host_label: env("PG_HOST_LABEL", "postgres"),
            environment: env("PG_ENVIRONMENT", "prod"),
            spool_path: PathBuf::from(env("GARMR_SPOOL", "/var/lib/garmr/pgaudit.spool")),
            batch: env("GARMR_BATCH", "500").parse().unwrap_or(500).max(1),
            poll: Duration::from_millis(
                env("GARMR_POLL_MS", "1000").parse().unwrap_or(1000).max(50),
            ),
        }
    }
}

/// The newest `*.csv` in `dir` by mtime, if any.
fn newest_csv(dir: &Path) -> Option<PathBuf> {
    let mut best: Option<(std::time::SystemTime, PathBuf)> = None;
    for e in std::fs::read_dir(dir).ok()?.flatten() {
        let p = e.path();
        if p.extension().and_then(|x| x.to_str()) != Some("csv") {
            continue;
        }
        let m = e.metadata().ok().and_then(|m| m.modified().ok());
        if let Some(m) = m {
            if best.as_ref().is_none_or(|(bm, _)| m > *bm) {
                best = Some((m, p));
            }
        }
    }
    best.map(|(_, p)| p)
}

/// One shipped event, serialized to a native `WireEvent`.
fn wire_event(cfg: &Config, message: &str) -> serde_json::Value {
    serde_json::json!({
        "message": message,
        "host": cfg.host_label,
        "service": "postgres",
        "source": "postgres-csvlog",
        "log_type": "audit",
        "environment": cfg.environment,
        "severity": "info",
    })
}

/// Ship one batch, retrying with capped backoff until it succeeds (or, for
/// `--once`, a bounded number of attempts). Returns `Ok(())` only on a 2xx.
async fn ship_batch(
    client: &reqwest::Client,
    cfg: &Config,
    records: &[&str],
    epoch: u64,
    seq: u64,
    max_attempts: Option<u32>,
) -> Result<()> {
    let body: Vec<serde_json::Value> = records.iter().map(|r| wire_event(cfg, r)).collect();
    let mut attempt = 0u32;
    loop {
        let mut req = client
            .post(&cfg.ingest_url)
            .json(&body)
            .header("X-Garmr-Seq", seq.to_string())
            .header("X-Garmr-Epoch", epoch.to_string());
        if let Some(tok) = &cfg.token {
            req = req.bearer_auth(tok);
        }
        match req.send().await {
            Ok(resp) if resp.status().is_success() => return Ok(()),
            Ok(resp) => {
                tracing::warn!(status = %resp.status(), attempt, "pgaudit: ingest rejected batch");
            }
            Err(e) => tracing::warn!(error = %e, attempt, "pgaudit: ingest POST failed"),
        }
        attempt += 1;
        if let Some(max) = max_attempts {
            if attempt >= max {
                anyhow::bail!("batch delivery failed after {max} attempts");
            }
        }
        tokio::time::sleep(Duration::from_millis(backoff_ms(attempt, 500, 30_000))).await;
    }
}

/// Drain the spool: ship pending batches, committing each after a confirmed 2xx.
/// `seq` advances per delivered batch (the receiver's gap detector reads it).
async fn drain(
    client: &reqwest::Client,
    cfg: &Config,
    spool: &mut Spool,
    epoch: u64,
    seq: &mut u64,
    max_attempts: Option<u32>,
) -> Result<()> {
    while !spool.is_empty() {
        let batch: Vec<String> = spool
            .peek(cfg.batch)
            .into_iter()
            .map(str::to_string)
            .collect();
        let refs: Vec<&str> = batch.iter().map(String::as_str).collect();
        ship_batch(client, cfg, &refs, epoch, *seq, max_attempts).await?;
        spool.commit(batch.len())?;
        *seq += 1;
    }
    Ok(())
}

/// `garmr pgaudit-ship` — follow the pgAudit csvlog and ship audit records
/// durably. `--once` catches up the existing tail and exits.
pub(crate) async fn pgaudit_ship(_cli: &Cli, once: bool) -> Result<()> {
    let cfg = Config::from_env();
    if let Some(parent) = cfg.spool_path.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    let mut spool = Spool::open(&cfg.spool_path)?;
    if cfg.token.is_none() {
        tracing::warn!("pgaudit: GARMR_COLLECTOR_TOKEN unset — shipping UNAUTHENTICATED (no server-side sequence tracking)");
    }
    tracing::info!(
        url = %cfg.ingest_url, logdir = %cfg.logdir.display(), spool = %cfg.spool_path.display(),
        backlog = spool.len(), "pgaudit collector starting"
    );
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        // Refuse redirects: the configured ingest URL is egress-checked once; a 3xx
        // to another host would ship audit bytes to an un-vetted destination.
        .redirect(reqwest::redirect::Policy::none())
        .build()?;
    // A monotonic-ish epoch: process start (whole seconds). A restart bumps it, so
    // the receiver sees a new (epoch, seq) lineage rather than a seq regression.
    let epoch = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let mut seq: u64 = 0;

    // First, flush any backlog from a prior run.
    let max_attempts = if once { Some(8) } else { None };
    drain(&client, &cfg, &mut spool, epoch, &mut seq, max_attempts).await?;

    let mut cur_file: Option<PathBuf> = None;
    let mut offset: u64 = 0;
    let mut partial = String::new();
    loop {
        let newest = newest_csv(&cfg.logdir);
        // Rotation: a new newest file → start it from the top.
        if newest != cur_file {
            cur_file = newest.clone();
            offset = 0;
            partial.clear();
        }
        if let Some(path) = &cur_file {
            let (text, new_off) = read_from(path, offset)?;
            offset = new_off;
            if !text.is_empty() {
                // `+ text.as_str()`, not `+ &text`. `String + &String` normally works by
                // coercing `&String` to `&str`, but `smartstring` — pulled in under some
                // feature combinations of this workspace — contributes competing `Add`
                // impls, and the coercion then stops applying: `no implementation for
                // String + &String`. Naming `&str` explicitly is unambiguous under every
                // feature set. Found by the 2026-08-01 fleet compile sweep, which could
                // not reach this repo at all until its missing Git-LFS objects were
                // restored.
                let combined = std::mem::take(&mut partial) + text.as_str();
                let (records, rest) = reassemble(&combined);
                partial = rest;
                for r in records {
                    if is_audit(&r) {
                        spool.append(r)?;
                    }
                }
            }
        }
        // On --once, flush the trailing partial (EOF means the last record is done).
        if once && !partial.is_empty() {
            let r = std::mem::take(&mut partial);
            if is_audit(&r) {
                spool.append(r)?;
            }
        }
        drain(&client, &cfg, &mut spool, epoch, &mut seq, max_attempts).await?;
        if once {
            tracing::info!(shipped_batches = seq, "pgaudit: --once catch-up complete");
            return Ok(());
        }
        tracing::debug!(backlog = spool.len(), "pgaudit heartbeat");
        tokio::time::sleep(cfg.poll).await;
    }
}

/// Read `path` from byte `offset` to EOF, returning the new bytes (lossy UTF-8)
/// and the new offset. A truncated/rotated file (size < offset) restarts at 0.
fn read_from(path: &Path, offset: u64) -> Result<(String, u64)> {
    use std::io::{Seek, SeekFrom};
    let mut f = std::fs::File::open(path).context("open csvlog")?;
    let len = f.metadata()?.len();
    let start = if len < offset { 0 } else { offset };
    f.seek(SeekFrom::Start(start))?;
    let mut buf = Vec::new();
    f.read_to_end(&mut buf)?;
    Ok((
        String::from_utf8_lossy(&buf).into_owned(),
        start + buf.len() as u64,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_stamp_detects_record_boundaries() {
        assert!(is_stamp("2026-07-28 00:12:34.567 UTC,\"u\",..."));
        assert!(!is_stamp("\tDETAIL:  continued line"));
        assert!(!is_stamp("2026-07-28 short"));
        assert!(!is_stamp(""));
    }

    #[test]
    fn reassemble_joins_multiline_records_and_holds_the_partial() {
        let text = "2026-07-28 00:00:01 UTC,a,LOG:  AUDIT: SELECT\n\tcontinued\n\
                    2026-07-28 00:00:02 UTC,b,LOG:  plain line\n\
                    2026-07-28 00:00:03 UTC,c,LOG:  AUDIT: UPDATE\n\tstill open";
        let (records, partial) = reassemble(text);
        assert_eq!(
            records.len(),
            2,
            "two complete records; the third is still open"
        );
        assert!(records[0].contains("AUDIT: SELECT") && records[0].contains("continued"));
        assert!(is_audit(&records[0]));
        assert!(
            !is_audit(&records[1]),
            "the plain line is not an audit record"
        );
        assert!(partial.contains("AUDIT: UPDATE") && partial.contains("still open"));
    }

    #[test]
    fn backoff_is_capped_and_grows() {
        assert_eq!(backoff_ms(0, 500, 30_000), 500);
        assert_eq!(backoff_ms(1, 500, 30_000), 1000);
        assert_eq!(backoff_ms(3, 500, 30_000), 4000);
        assert_eq!(backoff_ms(20, 500, 30_000), 30_000, "capped");
        assert_eq!(
            backoff_ms(60, 500, 30_000),
            30_000,
            "shift saturates + capped"
        );
    }

    #[test]
    fn spool_is_durable_bounded_and_delivers_exactly_the_committed_records() {
        let dir = std::env::temp_dir().join(format!("garmr-spool-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("pgaudit.spool");
        {
            let mut s = Spool::open(&path).unwrap();
            s.append("rec-1".into()).unwrap();
            s.append("rec-2".into()).unwrap();
            s.append("rec-3".into()).unwrap();
            assert_eq!(s.len(), 3);
            // Deliver the first 2, keep 1.
            assert_eq!(s.peek(2), vec!["rec-1", "rec-2"]);
            s.commit(2).unwrap();
            assert_eq!(s.len(), 1);
        }
        // Reopen: only the undelivered record survived (crash-safety + bounding).
        {
            let mut s = Spool::open(&path).unwrap();
            assert_eq!(s.len(), 1);
            assert_eq!(s.peek(10), vec!["rec-3"]);
            s.commit(1).unwrap();
            assert!(s.is_empty());
        }
        // Fully drained → the file is compacted away.
        assert!(!path.exists(), "a drained spool leaves no file");
        std::fs::remove_dir_all(&dir).ok();
    }
}
