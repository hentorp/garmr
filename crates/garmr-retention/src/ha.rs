// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! HA read-replica: ship the warehouse to object storage, pull it on a
//! follower (M7-5).
//!
//! garmr is single-writer by design (the skade lakehouse holds a redb catalog
//! lock; exactly one process ingests). This module adds **read replicas**: a
//! writer periodically ships a consistent snapshot of its warehouse to an S3
//! prefix, and one or more followers pull that snapshot and serve the read API
//! (`/api/query`, search, cases…) — horizontal read scale and a warm standby,
//! without ever introducing a second writer (so there is no split-brain on the
//! write path; a follower is strictly read-only).
//!
//! ## Consistency: the manifest is the atomic pointer
//!
//! Iceberg data files are immutable and content-addressed, so shipping them is
//! safe to do incrementally and out of order. The *catalog* (which snapshot is
//! current) is the only mutable pointer. So [`HaSync::ship`] uploads every data
//! and metadata file first, then writes a single `MANIFEST.json` **last** — the
//! snapshot pointer. [`HaSync::pull`] reads `MANIFEST.json` **first**, downloads
//! exactly the files it names into a staging dir, and only then swaps them into
//! the live warehouse. A follower therefore never observes a half-shipped
//! snapshot: it either sees the previous complete `MANIFEST.json` or the new
//! one, never a torn mix.
//!
//! ## Known-unverified (needs a second node)
//!
//! The redb catalog file is mutable, so shipping it while the writer commits
//! could capture a torn page (shadow paging keeps committed pages immutable,
//! but a page freed by a LATER commit may be rewritten mid-copy). The ship path
//! therefore copies the catalog privately and requires the COPY to open —
//! redb's own validation, and recovery where needed — before it is uploaded,
//! retrying with a fresh copy up to three times ([`validated_redb_copy`]).
//! Behind that, skade's heal-on-open still rolls a torn catalog back to its
//! last good root on the follower, so the residual cost is one stale pull, not
//! corruption — but the combination has NOT been
//! exercised under a concurrent write load on real separate nodes. True
//! multi-node failover and consistency-under-load are unverified on a
//! single-host lab. See docs/ha-design.md.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use futures::StreamExt;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use garmr_core::{Error, Result};
use object_store::{ObjectStore, ObjectStoreExt, PutPayload};
use serde::{Deserialize, Serialize};

/// Object key of the atomic snapshot pointer, written last on ship / read first
/// on pull. Its presence-and-completeness is the whole consistency contract.
const MANIFEST_KEY: &str = "MANIFEST.json";

/// One entry in a shipped snapshot: a warehouse-relative path, its byte length
/// (a cheap change-detector so a follower skips unchanged files), and the
/// BLAKE3 of its content — the strong check a length can never be.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Entry {
    path: String,
    len: u64,
    /// BLAKE3 hex of the file as shipped. `None` only for entries written by a
    /// pre-digest writer (`serde(default)`), which a pull accepts undigested
    /// rather than refusing history that predates the field.
    #[serde(default)]
    digest: Option<String>,
}

/// The snapshot pointer. `id` is monotonic (the writer's ship counter) so a
/// follower can tell whether a pull actually advanced the snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Manifest {
    id: u64,
    files: Vec<Entry>,
    /// The writer epoch that produced this snapshot. `#[serde(default)]` so
    /// manifests written before fencing existed decode as epoch 0, which is
    /// below every real epoch and therefore never wins a comparison.
    #[serde(default)]
    epoch: u64,
    /// Unix µs when the manifest was written — the follower's RPO clock.
    #[serde(default)]
    created_at_us: i64,
    /// The shipping node's id (`audit.node_id`), so a bucket shared by several
    /// deployments says which writer produced what.
    #[serde(default)]
    writer: String,
}

/// Object key of the writer lease. Its `epoch` is the fencing token: strictly
/// increasing, and every snapshot carries the epoch that produced it.
const EPOCH_KEY: &str = "EPOCH.json";

/// The writer lease.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Lease {
    /// Strictly increasing. A snapshot stamped with a lower epoch than the
    /// current lease was produced by a writer that has since been fenced out.
    pub epoch: u64,
    /// Who holds it — for operators reading the bucket, never for authorization.
    pub holder: String,
    pub acquired_at_us: i64,
}

/// What a writer should do about an observed lease.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FenceVerdict {
    /// This node still holds the lease; keep writing.
    Continue,
    /// A higher epoch exists: another node was promoted. The correct response is
    /// to STOP, not to keep shipping — a fenced writer that keeps going is the
    /// split-brain this exists to prevent, and losing availability on one node
    /// is recoverable in a way divergent history is not.
    SelfFence { observed: u64 },
}

/// Decide whether a writer holding `mine` may continue, given the lease it just
/// observed. Pure so the rule is testable without a store.
///
/// A MISSING lease is `Continue`: a single-node deployment that never promoted
/// anything has no lease, and refusing to write there would break the common
/// case to defend against a scenario that cannot occur without a second node.
pub fn fence_verdict(mine: u64, observed: Option<&Lease>) -> FenceVerdict {
    match observed {
        Some(l) if l.epoch > mine => FenceVerdict::SelfFence { observed: l.epoch },
        _ => FenceVerdict::Continue,
    }
}

/// Ships / pulls a warehouse snapshot over an S3-compatible object store. Built
/// from the same `GARMR_S3_*` env as the cold tier, under a distinct prefix
/// (`GARMR_HA_S3_PREFIX`, default `ha/`) so HA snapshots and cold archives never
/// collide in the bucket.
pub struct HaSync {
    store: Arc<dyn ObjectStore>,
    prefix: String,
}

impl HaSync {
    /// Build from `GARMR_S3_*` (+ optional `GARMR_HA_S3_PREFIX`), or `Ok(None)`
    /// when S3 is unconfigured — HA then simply isn't available and the caller
    /// stays single-node. Shares the credential surface with [`crate::S3Cold`].
    pub fn from_env() -> Result<Option<Self>> {
        let (Ok(endpoint), Ok(bucket), Ok(ak), Ok(sk)) = (
            std::env::var("GARMR_S3_ENDPOINT"),
            std::env::var("GARMR_S3_BUCKET"),
            std::env::var("GARMR_S3_ACCESS_KEY"),
            std::env::var("GARMR_S3_SECRET_KEY"),
        ) else {
            return Ok(None);
        };
        // Egress chokepoint (invariant #1): a denied object-store endpoint → HA
        // unavailable (single-node), the exact path the caller handles when S3 is
        // unconfigured. Air-gap denies external S3; a loopback/LAN one builds.
        if garmr_core::egress::global()
            .check(garmr_core::EgressClass::ObjectStore, &endpoint)
            .is_err()
        {
            return Ok(None);
        }
        let region = std::env::var("GARMR_S3_REGION").unwrap_or_else(|_| "us-east-1".into());
        let mut prefix = std::env::var("GARMR_HA_S3_PREFIX").unwrap_or_else(|_| "ha/".into());
        if !prefix.ends_with('/') {
            prefix.push('/');
        }
        let allow_http = endpoint.starts_with("http://");
        let s3 = object_store::aws::AmazonS3Builder::new()
            .with_endpoint(&endpoint)
            .with_bucket_name(&bucket)
            .with_access_key_id(ak)
            .with_secret_access_key(sk)
            .with_region(region)
            .with_allow_http(allow_http)
            .with_virtual_hosted_style_request(false)
            // The same retry/backoff the cold tier uses — a transient S3 hiccup
            // retries inside the client instead of failing the whole ship/pull.
            .with_retry(crate::object_retry())
            .build()
            .map_err(|e| Error::store(format!("HA S3 init ({endpoint}): {e}")))?;
        tracing::info!(%endpoint, %bucket, %prefix, "HA: object-store replica target configured");
        Ok(Some(Self {
            store: Arc::new(s3),
            prefix,
        }))
    }

    fn key(&self, rel: &str) -> object_store::path::Path {
        object_store::path::Path::from(format!("{}{}", self.prefix, rel))
    }

    /// Ship a consistent snapshot of `warehouse_dir` to the object store.
    ///
    /// Uploads every regular file first (immutable parquet is skipped when an
    /// object of the same size already exists — cheap incrementality), then
    /// writes `MANIFEST.json` last as the atomic pointer. `snapshot_id` is the
    /// writer's monotonic ship counter, stamped into the manifest.
    /// `epoch` is the writer lease this snapshot was produced under. It is
    /// stamped into the manifest so a follower can reject a snapshot from a
    /// writer that has since been fenced out — an old writer resurrecting after
    /// a failover would otherwise overwrite the new writer's history.
    pub async fn ship(
        &self,
        warehouse_dir: &Path,
        snapshot_id: u64,
        epoch: u64,
        writer: &str,
    ) -> Result<usize> {
        let files = collect_files(warehouse_dir)?;
        // The previous manifest's entries, so an unchanged immutable file keeps
        // its recorded digest without a local re-read.
        let prev: HashMap<String, Entry> = self
            .get_manifest()
            .await?
            .map(|m| m.files.into_iter().map(|e| (e.path.clone(), e)).collect())
            .unwrap_or_default();
        let mut entries = Vec::with_capacity(files.len());
        let mut uploaded = 0usize;
        for (rel, abs) in &files {
            let len = tokio::fs::metadata(abs).await.map(|m| m.len()).unwrap_or(0);
            // Immutable data files (content-addressed parquet under data/) never
            // change once written, so skip re-upload when the object already
            // exists at the same size. Metadata (small, mutable) is always sent.
            let immutable = rel.ends_with(".parquet");
            if immutable && self.object_len(rel).await == Some(len) {
                // Keep the digest the previous manifest recorded; hash the local
                // file (one read, no upload) only when the object predates
                // digests — the manifest converges to fully digested either way.
                let digest = match prev
                    .get(rel)
                    .filter(|e| e.len == len)
                    .and_then(|e| e.digest.clone())
                {
                    Some(d) => d,
                    None => hash_file(abs).await?,
                };
                entries.push(Entry {
                    path: rel.clone(),
                    len,
                    digest: Some(digest),
                });
                continue;
            }
            // Mutable redb files (the catalog) can be torn by a concurrent
            // commit: shadow paging keeps pages a committed root references
            // immutable, but a page freed by a LATER commit may be rewritten
            // while a sequential copy is mid-file. Copy → open-to-validate →
            // retry, and ship the validated private copy, never the live file.
            let (sent_len, digest) = if rel.ends_with(".redb") {
                let tmp = validated_redb_copy(abs, rel).await?;
                let res = self.upload_streamed(rel, &tmp).await;
                let _ = tokio::fs::remove_file(&tmp).await;
                res?
            } else {
                self.upload_streamed(rel, abs).await?
            };
            entries.push(Entry {
                path: rel.clone(),
                len: sent_len,
                digest: Some(digest),
            });
            uploaded += 1;
        }
        // The pointer, written last: only now is the snapshot complete.
        let manifest = Manifest {
            id: snapshot_id,
            files: entries,
            epoch,
            created_at_us: chrono::Utc::now().timestamp_micros(),
            writer: writer.to_string(),
        };
        let body = serde_json::to_vec(&manifest).map_err(Error::store)?;
        self.store
            .put(
                &self.key(MANIFEST_KEY),
                PutPayload::from(bytes::Bytes::from(body)),
            )
            .await
            .map_err(|e| Error::store(format!("HA upload manifest: {e}")))?;
        tracing::info!(
            snapshot_id,
            files = manifest.files.len(),
            uploaded,
            "HA: shipped snapshot"
        );
        status::stamp(manifest.created_at_us, snapshot_id);
        Ok(uploaded)
    }

    /// Stream one file into the object store through a bounded-memory multipart
    /// writer, hashing as it goes. Returns (bytes sent, BLAKE3 hex). RAM is
    /// bounded by the writer's buffer capacity, not the file size.
    async fn upload_streamed(&self, rel: &str, abs: &Path) -> Result<(u64, String)> {
        let mut f = tokio::fs::File::open(abs)
            .await
            .map_err(|e| Error::store(format!("HA open {rel}: {e}")))?;
        let mut w = object_store::buffered::BufWriter::new(self.store.clone(), self.key(rel));
        let mut hasher = blake3::Hasher::new();
        let mut buf = vec![0u8; 1024 * 1024];
        let mut sent = 0u64;
        loop {
            let n = f
                .read(&mut buf)
                .await
                .map_err(|e| Error::store(format!("HA read {rel}: {e}")))?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
            w.write_all(&buf[..n])
                .await
                .map_err(|e| Error::store(format!("HA upload {rel}: {e}")))?;
            sent += n as u64;
        }
        w.shutdown()
            .await
            .map_err(|e| Error::store(format!("HA finalize {rel}: {e}")))?;
        Ok((sent, hasher.finalize().to_hex().to_string()))
    }

    /// Pull the latest shipped snapshot into `warehouse_dir`. Reads
    /// `MANIFEST.json` first, materialises exactly the files it names into a
    /// staging dir (skipping any already present locally at the same size), then
    /// swaps them into place. Returns `Ok(Some(id))` when a *new* snapshot was
    /// applied (id greater than `have_id`), `Ok(None)` when already current.
    pub async fn pull(&self, warehouse_dir: &Path, have_id: u64) -> Result<Option<u64>> {
        let manifest = match self.get_manifest().await? {
            Some(m) => m,
            None => return Ok(None), // nothing shipped yet
        };
        if manifest.id <= have_id {
            return Ok(None); // already at or ahead of this snapshot
        }
        // Epoch regression: this snapshot came from a writer that has since been
        // fenced out. Its snapshot id may well be HIGHER than ours (an old
        // writer keeps counting), so the id check above cannot catch it — and
        // applying it would overwrite the promoted writer's history with the
        // deposed one's. Refuse, loudly, and stay where we are.
        if let Some(lease) = self.lease().await? {
            if manifest.epoch < lease.epoch {
                tracing::error!(
                    manifest_epoch = manifest.epoch,
                    lease_epoch = lease.epoch,
                    snapshot = manifest.id,
                    "HA follower REFUSED a snapshot from a fenced-out writer"
                );
                return Ok(None);
            }
        }
        let staging = warehouse_dir.with_extension("pull-staging");
        let _ = tokio::fs::remove_dir_all(&staging).await;
        tokio::fs::create_dir_all(&staging)
            .await
            .map_err(Error::store)?;

        for e in &manifest.files {
            let dest = staging.join(&e.path);
            if let Some(parent) = dest.parent() {
                tokio::fs::create_dir_all(parent)
                    .await
                    .map_err(Error::store)?;
            }
            // Reuse an already-local immutable file instead of re-downloading —
            // a follower keeps most parquet between pulls. The reuse copy is
            // hashed in transit (same IO as the copy itself) and falls back to
            // a download on mismatch: a stale or corrupt local file must never
            // shadow the shipped one.
            let live = warehouse_dir.join(&e.path);
            if e.path.ends_with(".parquet")
                && tokio::fs::metadata(&live).await.map(|m| m.len()).ok() == Some(e.len)
            {
                match copy_hashed(&live, &dest).await {
                    Ok(local_digest)
                        if e.digest.is_none() || e.digest.as_deref() == Some(&local_digest) =>
                    {
                        continue;
                    }
                    Ok(_) => tracing::warn!(
                        path = %e.path,
                        "HA pull: local copy does not match the manifest digest — re-downloading"
                    ),
                    Err(err) => tracing::warn!(
                        path = %e.path, error = %err,
                        "HA pull: local reuse failed — re-downloading"
                    ),
                }
            }
            // Streamed download, hashed in transit. RAM is bounded by the chunk
            // size, and a digest mismatch fails the pull BY NAME before any of
            // it is swapped live.
            let got = self
                .store
                .get(&self.key(&e.path))
                .await
                .map_err(|err| Error::store(format!("HA get {}: {err}", e.path)))?;
            let mut stream = got.into_stream();
            let mut out = tokio::fs::File::create(&dest).await.map_err(Error::store)?;
            let mut hasher = blake3::Hasher::new();
            while let Some(chunk) = stream.next().await {
                let chunk =
                    chunk.map_err(|err| Error::store(format!("HA read {}: {err}", e.path)))?;
                hasher.update(&chunk);
                out.write_all(&chunk).await.map_err(Error::store)?;
            }
            out.flush().await.map_err(Error::store)?;
            drop(out);
            let got_digest = hasher.finalize().to_hex().to_string();
            if let Some(want) = &e.digest {
                if want != &got_digest {
                    return Err(Error::store(format!(
                        "HA pull: digest mismatch for {} (manifest {}, downloaded {}) — refusing \
                         to apply the snapshot",
                        e.path, want, got_digest
                    )));
                }
            }
        }

        // Swap staging → live. Move the old dir aside first so the replace is a
        // rename on the same filesystem (atomic), then drop the old copy.
        let backup = warehouse_dir.with_extension("pull-old");
        let _ = tokio::fs::remove_dir_all(&backup).await;
        if tokio::fs::metadata(warehouse_dir).await.is_ok() {
            tokio::fs::rename(warehouse_dir, &backup)
                .await
                .map_err(Error::store)?;
        }
        tokio::fs::rename(&staging, warehouse_dir)
            .await
            .map_err(Error::store)?;
        let _ = tokio::fs::remove_dir_all(&backup).await;
        tracing::info!(
            snapshot_id = manifest.id,
            files = manifest.files.len(),
            "HA: applied snapshot"
        );
        status::stamp(chrono::Utc::now().timestamp_micros(), manifest.id);
        Ok(Some(manifest.id))
    }

    /// Byte length of an object, or `None` if absent/unreadable.
    async fn object_len(&self, rel: &str) -> Option<u64> {
        self.store.head(&self.key(rel)).await.ok().map(|m| m.size)
    }

    /// Read the current writer lease, or `None` when nothing has been promoted.
    pub async fn lease(&self) -> Result<Option<Lease>> {
        match self.store.get(&self.key(EPOCH_KEY)).await {
            Ok(got) => {
                let bytes = got.bytes().await.map_err(Error::store)?;
                Ok(Some(serde_json::from_slice(&bytes).map_err(Error::store)?))
            }
            Err(object_store::Error::NotFound { .. }) => Ok(None),
            Err(e) => Err(Error::store(format!("HA read lease: {e}"))),
        }
    }

    /// Take the writer lease, moving the epoch strictly forward.
    ///
    /// The write is CONDITIONAL — create-if-absent for the first promotion,
    /// compare-and-swap against the observed version afterwards — so when two
    /// nodes promote at the same moment exactly one succeeds and the loser is
    /// told, rather than both believing they won. That is the entire point:
    /// without a conditional write this would be a read-then-write race and the
    /// lease would be decoration.
    ///
    /// HONEST LIMIT: this is authoritative only while the object store is
    /// reachable. A writer partitioned away from the bucket cannot observe that
    /// it has been fenced, so it keeps writing locally until it can. Fencing
    /// here is a guarantee about what the STORE accepts, not a claim that
    /// split-brain is impossible under partition.
    pub async fn acquire_lease(&self, holder: &str, now_us: i64) -> Result<Lease> {
        use object_store::{PutMode, PutOptions, UpdateVersion};
        let current = self.store.get(&self.key(EPOCH_KEY)).await;
        let (next_epoch, mode) = match current {
            Ok(got) => {
                let meta = got.meta.clone();
                let bytes = got.bytes().await.map_err(Error::store)?;
                let l: Lease = serde_json::from_slice(&bytes).map_err(Error::store)?;
                (
                    l.epoch + 1,
                    PutMode::Update(UpdateVersion {
                        e_tag: meta.e_tag.clone(),
                        version: meta.version.clone(),
                    }),
                )
            }
            Err(object_store::Error::NotFound { .. }) => (1, PutMode::Create),
            Err(e) => return Err(Error::store(format!("HA read lease: {e}"))),
        };
        let lease = Lease {
            epoch: next_epoch,
            holder: holder.to_string(),
            acquired_at_us: now_us,
        };
        let body = serde_json::to_vec(&lease).map_err(Error::store)?;
        self.store
            .put_opts(
                &self.key(EPOCH_KEY),
                PutPayload::from(bytes::Bytes::from(body)),
                PutOptions {
                    mode,
                    ..Default::default()
                },
            )
            .await
            .map_err(|e| match e {
                object_store::Error::AlreadyExists { .. }
                | object_store::Error::Precondition { .. } => Error::store(format!(
                    "HA promote lost the race for epoch {next_epoch} — another node promoted                      first. This node must NOT become a writer."
                )),
                other => Error::store(format!("HA write lease: {other}")),
            })?;
        tracing::info!(epoch = next_epoch, holder, "HA: writer lease acquired");
        Ok(lease)
    }

    /// The id of the newest shipped snapshot, or 0 when nothing is shipped yet.
    ///
    /// A restarting writer MUST seed its snapshot counter from this. Snapshot
    /// ids are the follower's freshness test — [`pull`](Self::pull) ignores any
    /// manifest whose id is `<= have_id` — so a writer that restarts its counter
    /// at 1 re-ships ids the follower has already passed, and the follower
    /// silently drops every one of them until the counter climbs back above
    /// where it left off. At a 5-minute interval and 57 snapshots shipped before
    /// the restart, that is roughly five hours of replication stall on a
    /// follower that looks healthy the whole time.
    pub async fn last_shipped_id(&self) -> Result<u64> {
        Ok(self.get_manifest().await?.map(|m| m.id).unwrap_or(0))
    }

    async fn get_manifest(&self) -> Result<Option<Manifest>> {
        match self.store.get(&self.key(MANIFEST_KEY)).await {
            Ok(got) => {
                let bytes = got.bytes().await.map_err(Error::store)?;
                let m: Manifest = serde_json::from_slice(&bytes).map_err(Error::store)?;
                Ok(Some(m))
            }
            // A missing manifest means nothing has been shipped yet, not an error.
            Err(object_store::Error::NotFound { .. }) => Ok(None),
            Err(e) => Err(Error::store(format!("HA get manifest: {e}"))),
        }
    }
}

/// Recursively collect regular files under `dir` as (warehouse-relative path,
/// absolute path) pairs, skipping the staging/backup scratch dirs a pull uses.
/// BLAKE3 of a local file, streamed (bounded RAM).
async fn hash_file(abs: &Path) -> Result<String> {
    let mut f = tokio::fs::File::open(abs)
        .await
        .map_err(|e| Error::store(format!("HA hash open {}: {e}", abs.display())))?;
    let mut hasher = blake3::Hasher::new();
    let mut buf = vec![0u8; 1024 * 1024];
    loop {
        let n = f.read(&mut buf).await.map_err(Error::store)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hasher.finalize().to_hex().to_string())
}

/// Copy `src` → `dst` while hashing the bytes in transit; returns the BLAKE3
/// hex of what was actually copied. Same IO cost as a plain copy.
async fn copy_hashed(src: &Path, dst: &Path) -> Result<String> {
    let mut f = tokio::fs::File::open(src).await.map_err(Error::store)?;
    let mut out = tokio::fs::File::create(dst).await.map_err(Error::store)?;
    let mut hasher = blake3::Hasher::new();
    let mut buf = vec![0u8; 1024 * 1024];
    loop {
        let n = f.read(&mut buf).await.map_err(Error::store)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        out.write_all(&buf[..n]).await.map_err(Error::store)?;
    }
    out.flush().await.map_err(Error::store)?;
    Ok(hasher.finalize().to_hex().to_string())
}

/// Copy a live redb file to a private temp path and prove the copy OPENS.
///
/// redb's shadow paging keeps every page a committed root references
/// immutable, but a page freed by a later commit may be rewritten while a
/// sequential copy is mid-file — so a copy taken under a live writer can be
/// torn even though the source is always consistent. Opening the copy runs
/// redb's own validation (and, if needed, its recovery — a copy that recovery
/// makes openable is exactly what the follower needs). Three attempts: a torn
/// copy is transient and a fresh copy fixes it. A file that NEVER validates is
/// shipped as-is with a loud warning — replicating the writer's actual bytes
/// beats not replicating at all, and the follower's own open will say the rest.
async fn validated_redb_copy(abs: &Path, rel: &str) -> Result<PathBuf> {
    let mut tmp = PathBuf::new();
    for attempt in 1..=3u32 {
        tmp = std::env::temp_dir().join(format!(
            "garmr-ha-{}-{}-{attempt}.redb",
            std::process::id(),
            rel.replace(['/', '\\'], "_")
        ));
        tokio::fs::copy(abs, &tmp)
            .await
            .map_err(|e| Error::store(format!("HA catalog copy {rel}: {e}")))?;
        let probe = tmp.clone();
        let opened = tokio::task::spawn_blocking(move || {
            redb::Database::open(&probe)
                .map(drop)
                .map_err(|e| e.to_string())
        })
        .await
        .map_err(|e| Error::store(format!("HA catalog validate join: {e}")))?;
        match opened {
            Ok(()) => return Ok(tmp),
            Err(e) => {
                tracing::warn!(
                    %rel, attempt, error = %e,
                    "HA: catalog copy failed validation — retrying with a fresh copy"
                );
                let _ = tokio::fs::remove_file(&tmp).await;
            }
        }
    }
    // Last resort: one more raw copy, shipped unvalidated but said out loud.
    tokio::fs::copy(abs, &tmp)
        .await
        .map_err(|e| Error::store(format!("HA catalog copy {rel}: {e}")))?;
    tracing::error!(
        %rel,
        "HA: catalog copy failed validation on every attempt — shipping the raw copy; the \
         follower may need redb recovery on open"
    );
    Ok(tmp)
}

/// Last successful ship (writer) or applied pull (follower) in THIS process,
/// for `/api/capabilities`. Zeros until the first success.
pub mod status {
    use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};

    static LAST_AT_US: AtomicI64 = AtomicI64::new(0);
    static LAST_ID: AtomicU64 = AtomicU64::new(0);

    pub(super) fn stamp(at_us: i64, id: u64) {
        LAST_AT_US.store(at_us, Ordering::Relaxed);
        LAST_ID.store(id, Ordering::Relaxed);
    }

    /// `(unix µs of the last successful ship/pull, its snapshot id)` — `(0, 0)`
    /// when this process has not shipped or pulled yet.
    pub fn snapshot() -> (i64, u64) {
        (
            LAST_AT_US.load(Ordering::Relaxed),
            LAST_ID.load(Ordering::Relaxed),
        )
    }
}

fn collect_files(dir: &Path) -> Result<Vec<(String, PathBuf)>> {
    let mut out = Vec::new();
    walk(dir, dir, &mut out)?;
    out.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(out)
}

fn walk(root: &Path, dir: &Path, out: &mut Vec<(String, PathBuf)>) -> Result<()> {
    for entry in std::fs::read_dir(dir).map_err(Error::store)? {
        let entry = entry.map_err(Error::store)?;
        let path = entry.path();
        let ft = entry.file_type().map_err(Error::store)?;
        if ft.is_dir() {
            walk(root, &path, out)?;
        } else if ft.is_file() {
            let rel = path
                .strip_prefix(root)
                .map_err(|e| Error::store(e.to_string()))?
                .to_string_lossy()
                .replace('\\', "/");
            out.push((rel, path));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    impl HaSync {
        /// A HaSync backed by an in-memory object store — a self-contained target
        /// for the ship/pull round-trip test (no MinIO/S3 needed).
        fn in_memory() -> Self {
            Self {
                store: Arc::new(object_store::memory::InMemory::new()),
                prefix: "ha/".into(),
            }
        }
    }

    fn tmp(tag: &str) -> PathBuf {
        std::env::temp_dir().join(format!("garmr-ha-{tag}-{}", uuid::Uuid::new_v4()))
    }

    fn write(path: &Path, body: &[u8]) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, body).unwrap();
    }

    #[tokio::test]
    async fn ship_pull_roundtrip_and_snapshot_gating() {
        let ha = HaSync::in_memory();
        let src = tmp("src");
        let dst = tmp("dst");

        // A warehouse-shaped tree: nested data file + a metadata pointer.
        write(
            &src.join("data/part-00001.parquet"),
            b"immutable columnar bytes",
        );
        write(&src.join("metadata/v1.metadata.json"), b"{\"snapshot\":1}");
        write(&src.join("catalog.redb"), b"redb-catalog-v1");

        // Ship snapshot 1, then pull it into a fresh dir.
        let uploaded = ha.ship(&src, 1, 1, "test-writer").await.unwrap();
        assert_eq!(uploaded, 3, "all three files uploaded on the first ship");
        let applied = ha.pull(&dst, 0).await.unwrap();
        assert_eq!(applied, Some(1), "pull applies snapshot 1");

        // Every file arrived byte-identical.
        for rel in [
            "data/part-00001.parquet",
            "metadata/v1.metadata.json",
            "catalog.redb",
        ] {
            assert_eq!(
                std::fs::read(dst.join(rel)).unwrap(),
                std::fs::read(src.join(rel)).unwrap(),
                "{rel} round-trips byte-for-byte"
            );
        }

        // Snapshot gating: re-pulling at the same id is a no-op.
        assert_eq!(ha.pull(&dst, 1).await.unwrap(), None, "already current");

        // Ship snapshot 2 with a changed metadata pointer (immutable parquet
        // unchanged → skipped by the exists-at-same-size check).
        write(&src.join("metadata/v2.metadata.json"), b"{\"snapshot\":2}");
        let uploaded2 = ha.ship(&src, 2, 1, "test-writer").await.unwrap();
        assert!(
            uploaded2 < 4,
            "snapshot 2 skips the unchanged immutable parquet (uploaded {uploaded2})"
        );
        assert_eq!(
            ha.pull(&dst, 1).await.unwrap(),
            Some(2),
            "pull advances to 2"
        );
        assert!(dst.join("metadata/v2.metadata.json").exists());

        std::fs::remove_dir_all(&src).ok();
        std::fs::remove_dir_all(&dst).ok();
    }

    #[tokio::test]
    async fn a_corrupted_object_fails_the_pull_by_name() {
        let ha = HaSync::in_memory();
        let src = tmp("dig-src");
        let dst = tmp("dig-dst");
        write(
            &src.join("data/part-00001.parquet"),
            b"real columnar bytes!",
        );
        write(&src.join("metadata/v1.metadata.json"), b"{\"snapshot\":1}");
        ha.ship(&src, 1, 1, "test-writer").await.unwrap();

        // Corrupt the object in the bucket with SAME-LENGTH garbage, so only
        // the digest — never the length — can catch it.
        ha.store
            .put(
                &ha.key("data/part-00001.parquet"),
                PutPayload::from(bytes::Bytes::from_static(b"evil replacement byte")),
            )
            .await
            .unwrap();

        let err = ha.pull(&dst, 0).await.unwrap_err().to_string();
        assert!(
            err.contains("data/part-00001.parquet") && err.contains("digest mismatch"),
            "the pull names the corrupted file: {err}"
        );

        std::fs::remove_dir_all(&src).ok();
        std::fs::remove_dir_all(&dst).ok();
    }

    #[tokio::test]
    async fn a_multi_chunk_file_round_trips_through_the_streamed_path() {
        let ha = HaSync::in_memory();
        let src = tmp("big-src");
        let dst = tmp("big-dst");
        // Bigger than the BufWriter buffer capacity (10 MiB), so the upload
        // takes the multipart path and the download crosses many chunks.
        let mut big = vec![0u8; 12 * 1024 * 1024];
        for (i, b) in big.iter_mut().enumerate() {
            *b = (i % 251) as u8;
        }
        write(&src.join("data/big-00001.parquet"), &big);
        write(&src.join("metadata/v1.metadata.json"), b"{\"snapshot\":1}");
        ha.ship(&src, 1, 1, "test-writer").await.unwrap();
        ha.pull(&dst, 0).await.unwrap();
        assert_eq!(
            std::fs::read(dst.join("data/big-00001.parquet")).unwrap(),
            big,
            "12 MiB file round-trips byte-for-byte through multipart + streaming"
        );
        std::fs::remove_dir_all(&src).ok();
        std::fs::remove_dir_all(&dst).ok();
    }

    #[tokio::test]
    async fn the_manifest_records_writer_and_creation_time() {
        let ha = HaSync::in_memory();
        let src = tmp("meta-src");
        write(&src.join("metadata/v1.metadata.json"), b"{}");
        ha.ship(&src, 1, 7, "node-alpha").await.unwrap();
        let m = ha.get_manifest().await.unwrap().unwrap();
        assert_eq!(m.writer, "node-alpha");
        assert_eq!(m.epoch, 7);
        assert!(m.created_at_us > 0, "created_at is stamped");
        assert!(
            m.files.iter().all(|e| e.digest.is_some()),
            "every entry ships with a digest"
        );
        std::fs::remove_dir_all(&src).ok();
    }

    #[tokio::test]
    async fn writer_restart_resumes_the_counter_instead_of_starving_the_follower() {
        let ha = HaSync::in_memory();
        let src = tmp("restart-src");
        let dst = tmp("restart-dst");
        write(&src.join("data/part-00001.parquet"), b"immutable bytes");
        write(&src.join("metadata/v1.metadata.json"), b"{\"snapshot\":1}");

        // A writer's first lifetime: three snapshots, follower keeps up.
        for id in 1..=3 {
            ha.ship(&src, id, 1, "test-writer").await.unwrap();
        }
        assert_eq!(ha.pull(&dst, 0).await.unwrap(), Some(3));
        let follower_has = 3u64;

        // The writer restarts. Seeded from the bucket, it continues at 4 — so
        // the very next snapshot is one the follower accepts.
        assert_eq!(
            ha.last_shipped_id().await.unwrap(),
            3,
            "the counter resumes from what is actually shipped"
        );
        let next = ha.last_shipped_id().await.unwrap() + 1;
        write(&src.join("metadata/v4.metadata.json"), b"{\"snapshot\":4}");
        ha.ship(&src, next, 1, "test-writer").await.unwrap();
        assert_eq!(
            ha.pull(&dst, follower_has).await.unwrap(),
            Some(4),
            "follower applies the post-restart snapshot"
        );
        assert!(dst.join("metadata/v4.metadata.json").exists());

        // The regression this guards: a counter restarting at 1 ships an id the
        // follower is already past, and pull drops it — replication stalls with
        // both sides reporting healthy.
        ha.ship(&src, 1, 1, "test-writer").await.unwrap();
        assert_eq!(
            ha.pull(&dst, follower_has).await.unwrap(),
            None,
            "a re-shipped low id is silently ignored — exactly the starvation being fixed"
        );

        // An empty bucket seeds 0, so a fresh deployment still starts at 1.
        assert_eq!(HaSync::in_memory().last_shipped_id().await.unwrap(), 0);

        std::fs::remove_dir_all(&src).ok();
        std::fs::remove_dir_all(&dst).ok();
    }

    #[test]
    fn a_higher_observed_epoch_fences_this_writer() {
        let lease = |e: u64| Lease {
            epoch: e,
            holder: "other".into(),
            acquired_at_us: 0,
        };
        // Someone else was promoted: stop. A fenced writer that keeps shipping
        // IS the split-brain this exists to prevent, and losing one node's
        // availability is recoverable in a way divergent history is not.
        assert_eq!(
            fence_verdict(3, Some(&lease(4))),
            FenceVerdict::SelfFence { observed: 4 }
        );
        // Our own epoch, or an older one, is not a reason to stop.
        assert_eq!(fence_verdict(4, Some(&lease(4))), FenceVerdict::Continue);
        assert_eq!(fence_verdict(4, Some(&lease(2))), FenceVerdict::Continue);
        // No lease at all: a single-node deployment that never promoted must
        // keep working — refusing here would break the common case to defend
        // against a scenario that needs a second node to exist.
        assert_eq!(fence_verdict(0, None), FenceVerdict::Continue);
    }

    #[tokio::test]
    async fn exactly_one_of_two_concurrent_promotions_wins() {
        let ha = HaSync::in_memory();
        assert!(
            ha.lease().await.unwrap().is_none(),
            "no lease before promotion"
        );

        // First promotion creates the lease at epoch 1.
        let first = ha.acquire_lease("node-a", 100).await.unwrap();
        assert_eq!(first.epoch, 1);

        // A second promotion moves it forward.
        let second = ha.acquire_lease("node-b", 200).await.unwrap();
        assert_eq!(second.epoch, 2);
        assert_eq!(ha.lease().await.unwrap().unwrap().holder, "node-b");

        // node-a now holds a stale epoch and must fence itself.
        let observed = ha.lease().await.unwrap();
        assert_eq!(
            fence_verdict(first.epoch, observed.as_ref()),
            FenceVerdict::SelfFence { observed: 2 }
        );
    }

    #[tokio::test]
    async fn a_follower_refuses_a_snapshot_from_a_fenced_out_writer() {
        let ha = HaSync::in_memory();
        let src = tmp("fence-src");
        let dst = tmp("fence-dst");
        write(&src.join("data/part-1.parquet"), b"bytes");
        write(&src.join("metadata/v1.metadata.json"), b"{}");

        // Old writer holds epoch 1 and ships snapshot 5; the follower takes it.
        ha.acquire_lease("node-a", 100).await.unwrap();
        ha.ship(&src, 5, 1, "test-writer").await.unwrap();
        assert_eq!(ha.pull(&dst, 0).await.unwrap(), Some(5));

        // Failover: node-b promotes to epoch 2.
        ha.acquire_lease("node-b", 200).await.unwrap();

        // The deposed writer keeps counting and ships snapshot 6 under its OLD
        // epoch. Its id is HIGHER than what the follower holds, so the id check
        // alone would accept it and overwrite the new writer's history.
        write(&src.join("metadata/v2.metadata.json"), b"{}");
        ha.ship(&src, 6, 1, "test-writer").await.unwrap();
        assert_eq!(
            ha.pull(&dst, 5).await.unwrap(),
            None,
            "a snapshot from a fenced-out epoch must be refused despite its higher id"
        );

        // The current writer's snapshot is accepted.
        ha.ship(&src, 7, 2, "test-writer").await.unwrap();
        assert_eq!(ha.pull(&dst, 5).await.unwrap(), Some(7));

        std::fs::remove_dir_all(&src).ok();
        std::fs::remove_dir_all(&dst).ok();
    }
}
