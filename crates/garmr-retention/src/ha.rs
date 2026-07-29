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
//! The redb catalog file is mutable and is copied whole. Shipping it while the
//! writer commits can capture a torn page; skade's heal-on-open (the durability
//! work) rolls a torn catalog back to its last good root on the follower, so a
//! torn ship costs one stale pull, not corruption — but this has NOT been
//! exercised under a concurrent write load on real separate nodes. True
//! multi-node failover and consistency-under-load are unverified on a
//! single-host lab. See docs/ha-design.md.

use std::path::{Path, PathBuf};

use garmr_core::{Error, Result};
use object_store::{ObjectStore, ObjectStoreExt, PutPayload};
use serde::{Deserialize, Serialize};

/// Object key of the atomic snapshot pointer, written last on ship / read first
/// on pull. Its presence-and-completeness is the whole consistency contract.
const MANIFEST_KEY: &str = "MANIFEST.json";

/// One entry in a shipped snapshot: a warehouse-relative path and its byte
/// length (a cheap change-detector so a follower skips unchanged files).
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Entry {
    path: String,
    len: u64,
}

/// The snapshot pointer. `id` is monotonic (the writer's ship counter) so a
/// follower can tell whether a pull actually advanced the snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Manifest {
    id: u64,
    files: Vec<Entry>,
}

/// Ships / pulls a warehouse snapshot over an S3-compatible object store. Built
/// from the same `GARMR_S3_*` env as the cold tier, under a distinct prefix
/// (`GARMR_HA_S3_PREFIX`, default `ha/`) so HA snapshots and cold archives never
/// collide in the bucket.
pub struct HaSync {
    store: Box<dyn ObjectStore>,
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
            .build()
            .map_err(|e| Error::store(format!("HA S3 init ({endpoint}): {e}")))?;
        tracing::info!(%endpoint, %bucket, %prefix, "HA: object-store replica target configured");
        Ok(Some(Self {
            store: Box::new(s3),
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
    pub async fn ship(&self, warehouse_dir: &Path, snapshot_id: u64) -> Result<usize> {
        let files = collect_files(warehouse_dir)?;
        let mut entries = Vec::with_capacity(files.len());
        let mut uploaded = 0usize;
        for (rel, abs) in &files {
            let len = tokio::fs::metadata(abs).await.map(|m| m.len()).unwrap_or(0);
            entries.push(Entry {
                path: rel.clone(),
                len,
            });
            // Immutable data files (content-addressed parquet under data/) never
            // change once written, so skip re-upload when the object already
            // exists at the same size. Metadata (small, mutable) is always sent.
            let immutable = rel.ends_with(".parquet");
            if immutable && self.object_len(rel).await == Some(len) {
                continue;
            }
            let bytes = tokio::fs::read(abs)
                .await
                .map_err(|e| Error::store(format!("HA read {rel}: {e}")))?;
            self.store
                .put(&self.key(rel), PutPayload::from(bytes::Bytes::from(bytes)))
                .await
                .map_err(|e| Error::store(format!("HA upload {rel}: {e}")))?;
            uploaded += 1;
        }
        // The pointer, written last: only now is the snapshot complete.
        let manifest = Manifest {
            id: snapshot_id,
            files: entries,
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
        Ok(uploaded)
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
            // Reuse an already-local immutable file (same path+size) instead of
            // re-downloading — a follower keeps most parquet between pulls.
            let live = warehouse_dir.join(&e.path);
            if e.path.ends_with(".parquet")
                && tokio::fs::metadata(&live).await.map(|m| m.len()).ok() == Some(e.len)
            {
                tokio::fs::copy(&live, &dest).await.map_err(Error::store)?;
                continue;
            }
            let got = self
                .store
                .get(&self.key(&e.path))
                .await
                .map_err(|err| Error::store(format!("HA get {}: {err}", e.path)))?;
            let bytes = got
                .bytes()
                .await
                .map_err(|err| Error::store(format!("HA read {}: {err}", e.path)))?;
            tokio::fs::write(&dest, &bytes)
                .await
                .map_err(Error::store)?;
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
        Ok(Some(manifest.id))
    }

    /// Byte length of an object, or `None` if absent/unreadable.
    async fn object_len(&self, rel: &str) -> Option<u64> {
        self.store.head(&self.key(rel)).await.ok().map(|m| m.size)
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
                store: Box::new(object_store::memory::InMemory::new()),
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
        let uploaded = ha.ship(&src, 1).await.unwrap();
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
        let uploaded2 = ha.ship(&src, 2).await.unwrap();
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
}