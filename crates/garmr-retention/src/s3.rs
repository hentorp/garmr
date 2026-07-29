// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! Optional S3 cold-tier backend.
//!
//! garmr's hot/cold tiering (see [`crate::manager`]) seals aged event windows
//! into immutable archives under `cold_dir`. By default those live on local
//! disk. This module lets them live on **object storage** instead: on seal the
//! archive is uploaded and the local copy dropped to reclaim disk; on read it is
//! fetched back on demand, then the existing checksum-verify + thaw runs
//! unchanged. That gives the enterprise story — cold survives host-disk loss and
//! scales past a single NUC's disk — while reusing the *verified* compression
//! and integrity path (the S3 layer only moves bytes; it never changes them).
//!
//! Configured entirely from `GARMR_S3_*` env (like every other garmr secret);
//! unset ⇒ [`S3Cold::from_env`] returns `None` and cold stays purely local, so
//! nothing changes for a file-only deployment.

use std::path::Path;

use garmr_core::{Error, Result};
use object_store::aws::AmazonS3Builder;
// ObjectStoreExt carries the convenience `put`/`get`/`head` (over `put_opts`).
use object_store::{ObjectStore, ObjectStoreExt, PutPayload};

/// A configured S3 cold-tier target. Keys are archive basenames (mirroring the
/// local `cold_dir` layout), so a `ColdArchive.file` maps 1:1 to an object key.
pub struct S3Cold {
    store: Box<dyn ObjectStore>,
    bucket: String,
}

impl S3Cold {
    /// Build from `GARMR_S3_*` env, or `Ok(None)` when unconfigured (the caller
    /// then stays on local-only cold). All four of endpoint/bucket/access/secret
    /// are required together; region defaults to `us-east-1` (MinIO ignores it).
    pub fn from_env() -> Result<Option<Self>> {
        let (Ok(endpoint), Ok(bucket), Ok(ak), Ok(sk)) = (
            std::env::var("GARMR_S3_ENDPOINT"),
            std::env::var("GARMR_S3_BUCKET"),
            std::env::var("GARMR_S3_ACCESS_KEY"),
            std::env::var("GARMR_S3_SECRET_KEY"),
        ) else {
            return Ok(None);
        };
        // Egress chokepoint (invariant #1): a denied object-store endpoint →
        // degrade to local-only cold (the exact path the caller already handles
        // when unconfigured). Air-gap denies an external S3; a loopback/LAN
        // (e.g. on-prem MinIO) endpoint still builds.
        if garmr_core::egress::global()
            .check(garmr_core::EgressClass::ObjectStore, &endpoint)
            .is_err()
        {
            return Ok(None);
        }
        let region = std::env::var("GARMR_S3_REGION").unwrap_or_else(|_| "us-east-1".into());
        let allow_http = endpoint.starts_with("http://");
        let s3 = AmazonS3Builder::new()
            .with_endpoint(&endpoint)
            .with_bucket_name(&bucket)
            .with_access_key_id(ak)
            .with_secret_access_key(sk)
            .with_region(region)
            .with_allow_http(allow_http)
            // MinIO (and most self-hosted S3) speak path-style, not virtual-host.
            .with_virtual_hosted_style_request(false)
            .build()
            .map_err(|e| Error::store(format!("S3 cold-tier init ({endpoint}): {e}")))?;
        tracing::info!(%endpoint, %bucket, "cold tier: S3 backend configured");
        Ok(Some(Self {
            store: Box::new(s3),
            bucket,
        }))
    }

    pub fn bucket(&self) -> &str {
        &self.bucket
    }

    fn key(name: &str) -> object_store::path::Path {
        object_store::path::Path::from(name)
    }

    /// Upload a just-sealed local archive to `key` (its basename).
    pub async fn upload(&self, local: &Path, key: &str) -> Result<()> {
        let bytes = tokio::fs::read(local)
            .await
            .map_err(|e| Error::store(format!("read {} for S3 upload: {e}", local.display())))?;
        self.store
            .put(&Self::key(key), PutPayload::from(bytes::Bytes::from(bytes)))
            .await
            .map_err(|e| Error::store(format!("S3 upload {key}: {e}")))?;
        Ok(())
    }

    /// Fetch an archive from `key` to `local` (for the verify + thaw path).
    pub async fn download(&self, key: &str, local: &Path) -> Result<()> {
        let got = self
            .store
            .get(&Self::key(key))
            .await
            .map_err(|e| Error::store(format!("S3 get {key}: {e}")))?;
        let bytes = got
            .bytes()
            .await
            .map_err(|e| Error::store(format!("S3 read {key}: {e}")))?;
        tokio::fs::write(local, &bytes)
            .await
            .map_err(|e| Error::store(format!("write {} from S3: {e}", local.display())))?;
        Ok(())
    }

    /// Is `key` present in the bucket?
    pub async fn exists(&self, key: &str) -> bool {
        self.store.head(&Self::key(key)).await.is_ok()
    }
}