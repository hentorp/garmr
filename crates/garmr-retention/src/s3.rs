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
            // Shared with HA replication — see `crate::object_retry`.
            .with_retry(crate::object_retry())
            .build()
            .map_err(|e| Error::store(format!("S3 cold-tier init ({endpoint}): {e}")))?;
        tracing::info!(%endpoint, %bucket, "cold tier: S3 backend configured");
        Ok(Some(Self {
            store: Box::new(s3),
        }))
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

    /// Delete the object at `key`.
    ///
    /// Retention expiry MUST call this. When S3 is configured, sealing uploads
    /// the archive and then drops the local copy to reclaim disk — so an expiry
    /// that only unlinks the local path deletes a file that is already gone and
    /// leaves the real data in the bucket, while removing the manifest row that
    /// was the last pointer to it. The operator sees a successful expiry, the
    /// data survives, and nothing in garmr can find it again.
    ///
    /// A missing object is SUCCESS, not an error: expiry is idempotent by
    /// design (a retried run must converge), and "the object is not there" is
    /// exactly the post-condition being asked for.
    ///
    /// What this cannot promise: bucket versioning, replication or backups may
    /// retain copies outside garmr's reach. That is an object-store
    /// configuration question, and the deletion certificate says what garmr
    /// verifiably did rather than making a claim about physical media.
    pub async fn delete(&self, key: &str) -> Result<()> {
        match self.store.delete(&Self::key(key)).await {
            Ok(()) => Ok(()),
            Err(object_store::Error::NotFound { .. }) => Ok(()),
            Err(e) => Err(Error::store(format!("S3 delete {key}: {e}"))),
        }
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
}
