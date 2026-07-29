// Apache-2.0 licensed. See ../LICENSE-APACHE.

//! # Pluggable object store
//!
//! [`ObjectStore`] is skade's backend-agnostic bytes-IO abstraction for the
//! Iceberg data and metadata files a [`crate::Warehouse`] reads and writes. It
//! decouples skade from any single S3 client so a consumer (e.g. an isolated
//! Njord mail-server) can run skade → Iceberg on a **shared MinIO** with the
//! backend of *its* choice — the same S3 SDK it already links, an embedded
//! local store, or no object store at all.
//!
//! ## The trait
//!
//! ```ignore
//! #[async_trait]
//! pub trait ObjectStore {
//!     async fn put(&self, key: &str, bytes: Bytes) -> Result<()>;
//!     async fn get(&self, key: &str) -> Result<Bytes>;
//!     async fn list(&self, prefix: &str) -> Result<Vec<String>>;
//!     async fn delete(&self, key: &str) -> Result<()>;
//!     async fn exists(&self, key: &str) -> Result<bool>;
//! }
//! ```
//!
//! ## Backends (feature-gated)
//!
//! | backend                  | feature   | what                                            |
//! |--------------------------|-----------|-------------------------------------------------|
//! | [`MemoryStore`]          | *(always)*| in-process map; for tests / ephemeral use       |
//! | [`LocalFsStore`]         | `rustfs`  | embedded, zero-external-dep local filesystem    |
//! | [`RustS3Store`]          | `s3`      | MinIO/S3 via **rust-s3**, configurable endpoint |
//! | [`AwsS3Store`]           | `aws-s3`  | MinIO/S3 via **aws-sdk-s3** (reuse Njord's SDK) |
//!
//! `default = []` — none of the S3 backends are pulled unless asked for, and
//! [`Warehouse::open`](crate::Warehouse::open) keeps using the local filesystem
//! exactly as before. Wire a custom store with
//! [`Warehouse::open_with_store`](crate::Warehouse::open_with_store).
//!
//! ## How the warehouse uses it
//!
//! iceberg-rust drives all blob IO through its own `Storage` / `StorageFactory`
//! extension points. [`ObjectStoreFactory`] bridges any [`ObjectStore`] into an
//! iceberg `StorageFactory`, so the warehouse plumbs the trait object straight
//! through the existing `FileIO` machinery — no hardwired client.

use std::collections::HashMap;
use std::ops::Range;
use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;

use crate::error::{Result, SkadeError};

/// skade's backend-agnostic object store: the bytes-IO skade does for Iceberg
/// data and metadata files, behind one async trait.
///
/// Keys are opaque path-like strings (`"warehouse/main/events/metadata/…"`).
/// Implementations may be backed by memory, a local filesystem, or any S3
/// compatible endpoint (MinIO). All methods are async and fallible.
#[async_trait]
pub trait ObjectStore: std::fmt::Debug + Send + Sync {
    /// Write `bytes` at `key`, overwriting any existing object.
    async fn put(&self, key: &str, bytes: Bytes) -> Result<()>;

    /// Read the whole object at `key`. Errors if it does not exist.
    async fn get(&self, key: &str) -> Result<Bytes>;

    /// Read a byte range `[start, end)` of the object at `key`. The default
    /// fetches the whole object and slices it; S3 backends override with a
    /// ranged GET.
    async fn get_range(&self, key: &str, range: Range<u64>) -> Result<Bytes> {
        let body = self.get(key).await?;
        let len = body.len() as u64;
        let start = range.start.min(len) as usize;
        let end = range.end.min(len) as usize;
        Ok(body.slice(start..end))
    }

    /// List the keys under `prefix` (recursive; full keys, not relative).
    async fn list(&self, prefix: &str) -> Result<Vec<String>>;

    /// Delete the object at `key`. A missing key is not an error.
    async fn delete(&self, key: &str) -> Result<()>;

    /// Whether an object exists at `key`.
    async fn exists(&self, key: &str) -> Result<bool>;

    /// Object size in bytes, or `None` if it does not exist. The default
    /// `get`s the object; backends with a cheap HEAD override this.
    async fn size(&self, key: &str) -> Result<Option<u64>> {
        match self.get(key).await {
            Ok(b) => Ok(Some(b.len() as u64)),
            Err(_) => Ok(None),
        }
    }
}

// ───────────────────────── MemoryStore (always on) ─────────────────────────

/// An in-process [`ObjectStore`] backed by a shared map. Cheap to clone (shares
/// the backing map). Intended for tests and ephemeral warehouses — nothing is
/// persisted. Always available (no feature gate).
#[derive(Debug, Clone, Default)]
pub struct MemoryStore {
    inner: Arc<std::sync::RwLock<HashMap<String, Bytes>>>,
}

impl MemoryStore {
    /// A fresh empty store.
    pub fn new() -> Self {
        // Object-store backend marker: the in-memory backend is available.
        crate::functional_status(
            "skade/object_store/memory",
            "backend_constructed",
            true,
            "in-memory ObjectStore",
        );
        Self::default()
    }

    /// Number of objects currently held (test helper).
    pub fn len(&self) -> usize {
        self.inner.read().unwrap().len()
    }

    /// Whether the store holds no objects.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[async_trait]
impl ObjectStore for MemoryStore {
    async fn put(&self, key: &str, bytes: Bytes) -> Result<()> {
        self.inner.write().unwrap().insert(key.to_string(), bytes);
        Ok(())
    }

    async fn get(&self, key: &str) -> Result<Bytes> {
        self.inner
            .read()
            .unwrap()
            .get(key)
            .cloned()
            .ok_or_else(|| SkadeError::Other(format!("object not found: {key}")))
    }

    async fn list(&self, prefix: &str) -> Result<Vec<String>> {
        Ok(self
            .inner
            .read()
            .unwrap()
            .keys()
            .filter(|k| k.starts_with(prefix))
            .cloned()
            .collect())
    }

    async fn delete(&self, key: &str) -> Result<()> {
        self.inner.write().unwrap().remove(key);
        Ok(())
    }

    async fn exists(&self, key: &str) -> Result<bool> {
        Ok(self.inner.read().unwrap().contains_key(key))
    }

    async fn size(&self, key: &str) -> Result<Option<u64>> {
        Ok(self.inner.read().unwrap().get(key).map(|b| b.len() as u64))
    }
}

// ───────────────────────── LocalFsStore (feature rustfs) ─────────────────────

/// An embedded, zero-external-dependency [`ObjectStore`] backed by a local
/// directory. Keys map to paths under `root`; this is the "rustfs" backend —
/// a real persistent store with no S3 server and no extra crates, ideal for
/// single-host deployments and CI.
///
/// (The `rustfs` *crate* on crates.io is a full distributed object-storage
/// *server*, not an embeddable client; the zero-dep local store this feature
/// provides is what consumers actually want for "local object store".)
#[cfg(feature = "rustfs")]
#[derive(Debug, Clone)]
pub struct LocalFsStore {
    root: std::path::PathBuf,
}

#[cfg(feature = "rustfs")]
impl LocalFsStore {
    /// Open (creating if absent) a store rooted at `root`.
    pub fn new(root: impl Into<std::path::PathBuf>) -> Result<Self> {
        let root = root.into();
        std::fs::create_dir_all(&root)?;
        // Object-store backend marker: the local-fs (rustfs) backend is ready.
        crate::functional_status(
            "skade/object_store/rustfs",
            "backend_constructed",
            true,
            &root.display().to_string(),
        );
        Ok(Self { root })
    }

    fn path_for(&self, key: &str) -> std::path::PathBuf {
        // Keys are slash-separated; join component-wise so it works on any OS
        // and stays under `root` (leading slashes ignored).
        let mut p = self.root.clone();
        for comp in key
            .split('/')
            .filter(|c| !c.is_empty() && *c != "." && *c != "..")
        {
            p.push(comp);
        }
        p
    }
}

#[cfg(feature = "rustfs")]
#[async_trait]
impl ObjectStore for LocalFsStore {
    async fn put(&self, key: &str, bytes: Bytes) -> Result<()> {
        let path = self.path_for(key);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&path, &bytes)?;
        Ok(())
    }

    async fn get(&self, key: &str) -> Result<Bytes> {
        let path = self.path_for(key);
        Ok(Bytes::from(std::fs::read(&path)?))
    }

    async fn list(&self, prefix: &str) -> Result<Vec<String>> {
        let mut out = Vec::new();
        let root = self.root.clone();
        let prefix = prefix.to_string();
        // Walk the tree; emit keys (root-relative, slash-joined) under `prefix`.
        let mut stack = vec![root.clone()];
        while let Some(dir) = stack.pop() {
            let rd = match std::fs::read_dir(&dir) {
                Ok(rd) => rd,
                Err(_) => continue,
            };
            for entry in rd.flatten() {
                let p = entry.path();
                if p.is_dir() {
                    stack.push(p);
                } else if let Ok(rel) = p.strip_prefix(&root) {
                    let key = rel
                        .components()
                        .map(|c| c.as_os_str().to_string_lossy())
                        .collect::<Vec<_>>()
                        .join("/");
                    if key.starts_with(&prefix) {
                        out.push(key);
                    }
                }
            }
        }
        Ok(out)
    }

    async fn delete(&self, key: &str) -> Result<()> {
        let path = self.path_for(key);
        match std::fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.into()),
        }
    }

    async fn exists(&self, key: &str) -> Result<bool> {
        Ok(self.path_for(key).is_file())
    }

    async fn size(&self, key: &str) -> Result<Option<u64>> {
        Ok(std::fs::metadata(self.path_for(key)).ok().map(|m| m.len()))
    }
}

// ───────────────────────── S3 config (shared shape) ─────────────────────────

/// Connection settings for an S3-compatible endpoint (MinIO, AWS, RustFS, …).
///
/// Shared by the [`RustS3Store`] (`s3`) and [`AwsS3Store`] (`aws-s3`) backends
/// so a consumer can swap SDKs without touching its config. `endpoint` is the
/// custom MinIO URL (e.g. `http://minio:9000`); leave it empty for real AWS.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct S3Config {
    /// Custom S3 endpoint URL (MinIO/RustFS). Empty → default AWS endpoints.
    pub endpoint: String,
    /// Region (MinIO ignores it but SigV4 needs a value; use `us-east-1`).
    pub region: String,
    /// Bucket the warehouse lives in.
    pub bucket: String,
    /// Access key id.
    pub access_key_id: String,
    /// Secret access key.
    pub secret_access_key: String,
    /// Path-style addressing (`http://host/bucket/key`). Required for MinIO.
    pub path_style: bool,
}

impl Default for S3Config {
    fn default() -> Self {
        Self {
            endpoint: String::new(),
            region: "us-east-1".to_string(),
            bucket: String::new(),
            access_key_id: String::new(),
            secret_access_key: String::new(),
            path_style: true,
        }
    }
}

impl S3Config {
    /// Map an iceberg location (`s3://bucket/key`, or a bare key) to the S3 key.
    /// Used only by the S3 backends; harmless dead code without them.
    #[cfg_attr(not(any(feature = "s3", feature = "aws-s3")), allow(dead_code))]
    fn strip_to_key<'a>(&self, path: &'a str) -> &'a str {
        let with_bucket = format!("s3://{}/", self.bucket);
        if let Some(k) = path.strip_prefix(&with_bucket) {
            return k;
        }
        if let Some(rest) = path.strip_prefix("s3://") {
            return rest.splitn(2, '/').nth(1).unwrap_or("");
        }
        path
    }
}

// ───────────────────────── RustS3Store (feature s3) ─────────────────────────

/// An [`ObjectStore`] over an S3-compatible endpoint using **rust-s3**.
///
/// This is skade's default S3 backend (feature `s3`). Points at any custom
/// MinIO/RustFS endpoint via [`S3Config::endpoint`] with path-style addressing.
///
/// > Note: `rust-s3` uses `maybe-async`. In a workspace that also links `gix`
/// > (which flips `maybe-async` to `is_sync` globally) `rust-s3` will not
/// > compile — use the [`AwsS3Store`] (`aws-s3`) backend there instead. The
/// > published skade crate has its own detached workspace, so the `s3` feature
/// > builds cleanly for direct consumers.
#[cfg(feature = "s3")]
#[derive(Clone)]
pub struct RustS3Store {
    cfg: S3Config,
    bucket: Box<s3::Bucket>,
}

#[cfg(feature = "s3")]
impl std::fmt::Debug for RustS3Store {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RustS3Store")
            .field("endpoint", &self.cfg.endpoint)
            .field("bucket", &self.cfg.bucket)
            .finish()
    }
}

#[cfg(feature = "s3")]
impl RustS3Store {
    /// Build a store from `cfg`. Does not contact the endpoint.
    pub fn new(cfg: S3Config) -> Result<Self> {
        use s3::creds::Credentials;
        use s3::{Bucket, Region};

        let region = if cfg.endpoint.is_empty() {
            cfg.region
                .parse()
                .map_err(|e| SkadeError::other(format!("invalid region: {e}")))?
        } else {
            Region::Custom {
                region: cfg.region.clone(),
                endpoint: cfg.endpoint.clone(),
            }
        };
        let creds = Credentials::new(
            Some(&cfg.access_key_id),
            Some(&cfg.secret_access_key),
            None,
            None,
            None,
        )
        .map_err(|e| SkadeError::other(format!("s3 credentials: {e}")))?;
        let mut bucket = Bucket::new(&cfg.bucket, region, creds)
            .map_err(|e| SkadeError::other(format!("s3 bucket: {e}")))?;
        if cfg.path_style {
            bucket.set_path_style();
        }
        // Object-store backend marker: the rust-s3 (s3) backend is configured.
        // Does not contact the endpoint, so this is "constructed", not "reachable".
        crate::functional_status(
            "skade/object_store/s3",
            "backend_constructed",
            true,
            &cfg.bucket,
        );
        Ok(Self { cfg, bucket })
    }
}

#[cfg(feature = "s3")]
#[async_trait]
impl ObjectStore for RustS3Store {
    async fn put(&self, key: &str, bytes: Bytes) -> Result<()> {
        let k = self.cfg.strip_to_key(key);
        self.bucket
            .put_object(k, &bytes)
            .await
            .map_err(|e| SkadeError::other(format!("s3 put {k}: {e}")))?;
        Ok(())
    }

    async fn get(&self, key: &str) -> Result<Bytes> {
        let k = self.cfg.strip_to_key(key);
        let resp = self
            .bucket
            .get_object(k)
            .await
            .map_err(|e| SkadeError::other(format!("s3 get {k}: {e}")))?;
        Ok(Bytes::from(resp.to_vec()))
    }

    async fn get_range(&self, key: &str, range: Range<u64>) -> Result<Bytes> {
        if range.end <= range.start {
            return Ok(Bytes::new());
        }
        let k = self.cfg.strip_to_key(key);
        // rust-s3 takes an inclusive end; iceberg's range is exclusive.
        let resp = self
            .bucket
            .get_object_range(k, range.start, Some(range.end - 1))
            .await
            .map_err(|e| SkadeError::other(format!("s3 get_range {k}: {e}")))?;
        Ok(Bytes::from(resp.to_vec()))
    }

    async fn list(&self, prefix: &str) -> Result<Vec<String>> {
        let p = self.cfg.strip_to_key(prefix).to_string();
        let results = self
            .bucket
            .list(p, None)
            .await
            .map_err(|e| SkadeError::other(format!("s3 list: {e}")))?;
        let mut out = Vec::new();
        for page in results {
            for obj in page.contents {
                out.push(obj.key);
            }
        }
        Ok(out)
    }

    async fn delete(&self, key: &str) -> Result<()> {
        let k = self.cfg.strip_to_key(key);
        self.bucket
            .delete_object(k)
            .await
            .map_err(|e| SkadeError::other(format!("s3 delete {k}: {e}")))?;
        Ok(())
    }

    async fn exists(&self, key: &str) -> Result<bool> {
        let k = self.cfg.strip_to_key(key);
        match self.bucket.head_object(k).await {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    async fn size(&self, key: &str) -> Result<Option<u64>> {
        let k = self.cfg.strip_to_key(key);
        match self.bucket.head_object(k).await {
            Ok((head, _)) => Ok(head.content_length.map(|l| l as u64)),
            Err(_) => Ok(None),
        }
    }
}

// ───────────────────────── AwsS3Store (feature aws-s3) ───────────────────────

/// An [`ObjectStore`] over an S3-compatible endpoint using the **aws-sdk-s3**
/// crate (feature `aws-s3`).
///
/// Use this when the consumer (e.g. Njord) already links `aws-sdk-s3` and wants
/// to avoid pulling a second S3 client. Points at a custom MinIO endpoint via
/// [`S3Config::endpoint`] + force-path-style.
#[cfg(feature = "aws-s3")]
#[derive(Debug, Clone)]
pub struct AwsS3Store {
    cfg: S3Config,
    client: aws_sdk_s3::Client,
}

#[cfg(feature = "aws-s3")]
impl AwsS3Store {
    /// Build a store from `cfg`. Does not contact the endpoint.
    pub async fn new(cfg: S3Config) -> Result<Self> {
        use aws_sdk_s3::config::{Credentials, Region};

        let creds = Credentials::new(
            cfg.access_key_id.clone(),
            cfg.secret_access_key.clone(),
            None,
            None,
            "skade-static",
        );
        let mut builder = aws_sdk_s3::Config::builder()
            .region(Region::new(cfg.region.clone()))
            .credentials_provider(creds)
            .force_path_style(cfg.path_style)
            .behavior_version(aws_sdk_s3::config::BehaviorVersion::latest());
        if !cfg.endpoint.is_empty() {
            builder = builder.endpoint_url(cfg.endpoint.clone());
        }
        let client = aws_sdk_s3::Client::from_conf(builder.build());
        // Object-store backend marker: the aws-sdk-s3 (aws-s3) backend is
        // configured. Does not contact the endpoint (constructed, not reachable).
        crate::functional_status(
            "skade/object_store/aws-s3",
            "backend_constructed",
            true,
            &cfg.bucket,
        );
        Ok(Self { cfg, client })
    }
}

#[cfg(feature = "aws-s3")]
#[async_trait]
impl ObjectStore for AwsS3Store {
    async fn put(&self, key: &str, bytes: Bytes) -> Result<()> {
        let k = self.cfg.strip_to_key(key);
        self.client
            .put_object()
            .bucket(&self.cfg.bucket)
            .key(k)
            .body(bytes.to_vec().into())
            .send()
            .await
            .map_err(|e| SkadeError::other(format!("aws-s3 put {k}: {e}")))?;
        Ok(())
    }

    async fn get(&self, key: &str) -> Result<Bytes> {
        let k = self.cfg.strip_to_key(key);
        let resp = self
            .client
            .get_object()
            .bucket(&self.cfg.bucket)
            .key(k)
            .send()
            .await
            .map_err(|e| SkadeError::other(format!("aws-s3 get {k}: {e}")))?;
        let data = resp
            .body
            .collect()
            .await
            .map_err(|e| SkadeError::other(format!("aws-s3 body {k}: {e}")))?;
        Ok(data.into_bytes())
    }

    async fn get_range(&self, key: &str, range: Range<u64>) -> Result<Bytes> {
        if range.end <= range.start {
            return Ok(Bytes::new());
        }
        let k = self.cfg.strip_to_key(key);
        // HTTP Range header is inclusive; iceberg's range is exclusive.
        let header = format!("bytes={}-{}", range.start, range.end - 1);
        let resp = self
            .client
            .get_object()
            .bucket(&self.cfg.bucket)
            .key(k)
            .range(header)
            .send()
            .await
            .map_err(|e| SkadeError::other(format!("aws-s3 get_range {k}: {e}")))?;
        let data = resp
            .body
            .collect()
            .await
            .map_err(|e| SkadeError::other(format!("aws-s3 body {k}: {e}")))?;
        Ok(data.into_bytes())
    }

    async fn list(&self, prefix: &str) -> Result<Vec<String>> {
        let p = self.cfg.strip_to_key(prefix).to_string();
        let mut out = Vec::new();
        let mut token: Option<String> = None;
        loop {
            let mut req = self
                .client
                .list_objects_v2()
                .bucket(&self.cfg.bucket)
                .prefix(&p);
            if let Some(t) = &token {
                req = req.continuation_token(t);
            }
            let resp = req
                .send()
                .await
                .map_err(|e| SkadeError::other(format!("aws-s3 list: {e}")))?;
            for obj in resp.contents() {
                if let Some(k) = obj.key() {
                    out.push(k.to_string());
                }
            }
            if resp.is_truncated().unwrap_or(false) {
                token = resp.next_continuation_token().map(|s| s.to_string());
                if token.is_none() {
                    break;
                }
            } else {
                break;
            }
        }
        Ok(out)
    }

    async fn delete(&self, key: &str) -> Result<()> {
        let k = self.cfg.strip_to_key(key);
        self.client
            .delete_object()
            .bucket(&self.cfg.bucket)
            .key(k)
            .send()
            .await
            .map_err(|e| SkadeError::other(format!("aws-s3 delete {k}: {e}")))?;
        Ok(())
    }

    async fn exists(&self, key: &str) -> Result<bool> {
        let k = self.cfg.strip_to_key(key);
        match self
            .client
            .head_object()
            .bucket(&self.cfg.bucket)
            .key(k)
            .send()
            .await
        {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    async fn size(&self, key: &str) -> Result<Option<u64>> {
        let k = self.cfg.strip_to_key(key);
        match self
            .client
            .head_object()
            .bucket(&self.cfg.bucket)
            .key(k)
            .send()
            .await
        {
            Ok(h) => Ok(h.content_length().map(|l| l as u64)),
            Err(_) => Ok(None),
        }
    }
}

// ─────────────────── iceberg StorageFactory / Storage bridge ─────────────────

pub use bridge::ObjectStoreFactory;

mod bridge {
    use std::ops::Range;
    use std::sync::Arc;

    use async_trait::async_trait;
    use bytes::Bytes;
    use iceberg::io::{
        FileMetadata, FileRead, FileWrite, InputFile, OutputFile, Storage, StorageConfig,
        StorageFactory,
    };
    use iceberg::{Error, ErrorKind, Result as IceResult};
    use serde::{Deserialize, Serialize};

    use super::ObjectStore;

    fn ice_err(e: impl std::fmt::Display) -> Error {
        Error::new(ErrorKind::Unexpected, e.to_string())
    }

    /// A serializable description of which [`ObjectStore`] backend to build.
    ///
    /// iceberg's `StorageFactory` is `#[typetag::serde]` (it must round-trip
    /// through config), and a live SDK client is not serializable — so the
    /// factory carries this config and constructs the store in `build()`,
    /// exactly as the iceberg S3 FileIO does.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub enum ObjectStoreConfig {
        /// In-process [`MemoryStore`](super::MemoryStore).
        Memory,
        /// Local filesystem store rooted at a directory (feature `rustfs`).
        #[cfg(feature = "rustfs")]
        LocalFs { root: std::path::PathBuf },
        /// rust-s3 backend (feature `s3`).
        #[cfg(feature = "s3")]
        RustS3(super::S3Config),
        /// aws-sdk-s3 backend (feature `aws-s3`).
        #[cfg(feature = "aws-s3")]
        AwsS3(super::S3Config),
    }

    /// An iceberg [`StorageFactory`] that bridges a [`ObjectStore`] into the
    /// iceberg `FileIO` machinery. Built either from a serializable
    /// [`ObjectStoreConfig`] (so it survives the typetag round-trip) or, for
    /// in-process use, from a live `Arc<dyn ObjectStore>`.
    #[derive(Debug, Clone)]
    pub struct ObjectStoreFactory {
        config: ObjectStoreConfig,
        // A pre-built store (in-process path). Not serialized; rebuilt from
        // `config` after a typetag round-trip.
        live: Option<Arc<dyn ObjectStore>>,
    }

    impl ObjectStoreFactory {
        /// A factory from a serializable backend config (survives serialize).
        pub fn from_config(config: ObjectStoreConfig) -> Self {
            Self { config, live: None }
        }

        /// A factory wrapping an already-constructed store. Carries
        /// [`ObjectStoreConfig::Memory`] as its serialized form, so this is for
        /// in-process warehouses (the live store is not persisted across a
        /// typetag round-trip).
        pub fn from_store(store: Arc<dyn ObjectStore>) -> Self {
            Self {
                config: ObjectStoreConfig::Memory,
                live: Some(store),
            }
        }

        fn build_store(&self) -> IceResult<Arc<dyn ObjectStore>> {
            if let Some(s) = &self.live {
                return Ok(s.clone());
            }
            match &self.config {
                ObjectStoreConfig::Memory => Ok(Arc::new(super::MemoryStore::new())),
                #[cfg(feature = "rustfs")]
                ObjectStoreConfig::LocalFs { root } => Ok(Arc::new(
                    super::LocalFsStore::new(root.clone()).map_err(ice_err)?,
                )),
                #[cfg(feature = "s3")]
                ObjectStoreConfig::RustS3(cfg) => Ok(Arc::new(
                    super::RustS3Store::new(cfg.clone()).map_err(ice_err)?,
                )),
                #[cfg(feature = "aws-s3")]
                ObjectStoreConfig::AwsS3(cfg) => {
                    // build() is sync; bridge the async constructor.
                    let cfg = cfg.clone();
                    let store = futures::executor::block_on(super::AwsS3Store::new(cfg))
                        .map_err(ice_err)?;
                    Ok(Arc::new(store))
                }
            }
        }
    }

    // The factory serializes as its config (the live store, if any, is dropped
    // — a typetag round-trip rebuilds from config, the documented contract).
    impl Serialize for ObjectStoreFactory {
        fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
            self.config.serialize(s)
        }
    }
    impl<'de> Deserialize<'de> for ObjectStoreFactory {
        fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
            Ok(Self::from_config(ObjectStoreConfig::deserialize(d)?))
        }
    }

    #[typetag::serde(name = "skade_object_store")]
    impl StorageFactory for ObjectStoreFactory {
        fn build(&self, _config: &StorageConfig) -> IceResult<Arc<dyn Storage>> {
            Ok(Arc::new(ObjectStoreBridge {
                store: self.build_store()?,
            }))
        }
    }

    /// Wraps an [`ObjectStore`] as an iceberg [`Storage`]. Iceberg passes
    /// absolute locations (`s3://…` or `file://…` or bare); the underlying
    /// store maps those to its own key space.
    #[derive(Debug, Clone)]
    struct ObjectStoreBridge {
        store: Arc<dyn ObjectStore>,
    }

    // Serialize as nothing meaningful — a built Storage is rebuilt by the
    // factory, never deserialized standalone in our flow. typetag still
    // requires the impls.
    impl Serialize for ObjectStoreBridge {
        fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
            s.serialize_unit()
        }
    }
    impl<'de> Deserialize<'de> for ObjectStoreBridge {
        fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
            <()>::deserialize(d)?;
            Ok(ObjectStoreBridge {
                store: Arc::new(super::MemoryStore::new()),
            })
        }
    }

    #[typetag::serde(name = "skade_object_store_bridge")]
    #[async_trait]
    impl Storage for ObjectStoreBridge {
        async fn exists(&self, path: &str) -> IceResult<bool> {
            self.store.exists(path).await.map_err(ice_err)
        }

        async fn metadata(&self, path: &str) -> IceResult<FileMetadata> {
            let size = self.store.size(path).await.map_err(ice_err)?.unwrap_or(0);
            Ok(FileMetadata { size })
        }

        async fn read(&self, path: &str) -> IceResult<Bytes> {
            self.store.get(path).await.map_err(ice_err)
        }

        async fn reader(&self, path: &str) -> IceResult<Box<dyn FileRead>> {
            Ok(Box::new(ObjectStoreFileRead {
                store: self.store.clone(),
                key: path.to_string(),
            }))
        }

        async fn write(&self, path: &str, bs: Bytes) -> IceResult<()> {
            self.store.put(path, bs).await.map_err(ice_err)
        }

        async fn writer(&self, path: &str) -> IceResult<Box<dyn FileWrite>> {
            Ok(Box::new(ObjectStoreFileWrite {
                store: self.store.clone(),
                key: path.to_string(),
                buf: Vec::new(),
            }))
        }

        async fn delete(&self, path: &str) -> IceResult<()> {
            self.store.delete(path).await.map_err(ice_err)
        }

        async fn delete_prefix(&self, path: &str) -> IceResult<()> {
            for k in self.store.list(path).await.map_err(ice_err)? {
                self.store.delete(&k).await.map_err(ice_err)?;
            }
            Ok(())
        }

        fn new_input(&self, path: &str) -> IceResult<InputFile> {
            Ok(InputFile::new(Arc::new(self.clone()), path.to_string()))
        }

        fn new_output(&self, path: &str) -> IceResult<OutputFile> {
            Ok(OutputFile::new(Arc::new(self.clone()), path.to_string()))
        }
    }

    struct ObjectStoreFileRead {
        store: Arc<dyn ObjectStore>,
        key: String,
    }

    #[async_trait]
    impl FileRead for ObjectStoreFileRead {
        async fn read(&self, range: Range<u64>) -> IceResult<Bytes> {
            self.store
                .get_range(&self.key, range)
                .await
                .map_err(ice_err)
        }
    }

    /// Buffer-then-PUT-on-close writer (iceberg writes a whole file then closes).
    struct ObjectStoreFileWrite {
        store: Arc<dyn ObjectStore>,
        key: String,
        buf: Vec<u8>,
    }

    #[async_trait]
    impl FileWrite for ObjectStoreFileWrite {
        async fn write(&mut self, bs: Bytes) -> IceResult<()> {
            self.buf.extend_from_slice(&bs);
            Ok(())
        }

        async fn close(&mut self) -> IceResult<()> {
            let bytes = Bytes::from(std::mem::take(&mut self.buf));
            self.store.put(&self.key, bytes).await.map_err(ice_err)
        }
    }
}

pub use bridge::ObjectStoreConfig;
