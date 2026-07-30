//! An S3 `StorageFactory` for the iceberg-rust 0.9.1 client, backed by **aegir**
//! (our pure-Rust S3 client — SigV4 over ureq, zero-copy reads).
//!
//! iceberg 0.9.1 ships only `LocalFsStorageFactory` / `MemoryStorageFactory` but
//! exposes the `Storage` + `StorageFactory` traits as the extension point. This
//! implements them over aegir, so the same `iceberg::Catalog` (nornir embedded,
//! or the REST client to Nessie/Polaris) reads/writes a real object store
//! (RustFS). aegir has **no `maybe-async`**, so it compiles alongside gix where
//! rust-s3 can't. aegir's ops are blocking; the async `Storage` trait bridges via
//! `spawn_blocking`.

use std::ops::Range;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use aegir::Client;
use async_trait::async_trait;
use bytes::Bytes;
use tokio::sync::OnceCell;
use iceberg::io::{
    FileMetadata, FileRead, FileWrite, InputFile, OutputFile, Storage, StorageConfig,
    StorageFactory,
};
use iceberg::{Error, ErrorKind, Result};
use serde::{Deserialize, Serialize};

/// Connection config (all strings/bool, serializes cleanly; the live `Client` is
/// rebuilt from it).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct S3Cfg {
    pub endpoint: String,
    pub region: String,
    pub bucket: String,
    pub access_key_id: String,
    pub secret_access_key: String,
    /// Path-style addressing — aegir always uses it (kept for serde compat).
    pub path_style: bool,
}

fn err(e: impl std::fmt::Display) -> Error {
    Error::new(ErrorKind::Unexpected, e.to_string())
}

/// A transient connection drop worth retrying (RustFS closes idle pooled conns
/// under sustained heavy I/O). GET/PUT to a fixed key are idempotent.
fn is_transient(msg: &str) -> bool {
    let m = msg.to_ascii_lowercase();
    [
        "connection closed", "connection reset", "connection error", "message completed",
        "broken pipe", "timed out", "timeout", "unexpected eof", "incomplete",
        "os error 104", "os error 32",
    ]
    .iter()
    .any(|p| m.contains(p))
}

/// Retry an idempotent aegir op on transient failures (sync — runs inside
/// `spawn_blocking`). 100ms → 2s, 5 attempts.
fn retry<T>(what: &str, mut op: impl FnMut() -> aegir::Result<T>) -> Result<T> {
    let mut delay = Duration::from_millis(100);
    let mut last = String::new();
    for attempt in 1..=5u32 {
        match op() {
            Ok(v) => return Ok(v),
            Err(e) => {
                last = e.to_string();
                if attempt == 5 || !is_transient(&last) {
                    return Err(err(format!("{what} failed (attempt {attempt}/5): {last}")));
                }
                std::thread::sleep(delay);
                delay = (delay * 2).min(Duration::from_secs(2));
            }
        }
    }
    Err(err(format!("{what} exhausted retries: {last}")))
}

/// Run a blocking closure on the blocking pool, mapping the JoinError.
async fn blocking<T, F>(f: F) -> Result<T>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T> + Send + 'static,
{
    tokio::task::spawn_blocking(f).await.map_err(err)?
}

fn client(cfg: &S3Cfg) -> Client {
    Client::new(
        cfg.endpoint.as_str(),
        cfg.region.as_str(),
        cfg.access_key_id.as_str(),
        cfg.secret_access_key.as_str(),
    )
}

/// Create the warehouse bucket if absent (idempotent).
pub async fn ensure_bucket(cfg: &S3Cfg) -> Result<()> {
    let (c, b) = (client(cfg), cfg.bucket.clone());
    blocking(move || c.create_bucket(&b).map_err(err)).await
}

/// `StorageFactory` that builds S3-backed [`Storage`] instances.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct S3StorageFactory {
    cfg: S3Cfg,
}

impl S3StorageFactory {
    pub fn new(cfg: S3Cfg) -> Self {
        Self { cfg }
    }
}

#[typetag::serde]
impl StorageFactory for S3StorageFactory {
    fn build(&self, _config: &StorageConfig) -> Result<Arc<dyn Storage>> {
        Ok(Arc::new(S3Storage::new(self.cfg.clone())?))
    }
}

/// S3-backed [`Storage`]. Holds the config (serializable) + a live aegir client.
#[derive(Debug, Clone)]
pub struct S3Storage {
    cfg: S3Cfg,
    client: Client,
    bucket: String,
    bucket_prefix: String,
}

impl S3Storage {
    pub fn new(cfg: S3Cfg) -> Result<Self> {
        let client = client(&cfg);
        let bucket = cfg.bucket.clone();
        let bucket_prefix = format!("s3://{}/", cfg.bucket);
        Ok(Self { cfg, client, bucket, bucket_prefix })
    }

    /// Map an iceberg location (`s3://bucket/key`, or a bare key) to the S3 key.
    fn key<'a>(&self, path: &'a str) -> &'a str {
        if let Some(k) = path.strip_prefix(&self.bucket_prefix) {
            return k;
        }
        if let Some(rest) = path.strip_prefix("s3://") {
            return rest.splitn(2, '/').nth(1).unwrap_or("");
        }
        path
    }
}

impl Serialize for S3Storage {
    fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        self.cfg.serialize(s)
    }
}

impl<'de> Deserialize<'de> for S3Storage {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        let cfg = S3Cfg::deserialize(d)?;
        S3Storage::new(cfg).map_err(serde::de::Error::custom)
    }
}

#[typetag::serde]
#[async_trait]
impl Storage for S3Storage {
    async fn metadata(&self, path: &str) -> Result<FileMetadata> {
        let (c, b, k) = (self.client.clone(), self.bucket.clone(), self.key(path).to_string());
        let size = blocking(move || retry("head_object", || c.head_size(&b, &k))).await?;
        Ok(FileMetadata { size: size.unwrap_or(0) })
    }

    async fn exists(&self, path: &str) -> Result<bool> {
        let (c, b, k) = (self.client.clone(), self.bucket.clone(), self.key(path).to_string());
        blocking(move || c.head_object(&b, &k).map_err(err)).await
    }

    async fn read(&self, path: &str) -> Result<Bytes> {
        let (c, b, k) = (self.client.clone(), self.bucket.clone(), self.key(path).to_string());
        blocking(move || retry("get_object", || c.get_object(&b, &k))).await
    }

    async fn reader(&self, path: &str) -> Result<Box<dyn FileRead>> {
        Ok(Box::new(S3FileRead {
            client: self.client.clone(),
            bucket: self.bucket.clone(),
            key: self.key(path).to_string(),
            whole: OnceCell::new(),
            range_reads: AtomicUsize::new(0),
            object_gets: AtomicUsize::new(0),
            whole_file_cap: whole_file_cap(),
        }))
    }

    async fn write(&self, path: &str, bs: Bytes) -> Result<()> {
        let (c, b, k) = (self.client.clone(), self.bucket.clone(), self.key(path).to_string());
        blocking(move || retry("put_object", || c.put_object(&b, &k, &bs, None))).await
    }

    async fn writer(&self, path: &str) -> Result<Box<dyn FileWrite>> {
        Ok(Box::new(S3FileWrite {
            client: self.client.clone(),
            bucket: self.bucket.clone(),
            key: self.key(path).to_string(),
            buf: Vec::new(),
        }))
    }

    async fn delete(&self, path: &str) -> Result<()> {
        let (c, b, k) = (self.client.clone(), self.bucket.clone(), self.key(path).to_string());
        blocking(move || c.delete_object(&b, &k).map_err(err)).await
    }

    async fn delete_prefix(&self, path: &str) -> Result<()> {
        let (c, b, prefix) = (self.client.clone(), self.bucket.clone(), self.key(path).to_string());
        blocking(move || {
            for k in c.list_objects(&b, &prefix).map_err(err)? {
                c.delete_object(&b, &k).map_err(err)?;
            }
            Ok(())
        })
        .await
    }

    fn new_input(&self, path: &str) -> Result<InputFile> {
        Ok(InputFile::new(Arc::new(self.clone()), path.to_string()))
    }

    fn new_output(&self, path: &str) -> Result<OutputFile> {
        Ok(OutputFile::new(Arc::new(self.clone()), path.to_string()))
    }
}

/// Default whole-file read-ahead cap (bytes). A file at or under this size is
/// fetched once with a single GET and all subsequent `read(range)` calls are
/// served as zero-copy slices of that cached body — this collapses the many
/// sequential per-column-chunk ranged GETs the Parquet reader would otherwise
/// issue (the S3 scan-throughput root cause) into one round-trip. Files larger
/// than the cap keep using ranged GETs. Override with
/// `BENCH_S3_WHOLE_FILE_CAP` (bytes). Default 64 MiB — bench Parquet files are
/// well under it.
const WHOLE_FILE_CAP_DEFAULT: u64 = 64 * 1024 * 1024;

fn whole_file_cap() -> u64 {
    std::env::var("BENCH_S3_WHOLE_FILE_CAP")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(WHOLE_FILE_CAP_DEFAULT)
}

/// Read-ahead-coalescing reader. The Parquet reader issues many small ranged
/// reads (footer, then one per column chunk) against the *same* object. Issuing
/// one blocking GET per range serializes them on S3 round-trips. Instead, on the
/// first `read` we fetch the **whole object** once (when it fits under
/// `whole_file_cap`) and serve every range as a slice — turning N sequential
/// GETs into one. Concurrent `read` calls for the same file all await the single
/// shared fetch via the `OnceCell`. Oversized files fall back to ranged GETs.
struct S3FileRead {
    client: Client,
    bucket: String,
    key: String,
    /// The whole object, fetched at most once (lazily, shared across concurrent
    /// `read`s). `None` once fetched means the file was over the cap → use ranged
    /// GETs.
    whole: OnceCell<Option<Bytes>>,
    /// Count of ranged GETs actually issued to S3 (for the inject-and-assert test:
    /// the coalesced path issues 0 ranged GETs, the fallback path issues many).
    range_reads: AtomicUsize,
    /// Count of whole-object GETs issued (≤ 1 on the coalesced path).
    object_gets: AtomicUsize,
    whole_file_cap: u64,
}

impl S3FileRead {
    /// Fetch the whole object once if it fits the cap; cache it. Returns the
    /// cached body (or `None` when the object is too big to coalesce).
    async fn whole_body(&self) -> Result<&Option<Bytes>> {
        self.whole
            .get_or_try_init(|| async {
                let (c, b, k) = (self.client.clone(), self.bucket.clone(), self.key.clone());
                // HEAD the size first so we don't slurp a huge object into RAM.
                let size = blocking(move || retry("head_object", || c.head_size(&b, &k)))
                    .await?
                    .unwrap_or(0);
                if size > self.whole_file_cap {
                    return Ok(None);
                }
                let (c, b, k) = (self.client.clone(), self.bucket.clone(), self.key.clone());
                let body = blocking(move || retry("get_object", || c.get_object(&b, &k))).await?;
                self.object_gets.fetch_add(1, Ordering::AcqRel);
                Ok(Some(body))
            })
            .await
    }

    /// A single ranged GET (the fallback for oversized objects).
    async fn ranged(&self, range: Range<u64>) -> Result<Bytes> {
        // iceberg's range is exclusive; aegir/S3 byte range is inclusive.
        let (c, b, k, s, e) =
            (self.client.clone(), self.bucket.clone(), self.key.clone(), range.start, range.end - 1);
        self.range_reads.fetch_add(1, Ordering::AcqRel);
        blocking(move || retry("get_object_range", || c.get_object_range(&b, &k, s, e))).await
    }
}

#[async_trait]
impl FileRead for S3FileRead {
    async fn read(&self, range: Range<u64>) -> Result<Bytes> {
        if range.end <= range.start {
            return Ok(Bytes::new());
        }
        // Serve from the coalesced whole-object body when it fits the cap.
        if let Some(body) = self.whole_body().await? {
            let len = body.len() as u64;
            let start = range.start.min(len);
            let end = range.end.min(len);
            return Ok(body.slice(start as usize..end as usize));
        }
        // Oversized object: fall back to a ranged GET per call.
        self.ranged(range).await
    }
}

/// Buffering writer: iceberg writes a whole file then `close`s; we buffer and do
/// one PUT on close (fine for benchmark-sized files; no multipart bookkeeping).
struct S3FileWrite {
    client: Client,
    bucket: String,
    key: String,
    buf: Vec<u8>,
}

#[async_trait]
impl FileWrite for S3FileWrite {
    async fn write(&mut self, bs: Bytes) -> Result<()> {
        self.buf.extend_from_slice(&bs);
        Ok(())
    }

    async fn close(&mut self) -> Result<()> {
        let (c, b, k, buf) =
            (self.client.clone(), self.bucket.clone(), self.key.clone(), std::mem::take(&mut self.buf));
        blocking(move || retry("put_object", || c.put_object(&b, &k, &buf, None))).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build an `S3FileRead` with its whole-object cache pre-seeded to `body`, so
    /// the read-ahead/coalesce path can be exercised without a live S3 endpoint.
    fn seeded(body: &[u8]) -> S3FileRead {
        let r = S3FileRead {
            client: Client::new("http://localhost:0", "us-east-1", "ak", "sk"),
            bucket: "b".into(),
            key: "k".into(),
            whole: OnceCell::new(),
            range_reads: AtomicUsize::new(0),
            object_gets: AtomicUsize::new(0),
            whole_file_cap: WHOLE_FILE_CAP_DEFAULT,
        };
        r.whole.set(Some(Bytes::copy_from_slice(body))).unwrap();
        r
    }

    /// LAW (inject-and-assert): with a real object cached, many ranged `read`s
    /// (the Parquet footer-then-column-chunks access pattern) must each return the
    /// EXACT bytes of that range, and — crucially for the perf fix — issue ZERO
    /// ranged GETs to S3 (they're served as slices of the single coalesced body).
    /// This is the read-side concurrency/coalescing win: N sequential GETs → 1.
    #[tokio::test]
    async fn coalesced_reads_return_exact_bytes_and_issue_no_ranged_gets() {
        // Distinct bytes so a wrong slice is detectable.
        let body: Vec<u8> = (0..4096u32).map(|i| (i % 251) as u8).collect();
        let r = seeded(&body);

        // A spread of ranges, including the footer-like tail and the head.
        let ranges = [0u64..16, 100..200, 4000..4096, 2048..3072, 4095..4096];
        for rg in ranges {
            let got = r.read(rg.clone()).await.unwrap();
            assert_eq!(
                got.as_ref(),
                &body[rg.start as usize..rg.end as usize],
                "range {rg:?} returned wrong bytes"
            );
        }
        // An empty range is a no-op (no fetch).
        assert!(r.read(10..10).await.unwrap().is_empty());

        // The whole-file coalesce served every range: not one ranged GET issued,
        // and the seeded body counted as zero new object GETs.
        assert_eq!(r.range_reads.load(Ordering::Acquire), 0, "issued ranged GETs");
        assert_eq!(r.object_gets.load(Ordering::Acquire), 0);
    }

    /// A range past EOF is clamped, never panics on the slice (defends the
    /// `min(len)` clamp in `read`).
    #[tokio::test]
    async fn read_past_eof_is_clamped() {
        let r = seeded(b"hello");
        assert_eq!(r.read(3..99).await.unwrap().as_ref(), b"lo");
        assert_eq!(r.read(99..200).await.unwrap().as_ref(), b"");
    }
}
