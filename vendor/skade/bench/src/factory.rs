//! Catalog constructors. Both nornir and the REST client implement
//! `iceberg::CatalogBuilder`, so construction is uniform.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Result;
use iceberg::io::LocalFsStorageFactory;
use iceberg::CatalogBuilder;
#[cfg(feature = "rest")]
use iceberg_catalog_rest::{RestCatalogBuilder, REST_CATALOG_PROP_URI, REST_CATALOG_PROP_WAREHOUSE};
use skade_katalog::{RedbCatalog, RedbCatalogBuilder, WriteDurability};
use tempfile::TempDir;

#[cfg(feature = "s3")]
use crate::s3_storage::{ensure_bucket, S3Cfg, S3StorageFactory};

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

/// Destination #1 — PCIe-4.0 **NVMe** scratch (`/path/to/scratch`). The repo
/// lives on the T9 USB drive, which would skew measurements; keep measured I/O
/// here. Override with `BENCH_NVME_DIR`.
pub fn nvme_dir() -> PathBuf {
    let dir = PathBuf::from(env_or("BENCH_NVME_DIR", "/path/to/scratch"));
    std::fs::create_dir_all(&dir).ok();
    dir
}

/// Destination #2 — fastest **RAM**-backed tmpfs (`/dev/shm`). Note `/var/tmp` is
/// disk-backed (xfs) on this box, so `/dev/shm` is the real RAM dest. Override
/// with `BENCH_RAM_DIR`.
pub fn ram_dir() -> PathBuf {
    let dir = PathBuf::from(env_or("BENCH_RAM_DIR", "/dev/shm"));
    std::fs::create_dir_all(&dir).ok();
    dir
}

/// Default work dir (NVMe). Legacy `BENCH_WORK_DIR` still overrides it.
fn work_dir() -> PathBuf {
    match std::env::var("BENCH_WORK_DIR") {
        Ok(d) if !d.is_empty() => {
            let p = PathBuf::from(d);
            std::fs::create_dir_all(&p).ok();
            p
        }
        _ => nvme_dir(),
    }
}

/// A throwaway temp dir on the fast NVMe (not T9).
fn bench_tempdir() -> Result<TempDir> {
    Ok(TempDir::new_in(work_dir())?)
}

/// Shared S3 connection config for the RustFS warehouse, from `BENCH_S3_*`
/// envs (defaults match `containers/rustfs_up.sh`).
#[cfg(feature = "s3")]
pub fn bench_s3_cfg() -> S3Cfg {
    S3Cfg {
        endpoint: env_or("BENCH_S3_ENDPOINT", "http://localhost:9000"),
        region: env_or("BENCH_S3_REGION", "us-east-1"),
        bucket: env_or("BENCH_S3_BUCKET", "warehouse"),
        access_key_id: env_or("BENCH_S3_ACCESS_KEY", "rustfsadmin"),
        secret_access_key: env_or("BENCH_S3_SECRET_KEY", "rustfsadmin"),
        path_style: true,
    }
}

fn durability_from_env() -> WriteDurability {
    match std::env::var("BENCH_DURABILITY").unwrap_or_default().to_ascii_lowercase().as_str() {
        "eventual" => WriteDurability::Eventual,
        "none" => WriteDurability::None,
        _ => WriteDurability::Immediate,
    }
}

/// Embedded nornir catalog over a throwaway temp dir (the real deployment).
/// Returns the concrete type so the nornir-only `resolve_metadata` fast path
/// can also be measured. The `TempDir` must be kept alive for the run.
pub async fn embedded() -> Result<(RedbCatalog, TempDir)> {
    let tmp = bench_tempdir()?;
    let cat = embedded_in(&tmp).await?;
    Ok((cat, tmp))
}

/// Embedded nornir catalog whose warehouse + redb file live under `tmp` — used to
/// run the same scenario against multiple file destinations (NVMe vs RAM). The
/// caller owns the `TempDir` (build it with [`nvme_dir`] / [`ram_dir`] via
/// `TempDir::new_in`) and must keep it alive for the run.
pub async fn embedded_in(tmp: &TempDir) -> Result<RedbCatalog> {
    let warehouse = tmp.path().join("warehouse");
    std::fs::create_dir_all(&warehouse)?;
    let cat = RedbCatalogBuilder::default()
        .db_path(tmp.path().join("catalog.redb"))
        .warehouse_location(format!("file://{}", warehouse.display()))
        .durability(durability_from_env())
        .with_storage_factory(Arc::new(LocalFsStorageFactory))
        .load("skade", HashMap::new())
        .await?;
    Ok(cat)
}

/// A throwaway temp dir under an explicit destination root (NVMe or RAM).
pub fn tempdir_in(root: &std::path::Path) -> Result<TempDir> {
    Ok(TempDir::new_in(root)?)
}

/// Embedded nornir catalog whose **data warehouse is S3 (RustFS)**, while the
/// catalog itself stays in a local redb file. This is the data-plane sibling of
/// [`embedded`]: control-plane in redb, data files in object storage.
#[cfg(feature = "s3")]
pub async fn embedded_s3() -> Result<(RedbCatalog, TempDir)> {
    let cfg = bench_s3_cfg();
    ensure_bucket(&cfg).await?;
    let tmp = bench_tempdir()?;
    let cat = RedbCatalogBuilder::default()
        .db_path(tmp.path().join("catalog.redb"))
        .warehouse_location(format!("s3://{}/wh", cfg.bucket))
        .durability(durability_from_env())
        .with_storage_factory(Arc::new(S3StorageFactory::new(cfg)))
        .load("skade", HashMap::new())
        .await?;
    Ok((cat, tmp))
}

/// An Iceberg REST catalog client (Nessie or Polaris) backed by the shared S3
/// (RustFS) warehouse — the client's `FileIO` reads/writes data files there.
#[cfg(all(feature = "s3", feature = "rest"))]
pub async fn rest_s3(uri: &str, warehouse: &str) -> Result<iceberg_catalog_rest::RestCatalog> {
    let cfg = bench_s3_cfg();
    ensure_bucket(&cfg).await?;
    let mut props = HashMap::from([
        (REST_CATALOG_PROP_URI.to_string(), uri.to_string()),
        (REST_CATALOG_PROP_WAREHOUSE.to_string(), warehouse.to_string()),
    ]);
    if let Ok(extra) = std::env::var("BENCH_REST_PROPS") {
        for kv in extra.split(',').filter(|s| !s.trim().is_empty()) {
            if let Some((k, v)) = kv.split_once('=') {
                props.insert(k.trim().to_string(), v.trim().to_string());
            }
        }
    }
    let cat = RestCatalogBuilder::default()
        .with_storage_factory(Arc::new(S3StorageFactory::new(cfg)))
        .load("rest", props)
        .await?;
    Ok(cat)
}

// Stubs for the default (no-`s3`) build: callers (the nornir-bench example
// targets) still reference these symbols, so keep them resolvable and fail
// loudly at runtime instead of forcing every call site behind a cfg.
#[cfg(not(feature = "s3"))]
pub async fn embedded_s3() -> Result<(RedbCatalog, TempDir)> {
    anyhow::bail!("S3 backend not compiled — rebuild with `--features s3`")
}

#[cfg(all(not(feature = "s3"), feature = "rest"))]
pub async fn rest_s3(_uri: &str, _warehouse: &str) -> Result<iceberg_catalog_rest::RestCatalog> {
    anyhow::bail!("S3 backend not compiled — rebuild with `--features s3`")
}

/// Apache Polaris REST catalog (OAuth2). `table_exists` is storage-free and runs
/// cleanly; the table *write* path needs S3+STS (a FILE warehouse 503s under a
/// podman bind mount), so only the control-plane RPC is benched here. Credentials
/// default to `polaris_up.sh`'s (`root:s3cr3t`, `PRINCIPAL_ROLE:ALL`).
#[cfg(feature = "rest")]
pub async fn rest_polaris(uri: &str) -> Result<iceberg_catalog_rest::RestCatalog> {
    let cred = env_or("BENCH_POLARIS_CRED", "root:s3cr3t");
    let scope = env_or("BENCH_POLARIS_SCOPE", "PRINCIPAL_ROLE:ALL");
    let props = HashMap::from([
        (REST_CATALOG_PROP_URI.to_string(), uri.to_string()),
        (REST_CATALOG_PROP_WAREHOUSE.to_string(), "warehouse".to_string()),
        ("credential".to_string(), cred),
        ("scope".to_string(), scope),
    ]);
    let cat = RestCatalogBuilder::default()
        .with_storage_factory(Arc::new(LocalFsStorageFactory))
        .load("rest", props)
        .await?;
    Ok(cat)
}

/// An Iceberg REST catalog client (Nessie or Polaris) at `uri`.
///
/// NOTE: `load_table` makes the client read the metadata file from `warehouse`
/// via `FileIO`. For a containerized server the warehouse must be reachable
/// from *both* sides — use a shared object store (MinIO/S3) or a bind-mounted
/// local path. With a local `file://` warehouse this works only when the server
/// writes to a path the client can also read (e.g. a shared bind mount).
#[cfg(feature = "rest")]
pub async fn rest(uri: &str, warehouse: &str) -> Result<iceberg_catalog_rest::RestCatalog> {
    let mut props = HashMap::from([
        (REST_CATALOG_PROP_URI.to_string(), uri.to_string()),
        (REST_CATALOG_PROP_WAREHOUSE.to_string(), warehouse.to_string()),
    ]);
    // Polaris requires OAuth2; pass its standard Iceberg-REST props without a
    // code change, e.g. BENCH_REST_PROPS="credential=client:secret,scope=PRINCIPAL_ROLE:ALL".
    if let Ok(extra) = std::env::var("BENCH_REST_PROPS") {
        for kv in extra.split(',').filter(|s| !s.trim().is_empty()) {
            if let Some((k, v)) = kv.split_once('=') {
                props.insert(k.trim().to_string(), v.trim().to_string());
            }
        }
    }
    let cat = RestCatalogBuilder::default()
        .with_storage_factory(Arc::new(LocalFsStorageFactory))
        .load("rest", props)
        .await?;
    Ok(cat)
}
