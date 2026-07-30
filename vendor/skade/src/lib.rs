// Apache-2.0 licensed. See LICENSE-APACHE.

//! Pure-Rust, embedded Apache Iceberg catalog backed by [redb].
//!
//! `skade-katalog` implements the `iceberg::Catalog` trait against a
//! single-file [redb] database. All catalog metadata (namespaces, namespace
//! properties, table-pointer rows) lives inside one `.redb` file. Iceberg
//! table metadata JSON / Avro manifests / Parquet data files live in whatever
//! storage backend the supplied `FileIO` points at (local fs, S3, GCS, …).
//!
//! ## Why redb?
//!
//! * **Pure Rust** — no `libsqlite3`, no JVM, no Postgres process.
//! * **ACID** — every catalog mutation is a single redb `WriteTransaction`,
//!   so concurrent writers in the same process are serialized correctly and
//!   crashes leave the database consistent.
//! * **No async runtime** in the storage layer — redb is sync; the
//!   `Catalog` trait wrapper is async only because the trait demands it.
//! * **Multi-table atomic commits** — because every redb write transaction
//!   spans every table in the database, this crate exposes
//!   [`RedbCatalog::atomic_release`] which commits N
//!   `iceberg::TableCommit` values atomically. Useful when one logical
//!   release ("publish bench_runs + dep_graph + components together") must
//!   either succeed entirely or roll back entirely.
//!
//! ## Quickstart
//!
//! ```no_run
//! use std::sync::Arc;
//! use iceberg::CatalogBuilder;
//! use iceberg::io::LocalFsStorageFactory;
//! use skade_katalog::RedbCatalogBuilder;
//!
//! # async fn run() -> anyhow::Result<()> {
//! let catalog = RedbCatalogBuilder::default()
//!     .db_path("/var/lib/myapp/catalog.redb")
//!     .warehouse_location("file:///var/lib/myapp/warehouse")
//!     .with_storage_factory(Arc::new(LocalFsStorageFactory))
//!     .load("myapp", std::collections::HashMap::new())
//!     .await?;
//! # Ok(()) }
//! ```
//!
//! ## What this crate is NOT
//!
//! * Not a distributed catalog. Single-process. Multiple processes opening
//!   the same file will be rejected by redb's file lock.
//! * Not a REST endpoint. If you need that, run something like Lakekeeper.
//! * Not schema-evolution-complete: iceberg-rust 0.9.1 does not yet expose
//!   public `TransactionAction`s for schema mutations. That's an upstream
//!   gap; once 0.10 lands it will work here unchanged.

mod atomic;
mod builder;
mod catalog;
mod error;
mod git;
mod heal;
mod keys;
mod meta_cache;
mod pointer_cache;
mod static_index;
mod store;
mod table_cache;

pub use builder::{
    REDB_CATALOG_PROP_DB_PATH, REDB_CATALOG_PROP_DURABILITY,
    REDB_CATALOG_PROP_METADATA_CACHE_BYTES, REDB_CATALOG_PROP_TABLE_HANDLE_CACHE_CAPACITY,
    REDB_CATALOG_PROP_WAREHOUSE, RedbCatalogBuilder, WriteDurability,
};
pub use catalog::RedbCatalog;
pub use error::RedbCatalogError;
pub use git::{BranchRetention, RefEntry, RefKind};
pub use heal::HealOutcome;
pub use meta_cache::DEFAULT_METADATA_CACHE_BYTES;
pub use store::{COMMIT_EVENT_BUFFER, CommitEvent};
pub use table_cache::DEFAULT_TABLE_HANDLE_CACHE_CAPACITY;

/// Benchmark-only pub hook onto the `pub(crate)` redb key builders.
///
/// The redb lookup keys (`keys::{table_key,namespace_key,table_prefix,…}`) are
/// `pub(crate)` — the catalog's internal on-disk encoding, deliberately not
/// part of the public API. But they are the hot path a commit / every catalog
/// op runs through, and the out-of-crate `skade-katalog-bench` harness needs to
/// time them (`skade.catalog_key` bencher) to prove the zero-copy builders keep
/// winning. This module re-exposes them as thin, `#[inline]` pass-throughs ONLY
/// under `--features bench`, so a normal build (and `cargo publish`) neither
/// widens the API nor pays anything. See `.nornir/catalog-key-zerocopy.md`.
#[cfg(feature = "bench")]
pub mod bench_keys {
    use iceberg::{NamespaceIdent, TableIdent};

    /// `TABLES` redb key — see [`crate::keys::table_key`].
    #[inline]
    pub fn table_key(catalog: &str, table: &TableIdent) -> String {
        crate::keys::table_key(catalog, table)
    }

    /// `NAMESPACES` redb key — see [`crate::keys::namespace_key`].
    #[inline]
    pub fn namespace_key(catalog: &str, ns: &NamespaceIdent) -> String {
        crate::keys::namespace_key(catalog, ns)
    }

    /// `NAMESPACE_PROPS` redb key — see [`crate::keys::namespace_prop_key`].
    #[inline]
    pub fn namespace_prop_key(catalog: &str, ns: &NamespaceIdent, prop: &str) -> String {
        crate::keys::namespace_prop_key(catalog, ns, prop)
    }

    /// `list_tables` scan lower bound — see [`crate::keys::table_prefix`].
    #[inline]
    pub fn table_prefix(catalog: &str, ns: &NamespaceIdent) -> String {
        crate::keys::table_prefix(catalog, ns)
    }

    /// Catalog-wide scan lower bound — see [`crate::keys::catalog_prefix`].
    #[inline]
    pub fn catalog_prefix(catalog: &str) -> String {
        crate::keys::catalog_prefix(catalog)
    }
}

/// Test-matrix emit shim for the catalog's own hot paths.
///
/// The library calls [`testmatrix::functional_status`] at the meaningful
/// success/branch points of its hot paths (the `atomic_release` multi-table
/// commit and the `load_table` read) so live catalog activity turns into
/// `nornir test --features testmatrix` rows. It is a compiled-out `#[inline]`
/// no-op unless the `testmatrix` feature is on (the release default), so a
/// normal build and `cargo publish` carry neither the emit nor the
/// nornir-testmatrix dependency.
pub(crate) mod testmatrix {
    /// Record one component self-report into the test-matrix. No-op (and the
    /// `nornir-testmatrix` dep is not linked) unless `--features testmatrix`.
    #[inline]
    pub(crate) fn functional_status(component: &str, check: &str, ok: bool, detail: &str) {
        #[cfg(feature = "testmatrix")]
        nornir_testmatrix::functional_status(component, check, ok, detail);
        #[cfg(not(feature = "testmatrix"))]
        {
            let _ = (component, check, ok, detail);
        }
    }
}
