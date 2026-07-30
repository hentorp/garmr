// Apache-2.0 licensed. See ../LICENSE-APACHE.

//! # skade — fast Iceberg I/O + ergonomic SQL, embedded
//!
//! *Skaði, the winter queen: she keeps the icebergs in order.*
//!
//! `skade` turns one local directory into an Apache Iceberg warehouse — the
//! catalog is [`skade-katalog`](https://crates.io/crates/skade-katalog)
//! (pure-Rust, redb-backed, ACID, in-process), the data plane is
//! `iceberg-rust` 0.9 + Arrow 58, and the SQL surface is DataFusion. No REST
//! service, no JVM, no C deps.
//!
//! By default the data/metadata blobs live on the local filesystem. For a
//! shared object store (MinIO/S3) the [`object_store`] module provides a
//! pluggable [`ObjectStore`] trait with feature-gated backends (`rustfs`
//! embedded-local, `s3` rust-s3, `aws-s3` aws-sdk-s3) — wire one with
//! [`Warehouse::open_with_store`] / [`Warehouse::open_with_object_store_config`].
//!
//! ## Quickstart
//!
//! ```no_run
//! use std::sync::Arc;
//! use skade::arrow_array::{Int64Array, RecordBatch, StringArray};
//! use skade::arrow_schema::{DataType, Field, Schema};
//!
//! # async fn run() -> skade::Result<()> {
//! // One directory = catalog (catalog.redb) + warehouse (metadata + parquet).
//! let wh = skade::open("/var/lib/myapp/lake").await?;
//!
//! let schema = Schema::new(vec![
//!     Field::new("id", DataType::Int64, false),
//!     Field::new("name", DataType::Utf8, false),
//! ]);
//! let mut events = wh.table_or_create("events", &schema).await?;
//!
//! // Arrow RecordBatch in …
//! let batch = RecordBatch::try_new(Arc::new(schema), vec![
//!     Arc::new(Int64Array::from(vec![1, 2, 3])),
//!     Arc::new(StringArray::from(vec!["a", "b", "c"])),
//! ])?;
//! events.append(&[batch]).await?; // one fast_append snapshot
//!
//! // … Arrow RecordBatches out (full-snapshot scan).
//! let back = events.read().await?;
//! assert_eq!(back.iter().map(|b| b.num_rows()).sum::<usize>(), 3);
//! # let _ = back; Ok(()) }
//! ```
//!
//! With the **`sql`** feature (opt-in) you also get a DataFusion query surface —
//! `Table::sql` for one table and `Warehouse::sql` across the warehouse:
//! `events.sql("SELECT count(*) FROM events WHERE id > 1").await?`.
//!
//! ## What's in the box
//!
//! * [`open`] / [`Warehouse`] — catalog-from-path: `catalog.redb` + `file://`
//!   warehouse + storage factory in one builder call.
//! * [`Table`] — [`Table::append`] / [`Table::ingest`] (ParquetWriter →
//!   RollingFileWriter → DataFileWriter → `fast_append`, as one call),
//!   [`Table::read`] (`scan().select_all().to_arrow()` as one call),
//!   [`Table::sql`].
//! * [`WriteProps`] — the Parquet `WriterProperties` knobs that live in skade:
//!   `compression`, per-column **bloom filters** (`bloom_columns`), tuned
//!   **row-group size**, and **dictionary** control. Bloom filters add
//!   intra-file row-group skipping on point lookups (e.g. a `symbol`/`sha`
//!   probe), complementing the catalog's sort/`SortOrder` file-level skipping.
//!   Wire it per handle with [`Table::write_props`], or call the explicit
//!   [`append_props`] / [`ingest_parallel_props`] / [`ingest_props`] /
//!   [`ingest_pipelined_props`] free functions. The bare `append`/`ingest*` and
//!   the `*_with(Compression)` APIs still work (they delegate with defaults).
//! * Schema bridges — [`arrow_to_iceberg`], [`recast`] (`Utf8 → LargeUtf8` /
//!   `Binary → LargeBinary` widening), [`widen_for_iceberg`] and its inverse
//!   [`unwiden`] (`Int32 ↔ UInt32`, `Int64 ↔ UInt64` bit-reinterpret — Iceberg
//!   has no unsigned types).
//! * Windowed Parquet reads — [`parquet_layout`] + [`rowgroup_windows`] +
//!   [`read_row_groups`]: bounded-memory, all-core (gatling) bulk ingest, or the
//!   single-call streaming [`ParquetWindows`] iterator (the reuse surface for a
//!   map/geo consumer streaming OSM/GeoParquet features viewport-by-viewport).
//!
//! ## Version contract
//!
//! skade pins **iceberg 0.9.x / arrow-* 58.x / parquet 58.x / datafusion
//! 54.x** and re-exports them ([`iceberg`], [`arrow_array`], [`arrow_schema`],
//! [`arrow_cast`], [`parquet`], [`datafusion`], [`iceberg_datafusion`],
//! [`skade_katalog`]) so dependents can name these types without guessing the
//! matching majors. When any of those majors move, skade bumps its **minor**
//! version and says so in the changelog.
//!
//! ## Feature flags
//!
//! * `sql` *(opt-in)* — DataFusion + iceberg-datafusion: [`Warehouse::sql`],
//!   [`Warehouse::session`], [`Table::sql`]. Off by default so the write/read
//!   data plane stays lean (no datafusion, no `liblzma-sys`); enable it for SQL.
//! * `rustfs` *(opt-in)* — [`object_store::LocalFsStore`], an embedded,
//!   zero-external-dep local-filesystem [`ObjectStore`].
//! * `s3` *(opt-in)* — [`object_store::RustS3Store`], MinIO/S3 via `rust-s3`.
//!   The default S3 backend. (Won't compile in a workspace that links `gix`;
//!   use `aws-s3` there.)
//! * `aws-s3` *(opt-in)* — [`object_store::AwsS3Store`], MinIO/S3 via
//!   `aws-sdk-s3` — reuse the consumer's existing S3 SDK.
//!
//! See `.nornir/object-store.md` for the full design + MinIO wiring.

mod bridge;
mod delete;
mod error;
/// Lineage emission — the event model + sink trait ("who did what, to which
/// tables, between which systems, when"). The types are always compiled; the
/// automatic emit hook on [`Table::append`] is gated behind the `lineage`
/// feature (default off). See `.nornir/cdc-streaming-lineage.md`.
pub mod lineage;
pub mod object_store;
mod parquet_io;
mod read;
/// Streaming CDC consume (feature `stream`): [`stream::ChangeStream`] +
/// [`Table::changes`] — a live changelog stream over skade-katalog's commit
/// broadcast, with a poll fallback and exactly-once [`stream::ConsumerCursor`]
/// resume. See `.nornir/cdc-streaming-lineage.md` §3.2.
/// Spatial index — a dependency-free geohash grid over point rows
/// ([`spatial::GeoIndex`]): bounding-box, radius, and k-nearest queries in
/// `O(log n + hits)`, built from the Arrow batches the warehouse already reads
/// ([`spatial::GeoIndex::from_batches`]). The first *spatial* acceleration
/// structure in the warehouse (columnar + ACID + time-travel had no spatial
/// answer without a full scan). See `.nornir/spatial-index-design.md`.
pub mod spatial;
#[cfg(feature = "stream")]
pub mod stream;
mod table;
mod warehouse;
mod write;

/// Bench-only hooks (feature `bench`, default OFF). Re-exposes the `pub(crate)`
/// partition-scan accelerator [`write::uniform_str_value`] plus a naive per-row
/// reference so the out-of-crate nornir-bench harness can A/B the two
/// (`skade_partition_key_scan`) and prove the uniform-collapse speedup. Compiled
/// out of a normal build (and `cargo publish`), so the public API stays lean.
#[cfg(feature = "bench")]
pub mod bench_partition {
    use arrow_array::{Array, GenericStringArray, OffsetSizeTrait};

    /// The offsets+`memcmp` uniform-collapse used on the partition-write hot path
    /// (see [`crate::write::uniform_str_value`]). `Some(value)` when the column
    /// is proven uniform+non-null; `None` otherwise.
    #[inline]
    pub fn uniform_str_value<O: OffsetSizeTrait>(a: &GenericStringArray<O>) -> Option<&str> {
        crate::write::uniform_str_value(a)
    }

    /// The pre-optimization reference: the exact per-row `value(i)` scan the fast
    /// path replaces on the uniform common case. Same verdict as
    /// [`uniform_str_value`] on a uniform, non-null column — the A/B baseline.
    #[inline]
    pub fn naive_str_value<O: OffsetSizeTrait>(a: &GenericStringArray<O>) -> Option<&str> {
        if a.len() == 0 || a.null_count() != 0 {
            return None;
        }
        let first = a.value(0);
        for i in 1..a.len() {
            if a.value(i) != first {
                return None;
            }
        }
        Some(first)
    }
}

pub use bridge::{arrow_to_iceberg, recast, unwiden, widen_for_iceberg};
pub use error::{Result, SkadeError};
#[cfg(feature = "lineage-http")]
pub use lineage::HttpLineageSink;
pub use lineage::{
    CapturingSink, DatasetRef, LINEAGE_EVENTS_TABLE, LineageEvent, LineageSink,
    Operation as LineageOperation, SystemRef, WarehouseLineageSink, emit_release,
    lineage_events_schema,
};
pub use object_store::{MemoryStore, ObjectStore, ObjectStoreConfig, ObjectStoreFactory, S3Config};
/// The Parquet compression codec for writes (re-exported from `parquet`).
pub use parquet::basic::Compression;
pub use parquet_io::{ParquetWindows, parquet_layout, read_row_groups, rowgroup_windows};
pub use read::{
    ChangelogBatch, DeltaPlan, EqualityDeleteFile, Scalar, ScanFilter, ScanPlanStats, TableKind,
    arrow_schema_of, change_type, lookup, plan_stats, read_all, read_changelog, read_columns,
    read_delta, read_equality_deletes, read_filtered, read_limited, scan_count,
};
pub use skade_katalog::HealOutcome;
#[cfg(feature = "stream")]
pub use stream::{ChangeStream, ConsumerCursor};
pub use table::Table;
pub use warehouse::{CompactReport, DEFAULT_NAMESPACE, Warehouse};
pub use write::{
    IngestStats, WriteProps, append, append_props, append_stream_props, append_with, ingest,
    ingest_parallel, ingest_parallel_props, ingest_parallel_with, ingest_pipelined,
    ingest_pipelined_props, ingest_props, ingest_with,
};

// Version-contract re-exports: the exact majors skade is built against.
pub use arrow_array;
pub use arrow_cast;
pub use arrow_schema;
pub use arrow_select;
pub use iceberg;
pub use parquet;
pub use skade_katalog;

#[cfg(feature = "sql")]
pub use datafusion;
#[cfg(feature = "sql")]
pub use iceberg_datafusion;

use std::path::Path;

/// Open (creating if absent) the Iceberg warehouse at `dir`.
/// Shorthand for [`Warehouse::open`].
pub async fn open(dir: impl AsRef<Path>) -> Result<Warehouse> {
    Warehouse::open(dir).await
}

/// **Introspection / emit marker** — record one functional-status row for the
/// nornir test matrix. Wraps `nornir_testmatrix::functional_status` behind the
/// `testmatrix` feature (a compiled-out `#[inline]` no-op otherwise, with no
/// nornir dep). `component` is the reporting surface (e.g. `"skade/write"`),
/// `check` what it verified, `ok` the verdict, `detail` a short human note. The
/// warehouse's data-plane surfaces (write/read, `read_delta` CDC, equality-delete
/// MOR, the object-store backends, the lineage sink) call this so `nornir test
/// --features testmatrix` SEES each surface's health. No-op (zero cost) by default.
#[inline]
pub fn functional_status(component: &str, check: &str, ok: bool, detail: &str) {
    #[cfg(feature = "testmatrix")]
    nornir_testmatrix::functional_status(component, check, ok, detail);
    #[cfg(not(feature = "testmatrix"))]
    {
        let _ = (component, check, ok, detail);
    }
}
