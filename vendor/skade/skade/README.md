# skade

*Skaði, the winter queen: she keeps the icebergs in order.*

Fast Apache Iceberg table **writing/reading** and ergonomic **DataFusion SQL**
over an embedded, pure-Rust catalog
([skade-katalog](https://crates.io/crates/skade-katalog)). One directory is
the whole warehouse — no object store, no REST service, no JVM, no C deps.

```text
<dir>/catalog.redb   — the embedded catalog (namespaces + table pointers, ACID)
<dir>/warehouse/     — Iceberg metadata JSON, Avro manifests, Parquet data
```

## Why

The pieces exist — `iceberg-rust` for the table format, DataFusion for SQL,
`skade-katalog` for an in-process catalog — but wiring them up means learning
the five-layer writer stack (`ParquetWriter → RollingFileWriter →
DataFileWriter → fast_append → commit`), the field-id schema dance, and the
catalog-provider registration. skade packages those as one-call ergonomics,
extracted from skade-katalog's benchmark data-plane (where the stack ingests
hundreds of millions of OSM/TPC-H rows) and from znippy's Iceberg sink.

## Quickstart

```rust,no_run
use std::sync::Arc;
use skade::arrow_array::{Int64Array, RecordBatch, StringArray};
use skade::arrow_schema::{DataType, Field, Schema};

# async fn run() -> skade::Result<()> {
let wh = skade::open("/var/lib/myapp/lake").await?;

let schema = Schema::new(vec![
    Field::new("id", DataType::Int64, false),
    Field::new("name", DataType::Utf8, false),
]);
let mut events = wh.table_or_create("events", &schema).await?;

// Arrow RecordBatch in — one fast_append snapshot per call.
let batch = RecordBatch::try_new(Arc::new(schema), vec![
    Arc::new(Int64Array::from(vec![1, 2, 3])),
    Arc::new(StringArray::from(vec!["a", "b", "c"])),
])?;
events.append(&[batch]).await?;

// Arrow out…
let batches = events.read().await?;

// …or SQL out. Single table under its bare name:
let top = events.sql("SELECT name FROM events WHERE id > 1").await?;

// …or any number of tables in one statement (default-namespace tables are
// bare; everything is also reachable as skade.<ns>.<table>):
let joined = wh.sql("SELECT e.id FROM events e JOIN skade.main.events x ON e.id = x.id").await?;
# let _ = (batches, top, joined); Ok(()) }
```

## What's in the box

| Surface | Calls |
|---|---|
| Warehouse-in-a-dir | `skade::open(dir)`, `Warehouse::{create_table, table, table_or_create, table_idents, catalog}` |
| Write | `Table::append` (one commit), `Table::ingest` (grouped commits + `IngestStats`), free functions `append`/`ingest` for raw `iceberg::table::Table` |
| Read | `Table::read` / `read_all` (`scan().select_all().to_arrow()` as one call), `scan_count`, `arrow_schema_of` |
| SQL (feature `sql`, default) | `Warehouse::sql`, `Warehouse::session` (a `SessionContext` you keep), `Table::sql` |
| Schema bridges | `arrow_to_iceberg` (field ids 1..N), `recast` (`Utf8→LargeUtf8`/`Binary→LargeBinary` widening), `widen_for_iceberg` + inverse `unwiden` (`Int32↔UInt32`, `Int64↔UInt64` **bit-reinterpret** — Iceberg has no unsigned types) |
| Windowed Parquet ingest | `parquet_layout` + `rowgroup_windows` + `read_row_groups` (bounded-memory, thread-parallel) |

`Table` is a thin handle: `inner()` exposes the raw `iceberg::table::Table`
(snapshots, metadata, custom scans) and `Warehouse::catalog()` the raw
`RedbCatalog` (atomic multi-table release commits, time travel) when the
one-call surface is not enough.

## Version contract

skade pins **iceberg 0.9.x · arrow-\*/parquet 58.x · datafusion 54.x** (the
matching majors) and re-exports them — `skade::{iceberg, arrow_array,
arrow_schema, arrow_cast, parquet, datafusion, iceberg_datafusion,
skade_katalog}` — so dependents never have to guess which majors interop.
**Bump policy:** when any of those majors move, skade bumps its **minor**
version and calls it out in the changelog. (znippy is on Arrow 58, so it now
shares this crate's Arrow types directly and relies on this contract.)

## Performance note: the parallel-scan patch

Stock `iceberg-datafusion` 0.9.1 plans a table scan as a **single** DataFusion
partition — one serial Parquet-decode stream, ~1 busy core on a 32-core box,
~8× slower than it should be. skade-katalog's bench tree carries a patched
copy (`../bench/vendor/iceberg-datafusion`) that exposes **one partition per
data file** (SF100 TPC-H: ~1660 s → ~197 s).

skade's own builds/tests pick that patch up via a local `[patch.crates-io]`
(stripped automatically on publish), but the **published** crate depends on
stock `iceberg-datafusion 0.9.1` — crates.io forbids git/path deps. Until the
patch is upstreamed, consumers who want the fast scan add to their workspace:

```toml
[patch.crates-io]
iceberg-datafusion = { path = "…/skade/bench/vendor/iceberg-datafusion" }
```

## Feature flags

* `sql` *(default)* — DataFusion + iceberg-datafusion. Disable
  (`default-features = false`) for a write/read-only data plane with a much
  smaller dependency tree.

## Scope / non-goals

* **Local filesystem warehouses.** The catalog builder accepts other
  `iceberg` storage factories, but skade's one-call surface targets the
  embedded, single-directory case. S3/GCS plumbing stays in skade-katalog's
  bench for now.
* **Single process** (redb file lock — same rule as skade-katalog).
* Schema evolution waits on upstream `iceberg-rust` transaction actions.

## Benchmarks

A criterion suite (`benches/throughput.rs`) covers the write/read paths so perf
changes are visible:

| group | what it measures |
|---|---|
| `append` (1k, 10k) | single-batch append (one `fast_append` snapshot, fsync-bound) |
| `append_partitioned_repo` | the per-commit identity `partition_key_for` overhead |
| `ingest` | bulk ingest, commit every N (amortised fsync) |
| `ingest_parallel_scaling` (1core / allcores) | the gatling parallel encode — ~3.8× all-cores |
| `read` | full-snapshot scan → Arrow |

```bash
cargo bench -p skade                          # run; prints `change: ±%` vs the last run
cargo bench -p skade -- --save-baseline v0.4.3 # pin a named baseline for a release
cargo bench -p skade -- --baseline   v0.4.3   # compare a later build against it
```

To see a change's impact: bench → make the change → bench again (criterion diffs
against the saved baseline). Pin a `--save-baseline <version>` per release to
track improvements across versions. (Run on an idle box — these are I/O + fsync
bound, so a busy machine adds variance.)

License: Apache-2.0.
