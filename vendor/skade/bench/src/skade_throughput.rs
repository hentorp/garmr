//! Shared workload setup for the `skade.*` throughput benchers.
//!
//! Lifted verbatim from the old criterion suite (`skade/benches/throughput.rs`)
//! when it was migrated onto the nornir Bencher engine. These helpers build the
//! synthetic schema + batches and a fresh embedded warehouse/table over a temp
//! dir so each `skade.*` bencher in `examples/nornir-bench.rs` can drive the
//! high-level `skade::Table` API (append / ingest / ingest_parallel /
//! ingest_pipelined / read / recast / compression) directly.

use std::sync::Arc;

// arrow_array / arrow_schema are direct deps of this lib crate (and the SAME
// arrow 57 that `skade` re-exports), so the batches built here interop with the
// `skade::Table` API the example drives them through. We can't `use skade::…`
// here because `skade` is a dev-dependency (examples/tests only), not a lib dep.
use arrow_array::{Float64Array, Int64Array, RecordBatch, StringArray};
use arrow_schema::{DataType, Field, Schema};

/// The 4-column synthetic schema (repo / id / name / score) the criterion
/// throughput suite drove through skade — mirrors nornir's warehouse write shape.
pub fn schema() -> Arc<Schema> {
    Arc::new(Schema::new(vec![
        Field::new("repo", DataType::Utf8, false),
        Field::new("id", DataType::Int64, false),
        Field::new("name", DataType::Utf8, false),
        Field::new("score", DataType::Float64, false),
    ]))
}

/// One `rows`-row RecordBatch matching [`schema`].
pub fn batch(rows: usize) -> RecordBatch {
    RecordBatch::try_new(
        schema(),
        vec![
            Arc::new(StringArray::from(vec!["nornir"; rows])),
            Arc::new(Int64Array::from((0..rows as i64).collect::<Vec<_>>())),
            Arc::new(StringArray::from(
                (0..rows).map(|i| format!("row-{i}")).collect::<Vec<_>>(),
            )),
            Arc::new(Float64Array::from(
                (0..rows).map(|i| i as f64).collect::<Vec<_>>(),
            )),
        ],
    )
    .unwrap()
}
