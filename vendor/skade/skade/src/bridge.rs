//! Schema bridges between Arrow and Iceberg.
//!
//! Iceberg's type system is narrower than Arrow's: it has no unsigned integers
//! and its `String`/`Binary` map to Arrow `LargeUtf8`/`LargeBinary` on the scan
//! path. These helpers cross that gap in both directions:
//!
//! * [`arrow_to_iceberg`] — derive an Iceberg [`Schema`] (field ids `1..N`)
//!   from any flat Arrow schema.
//! * [`recast`] — cast batches to a target (field-id-tagged) Arrow schema,
//!   covering the `Utf8 → LargeUtf8` / `Binary → LargeBinary` widening.
//! * [`widen_for_iceberg`] — make a batch Iceberg-typable: narrow ints are
//!   value-cast to `Int32`; `UInt32`/`UInt64` are **bit-reinterpreted** to
//!   `Int32`/`Int64` (lossless, order-changing for top-bit-set values).
//! * [`unwiden`] — the exact inverse: `Int32 → UInt32` / `Int64 → UInt64`
//!   bit-reinterprets plus value-casts back to the other narrow target types.

use std::sync::Arc;

use arrow_array::cast::AsArray;
use arrow_array::types::{Int32Type, Int64Type, UInt32Type, UInt64Type};
use arrow_array::{ArrayRef, RecordBatch};
use arrow_schema::{DataType, Field, Schema as ArrowSchema, SchemaRef as ArrowSchemaRef, TimeUnit};
use iceberg::spec::{NestedField, PrimitiveType, Schema, Type};

use crate::error::{Result, SkadeError};

/// Map a flat Arrow schema to an Iceberg schema: field ids `1..N` in column
/// order; nullable Arrow fields become optional, others required. Covers the
/// scalar Iceberg types: bool, int/long, float/double, decimal, date, time,
/// timestamp/timestamptz (µs) and the **v3** nanosecond timestamps, string,
/// binary. Nested types (List/Struct/Map) and the not-yet-in-iceberg-rust v3
/// types (variant, geometry/geography) bail with a clear error.
pub fn arrow_to_iceberg(schema: &ArrowSchema) -> Result<Schema> {
    let mut fields = Vec::with_capacity(schema.fields().len());
    for (i, f) in schema.fields().iter().enumerate() {
        let pt = match f.data_type() {
            DataType::Boolean => PrimitiveType::Boolean,
            DataType::Int8 | DataType::Int16 | DataType::Int32 => PrimitiveType::Int,
            DataType::Int64 => PrimitiveType::Long,
            DataType::Float32 => PrimitiveType::Float,
            DataType::Float64 => PrimitiveType::Double,
            DataType::Date32 => PrimitiveType::Date,
            DataType::Time64(TimeUnit::Microsecond) => PrimitiveType::Time,
            // Microsecond timestamps (iceberg v1+); nanosecond is iceberg v3.
            DataType::Timestamp(TimeUnit::Microsecond, None) => PrimitiveType::Timestamp,
            DataType::Timestamp(TimeUnit::Microsecond, Some(_)) => PrimitiveType::Timestamptz,
            DataType::Timestamp(TimeUnit::Nanosecond, None) => PrimitiveType::TimestampNs,
            DataType::Timestamp(TimeUnit::Nanosecond, Some(_)) => PrimitiveType::TimestamptzNs,
            DataType::Decimal128(precision, scale) if *scale >= 0 => PrimitiveType::Decimal {
                precision: *precision as u32,
                scale: *scale as u32,
            },
            DataType::Utf8 | DataType::LargeUtf8 | DataType::Utf8View => PrimitiveType::String,
            DataType::Binary | DataType::LargeBinary | DataType::BinaryView => {
                PrimitiveType::Binary
            }
            // Unsigned columns must go through `widen_for_iceberg` first.
            other => {
                return Err(SkadeError::Other(format!(
                    "unmapped arrow type {other:?} for column {} (unsigned ints: \
                     widen_for_iceberg first)",
                    f.name()
                )));
            }
        };
        let id = (i + 1) as i32;
        let nf = if f.is_nullable() {
            NestedField::optional(id, f.name(), Type::Primitive(pt))
        } else {
            NestedField::required(id, f.name(), Type::Primitive(pt))
        };
        fields.push(nf.into());
    }
    Ok(Schema::builder()
        .with_schema_id(0)
        .with_fields(fields)
        .build()?)
}

/// Re-cast each batch's columns to `target` (typically the table's
/// field-id-tagged Arrow schema), handling Iceberg's `Utf8 → LargeUtf8` /
/// `Binary → LargeBinary` widening so the written Parquet carries the field ids
/// the catalog scan needs. Column count and order must already match.
pub fn recast(batches: &[RecordBatch], target: ArrowSchemaRef) -> Result<Vec<RecordBatch>> {
    let n = target.fields().len();
    let mut out = Vec::with_capacity(batches.len());
    for b in batches {
        if b.num_columns() != n {
            return Err(SkadeError::Other(format!(
                "column count mismatch: batch has {}, target schema has {n}",
                b.num_columns()
            )));
        }
        // Zero-copy fast path: `arrow_cast::cast` allocates a fresh array even
        // when source type == target type, so a naive recast copies every column
        // of every batch on every write. Instead, cast ONLY the columns whose
        // type actually differs; matching columns pass through as Arc clones
        // (no buffer copy). When the caller already built the batch against the
        // table's field-id schema — the common case — this is fully zero-copy:
        // we re-stamp the field-id `target` schema over the same buffers.
        let cols: Vec<ArrayRef> = (0..n)
            .map(|i| {
                let c = b.column(i);
                if c.data_type() == target.field(i).data_type() {
                    Ok(Arc::clone(c)) // zero-copy
                } else {
                    Ok(arrow_cast::cast(c, target.field(i).data_type())?)
                }
            })
            .collect::<Result<_>>()?;
        out.push(RecordBatch::try_new(target.clone(), cols)?);
    }
    Ok(out)
}

/// Reinterpret/widen a batch so every column has an Iceberg-mappable type:
///
/// * `UInt8`/`UInt16`/`Int8`/`Int16` → `Int32` (value cast, lossless),
/// * `UInt32` → `Int32` and `UInt64` → `Int64` (**bit reinterpret**, lossless;
///   values above the signed max come back negative until [`unwiden`]),
/// * everything else passes through untouched.
pub fn widen_for_iceberg(batch: &RecordBatch) -> Result<RecordBatch> {
    let schema = batch.schema();
    let mut fields: Vec<Field> = Vec::with_capacity(schema.fields().len());
    let mut columns: Vec<ArrayRef> = Vec::with_capacity(schema.fields().len());

    for (i, field) in schema.fields().iter().enumerate() {
        let col = batch.column(i);
        let (dt, arr): (DataType, ArrayRef) = match field.data_type() {
            DataType::UInt8 | DataType::UInt16 | DataType::Int8 | DataType::Int16 => {
                (DataType::Int32, arrow_cast::cast(col, &DataType::Int32)?)
            }
            DataType::UInt32 => {
                let a = col.as_primitive::<UInt32Type>();
                (
                    DataType::Int32,
                    Arc::new(a.unary::<_, Int32Type>(|v| v as i32)) as ArrayRef,
                )
            }
            DataType::UInt64 => {
                let a = col.as_primitive::<UInt64Type>();
                (
                    DataType::Int64,
                    Arc::new(a.unary::<_, Int64Type>(|v| v as i64)) as ArrayRef,
                )
            }
            _ => (field.data_type().clone(), col.clone()),
        };
        fields.push(Field::new(field.name(), dt, field.is_nullable()));
        columns.push(arr);
    }

    Ok(RecordBatch::try_new(
        Arc::new(ArrowSchema::new(fields)),
        columns,
    )?)
}

/// Inverse of [`widen_for_iceberg`]: cast batches back to `target` (the
/// original, possibly-unsigned schema). `Int32 → UInt32` and `Int64 → UInt64`
/// are **bit reinterprets** (so a `u64` above `i64::MAX` round-trips exactly);
/// other mismatches (e.g. `Int32 → UInt16`, `LargeUtf8 → Utf8`) go through the
/// regular cast kernel.
pub fn unwiden(batches: &[RecordBatch], target: ArrowSchemaRef) -> Result<Vec<RecordBatch>> {
    let n = target.fields().len();
    let mut out = Vec::with_capacity(batches.len());
    for b in batches {
        if b.num_columns() != n {
            return Err(SkadeError::Other(format!(
                "column count mismatch: batch has {}, target schema has {n}",
                b.num_columns()
            )));
        }
        let mut cols: Vec<ArrayRef> = Vec::with_capacity(n);
        for i in 0..n {
            let col = b.column(i);
            let want = target.field(i).data_type();
            let arr: ArrayRef = match (col.data_type(), want) {
                (a, b) if a == b => col.clone(),
                (DataType::Int32, DataType::UInt32) => {
                    let a = col.as_primitive::<Int32Type>();
                    Arc::new(a.unary::<_, UInt32Type>(|v| v as u32))
                }
                (DataType::Int64, DataType::UInt64) => {
                    let a = col.as_primitive::<Int64Type>();
                    Arc::new(a.unary::<_, UInt64Type>(|v| v as u64))
                }
                _ => arrow_cast::cast(col, want)?,
            };
            cols.push(arr);
        }
        out.push(RecordBatch::try_new(target.clone(), cols)?);
    }
    Ok(out)
}
