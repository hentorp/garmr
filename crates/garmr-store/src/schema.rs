// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! The `events` table shape and the `Event` → Arrow `RecordBatch` builder.
//!
//! One table in skade's default namespace, so SQL uses the bare name
//! (`FROM events`). The `fields` map is flattened to a JSON string column —
//! iceberg-rust 0.9 has no schema evolution and maps Utf8 cleanly, so the
//! agent's tools filter it with `fields LIKE '%"src_ip":"1.2.3.4"%'` or
//! DataFusion JSON functions rather than needing per-key columns.

use std::sync::Arc;

use chrono::Utc;
use garmr_core::Event;
use skade::arrow_array::{
    ArrayRef, Int32Array, RecordBatch, StringArray, TimestampMicrosecondArray,
};
use skade::arrow_schema::{DataType, Field, Schema, TimeUnit};
use skade::{Compression, WriteProps};

use arrow_buffer::{Buffer, NullBuffer, OffsetBuffer};

/// The events table name.
pub const T_EVENTS: &str = "events";

/// The events column that carries a per-column Parquet **bloom filter**:
/// `event_id`, the stable content-derived BLAKE3 id. It is high-cardinality
/// (one distinct value per event) and the natural equality / point-lookup key,
/// so a bloom filter on it lets a reader **skip whole row groups** that cannot
/// contain a probed id — the intra-file complement to the `event_ts` sort's
/// file-level skipping.
///
/// This helps only *exact-id* probes (e.g. skade's [`skade::Table::lookup`],
/// which reads blooms); the agent's `fields LIKE '%"user":"…"%'` needle is a
/// substring scan over a JSON blob and can never use it. See the module tests
/// and [`events_write_props`].
pub const EVENT_BLOOM_COLUMN: &str = "event_id";

/// The [`WriteProps`] every events **append** writes with: the bare Parquet
/// defaults (uncompressed, dictionary on — unchanged from before) *plus* a bloom
/// filter on [`EVENT_BLOOM_COLUMN`]. Enabling the bloom is purely additive: file
/// bytes gain a small per-row-group filter, and nothing on the read path changes
/// until a caller issues an exact `event_id` lookup.
pub fn events_write_props() -> WriteProps {
    WriteProps::default().bloom_columns([EVENT_BLOOM_COLUMN])
}

/// The [`WriteProps`] the **compaction rebuild** writes with: the same bloom on
/// [`EVENT_BLOOM_COLUMN`], plus the zstd compression and 128k-row row groups the
/// rebuild uses to emit a few big, range-prunable files. Without carrying the
/// bloom here a rebuild would silently drop it from the hot table (skade's plain
/// `compact_table` rebuilds with no bloom), so under continuous ingest — where
/// compaction fires often — the append-time filter would be short-lived.
pub fn events_compact_write_props() -> WriteProps {
    WriteProps::new(Compression::ZSTD(Default::default()))
        .row_group_size(128 * 1024)
        .bloom_columns([EVENT_BLOOM_COLUMN])
}

/// Event schema version stamped on every V2 row. V1 rows (written before this
/// column existed) read back `NULL` and are treated as version 1.
pub const EVENT_SCHEMA_VERSION: i32 = 2;

/// Arrow schema for `events`.
///
/// **Column order is a contract.** skade's `recast` is positional (batch column
/// `i` ↔ table field `i`), so the original nine columns (positions 0..8) must
/// NEVER be reordered or removed. Event V2 provenance columns are strictly
/// *appended*; on an existing (V1) warehouse `Table::ensure_schema` adds them
/// with higher field-ids, preserving positions 0..8. See `build_events_batch`,
/// which emits columns in exactly this order.
pub fn events_schema() -> Schema {
    Schema::new(vec![
        // --- v1: the six-label model + raw line + extracted fields (do not reorder) ---
        Field::new(
            "event_ts",
            DataType::Timestamp(TimeUnit::Microsecond, None),
            false,
        ),
        Field::new("host", DataType::Utf8, false),
        Field::new("service", DataType::Utf8, true),
        Field::new("source", DataType::Utf8, true),
        Field::new("environment", DataType::Utf8, true),
        Field::new("severity", DataType::Utf8, true),
        Field::new("log_type", DataType::Utf8, true),
        Field::new("message", DataType::Utf8, false),
        Field::new("fields", DataType::Utf8, true),
        // --- v2: provenance (appended; all nullable so old rows read back NULL) ---
        // schema_version: 2 for V2; NULL on legacy V1 rows.
        Field::new("schema_version", DataType::Int32, true),
        // event_id: stable content-derived BLAKE3 id — the dedup + reference key.
        Field::new("event_id", DataType::Utf8, true),
        // ingest_time: when durably stored (receive time) vs event_ts (source
        // time); their divergence is the ingest-lag signal.
        Field::new(
            "ingest_time",
            DataType::Timestamp(TimeUnit::Microsecond, None),
            true,
        ),
        // raw_payload_hash: BLAKE3 of the raw message (payload provenance).
        Field::new("raw_payload_hash", DataType::Utf8, true),
        // parser_name: the producer/parser class that normalized this event.
        Field::new("parser_name", DataType::Utf8, true),
        // source_trust: `unverified` until an inventory/collector identity raises
        // it (Phase 12).
        Field::new("source_trust", DataType::Utf8, true),
        // collector_id: the AUTHENTICATED collector identity that delivered this
        // row (Phase 12), or NULL when unattributed (legacy/unauthenticated). The
        // env learner keys anti-poisoning distinct-sources on this, not the
        // shipper-self-declared `source`. Appended last; nullable, so old rows
        // read back NULL.
        Field::new("collector_id", DataType::Utf8, true),
    ])
}

/// A stable, content-derived event id: BLAKE3 over the identifying fields. The
/// same logical event re-ingested (e.g. replay) yields the same id, which is the
/// basis for ingest deduplication.
pub fn event_id_for(e: &Event) -> String {
    // Serialize `fields` here for callers that only want the id; the batch
    // builder computes the JSON once and feeds those exact bytes in via
    // [`hash_event_id`] so a build never serializes `fields` twice.
    let fields_json = serde_json::to_string(&e.fields).ok();
    hash_event_id(e, fields_json.as_deref().map(str::as_bytes))
        .to_hex()
        .to_string()
}

/// The id digest, parameterised on the already-serialized `fields` JSON **bytes**
/// so the batch builder can share one serialization between the `fields` column
/// and the id (and hash straight out of its reused per-worker buffer, no `str`
/// round-trip). `fields_json` is `None` exactly when serializing `e.fields`
/// errors — the same case the old inline `if let Ok(..)` skipped. `to_writer` and
/// `to_string` emit identical bytes, so the digest is byte-identical to the
/// previous implementation. Returns the raw `blake3::Hash` so the hot path can
/// hex-encode it into a preallocated buffer with no intermediate `String`.
#[inline]
fn hash_event_id(e: &Event, fields_json: Option<&[u8]>) -> blake3::Hash {
    hash_id_parts(
        e.ts.timestamp_micros(),
        &e.host,
        &e.source,
        &e.service,
        &e.message,
        fields_json,
    )
}

/// The id digest over the raw identifying pieces — the single source of truth for
/// `event_id`, shared by the `Event` path ([`hash_event_id`]) and the Arrow-wire
/// path ([`build_events_batch_from_wire`]) so the SAME logical event gets the SAME
/// id no matter which ingest path delivered it (one dedup identity). Field order
/// and the `\0` separators are a wire contract — never reorder.
#[inline]
fn hash_id_parts(
    ts_micros: i64,
    host: &str,
    source: &str,
    service: &str,
    message: &str,
    fields_json: Option<&[u8]>,
) -> blake3::Hash {
    let mut h = blake3::Hasher::new();
    h.update(&ts_micros.to_le_bytes());
    h.update(&[0]);
    h.update(host.as_bytes());
    h.update(&[0]);
    h.update(source.as_bytes());
    h.update(&[0]);
    h.update(service.as_bytes());
    h.update(&[0]);
    h.update(message.as_bytes());
    h.update(&[0]);
    if let Some(f) = fields_json {
        h.update(f);
    }
    h.finalize()
}

/// A BLAKE3 digest as a byte string (32 bytes → 64 lowercase hex chars).
const HEX_LEN: usize = 64;
const HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";

/// Write the lowercase hex of a 32-byte BLAKE3 `digest` into `dst` (exactly
/// [`HEX_LEN`] bytes), high nibble first — byte-identical to
/// `blake3::Hash::to_hex()`. Zero allocation: the caller owns `dst` (a disjoint
/// slot of one preallocated Arrow value buffer).
#[inline]
fn write_hex(dst: &mut [u8], digest: &[u8; 32]) {
    debug_assert_eq!(dst.len(), HEX_LEN);
    for (i, &b) in digest.iter().enumerate() {
        dst[2 * i] = HEX_DIGITS[(b >> 4) as usize];
        dst[2 * i + 1] = HEX_DIGITS[(b & 0x0f) as usize];
    }
}

/// Rows at/above this count fan the expensive per-row provenance work (the
/// `fields` JSON serialize + the two BLAKE3 hashes) across every core via
/// gatling's no-barrier self-dispatch; below it the scoped-thread spawn costs
/// more than it saves, so a serial pass wins.
///
/// **This number is MEASURED, not estimated** — see
/// `.nornir/uber-garm-one-core-root-cause-2026-07-27.md` §2 and §6. It was 4096,
/// which was a guess, and the guess was wrong in a way that mattered: entering
/// one gatling fan-out costs **195 µs** on t14s (`probe::forkjoin_spawn_cost_us`)
/// and the serial build costs **625 ns/row** (`garmr.encode_batch`
/// `serial_path_rows_per_sec`), with an asymptotic fan-out speedup of **1.74×**.
/// The break-even batch is therefore
///
/// ```text
/// n* = spawn / (per_row × (1 − 1/S)) = 195 µs / (0.625 µs × 0.425) ≈ 734 rows
/// ```
///
/// so 4096 sat **5.6× above break-even** and every batch between ~734 and 4096
/// rows took the serial branch while the fan-out would have won. That range is
/// not hypothetical: live ingest coalesces `min(MAX_COALESCE_EVENTS, 3 s of
/// arrivals)` into one commit (`garmr-cli/src/pipeline.rs`), so 4096 meant the
/// fan-out only ran above ~1 365 events/sec sustained — it was dead code for a
/// deployment ingesting less than that.
///
/// 2048 keeps a **2.8× margin** over the measured break-even (so it stays a win
/// on a host with a costlier spawn — the price scales with worker count, and
/// even at twice t14s's it is still positive here) while halving the dead zone
/// to ~683 events/sec. Measured win at 2048 rows: **1.38×** vs the serial pass.
///
/// Re-derive it, do not re-guess it, when moving to a different box.
const PARALLEL_ROW_THRESHOLD: usize = 2048;

/// The number of v1 payload **string** columns folded per-worker — `host`,
/// `service`, `source`, `environment`, `severity`, `log_type`, `message`, in
/// `events_schema` positions 1..=7. (`event_ts`, position 0, is a cheap `i64`
/// primitive built serially.) These used to be seven serial `from_iter` passes
/// *after* the fold — the encode path's Amdahl serial tail (root-cause §5); they
/// now ride the SAME `gatling_reduce` as the provenance columns.
/// The `v1` array is stored in `events_schema` column order — `v1[0]`→host (pos
/// 1), `v1[1]`→service (2), source (3), environment (4), severity (5),
/// log_type (6), `v1[6]`→message (7) — matching the fold in [`ProvSeg::absorb`]
/// and the destructure in [`build_batch`].
const V1_STR: usize = 7;

/// One worker's private slice of ONE variable-width, **non-null** string column:
/// every row's UTF-8 concatenated (`vals`) with its per-row byte length (`lens`).
/// No validity vector — an `Event`'s payload strings are never null, so the
/// assembled column carries no null buffer, byte-identical to the old
/// `rows.iter().map(|(e,_)| Some(..)).collect()`.
#[derive(Default)]
struct StrCol {
    vals: Vec<u8>,
    lens: Vec<u32>,
}

impl StrCol {
    /// Append `s`'s bytes to the reused value buffer and record its length — the
    /// per-row work that used to live in a serial `StringArray::from_iter`.
    #[inline]
    fn push(&mut self, s: &str) {
        self.vals.extend_from_slice(s.as_bytes());
        self.lens.push(s.len() as u32);
    }
}

/// One worker's private slice of the provenance columns — the "one buffer per
/// worker, concat `n_workers` not `n_rows`" shape (the vendored `parwrite` /
/// lbzip2 pattern). A worker folds its whole contiguous row-partition into a
/// single `ProvSeg`, appending to REUSED growing buffers, so a build allocates
/// `~n_workers` buffers, not one `String` per row. Rows stay in order within a
/// seg, and `gatling_reduce` merges segs in ascending partition order, so the
/// concatenation of all segs is the original row order.
#[derive(Default)]
struct ProvSeg {
    /// `fields` JSON bytes for every row in this partition, concatenated. Written
    /// by `serde_json::to_writer` (no intermediate `String`).
    fields_vals: Vec<u8>,
    /// Per-row byte length of this row's `fields` JSON inside `fields_vals`.
    fields_lens: Vec<u32>,
    /// Per-row validity: `false` ⇒ the `fields` column is NULL for this row
    /// (serialization errored — the old `.ok()` → NULL path).
    fields_valid: Vec<bool>,
    /// Fixed 64-byte lowercase hex of each row's `event_id`, concatenated.
    id_hex: Vec<u8>,
    /// Fixed 64-byte lowercase hex of each row's `raw_payload_hash`, concatenated.
    ph_hex: Vec<u8>,
    /// The seven v1 payload string columns for this partition (see [`V1_STR`]),
    /// each concatenated with per-row lengths — folded here so the string column
    /// build joins the parallel region instead of trailing it serially.
    v1: [StrCol; V1_STR],
}

impl ProvSeg {
    /// Absorb row `e` (with its serialized-once `fields` JSON) into the reused
    /// buffers. The `fields` map is serialized a SINGLE time here — into
    /// `fields_vals` — and those exact bytes feed the `event_id` hash, so nothing
    /// is serialized twice and nothing is heap-allocated per row.
    #[inline]
    fn absorb(&mut self, e: &Event) {
        let start = self.fields_vals.len();
        let ok = serde_json::to_writer(&mut self.fields_vals, &e.fields).is_ok();
        let (fields_bytes, valid) = if ok {
            (Some(&self.fields_vals[start..]), true)
        } else {
            // A partial write on error would corrupt the column; roll it back and
            // emit NULL for this row (serializing a String→String map effectively
            // never errors, so this is the cold path).
            self.fields_vals.truncate(start);
            (None, false)
        };
        self.fields_lens
            .push((self.fields_vals.len() - start) as u32);
        self.fields_valid.push(valid);

        // event_id: hash the identifying fields + the just-written `fields` bytes,
        // hex straight into the reused id buffer. Scoped so the immutable borrow of
        // `fields_vals` ends before the mutable `id_hex` extend.
        let mut id_slot = [0u8; HEX_LEN];
        write_hex(&mut id_slot, hash_event_id(e, fields_bytes).as_bytes());
        self.id_hex.extend_from_slice(&id_slot);

        // raw_payload_hash: BLAKE3 of the message, hex into the reused buffer.
        let mut ph_slot = [0u8; HEX_LEN];
        write_hex(&mut ph_slot, blake3::hash(e.message.as_bytes()).as_bytes());
        self.ph_hex.extend_from_slice(&ph_slot);

        // The v1 payload string columns — same partition, `events_schema` order
        // (see [`V1_STR`]). Folded here rather than in a serial `from_iter` tail.
        self.v1[0].push(e.host.as_str());
        self.v1[1].push(e.service.as_str());
        self.v1[2].push(e.source.as_str());
        self.v1[3].push(e.environment.as_str());
        self.v1[4].push(e.severity.as_str());
        self.v1[5].push(e.log_type.as_str());
        self.v1[6].push(e.message.as_str());
    }
}

/// Assemble a fixed-width **hex** provenance column (`event_id` /
/// `raw_payload_hash`) directly from the fold's per-worker seg buffers with ONE
/// bulk copy into a preallocated Arrow value buffer — no per-row
/// `from_iter_values` pass. `pick(seg)` is that seg's already-concatenated
/// 64-byte-per-row hex block, so the blocks are memcpy'd end-to-end (one
/// `extend_from_slice` per fold worker — `~n_workers` copies, not `n`) and the
/// offsets are the trivial `i*64` stride. `StringArray::new` then validates the
/// whole buffer as UTF-8 in one simd pass (the bytes are ASCII hex, always valid)
/// rather than per row. Generic over the seg type so both the native `ProvSeg`
/// fold and the Arrow-wire `(id_hex, ph_hex)` fold share it.
///
/// The copy is left SERIAL on purpose: it is memory-bandwidth bound, and fanning
/// it across cores (a `gatling_scanlines` variant) measured a net throughput LOSS
/// on oden — the fork-join spawn plus per-row scatter cost more than the bulk
/// memcpy, inflating `encode_cores_busy` while *lowering* rows/sec (the "busy
/// cores producing little" trap — root-cause §5/§6). The win is dropping the
/// per-row assembly tail, not adding threads.
fn hex_column<S, F>(segs: &[S], n: usize, pick: F) -> StringArray
where
    F: Fn(&S) -> &[u8],
{
    let mut values = Vec::with_capacity(n * HEX_LEN);
    for s in segs {
        values.extend_from_slice(pick(s));
    }
    let offsets = OffsetBuffer::from_lengths(std::iter::repeat_n(HEX_LEN, n));
    StringArray::new(offsets, Buffer::from_vec(values), None)
}

/// Assemble the variable-width **`fields`** provenance column from the fold's
/// per-worker seg buffers with ONE bulk copy into a preallocated value buffer.
/// Each seg already holds its rows' JSON concatenated (`fields_vals`) with per-row
/// lengths (`fields_lens`) and validity (`fields_valid`), so the column is those
/// blocks memcpy'd end-to-end, offsets from the per-row lengths, and a null buffer
/// only when some row's serialization errored (the cold path — a `String→String`
/// map effectively never fails). No per-row `Vec<Option<&str>>` / `from_iter`
/// pass; `StringArray::new` validates the whole buffer as UTF-8 in one simd pass.
fn fields_column(segs: &[ProvSeg], n: usize) -> StringArray {
    let total: usize = segs.iter().map(|s| s.fields_vals.len()).sum();
    let mut values = Vec::with_capacity(total);
    let mut lens: Vec<usize> = Vec::with_capacity(n);
    let mut valid: Vec<bool> = Vec::with_capacity(n);
    let mut any_null = false;
    for s in segs {
        values.extend_from_slice(&s.fields_vals);
        lens.extend(s.fields_lens.iter().map(|&l| l as usize));
        for &v in &s.fields_valid {
            any_null |= !v;
            valid.push(v);
        }
    }
    let offsets = OffsetBuffer::from_lengths(lens);
    // Match the old `collect()` repr: no null buffer when every row is valid.
    let nulls = if any_null {
        Some(valid.into_iter().collect::<NullBuffer>())
    } else {
        None
    };
    StringArray::new(offsets, Buffer::from_vec(values), nulls)
}

/// Assemble a **non-null** variable-width string column (the v1 payload columns:
/// `host`, `service`, `source`, `environment`, `severity`, `log_type`,
/// `message`) from the fold's per-worker seg buffers with ONE bulk copy into a
/// preallocated value buffer — the same shape as [`fields_column`], minus the
/// validity vector (payload strings are never null). `pick(seg)` is that seg's
/// [`StrCol`] for this column, so the blocks are memcpy'd end-to-end
/// (`~n_workers` copies, not `n`), the offsets come from the per-row lengths, and
/// `StringArray::new` validates the whole buffer as UTF-8 in one simd pass. The
/// output is byte-identical to the old
/// `rows.iter().map(|(e,_)| Some(..)).collect::<StringArray>()`.
fn str_column(segs: &[ProvSeg], n: usize, pick: impl Fn(&ProvSeg) -> &StrCol) -> StringArray {
    let total: usize = segs.iter().map(|s| pick(s).vals.len()).sum();
    let mut values = Vec::with_capacity(total);
    let mut lens: Vec<usize> = Vec::with_capacity(n);
    for s in segs {
        let c = pick(s);
        values.extend_from_slice(&c.vals);
        lens.extend(c.lens.iter().map(|&l| l as usize));
    }
    let offsets = OffsetBuffer::from_lengths(lens);
    StringArray::new(offsets, Buffer::from_vec(values), None)
}

/// Every per-row **string** column of the native `Event` build, assembled from
/// one parallel fold: the three provenance columns plus the seven v1 payload
/// strings (see [`V1_STR`]). Column order in `v1` matches [`V1_STR_POS`].
struct FoldedCols {
    fields: StringArray,
    event_id: StringArray,
    raw_payload_hash: StringArray,
    v1: [StringArray; V1_STR],
}

/// Build every per-row **string** column — the three provenance columns
/// (`fields`, `event_id`, `raw_payload_hash`) AND the seven v1 payload strings
/// (`host` … `message`) — in ONE pass with ZERO per-row allocation. Above the
/// threshold the rows are split into contiguous partitions folded across every
/// core via `gatling_reduce` (private per-worker `ProvSeg`, no rayon — ROOT LAW
/// #0); below it a single serial seg.
///
/// The Arrow arrays are then assembled directly from the fold's per-worker byte
/// buffers with one bulk copy per column (`~n_workers` `extend_from_slice` calls,
/// not `n`) plus a single simd UTF-8 validation. Folding the v1 strings in here
/// (instead of the seven serial `from_iter` passes `build_batch` used to run
/// after the fold) removes the encode path's Amdahl serial tail — the #1 open
/// lever in `.nornir/uber-garm-one-core-root-cause-2026-07-27.md` §5/§7.2 — so
/// the fan-out reaches the string-column work as well as the hashing.
fn fold_string_columns(rows: &[(&Event, Option<&str>)]) -> FoldedCols {
    let n = rows.len();
    let workers = if n >= PARALLEL_ROW_THRESHOLD { 0 } else { 1 };
    let segs: Vec<ProvSeg> = gatling::gatling_forkjoin::gatling_reduce(
        n,
        workers,
        || Vec::<ProvSeg>::with_capacity(1),
        |acc, i| {
            if acc.is_empty() {
                acc.push(ProvSeg::default());
            }
            acc.last_mut().unwrap().absorb(rows[i].0);
        },
        |acc, mut part| acc.append(&mut part),
    );

    FoldedCols {
        fields: fields_column(&segs, n),
        event_id: hex_column(&segs, n, |s| &s.id_hex),
        raw_payload_hash: hex_column(&segs, n, |s| &s.ph_hex),
        v1: std::array::from_fn(|c| str_column(&segs, n, |s| &s.v1[c])),
    }
}

#[cfg(test)]
fn payload_hash(message: &str) -> String {
    blake3::hash(message.as_bytes()).to_hex().to_string()
}

/// Build a `RecordBatch` from a slice of normalised events (unattributed:
/// `collector_id` NULL, `source_trust` = `unverified`). Byte-identical to before
/// Phase 12 for every existing caller.
pub fn build_events_batch(events: &[Event]) -> anyhow::Result<RecordBatch> {
    let rows: Vec<(&Event, Option<&str>)> = events.iter().map(|e| (e, None)).collect();
    build_batch(&rows)
}

/// Build a batch where each event carries an optional AUTHENTICATED collector id
/// (Phase 12). `Some` ⇒ `collector_id` stamped + `source_trust` = `authenticated`;
/// `None` ⇒ NULL + `unverified` (the unauthenticated/legacy row).
pub fn build_events_batch_attributed(
    rows: &[(Event, Option<String>)],
) -> anyhow::Result<RecordBatch> {
    let refs: Vec<(&Event, Option<&str>)> = rows.iter().map(|(e, c)| (e, c.as_deref())).collect();
    build_batch(&refs)
}

/// Number of v1 payload columns (positions 0..8): `event_ts` .. `fields`. The
/// Arrow-Flight wire carries exactly these; the receiver appends the v2
/// provenance columns. See [`events_schema`] and the Flight design doc.
const V1_COLUMNS: usize = 9;

/// Downcast column `i` of `wire` to a `StringArray`, or a clear error.
fn wire_str(wire: &RecordBatch, i: usize) -> anyhow::Result<&skade::arrow_array::StringArray> {
    wire.column(i)
        .as_any()
        .downcast_ref::<StringArray>()
        .ok_or_else(|| anyhow::anyhow!("wire column {i} is not Utf8"))
}

/// A `StringArray` value, treating NULL as the empty string — an `Event`'s
/// `String` fields are never null (an absent value is `""`), so this makes the
/// wire path's id hash match the `Event` path's for the canonical event.
#[inline]
fn str_or_empty(a: &skade::arrow_array::StringArray, i: usize) -> &str {
    use skade::arrow_array::Array;
    if a.is_null(i) {
        ""
    } else {
        a.value(i)
    }
}

/// **The columnar swallow (Flight ingest, f4).** Turn an Arrow **wire batch** —
/// the 9 v1 payload columns a `flightbeat` sender ships — into the full 16-column
/// events `RecordBatch`, computing every v2 provenance column WITHOUT ever
/// materialising an owned `Event` and without re-serializing `fields` (it is
/// already a JSON column on the wire). The v1 columns pass through zero-copy
/// (cloned `Arc`s); the two BLAKE3 columns are hashed straight from the arrays via
/// the SAME [`hash_id_parts`] the `Event` path uses, so a Flight-delivered event
/// and the same event via NDJSON share one `event_id` (one dedup identity).
///
/// `collector` is the AUTHENTICATED Flight peer identity (or `None`): it stamps
/// `collector_id` and lifts `source_trust` to `authenticated`, exactly as the
/// native attributed path does. The wire batch's `fields` column must be the
/// canonical JSON of the field map (sorted keys — what `serde_json` emits for the
/// `BTreeMap`) for the cross-path id to match.
pub fn build_events_batch_from_wire(
    wire: &RecordBatch,
    collector: Option<&str>,
) -> anyhow::Result<RecordBatch> {
    // Validate the wire batch is the v1 payload prefix — the Flight analogue of
    // native ingest's `deny_unknown_fields`: a misdirected or malformed batch
    // fails loudly rather than corrupting the table.
    anyhow::ensure!(
        wire.num_columns() >= V1_COLUMNS,
        "wire batch has {} columns, need the {V1_COLUMNS} v1 payload columns",
        wire.num_columns()
    );
    let want = events_schema();
    for i in 0..V1_COLUMNS {
        let wf = wire.schema();
        let wf = wf.field(i);
        let ef = want.field(i);
        anyhow::ensure!(
            wf.name() == ef.name() && wf.data_type() == ef.data_type(),
            "wire column {i} is {}:{:?}, expected {}:{:?}",
            wf.name(),
            wf.data_type(),
            ef.name(),
            ef.data_type()
        );
    }

    let n = wire.num_rows();
    let ts = wire
        .column(0)
        .as_any()
        .downcast_ref::<TimestampMicrosecondArray>()
        .ok_or_else(|| anyhow::anyhow!("wire column 0 (event_ts) is not Timestamp(us)"))?;
    let host = wire_str(wire, 1)?;
    let service = wire_str(wire, 2)?;
    let source = wire_str(wire, 3)?;
    let message = wire_str(wire, 7)?;
    let fields = wire_str(wire, 8)?;

    // event_id + raw_payload_hash from the arrays, zero per-row alloc, fanned via
    // gatling_reduce (reused per-worker hex buffers — the same shape as
    // `build_provenance`). `fields` is already serialized on the wire, so its
    // bytes are hashed directly (no re-serialize).
    use skade::arrow_array::Array;
    let workers = if n >= PARALLEL_ROW_THRESHOLD { 0 } else { 1 };
    let segs: Vec<(Vec<u8>, Vec<u8>)> = gatling::gatling_forkjoin::gatling_reduce(
        n,
        workers,
        || Vec::<(Vec<u8>, Vec<u8>)>::with_capacity(1),
        |acc, i| {
            if acc.is_empty() {
                acc.push((Vec::new(), Vec::new()));
            }
            let (id_hex, ph_hex) = acc.last_mut().unwrap();
            let fj = if fields.is_null(i) {
                None
            } else {
                Some(fields.value(i).as_bytes())
            };
            let id = hash_id_parts(
                ts.value(i),
                str_or_empty(host, i),
                str_or_empty(source, i),
                str_or_empty(service, i),
                str_or_empty(message, i),
                fj,
            );
            let mut slot = [0u8; HEX_LEN];
            write_hex(&mut slot, id.as_bytes());
            id_hex.extend_from_slice(&slot);
            write_hex(
                &mut slot,
                blake3::hash(str_or_empty(message, i).as_bytes()).as_bytes(),
            );
            ph_hex.extend_from_slice(&slot);
        },
        |acc, mut part| acc.append(&mut part),
    );
    // Assemble the two hex columns directly from the per-worker seg buffers with
    // one bulk copy each — the same `hex_column` the native path uses, so the
    // array building is not a per-row serial tail after the fold.
    let event_id = hex_column(&segs, n, |(id, _)| id.as_slice());
    let raw_payload_hash = hex_column(&segs, n, |(_, ph)| ph.as_slice());

    // v2 columns computed server-side (authority): const version, receive time,
    // parser name (= source), and the collector attribution → trust.
    let now_us = Utc::now().timestamp_micros();
    let schema_version: Int32Array = (0..n).map(|_| Some(EVENT_SCHEMA_VERSION)).collect();
    let ingest_time: TimestampMicrosecondArray = (0..n).map(|_| Some(now_us)).collect();
    let parser_name: StringArray = (0..n).map(|i| Some(str_or_empty(source, i))).collect();
    let trust = if collector.is_some() {
        "authenticated"
    } else {
        "unverified"
    };
    let source_trust: StringArray = (0..n).map(|_| Some(trust)).collect();
    let collector_id: StringArray = (0..n).map(|_| collector).collect();

    // v1 columns pass through zero-copy (cloned Arcs); v2 freshly built. Same
    // column order as `events_schema`.
    let cols: Vec<ArrayRef> = vec![
        wire.column(0).clone(),
        wire.column(1).clone(),
        wire.column(2).clone(),
        wire.column(3).clone(),
        wire.column(4).clone(),
        wire.column(5).clone(),
        wire.column(6).clone(),
        wire.column(7).clone(),
        wire.column(8).clone(),
        Arc::new(schema_version),
        Arc::new(event_id),
        Arc::new(ingest_time),
        Arc::new(raw_payload_hash),
        Arc::new(parser_name),
        Arc::new(source_trust),
        Arc::new(collector_id),
    ];
    Ok(RecordBatch::try_new(Arc::new(events_schema()), cols)?)
}

/// The v1 payload schema — the 9 columns a `flightbeat` sender ships (the prefix
/// of [`events_schema`]). The receiver appends the v2 provenance columns.
pub fn wire_schema() -> Schema {
    Schema::new(events_schema().fields()[..V1_COLUMNS].to_vec())
}

/// Build a **wire batch** — the 9 v1 payload columns — from events: what a
/// `flightbeat` sender emits (and the `ingest_flight` bench arm ships). No
/// provenance, no hashing; just the payload columns (`fields` serialized to its
/// canonical JSON, so the receiver's recomputed `event_id` matches the native
/// path's — see [`build_events_batch_from_wire`]).
pub fn build_wire_batch(events: &[Event]) -> anyhow::Result<RecordBatch> {
    let ts: TimestampMicrosecondArray = events
        .iter()
        .map(|e| Some(e.ts.timestamp_micros()))
        .collect();
    let host: StringArray = events.iter().map(|e| Some(e.host.as_str())).collect();
    let service: StringArray = events.iter().map(|e| Some(e.service.as_str())).collect();
    let source: StringArray = events.iter().map(|e| Some(e.source.as_str())).collect();
    let environment: StringArray = events
        .iter()
        .map(|e| Some(e.environment.as_str()))
        .collect();
    let severity: StringArray = events.iter().map(|e| Some(e.severity.as_str())).collect();
    let log_type: StringArray = events.iter().map(|e| Some(e.log_type.as_str())).collect();
    let message: StringArray = events.iter().map(|e| Some(e.message.as_str())).collect();
    let fields: StringArray = events
        .iter()
        .map(|e| serde_json::to_string(&e.fields).ok())
        .collect();
    let cols: Vec<ArrayRef> = vec![
        Arc::new(ts),
        Arc::new(host),
        Arc::new(service),
        Arc::new(source),
        Arc::new(environment),
        Arc::new(severity),
        Arc::new(log_type),
        Arc::new(message),
        Arc::new(fields),
    ];
    Ok(RecordBatch::try_new(Arc::new(wire_schema()), cols)?)
}

/// The shared column builder — refs only, no `Event` clone. Column order matches
/// [`events_schema`] exactly.
fn build_batch(rows: &[(&Event, Option<&str>)]) -> anyhow::Result<RecordBatch> {
    // `event_ts` is a cheap `i64`-micros primitive — built serially. Every per-row
    // STRING column (the seven v1 payload strings AND the three provenance columns)
    // is built inside ONE gatling fold below, so the seven serial `from_iter`
    // string passes that used to trail the fold — the encode Amdahl serial tail
    // (root-cause §5) — are gone.
    let ts: TimestampMicrosecondArray = rows
        .iter()
        .map(|(e, _)| Some(e.ts.timestamp_micros()))
        .collect();

    // ---- every per-row string column, fanned across cores via `gatling_reduce` ----
    // The real per-row work: `fields` JSON (serialized once into a reused per-worker
    // buffer, feeding the `event_id` hash — no double serialize), two BLAKE3 hashes,
    // and the seven v1 payload strings, all folded in one no-barrier pass.
    let FoldedCols {
        fields,
        event_id,
        raw_payload_hash,
        v1: [host, service, source, environment, severity, log_type, message],
    } = fold_string_columns(rows);
    // `parser_name` is byte-for-byte the `source` column; share the immutable Arrow
    // Arc rather than rebuild it (one fewer string column, identical output).
    let source_col: ArrayRef = Arc::new(source);

    // --- trailing v2 columns: cheap constants + the per-row collector Option ---
    let now_us = Utc::now().timestamp_micros();
    let schema_version: Int32Array = rows.iter().map(|_| Some(EVENT_SCHEMA_VERSION)).collect();
    let ingest_time: TimestampMicrosecondArray = rows.iter().map(|_| Some(now_us)).collect();
    // source_trust reflects the collector attribution.
    let source_trust: StringArray = rows
        .iter()
        .map(|(_, c)| {
            Some(if c.is_some() {
                "authenticated"
            } else {
                "unverified"
            })
        })
        .collect();
    let collector_id: StringArray = rows.iter().map(|(_, c)| *c).collect();

    let cols: Vec<ArrayRef> = vec![
        Arc::new(ts),
        Arc::new(host),
        Arc::new(service),
        source_col.clone(), // source
        Arc::new(environment),
        Arc::new(severity),
        Arc::new(log_type),
        Arc::new(message),
        Arc::new(fields),
        Arc::new(schema_version),
        Arc::new(event_id),
        Arc::new(ingest_time),
        Arc::new(raw_payload_hash),
        source_col, // parser_name == source
        Arc::new(source_trust),
        Arc::new(collector_id),
    ];
    Ok(RecordBatch::try_new(Arc::new(events_schema()), cols)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use skade::arrow_array::{Array, StringArray};
    use std::collections::BTreeMap;

    fn ev() -> Event {
        Event {
            ts: Utc::now(),
            host: "h".into(),
            service: "s".into(),
            source: "syslog".into(),
            environment: "prod".into(),
            severity: "info".into(),
            log_type: "system".into(),
            message: "m".into(),
            fields: BTreeMap::new(),
        }
    }

    fn col<'a>(b: &'a RecordBatch, name: &str) -> &'a StringArray {
        let i = b.schema().index_of(name).unwrap();
        b.column(i).as_any().downcast_ref::<StringArray>().unwrap()
    }

    #[test]
    fn attributed_stamps_collector_and_trust_unattributed_is_null() {
        let e = ev();
        let batch = build_events_batch_attributed(&[
            (e.clone(), Some("collector-a".into())),
            (e.clone(), None),
        ])
        .unwrap();
        let cid = col(&batch, "collector_id");
        assert_eq!(cid.value(0), "collector-a");
        assert!(cid.is_null(1), "an unattributed row has NULL collector_id");
        let trust = col(&batch, "source_trust");
        assert_eq!(trust.value(0), "authenticated");
        assert_eq!(trust.value(1), "unverified");

        // The plain builder is byte-identical to before: NULL + unverified.
        let plain = build_events_batch(&[e]).unwrap();
        assert!(col(&plain, "collector_id").is_null(0));
        assert_eq!(col(&plain, "source_trust").value(0), "unverified");
    }

    #[test]
    fn event_id_is_independent_of_collector_attribution() {
        // Dedup identity must not change with attribution.
        let e = ev();
        assert_eq!(
            event_id_for(&e),
            col(
                &build_events_batch_attributed(&[(e.clone(), Some("x".into()))]).unwrap(),
                "event_id"
            )
            .value(0)
        );
    }

    /// The gatling fan-out that fills the provenance columns for a large batch
    /// must produce EXACTLY what a serial `event_id_for` / `payload_hash` /
    /// `fields`-serialize would — same value, same row. This drives a batch past
    /// [`PARALLEL_ROW_THRESHOLD`] so the parallel path actually runs, then checks
    /// every row against an independent serial oracle. It goes red the instant the
    /// fan-out misaligns an index, drops the double-serialize equivalence, or the
    /// worker order leaks into the output.
    /// The fan-out must be REACHABLE at the batch sizes production actually
    /// produces — a correct, tested fan-out that never runs is dead code.
    ///
    /// Live ingest coalesces `min(MAX_COALESCE_EVENTS = 10_000, 3 s of arrivals)`
    /// into one commit (`garmr-cli/src/pipeline.rs`), so this threshold is also
    /// an implicit **ingest-rate** gate: the fan-out only runs above
    /// `PARALLEL_ROW_THRESHOLD / 3 s` events per second. At the old value of 4096
    /// that was ~1 365 events/sec — above what many deployments sustain, so the
    /// whole parallel provenance build was skipped in the field while every
    /// published bench number (50 000-row batches) exercised it.
    ///
    /// The bound below is the MEASURED break-even (~734 rows on t14s: a 195 µs
    /// gatling entry against a 625 ns/row serial build at a 1.74× fan-out
    /// speedup) rounded up with margin — see
    /// `.nornir/uber-garm-one-core-root-cause-2026-07-27.md` §6. This test goes
    /// red if anyone raises the threshold back toward a value that switches the
    /// fan-out off in production, and it is deliberately a statement about a
    /// measurement rather than about taste.
    #[test]
    // The assertion IS about a compile-time constant — that is the whole point:
    // it pins a tuning constant to a measurement so raising it fails the build
    // rather than silently switching a fan-out off in production.
    #[allow(clippy::assertions_on_constants)]
    fn parallel_threshold_is_reachable_at_production_batch_sizes() {
        const MEASURED_BREAK_EVEN_ROWS: usize = 734;
        const MARGIN: usize = 4; // stay within 4x of break-even
        assert!(
            PARALLEL_ROW_THRESHOLD <= MEASURED_BREAK_EVEN_ROWS * MARGIN,
            "PARALLEL_ROW_THRESHOLD = {PARALLEL_ROW_THRESHOLD} is more than {MARGIN}x the \
             measured break-even ({MEASURED_BREAK_EVEN_ROWS} rows). At a 3-second ingest \
             coalesce window that switches the columnar fan-out OFF below \
             {} events/sec — dead code in the field. Re-derive the break-even \
             (probe::forkjoin_spawn_cost_us vs the serial per-row cost) before raising it.",
            PARALLEL_ROW_THRESHOLD / 3,
        );
    }

    #[test]
    // Same as above: a deliberate assertion about a constant, guarding that this
    // test can actually straddle the serial/parallel split.
    #[allow(clippy::assertions_on_constants)]
    fn parallel_provenance_matches_serial_oracle() {
        assert!(
            PARALLEL_ROW_THRESHOLD >= 2,
            "threshold must leave room for a serial vs parallel split"
        );
        let n = PARALLEL_ROW_THRESHOLD + 137; // safely into the parallel regime
        let events: Vec<Event> = (0..n)
            .map(|i| {
                let mut e = ev();
                // Distinct host + message + a fields entry per row so identical
                // ids across rows can't mask a misalignment.
                e.host = format!("host-{i}").into();
                e.message = format!("line {i} user=mallory port={}", i % 65535);
                e.fields
                    .insert("src_ip".into(), format!("10.0.{}.{}", i / 256, i % 256));
                e.fields.insert("seq".into(), i.to_string());
                e
            })
            .collect();

        let batch = build_events_batch(&events).unwrap();
        assert_eq!(batch.num_rows(), n);

        let id_col = col(&batch, "event_id");
        let hash_col = col(&batch, "raw_payload_hash");
        let fields_col = col(&batch, "fields");
        // The v1 payload string columns are now built in the SAME gatling fold as
        // the provenance columns, so a misaligned partition or a leaked worker
        // order would corrupt them too. Check every one against the source event —
        // `host`/`message` are distinct per row, so a cross-partition shuffle is
        // caught, and `parser_name` must mirror `source` byte-for-byte.
        let host_col = col(&batch, "host");
        let service_col = col(&batch, "service");
        let source_col = col(&batch, "source");
        let env_col = col(&batch, "environment");
        let sev_col = col(&batch, "severity");
        let lt_col = col(&batch, "log_type");
        let msg_col = col(&batch, "message");
        let parser_col = col(&batch, "parser_name");
        for (i, e) in events.iter().enumerate() {
            assert_eq!(id_col.value(i), event_id_for(e), "event_id row {i}");
            assert_eq!(
                hash_col.value(i),
                payload_hash(&e.message),
                "payload_hash row {i}"
            );
            assert_eq!(
                fields_col.value(i),
                serde_json::to_string(&e.fields).unwrap(),
                "fields json row {i}"
            );
            assert_eq!(host_col.value(i), e.host.as_str(), "host row {i}");
            assert_eq!(service_col.value(i), e.service.as_str(), "service row {i}");
            assert_eq!(source_col.value(i), e.source.as_str(), "source row {i}");
            assert_eq!(
                env_col.value(i),
                e.environment.as_str(),
                "environment row {i}"
            );
            assert_eq!(sev_col.value(i), e.severity.as_str(), "severity row {i}");
            assert_eq!(lt_col.value(i), e.log_type.as_str(), "log_type row {i}");
            assert_eq!(msg_col.value(i), e.message.as_str(), "message row {i}");
            assert_eq!(
                parser_col.value(i),
                e.source.as_str(),
                "parser_name row {i}"
            );
        }
    }

    /// The Arrow-wire columnar swallow (Flight ingest) must reproduce the v2
    /// provenance BYTE-FOR-BYTE against the native `Event` path — the guarantee
    /// that a Flight-delivered event and the same event via NDJSON share one
    /// `event_id` (one dedup identity). Build a canonical batch from events, take
    /// its 9 v1 columns as the "wire", swallow them, and assert event_id /
    /// raw_payload_hash / fields match the native build exactly — plus that the
    /// collector attribution stamps source_trust + collector_id. Crosses the
    /// parallel threshold so the gatling wire path runs. Red the instant the two
    /// paths' id hashing, column order, or attribution diverge.
    #[test]
    fn wire_swallow_matches_native_provenance_and_stamps_collector() {
        let n = PARALLEL_ROW_THRESHOLD + 41;
        let events: Vec<Event> = (0..n)
            .map(|i| {
                let mut e = ev();
                e.host = format!("host-{i}").into();
                e.source = "flightbeat".into();
                e.message = format!("line {i} from {}", i % 7);
                e.fields
                    .insert("src_ip".into(), format!("10.1.{}.{}", i / 256, i % 256));
                e
            })
            .collect();

        // Native path → canonical full batch; its first 9 columns are the wire.
        let native = build_events_batch(&events).unwrap();
        let wire = native
            .project(&(0..V1_COLUMNS).collect::<Vec<_>>())
            .unwrap();

        let swallowed = build_events_batch_from_wire(&wire, Some("collector-x")).unwrap();
        assert_eq!(swallowed.num_rows(), n);

        // Provenance is byte-identical to the native build → same dedup identity.
        for c in ["event_id", "raw_payload_hash", "fields", "host", "message"] {
            assert_eq!(col(&swallowed, c), col(&native, c), "column {c} diverged");
        }
        // Collector attribution stamped.
        let trust = col(&swallowed, "source_trust");
        let cid = col(&swallowed, "collector_id");
        for i in 0..n {
            assert_eq!(trust.value(i), "authenticated", "source_trust row {i}");
            assert_eq!(cid.value(i), "collector-x", "collector_id row {i}");
        }

        // Unattributed swallow → unverified + NULL collector, matching native.
        let plain = build_events_batch_from_wire(&wire, None).unwrap();
        use skade::arrow_array::Array;
        assert_eq!(col(&plain, "source_trust").value(0), "unverified");
        assert!(col(&plain, "collector_id").is_null(0));

        // A wire batch missing v1 columns is rejected (deny-unknown analogue).
        let truncated = native.project(&[0, 1, 2]).unwrap();
        assert!(build_events_batch_from_wire(&truncated, None).is_err());
    }
}
