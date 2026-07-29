//! Parallel NDJSON (JSON-Lines) scanner — the [`vtd`](crate::vtd) pattern
//! applied to newline-delimited JSON.
//!
//! ## The safe-split insight
//!
//! Per RFC 8259 §7, unescaped control characters (U+0000 through U+001F) are
//! **illegal** inside JSON strings — and that includes 0x0A. A newline that
//! appears inside a string value must be written as the two bytes `\n`
//! (backslash + 'n'), never as a raw 0x0A byte. Therefore, in valid NDJSON,
//! **every raw `\n` byte in the input IS a record boundary** — there is no
//! place a raw newline can legally hide inside a record.
//!
//! That makes the parallel split trivial: cut the input at a candidate offset
//! (`len / n_workers`), then `memchr(b'\n')` forward to just past the next
//! newline — guaranteed not to split a record. Same candidate-offset +
//! forward-seek pattern as the XML scanner's `find_top_level_start`, only
//! simpler: a single memchr instead of a tag-name probe.
//!
//! Corollary: no string/escape state machine is needed for SPLITTING. Escape
//! handling (`\"`, `\\`) only matters inside per-record field probing
//! ([`find_key`]), which is string-aware and depth-tracked.
//!
//! ## Out of scope (v1)
//!
//! A single giant JSON array (`[{...},{...},...]`) has no raw-newline
//! guarantee between elements — splitting one requires a sequential
//! string-aware depth scan to find element boundaries. NDJSON / JSON-seq is
//! the v1 surface; array splitting is future work.

use memchr::memchr;

// ── RecordSpan ───────────────────────────────────────────────────────────────

/// Byte range of one NDJSON record in the original input. The terminating
/// newline (and a trailing `\r` for CRLF input) is excluded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecordSpan {
    /// Byte offset of the record's first byte in the original input.
    pub offset: usize,
    /// Byte length of the record (newline / `\r` excluded).
    pub len: usize,
}

// ── Error ────────────────────────────────────────────────────────────────────

/// Failure while scanning a JSON **array** ([`scan_array_spans`]). NDJSON
/// scanning is infallible (any byte layout is tolerated), so only the array
/// path — which must honour string/escape/depth structure — can fail.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JsonError {
    /// The top-level value is not a JSON array (no leading `[` after
    /// whitespace) — e.g. an object, a bare scalar, or empty input.
    ExpectedArray,
    /// Malformed structure at the given absolute byte offset — an unterminated
    /// string or container, or input that ends before the closing `]`.
    Malformed(usize),
}

impl std::fmt::Display for JsonError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            JsonError::ExpectedArray => write!(f, "top-level value is not a JSON array"),
            JsonError::Malformed(at) => write!(f, "malformed JSON array at byte offset {at}"),
        }
    }
}

impl std::error::Error for JsonError {}

// ── Safe split ───────────────────────────────────────────────────────────────

/// Forward-seek from `candidate` to the nearest safe split point: the byte
/// just past the next `\n`, or `bytes.len()` if no newline follows.
///
/// Safe because a raw 0x0A is illegal inside a JSON string (RFC 8259 §7), so
/// the returned offset can never land inside a record. Monotonic in
/// `candidate`, so candidate offsets produced by `len / n_workers` always
/// yield non-overlapping, ordered slices (a candidate landing inside the
/// same line as its predecessor simply produces an empty slice).
#[inline]
pub fn find_safe_split(bytes: &[u8], candidate: usize) -> usize {
    if candidate >= bytes.len() {
        return bytes.len();
    }
    match memchr(b'\n', &bytes[candidate..]) {
        Some(rel) => candidate + rel + 1,
        None => bytes.len(),
    }
}

// ── Sequential scan ──────────────────────────────────────────────────────────

/// Core scanner: emit one [`RecordSpan`] per non-empty line in `slice`.
/// `base` is added to every offset so spans carry absolute positions into
/// the original input (not positions within the slice).
///
/// - `\r\n` line endings: the `\r` is trimmed from the span.
/// - Empty lines (and a lone `\r`): tolerated, NOT reported.
/// - Final record without a trailing newline: counted.
///
/// Returns the number of records emitted.
pub fn scan_records_slice(
    slice: &[u8],
    base: usize,
    on_record: &mut impl FnMut(RecordSpan),
) -> u64 {
    let mut pos = 0usize;
    let mut count = 0u64;

    while pos < slice.len() {
        let line_end = match memchr(b'\n', &slice[pos..]) {
            Some(rel) => pos + rel,
            None => slice.len(),
        };

        // Trim a trailing '\r' (CRLF input).
        let mut end = line_end;
        if end > pos && slice[end - 1] == b'\r' {
            end -= 1;
        }

        // Empty lines are separators, not records.
        if end > pos {
            on_record(RecordSpan {
                offset: base + pos,
                len: end - pos,
            });
            count += 1;
        }

        pos = line_end + 1;
    }

    count
}

/// Single-threaded scan over the whole input. Kept for tests and small inputs.
pub fn scan_records<F>(bytes: &[u8], mut on_record: F) -> u64
where
    F: FnMut(RecordSpan),
{
    scan_records_slice(bytes, 0, &mut on_record)
}

// ── Parallel scan ────────────────────────────────────────────────────────────

/// Parallel scan: cut the input at `n_workers` candidate offsets, forward-seek
/// each cut to a safe split point ([`find_safe_split`]), then scan the slices
/// independently on the gatling fork-join pool. No barrier, no rendezvous — the
/// boundaries are fully determined up front by `n` memchr probes (~nanoseconds
/// each).
///
/// Parallelism is [`gatling_for_each`](crate::gatling_forkjoin::gatling_for_each):
/// `std::thread::scope` + one shared atomic cursor, no global pool (this crate is
/// rayon-free — see `.nornir/gatling-guide.md`, rule zero).
///
/// Results are collected per-slice into `Vec<RecordSpan>`, then merged in
/// input order and fed to `on_record` on the calling thread — same shape as
/// `vtd::build_elem_index_pipelined`. Returns the total record count.
pub fn scan_records_parallel<F>(bytes: &[u8], n_workers: usize, mut on_record: F) -> u64
where
    F: FnMut(RecordSpan),
{
    use crate::gatling_forkjoin::gatling_for_each;

    let n = n_workers.max(1);

    if n == 1 || bytes.is_empty() {
        return scan_records(bytes, on_record);
    }

    // OVERSPLIT + self-dispatch. The old shape cut the file into exactly `n`
    // equal-BYTE slices and ran `n` workers — one slice per worker, no stealing:
    // a slice that happens to hold heavier/denser records (or lands past a long
    // record) leaves its worker running alone while the others sit idle having
    // drained their light slices. Cutting into MANY more slices than cores and
    // letting the engine self-dispatch (workers = 0 ⇒ one per core, shared atomic
    // cursor) means an idle core just claims the next slice — the dense tail is
    // spread across all cores instead of choking one. `SPLIT` slices per worker
    // is enough granularity to balance without over-fragmenting the memchr cuts.
    const SPLIT: usize = 8;
    let chunks = (n * SPLIT).min(bytes.len()).max(1);

    // Candidate offsets → safe boundaries. Slice 0 always starts at 0;
    // every other boundary is just past a newline, so no record straddles one.
    let chunk_size = (bytes.len() / chunks).max(1);
    let mut bounds = Vec::with_capacity(chunks + 1);
    bounds.push(0usize);
    for i in 1..chunks {
        bounds.push(find_safe_split(bytes, i * chunk_size));
    }
    bounds.push(bytes.len());

    // `bounds` may collapse to fewer distinct cut points than `chunks` (e.g. a
    // file with one enormous record swallows several nominal cuts); the real
    // slice count is `bounds.len() - 1`. Self-dispatch across one-worker-per-core.
    let slices = bounds.len() - 1;
    let partials: Vec<Vec<RecordSpan>> = gatling_for_each(slices, 0, |i| {
        let start = bounds[i];
        let end = bounds[i + 1];
        let mut local: Vec<RecordSpan> = Vec::new();
        scan_records_slice(&bytes[start..end], start, &mut |r| local.push(r));
        local
    });

    let mut total = 0u64;
    for partial in partials {
        total += partial.len() as u64;
        for r in partial {
            on_record(r);
        }
    }
    total
}

/// Parallel scan **fused with a per-record map** — the version where the
/// per-record parse runs on ALL cores. [`scan_records_parallel`] discovers the
/// [`RecordSpan`]s in parallel but then hands them to `on_record` **serially on
/// the calling thread**, so a caller whose real work is the parse is pinned to
/// one core. Here each gatling worker instead FUSES scan + map: it walks its
/// slice `\n`→`\n` and, for every record, immediately calls
/// `map(span, &bytes[span.offset .. span.offset + span.len])` — so the record
/// parse happens in the worker, spread across every core.
///
/// The NDJSON analogue of [`scan_array_parallel`], sharing
/// [`scan_records_parallel`]'s oversplit + [`find_safe_split`] boundary logic:
/// the input is cut into `n_workers * SPLIT` slices at safe (post-newline)
/// boundaries and self-dispatched one-per-core. Each worker returns a local
/// `Vec<T>`; the per-slice vectors are concatenated **in input order**, so the
/// result is deterministic regardless of worker scheduling — identical to a
/// serial `map` over the records.
///
/// Small input / `n_workers == 1` → a serial fused map on the calling thread.
pub fn scan_records_map_parallel<T, F>(bytes: &[u8], n_workers: usize, map: F) -> Vec<T>
where
    T: Send,
    F: Fn(RecordSpan, &[u8]) -> T + Sync,
{
    use crate::gatling_forkjoin::gatling_for_each;

    let n = n_workers.max(1);

    // Small-input / single-worker → serial fused map on the calling thread.
    if n == 1 || bytes.is_empty() {
        let mut out = Vec::new();
        scan_records_slice(bytes, 0, &mut |r| {
            out.push(map(r, &bytes[r.offset..r.offset + r.len]));
        });
        return out;
    }

    // OVERSPLIT + self-dispatch — identical boundary logic to
    // `scan_records_parallel` (see its comment): `n * SPLIT` slices cut at safe
    // post-newline offsets, self-dispatched one-worker-per-core.
    const SPLIT: usize = 8;
    let chunks = (n * SPLIT).min(bytes.len()).max(1);

    let chunk_size = (bytes.len() / chunks).max(1);
    let mut bounds = Vec::with_capacity(chunks + 1);
    bounds.push(0usize);
    for i in 1..chunks {
        bounds.push(find_safe_split(bytes, i * chunk_size));
    }
    bounds.push(bytes.len());

    // Each worker fuses scan + map over its slice, collecting a local `Vec<T>`.
    // `scan_records_slice` reports spans with ABSOLUTE offsets (base = start),
    // so `map` slices back into the ORIGINAL `bytes`.
    let slices = bounds.len() - 1;
    let partials: Vec<Vec<T>> = gatling_for_each(slices, 0, |i| {
        let start = bounds[i];
        let end = bounds[i + 1];
        let mut local: Vec<T> = Vec::new();
        scan_records_slice(&bytes[start..end], start, &mut |r| {
            local.push(map(r, &bytes[r.offset..r.offset + r.len]));
        });
        local
    });

    // Concatenate per-slice results in input order → deterministic.
    partials.into_iter().flatten().collect()
}

// ── Oversplit boundaries ──────────────────────────────────────────────────────

/// Cut `bytes` into `n_workers * split` slices at safe (post-newline) boundaries
/// — the shared oversplit used by every parallel NDJSON entry point. A higher
/// `split` yields finer load-balancing units for the gatling dispatcher (so no
/// core idles on a heavy tail slice) at the cost of more `find_safe_split`
/// memchr probes. Returns `slices + 1` monotonically non-decreasing offsets
/// (`bounds[0] == 0`, `bounds[last] == bytes.len()`); `bounds.len() - 1` is the
/// real slice count (fewer than requested when cuts collapse onto one line).
fn slice_bounds(bytes: &[u8], n_workers: usize, split: usize) -> Vec<usize> {
    let chunks = (n_workers.max(1) * split.max(1)).min(bytes.len()).max(1);
    let chunk_size = (bytes.len() / chunks).max(1);
    let mut bounds = Vec::with_capacity(chunks + 1);
    bounds.push(0usize);
    for i in 1..chunks {
        bounds.push(find_safe_split(bytes, i * chunk_size));
    }
    bounds.push(bytes.len());
    bounds
}

/// Count the NDJSON records in `slice` (memchr-only, no field work). The count
/// pass of the two-pass slab parser ([`scan_records_slab_with`]).
#[inline]
fn count_records(slice: &[u8]) -> usize {
    let mut c = 0usize;
    scan_records_slice(slice, 0, &mut |_| c += 1);
    c
}

// ── Zero-copy record slab (the production scan primitive) ─────────────────────

/// A borrowed field descriptor: a byte `(offset, len)` **into the parsed input**
/// — never an owned `String`. `#[repr(C)]`, `Copy`, POD. [`FieldSpan::ABSENT`]
/// (`offset == u32::MAX`) marks a key that was not present in the record.
///
/// Offsets are `u32`, so the slab parser addresses inputs up to 4 GiB.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FieldSpan {
    /// Byte offset of the field value in the original input (`u32::MAX` ⇒ absent).
    pub offset: u32,
    /// Byte length of the field value (raw, escapes not decoded).
    pub len: u32,
}

impl FieldSpan {
    /// The sentinel for a key that was not found in the record.
    pub const ABSENT: FieldSpan = FieldSpan {
        offset: u32::MAX,
        len: 0,
    };

    /// Was the key present?
    #[inline]
    pub fn is_present(&self) -> bool {
        self.offset != u32::MAX
    }

    /// Resolve the descriptor back to the borrowed value bytes in `bytes`
    /// (the same input the slab was parsed from), or `None` if absent.
    #[inline]
    pub fn get<'a>(&self, bytes: &'a [u8]) -> Option<&'a [u8]> {
        self.is_present()
            .then(|| &bytes[self.offset as usize..self.offset as usize + self.len as usize])
    }
}

/// One parsed record: `K` located field descriptors, positional to the `keys`
/// config handed to the parser. `#[repr(C)]`, `Copy`, **zero owned allocation** —
/// this is the copy descriptor the fast slab path yields; the consumer copies out
/// only the fields it keeps, AFTER the parallel region.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct JsonRec<const K: usize> {
    /// Field descriptors in the same order as the `keys` config.
    pub fields: [FieldSpan; K],
}

impl<const K: usize> JsonRec<K> {
    /// Borrow field `k`'s value bytes out of `bytes` (the parsed input), or
    /// `None` if that key was absent in this record.
    #[inline]
    pub fn field<'a>(&self, k: usize, bytes: &'a [u8]) -> Option<&'a [u8]> {
        self.fields[k].get(bytes)
    }
}

/// Locate the `K` configured `keys` in one record and pack them into a
/// [`JsonRec`] of borrowed `(offset, len)` descriptors — `find_key`'s `&[u8]`
/// borrow converted to an absolute offset by pointer arithmetic vs `bytes`.
/// No allocation.
#[inline]
fn parse_rec<const K: usize>(bytes: &[u8], span: RecordSpan, keys: &[&str; K]) -> JsonRec<K> {
    let base = bytes.as_ptr() as usize;
    let rec = &bytes[span.offset..span.offset + span.len];
    let mut fields = [FieldSpan::ABSENT; K];
    for (k, slot) in fields.iter_mut().enumerate() {
        if let Some(v) = find_key(rec, keys[k]) {
            let off = (v.as_ptr() as usize - base) as u32;
            *slot = FieldSpan {
                offset: off,
                len: v.len() as u32,
            };
        }
    }
    JsonRec { fields }
}

/// A `Send`+`Sync`+`Copy` raw-pointer wrapper for the disjoint-slot output slab —
/// the same idiom as gatling's internal `OutPtr` (private, so replicated here).
/// Soundness is argued at the write site: every slab index is produced by the
/// prefix-sum, so each slot is written by exactly one worker, never aliased.
struct SlabPtr<T>(*mut T);
impl<T> Clone for SlabPtr<T> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<T> Copy for SlabPtr<T> {}
// SAFETY: workers only ever write DISJOINT indices (prefix-sum bases), never read
// through the pointer and never alias — so sharing it across the scoped threads
// (`&closure`, hence `Sync`) and moving copies in (`Send`) is sound.
unsafe impl<T: Send> Send for SlabPtr<T> {}
unsafe impl<T: Send> Sync for SlabPtr<T> {}
impl<T> SlabPtr<T> {
    /// Write `v` into slot `i`. SAFETY: caller guarantees `i` is in-bounds and
    /// unique to this worker (from the prefix-sum), so no aliasing write.
    #[inline]
    unsafe fn write_at(&self, i: usize, v: T) {
        unsafe { self.0.add(i).write(v) };
    }
}

/// Production zero-alloc NDJSON scan: parse `bytes` into ONE `Vec<JsonRec<K>>`,
/// each record's `K` configured `keys` located as borrowed `(offset, len)`
/// descriptors — **no per-record allocation, no serial teardown**. Baked to the
/// tuned dispatch knobs; [`scan_records_slab_with`] exposes them.
///
/// `keys` is the small fixed field-config the consumer wants located per record
/// (e.g. garm's Event fields); resolve each with [`JsonRec::field`] AFTER the
/// parallel region, copying out only what is kept.
pub fn scan_records_slab<const K: usize>(
    bytes: &[u8],
    keys: [&str; K],
    n_workers: usize,
) -> Vec<JsonRec<K>> {
    scan_records_slab_with(bytes, keys, n_workers, SLAB_SPLIT, SLAB_BATCH)
}

/// Tuned dispatch knobs for [`scan_records_slab`] — winners of the bench sweep
/// (`json.ndjson_slab` in `examples/nornir-bench.rs`, 32-core / ~175 B records):
/// oversplit ×256 (finer LPT units drain the tail — cores climbed 14→26 as split
/// rose 8→256, then declined past it as boundary/dispatch overhead took over),
/// balanced-claim batch 16.
const SLAB_SPLIT: usize = 256;
const SLAB_BATCH: usize = 16;

/// Knob-exposed [`scan_records_slab`] (for tuning / benching). The two-pass
/// blueprint from `vtd::build_elem_index_to_mmap`:
///
/// 1. **Oversplit** into `n_workers * split` safe-boundary slices ([`slice_bounds`]).
/// 2. **Count pass** (parallel [`gatling_for_each`]): records per slice.
/// 3. **Prefix-sum** → each slice's write base + the exact total; allocate ONE
///    `Vec<JsonRec<K>>` of that length.
/// 4. **Parse pass** (parallel, LPT-balanced by slice byte length via
///    [`gatling_for_each_balanced`](crate::gatling_forkjoin::gatling_for_each_balanced)):
///    each slice writes `slab[base + local_i]` directly — disjoint indices, no
///    concat, no per-worker growable `Vec`, no serial post-pass touching every
///    record.
///
/// `split` (oversplit factor) trades finer load-balancing units against more
/// memchr boundary probes; `batch` is the gatling balanced-dispatch claim size.
pub fn scan_records_slab_with<const K: usize>(
    bytes: &[u8],
    keys: [&str; K],
    n_workers: usize,
    split: usize,
    batch: usize,
) -> Vec<JsonRec<K>> {
    use crate::gatling_forkjoin::{gatling_for_each, gatling_for_each_balanced};

    let n = n_workers.max(1);

    // Small-input / single-worker → serial parse into an exact-length slab.
    if n == 1 || bytes.is_empty() {
        let mut out = Vec::new();
        scan_records_slice(bytes, 0, &mut |r| out.push(parse_rec(bytes, r, &keys)));
        return out;
    }

    let bounds = slice_bounds(bytes, n, split);
    let slices = bounds.len() - 1;

    // 2. Count pass — records per slice (parallel, memchr-only).
    let counts: Vec<usize> = gatling_for_each(slices, n, |s| {
        count_records(&bytes[bounds[s]..bounds[s + 1]])
    });

    // 3. Prefix-sum → per-slice write base + exact total.
    let mut bases = Vec::with_capacity(slices);
    let mut total = 0usize;
    for &c in &counts {
        bases.push(total);
        total += c;
    }

    // 4. Parse pass — one slab, disjoint writes, LPT-balanced by slice bytes.
    let mut slab: Vec<JsonRec<K>> = Vec::with_capacity(total);
    {
        let ptr = SlabPtr(slab.as_mut_ptr());
        let weight = |s: usize| (bounds[s + 1] - bounds[s]) as u64;
        let _: Vec<()> = gatling_for_each_balanced(slices, n, batch, weight, |s| {
            let base_i = bases[s];
            let mut local = 0usize;
            scan_records_slice(&bytes[bounds[s]..bounds[s + 1]], bounds[s], &mut |r| {
                let rec = parse_rec(bytes, r, &keys);
                // SAFETY: `base_i + local` lies in this slice's disjoint output
                // range `[bases[s], bases[s] + counts[s])` (prefix-sum), in-bounds
                // (< total ≤ capacity), and is written exactly once.
                unsafe { ptr.write_at(base_i + local, rec) };
                local += 1;
            });
            debug_assert_eq!(
                local, counts[s],
                "slice record count drifted between passes"
            );
        });
    }
    // SAFETY: the parse pass wrote every one of `total` slots exactly once (the
    // per-slice disjoint ranges tile `0..total`), and `JsonRec<K>` is POD (no Drop).
    unsafe { slab.set_len(total) };
    slab
}

/// Balanced sibling of [`scan_records_map_parallel`] — the fused scan+map with
/// the LPT-balanced dispatch and tunable oversplit/batch knobs, for the **full
/// owned-output** path where `map` builds a complete owned record in the worker
/// (so its allocations are freed IN the worker, in parallel — never a serial
/// teardown on the collector thread).
///
/// `split` / `batch` are the same knobs as [`scan_records_slab_with`]. Results
/// are concatenated in input order (cheap when `T` is small, e.g. a per-record
/// digest the worker folds the owned record down to).
pub fn scan_records_map_parallel_balanced<T, F>(
    bytes: &[u8],
    n_workers: usize,
    split: usize,
    batch: usize,
    map: F,
) -> Vec<T>
where
    T: Send,
    F: Fn(RecordSpan, &[u8]) -> T + Sync,
{
    use crate::gatling_forkjoin::gatling_for_each_balanced;

    let n = n_workers.max(1);
    if n == 1 || bytes.is_empty() {
        let mut out = Vec::new();
        scan_records_slice(bytes, 0, &mut |r| {
            out.push(map(r, &bytes[r.offset..r.offset + r.len]));
        });
        return out;
    }

    let bounds = slice_bounds(bytes, n, split);
    let slices = bounds.len() - 1;
    let weight = |s: usize| (bounds[s + 1] - bounds[s]) as u64;
    let partials: Vec<Vec<T>> = gatling_for_each_balanced(slices, n, batch, weight, |s| {
        let mut local: Vec<T> = Vec::new();
        scan_records_slice(&bytes[bounds[s]..bounds[s + 1]], bounds[s], &mut |r| {
            local.push(map(r, &bytes[r.offset..r.offset + r.len]));
        });
        local
    });
    partials.into_iter().flatten().collect()
}

// ── Per-record field probe ───────────────────────────────────────────────────

#[inline]
fn is_ws(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\r' | b'\n')
}

/// Skip JSON whitespace starting at `pos`.
#[inline]
fn skip_ws(bytes: &[u8], mut pos: usize) -> usize {
    while pos < bytes.len() && is_ws(bytes[pos]) {
        pos += 1;
    }
    pos
}

/// Skip a JSON string. `pos` must point at the opening `"`. Returns the
/// position just past the closing quote. Escape-aware: `\X` consumes two
/// bytes, so `\"` and `\\` never terminate the string early.
fn skip_string(bytes: &[u8], pos: usize) -> Option<usize> {
    debug_assert_eq!(bytes.get(pos), Some(&b'"'));
    let mut p = pos + 1;
    while p < bytes.len() {
        match bytes[p] {
            b'\\' => p += 2, // escape: skip the escaped byte too
            b'"' => return Some(p + 1),
            _ => p += 1,
        }
    }
    None
}

/// Skip a `{...}` or `[...]` container. `pos` must point at the opening
/// brace/bracket. Returns the position just past the matching close.
/// String-aware: braces inside string values don't affect the depth.
fn skip_container(bytes: &[u8], pos: usize) -> Option<usize> {
    let mut depth = 0usize;
    let mut p = pos;
    while p < bytes.len() {
        match bytes[p] {
            b'"' => p = skip_string(bytes, p)?,
            b'{' | b'[' => {
                depth += 1;
                p += 1;
            }
            b'}' | b']' => {
                depth = depth.checked_sub(1)?;
                p += 1;
                if depth == 0 {
                    return Some(p);
                }
            }
            _ => p += 1,
        }
    }
    None
}

/// Skip any JSON value starting at `pos`. Returns the position just past it.
fn skip_value(bytes: &[u8], pos: usize) -> Option<usize> {
    match bytes.get(pos)? {
        b'"' => skip_string(bytes, pos),
        b'{' | b'[' => skip_container(bytes, pos),
        _ => {
            // number / true / false / null — token runs to a delimiter.
            let mut p = pos;
            while p < bytes.len() && !matches!(bytes[p], b',' | b'}' | b']') && !is_ws(bytes[p]) {
                p += 1;
            }
            (p > pos).then_some(p)
        }
    }
}

/// Slice out the value starting at `pos` (already whitespace-skipped):
/// - string → the RAW contents between the quotes (escapes NOT decoded)
/// - object/array → the raw `{...}` / `[...]` slice including delimiters
/// - number/true/false/null → the bare token
fn value_slice(bytes: &[u8], pos: usize) -> Option<&[u8]> {
    match bytes.get(pos)? {
        b'"' => {
            let end = skip_string(bytes, pos)?;
            Some(&bytes[pos + 1..end - 1])
        }
        b'{' | b'[' => {
            let end = skip_container(bytes, pos)?;
            Some(&bytes[pos..end])
        }
        _ => {
            let end = skip_value(bytes, pos)?;
            Some(&bytes[pos..end])
        }
    }
}

/// Light zero-copy field probe — the NDJSON analogue of `vtd::find_attr`.
///
/// Locates `"key"` as an object key at the TOP nesting level of `record`
/// (which must be a JSON object) and returns the raw value slice per
/// [`value_slice`]. Walks key/value pairs in order, skipping non-matching
/// values wholesale — nested objects/arrays are stepped over with a
/// string-aware depth scan, so a `"key"` inside a nested container or inside
/// a string value can never match. No full JSON parse, no allocation.
///
/// `key` is matched against the raw (undecoded) key bytes — keys containing
/// JSON escapes must be passed in their escaped form.
pub fn find_key<'a>(record: &'a [u8], key: &str) -> Option<&'a [u8]> {
    let key = key.as_bytes();

    let mut pos = skip_ws(record, 0);
    if record.get(pos) != Some(&b'{') {
        return None; // top-level value is not an object
    }
    pos += 1;

    loop {
        pos = skip_ws(record, pos);
        match record.get(pos)? {
            b'}' => return None, // end of object — key not present
            b',' => {
                pos += 1;
            } // between pairs
            b'"' => {
                // Key string.
                let key_start = pos + 1;
                let past_key = skip_string(record, pos)?;
                let key_end = past_key - 1;

                // Colon.
                pos = skip_ws(record, past_key);
                if record.get(pos) != Some(&b':') {
                    return None; // malformed record — bail out
                }

                // Value.
                pos = skip_ws(record, pos + 1);
                if &record[key_start..key_end] == key {
                    return value_slice(record, pos);
                }
                pos = skip_value(record, pos)?;
            }
            _ => return None, // malformed record — bail out
        }
    }
}

// ── JSON-array scan ────────────────────────────────────────────────────────────

/// Discover the top-level element boundaries of a single JSON **array**
/// (`[e0, e1, …]`) in one sequential, string/escape/depth-aware pass.
///
/// Unlike NDJSON, an array cannot be blind-split at a candidate offset: from a
/// random byte you cannot tell whether you are inside a string or a nested
/// container, so a `,` inside `"a,b"` or inside `{…}` is not a top-level
/// separator. Boundary discovery is therefore inherently single-pass (cheap
/// O(n) byte classification); the multi-core win lives in *parsing* the
/// discovered elements in parallel ([`scan_array_parallel`]) — mirroring the
/// decompressors' single-core read + parallel decode shape.
///
/// Each returned [`RecordSpan`] covers one element's first non-whitespace byte
/// through its last byte, excluding the separating `,` and any surrounding
/// whitespace. Nested objects/arrays, strings containing `,`/`]`/`{`/`}`/`[`,
/// and escaped quotes are all handled (via [`skip_string`]/[`skip_container`]).
/// An empty array (`[]` or `[  ]`) yields zero spans.
///
/// Leniency (documented, not enforced as errors): a trailing comma
/// (`[1,2,]`) and a leading/duplicated comma (`[,1]`, `[1,,2]`) are tolerated —
/// commas are treated purely as separators and never emit a span. Only the
/// FIRST top-level array is scanned; any bytes after its closing `]` are
/// ignored. A lone top-level scalar or object (no leading `[`) is
/// [`JsonError::ExpectedArray`].
///
/// # Errors
/// - [`JsonError::ExpectedArray`] if the first non-whitespace byte is not `[`.
/// - [`JsonError::Malformed`] on an unterminated string/container or input that
///   ends before the closing `]`.
pub fn scan_array_spans(bytes: &[u8]) -> Result<Vec<RecordSpan>, JsonError> {
    let mut pos = skip_ws(bytes, 0);
    if bytes.get(pos) != Some(&b'[') {
        return Err(JsonError::ExpectedArray);
    }
    pos += 1; // past '['

    let mut spans = Vec::new();
    loop {
        pos = skip_ws(bytes, pos);
        match bytes.get(pos) {
            // Ran off the end before the closing ']'.
            None => return Err(JsonError::Malformed(bytes.len())),
            // End of the top-level array.
            Some(b']') => return Ok(spans),
            // Separator (also tolerates leading/duplicated/trailing commas).
            Some(b',') => pos += 1,
            // Element: skip one complete value, string/escape/depth-aware.
            Some(_) => {
                let start = pos;
                let end = skip_value(bytes, pos).ok_or(JsonError::Malformed(start))?;
                spans.push(RecordSpan {
                    offset: start,
                    len: end - start,
                });
                pos = end;
            }
        }
    }
}

/// Parallel parse of a single JSON **array**: discover element boundaries once
/// with [`scan_array_spans`], then map each element on the gatling fork-join
/// pool. The array analogue of [`scan_records_parallel`] — but the boundary
/// discovery is sequential (see [`scan_array_spans`]), so only the `map` is
/// parallel.
///
/// `map(span, elem_bytes)` is handed each element's [`RecordSpan`] plus the
/// zero-copy `&bytes[span.offset..span.offset + span.len]` slice. Results come
/// back **in array order** (index-ordered [`gatling_for_each`](crate::gatling_forkjoin::gatling_for_each))
/// — deterministic regardless of worker scheduling.
///
/// Small inputs (below the same ~4 MiB floor the XML scanner uses, or with a
/// single element) run serially: fan-out overhead would dominate.
///
/// # Errors
/// Propagates any [`JsonError`] from [`scan_array_spans`].
pub fn scan_array_parallel<T, F>(bytes: &[u8], map: F) -> Result<Vec<T>, JsonError>
where
    T: Send,
    F: Fn(RecordSpan, &[u8]) -> T + Sync,
{
    use crate::gatling_forkjoin::gatling_for_each;

    let spans = scan_array_spans(bytes)?;

    // Small-input guard, consistent with the XML scanner's 4 MiB serial floor:
    // below it (or with <2 elements) the fan-out never pays for itself.
    if bytes.len() < 4 * 1024 * 1024 || spans.len() < 2 {
        return Ok(spans
            .iter()
            .map(|&s| map(s, &bytes[s.offset..s.offset + s.len]))
            .collect());
    }

    // Parallel parse: one output slot per element, written in index order.
    let out = gatling_for_each(spans.len(), 0, |i| {
        let s = spans[i];
        map(s, &bytes[s.offset..s.offset + s.len])
    });
    Ok(out)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn seq(bytes: &[u8]) -> Vec<RecordSpan> {
        let mut v = Vec::new();
        scan_records(bytes, |r| v.push(r));
        v
    }

    fn par(bytes: &[u8], n: usize) -> Vec<RecordSpan> {
        let mut v = Vec::new();
        scan_records_parallel(bytes, n, |r| v.push(r));
        v
    }

    #[test]
    fn empty_input() {
        assert!(seq(b"").is_empty());
        assert!(par(b"", 4).is_empty());
    }

    #[test]
    fn single_record_no_trailing_newline() {
        let input = br#"{"a":1}"#;
        let spans = seq(input);
        assert_eq!(spans, vec![RecordSpan { offset: 0, len: 7 }]);
    }

    #[test]
    fn basic_records_and_spans() {
        let input = b"{\"a\":1}\n{\"b\":2}\n";
        let spans = seq(input);
        assert_eq!(
            spans,
            vec![
                RecordSpan { offset: 0, len: 7 },
                RecordSpan { offset: 8, len: 7 },
            ]
        );
        // Spans slice back to the exact record bytes.
        assert_eq!(
            &input[spans[0].offset..spans[0].offset + spans[0].len],
            b"{\"a\":1}"
        );
        assert_eq!(
            &input[spans[1].offset..spans[1].offset + spans[1].len],
            b"{\"b\":2}"
        );
    }

    #[test]
    fn crlf_trimmed() {
        let input = b"{\"a\":1}\r\n{\"b\":2}\r\n";
        let spans = seq(input);
        assert_eq!(spans.len(), 2);
        assert_eq!(spans[0], RecordSpan { offset: 0, len: 7 });
        assert_eq!(spans[1], RecordSpan { offset: 9, len: 7 });
        // No '\r' inside any span.
        for s in &spans {
            assert!(!input[s.offset..s.offset + s.len].contains(&b'\r'));
        }
    }

    #[test]
    fn empty_lines_skipped() {
        let input = b"{\"a\":1}\n\n\r\n{\"b\":2}\n\n";
        let spans = seq(input);
        assert_eq!(spans.len(), 2);
        assert_eq!(spans[0].offset, 0);
        assert_eq!(
            &input[spans[1].offset..spans[1].offset + spans[1].len],
            b"{\"b\":2}"
        );
    }

    #[test]
    fn escaped_quotes_and_backslashes_in_strings() {
        // Raw bytes: {"s":"a\"b\\"}  — escaped quote and escaped backslash.
        let input = b"{\"s\":\"a\\\"b\\\\\"}\n{\"t\":2}\n";
        let spans = seq(input);
        assert_eq!(spans.len(), 2);
        // The escapes must not confuse the line scanner (they can't — splitting
        // is escape-blind by design) nor the field probe.
        let rec0 = &input[spans[0].offset..spans[0].offset + spans[0].len];
        assert_eq!(find_key(rec0, "s"), Some(b"a\\\"b\\\\".as_slice()));
    }

    /// Deterministic synthetic NDJSON with varied record sizes for split tests.
    fn synth_corpus(n_records: usize) -> Vec<u8> {
        let mut buf = Vec::new();
        for i in 0..n_records {
            let pad = "x".repeat(i % 53); // varied lengths → varied split points
            let line = format!("{{\"id\":{i},\"name\":\"u{i}\\\"q\\\\p\",\"pad\":\"{pad}\"}}",);
            buf.extend_from_slice(line.as_bytes());
            // Mix of LF / CRLF / occasional empty line.
            match i % 7 {
                0 => buf.extend_from_slice(b"\r\n"),
                3 => buf.extend_from_slice(b"\n\n"),
                _ => buf.push(b'\n'),
            }
        }
        // Last record without trailing newline.
        buf.extend_from_slice(b"{\"id\":-1}");
        buf
    }

    #[test]
    fn parallel_matches_sequential_exact_spans() {
        let bytes = synth_corpus(2_000);
        let expected = seq(&bytes);
        assert_eq!(expected.len() as u64, 2_001);

        // Many worker counts → many distinct candidate split points, so
        // records straddle candidate offsets in nearly every configuration.
        for n in [2, 3, 4, 5, 8, 13, 16, 32, 100] {
            let got = par(&bytes, n);
            assert_eq!(got.len(), expected.len(), "n={n}: count mismatch");
            for (i, (g, e)) in got.iter().zip(&expected).enumerate() {
                assert_eq!(g, e, "n={n} record {i}: span mismatch");
            }
        }
    }

    #[test]
    fn scan_records_map_parallel_matches_serial_and_preserves_order() {
        // Thousands of varied-length records so nearly every candidate split lands
        // mid-record — the fused-map workers must still reproduce a serial map
        // exactly, in input order.
        let bytes = synth_corpus(5_000);

        // The fused map: pull a few fields into an OWNED tuple (the zero-copy VTD
        // path — `find_key` slices, we copy only the bytes we keep). Non-capturing,
        // so `Fn + Sync + Copy` — reusable across every worker count below.
        let map = |s: RecordSpan, rec: &[u8]| -> (usize, Vec<u8>, Vec<u8>) {
            let id = find_key(rec, "id").map(|v| v.to_vec()).unwrap_or_default();
            let name = find_key(rec, "name")
                .map(|v| v.to_vec())
                .unwrap_or_default();
            (s.offset, id, name)
        };

        // Serial fused-map reference.
        let mut serial: Vec<(usize, Vec<u8>, Vec<u8>)> = Vec::new();
        scan_records(&bytes, |r| {
            serial.push(map(r, &bytes[r.offset..r.offset + r.len]))
        });
        assert_eq!(serial.len(), 5_001, "corpus must hold thousands of records");

        // n==1 serial path agrees.
        assert_eq!(scan_records_map_parallel(&bytes, 1, map), serial, "n=1");

        // Parallel fused map must equal the serial map, order preserved.
        for n in [2, 3, 4, 5, 8, 16, 64] {
            let got = scan_records_map_parallel(&bytes, n, map);
            assert_eq!(got.len(), serial.len(), "n={n}: count mismatch");
            assert_eq!(got, serial, "n={n}: fused-map output/order mismatch");
        }
    }

    #[test]
    fn scan_records_slab_matches_serial_across_workers_and_knobs() {
        let bytes = synth_corpus(5_000);
        let keys = ["id", "name", "pad"];

        // Serial reference: each record's three fields resolved to owned bytes
        // (None when absent — the trailing `{"id":-1}` has no name/pad).
        let mut reference: Vec<[Option<Vec<u8>>; 3]> = Vec::new();
        scan_records(&bytes, |r| {
            let rec = &bytes[r.offset..r.offset + r.len];
            reference.push([
                find_key(rec, "id").map(|v| v.to_vec()),
                find_key(rec, "name").map(|v| v.to_vec()),
                find_key(rec, "pad").map(|v| v.to_vec()),
            ]);
        });
        assert_eq!(reference.len(), 5_001);

        // The slab parser must reproduce the reference EXACTLY — same field
        // values, same record order — across worker counts and dispatch knobs.
        for n in [1usize, 2, 3, 4, 8, 16, 64] {
            for (split, batch) in [(8usize, 8usize), (16, 16), (32, 4), (64, 32)] {
                let slab = scan_records_slab_with(&bytes, keys, n, split, batch);
                assert_eq!(
                    slab.len(),
                    reference.len(),
                    "n={n} split={split} batch={batch}: count"
                );
                for (i, (rec, refr)) in slab.iter().zip(&reference).enumerate() {
                    for k in 0..3 {
                        let got = rec.field(k, &bytes).map(|v| v.to_vec());
                        assert_eq!(got, refr[k], "n={n} split={split} rec {i} field {k}");
                    }
                }
            }
        }

        // The production entry point (baked knobs) agrees too.
        let prod = scan_records_slab(&bytes, keys, 8);
        assert_eq!(prod.len(), reference.len());
        assert_eq!(prod[0].field(0, &bytes), Some(b"0".as_slice()));
        // A present-but-empty field resolves to an empty slice, not absent.
        assert!(
            prod.last().unwrap().field(1, &bytes).is_none(),
            "absent name → None"
        );
    }

    #[test]
    fn scan_records_map_parallel_balanced_matches_serial() {
        let bytes = synth_corpus(4_000);
        // Owned-output map (built + folded in the worker), returning a small digest.
        let map = |_s: RecordSpan, rec: &[u8]| -> u64 {
            let id = find_key(rec, "id").map(|v| v.to_vec()).unwrap_or_default();
            let name = find_key(rec, "name")
                .map(|v| v.to_vec())
                .unwrap_or_default();
            (id.len() as u64) << 32 | name.len() as u64
        };
        let mut serial: Vec<u64> = Vec::new();
        scan_records(&bytes, |r| {
            serial.push(map(r, &bytes[r.offset..r.offset + r.len]))
        });
        for n in [2usize, 4, 8, 16] {
            for (split, batch) in [(8usize, 8usize), (32, 16), (64, 32)] {
                let got = scan_records_map_parallel_balanced(&bytes, n, split, batch, map);
                assert_eq!(got, serial, "n={n} split={split} batch={batch}");
            }
        }
    }

    #[test]
    fn single_record_larger_than_worker_slice() {
        // One huge record (no internal newline) dwarfing chunk_size at n=8:
        // all interior candidates forward-seek past the same newline.
        let big = format!("{{\"blob\":\"{}\"}}", "y".repeat(10_000));
        let input = format!("{big}\n{{\"id\":1}}\n");
        let bytes = input.as_bytes();

        let expected = seq(bytes);
        assert_eq!(expected.len(), 2);
        for n in [2, 8, 64] {
            assert_eq!(par(bytes, n), expected, "n={n}");
        }
    }

    #[test]
    fn skewed_corpus_oversplit_matches_sequential() {
        // Deliberately SKEWED: one monster record whose bytes dominate the whole
        // file, followed by a long tail of tiny records. Under the old
        // one-slice-per-worker split the worker owning the monster ran alone;
        // the oversplit + self-dispatch scan must still produce byte-identical
        // spans to the serial baseline. This is the correctness invariant of the
        // core-saturation rebalance — same records out, just spread over cores.
        let mut buf = Vec::new();
        let monster = format!("{{\"blob\":\"{}\"}}", "q".repeat(200_000));
        buf.extend_from_slice(monster.as_bytes());
        buf.push(b'\n');
        for i in 0..5_000 {
            buf.extend_from_slice(format!("{{\"id\":{i}}}\n").as_bytes());
        }
        let expected = seq(&buf);
        assert_eq!(expected.len(), 5_001);
        for n in [2, 4, 8, 12, 16, 64] {
            let got = par(&buf, n);
            assert_eq!(got.len(), expected.len(), "n={n}: count mismatch");
            assert_eq!(got, expected, "n={n}: span mismatch");
        }
    }

    /// Randomised parity: for many RNG seeds, build an NDJSON corpus of records
    /// with wildly varied lengths, escape sequences, CRLF/LF/blank-line mixes and
    /// a random tail (with or without a trailing newline), then assert the
    /// gatling-parallel scan produces byte-identical spans to the sequential
    /// baseline across every worker count — including counts far above the record
    /// count, where nearly every candidate offset lands mid-record. This is the
    /// property the rayon→gatling_for_each port must preserve.
    fn rng_corpus(seed: u64) -> Vec<u8> {
        // Tiny deterministic xorshift — avoids pinning a rand version/type here.
        let mut s = seed | 1;
        let mut next = move || {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            s
        };
        let n_records = (next() % 400) as usize;
        let mut buf = Vec::new();
        for i in 0..n_records {
            let pad_len = (next() % 97) as usize;
            let pad = "z".repeat(pad_len);
            // Mix escaped quotes/backslashes and braces inside string values so
            // the escape-blind splitter and the field probe both get exercised.
            let line = format!("{{\"id\":{i},\"s\":\"v{i}\\\"{{[}}]\\\\p\",\"pad\":\"{pad}\"}}",);
            buf.extend_from_slice(line.as_bytes());
            match next() % 5 {
                0 => buf.extend_from_slice(b"\r\n"),
                1 => buf.extend_from_slice(b"\n\n"),
                2 => buf.extend_from_slice(b"\n\r\n"), // blank CRLF line between records
                _ => buf.push(b'\n'),
            }
        }
        // Random tail: sometimes a final record without a trailing newline.
        if next() % 2 == 0 {
            buf.extend_from_slice(b"{\"id\":-7,\"last\":true}");
        }
        buf
    }

    #[test]
    fn parallel_matches_sequential_randomized() {
        for seed in 0..64u64 {
            let bytes = rng_corpus(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15));
            let expected = seq(&bytes);
            for n in [1, 2, 3, 4, 5, 7, 8, 16, 33, 64, 500] {
                let got = par(&bytes, n);
                assert_eq!(
                    got.len(),
                    expected.len(),
                    "seed={seed} n={n}: count mismatch"
                );
                for (i, (g, e)) in got.iter().zip(&expected).enumerate() {
                    assert_eq!(g, e, "seed={seed} n={n} record {i}: span mismatch");
                    // Spans must slice back to the exact record bytes.
                    assert_eq!(
                        &bytes[g.offset..g.offset + g.len],
                        &bytes[e.offset..e.offset + e.len],
                        "seed={seed} n={n} record {i}: bytes mismatch"
                    );
                }
            }
        }
    }

    /// Concurrency-boundary stress: many single-byte records so `chunk_size`
    /// collapses to 1 and every worker's candidate offset lands on (or just
    /// after) a record boundary. With `n` far exceeding the record count, most
    /// slices are empty — the merge must still reproduce the sequential span list
    /// exactly, with no dropped or duplicated record at any chunk seam.
    #[test]
    fn parallel_boundary_stress_tiny_records() {
        // 1000 one-char records: "a\nb\n..." (chars cycle, content irrelevant).
        let mut bytes = Vec::new();
        for i in 0..1000u32 {
            bytes.push(b'a' + (i % 26) as u8);
            bytes.push(b'\n');
        }
        let expected = seq(&bytes);
        assert_eq!(expected.len(), 1000);
        for n in [2, 3, 4, 7, 16, 999, 1000, 1001, 4096] {
            assert_eq!(par(&bytes, n), expected, "n={n}");
        }

        // Also exercise exact-multiple boundaries: uniform 8-byte records so
        // `i * chunk_size` frequently lands exactly on a newline.
        let mut uniform = Vec::new();
        for _ in 0..256 {
            uniform.extend_from_slice(b"1234567\n"); // 7 bytes + '\n' = 8
        }
        let exp2 = seq(&uniform);
        assert_eq!(exp2.len(), 256);
        for n in [2, 4, 8, 16, 32, 64, 128, 256] {
            assert_eq!(par(&uniform, n), exp2, "uniform n={n}");
        }
    }

    /// Degenerate inputs feeding the parallel path directly: nothing but
    /// separators, a lone record, and a single trailing byte — the parallel scan
    /// must agree with the sequential scan on all of them for every worker count.
    #[test]
    fn parallel_matches_sequential_degenerate() {
        let cases: &[&[u8]] = &[
            b"",
            b"\n",
            b"\n\n\n\n",
            b"\r\n\r\n",
            b"x",
            b"x\n",
            b"{\"a\":1}",
            b"\n\n{\"a\":1}\n\n",
        ];
        for case in cases {
            let expected = seq(case);
            for n in [1, 2, 4, 8, 64] {
                assert_eq!(par(case, n), expected, "case={case:?} n={n}");
            }
        }
    }

    #[test]
    fn find_safe_split_basics() {
        let bytes = b"abc\ndef\nghi";
        assert_eq!(find_safe_split(bytes, 0), 4); // past first '\n'
        assert_eq!(find_safe_split(bytes, 4), 8); // past second '\n'
        assert_eq!(find_safe_split(bytes, 5), 8); // mid-record → same boundary
        assert_eq!(find_safe_split(bytes, 9), 11); // no newline left → len
        assert_eq!(find_safe_split(bytes, 11), 11); // at end
        assert_eq!(find_safe_split(bytes, 999), 11); // past end → clamped
    }

    // ── find_key ──────────────────────────────────────────────────────────────

    #[test]
    fn find_key_value_types() {
        let rec =
            br#"{"s":"hello","n":-12.5e3,"t":true,"f":false,"z":null,"o":{"a":1},"arr":[1,2,3]}"#;
        assert_eq!(find_key(rec, "s"), Some(b"hello".as_slice()));
        assert_eq!(find_key(rec, "n"), Some(b"-12.5e3".as_slice()));
        assert_eq!(find_key(rec, "t"), Some(b"true".as_slice()));
        assert_eq!(find_key(rec, "f"), Some(b"false".as_slice()));
        assert_eq!(find_key(rec, "z"), Some(b"null".as_slice()));
        assert_eq!(find_key(rec, "o"), Some(br#"{"a":1}"#.as_slice()));
        assert_eq!(find_key(rec, "arr"), Some(b"[1,2,3]".as_slice()));
        assert_eq!(find_key(rec, "missing"), None);
    }

    #[test]
    fn find_key_ignores_nested_keys() {
        // "id" exists only inside the nested object and array — must NOT match.
        let rec = br#"{"outer":{"id":1},"list":[{"id":2}],"name":"x"}"#;
        assert_eq!(find_key(rec, "id"), None);
        assert_eq!(find_key(rec, "name"), Some(b"x".as_slice()));
        // Top-level key after a nested container holding the same name.
        let rec2 = br#"{"outer":{"id":1},"id":42}"#;
        assert_eq!(find_key(rec2, "id"), Some(b"42".as_slice()));
    }

    #[test]
    fn find_key_ignores_lookalikes_in_string_values() {
        // The string VALUE contains the bytes "key": — must not match.
        let rec = br#"{"a":"fake \"key\": 1, more","key":7}"#;
        assert_eq!(find_key(rec, "key"), Some(b"7".as_slice()));
        // And braces inside strings must not break depth tracking.
        let rec2 = br#"{"a":"{[}]","key":"v"}"#;
        assert_eq!(find_key(rec2, "key"), Some(b"v".as_slice()));
    }

    #[test]
    fn find_key_whitespace_and_non_object() {
        let rec = b"  { \"a\" : 1 , \"b\" : \"two\" }  ";
        assert_eq!(find_key(rec, "a"), Some(b"1".as_slice()));
        assert_eq!(find_key(rec, "b"), Some(b"two".as_slice()));
        // Non-object top-level records yield None.
        assert_eq!(find_key(b"[1,2,3]", "a"), None);
        assert_eq!(find_key(b"42", "a"), None);
        assert_eq!(find_key(b"", "a"), None);
    }

    #[test]
    fn find_key_escaped_string_values() {
        let rec = b"{\"path\":\"C:\\\\dir\\\\file\",\"q\":\"say \\\"hi\\\"\"}";
        assert_eq!(find_key(rec, "path"), Some(b"C:\\\\dir\\\\file".as_slice()));
        assert_eq!(find_key(rec, "q"), Some(b"say \\\"hi\\\"".as_slice()));
    }

    // ── scan_array_spans / scan_array_parallel ─────────────────────────────────

    /// Reference: map a span to the exact element bytes it covers.
    fn elem<'a>(bytes: &'a [u8], s: RecordSpan) -> &'a [u8] {
        &bytes[s.offset..s.offset + s.len]
    }

    #[test]
    fn array_5000_small_objects_reparse() {
        let mut buf = String::from("[");
        for i in 0..5000 {
            if i > 0 {
                buf.push(',');
            }
            buf.push_str(&format!("{{\"id\":{i},\"name\":\"u{i}\"}}"));
        }
        buf.push(']');
        let bytes = buf.as_bytes();

        let spans = scan_array_spans(bytes).unwrap();
        assert_eq!(spans.len(), 5000);
        for (i, s) in spans.iter().enumerate() {
            let e = elem(bytes, *s);
            // Reparse with serde_json …
            let v: serde_json::Value = serde_json::from_slice(e).unwrap();
            assert_eq!(v["id"], i);
            assert_eq!(v["name"], format!("u{i}"));
            // … and with the crate's own zero-copy probe.
            assert_eq!(find_key(e, "id"), Some(i.to_string().as_bytes()));
        }
    }

    #[test]
    fn array_strings_with_delimiters_not_split() {
        // Each element is an object whose string value packs every byte that
        // could fool a naive splitter: , ] { } [ , an escaped quote, and a
        // literal backslash-n (the two bytes '\' 'n', NOT a raw newline).
        let bytes = br#"[{"s":"a,b]c{d}e[f\"g\\h\n"},{"s":"plain"},{"s":",,,]]]"}]"#;
        let spans = scan_array_spans(bytes).unwrap();
        assert_eq!(spans.len(), 3);
        assert_eq!(elem(bytes, spans[0]), br#"{"s":"a,b]c{d}e[f\"g\\h\n"}"#);
        assert_eq!(elem(bytes, spans[1]), br#"{"s":"plain"}"#);
        assert_eq!(elem(bytes, spans[2]), br#"{"s":",,,]]]"}"#);
        for s in &spans {
            let v: serde_json::Value = serde_json::from_slice(elem(bytes, *s)).unwrap();
            assert!(v["s"].is_string());
        }
    }

    #[test]
    fn array_deeply_nested_elements() {
        let bytes = br#"[{"a":{"b":{"c":[1,2,{"d":[3,4]}]}}},[[[[]]]],{"x":[{"y":{"z":9}}]}]"#;
        let spans = scan_array_spans(bytes).unwrap();
        assert_eq!(spans.len(), 3);
        assert_eq!(
            elem(bytes, spans[0]),
            br#"{"a":{"b":{"c":[1,2,{"d":[3,4]}]}}}"#
        );
        assert_eq!(elem(bytes, spans[1]), br#"[[[[]]]]"#);
        assert_eq!(elem(bytes, spans[2]), br#"{"x":[{"y":{"z":9}}]}"#);
        for s in &spans {
            // Each element must be valid JSON on its own.
            serde_json::from_slice::<serde_json::Value>(elem(bytes, *s)).unwrap();
        }
    }

    #[test]
    fn array_whitespace_and_newlines_between_elements() {
        let bytes = b"[\n  {\"a\":1} ,\n\t{\"b\":2}\r\n , { \"c\" : 3 }\n]";
        let spans = scan_array_spans(bytes).unwrap();
        assert_eq!(spans.len(), 3);
        // Surrounding whitespace and the separators are excluded from spans.
        assert_eq!(elem(bytes, spans[0]), b"{\"a\":1}");
        assert_eq!(elem(bytes, spans[1]), b"{\"b\":2}");
        assert_eq!(elem(bytes, spans[2]), b"{ \"c\" : 3 }");
    }

    #[test]
    fn array_scalar_elements() {
        // Top-level scalars: numbers, bools, null, strings (with tricky bytes).
        let bytes = br#"[1, -2.5e3 , true,false, null , "x,y]z" ]"#;
        let spans = scan_array_spans(bytes).unwrap();
        assert_eq!(spans.len(), 6);
        assert_eq!(elem(bytes, spans[0]), b"1");
        assert_eq!(elem(bytes, spans[1]), b"-2.5e3");
        assert_eq!(elem(bytes, spans[2]), b"true");
        assert_eq!(elem(bytes, spans[3]), b"false");
        assert_eq!(elem(bytes, spans[4]), b"null");
        assert_eq!(elem(bytes, spans[5]), br#""x,y]z""#);
    }

    #[test]
    fn array_empty_variants_zero_spans() {
        assert_eq!(scan_array_spans(b"[]").unwrap().len(), 0);
        assert_eq!(scan_array_spans(b"[ ]").unwrap().len(), 0);
        assert_eq!(scan_array_spans(b"[\n\t \r\n]").unwrap().len(), 0);
    }

    #[test]
    fn array_leading_ws_before_bracket() {
        let bytes = b"   \n\t [1,2,3]";
        let spans = scan_array_spans(bytes).unwrap();
        assert_eq!(spans.len(), 3);
        assert_eq!(elem(bytes, spans[2]), b"3");
    }

    #[test]
    fn array_trailing_and_leading_commas_tolerated() {
        // Lenient: commas are separators only, never emit a span.
        assert_eq!(scan_array_spans(b"[1,2,]").unwrap().len(), 2);
        assert_eq!(scan_array_spans(b"[,1,,2,]").unwrap().len(), 2);
    }

    #[test]
    fn array_malformed_errors() {
        // Not an array at all.
        assert_eq!(scan_array_spans(b"42"), Err(JsonError::ExpectedArray));
        assert_eq!(
            scan_array_spans(b"{\"a\":1}"),
            Err(JsonError::ExpectedArray)
        );
        assert_eq!(scan_array_spans(b""), Err(JsonError::ExpectedArray));
        // Unterminated array (no closing ']').
        assert!(matches!(
            scan_array_spans(b"[1,2,3"),
            Err(JsonError::Malformed(_))
        ));
        // Unterminated string inside an element.
        assert!(matches!(
            scan_array_spans(br#"["abc]"#),
            Err(JsonError::Malformed(_))
        ));
        // Unterminated nested container.
        assert!(matches!(
            scan_array_spans(br#"[{"a":[1,2}]"#),
            Err(JsonError::Malformed(_))
        ));
    }

    /// Build a JSON array large enough (> 4 MiB) to exercise the parallel path.
    fn big_array(n: usize) -> Vec<u8> {
        let mut buf = String::from("[");
        for i in 0..n {
            if i > 0 {
                buf.push(',');
            }
            let pad = "p".repeat(1000); // ~1 KiB/element ⇒ n≈5000 clears 4 MiB
            buf.push_str(&format!(
                "{{\"id\":{i},\"s\":\"v{i},]{{[}}\\\"x\",\"pad\":\"{pad}\"}}"
            ));
        }
        buf.push(']');
        buf.into_bytes()
    }

    #[test]
    fn array_parallel_matches_serial() {
        let bytes = big_array(5000);
        assert!(
            bytes.len() > 4 * 1024 * 1024,
            "corpus must clear the serial floor"
        );

        // Serial reference over the discovered spans.
        let spans = scan_array_spans(&bytes).unwrap();
        assert_eq!(spans.len(), 5000);
        let reference: Vec<u64> = spans
            .iter()
            .map(|&s| {
                let id = find_key(elem(&bytes, s), "id").unwrap();
                std::str::from_utf8(id).unwrap().parse().unwrap()
            })
            .collect();

        // Parallel map must return the same values, in the same order.
        let got: Vec<u64> = scan_array_parallel(&bytes, |_span, e| {
            let id = find_key(e, "id").unwrap();
            std::str::from_utf8(id).unwrap().parse().unwrap()
        })
        .unwrap();

        assert_eq!(got.len(), 5000);
        assert_eq!(got, reference);
        // Deterministic index order: id == position.
        for (i, v) in got.iter().enumerate() {
            assert_eq!(*v, i as u64);
        }
    }

    #[test]
    fn array_parallel_small_input_serial_path() {
        // Below the 4 MiB floor: still correct, just runs serially.
        let bytes = br#"[{"id":0},{"id":1},{"id":2}]"#;
        let got: Vec<u64> = scan_array_parallel(bytes, |_s, e| {
            std::str::from_utf8(find_key(e, "id").unwrap())
                .unwrap()
                .parse()
                .unwrap()
        })
        .unwrap();
        assert_eq!(got, vec![0, 1, 2]);

        // Error propagation through the parallel entry point.
        assert_eq!(
            scan_array_parallel(b"nope", |_s, _e| 0u8).err(),
            Some(JsonError::ExpectedArray)
        );
    }
}
