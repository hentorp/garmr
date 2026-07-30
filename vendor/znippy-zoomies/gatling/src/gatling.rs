//! Gatling — generic no-barrier worker-pool streaming engine.
//!
//! Extracted from katana-osm's `xml_to_pbf_bz2` (the pipeline behind its planet /
//! Sweden benchmarks). The engine carries **no** codec / format knowledge — the
//! caller plugs in a codec (how to split and transform) and a sink (how to consume
//! the output in order).
//!
//! # Two modes
//!
//! ## Byte mode ([`run`])
//! Use when workers produce raw bytes that need reassembly (e.g. bz2 decode → XML).
//! - [`Codec`] splits input into segments and decodes each → `Vec<u8>`.
//! - [`Sink`] receives assembled, boundary-aligned byte slices.
//! - Collector concatenates decoded segments, finds a safe boundary via
//!   [`Sink::safe_end`], then calls [`Sink::process`].
//!
//! ```text
//! Reader → Main(split) → N Workers(decode→bytes) → Collector(assemble+safe_end) → Sink
//! ```
//!
//! ## Typed mode ([`run_typed`])
//! Use when workers produce fully-processed output that needs no reassembly
//! (e.g. VTD-parse raw XML → parsed records, or any transform where `split` already
//! guarantees logical boundaries between segments).
//! - [`TypedCodec`] splits input and transforms each segment → `Self::Output`.
//! - [`TypedSink`] receives each segment's output individually, in stream order.
//! - Collector is trivial: just delivers outputs in order, no assembly, no carry.
//!
//! ```text
//! Reader → Main(split) → N Workers(transform→T) → Collector(forward in order) → TypedSink
//! ```
//!
//! # Properties (both modes)
//! - **Zero-copy input:** bytes stay in the slot; workers get a raw pointer.
//! - **No barrier:** slot N+1 is split and dispatched while slot N is still processing.
//! - **Carry in headroom:** unconsumed tail from `split` is prepended to next chunk.

use std::io::Read;
use std::sync::{Arc, Mutex, mpsc};

use anyhow::Result;

/// Async-I/O sibling of this engine — a no-barrier, bounded, ordered async task
/// pool for **I/O-bound** work (S3 PUT/GET fan-out, etc.), as opposed to the
/// **CPU-bound** thread pool [`run`]/[`run_typed`] of this module. See
/// [`io`](mod@io) for the substrate-difference rationale.
#[path = "gatling_io.rs"]
pub mod io;

/// Item-oriented sibling of this engine — an **ordered streaming-sink** gatling
/// for a labelled-discrete-entry pipeline (e.g. znippy-compress). The caller stays
/// the producer (yields `(Label, Input)` items, pulled lazily under backpressure);
/// N workers run a `map`; outputs stream to a [`ordered::OrderedSink`] in producer
/// order through a **bounded** reorder buffer. See [`ordered`](mod@ordered).
#[path = "gatling_ordered.rs"]
pub mod ordered;

/// Zero-allocation **slot pool** variant — the buffer substrate the streaming
/// [`run`]/[`run_typed`] engine fans over: one reader fills pre-allocated
/// fixed-size slots, N workers borrow each as `&[u8]` (zero-copy) via
/// [`revolver::get_chunk_slice`]. Folded in from the former top-level
/// `chunk_revolver` module (still re-exported crate-root as `chunk_revolver` for
/// API compatibility). See [`revolver`](mod@revolver).
#[path = "revolver/mod.rs"]
pub mod revolver;

/// Result of splitting a compressed buffer into independent decode units.
pub struct Split<S> {
    /// One descriptor per decode unit, in stream order.
    pub segments: Vec<S>,
    /// Number of bytes consumed from the input slice; the remainder becomes carry.
    pub consumed: usize,
}

/// Decompressor plug-in. `Seg` is an opaque, `Copy` per-unit descriptor (e.g. a
/// bz2 bit range) computed by `split` and handed back to `decode`.
pub trait Codec: Sync {
    /// Per-decode-unit descriptor. Must be cheap to copy and `Send`.
    type Seg: Send + Copy + 'static;

    /// Find independent decode units in `data`. Return `None` when no complete
    /// unit is available yet (the caller grows the carry and retries next chunk).
    /// `is_last` is true for the final chunk of the stream.
    fn split(&self, data: &[u8], n_workers: usize, is_last: bool) -> Option<Split<Self::Seg>>;

    /// Decode one unit of `data` into its uncompressed bytes.
    fn decode(&self, data: &[u8], seg: &Self::Seg) -> Vec<u8>;
}

/// Consumer plug-in. Methods run on the engine's single collector thread, so a
/// `Sink` may safely own mutable state and fan work out to its own writer thread.
pub trait Sink: Send {
    /// Largest prefix length of `assembled` (decoded bytes) that ends on a safe
    /// boundary (e.g. the end of an XML element). Return `0` if none yet; return
    /// `assembled.len()` when `is_last` to flush everything.
    fn safe_end(&self, assembled: &[u8], is_last: bool) -> usize;

    /// Process one contiguous decoded run, already cut at a safe boundary.
    fn process(&mut self, bytes: &[u8]) -> Result<()>;
}

// ── Typed mode traits ───────────────────────────────────────────────────────

/// Transform plug-in for typed mode. Workers call [`TypedCodec::transform`] to
/// produce an arbitrary output type per segment. `split` must ensure each segment
/// is logically self-contained (e.g. cut at XML element boundaries) — the collector
/// will NOT reassemble segments; each output is forwarded individually.
pub trait TypedCodec: Sync {
    /// Per-segment descriptor (e.g. a `(usize, usize)` byte range within the chunk).
    type Seg: Send + Copy + 'static;

    /// Fully-processed output produced by one worker for one segment.
    type Output: Send + 'static;

    /// Find segment boundaries in `data`. Each segment must be logically complete
    /// (no partial elements spanning segments). `consumed` = bytes up to the last
    /// safe boundary; remainder becomes carry for next chunk.
    fn split(&self, data: &[u8], n_workers: usize, is_last: bool) -> Option<Split<Self::Seg>>;

    /// Transform one segment of `data` into typed output. Called on N worker
    /// threads in parallel. `data` is the full slot slice (carry + read);
    /// use `seg` to index into it.
    fn transform(&self, data: &[u8], seg: &Self::Seg) -> Self::Output;

    /// Called once on each worker thread after it has processed all of its
    /// segments, just before the thread exits. Lets a codec flush per-worker
    /// accumulated state (e.g. a partial row group carried across segments via
    /// thread-local storage) into the stream. The returned output, if any, is
    /// forwarded to the sink after all in-order segment outputs. Default: none.
    fn finish_worker(&self) -> Option<Self::Output> {
        None
    }
}

/// Consumer plug-in for typed mode. Receives each segment's output individually,
/// in strict stream order. The collector thread calls this — fan out to a writer
/// thread or batch internally as needed.
pub trait TypedSink<T>: Send {
    /// Process one segment's output. `is_last` is true for the final segment
    /// of the entire stream (not just the chunk).
    fn process(&mut self, output: T, is_last: bool) -> Result<()>;

    /// Called once after all segments have been processed. Default is no-op.
    fn finish(&mut self) -> Result<()> {
        Ok(())
    }
}

/// How a slot's backing memory is grown/faulted when the reader fills it.
///
/// Both modes lazily allocate slots (a small input still only ever touches one
/// slot); they differ only in how much of an *allocated* slot gets faulted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SlotFill {
    /// Grow the slot in blocks to exactly the bytes read, never faulting the
    /// unused tail. A 24 MB read into a 232 MB slot touches ~24 MB, not 232 MB.
    /// Best for small / single-chunk / partial-tail inputs. This is the default.
    #[default]
    Incremental,
    /// Size each slot to the full `carry_headroom + chunk_size` once, on first
    /// use, then reuse it across reads with no re-zeroing and no reallocation.
    /// The up-front fault is paid once and amortizes to ~zero over the many
    /// full chunks of a large (planet-scale) input. Best when nearly every
    /// chunk is full so the slot tail is never wasted.
    Big,
}

/// Engine tuning. `slot size = carry_headroom + chunk_size`.
pub struct Config {
    /// Compressed bytes read per slot.
    pub chunk_size: usize,
    /// Bytes reserved at the head of each slot for prepended carry.
    pub carry_headroom: usize,
    /// Slot-pool depth (slots in flight).
    pub ring_slots: usize,
    /// Bytes to prepend to the first chunk (e.g. a stream header already read).
    pub initial_carry: Vec<u8>,
    /// Slot memory-growth strategy. See [`SlotFill`].
    pub slot_fill: SlotFill,
}

// ── Internal message types ──────────────────────────────────────────────────

struct WorkItem<S> {
    chunk_id: u64,
    seg_id: usize,
    data_ptr: *const u8,
    data_len: usize,
    seg: S,
}
// SAFETY: `data_ptr` points into a slot held alive in `InFlight` by the collector
// until every segment of that chunk has been decoded and the slot recycled. The
// reader never overwrites a slot while it is in flight (it is removed from the
// free pool). `S: Send` covers the descriptor payload.
unsafe impl<S: Send> Send for WorkItem<S> {}

struct SegResult {
    chunk_id: u64,
    seg_id: usize,
    output: Vec<u8>,
}

struct InFlight {
    chunk_id: u64,
    slot: Vec<u8>,
    n_segments: usize,
    results: Vec<Option<Vec<u8>>>,
    done: usize,
    is_last: bool,
}

enum Msg {
    New(InFlight),
    Result(SegResult),
}

// ── Engine ──────────────────────────────────────────────────────────────────

/// Fill `slot` with up to `chunk_size` bytes read from `src`, placed at offset
/// `carry_headroom` (leaving the front free for a prepended carry). Returns the
/// number of bytes read.
///
/// The [`SlotFill`] mode controls how much slot memory gets faulted:
/// - [`SlotFill::Incremental`] grows the slot in blocks to exactly the bytes
///   read, never touching the unused tail — the win on small / partial inputs.
/// - [`SlotFill::Big`] sizes the slot to its full extent once and reuses it with
///   no re-zeroing or reallocation — the up-front fault amortizes over the many
///   full chunks of a planet-scale input.
///
/// For a full chunk (`got == chunk_size`) both modes touch the same region, so
/// large reads never regress regardless of mode.
///
/// Returns `(bytes_read, is_last)`. End-of-stream is detected precisely: a short
/// read means EOF was hit mid-chunk, and after a *full* chunk we peek one byte
/// past it — an empty peek means the stream ends exactly here (this is the last
/// chunk), while a peeked byte is stashed in `pending` as the next chunk's first
/// data byte. This flags `is_last` correctly even when the input length is an
/// exact multiple of `chunk_size` (where `got == chunk_size` on every read and no
/// trailing short read ever occurs). The one-byte peek costs nothing meaningful
/// and needs no extra slot, so it never deadlocks the pool.
fn fill_slot<R: Read>(
    src: &mut R,
    slot: &mut Vec<u8>,
    carry_headroom: usize,
    chunk_size: usize,
    fill: SlotFill,
    pending: &mut Option<u8>,
) -> (usize, bool) {
    // A byte peeked past the previous full chunk belongs at the front of this
    // chunk's data region.
    let prefill = pending.take();
    let got = match fill {
        SlotFill::Big => {
            let slot_size = carry_headroom + chunk_size;
            // Pay the fault once: a fresh slot is sized here; a recycled slot is
            // already full-length, so this is a no-op (no realloc, no re-zero).
            if slot.len() != slot_size {
                slot.resize(slot_size, 0);
            }
            let mut got = 0usize;
            if let Some(b) = prefill {
                slot[carry_headroom] = b;
                got = 1;
            }
            while got < chunk_size {
                match src.read(&mut slot[carry_headroom + got..slot_size]) {
                    Ok(0) => break,
                    Ok(k) => got += k,
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(_) => break,
                }
            }
            // Leave the slot full-length so the next reuse skips the resize.
            got
        }
        SlotFill::Incremental => {
            const READ_BLOCK: usize = 8 * 1024 * 1024;
            slot.clear();
            // Carry prefix: bytes [data_start..carry_headroom] are overwritten by
            // the prepended carry before use; [0..data_start] is never read.
            slot.resize(carry_headroom, 0);
            let mut got = 0usize;
            if let Some(b) = prefill {
                slot.push(b);
                got = 1;
            }
            while got < chunk_size {
                let want = READ_BLOCK.min(chunk_size - got);
                let base = slot.len();
                slot.resize(base + want, 0);
                match src.read(&mut slot[base..base + want]) {
                    Ok(0) => {
                        slot.truncate(base);
                        break;
                    }
                    Ok(k) => {
                        slot.truncate(base + k);
                        got += k;
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {
                        slot.truncate(base);
                        continue;
                    }
                    Err(_) => {
                        slot.truncate(base);
                        break;
                    }
                }
            }
            got
        }
    };

    // Determine end-of-stream. A short read already means EOF; after a full
    // chunk, probe one byte forward without losing it.
    let is_last = if got < chunk_size {
        true
    } else {
        let mut probe = [0u8; 1];
        loop {
            match src.read(&mut probe) {
                Ok(0) => break true,
                Ok(_) => {
                    *pending = Some(probe[0]);
                    break false;
                }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => break true,
            }
        }
    };

    (got, is_last)
}

/// Run the engine to completion over `reader`, driving `sink`.
///
/// `sink` is borrowed mutably for the duration; counts / outputs the consumer
/// accumulates are read from it after `run` returns (e.g. via a `finish` method
/// of your own). `codec` is shared across the decode workers.
pub fn run<C: Codec, S: Sink>(
    reader: impl Read + Send,
    codec: C,
    sink: &mut S,
    n_workers: usize,
    cfg: Config,
) -> Result<()> {
    let n_workers = n_workers.max(1);
    let slot_size = cfg.carry_headroom + cfg.chunk_size;
    assert!(
        cfg.initial_carry.len() <= cfg.carry_headroom,
        "initial_carry {} exceeds carry_headroom {}",
        cfg.initial_carry.len(),
        cfg.carry_headroom
    );

    let codec_ref = &codec;
    let sink_ref: &mut S = sink;

    std::thread::scope(|s| -> Result<()> {
        // ── Slot pool (lazy) ──────────────────────────────────────────────────
        // Slots are allocated on demand, capped at `ring_slots`. A small input only
        // ever touches one slot, so it never pays the full `ring_slots × slot_size`
        // up front (a 5 MB file used to zero 6 × 232 MB = 1.4 GB before reading a byte).
        let (slot_return_tx, slot_return_rx) = mpsc::sync_channel::<Vec<u8>>(cfg.ring_slots);

        // ── Reader thread ─────────────────────────────────────────────────────
        let (filled_tx, filled_rx) = mpsc::sync_channel::<(Vec<u8>, usize, bool)>(cfg.ring_slots);
        let chunk_size = cfg.chunk_size;
        let carry_headroom = cfg.carry_headroom;
        let ring_slots = cfg.ring_slots;
        let slot_fill = cfg.slot_fill;
        s.spawn(move || {
            use std::sync::mpsc::TryRecvError;
            let mut src = reader;
            let mut allocated = 0usize;
            let mut pending: Option<u8> = None;
            loop {
                // Reuse a recycled slot if one is waiting; else allocate a fresh
                // slot while under budget; else block for a slot to come back.
                let mut slot = match slot_return_rx.try_recv() {
                    Ok(sl) => sl,
                    Err(TryRecvError::Empty) if allocated < ring_slots => {
                        allocated += 1;
                        Vec::with_capacity(slot_size)
                    }
                    Err(TryRecvError::Empty) => match slot_return_rx.recv() {
                        Ok(sl) => sl,
                        Err(_) => break,
                    },
                    Err(TryRecvError::Disconnected) => break,
                };
                let (got, is_last) = fill_slot(
                    &mut src,
                    &mut slot,
                    carry_headroom,
                    chunk_size,
                    slot_fill,
                    &mut pending,
                );
                if filled_tx.send((slot, got, is_last)).is_err() {
                    break;
                }
                if is_last {
                    break;
                }
            }
        });

        // ── Decode workers (persistent, no barrier) ───────────────────────────
        let (work_tx, work_rx) = mpsc::sync_channel::<WorkItem<C::Seg>>(n_workers * 2);
        let (collector_tx, collector_rx) = mpsc::sync_channel::<Msg>(n_workers * 4);
        let work_rx = Arc::new(Mutex::new(work_rx));

        for _ in 0..n_workers {
            let work_rx = Arc::clone(&work_rx);
            let collector_tx = collector_tx.clone();
            s.spawn(move || {
                loop {
                    let item = {
                        let rx = work_rx.lock().expect("work_rx lock");
                        match rx.recv() {
                            Ok(item) => item,
                            Err(_) => break,
                        }
                    };
                    // SAFETY: the slot backing `data_ptr` is held in `InFlight`
                    // by the collector and not recycled until all its segments
                    // are decoded, so the pointer is valid for this read.
                    let data = unsafe { std::slice::from_raw_parts(item.data_ptr, item.data_len) };
                    let output = codec_ref.decode(data, &item.seg);
                    let _ = collector_tx.send(Msg::Result(SegResult {
                        chunk_id: item.chunk_id,
                        seg_id: item.seg_id,
                        output,
                    }));
                }
            });
        }
        drop(work_rx);

        // Main keeps an inflight sender; workers keep their clones.
        let inflight_tx = collector_tx.clone();
        drop(collector_tx);

        // ── Collector thread ──────────────────────────────────────────────────
        let slot_return_for_collector = slot_return_tx.clone();
        let collector = s.spawn(move || -> Result<()> {
            let mut in_flight: Vec<InFlight> = Vec::new();
            let mut next_id: u64 = 0;
            let mut carry: Vec<u8> = Vec::new();

            while let Ok(msg) = collector_rx.recv() {
                match msg {
                    Msg::New(slot) => in_flight.push(slot),
                    Msg::Result(r) => {
                        for slot in in_flight.iter_mut() {
                            if slot.chunk_id == r.chunk_id {
                                slot.results[r.seg_id] = Some(r.output);
                                slot.done += 1;
                                break;
                            }
                        }
                    }
                }

                // Flush completed slots strictly in stream order.
                loop {
                    let Some(idx) = in_flight.iter().position(|s| s.chunk_id == next_id) else {
                        break;
                    };
                    if in_flight[idx].done < in_flight[idx].n_segments {
                        break;
                    }

                    let mut done = in_flight.remove(idx);
                    let is_last = done.is_last;

                    let mut buf = std::mem::take(&mut carry);
                    for seg in done.results.drain(..) {
                        if let Some(bytes) = seg {
                            buf.extend_from_slice(&bytes);
                        }
                    }

                    let safe = sink_ref.safe_end(&buf, is_last);
                    if safe == 0 {
                        carry = buf;
                    } else {
                        carry = buf[safe..].to_vec();
                        buf.truncate(safe);
                        sink_ref.process(&buf)?;
                    }

                    slot_return_for_collector.send(done.slot).ok();
                    next_id += 1;
                }
            }

            if !carry.is_empty() {
                sink_ref.process(&carry)?;
            }
            Ok(())
        });

        // ── Main: carry + split + dispatch ────────────────────────────────────
        // A zero-read chunk whose carry has not grown past the seed length means
        // the stream is finished (the carry holds only the prepended header).
        let carry_floor = cfg.initial_carry.len();
        let mut carry: Vec<u8> = cfg.initial_carry;
        let mut chunk_id: u64 = 0;
        // Truncation/corruption guard — see the twin in `run_typed`. Bails when the
        // codec can never split a growing carry (e.g. a truncated / zero-padded
        // input) instead of accumulating to OOM.
        let max_carry = cfg.chunk_size.saturating_mul(16).max(1 << 30);

        for (mut slot, read_len, is_last) in filled_rx.iter() {
            if carry.len() > max_carry {
                return Err(anyhow::anyhow!(
                    "gatling: no split boundary found across {} MiB of accumulated carry — \
                     the input stream is truncated or corrupt (e.g. an incomplete / zero-padded download)",
                    carry.len() >> 20
                ));
            }
            if read_len == 0 && carry.len() <= carry_floor {
                slot_return_tx.send(slot).ok();
                break;
            }

            // Prepend the carry so the worker sees a single contiguous
            // `carry ++ read` slice. The common case fits in the slot's reserved
            // front headroom (zero-copy). When a single unit spans enough chunks
            // that the carry outgrows the headroom, fall back to a dedicated
            // buffer sized to the actual carry — the headroom is a fast-path
            // optimization, not a hard cap on unit size.
            let carry_len = carry.len();
            let (buf, data_start, data_end) = if carry_len <= carry_headroom {
                let data_start = carry_headroom - carry_len;
                slot[data_start..carry_headroom].copy_from_slice(&carry);
                (slot, data_start, carry_headroom + read_len)
            } else {
                let mut combined = Vec::with_capacity(carry_len + read_len);
                combined.extend_from_slice(&carry);
                combined.extend_from_slice(&slot[carry_headroom..carry_headroom + read_len]);
                // The read bytes are copied out; recycle the slot immediately.
                slot_return_tx.send(slot).ok();
                let end = combined.len();
                (combined, 0, end)
            };

            let data = &buf[data_start..data_end];
            let split = match codec_ref.split(data, n_workers, is_last) {
                Some(sp) => sp,
                None => {
                    carry.clear();
                    carry.extend_from_slice(data);
                    slot_return_tx.send(buf).ok();
                    if is_last {
                        break;
                    }
                    continue;
                }
            };

            carry.clear();
            carry.extend_from_slice(&data[split.consumed..]);

            let n_segments = split.segments.len();
            let inflight = InFlight {
                chunk_id,
                slot: buf,
                n_segments,
                results: (0..n_segments).map(|_| None).collect(),
                done: 0,
                is_last,
            };

            // Pointer into the slot before it is moved into the collector.
            let data_ptr = inflight.slot[data_start..].as_ptr();
            let data_len = data_end - data_start;

            inflight_tx
                .send(Msg::New(inflight))
                .map_err(|_| anyhow::anyhow!("collector closed"))?;

            for (seg_id, seg) in split.segments.into_iter().enumerate() {
                work_tx
                    .send(WorkItem {
                        chunk_id,
                        seg_id,
                        data_ptr,
                        data_len,
                        seg,
                    })
                    .map_err(|_| anyhow::anyhow!("work channel closed"))?;
            }

            chunk_id += 1;
            if is_last {
                break;
            }
        }

        drop(work_tx);
        drop(inflight_tx);
        drop(slot_return_tx);

        collector.join().expect("collector panicked")?;
        Ok(())
    })
}

// ── Typed mode internals ────────────────────────────────────────────────────

struct TypedWorkItem<S> {
    chunk_id: u64,
    seg_id: usize,
    data_ptr: *const u8,
    data_len: usize,
    seg: S,
}
unsafe impl<S: Send> Send for TypedWorkItem<S> {}

struct TypedSegResult<T> {
    chunk_id: u64,
    seg_id: usize,
    output: T,
}

struct TypedInFlight<T> {
    chunk_id: u64,
    slot: Vec<u8>,
    n_segments: usize,
    results: Vec<Option<T>>,
    done: usize,
    is_last: bool,
}

enum TypedMsg<T> {
    New(TypedInFlight<T>),
    Result(TypedSegResult<T>),
    /// End-of-worker remainder, forwarded to the sink after all ordered outputs.
    Tail(T),
}

// ── Typed engine ────────────────────────────────────────────────────────────

/// Run the typed engine to completion. Workers call [`TypedCodec::transform`] to
/// produce arbitrary output per segment; the collector forwards each output to
/// `sink` in strict stream order (no byte assembly, no boundary logic).
///
/// Use this when `split` already guarantees logically-complete segments (e.g. cut
/// at XML element boundaries) and workers produce fully-processed typed output
/// (parsed records, encoded row groups, etc.).
pub fn run_typed<C: TypedCodec, S: TypedSink<C::Output>>(
    reader: impl Read + Send,
    codec: C,
    sink: &mut S,
    n_workers: usize,
    cfg: Config,
) -> Result<()> {
    let n_workers = n_workers.max(1);
    let slot_size = cfg.carry_headroom + cfg.chunk_size;
    assert!(
        cfg.initial_carry.len() <= cfg.carry_headroom,
        "initial_carry {} exceeds carry_headroom {}",
        cfg.initial_carry.len(),
        cfg.carry_headroom
    );

    let codec_ref = &codec;
    let sink_ref: &mut S = sink;

    std::thread::scope(|s| -> Result<()> {
        // ── Slot pool (lazy) ──────────────────────────────────────────────────
        let (slot_return_tx, slot_return_rx) = mpsc::sync_channel::<Vec<u8>>(cfg.ring_slots);

        // ── Reader thread ─────────────────────────────────────────────────────
        let (filled_tx, filled_rx) = mpsc::sync_channel::<(Vec<u8>, usize, bool)>(cfg.ring_slots);
        let chunk_size = cfg.chunk_size;
        let carry_headroom = cfg.carry_headroom;
        let ring_slots = cfg.ring_slots;
        let slot_fill = cfg.slot_fill;
        s.spawn(move || {
            use std::sync::mpsc::TryRecvError;
            let mut src = reader;
            let mut allocated = 0usize;
            let mut pending: Option<u8> = None;
            loop {
                let mut slot = match slot_return_rx.try_recv() {
                    Ok(sl) => sl,
                    Err(TryRecvError::Empty) if allocated < ring_slots => {
                        allocated += 1;
                        Vec::with_capacity(slot_size)
                    }
                    Err(TryRecvError::Empty) => match slot_return_rx.recv() {
                        Ok(sl) => sl,
                        Err(_) => break,
                    },
                    Err(TryRecvError::Disconnected) => break,
                };
                let (got, is_last) = fill_slot(
                    &mut src,
                    &mut slot,
                    carry_headroom,
                    chunk_size,
                    slot_fill,
                    &mut pending,
                );
                if filled_tx.send((slot, got, is_last)).is_err() {
                    break;
                }
                if is_last {
                    break;
                }
            }
        });

        // ── Transform workers (persistent, no barrier) ────────────────────────
        let (work_tx, work_rx) = mpsc::sync_channel::<TypedWorkItem<C::Seg>>(n_workers * 2);
        let (collector_tx, collector_rx) = mpsc::sync_channel::<TypedMsg<C::Output>>(n_workers * 4);
        let work_rx = Arc::new(Mutex::new(work_rx));

        for _ in 0..n_workers {
            let work_rx = Arc::clone(&work_rx);
            let collector_tx = collector_tx.clone();
            s.spawn(move || {
                loop {
                    let item = {
                        let rx = work_rx.lock().expect("work_rx lock");
                        match rx.recv() {
                            Ok(item) => item,
                            Err(_) => break,
                        }
                    };
                    // SAFETY: slot is held alive by collector until all segments done.
                    let data = unsafe { std::slice::from_raw_parts(item.data_ptr, item.data_len) };
                    let output = codec_ref.transform(data, &item.seg);
                    let _ = collector_tx.send(TypedMsg::Result(TypedSegResult {
                        chunk_id: item.chunk_id,
                        seg_id: item.seg_id,
                        output,
                    }));
                }
                // This worker has drained all its segments; flush any per-worker
                // remainder (e.g. a partial row group accumulated across segments).
                if let Some(tail) = codec_ref.finish_worker() {
                    let _ = collector_tx.send(TypedMsg::Tail(tail));
                }
            });
        }
        drop(work_rx);

        let inflight_tx = collector_tx.clone();
        drop(collector_tx);

        // ── Collector thread (trivial: forward in order, no assembly) ─────────
        let slot_return_for_collector = slot_return_tx.clone();
        let collector = s.spawn(move || -> Result<()> {
            let mut in_flight: Vec<TypedInFlight<C::Output>> = Vec::new();
            let mut next_id: u64 = 0;
            let mut tails: Vec<C::Output> = Vec::new();

            while let Ok(msg) = collector_rx.recv() {
                match msg {
                    TypedMsg::New(slot) => in_flight.push(slot),
                    TypedMsg::Result(r) => {
                        for slot in in_flight.iter_mut() {
                            if slot.chunk_id == r.chunk_id {
                                slot.results[r.seg_id] = Some(r.output);
                                slot.done += 1;
                                break;
                            }
                        }
                    }
                    TypedMsg::Tail(out) => tails.push(out),
                }

                // Flush completed slots strictly in stream order.
                loop {
                    let Some(idx) = in_flight.iter().position(|s| s.chunk_id == next_id) else {
                        break;
                    };
                    if in_flight[idx].done < in_flight[idx].n_segments {
                        break;
                    }

                    let mut done = in_flight.remove(idx);
                    let is_last = done.is_last;
                    let n = done.results.len();

                    // Forward each segment's output in order.
                    for (i, output) in done.results.drain(..).enumerate() {
                        if let Some(val) = output {
                            let last_segment = is_last && i == n - 1;
                            sink_ref.process(val, last_segment)?;
                        }
                    }

                    slot_return_for_collector.send(done.slot).ok();
                    next_id += 1;
                }
            }

            // All ordered segment outputs are flushed; emit per-worker remainders.
            for tail in tails {
                sink_ref.process(tail, false)?;
            }
            sink_ref.finish()?;
            Ok(())
        });

        // ── Main: carry + split + dispatch ────────────────────────────────────
        let carry_floor = cfg.initial_carry.len();
        let mut carry: Vec<u8> = cfg.initial_carry;
        let mut chunk_id: u64 = 0;
        // Truncation/corruption guard. A well-formed stream never accumulates an
        // un-splittable carry larger than a few chunks (a single OSM element / bz2
        // block is < the headroom). If `split` keeps returning None while carry
        // grows without bound — the exact symptom of a truncated or zero-padded
        // input (e.g. an incomplete torrent download, whose un-fetched tail is a
        // sparse hole of zeros with no block magic) — bail loudly here instead of
        // growing the carry buffer to many GiB and hanging forever.
        let max_carry = chunk_size.saturating_mul(16).max(1 << 30);

        for (mut slot, read_len, is_last) in filled_rx.iter() {
            if carry.len() > max_carry {
                return Err(anyhow::anyhow!(
                    "gatling: no split boundary found across {} MiB of accumulated carry — \
                     the input stream is truncated or corrupt (e.g. an incomplete / zero-padded download)",
                    carry.len() >> 20
                ));
            }
            if read_len == 0 && carry.len() <= carry_floor {
                slot_return_tx.send(slot).ok();
                break;
            }

            // Prepend the carry so the worker sees a single contiguous
            // `carry ++ read` slice. The common case fits in the slot's reserved
            // front headroom (zero-copy). When a single element/record spans
            // enough chunks that the carry outgrows the headroom (planet-scale
            // OSM: a run with no internal split boundary larger than the 32 MiB
            // headroom), fall back to a dedicated buffer sized to the actual
            // carry. The headroom is a fast-path optimization, not a hard cap on
            // element size.
            let carry_len = carry.len();
            let (buf, data_start, data_end) = if carry_len <= carry_headroom {
                let data_start = carry_headroom - carry_len;
                slot[data_start..carry_headroom].copy_from_slice(&carry);
                (slot, data_start, carry_headroom + read_len)
            } else {
                let mut combined = Vec::with_capacity(carry_len + read_len);
                combined.extend_from_slice(&carry);
                combined.extend_from_slice(&slot[carry_headroom..carry_headroom + read_len]);
                // The read bytes are copied out; recycle the slot immediately.
                slot_return_tx.send(slot).ok();
                let end = combined.len();
                (combined, 0, end)
            };

            let data = &buf[data_start..data_end];
            let split = match codec_ref.split(data, n_workers, is_last) {
                Some(sp) => sp,
                None => {
                    carry.clear();
                    carry.extend_from_slice(data);
                    slot_return_tx.send(buf).ok();
                    if is_last {
                        break;
                    }
                    continue;
                }
            };

            carry.clear();
            carry.extend_from_slice(&data[split.consumed..]);

            let n_segments = split.segments.len();
            let inflight = TypedInFlight {
                chunk_id,
                slot: buf,
                n_segments,
                results: (0..n_segments).map(|_| None).collect(),
                done: 0,
                is_last,
            };

            let data_ptr = inflight.slot[data_start..].as_ptr();
            let data_len = data_end - data_start;

            inflight_tx
                .send(TypedMsg::New(inflight))
                .map_err(|_| anyhow::anyhow!("collector closed"))?;

            for (seg_id, seg) in split.segments.into_iter().enumerate() {
                work_tx
                    .send(TypedWorkItem {
                        chunk_id,
                        seg_id,
                        data_ptr,
                        data_len,
                        seg,
                    })
                    .map_err(|_| anyhow::anyhow!("work channel closed"))?;
            }

            chunk_id += 1;
            if is_last {
                break;
            }
        }

        drop(work_tx);
        drop(inflight_tx);
        drop(slot_return_tx);

        collector.join().expect("collector panicked")?;
        Ok(())
    })
}
