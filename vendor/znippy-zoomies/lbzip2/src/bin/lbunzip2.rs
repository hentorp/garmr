//! CLI parallel bzip2 decompressor — pure Rust, all available cores.
//!
//! Usage: lbunzip2 <input.bz2> [output]
//!   If output is omitted, strips .bz2 extension.
//!
//! Streaming decode on the shared **gatling** ordered engine
//! ([`gatling::gatling::ordered::run_ordered_sink`]). A single dispatch thread is
//! the I/O producer: it reads compressed chunks, prepends the carry (the chunk's
//! undecoded tail), `split_chunk`s each chunk into per-block segments, and yields
//! one segment at a time. N self-dispatching map workers CRC-check-decode segments;
//! the ordered sink writes decoded output in strict stream order. There is no
//! hand-rolled worker pool and no `Arc<Mutex<Receiver>>` — the shared engine is the
//! one parallel primitive in the constellation.

use std::{
    fs::File,
    io::{BufWriter, Read, Write},
    sync::{Arc, Mutex},
    time::Instant,
};

use anyhow::Result;
use gatling::gatling::ordered::{OrderedSink, run_ordered_sink};

use lbzip2::chunk::{self, ChunkSplit, DecodeMode};

/// Compressed bytes read per chunk. This is the streaming unit: a chunk's blocks
/// are split into per-worker segments, decoded, and flushed (in order) to the
/// writer before the next chunk is admitted, so the decoded output resident at any
/// instant is bounded by roughly the few segments in flight (gatling's `cap`) — NOT
/// the whole file. 8 MB compressed ≈ ~60 MB decoded/chunk and still ~60 bzip2
/// blocks per chunk, so every worker stays fed while memory stays bounded.
const CHUNK_SIZE_DEFAULT: usize = 4 * 1024 * 1024;
const BUF_CAP: usize = 4 * 1024 * 1024;

/// Detect physical (non-SMT) core count via Linux sysfs topology.
/// Falls back to available_parallelism() on non-Linux or if sysfs is unavailable.
fn physical_cores() -> Option<usize> {
    #[cfg(target_os = "linux")]
    {
        use std::collections::HashSet;
        let mut ids = HashSet::new();
        for entry in std::fs::read_dir("/sys/devices/system/cpu").ok()? {
            let entry = entry.ok()?;
            let name = entry.file_name();
            let name = name.to_str()?;
            if !name.starts_with("cpu") || !name[3..].chars().next()?.is_ascii_digit() {
                continue;
            }
            let base = entry.path().join("topology");
            let pkg = std::fs::read_to_string(base.join("physical_package_id"))
                .ok()
                .and_then(|s| s.trim().parse::<u32>().ok())
                .unwrap_or(0);
            if let Ok(s) = std::fs::read_to_string(base.join("core_id")) {
                if let Ok(core) = s.trim().parse::<u32>() {
                    ids.insert((pkg, core));
                }
            }
        }
        if !ids.is_empty() {
            return Some(ids.len());
        }
    }
    std::thread::available_parallelism().map(|n| n.get()).ok()
}

fn read_chunk(reader: &mut impl Read, buf: &mut [u8]) -> usize {
    let mut got = 0;
    while got < buf.len() {
        match reader.read(&mut buf[got..]) {
            Ok(0) => break,
            Ok(k) => got += k,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => {
                eprintln!("read error: {e}");
                break;
            }
        }
    }
    got
}

/// One decode segment handed to a gatling map worker: a shared reference to the
/// chunk's compressed bytes plus the `[start_bit, end_bit)` block range within them.
/// The `Arc` keeps the chunk buffer alive across every segment that references it —
/// the ownership-based replacement for the old raw-pointer-into-a-recycled-slot.
struct SegIn {
    data: Arc<Vec<u8>>,
    start_bit: u64,
    end_bit: u64,
    max_blocksize: u32,
}

/// The chunk the producer is currently yielding segments from.
struct CurChunk {
    data: Arc<Vec<u8>>,
    split: ChunkSplit,
    next_seg: usize,
    total_bits: u64,
}

/// Recycled decode-slot pool. A worker `take()`s a buffer, decodes its segment INTO
/// it (`decode_segment_checked_into`), and hands it to the ordered writer, which
/// `give()`s it back after writing. After warmup (≈ `cap` + `n_workers` buffers) the
/// steady state performs **zero allocation** — the "decompress into a pre-allocated
/// bigger-than-max slot, writer takes the bytes later" design. Each slot keeps its
/// capacity across reuse; a pathological (RLE1-expanded) block grows its slot once and
/// that capacity is then retained.
struct BufPool {
    free: Mutex<Vec<Vec<u8>>>,
    slot_cap: usize,
}

impl BufPool {
    fn new(slot_cap: usize) -> Self {
        Self {
            free: Mutex::new(Vec::new()),
            slot_cap,
        }
    }
    fn take(&self) -> Vec<u8> {
        self.free
            .lock()
            .unwrap()
            .pop()
            .unwrap_or_else(|| Vec::with_capacity(self.slot_cap))
    }
    fn give(&self, buf: Vec<u8>) {
        // Capacity retained; `decode_segment_checked_into` clears on next use.
        self.free.lock().unwrap().push(buf);
    }
}

/// Ordered sink: write decoded segments to the output file in strict stream order,
/// then recycle each slot back to the pool. Runs on the calling thread (the gatling
/// collector), which owns the writer — so it is the single-core writer that "takes
/// the offset" (its running position) from each in-order slot.
struct WriteSink<'a, W: Write> {
    w: W,
    total: u64,
    pool: &'a BufPool,
}

impl<W: Write> OrderedSink<Vec<u8>> for WriteSink<'_, W> {
    fn emit(&mut self, _seq: u64, data: Vec<u8>) -> Result<()> {
        if !data.is_empty() {
            self.total += data.len() as u64;
            self.w.write_all(&data)?;
        }
        self.pool.give(data);
        Ok(())
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("usage: lbunzip2 <input.bz2> [output]");
        std::process::exit(1);
    }

    let input_path = &args[1];
    let output_path = if args.len() > 2 {
        args[2].clone()
    } else if input_path.ends_with(".bz2") {
        input_path[..input_path.len() - 4].to_string()
    } else {
        format!("{input_path}.out")
    };

    let in_file = File::open(input_path).expect("open input");
    let in_size = in_file.metadata().map(|m| m.len()).unwrap_or(0);
    // Read straight from the File — no BufReader. `read_chunk` fills the chunk buffer
    // in ≤ CHUNK_SIZE reads directly, so a BufReader would only add a second userspace
    // copy (kernel page-cache → its buffer → our `data`). Direct = one copy.
    let mut reader = in_file;

    // Read bz2 header (4 bytes: "BZhN")
    let mut header = [0u8; 4];
    reader.read_exact(&mut header).expect("read bz2 header");

    let bz2_level = header[3];
    if &header[..2] != b"BZ" || header[2] != b'h' || !(b'1'..=b'9').contains(&bz2_level) {
        eprintln!("invalid bzip2 header");
        std::process::exit(1);
    }
    let max_blocksize = 100_000 * (bz2_level - b'0') as u32;

    let n_workers: usize = std::env::var("LBZIP2_THREADS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or_else(|| physical_cores().unwrap_or(4));

    // Chunk **segmentation granularity** — DISTINCT from worker parallelism.
    //
    // The streaming producer holds back the LAST segment of every non-final
    // chunk as `carry` (its trailing bzip2 block may continue into the next
    // chunk), decoding the first `decode_segments = n - 1`. That requires every
    // chunk to split into ≥2 segments: with a single segment `split_chunk`
    // returns `None` for non-last chunks, so the producer's `None` branch
    // discards those bytes and only the FINAL chunk is ever decoded — a silent
    // truncation to the last ~CHUNK_SIZE (and, in the bench, an impossible
    // "single-core faster than all cores" throughput because the full corpus
    // size is billed against that near-instant partial decode).
    //
    // `split_boundaries_parallel(_, 1, _)` returns no interior splits ⇒ n = 1,
    // so `LBZIP2_THREADS=1` used to trip exactly that path. Floor the segment
    // count at 2 so a single worker still streams the WHOLE file (segments are
    // just decoded one at a time, in order); worker parallelism stays exactly
    // `n_workers`.
    // Oversubscription knob: segments/chunk = n_workers * LBZIP2_SEG_MULT (default 1).
    // >1 gives the ordered-sink pool more units than cores so the per-chunk tail
    // self-balances instead of stranding a core. Floor at 2 (carry needs ≥2).
    let seg_mult: usize = std::env::var("LBZIP2_SEG_MULT")
        .ok()
        .and_then(|v| v.parse().ok())
        .filter(|&m| m >= 1)
        .unwrap_or(3);
    let n_segments = (n_workers * seg_mult).max(2);

    // Compressed read unit per chunk. LBZIP2_CHUNK_MB overrides (in MB).
    let chunk_size: usize = std::env::var("LBZIP2_CHUNK_MB")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|&m| m >= 1)
        .map(|m| m * 1024 * 1024)
        .unwrap_or(CHUNK_SIZE_DEFAULT);

    eprintln!(
        "lbunzip2: {} ({} MB) → {}  [{} gatling workers, {} segments/chunk]",
        input_path,
        in_size / (1024 * 1024),
        output_path,
        n_workers,
        n_segments,
    );

    let t0 = Instant::now();

    // ── Producer: read → carry → split → yield one segment at a time ──────────
    // Runs on gatling's dispatch thread, so its I/O overlaps decode. Keeps the
    // reader, the carry (undecoded tail prepended into the next chunk), and the
    // in-progress chunk's split state across pulls.
    let mut carry: Vec<u8> = header.to_vec();
    let mut cur: Option<CurChunk> = None;
    let mut finished = false;

    let producer = move || -> Option<((), SegIn)> {
        loop {
            // Yield the next undelivered segment of the current chunk.
            if let Some(c) = cur.as_mut() {
                if c.next_seg < c.split.decode_segments {
                    let i = c.next_seg;
                    c.next_seg += 1;
                    let n_seg = c.split.segment_starts.len();
                    let start_bit = c.split.segment_starts[i].bit_offset;
                    let end_bit = if i + 1 < n_seg {
                        c.split.segment_starts[i + 1].bit_offset
                    } else {
                        c.total_bits
                    };
                    return Some((
                        (),
                        SegIn {
                            data: Arc::clone(&c.data),
                            start_bit,
                            end_bit,
                            max_blocksize,
                        },
                    ));
                }
            }
            cur = None;
            if finished {
                return None;
            }

            // Read the next chunk into a carry-prefixed buffer.
            let base = carry.len();
            let mut data = std::mem::take(&mut carry);
            data.resize(base + chunk_size, 0);
            let got = read_chunk(&mut reader, &mut data[base..]);
            data.truncate(base + got);
            let is_last = got < chunk_size;

            if got == 0 && base <= 4 {
                finished = true;
                return None;
            }

            match chunk::split_chunk(&data, n_segments, max_blocksize, is_last) {
                None => {
                    if is_last {
                        finished = true;
                        return None;
                    }
                    // No block boundary in this chunk: drop the read bytes and keep
                    // the pre-read carry unchanged (the first `base` bytes are it).
                    data.truncate(base);
                    carry = data;
                    continue;
                }
                Some(split) => {
                    let total_bits = data.len() as u64 * 8;
                    carry = data[split.consumed..].to_vec();
                    if is_last {
                        finished = true;
                    }
                    cur = Some(CurChunk {
                        data: Arc::new(data),
                        split,
                        next_seg: 0,
                        total_bits,
                    });
                    // loop back to yield this chunk's first segment
                }
            }
        }
    };

    // Recycled decode-slot pool. Slot capacity is generous (a segment is ~one bzip2
    // block ≈ chunk/segments decoded); each slot grows once to its true size then is
    // reused, so steady-state decode allocates nothing and never re-zeroes fresh pages.
    let pool = BufPool::new(2 * 1024 * 1024);

    // ── Map: CRC-checked segment decode INTO a recycled slot ──────────────────
    // SECURITY: a per-block CRC mismatch is fatal — we exit non-zero rather than
    // emit silently-truncated output. Matches the old worker behaviour exactly.
    // GATE: memory-level-parallel interleaved decode is a single-core win but
    // neutral-to-harmful once the socket is memory-bandwidth-bound, so use it ONLY
    // when decoding with a single worker (`LBZIP2_THREADS=1` / the `_st` bench).
    // Every multi-worker decode takes the byte-identical serial baseline.
    let decode_mode = if n_workers == 1 {
        DecodeMode::Interleaved
    } else {
        DecodeMode::Serial
    };

    let map = |_label: (), s: SegIn| -> Vec<u8> {
        let mut buf = pool.take();
        match chunk::decode_segment_checked_into(
            &s.data,
            s.start_bit,
            s.end_bit,
            s.max_blocksize,
            &mut buf,
            decode_mode,
        ) {
            Ok(()) => buf,
            Err(e) => {
                // Red-when-broken matrix row: a corrupt-input rejection is a
                // FAIL verdict for the decode cell, not a silent exit. Emitting
                // ok=false before bailing means a broken/tampered stream shows
                // up RED in `nornir test --features testmatrix` instead of the
                // row simply going missing.
                lbzip2::functional_status(
                    "lbunzip2",
                    "decode",
                    false,
                    &format!("corrupt input rejected: {e}"),
                );
                eprintln!("lbunzip2: corrupt input: {e}");
                std::process::exit(1);
            }
        }
    };

    // ── Sink: ordered streaming write on the calling thread ───────────────────
    let out_file = File::create(&output_path).expect("create output");
    let mut sink = WriteSink {
        w: BufWriter::with_capacity(BUF_CAP, out_file),
        total: 0,
        pool: &pool,
    };

    // Ring depth (segments in flight). 0 ⇒ run_ordered_sink default = 2*n_workers.
    let cap: usize = std::env::var("LBZIP2_CAP")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    run_ordered_sink(producer, n_workers, cap, map, &mut sink).expect("decode pipeline");
    sink.w.flush().expect("flush output");
    let total_out = sink.total;

    let elapsed = t0.elapsed().as_secs_f64();
    let out_mb = total_out / (1024 * 1024);
    let in_mb = in_size / (1024 * 1024);

    eprintln!(
        "done: {:.1}s  {} MB → {} MB  ({:.0} MB/s decompressed)",
        elapsed,
        in_mb,
        out_mb,
        out_mb as f64 / elapsed,
    );

    // Introspection marker: the parallel bzip2 decode pipeline drained cleanly.
    lbzip2::functional_status(
        "lbunzip2",
        "decode",
        true,
        &format!("{out_mb} MB decompressed in {elapsed:.1}s"),
    );
}
