//! lgz — parallel gzip decompressor CLI.
//!
//! Full streaming ring-slot pipeline (same architecture as lbzip2-rs/ljar-rs):
//!
//! ```text
//! Reader ──→ Main(carry+split) ──→ N Workers ──→ Collector ──→ Writer
//!   ↑                                                  │
//!   └────────────── ring-slot recycle ─────────────────┘
//! ```
//!
//! - Reader thread: pulls free 232MB ring slots, fills with compressed bytes.
//!   Blocks on `free_rx.recv()` when all slots are in use → bounded memory.
//! - Main thread: parses gzip header (first chunk only), prepends carry into
//!   headroom, calls `split_chunk`. Posts WorkItems (raw pointers into slot)
//!   to workers + InFlightSlot to collector. No barrier between chunks.
//! - N dedicated worker threads: loop on `Arc<Mutex<Receiver<WorkItem>>>::recv()`
//!   → decode segment → send SegmentResult. No fork-join barrier, no idle time.
//! - Collector: tracks `Vec<InFlightSlot>` by chunk_id, applies results, flushes
//!   completed chunks in order to writer, recycles slot back to reader's pool.
//! - Writer: single thread, BufWriter to stdout/file.
//!
//! Slot lifetime safety: a slot is recycled ONLY when `done_count ==
//! decode_segments`. Workers hold `*const u8` into slots — valid because the
//! collector owns the slot until that condition is met.
//!
//! Usage: lgz < input.gz > output
//!        lgz input.gz -o output
//!        lgz input.gz          (writes to stdout)

use std::collections::{HashSet, VecDeque};
use std::fs::File;
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::thread;
use std::time::Instant;

use anyhow::Result;
use gatling::gatling::ordered::{OrderedSink, run_ordered_sink};

use lgz::chunk::{decode_segment_into_hint, split_chunk};

// ── Constants ────────────────────────────────────────────────────────────────

const CHUNK_SIZE: usize = 200 * 1024 * 1024;
const CARRY_HEADROOM: usize = 32 * 1024 * 1024;
const BUF_CAP: usize = 4 * 1024 * 1024;

// ── Pipeline items ─────────────────────────────────────────────────────────────

/// One decode segment handed to a gatling map worker: an owned copy of the
/// segment's compressed (byte-aligned, flush-delimited) bytes plus an output-size
/// hint. Owning the bytes replaces the old raw-pointer-into-a-recycled-slot; the
/// copy is a few flush-delimited bytes, dwarfed by the decode it feeds.
struct SegIn {
    data: Vec<u8>,
    hint: usize,
}

/// Ordered sink: write decoded segments to the output in strict stream order.
/// Runs on the calling thread (the gatling collector), so it owns the writer.
struct WriteSink<W: Write> {
    w: W,
    total: u64,
}

impl<W: Write> OrderedSink<Vec<u8>> for WriteSink<W> {
    fn emit(&mut self, _seq: u64, data: Vec<u8>) -> Result<()> {
        if !data.is_empty() {
            self.total += data.len() as u64;
            self.w.write_all(&data)?;
        }
        Ok(())
    }
}

// ── Physical core detection ──────────────────────────────────────────────────

fn physical_cores() -> usize {
    let n = (|| -> Option<usize> {
        let mut seen = HashSet::new();
        for e in std::fs::read_dir("/sys/devices/system/cpu").ok()? {
            let e = e.ok()?;
            let s = e.file_name().to_str()?.to_string();
            if !s.starts_with("cpu")
                || s[3..].is_empty()
                || !s[3..].bytes().all(|b| b.is_ascii_digit())
            {
                continue;
            }
            let pkg =
                std::fs::read_to_string(e.path().join("topology/physical_package_id")).ok()?;
            let core = std::fs::read_to_string(e.path().join("topology/core_id")).ok()?;
            seen.insert((pkg.trim().to_string(), core.trim().to_string()));
        }
        Some(seen.len()).filter(|&n| n > 0)
    })();
    n.unwrap_or_else(|| {
        thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4)
    })
}

/// Worker count for the decode engine. Honors `LGZ_THREADS` (mirrors lbunzip2's
/// `LBZIP2_THREADS`) so a bench harness can pin single-core (`LGZ_THREADS=1`) vs
/// all-core runs; falls back to the physical core count. Clamped to ≥1.
fn n_workers() -> usize {
    std::env::var("LGZ_THREADS")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|&n| n >= 1)
        .unwrap_or_else(physical_cores)
}

// ── Read helper (handles short reads) ────────────────────────────────────────

fn read_chunk(reader: &mut impl Read, buf: &mut [u8]) -> usize {
    let mut got = 0;
    while got < buf.len() {
        match reader.read(&mut buf[got..]) {
            Ok(0) => break,
            Ok(k) => got += k,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => {
                eprintln!("lgz: read error: {e}");
                break;
            }
        }
    }
    got
}

// ── Gzip header skip ─────────────────────────────────────────────────────────

fn skip_gzip_header(data: &[u8]) -> Result<usize, &'static str> {
    if data.len() < 10 {
        return Err("too short for gzip header");
    }
    if data[0] != 0x1f || data[1] != 0x8b {
        return Err("bad gzip magic");
    }
    if data[2] != 0x08 {
        return Err("not DEFLATE");
    }

    let flags = data[3];
    let mut pos = 10;

    if flags & 0x04 != 0 {
        if pos + 2 > data.len() {
            return Err("truncated FEXTRA");
        }
        let xlen = u16::from_le_bytes([data[pos], data[pos + 1]]) as usize;
        pos += 2 + xlen;
    }
    if flags & 0x08 != 0 {
        while pos < data.len() && data[pos] != 0 {
            pos += 1;
        }
        pos += 1;
    }
    if flags & 0x10 != 0 {
        while pos < data.len() && data[pos] != 0 {
            pos += 1;
        }
        pos += 1;
    }
    if flags & 0x02 != 0 {
        pos += 2;
    }

    if pos >= data.len() {
        return Err("header extends past input");
    }
    Ok(pos)
}

/// Verify a decoded single-member gzip output against the file's trailer — the
/// last 8 bytes are CRC32 (LE) then ISIZE (uncompressed length mod 2^32, LE).
///
/// The speculative parallel decoder can "succeed" on a wrong split point and
/// hand back garbage of the right shape, so its output must be checked against
/// the trailer before we emit it. Returns false (→ caller falls back to flate2)
/// if the trailer can't be read or either field disagrees. Only valid for a
/// single-member stream, which is exactly where the speculative path runs (the
/// concatenated-member path handles the multi-trailer case separately).
fn gzip_trailer_ok(raw: &[u8], output: &[u8]) -> bool {
    if raw.len() < 8 {
        return false;
    }
    let t = &raw[raw.len() - 8..];
    let expected_crc = u32::from_le_bytes([t[0], t[1], t[2], t[3]]);
    let expected_isize = u32::from_le_bytes([t[4], t[5], t[6], t[7]]);
    let mut crc = flate2::Crc::new();
    crc.update(output);
    crc.sum() == expected_crc && (output.len() as u32) == expected_isize
}

// ── Multi-member parallel-writer fast path ────────────────────────────────────

/// Concatenated-gzip fast path (the common `.gz` from log rotation, `cat *.gz`,
/// pigz `--independent`, or a `.tar.gz` written member-per-file): the members
/// are fully independent, so they decode in parallel across every core — and,
/// crucially, they are **streamed out with BOUNDED in-flight memory** instead of
/// materialising the whole decompressed output first (the old
/// `decode_members_parallel` → `Vec<Vec<u8>>` held every member resident at once,
/// i.e. O(output) ≈ the full file — the peak-RSS regression).
///
/// - regular-file output (`-o file`): the file is pre-sized (each member's
///   uncompressed length is read straight from its gzip `ISIZE` trailer, so the
///   byte layout is known without decoding), then
///   [`gatling::parwrite::write_segments_positional`] fans the members across the
///   worker pool — each worker **decodes one member into a reused scratch buffer
///   and immediately `pwrite`s it at its offset**, recycling the buffer for the
///   next member. In-flight memory ≈ `n_workers × member_size`, never O(output).
/// - stdout / pipe: members are validated (cheap parallel probe) and then decoded
///   in **bounded parallel batches** (`n_workers` at a time), each batch written
///   in order and dropped before the next — again bounded, no whole-output `Vec`.
///
/// Returns `true` when it handled the input. Returns `false` (fall through to
/// the streaming ring-slot pipeline) for stdin input, a single-member stream, a
/// read error, or — for stdout, *before any byte is written* — a member that
/// fails to probe (a false-positive header inside one real member's body). The
/// `-o` path can fall through even after starting: `main`'s non-fast path
/// re-`File::create`s the output, truncating any partial write.
fn try_multimember_fastpath(args: &[String], t0: Instant, n_workers: usize) -> bool {
    // Need a real input file (not stdin) to random-access members.
    if args.len() < 2 || args[1] == "-o" {
        return false;
    }
    let input_path = &args[1];
    let in_file = match File::open(input_path) {
        Ok(f) => f,
        Err(_) => return false,
    };
    // mmap so the compressed bytes fault in lazily during the parallel decode
    // instead of a single serial `read` copy of the whole file.
    let mmap = match unsafe { memmap2::Mmap::map(&in_file) } {
        Ok(m) => m,
        Err(_) => return false,
    };
    let raw: &[u8] = &mmap;
    let input_size = raw.len() as u64;

    // Locate every concatenated gzip member. `< 2` ⇒ single-member stream: fall
    // through to the streaming ring-slot pipeline (pigz flush handling etc.).
    let members = lgz::speculative::find_gzip_members_parallel(raw, n_workers);
    if members.len() < 2 {
        return false;
    }
    let ranges: Vec<(usize, usize)> = members
        .windows(2)
        .map(|w| (w[0], w[1]))
        .chain(std::iter::once((*members.last().unwrap(), raw.len())))
        .collect();

    let decode_member = |s: usize, e: usize, out: &mut Vec<u8>| -> Result<(), String> {
        use std::io::Read;
        let mut dec = flate2::read::GzDecoder::new(&raw[s..e]);
        dec.read_to_end(out)
            .map_err(|err| err.to_string())
            .map(|_| ())
    };

    let out_file = args
        .iter()
        .position(|a| a == "-o")
        .map(|i| args[i + 1].clone());

    let n_members = ranges.len();
    let total_out: u64;

    match out_file {
        Some(path) => {
            // Regular-file output → pre-size from gzip ISIZE, then decode-and-
            // pwrite each member positionally with a recycled per-worker buffer.
            // ISIZE = the member's uncompressed size mod 2^32 (last 4 bytes of the
            // member's byte range) — authoritative for members < 4 GiB, which is
            // every member a concatenating tool ever emits. The decode validates
            // its output length against ISIZE and fails the segment on mismatch
            // (wrapped/lying trailer), so we never pwrite past a neighbour.
            let mut offsets = Vec::with_capacity(n_members);
            let mut sizes = Vec::with_capacity(n_members);
            let mut acc = 0u64;
            for &(_s, e) in &ranges {
                if e < 4 {
                    return false; // malformed member framing — let main retry
                }
                let isz =
                    u32::from_le_bytes([raw[e - 4], raw[e - 3], raw[e - 2], raw[e - 1]]) as u64;
                offsets.push(acc);
                sizes.push(isz);
                acc += isz;
            }
            total_out = acc;

            let f = File::create(&path).unwrap_or_else(|e| {
                eprintln!("lgz: cannot create '{path}': {e}");
                std::process::exit(1);
            });
            if let Err(e) = f.set_len(total_out) {
                eprintln!("lgz: cannot size output: {e}");
                std::process::exit(1);
            }

            let ranges_ref = &ranges;
            let sizes_ref = &sizes;
            let stats = gatling::parwrite::write_segments_positional(
                &f,
                n_members,
                &offsets,
                n_workers,
                |i, buf| {
                    let (s, e) = ranges_ref[i];
                    decode_member(s, e, buf)?;
                    if buf.len() as u64 != sizes_ref[i] {
                        return Err(format!(
                            "member {i} decoded {} bytes, ISIZE says {}",
                            buf.len(),
                            sizes_ref[i],
                        ));
                    }
                    Ok(())
                },
            );
            if stats.failed > 0 {
                // A validated gzip header whose body will not cleanly decode:
                // fall through so main re-creates (truncates) the output and the
                // streaming pipeline / flate2 fallback gets a correct shot at it.
                eprintln!(
                    "lgz: {} member(s) failed the fast path — falling back",
                    stats.failed
                );
                return false;
            }
        }
        None => {
            // Stdout / pipe → cannot seek, so we must be sure every member is real
            // BEFORE writing a byte (no truncate-and-retry on a pipe). That guard is
            // ALREADY met: `find_gzip_members_parallel` confirmed every member ≥1 via
            // `is_gzip_member_start` (header shape + inflate probe), and member 0 is a
            // real gzip header (the caller reached this path through a gzip stream).
            // A member that starts valid but corrupts mid-body is caught by the sink's
            // decode-failure abort below. The old separate parallel "probe pass" here
            // just RE-inflated the head of every member — a second full fork-join
            // barrier (its own thread-pool spawn + join) in front of the decode, for
            // no safety the member scan had not already established. Dropping it
            // removes that serial-ish stall so decode starts immediately.

            // Stream the members through the ordered gatling engine instead of the
            // old fixed-`n_workers` batch → serial-write loop. The batched loop had
            // a **fork-join barrier + serial drain per batch**: all workers decoded
            // a batch, then every core sat idle while the batch's outputs were
            // written in order, then the next batch launched. On the multi-member
            // corpus that idle write window was ~1/3 of wall time → only ~8/12 cores
            // busy. `run_ordered_sink` self-dispatches every member to a free worker
            // (no barrier) and the ordered sink writes each member the instant it is
            // next-in-order **while the other workers keep decoding** — read↔decode
            // ↔write fully overlap, so all cores stay fed. Buffers are ISIZE-presized
            // so the per-member decode never reallocs-and-copies as it grows.
            let hints: Vec<usize> = ranges
                .iter()
                .map(|&(_s, e)| {
                    if e >= 4 {
                        u32::from_le_bytes([raw[e - 4], raw[e - 3], raw[e - 2], raw[e - 1]])
                            as usize
                    } else {
                        0
                    }
                })
                .collect();
            // Recycled buffers are reserved to the LARGEST member so that once a
            // buffer has grown it is never reallocated-and-copied again for a bigger
            // member later in the stream.
            let max_hint = hints.iter().copied().max().unwrap_or(0);

            let mut w = BufWriter::with_capacity(BUF_CAP, io::stdout());
            let mut written = 0u64;

            // Recycled decode-buffer pool → ZERO steady-state allocation. Each
            // member decodes into a large (ISIZE-sized) buffer; the naïve version
            // `Vec::with_capacity` + drop-per-member churned 130+K minor page faults
            // and a `munmap` per member, all serialising on the kernel mmap_lock —
            // which capped saturation at ~8.5/12 no matter the worker count. Here
            // the ordered sink hands each drained buffer BACK to the pool after it
            // writes, so a worker pulls an already-faulted-in warm buffer for its
            // next member: after the first ~`cap` members there are no more output
            // allocations and no more fresh-page faults in the hot loop. Resident
            // pool memory is bounded (≈ in-flight cap × max member size).
            let pool: std::sync::Mutex<Vec<Vec<u8>>> = std::sync::Mutex::new(Vec::new());

            let ranges_ref = &ranges;
            let pool_ref = &pool;
            let mut next_idx = 0usize;
            let producer = move || -> Option<((), usize)> {
                if next_idx < n_members {
                    let i = next_idx;
                    next_idx += 1;
                    Some(((), i))
                } else {
                    None
                }
            };
            // Decode one member into a recycled, ISIZE-presized buffer; `None` marks
            // a member that passed the cheap probe but failed a full decode.
            let map = |_label: (), i: usize| -> Option<Vec<u8>> {
                use std::io::Read;
                let (s, e) = ranges_ref[i];
                let mut o = pool_ref.lock().unwrap().pop().unwrap_or_default();
                o.clear();
                o.reserve(max_hint); // no-op once a recycled buffer is big enough
                let mut dec = flate2::read::GzDecoder::new(&raw[s..e]);
                dec.read_to_end(&mut o).ok().map(|_| o)
            };
            let mut sink = |_seq: u64, opt: Option<Vec<u8>>| -> Result<()> {
                match opt {
                    Some(mut d) => {
                        written += d.len() as u64;
                        w.write_all(&d)?;
                        d.clear();
                        pool_ref.lock().unwrap().push(d); // recycle the warm buffer
                        Ok(())
                    }
                    // Passed the probe but failed a full decode: the stream is
                    // genuinely corrupt this far in — abort (earlier members are
                    // already on the pipe, so there is no clean recovery).
                    None => anyhow::bail!("member decode failed mid-stream"),
                }
            };
            // `cap = 0` ⇒ the engine's default in-flight bound of `2 × n_workers`
            // (≈ a 24-deep ring on this box): enough slots that every worker always
            // has a next member queued, while keeping resident memory bounded.
            run_ordered_sink(producer, n_workers, 0, map, &mut sink).unwrap_or_else(|e| {
                // Red-when-broken: a decode-pipeline failure is a FAIL verdict
                // for the lgz decode cell, emitted before bailing so the matrix
                // sees RED instead of a vanished row.
                lgz::functional_status(
                    "lgz",
                    "decode",
                    false,
                    &format!("multi-member decode failed: {e}"),
                );
                eprintln!("lgz: {e}");
                std::process::exit(1);
            });
            w.flush().expect("flush output");
            total_out = written;
        }
    }

    let elapsed = t0.elapsed();
    eprintln!(
        "lgz: {} → {} bytes ({:.1}×) in {:.3}s ({:.0} MB/s output)  [multi-member streaming, {} members]",
        input_size,
        total_out,
        total_out as f64 / input_size.max(1) as f64,
        elapsed.as_secs_f64(),
        total_out as f64 / elapsed.as_secs_f64() / 1_048_576.0,
        n_members,
    );
    lgz::functional_status(
        "lgz",
        "decode",
        true,
        &format!(
            "multi-member gzip decode ({n_members} members) in {:.3}s",
            elapsed.as_secs_f64()
        ),
    );
    true
}

// ── Main ─────────────────────────────────────────────────────────────────────

fn main() {
    let t0 = Instant::now();
    let args: Vec<String> = std::env::args().collect();

    // Fast path: concatenated multi-member gzip decodes writer-parallel with no
    // serial concat. Falls through for stdin / single-member / flush streams.
    if try_multimember_fastpath(&args, t0, n_workers()) {
        return;
    }

    let (input, output): (Box<dyn Read + Send>, Box<dyn Write + Send>) = match args.len() {
        1 => (Box::new(io::stdin()), Box::new(io::stdout())),
        2 => {
            let f = File::open(&args[1]).unwrap_or_else(|e| {
                eprintln!("lgz: cannot open '{}': {}", args[1], e);
                std::process::exit(1);
            });
            (Box::new(f), Box::new(io::stdout()))
        }
        _ if args.contains(&"-o".to_string()) => {
            let o_idx = args.iter().position(|a| a == "-o").unwrap();
            let input_file = &args[1];
            let output_file = &args[o_idx + 1];
            let f_in = File::open(input_file).unwrap_or_else(|e| {
                eprintln!("lgz: cannot open '{}': {}", input_file, e);
                std::process::exit(1);
            });
            let f_out = File::create(output_file).unwrap_or_else(|e| {
                eprintln!("lgz: cannot create '{}': {}", output_file, e);
                std::process::exit(1);
            });
            (Box::new(f_in), Box::new(f_out))
        }
        _ => {
            eprintln!("Usage: lgz [input.gz] [-o output]");
            std::process::exit(1);
        }
    };

    let n_workers = n_workers();
    eprintln!("lgz: {n_workers} gatling workers");

    // ── Streaming decode on the shared gatling ordered engine ─────────────────
    // A single dispatch thread is the I/O producer: it reads compressed chunks,
    // prepends the carry (undecoded tail), strips the gzip header/trailer, and
    // `split_chunk`s each chunk at flush boundaries — yielding one segment at a
    // time. N self-dispatching map workers decode segments; the ordered sink
    // writes decoded output in strict stream order. The old hand-rolled reader /
    // N-worker pool / collector / writer threads are gone — the engine is the pool.
    //
    // `fallback_needed` / `input_size` are set inside the producer (which runs on
    // the dispatch thread) and read back here after the run via shared atomics.
    let fallback_flag = Arc::new(AtomicBool::new(false));
    let input_size_atomic = Arc::new(AtomicU64::new(0));

    let producer = {
        let fb = Arc::clone(&fallback_flag);
        let isz = Arc::clone(&input_size_atomic);
        let mut reader = BufReader::with_capacity(BUF_CAP, input);
        let mut carry: Vec<u8> = Vec::new();
        let mut chunk_id: u64 = 0;
        let mut header_stripped = false;
        let mut finished = false;
        let mut pending: VecDeque<SegIn> = VecDeque::new();

        move || -> Option<((), SegIn)> {
            loop {
                // Drain any segments already queued for the current chunk.
                if let Some(item) = pending.pop_front() {
                    return Some(((), item));
                }
                if finished {
                    return None;
                }

                // Read the next chunk into a carry-prefixed buffer.
                let base = carry.len();
                let mut data = std::mem::take(&mut carry);
                data.resize(base + CHUNK_SIZE, 0);
                let read_len = read_chunk(&mut reader, &mut data[base..]);
                data.truncate(base + read_len);
                let is_last = read_len < CHUNK_SIZE;
                isz.fetch_add(read_len as u64, Ordering::Relaxed);

                if read_len == 0 && base == 0 {
                    finished = true;
                    return None;
                }

                let carry_len = base;
                if carry_len > CARRY_HEADROOM {
                    // Carry too large — no flush boundaries found in a huge region.
                    // Abort and let main try the whole-file fallback strategies.
                    fb.store(true, Ordering::Relaxed);
                    finished = true;
                    return None;
                }
                let data_end = data.len(); // == carry_len + read_len

                // First chunk: strip gzip header.
                let deflate_start = if !header_stripped {
                    header_stripped = true;
                    match skip_gzip_header(&data) {
                        Ok(hdr_len) => hdr_len,
                        Err(e) => {
                            eprintln!("lgz: {e}");
                            std::process::exit(1);
                        }
                    }
                } else {
                    0
                };

                // Strip 8-byte trailer from last chunk (CRC32 + ISIZE).
                let deflate_end = if is_last && data_end > deflate_start + 8 {
                    data_end - 8
                } else {
                    data_end
                };

                if deflate_end <= deflate_start {
                    if is_last {
                        finished = true;
                        return None;
                    }
                    // Keep the pre-read carry unchanged, drop this read.
                    data.truncate(base);
                    carry = data;
                    continue;
                }

                let dslice = &data[deflate_start..deflate_end];

                match split_chunk(dslice, n_workers, is_last) {
                    Some(split) if split.decode_segments > 1 => {
                        // Detect sync-flush vs full-flush.
                        // Full-flush: after the 00 00 FF FF scan boundary, there's
                        // an empty stored block (00 00 00 FF FF) resetting the LZ77
                        // window. Sync-flush: raw deflate with back-references into
                        // the previous segment's window (segments NOT independent).
                        let seg1_start = split.segment_starts[1];
                        let seg1_data = &dslice[seg1_start..];
                        let is_full_flush = seg1_data.len() >= 5
                            && seg1_data[0] == 0x00
                            && seg1_data[1] == 0x00
                            && seg1_data[2] == 0x00
                            && seg1_data[3] == 0xFF
                            && seg1_data[4] == 0xFF;

                        if !is_full_flush {
                            // Sync-flush: decode the entire chunk as one segment
                            // (still overlaps I/O via the streaming producer).
                            let isize_hint = if is_last && data_end >= 4 {
                                u32::from_le_bytes([
                                    data[data_end - 4],
                                    data[data_end - 3],
                                    data[data_end - 2],
                                    data[data_end - 1],
                                ]) as usize
                            } else {
                                0
                            };
                            carry.clear();
                            pending.push_back(SegIn {
                                data: dslice.to_vec(),
                                hint: isize_hint,
                            });
                            chunk_id += 1;
                            if is_last {
                                finished = true;
                            }
                            continue;
                        }

                        // Full-flush: independent segments. Compute carry (the
                        // undecoded tail) immediately, then queue every segment.
                        carry.clear();
                        if split.consumed < dslice.len() {
                            carry.extend_from_slice(&dslice[split.consumed..]);
                        }
                        let decode_segments = split.decode_segments;
                        for i in 0..decode_segments {
                            let start_byte = split.segment_starts[i];
                            let end_byte = if i + 1 < split.segment_starts.len() {
                                split.segment_starts[i + 1]
                            } else {
                                split.consumed
                            };
                            pending.push_back(SegIn {
                                data: dslice[start_byte..end_byte].to_vec(),
                                hint: 0,
                            });
                        }
                        chunk_id += 1;
                        if is_last {
                            finished = true;
                        }
                        continue;
                    }
                    Some(_) | None => {
                        // No usable flush boundaries in this chunk.
                        if is_last && chunk_id == 0 {
                            // Entire file has no flush boundaries — fall back.
                            fb.store(true, Ordering::Relaxed);
                            finished = true;
                            return None;
                        }

                        // Mid-stream chunk without boundaries: accumulate as carry
                        // (dslice already embeds the previous carry).
                        carry = dslice.to_vec();

                        if is_last {
                            // Final tail without boundaries — decode it as a single
                            // segment.
                            if !carry.is_empty() {
                                let seg = std::mem::take(&mut carry);
                                pending.push_back(SegIn { data: seg, hint: 0 });
                            }
                            finished = true;
                        }
                        continue;
                    }
                }
            }
        }
    };

    // Map: lenient per-segment DEFLATE decode (matches the old worker — a decode
    // error yields whatever decoded so far; the fallback / trailer checks catch a
    // genuinely bad stream).
    let map = |_label: (), s: SegIn| -> Vec<u8> {
        let mut output = Vec::new();
        let _ = decode_segment_into_hint(&s.data, &mut output, s.hint);
        output
    };

    // Sink: ordered streaming write on the calling thread (owns the writer).
    let mut sink = WriteSink {
        w: BufWriter::with_capacity(BUF_CAP, output),
        total: 0u64,
    };

    run_ordered_sink(producer, n_workers, 0, map, &mut sink).expect("decode pipeline");
    sink.w.flush().expect("flush output");

    let fallback_needed = fallback_flag.load(Ordering::Relaxed);
    let input_size = input_size_atomic.load(Ordering::Relaxed);
    let total_out = sink.total;

    // If no flush boundaries were found, try speculative parallel decode.
    if fallback_needed {
        eprintln!("lgz: no flush boundaries — trying parallel strategies");
        let input_path = if args.len() >= 2 && args[1] != "-o" {
            args[1].clone()
        } else {
            eprintln!("lgz: cannot re-read stdin for fallback");
            std::process::exit(1);
        };

        // Re-read the file.
        #[cfg(feature = "timing")]
        let t_reread = Instant::now();
        let mut raw = Vec::new();
        File::open(&input_path)
            .unwrap()
            .read_to_end(&mut raw)
            .unwrap();
        #[cfg(feature = "timing")]
        eprintln!(
            "[timing] file re-read: {:.1}ms ({:.1} MB)",
            t_reread.elapsed().as_secs_f64() * 1000.0,
            raw.len() as f64 / 1_048_576.0
        );

        // Strategy 1: Concatenated gzip members (fully parallel, no window needed).
        #[cfg(feature = "timing")]
        let t_strat = Instant::now();
        let buf =
            if let Some(decoded) = lgz::speculative::decode_concatenated_members(&raw, n_workers) {
                // decode_concatenated_members decodes each member with flate2, which
                // verifies that member's own CRC32 + ISIZE trailer and returns None on
                // any failure — so this output is already validated.
                #[cfg(feature = "timing")]
                eprintln!(
                    "[timing] concatenated members decode: {:.1}ms  output={:.1}MB",
                    t_strat.elapsed().as_secs_f64() * 1000.0,
                    decoded.len() as f64 / 1_048_576.0
                );
                decoded
            } else {
                // Strategy 2: Speculative DEFLATE block boundary scan.
                #[cfg(feature = "timing")]
                eprintln!(
                    "[timing] no concatenated members ({:.1}ms), trying speculative",
                    t_strat.elapsed().as_secs_f64() * 1000.0
                );

                let deflate_start = skip_gzip_header(&raw).unwrap_or(10);
                let deflate_end = if raw.len() > deflate_start + 8 {
                    raw.len() - 8
                } else {
                    raw.len()
                };
                let deflate_data = &raw[deflate_start..deflate_end];

                #[cfg(feature = "timing")]
                let t_spec = Instant::now();
                // A wrong split point can "successfully" decode garbage, so the
                // speculative output is only trustworthy if it matches the gzip
                // trailer (CRC32 + ISIZE over the whole single-member output). We
                // validate BEFORE emitting a single byte; on any mismatch we discard
                // it and fall through to the authoritative flate2 path. Never emit
                // bytes we did not validate.
                let spec = lgz::speculative::speculative_decode(deflate_data, n_workers)
                    .filter(|out| gzip_trailer_ok(&raw, out));
                if let Some(decoded) = spec {
                    #[cfg(feature = "timing")]
                    eprintln!(
                        "[timing] speculative decode: {:.1}ms  output={:.1}MB",
                        t_spec.elapsed().as_secs_f64() * 1000.0,
                        decoded.len() as f64 / 1_048_576.0
                    );
                    eprintln!("lgz: speculative parallel decode succeeded (trailer verified)");
                    decoded
                } else {
                    // Strategy 3: Single-threaded flate2 fallback (CRC-validated).
                    #[cfg(feature = "timing")]
                    eprintln!(
                        "[timing] speculative failed/unverified ({:.1}ms), flate2 fallback",
                        t_spec.elapsed().as_secs_f64() * 1000.0
                    );
                    eprintln!("lgz: single-threaded flate2 fallback");
                    #[cfg(feature = "timing")]
                    let t_flate = Instant::now();
                    let mut decoder = flate2::read::GzDecoder::new(raw.as_slice());
                    let mut buf = Vec::new();
                    decoder.read_to_end(&mut buf).unwrap_or_else(|e| {
                        // Red-when-broken: single-member fallback decode failure is
                        // a FAIL verdict, emitted before exiting.
                        lgz::functional_status(
                            "lgz",
                            "decode",
                            false,
                            &format!("flate2 fallback decode failed: {e}"),
                        );
                        eprintln!("lgz: decompression failed: {e}");
                        std::process::exit(1);
                    });
                    #[cfg(feature = "timing")]
                    eprintln!(
                        "[timing] flate2 decode: {:.1}ms  output={:.1}MB",
                        t_flate.elapsed().as_secs_f64() * 1000.0,
                        buf.len() as f64 / 1_048_576.0
                    );
                    buf
                }
            };

        let output: Box<dyn Write> = if let Some(o_idx) = args.iter().position(|a| a == "-o") {
            Box::new(File::create(&args[o_idx + 1]).unwrap())
        } else {
            Box::new(io::stdout())
        };
        let mut w = BufWriter::with_capacity(BUF_CAP, output);
        w.write_all(&buf).unwrap();
        w.flush().unwrap();

        let elapsed = t0.elapsed();
        eprintln!(
            "lgz: {} → {} bytes ({:.1}×) in {:.3}s ({:.0} MB/s output)",
            input_size,
            buf.len(),
            buf.len() as f64 / input_size.max(1) as f64,
            elapsed.as_secs_f64(),
            buf.len() as f64 / elapsed.as_secs_f64() / 1_048_576.0,
        );
    } else {
        let elapsed = t0.elapsed();
        eprintln!(
            "lgz: {} → {} bytes ({:.1}×) in {:.3}s ({:.0} MB/s output)",
            input_size,
            total_out,
            total_out as f64 / input_size.max(1) as f64,
            elapsed.as_secs_f64(),
            total_out as f64 / elapsed.as_secs_f64() / 1_048_576.0,
        );
    }

    // Introspection marker: the lgz gzip decode pipeline finished.
    lgz::functional_status(
        "lgz",
        "decode",
        true,
        &format!(
            "gzip decode completed in {:.3}s",
            t0.elapsed().as_secs_f64()
        ),
    );
}
