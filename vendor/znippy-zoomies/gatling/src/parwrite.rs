//! Parallel-writer gatling — the shared extract/decode/**write** fan-out.
//!
//! The streaming [`crate::gatling`] engine and the fork-join
//! [`crate::gatling_forkjoin`] both funnel their decoded output through a
//! **single ordered sink** (one collector thread draining an mpsc, one writer).
//! For codecs whose output units are *independent files or independent regions
//! of one pre-sized stream*, that single writer is the last un-parallelised
//! stage — the serial drain that leaves cores idle while one thread copies and
//! writes gigabytes.
//!
//! This module removes it. It is the parallel-writer sibling of
//! [`gatling_for_each`](crate::gatling_forkjoin::gatling_for_each): the same
//! no-barrier, self-dispatching (atomic-cursor) worker pool built on
//! `std::thread::scope`, but each worker also **writes its own output** — there
//! is no collector and no writer thread on the critical path.
//!
//! Two shapes, both format-agnostic (the caller plugs in the decode):
//!
//! - [`extract_entries_unordered`] — N workers self-dispatch **independent
//!   entries** (ZIP/JAR members). Each worker `pread`s its entry's compressed
//!   bytes from the shared input (thread-safe positional reads, no shared file
//!   offset), decodes, and writes its **own output file**. Entries are
//!   independent, so the file writes never conflict and no ordering is needed.
//!
//! - [`write_segments_positional`] — N workers self-dispatch **independent
//!   segments of one output stream** (concatenated gzip members). The caller
//!   pre-computes each segment's byte offset (a prefix-sum of known output
//!   sizes) and pre-sizes the output file; each worker decodes its segment and
//!   `pwrite`s it at the segment's offset. Exact byte order is preserved with
//!   no ordered collector and no serial concatenation.
//!
//! Both reuse each worker's scratch buffers across the units it claims
//! (zero-alloc hot loop after warm-up), never copy input into the pool (the
//! decode reads directly from the shared source), and are rayon-free: pure
//! `std::thread::scope` + one `AtomicUsize` cursor — the gatling soul.

use std::fs::{self, File};
use std::io::Write;
use std::os::unix::fs::FileExt;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};

/// Outcome of a parallel-writer run: how many units were written and how many
/// failed (a failed unit is logged to stderr and skipped, never aborting the
/// siblings).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct WriteStats {
    /// Units decoded and written successfully.
    pub ok: usize,
    /// Units that failed to read/decode/write (skipped, logged).
    pub failed: usize,
}

/// One independent extraction unit for [`extract_entries_unordered`]: read
/// `comp_len` compressed bytes at `data_offset` from the shared input, decode,
/// and write the result to `out_dir.join(name)`.
pub struct EntryJob {
    /// Byte offset of the entry's compressed payload in the shared input file.
    pub data_offset: u64,
    /// Compressed payload length in bytes.
    pub comp_len: usize,
    /// Uncompressed size (exact, from the archive central directory) — sizes the
    /// decode output buffer so the hot loop never reallocates.
    pub out_size: usize,
    /// Method-0 STORE entry: payload is copied verbatim (no decode).
    pub is_store: bool,
    /// Relative output path (joined onto `out_dir`).
    pub name: String,
}

/// Extract independent entries across a no-barrier, self-dispatching worker pool
/// — **each worker decodes AND writes its own output file**, with no ordered
/// collector and no single writer thread.
///
/// `input` is the shared archive file; workers read each entry's compressed
/// bytes with `read_exact_at` (`pread`), which is thread-safe and uses no shared
/// file offset, so N workers read disjoint regions concurrently. `decode` turns
/// one entry's compressed bytes into its uncompressed bytes: it is handed the
/// compressed slice, the entry's exact `out_size`, and a **reused** output
/// buffer to fill (cleared first). STORE entries (`is_store`) bypass `decode`
/// and are copied verbatim.
///
/// Returns the [`WriteStats`]. A unit that fails to read/decode/write is logged
/// to stderr and skipped; its siblings keep running.
pub fn extract_entries_unordered<D>(
    input: &File,
    jobs: &[EntryJob],
    out_dir: &Path,
    n_workers: usize,
    decode: D,
) -> WriteStats
where
    D: Fn(&[u8], usize, &mut Vec<u8>) -> Result<(), String> + Sync,
{
    let n = jobs.len();
    if n == 0 {
        return WriteStats::default();
    }
    let workers = n_workers.max(1).min(n);

    let next = AtomicUsize::new(0);
    let ok = AtomicUsize::new(0);
    let failed = AtomicUsize::new(0);

    let next_ref = &next;
    let ok_ref = &ok;
    let failed_ref = &failed;
    let decode_ref = &decode;

    std::thread::scope(|s| {
        for _ in 0..workers {
            s.spawn(move || {
                // Per-worker scratch, reused across every entry this worker
                // claims — zero-alloc after the first (largest) entry.
                let mut comp: Vec<u8> = Vec::new();
                let mut out: Vec<u8> = Vec::new();
                loop {
                    let i = next_ref.fetch_add(1, Ordering::Relaxed);
                    if i >= n {
                        break;
                    }
                    let job = &jobs[i];

                    // Read the compressed payload via pread (no shared offset).
                    if comp.len() < job.comp_len {
                        comp.resize(job.comp_len, 0);
                    }
                    if let Err(e) = input.read_exact_at(&mut comp[..job.comp_len], job.data_offset)
                    {
                        eprintln!("parwrite: read {}: {e}", job.name);
                        failed_ref.fetch_add(1, Ordering::Relaxed);
                        continue;
                    }
                    let comp_slice = &comp[..job.comp_len];

                    // Decode (or copy for STORE) into the reused output buffer.
                    out.clear();
                    if job.is_store {
                        out.extend_from_slice(comp_slice);
                    } else if let Err(e) = decode_ref(comp_slice, job.out_size, &mut out) {
                        eprintln!("parwrite: decode {}: {e}", job.name);
                        failed_ref.fetch_add(1, Ordering::Relaxed);
                        continue;
                    }

                    // Write our own output file (independent entry → no ordering).
                    let dest = out_dir.join(&job.name);
                    if let Some(parent) = dest.parent() {
                        if let Err(e) = fs::create_dir_all(parent) {
                            eprintln!("parwrite: mkdir {}: {e}", parent.display());
                            failed_ref.fetch_add(1, Ordering::Relaxed);
                            continue;
                        }
                    }
                    match File::create(&dest).and_then(|mut f| f.write_all(&out)) {
                        Ok(()) => {
                            ok_ref.fetch_add(1, Ordering::Relaxed);
                        }
                        Err(e) => {
                            eprintln!("parwrite: write {}: {e}", dest.display());
                            failed_ref.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }
            });
        }
    });

    WriteStats {
        ok: ok.load(Ordering::Relaxed),
        failed: failed.load(Ordering::Relaxed),
    }
}

/// Write independent segments of **one** output stream at pre-computed offsets,
/// across a no-barrier, self-dispatching worker pool — **each worker decodes
/// AND `pwrite`s its own segment**, with no ordered collector and no serial
/// concatenation.
///
/// The caller has already laid out the stream: `offsets[i]` is the byte offset
/// in `out` where segment `i`'s decoded bytes belong (a prefix-sum of the
/// segments' known output sizes), and `out` has been pre-sized to the total
/// (e.g. via `set_len`). Each worker claims the next segment index, calls
/// `decode(i, &mut buf)` to fill its reused buffer, and `write_all_at`
/// (`pwrite`) writes it at `offsets[i]` — positional writes to disjoint regions
/// never conflict, so exact stream byte-order is preserved without any ordering
/// on the critical path.
///
/// `decode` should verify the decoded length matches what the caller assumed
/// for `offsets` (returning `Err` on mismatch); a failed segment is logged and
/// skipped, and the caller can detect `failed > 0` to fall back to a safe path.
pub fn write_segments_positional<D>(
    out: &File,
    n_segments: usize,
    offsets: &[u64],
    n_workers: usize,
    decode: D,
) -> WriteStats
where
    D: Fn(usize, &mut Vec<u8>) -> Result<(), String> + Sync,
{
    assert_eq!(
        offsets.len(),
        n_segments,
        "offsets must have one entry per segment"
    );
    if n_segments == 0 {
        return WriteStats::default();
    }
    let workers = n_workers.max(1).min(n_segments);

    let next = AtomicUsize::new(0);
    let ok = AtomicUsize::new(0);
    let failed = AtomicUsize::new(0);

    let next_ref = &next;
    let ok_ref = &ok;
    let failed_ref = &failed;
    let decode_ref = &decode;

    std::thread::scope(|s| {
        for _ in 0..workers {
            s.spawn(move || {
                let mut buf: Vec<u8> = Vec::new();
                loop {
                    let i = next_ref.fetch_add(1, Ordering::Relaxed);
                    if i >= n_segments {
                        break;
                    }
                    buf.clear();
                    if let Err(e) = decode_ref(i, &mut buf) {
                        eprintln!("parwrite: segment {i} decode: {e}");
                        failed_ref.fetch_add(1, Ordering::Relaxed);
                        continue;
                    }
                    match out.write_all_at(&buf, offsets[i]) {
                        Ok(()) => {
                            ok_ref.fetch_add(1, Ordering::Relaxed);
                        }
                        Err(e) => {
                            eprintln!("parwrite: segment {i} pwrite: {e}");
                            failed_ref.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }
            });
        }
    });

    WriteStats {
        ok: ok.load(Ordering::Relaxed),
        failed: failed.load(Ordering::Relaxed),
    }
}

/// Write already-decoded slices of **one** output stream at pre-computed offsets,
/// across a no-barrier, self-dispatching worker pool — **zero-copy parallel
/// `pwrite`**, no ordered collector and no serial concatenation.
///
/// The two-phase sibling of [`write_segments_positional`]: use it when the
/// segments are already materialised (e.g. members decoded in parallel by a
/// prior [`gatling_for_each`](crate::gatling_forkjoin::gatling_for_each) pass)
/// and their exact sizes — hence `offsets` — are known. `out` must be pre-sized
/// to the total (`set_len`). Each worker claims the next slice index and
/// `write_all_at` (`pwrite`)s `slices[i]` at `offsets[i]`; the slices are never
/// copied through the pool, and positional writes to disjoint regions preserve
/// exact stream byte-order with no ordering on the critical path.
pub fn write_slices_positional(
    out: &File,
    slices: &[&[u8]],
    offsets: &[u64],
    n_workers: usize,
) -> WriteStats {
    assert_eq!(
        offsets.len(),
        slices.len(),
        "offsets must have one entry per slice"
    );
    let n = slices.len();
    if n == 0 {
        return WriteStats::default();
    }
    let workers = n_workers.max(1).min(n);

    let next = AtomicUsize::new(0);
    let ok = AtomicUsize::new(0);
    let failed = AtomicUsize::new(0);

    let next_ref = &next;
    let ok_ref = &ok;
    let failed_ref = &failed;

    std::thread::scope(|s| {
        for _ in 0..workers {
            s.spawn(move || {
                loop {
                    let i = next_ref.fetch_add(1, Ordering::Relaxed);
                    if i >= n {
                        break;
                    }
                    match out.write_all_at(slices[i], offsets[i]) {
                        Ok(()) => {
                            ok_ref.fetch_add(1, Ordering::Relaxed);
                        }
                        Err(e) => {
                            eprintln!("parwrite: slice {i} pwrite: {e}");
                            failed_ref.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }
            });
        }
    });

    WriteStats {
        ok: ok.load(Ordering::Relaxed),
        failed: failed.load(Ordering::Relaxed),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    #[test]
    fn extract_writes_every_entry_concurrently() {
        // Build an "archive": three payloads concatenated in one temp file.
        let dir = std::env::temp_dir().join(format!("parwrite-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let arc_path = dir.join("archive.bin");

        let payloads: Vec<Vec<u8>> = (0..3)
            .map(|k| (0..1000).map(|i| (i as u8).wrapping_add(k as u8)).collect())
            .collect();
        let mut arc = Vec::new();
        let mut jobs = Vec::new();
        for (k, p) in payloads.iter().enumerate() {
            jobs.push(EntryJob {
                data_offset: arc.len() as u64,
                comp_len: p.len(),
                out_size: p.len(),
                is_store: true, // verbatim copy path
                name: format!("out_{k}.bin"),
            });
            arc.extend_from_slice(p);
        }
        fs::write(&arc_path, &arc).unwrap();
        let f = File::open(&arc_path).unwrap();

        let out_dir = dir.join("out");
        let stats = extract_entries_unordered(&f, &jobs, &out_dir, 4, |_c, _s, _o| Ok(()));
        assert_eq!(stats.ok, 3);
        assert_eq!(stats.failed, 0);
        for (k, p) in payloads.iter().enumerate() {
            let got = fs::read(out_dir.join(format!("out_{k}.bin"))).unwrap();
            assert_eq!(&got, p, "entry {k} bytes must round-trip");
        }
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn positional_writes_reassemble_in_order() {
        let dir = std::env::temp_dir().join(format!("parwrite-pos-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let out_path = dir.join("stream.bin");

        // Four segments of differing sizes; workers may finish out of order but
        // the positional writes must reassemble the exact concatenation.
        let segs: Vec<Vec<u8>> = vec![
            vec![1u8; 100],
            vec![2u8; 250],
            vec![3u8; 50],
            vec![4u8; 400],
        ];
        let mut offsets = Vec::new();
        let mut total = 0u64;
        for s in &segs {
            offsets.push(total);
            total += s.len() as u64;
        }
        let out = File::create(&out_path).unwrap();
        out.set_len(total).unwrap();

        let stats = write_segments_positional(&out, segs.len(), &offsets, 4, |i, buf| {
            buf.extend_from_slice(&segs[i]);
            Ok(())
        });
        assert_eq!(stats.ok, segs.len());
        assert_eq!(stats.failed, 0);
        drop(out);

        let mut got = Vec::new();
        File::open(&out_path)
            .unwrap()
            .read_to_end(&mut got)
            .unwrap();
        let mut want = Vec::new();
        for s in &segs {
            want.extend_from_slice(s);
        }
        assert_eq!(
            got, want,
            "positional segments must reassemble in stream order"
        );
        let _ = fs::remove_dir_all(&dir);
    }
}
