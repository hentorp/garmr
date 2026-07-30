//! lzip — parallel ZIP extractor.
//!
//! Parallel-writer pipeline (the shared `gatling::parwrite` fan-out):
//!
//! ```text
//!            ┌── worker 0 ──┐  pread entry → decode → write own file
//!   entries ─┼── worker 1 ──┤  pread entry → decode → write own file
//!    (CD)    └── worker N ──┘  pread entry → decode → write own file
//! ```
//!
//! ZIP entries are **independent** (each its own DEFLATE/STORE stream, its own
//! output file), so there is no single writer thread and no ordered collector:
//! N no-barrier workers self-dispatch the next entry via an atomic cursor, each
//! `pread`s its compressed bytes from the shared file (thread-safe positional
//! reads), decodes with the shared `linflate` core, and writes its own output
//! file — the whole extract runs writer-parallel across every core.
//!
//! Usage: lzip <file.zip> [output-dir]   (no output-dir ⇒ list mode)

use std::collections::HashSet;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::PathBuf;
use std::thread;

use gatling::parwrite::{EntryJob, extract_entries_unordered};
use lzip_parallel::central_dir::{EntryLocation, read_central_directory_from};
use lzip_parallel::chunk::decode_segment_into;
use lzip_parallel::entry::ZipError;

const LOCAL_HEADER_SIG: u32 = 0x04034b50;

// ── Physical core detection (Linux sysfs) ────────────────────────────────────

fn physical_cores() -> usize {
    let n = (|| -> Option<usize> {
        let mut seen = HashSet::new();
        for e in std::fs::read_dir("/sys/devices/system/cpu").ok()? {
            let e = e.ok()?;
            let fname = e.file_name();
            let s = fname.to_str()?;
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

// ── Local file header → compressed data offset ───────────────────────────────

fn local_data_offset(file: &mut File, loc: &EntryLocation) -> Result<u64, ZipError> {
    file.seek(SeekFrom::Start(loc.local_header_offset))
        .map_err(|_| ZipError("seek to local header failed"))?;
    let mut hdr = [0u8; 30];
    file.read_exact(&mut hdr)
        .map_err(|_| ZipError("read local header failed"))?;
    if u32::from_le_bytes(hdr[0..4].try_into().unwrap()) != LOCAL_HEADER_SIG {
        return Err(ZipError("invalid local file header signature"));
    }
    let name_len = u16::from_le_bytes(hdr[26..28].try_into().unwrap()) as u64;
    let extra_len = u16::from_le_bytes(hdr[28..30].try_into().unwrap()) as u64;
    Ok(loc.local_header_offset + 30 + name_len + extra_len)
}

/// Decode one whole DEFLATE entry into `out` (sized to `out_size`). The exact
/// uncompressed size from the central directory makes this a single allocation;
/// the rare overflow (a lying header) falls back to the growing decoder.
fn decode_entry(comp: &[u8], out_size: usize, out: &mut Vec<u8>) -> Result<(), String> {
    let need = out_size + linflate::OVERWRITE_HEADROOM;
    if out.len() < need {
        out.resize(need, 0);
    }
    match linflate::inflate_segment(comp, &mut out[..need]) {
        Ok(written) => {
            out.truncate(written);
            Ok(())
        }
        Err(linflate::InflateError::OutputOverflow) => {
            out.clear();
            decode_segment_into(comp, out).map_err(|e| e.to_string())
        }
        Err(e) => Err(e.to_string()),
    }
}

fn main() {
    // `-n<N>` / `-n <N>` overrides the worker count (the single-core `_st` bench row
    // pins it to `-n1`); absent, default to one worker per physical core.
    let raw: Vec<String> = std::env::args().skip(1).collect();
    let mut n_override: Option<usize> = None;
    let mut positional: Vec<String> = Vec::new();
    let mut it = raw.into_iter();
    while let Some(a) = it.next() {
        if let Some(v) = a.strip_prefix("-n") {
            n_override = if v.is_empty() {
                it.next().and_then(|s| s.parse().ok())
            } else {
                v.parse().ok()
            };
        } else {
            positional.push(a);
        }
    }
    if positional.is_empty() {
        eprintln!("usage: lzip [-n<workers>] <file.zip> [output-dir]");
        std::process::exit(1);
    }

    let zip_path = &positional[0];
    let out_dir: Option<PathBuf> = positional.get(1).map(PathBuf::from);
    let n_workers = n_override.filter(|&n| n > 0).unwrap_or_else(physical_cores);

    let mut file = File::open(zip_path).unwrap_or_else(|e| {
        eprintln!("error opening {zip_path}: {e}");
        std::process::exit(1);
    });

    let entries = read_central_directory_from(&mut file).unwrap_or_else(|e| {
        eprintln!("error: {e}");
        std::process::exit(1);
    });

    // ── List mode: no decompression, just print CD info ────────────────────
    if out_dir.is_none() {
        let files: Vec<_> = entries.iter().filter(|e| !e.is_directory).collect();
        for e in &files {
            println!("{:>10}  {}", e.uncompressed_size, e.name);
        }
        println!("{} entries", files.len());
        lzip_parallel::functional_status(
            "lzip",
            "list",
            true,
            &format!("{} entries listed", files.len()),
        );
        return;
    }
    let out_dir = out_dir.unwrap();

    // ── Resolve entries (compute data offsets via local headers) ──────────
    let mut sorted: Vec<&EntryLocation> = entries.iter().filter(|e| !e.is_directory).collect();
    sorted.sort_by_key(|e| e.local_header_offset);

    let mut jobs: Vec<EntryJob> = Vec::with_capacity(sorted.len());
    for loc in &sorted {
        match local_data_offset(&mut file, loc) {
            Ok(off) => jobs.push(EntryJob {
                data_offset: off,
                comp_len: loc.compressed_size as usize,
                out_size: loc.uncompressed_size as usize,
                is_store: loc.compression_method == 0,
                name: loc.name.clone(),
            }),
            Err(e) => eprintln!("skipping {}: {}", loc.name, e),
        }
    }

    let n_jobs = jobs.len();
    eprintln!("lzip: {n_jobs} entries, {n_workers} parallel writers");

    // ── Parallel-writer extract: each worker decodes AND writes its own file ─
    let stats = extract_entries_unordered(&file, &jobs, &out_dir, n_workers, decode_entry);

    if stats.failed > 0 {
        eprintln!("lzip: {} extracted, {} failed", stats.ok, stats.failed);
    }

    lzip_parallel::functional_status(
        "lzip",
        "extract",
        true,
        &format!("{} entries extracted", stats.ok),
    );
}
