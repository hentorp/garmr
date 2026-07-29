//! Blob decompression — handles zlib and zstd blob payloads.
//!
//! `decompress` is the hot path: called directly by the Gatling worker that
//! owns each blob, so every core decompresses and parses in parallel. The old
//! single-thread wrapper (`spawn_decompressor`) is gone — it was a
//! serialisation bottleneck.
//!
//! `ZSTD_DCtx` is reused per worker thread via `thread_local!` to avoid one
//! malloc/free per blob (hundreds of allocations per pass).

#![allow(unsafe_code, reason = "zstd-sys-rs is raw C FFI")]

use std::io::Read as _;

use anyhow::Context as _;
use flate2::read::ZlibDecoder;

use crate::pbf_io::read_varint;

const MAX_BLOB_SIZE: usize = 32 * 1024 * 1024; // 32 MB limit per OSM spec

/// Decompress one raw Blob protobuf. Returns `None` for empty/unsupported blobs.
pub fn decompress(blob_bytes: &[u8]) -> anyhow::Result<Option<Vec<u8>>> {
    decompress_blob(blob_bytes)
}

// ── Blob proto parser + dispatcher ───────────────────────────────────────────
// Blob { optional int32 raw_size = 2; oneof data { bytes raw = 1; bytes zlib_data = 3;
//         bytes zstd_data = 7; } }

fn decompress_blob(bytes: &[u8]) -> anyhow::Result<Option<Vec<u8>>> {
    let mut pos = 0usize;
    let mut raw_size = 0usize;
    let mut payload = BlobPayload::None;

    while pos < bytes.len() {
        let (tag, n) = read_varint(bytes, pos)?;
        pos = pos.saturating_add(n);
        let field = (tag >> 3) as u32;
        let wire_type = (tag & 7) as u32;

        match (field, wire_type) {
            (2, 0) => {
                // raw_size varint
                let (v, n2) = read_varint(bytes, pos)?;
                pos = pos.saturating_add(n2);
                raw_size = v as usize;
            }
            (1, 2) | (3, 2) | (7, 2) => {
                // raw / zlib_data / zstd_data — length-delimited
                let (len, n2) = read_varint(bytes, pos)?;
                pos = pos.saturating_add(n2);
                let len = len as usize;
                let slice = bytes
                    .get(pos..pos.saturating_add(len))
                    .ok_or_else(|| anyhow::anyhow!("blob data out of range"))?;
                pos = pos.saturating_add(len);
                payload = match field {
                    1 => BlobPayload::Raw(slice),
                    3 => BlobPayload::Zlib(slice),
                    7 => BlobPayload::Zstd(slice),
                    _ => unreachable!(),
                };
            }
            (_, 0) => {
                let (_, n2) = read_varint(bytes, pos)?;
                pos = pos.saturating_add(n2);
            }
            (_, 2) => {
                let (len, n2) = read_varint(bytes, pos)?;
                pos = pos.saturating_add(n2).saturating_add(len as usize);
            }
            _ => break,
        }
    }

    let decompressed = match payload {
        BlobPayload::None => return Ok(None),
        BlobPayload::Raw(data) => data.to_vec(),
        BlobPayload::Zlib(data) => {
            let cap = raw_size.min(MAX_BLOB_SIZE);
            let mut out = Vec::with_capacity(cap);
            ZlibDecoder::new(data)
                .take(MAX_BLOB_SIZE as u64)
                .read_to_end(&mut out)
                .context("zlib decompress")?;
            out
        }
        BlobPayload::Zstd(data) => decompress_zstd(data, raw_size).context("zstd decompress")?,
    };

    Ok(Some(decompressed))
}

enum BlobPayload<'a> {
    None,
    Raw(&'a [u8]),
    Zlib(&'a [u8]),
    Zstd(&'a [u8]),
}

// ── Per-thread zstd context ───────────────────────────────────────────────────

// Wraps a raw ZSTD_DCtx pointer so it can live in thread_local and be freed
// when the thread exits.  Never sent across threads — thread_local guarantees
// each thread gets its own instance.
struct ZstdDCtx(*mut zstd_sys_rs::ZSTD_DCtx);

// SAFETY: only ever accessed from the owning thread via thread_local.
unsafe impl Send for ZstdDCtx {}

impl Drop for ZstdDCtx {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: pointer was created by ZSTD_createDCtx and not freed yet.
            unsafe {
                zstd_sys_rs::ZSTD_freeDCtx(self.0);
            }
        }
    }
}

thread_local! {
    // One ZSTD_DCtx per rayon worker thread, alive for the duration of the thread.
    static ZSTD_CTX: ZstdDCtx = ZstdDCtx(
        // SAFETY: ZSTD_createDCtx returns a valid pointer or null.
        unsafe { zstd_sys_rs::ZSTD_createDCtx() }
    );
}

fn decompress_zstd(src: &[u8], raw_size: usize) -> anyhow::Result<Vec<u8>> {
    let cap = if raw_size > 0 {
        raw_size.min(MAX_BLOB_SIZE)
    } else {
        src.len().saturating_mul(4).min(MAX_BLOB_SIZE)
    };

    // Reuse a per-thread output buffer to avoid malloc/free per blob.
    thread_local! {
        static BUF: std::cell::RefCell<Vec<u8>> = std::cell::RefCell::new(Vec::new());
    }

    BUF.with(|cell| {
        let mut buf = cell.borrow_mut();
        buf.resize(cap, 0);

        let written = ZSTD_CTX.with(|ctx_wrapper| -> anyhow::Result<usize> {
            anyhow::ensure!(!ctx_wrapper.0.is_null(), "ZSTD_createDCtx returned null");
            let n = unsafe {
                zstd_sys_rs::ZSTD_decompressDCtx(
                    ctx_wrapper.0,
                    buf.as_mut_ptr().cast(),
                    buf.len(),
                    src.as_ptr().cast(),
                    src.len(),
                )
            };
            anyhow::ensure!(
                unsafe { zstd_sys_rs::ZSTD_isError(n) } == 0,
                "zstd error code {n}",
            );
            Ok(n)
        })?;

        // Return a copy of just the decompressed data.
        // The buffer stays allocated in thread-local for the next call.
        Ok(buf[..written].to_vec())
    })
}
