//! Safe, allocation-aware wrappers over the raw libzstd 1.5.7 FFI.
//!
//! The crate root is bindgen-generated FFI (`ZSTD_*`); this module adds the
//! minimum safe surface most callers need — one-shot compress/decompress plus a
//! **zero-extra-allocation** path: a reusable [`Decompressor`] (amortizes the
//! `ZSTD_DCtx` across many frames) that decompresses straight into a caller-owned
//! buffer via [`Decompressor::decompress_into`]. That's the shape hot loops want
//! (decode N frames, reuse one context + one output buffer, no per-frame `Vec`).

use core::ffi::c_void;

use crate::{
    ZSTD_DCtx, ZSTD_compress, ZSTD_compressBound, ZSTD_createDCtx, ZSTD_decompress,
    ZSTD_decompressDCtx, ZSTD_freeDCtx, ZSTD_getErrorName, ZSTD_getFrameContentSize, ZSTD_isError,
};

/// A libzstd error (the raw `size_t` code; name via `Display`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Error(pub usize);

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // SAFETY: ZSTD_getErrorName returns a static NUL-terminated C string.
        let name = unsafe { core::ffi::CStr::from_ptr(ZSTD_getErrorName(self.0)) };
        write!(f, "zstd error: {}", name.to_string_lossy())
    }
}

impl std::error::Error for Error {}

pub type Result<T> = core::result::Result<T, Error>;

#[inline]
fn check(code: usize) -> Result<usize> {
    // SAFETY: pure predicate over the return code.
    if unsafe { ZSTD_isError(code) } != 0 {
        Err(Error(code))
    } else {
        Ok(code)
    }
}

/// Maximum compressed size for `src_len` input bytes.
#[inline]
#[must_use]
pub fn compress_bound(src_len: usize) -> usize {
    // SAFETY: pure function of the length.
    unsafe { ZSTD_compressBound(src_len) }
}

/// Decompressed size declared in the frame header, if present and known.
/// `None` for "unknown" (streaming-written) or malformed frames.
#[inline]
#[must_use]
pub fn frame_content_size(src: &[u8]) -> Option<usize> {
    // SAFETY: reads only `src.len()` bytes from `src`.
    let s = unsafe { ZSTD_getFrameContentSize(src.as_ptr() as *const c_void, src.len()) };
    // ZSTD_CONTENTSIZE_UNKNOWN = (0ULL - 1), ZSTD_CONTENTSIZE_ERROR = (0ULL - 2).
    if s == u64::MAX || s == u64::MAX - 1 {
        None
    } else {
        Some(s as usize)
    }
}

/// One-shot compress into a fresh `Vec` at the given level (1..=22).
pub fn compress(src: &[u8], level: i32) -> Result<Vec<u8>> {
    let cap = compress_bound(src.len());
    let mut dst = vec![0u8; cap];
    // SAFETY: dst has `cap` writable bytes; src has `src.len()` readable bytes.
    let n = check(unsafe {
        ZSTD_compress(
            dst.as_mut_ptr() as *mut c_void,
            cap,
            src.as_ptr() as *const c_void,
            src.len(),
            level,
        )
    })?;
    dst.truncate(n);
    Ok(dst)
}

/// One-shot decompress into a fresh `Vec` sized from the frame header.
/// Errors if the frame doesn't declare its content size (use streaming/a known
/// bound for those).
pub fn decompress(src: &[u8]) -> Result<Vec<u8>> {
    let cap = frame_content_size(src).ok_or(Error(0))?;
    let mut dst = vec![0u8; cap];
    let n = decompress_into(src, &mut dst)?;
    debug_assert_eq!(n, cap);
    dst.truncate(n);
    Ok(dst)
}

/// Decompress one frame into a caller-owned buffer (no allocation here).
/// Returns the number of bytes written; `dst` must be at least the frame's
/// decompressed size.
pub fn decompress_into(src: &[u8], dst: &mut [u8]) -> Result<usize> {
    // SAFETY: dst/src are valid for their lengths; libzstd writes ≤ dst.len().
    check(unsafe {
        ZSTD_decompress(
            dst.as_mut_ptr() as *mut c_void,
            dst.len(),
            src.as_ptr() as *const c_void,
            src.len(),
        )
    })
}

/// Reusable decompression context. Creating a `ZSTD_DCtx` allocates and warms
/// internal tables; holding one across many frames (with [`Self::decompress_into`]
/// into a reused buffer) makes a decode loop allocation-free after warm-up.
pub struct Decompressor {
    dctx: *mut ZSTD_DCtx,
}

impl Decompressor {
    /// Allocate a decompression context.
    #[must_use]
    pub fn new() -> Self {
        // SAFETY: ZSTD_createDCtx returns an owned ctx or null on OOM.
        let dctx = unsafe { ZSTD_createDCtx() };
        assert!(!dctx.is_null(), "ZSTD_createDCtx returned null (OOM)");
        Self { dctx }
    }

    /// Decompress one frame into `dst` reusing this context. No allocation.
    pub fn decompress_into(&mut self, src: &[u8], dst: &mut [u8]) -> Result<usize> {
        // SAFETY: self.dctx is a live ctx; dst/src valid for their lengths.
        check(unsafe {
            ZSTD_decompressDCtx(
                self.dctx,
                dst.as_mut_ptr() as *mut c_void,
                dst.len(),
                src.as_ptr() as *const c_void,
                src.len(),
            )
        })
    }
}

impl Default for Decompressor {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for Decompressor {
    fn drop(&mut self) {
        // SAFETY: dctx came from ZSTD_createDCtx and is freed exactly once.
        unsafe { ZSTD_freeDCtx(self.dctx) };
    }
}

// The context is owned exclusively (methods take &mut self); it is safe to move
// to another thread, but not to share concurrently.
unsafe impl Send for Decompressor {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_oneshot() {
        let data = b"the quick brown fox jumps over the lazy dog".repeat(1000);
        let comp = compress(&data, 3).unwrap();
        assert!(comp.len() < data.len());
        assert_eq!(frame_content_size(&comp), Some(data.len()));
        assert_eq!(decompress(&comp).unwrap(), data);
    }

    #[test]
    fn roundtrip_zero_copy_reused_ctx() {
        let frames: Vec<Vec<u8>> = (0..16)
            .map(|i| compress(format!("frame {i} ").repeat(500).as_bytes(), 3).unwrap())
            .collect();
        let mut dctx = Decompressor::new();
        let mut buf = vec![0u8; 64 * 1024];
        for (i, f) in frames.iter().enumerate() {
            let n = dctx.decompress_into(f, &mut buf).unwrap();
            assert_eq!(&buf[..n], format!("frame {i} ").repeat(500).as_bytes());
        }
    }

    #[test]
    fn error_displays() {
        // A bogus frame should error, not panic.
        assert!(decompress_into(b"not a zstd frame", &mut [0u8; 16]).is_err());
    }
}
