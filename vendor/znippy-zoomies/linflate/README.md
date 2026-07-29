# linflate

*"Allfadern ser varje bit"* — The Allfather sees every bit.

Fast pure-Rust DEFLATE decompressor (inflate engine). Extracted from
[ljar-rs](https://codeberg.org/nordisk/znippy) as a shared crate used by both
[lgz-rs](https://codeberg.org/nordisk/znippy) and ljar-rs.

## Design

- **Full-buffer model** (libdeflate) — no streaming state machine, no circular window
- **SIMD match-copy** (zlib-ng) — SSE2/AVX2 chunk copies for overlapping LZ77 back-references
- **Branchless 64-bit bit refill** — 4 instructions, guarantees ≥56 bits after refill
- **Thread-local `DecompressTables` pool** — zero heap allocation on the hot decode path
- **11-bit first-level Huffman table** — subtable lookups eliminated for real-world streams
- **Segment-aware** — `inflate_segment()` stops at block boundary without requiring BFINAL
- **Window-prefix support** — enables pugz-style speculative parallel decode

Pure Rust, no unsafe *dependencies*. Uses `unsafe` internally for SIMD intrinsics
and raw-pointer arithmetic in the hot loop.

## Benchmark

Single-core decode throughput on Silesia corpus (x86-64, AVX2):

| Crate | Throughput | Notes |
|-------|-----------|-------|
| **linflate** | ~700 MB/s | full-buffer, SIMD match-copy |
| zlib-rs | ~550 MB/s | streaming, SIMD |
| libdeflate (C) | ~650 MB/s | full-buffer, reference |
| miniz_oxide | ~190 MB/s | pure safe Rust, streaming |
| flate2 (miniz_oxide) | ~190 MB/s | wrapper around miniz_oxide |

## Public API

```rust
use linflate::{inflate_into, inflate_segment, inflate_to_vec, OVERWRITE_HEADROOM, InflateError};

// Raw DEFLATE → pre-allocated buffer (zero-copy hot path)
fn inflate_into(compressed: &[u8], output: &mut [u8]) -> Result<usize, InflateError>;

// Non-BFINAL-aware: decompresses one or more blocks, stops at block boundary
fn inflate_segment(compressed: &[u8], output: &mut [u8]) -> Result<usize, InflateError>;

// With LZ77 window prefix for speculative/parallel decode
fn inflate_segment_with_prefix(
    compressed: &[u8], output: &mut [u8], prefix_len: usize,
) -> Result<usize, InflateError>;

// Limited output (for fixup passes in parallel decoders)
fn inflate_segment_with_prefix_limited(
    compressed: &[u8], output: &mut [u8], prefix_len: usize, limit: usize,
) -> Result<usize, InflateError>;

// Convenience: allocates and decompresses
fn inflate_to_vec(compressed: &[u8], expected_size: usize) -> Result<Vec<u8>, InflateError>;

// Caller must add this many bytes to the output buffer for SIMD overwrite safety
const OVERWRITE_HEADROOM: usize;
```

### Usage

```rust
let compressed: &[u8] = /* raw DEFLATE stream (no gzip/zlib header) */;
let mut output = vec![0u8; expected_size + linflate::OVERWRITE_HEADROOM];

let written = linflate::inflate_into(compressed, &mut output)?;
output.truncate(written);
```

## Part of the l-family

| Crate | Purpose |
|-------|---------|
| [lbzip2-rs](https://codeberg.org/nordisk/znippy) | Parallel bzip2 |
| [ljar-rs](https://codeberg.org/nordisk/znippy) | Parallel JAR/ZIP extraction |
| [lgz-rs](https://codeberg.org/nordisk/znippy) | Parallel gzip |
| **linflate-rs** | Shared DEFLATE inflate engine |

## License

MIT OR Apache-2.0

---

Repository: <https://codeberg.org/nordisk/znippy>
