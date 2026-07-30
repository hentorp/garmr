# lgz — Parallel Gzip Decompressor

*"Allfadern ser varje bit"*

Production-ready parallel gzip decompressor in Rust. Uses [linflate](https://codeberg.org/nordisk/znippy) (shared SIMD inflate engine) for all DEFLATE decoding.

Sister projects: [lbzip2-rs](https://codeberg.org/nordisk/znippy) · [ljar-rs](https://codeberg.org/nordisk/znippy) · [linflate-rs](https://codeberg.org/nordisk/znippy)

## Performance (32 cores, 1 GB input)

| Strategy | Throughput | Notes |
|----------|-----------|-------|
| Full-flush parallel (pigz -i) | 6,100+ MB/s | Linear scaling |
| Speculative parallel (gzip -1 random) | 527 MB/s | Two-pass pugz-style |
| Sync-flush fallback (single segment) | 1,729 MB/s | ISIZE-hinted alloc |
| vs pigz -d | 433 ms | |
| vs gzip -d | 449 ms | |

## Usage

```bash
lgz input.gz -o output       # decompress to file
lgz input.gz                  # decompress to stdout
lgz input.tar.gz -o dir/     # extract tar.gz
```

## Parallel Strategies

Three strategies, tried in priority order:

1. **Flush-boundary split** — SIMD scan for `00 00 FF FF` markers (pigz/BGZF), split at boundaries, decode segments in parallel.
2. **Concatenated gzip members** — Scan for `1f 8b 08` headers, decode fully independent members in parallel.
3. **Pugz-style speculative** — Two-pass: scan for stored-block LEN/NLEN patterns, probe-decode to confirm, split with 32 KB window prefix.

Falls back to single-threaded linflate decode if no split points found (with ISIZE hint for optimal allocation).

## Architecture

Ring-slot pipeline (shared with lbzip2-rs/ljar-rs):

```
Reader → Main (carry + split) → N Workers (decode_segment) → Collector → Writer
         6 slots × 232 MB        zero-copy raw-ptr access
```

- AVX-512 / AVX2 / scalar SIMD flush scanner (runtime-selected)
- Sync-flush vs full-flush auto-detection (5-byte pattern match, zero-cost)
- `--features timing` instrumentation (zero overhead when disabled)

## Dependencies

| Crate | Role |
|-------|------|
| `linflate` | SIMD DEFLATE decode (shared with ljar-rs) |
| `rayon` | Parallel segment decode |
| `flate2` | Gzip header/trailer parsing only |
| `tar` | Optional tar extraction |

## Acknowledgements

Two-pass speculative decode inspired by [pugz](https://github.com/Piezoid/pugz) (Kerbiriou & Chikhi, 2019, MIT).

## License

MIT OR Apache-2.0
