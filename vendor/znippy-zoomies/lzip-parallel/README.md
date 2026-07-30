# lzip-rs

*"Allfadern ser varje bit"*

Pure Rust parallel ZIP decompressor for Windows/Linux/macOS .zip files. Reads
the ZIP Central Directory, then decodes all DEFLATE entries in parallel using
[linflate](https://codeberg.org/nordisk/znippy) (shared SIMD inflate engine).

**1.8× faster than `unzip -t`** on multi-core hardware.

## Performance

| Workload | lzip | unzip | Speedup |
|----------|------|-------|---------|
| 2000-entry ZIP (6.9 MB compressed) | 1.86 s | 5.37 s | **1.8×** |

- Each ZIP entry is decoded independently (ZIP format is fully parallel by design)
- Large entries are also split internally at DEFLATE full-flush boundaries

## Usage

```bash
lzip archive.zip -o dir/    # extract to directory
lzip archive.zip            # list entries to stdout
```

## Architecture

1. Parse ZIP End-of-Central-Directory (EOCD)
2. Read Central Directory → build entry list
3. For each entry: resolve local header → get compressed data pointer
4. Parallel decode all entries via rayon (large entries also split internally at flush boundaries)
5. Write/output in order

### Ring-slot pipeline

Same architecture as lbzip2-rs / lgz-rs:

- **6 slots × 232 MB** (200 MB data + 32 MB carry headroom)
- AVX-512 / AVX2 / scalar SIMD flush scanner for intra-entry parallelism
- Dedicated reader, decoder (N threads), collector, and writer threads
- Zero-copy compressed input: workers read directly from ring-buffer slots

## Dependencies

| Crate | Role |
|-------|------|
| [linflate](https://codeberg.org/nordisk/znippy) | SIMD DEFLATE decode (shared with lgz-rs) |
| [rayon](https://crates.io/crates/rayon) | Parallel entry decode |

### Optional features

- `zlib-ng` — use zlib-ng backend via flate2 (requires C toolchain)
- `gen` — ZIP generation utilities (dev/testing)

## Sister projects

All at [codeberg.org/nordisk/znippy](https://codeberg.org/nordisk/znippy):

- [lbzip2-rs](https://codeberg.org/nordisk/znippy) — parallel bzip2 decompressor
- [lgz-rs](https://codeberg.org/nordisk/znippy) — parallel gzip decompressor
- [ljar-rs](https://codeberg.org/nordisk/znippy) — parallel JAR decompressor
- [linflate-rs](https://codeberg.org/nordisk/znippy) — shared SIMD DEFLATE engine

## License

MIT OR Apache-2.0
