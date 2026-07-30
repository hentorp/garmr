# ljar-rs

*"Allfadern ser varje bit"*

Pure Rust parallel JAR/ZIP decompressor. Reads the ZIP Central Directory, then
decodes all DEFLATE entries in parallel using [linflate](https://codeberg.org/nordisk/znippy)
(shared SIMD inflate engine). `miniz_oxide` is fully removed from production dependencies.

**1.8× faster than `unzip -t`** on multi-core hardware.

## Performance

| Workload | ljar | unzip | Speedup |
|----------|------|-------|---------|
| 2000-entry JAR (6.9 MB compressed) | 1.86 s | 5.37 s | **1.8×** |

- Each ZIP entry is decoded independently (ZIP format is fully parallel by design)
- Large entries are also split internally at DEFLATE full-flush boundaries

## Usage

```bash
ljar archive.jar -o dir/    # extract to directory
ljar archive.jar            # list entries to stdout
```

## Architecture

1. Parse ZIP End-of-Central-Directory (EOCD)
2. Read Central Directory → build entry list
3. For each entry: resolve local header → get compressed data pointer
4. Parallel decode all entries via the shared gatling fork-join engine (large entries also split internally at flush boundaries)
5. Write/output in order

### Ring-slot pipeline

Same architecture as lbzip2-rs / lgz-rs:

- **6 slots × 232 MB** (200 MB data + 32 MB carry headroom)
- AVX-512 / AVX2 / scalar SIMD flush scanner for intra-entry parallelism
- Dedicated reader, decoder (N threads), collector, and writer threads
- Zero-copy compressed input: workers read directly from ring-buffer slots

### Internal `src/inflate/` module

The embedded inflate engine in `src/inflate/` is now redundant — it has been
extracted into [linflate-rs](https://codeberg.org/nordisk/znippy) which is
the production SIMD DEFLATE decoder. The internal module remains as a historical
reference.

## Dependencies

| Crate | Role |
|-------|------|
| [linflate](https://codeberg.org/nordisk/znippy) | SIMD DEFLATE decode (shared with lgz-rs) |
| [gatling (rotaryengine)](https://crates.io/crates/rotaryengine) | Shared no-barrier fork-join engine for parallel entry decode |

### Optional features

- `zlib-ng` — use zlib-ng backend via flate2 (requires C toolchain)
- `gen` — JAR generation utilities (dev/testing)

## Sister projects

All at [codeberg.org/nordisk/znippy](https://codeberg.org/nordisk/znippy):

- [lbzip2-rs](https://codeberg.org/nordisk/znippy) — parallel bzip2 decompressor
- [lgz-rs](https://codeberg.org/nordisk/znippy) — parallel gzip decompressor
- [linflate-rs](https://codeberg.org/nordisk/znippy) — shared SIMD DEFLATE engine
- [lzip-rs](https://codeberg.org/nordisk/znippy) — parallel zip decompressor

## License

MIT OR Apache-2.0
