# lbzip2-rs  v0.4.2 "Sleipner" 🐴

<p align="center">
  <img src="doc/media/znippys.png" alt="znippys" width="400"/>
</p>

> 🧙‍♂ Med Allfaderns visdom och blick över varje bit.

Pure Rust parallel bzip2 decompressor. No C dependencies.
Zero per-block allocations, physical-core aware, no polling.
Usable as a **library** (in-process, zero-copy) or as a **CLI** tool:

```bash
# Decompress any bzip2 file (including pbzip2 concatenated streams)
cargo run --release --bin lbunzip2 -- planet-241021.osm.bz2 > planet.osm
```

**What makes this crate unique:** 100% Rust, zero-copy in-process library with a lightweight parallel split method that finds block boundaries with tiny forward-scans (~500 bytes per split). The decoder uses a streaming worker-pool (reorder buffer) to avoid global barriers and is tuned for modern CPU caches (packed Huffman tables fit L1, thread-local buffers leverage L2), yielding high throughput on many-core machines.

Part of the [znippy](https://codeberg.org/nordisk/znippy) group of software,
designed for fast zero-copy integration with
[osm-katana](https://codeberg.org/nordisk/znippy) — the parallel
OSM-to-GeoParquet pipeline.

## Performance vs C lbzip2

### Laptop — T14s (Ryzen AI 360, 8 cores + SMT, 64 GB DDR5)

Planet 1 GB slice (1023 MB compressed → 9861 MB decompressed), interleaved runs, 20s cooldown:

| Condition | Rust lbzip2-rs | C lbzip2 | Δ |
|---|---:|---:|---|
| **Cold start** (fair) | **23.6s (417 MB/s)** | 25.4s (388 MB/s) | **Rust +7.6%** |
| Thermal throttled | 27.5s | 25.6s | C +7% (laptop throttling) |
| **CPU time** (total work) | **2m58s** | 3m21s | **Rust −12% CPU** |

Rust uses 12% less total CPU — the single-thread decode is 1.5× faster than C libbz2.
On sustained workloads, thermal throttling on thin laptops can mask the advantage.

### Odin — Threadripper PRO 3975WX, 32 cores, 512 GB DDR4

Planet 1 GB slice (1023 MB compressed → 9861 MB decompressed), caches dropped, 20s cooldown:

| Condition | Rust lbzip2-rs | C lbzip2 | Δ |
|---|---:|---:|---|
| **Cold start** (fair) | **5.1s (1941 MB/s)** | 5.1s (1924 MB/s) | **~even** |
| **Warm** | **5.1s (1929 MB/s)** | 5.2s (1906 MB/s) | **Rust +1%** |
| **CPU time** (total work) | **2m16s** | 2m33s | **Rust −11% CPU** |

With 32 physical cores both implementations saturate the decode pipeline — wall time
converges. Rust still uses 11% less total CPU thanks to the faster single-thread decode.

Full planet (147 GB → 2.0 TB decompressed):

| Metric | Rust lbzip2-rs | C lbzip2 | Δ |
|---|---:|---:|---|
| **Wall time** | **10m 52s** | 12m 29s | **Rust +13%** |
| **Throughput** | **3104 MB/s** | 2703 MB/s | |
| **CPU time** (user) | **326m** | 382m | **Rust −15% CPU** |
| Output size | 2.0 TB | 2.0 TB | |

### Single-thread decode (library, no I/O)

| Implementation | Time | Throughput | vs C bzip2 |
|---|---:|---:|---:|
| C bzip2 (libbz2 1.0.8) | 123.5s | 80 MB/s | 1.0× |
| C lbzip2 -n1 | 96.0s | 103 MB/s | 1.3× |
| **Rust lbzip2-rs** | **87.9s** | **112 MB/s** | **1.4×** |

### End-to-end: Planet bz2 → PBF (osm-katana)

| | |
|---|---|
| Input | 147 GB planet-241021.osm.bz2 |
| Output | 68 GB planet-241021.osm.pbf |
| Time | **81 minutes** |
| Elements | 10.5 billion |
| Throughput | 309 MB/s decompressed XML |

Full pipeline: bz2 decompress → VTD XML parse → PBF encode, 15 workers.

## Usage

```rust
use lbzip2::chunk::ChunkDecoder;

let data: &[u8] = /* compressed chunk including BZhN header */;
let decoder = ChunkDecoder::from_header(&data[..4])?;

// Returns segments separately — no giant memcpy
let (segments, consumed) = decoder.decode_chunk_segments(data, true)?;
for seg in &segments {
    // each seg is a Vec<u8> of decompressed data, in order
}
```

Single-stream sequential API:

```rust
let output = lbzip2::stream::decompress(&compressed)?;
```

## Förklaring för Farbror Dan 🏍️🇸🇪

> *Hur fungerar worker-pool-arkitekturen?*

Tänk dig **6 rum** (slottar) som återanvänds i en ring. Varje rum
rymmer **200 MB komprimerad data** uppdelad i **N väggar** (en per
CPU-kärna). **N målare** (workers) målar väggar utan att stanna —
när en vägg i rum 1 är klar går målaren **direkt** till rum 2.

```
Rum 1:  [████████████░░] Lisa nästan klar
Rum 2:  [██████░░░░░░░░] Kalle + andra redan igång!
Rum 3:  [██░░░░░░░░░░░░] snabbaste redan här
```

Ingen barriär, ingen väntan. Materialaren fyller rum, målarna
målar, skrivaren skriver — som ett löpande band. 🐴

## License

MIT OR Apache-2.0, plus the original bzip2 license (BSD-style, Julian
Seward) for the block-decode routines inspired by the C reference
implementation. See [LICENSE-BZIP2](LICENSE-BZIP2) for the full text.
