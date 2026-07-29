# zip-core

Shared streaming-ZIP machinery for the znippy-zoomies constellation.

A JAR **is** a ZIP: both share the exact same End-of-Central-Directory record,
ZIP64 extensions, Central Directory header layout, and DEFLATE full-flush
boundaries. This crate holds that format-agnostic core **once** so the
[`ljar`](../ljar) (JAR) and [`lzip-parallel`](../lzip-parallel) (ZIP)
decompressors consume it as thin wrappers instead of carrying near-verbatim
twin copies.

Contents:

- `central_dir` — EOCD / ZIP64 EOCD parser + Central Directory walk, both the
  in-memory (`&[u8]`) and streaming (`Read + Seek`) entry points, producing
  `EntryLocation` records.
- `deflate_scan` — crate-local parallel full-flush split-point search (fans out
  through the shared gatling no-barrier engine; ROOT LAW #0: gatling only),
  re-exporting linflate's `FlushBoundary` / `find_all_flushes`.

The format-specific bits (entry decode, CRC policy, batch/streaming readers,
CLI) stay in each consumer crate.
