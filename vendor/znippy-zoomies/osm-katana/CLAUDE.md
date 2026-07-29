# osm-katana

Fast OSM format converter. Part of znippy workspace.
See `znippy/WORKSPACE.md` for dependency graph and release gate protocol.

## CLI subcommands

```
osm-katana convert  <input>              # OSM XML/BZ2/GZ/PBF → GeoParquet
osm-katana xml2pbf  <input> [output]     # OSM XML/BZ2 → PBF
osm-katana pbf2geo  <input>              # PBF → GeoParquet
osm-katana geo2arrow <input> <output>    # GeoParquet → Arrow IPC
osm-katana verify   [dir]               # inspect/verify GeoParquet output
```

`vtd_bench` remains a separate binary (dev/benchmark tool, not shipped).

## Benchmarks

```
cargo bench -p osm-katana
```

History: `znippy-zoomies/osm-katana/bench_history.json`

### Required columns per bench entry

```json
{
  "date": "2026-05-30",
  "version": "0.2.0",
  "machine": "T14s",
  "cores": 16,
  "results": [
    {
      "name":              "liechtenstein_bz2_to_geo",
      "converter":         "convert",
      "input_format":      "bz2",
      "input_mb":          5.2,
      "reference_tool":    "bzip2 -d | osmconvert",
      "reference_mbs":     8.5,
      "single_core_mbs":   14.2,
      "multi_core_mbs":    95.0,
      "cores_used":        16
    }
  ]
}
```

- `reference_mbs` — system tool baseline (bzip2+osmconvert, gzip+osmconvert, etc.)
- `single_core_mbs` — Rust impl, 1 thread (shows pure-Rust advantage over reference)
- `multi_core_mbs` — Rust impl, all cores (shows parallel advantage on top)

## Release
Follow release gate in WORKSPACE.md §Release gate protocol.
Publish: `cargo publish -p osm-katana`
