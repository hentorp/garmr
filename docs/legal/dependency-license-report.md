<!--
SPDX-FileCopyrightText: 2026 Vetra Automation AB
SPDX-License-Identifier: CC-BY-4.0
-->

# Dependency license & advisory report

Generated from `cargo metadata --locked --all-features` (770 packages, 739 of them third-party) and
`cargo deny` / `cargo audit`. See [`../../THIRD_PARTY_LICENSES.md`](../../THIRD_PARTY_LICENSES.md)
for the per-crate list and [`../../supply-chain/sbom.cdx.json`](../../supply-chain/sbom.cdx.json)
for the CycloneDX SBOM.

## License posture

Garmr's own crates are **AGPL-3.0-only**. Every third-party dependency declares a
license with a permissive or AGPL-compatible option; **no dependency has an
unknown/undeclared license**. `cargo deny check` reports **licenses: ok, bans: ok,
sources: ok** (all sources are crates.io or the in-tree vendored path deps).

### License histogram (dependencies, all features)

```
    311 MIT OR Apache-2.0
    155 MIT
     75 Apache-2.0
     54 Apache-2.0 OR MIT
     34 MIT/Apache-2.0
     18 Unicode-3.0
      7 BSD-3-Clause
      7 Unlicense/MIT
      7 Zlib OR Apache-2.0 OR MIT
      6 Apache-2.0/MIT
      6 Unlicense OR MIT
      5 Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT
      4 ISC
      4 MPL-2.0+
      4 Zlib
      3 Apache-2.0 OR ISC OR MIT
      3 BSD-2-Clause
      2 0BSD OR MIT OR Apache-2.0
      2 Apache-2.0 OR MIT OR Zlib
      2 BSD-2-Clause OR Apache-2.0 OR MIT
      2 MIT OR Apache-2.0 OR LGPL-2.1-or-later
      2 MIT OR Apache-2.0 OR Zlib
      2 MIT OR Zlib OR Apache-2.0
      1 (MIT OR Apache-2.0) AND Apache-2.0
      1 (MIT OR Apache-2.0) AND Unicode-3.0
      1 0BSD
      1 Apache-2.0 / MIT
      1 Apache-2.0 / MIT / MPL-2.0
      1 Apache-2.0 AND ISC
      1 Apache-2.0 AND MIT
      1 Apache-2.0 OR BSL-1.0
      1 Apache-2.0 OR GPL-2.0-only
      1 Apache-2.0 OR MIT OR Unlicense
      1 Apache-2.0 WITH LLVM-exception
      1 BSD-3-Clause AND MIT
      1 BSD-3-Clause/MIT
      1 CC0-1.0
      1 CC0-1.0 OR Apache-2.0 OR Apache-2.0 WITH LLVM-exception
      1 CC0-1.0 OR MIT-0 OR Apache-2.0
      1 CDLA-Permissive-2.0
      1 LGPL-3.0 OR MPL-2.0
      1 MIT AND BSD-3-Clause
      1 MIT OR Apache-2.0 OR BSD-1-Clause
      1 MIT/BSD-3-Clause
      1 MPL-2.0
      1 bzip2-1.0.6
      1 zlib-acknowledgement OR MIT
```

A few dependencies offer copyleft options alongside permissive ones
(`LGPL-3.0 OR MPL-2.0`, `Apache-2.0 OR GPL-2.0-only`, `MIT OR Apache-2.0 OR
LGPL-2.1-or-later`); the permissive/AGPL-compatible option is selected, and
file-level copyleft (`MPL-2.0`) is acceptable in an AGPL combined work.

## RustSec advisories — reviewed

`cargo audit` / `cargo deny check advisories` findings, **plus one GitHub-only
advisory those tools cannot see**, reviewed for the alpha. These are documented
follow-ups, not silently ignored; each carries a reachability argument and a
named clearing condition in [`../../deny.toml`](../../deny.toml). Resolving the
fixable ones is a pre-1.0 task.

> RustSec is narrower than GitHub's advisory database. A green `cargo deny check`
> is **not** proof that no advisory applies — triage Dependabot alerts alongside
> it. See [`../supply-chain.md`](../supply-chain.md).

| ID | Crate | Severity in Garmr's usage | Path | Remediation |
|---|---|---|---|---|
| RUSTSEC-2026-0041 | lz4_flex 0.10.0 | **Low** — reached only via `cozo → swapvec` external-sort spill; Garmr compresses/decompresses its **own** in-process graph-query intermediates, not attacker-supplied compressed blocks | garmr-graph → cozo 0.7.6 → swapvec 0.3.0 | Transitive & upstream-pinned. Upgrade `cozo`/`swapvec` upstream, or gate the graph feature. Track upstream. |
| RUSTSEC-2025-0132 | maxminddb 0.24.0 | **Not reachable** — verified: garmr's only call site is `Reader::open_readfile` (`crates/garmr-enrich/src/lib.rs`), which reads the GeoIP database into memory. The unsound `open_mmap` is never invoked | direct dep (garmr-enrich) | Bump to `maxminddb >= 0.27` and adapt the enrich API. Tracked as a pre-1.0 follow-up rather than an alpha blocker: the standalone Dependabot bump currently fails CI, and the advisory is unreachable in this tree |
| RUSTSEC-2026-0194 | quick-xml 0.39.4 | **Low** — quadratic parse on crafted XML; reached transitively, not on a primary ingest path | transitive | Upgrade the dependent crate to pull quick-xml ≥ 0.41. Track upstream. |
| RUSTSEC-2026-0195 | quick-xml 0.39.4 | **Low** — namespace-declaration memory DoS on crafted XML | transitive | As above. |
| CVE-2026-43868 | thrift 0.17.0 | **Low** — excessive memory allocation from a crafted size value. `parquet` 58 uses thrift to decode Parquet **file metadata**; garmr only reads Parquet it wrote into its own warehouse, or archives an operator placed on the configured cold tier — never attacker-supplied files. Ingested events (JSON/NDJSON/Arrow) never touch thrift | transitive: parquet 58.3 → datafusion 54 → vendored iceberg stack | Fixed in thrift ≥ 0.23, but `parquet` 58.3 pins `^0.17`. **Not visible to `cargo audit` or `cargo deny`** — this advisory exists only in GitHub's database, so Dependabot is what surfaces it |

### Unmaintained-crate warnings (informational)

`adler 1.0.2` (RUSTSEC-2025-0056), `bincode 1.3.3` (RUSTSEC-2025-0141),
`fxhash 0.2.1` (RUSTSEC-2025-0057), `paste 1.0.15` (RUSTSEC-2024-0436) — all
transitive, all "unmaintained" (not vulnerabilities). Accepted for alpha; revisit
as upstreams migrate (e.g. `adler2`).

## Reproduce

```bash
cargo deny check
cargo audit
bash scripts/sbom.sh supply-chain/sbom.cdx.json
```
