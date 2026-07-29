<!--
SPDX-FileCopyrightText: 2026 Vetra Automation AB
SPDX-License-Identifier: CC-BY-4.0
-->

# Third-party licenses

Garmr is distributed as a combined work under **AGPL-3.0-only**, but it includes
third-party components that remain under **their own licenses**. The Vetra
Automation AB copyright does not extend to them. This inventory is generated from
`cargo metadata` over the locked, all-features dependency graph, plus the vendored
components under `vendor/`. A machine-readable SBOM is at
[`supply-chain/sbom.cdx.json`](supply-chain/sbom.cdx.json) (CycloneDX 1.5).

See also [`docs/legal/dependency-license-report.md`](docs/legal/dependency-license-report.md)
for the license summary and the reviewed RustSec advisory status.

## Vendored components (under `vendor/`)

| Component | License | Upstream | Notes |
|---|---|---|---|
| `skade` | Apache-2.0 | codeberg.org/nordisk/skade | Lakehouse (Iceberg/Arrow/DataFusion re-export). Keeps `LICENSE-APACHE`. |
| `znippy` (`znippy-common`) | MIT | codeberg.org/nordisk/znippy | Cold-storage codec (feature-gated). |
| `znippy-zoomies` | MIT | codeberg.org/nordisk | Parallel fork-join utilities (used by ingest replay). Includes a module derived from "static-search-tree" © 2025 Ragnar Groot Koerkamp; see its `LICENSE`. |

All vendored components' own `LICENSE`/`COPYING` files are preserved in place and
must not be removed.

## Cargo dependency licenses (transitive, all features)

Every dependency below declares a license with a permissive or AGPL-compatible
option (no dependency has an unknown/undeclared license). Generated from the locked
graph:

| Crate | Version | License |
|---|---|---|
| addr2line | 0.25.1 | Apache-2.0 OR MIT |
| adler | 1.0.2 | 0BSD OR MIT OR Apache-2.0 |
| adler2 | 2.0.1 | 0BSD OR MIT OR Apache-2.0 |
| ahash | 0.7.8 | MIT OR Apache-2.0 |
| ahash | 0.8.12 | MIT OR Apache-2.0 |
| aho-corasick | 1.1.4 | Unlicense OR MIT |
| allocator-api2 | 0.2.21 | MIT OR Apache-2.0 |
| alloc-no-stdlib | 2.0.4 | BSD-3-Clause |
| alloc-stdlib | 0.2.4 | BSD-3-Clause |
| android_system_properties | 0.1.5 | MIT/Apache-2.0 |
| anstream | 1.0.0 | MIT OR Apache-2.0 |
| anstyle | 1.0.14 | MIT OR Apache-2.0 |
| anstyle-parse | 1.0.0 | MIT OR Apache-2.0 |
| anstyle-query | 1.1.5 | MIT OR Apache-2.0 |
| anstyle-wincon | 3.0.11 | MIT OR Apache-2.0 |
| anyhow | 1.0.103 | MIT OR Apache-2.0 |
| apache-avro | 0.21.0 | Apache-2.0 |
| approx | 0.5.1 | Apache-2.0 |
| ar_archive_writer | 0.5.2 | Apache-2.0 WITH LLVM-exception |
| arc-swap | 1.9.2 | MIT OR Apache-2.0 |
| array-init | 2.1.0 | MIT OR Apache-2.0 |
| arrayref | 0.3.9 | BSD-2-Clause |
| arrayvec | 0.7.8 | MIT OR Apache-2.0 |
| arrow | 58.3.0 | Apache-2.0 |
| arrow-arith | 58.3.0 | Apache-2.0 |
| arrow-array | 58.3.0 | Apache-2.0 AND MIT |
| arrow-buffer | 58.3.0 | Apache-2.0 |
| arrow-cast | 58.3.0 | Apache-2.0 |
| arrow-csv | 58.3.0 | Apache-2.0 |
| arrow-data | 58.3.0 | Apache-2.0 |
| arrow-flight | 58.3.0 | Apache-2.0 |
| arrow-ipc | 58.3.0 | Apache-2.0 |
| arrow-json | 58.3.0 | Apache-2.0 |
| arrow-ord | 58.3.0 | Apache-2.0 |
| arrow-row | 58.3.0 | Apache-2.0 |
| arrow-schema | 58.3.0 | Apache-2.0 |
| arrow-select | 58.3.0 | Apache-2.0 |
| arrow-string | 58.3.0 | Apache-2.0 |
| as-any | 0.3.2 | MIT OR Apache-2.0 |
| async-compression | 0.4.42 | MIT OR Apache-2.0 |
| async-lock | 3.4.2 | Apache-2.0 OR MIT |
| async-trait | 0.1.89 | MIT OR Apache-2.0 |
| atoi | 2.0.0 | MIT |
| atoi | 3.1.0 | MIT |
| atomic | 0.6.1 | Apache-2.0/MIT |
| atomic_float | 1.1.0 | Apache-2.0 OR MIT OR Unlicense |
| atomic-waker | 1.1.2 | Apache-2.0 OR MIT |
| autocfg | 1.5.1 | Apache-2.0 OR MIT |
| axum | 0.7.9 | MIT |
| axum | 0.8.9 | MIT |
| axum-core | 0.4.5 | MIT |
| axum-core | 0.5.6 | MIT |
| backon | 1.6.0 | Apache-2.0 |
| backtrace | 0.3.76 | MIT OR Apache-2.0 |
| backtrace-ext | 0.2.1 | MIT OR Apache-2.0 |
| base16ct | 0.2.0 | Apache-2.0 OR MIT |
| base64 | 0.13.1 | MIT/Apache-2.0 |
| base64 | 0.21.7 | MIT OR Apache-2.0 |
| base64 | 0.22.1 | MIT OR Apache-2.0 |
| base64ct | 1.8.3 | Apache-2.0 OR MIT |
| bigdecimal | 0.4.10 | MIT/Apache-2.0 |
| bimap | 0.6.3 | Apache-2.0/MIT |
| bincode | 1.3.3 | MIT |
| bitflags | 2.13.0 | MIT OR Apache-2.0 |
| bitmaps | 3.2.1 | MPL-2.0+ |
| bitpacking | 0.9.3 | MIT |
| bit-set | 0.8.0 | Apache-2.0 OR MIT |
| bit-vec | 0.8.0 | Apache-2.0 OR MIT |
| blake2 | 0.10.6 | MIT OR Apache-2.0 |
| blake3 | 1.8.5 | CC0-1.0 OR Apache-2.0 OR Apache-2.0 WITH LLVM-exception |
| block-buffer | 0.10.4 | MIT OR Apache-2.0 |
| block-buffer | 0.12.1 | MIT OR Apache-2.0 |
| bnum | 0.12.1 | MIT OR Apache-2.0 |
| bon | 3.9.3 | MIT OR Apache-2.0 |
| bon-macros | 3.9.3 | MIT OR Apache-2.0 |
| brotli | 8.0.4 | BSD-3-Clause AND MIT |
| brotli-decompressor | 5.0.3 | BSD-3-Clause/MIT |
| bs58 | 0.5.1 | MIT/Apache-2.0 |
| bstr | 1.12.3 | MIT OR Apache-2.0 |
| bumpalo | 3.20.3 | MIT OR Apache-2.0 |
| bytemuck | 1.25.0 | Zlib OR Apache-2.0 OR MIT |
| bytemuck_derive | 1.11.0 | Zlib OR Apache-2.0 OR MIT |
| byteorder | 1.5.0 | Unlicense OR MIT |
| bytes | 1.12.0 | MIT |
| byte-slice-cast | 1.2.3 | MIT |
| bzip2 | 0.6.1 | MIT OR Apache-2.0 |
| candle-core | 0.9.2 | MIT OR Apache-2.0 |
| candle-nn | 0.9.2 | MIT OR Apache-2.0 |
| candle-transformers | 0.9.2 | MIT OR Apache-2.0 |
| casey | 0.4.2 | MIT |
| cc | 1.2.66 | MIT OR Apache-2.0 |
| cedarwood | 0.4.6 | BSD-2-Clause |
| census | 0.4.2 | MIT |
| cfg_aliases | 0.2.1 | MIT |
| cfg-if | 1.0.4 | MIT OR Apache-2.0 |
| chacha20 | 0.10.1 | MIT OR Apache-2.0 |
| chrono | 0.4.45 | MIT OR Apache-2.0 |
| chrono-tz | 0.10.4 | MIT OR Apache-2.0 |
| chrono-tz | 0.8.6 | MIT OR Apache-2.0 |
| chrono-tz-build | 0.2.1 | MIT OR Apache-2.0 |
| ciborium | 0.2.2 | Apache-2.0 |
| ciborium-io | 0.2.2 | Apache-2.0 |
| ciborium-ll | 0.2.2 | Apache-2.0 |
| clap | 4.6.1 | MIT OR Apache-2.0 |
| clap_builder | 4.6.0 | MIT OR Apache-2.0 |
| clap_derive | 4.6.1 | MIT OR Apache-2.0 |
| clap_lex | 1.1.0 | MIT OR Apache-2.0 |
| cmake | 0.1.58 | MIT OR Apache-2.0 |
| colorchoice | 1.0.5 | MIT OR Apache-2.0 |
| comfy-table | 7.2.2 | MIT |
| compression-codecs | 0.4.38 | MIT OR Apache-2.0 |
| compression-core | 0.4.32 | MIT OR Apache-2.0 |
| concurrent-queue | 2.5.0 | Apache-2.0 OR MIT |
| constant_time_eq | 0.4.2 | CC0-1.0 OR MIT-0 OR Apache-2.0 |
| const-oid | 0.10.2 | Apache-2.0 OR MIT |
| const-oid | 0.9.6 | Apache-2.0 OR MIT |
| const-random | 0.1.18 | MIT OR Apache-2.0 |
| const-random-macro | 0.1.16 | MIT OR Apache-2.0 |
| core-foundation | 0.10.1 | MIT OR Apache-2.0 |
| core-foundation-sys | 0.8.7 | MIT OR Apache-2.0 |
| cozo | 0.7.6 | MPL-2.0 |
| cpufeatures | 0.2.17 | MIT OR Apache-2.0 |
| cpufeatures | 0.3.0 | MIT OR Apache-2.0 |
| crc32fast | 1.5.0 | MIT OR Apache-2.0 |
| crossbeam | 0.8.4 | MIT OR Apache-2.0 |
| crossbeam-channel | 0.5.16 | MIT OR Apache-2.0 |
| crossbeam-deque | 0.8.7 | MIT OR Apache-2.0 |
| crossbeam-epoch | 0.9.20 | MIT OR Apache-2.0 |
| crossbeam-queue | 0.3.13 | MIT OR Apache-2.0 |
| crossbeam-utils | 0.8.22 | MIT OR Apache-2.0 |
| crunchy | 0.2.4 | MIT |
| crypto-bigint | 0.5.5 | Apache-2.0 OR MIT |
| crypto-common | 0.1.7 | MIT OR Apache-2.0 |
| crypto-common | 0.2.2 | MIT OR Apache-2.0 |
| csv | 1.4.0 | Unlicense/MIT |
| csv-core | 0.1.13 | Unlicense/MIT |
| curve25519-dalek | 4.1.3 | BSD-3-Clause |
| curve25519-dalek-derive | 0.1.1 | MIT/Apache-2.0 |
| darling | 0.20.11 | MIT |
| darling | 0.23.0 | MIT |
| darling_core | 0.20.11 | MIT |
| darling_core | 0.23.0 | MIT |
| darling_macro | 0.20.11 | MIT |
| darling_macro | 0.23.0 | MIT |
| dashmap | 6.2.1 | MIT |
| datafusion | 54.0.0 | Apache-2.0 |
| datafusion-catalog | 54.0.0 | Apache-2.0 |
| datafusion-catalog-listing | 54.0.0 | Apache-2.0 |
| datafusion-common | 54.0.0 | Apache-2.0 |
| datafusion-common-runtime | 54.0.0 | Apache-2.0 |
| datafusion-datasource | 54.0.0 | Apache-2.0 |
| datafusion-datasource-arrow | 54.0.0 | Apache-2.0 |
| datafusion-datasource-csv | 54.0.0 | Apache-2.0 |
| datafusion-datasource-json | 54.0.0 | Apache-2.0 |
| datafusion-datasource-parquet | 54.0.0 | Apache-2.0 |
| datafusion-doc | 54.0.0 | Apache-2.0 |
| datafusion-execution | 54.0.0 | Apache-2.0 |
| datafusion-expr | 54.0.0 | Apache-2.0 |
| datafusion-expr-common | 54.0.0 | Apache-2.0 |
| datafusion-functions | 54.0.0 | Apache-2.0 |
| datafusion-functions-aggregate | 54.0.0 | Apache-2.0 |
| datafusion-functions-aggregate-common | 54.0.0 | Apache-2.0 |
| datafusion-functions-nested | 54.0.0 | Apache-2.0 |
| datafusion-functions-table | 54.0.0 | Apache-2.0 |
| datafusion-functions-window | 54.0.0 | Apache-2.0 |
| datafusion-functions-window-common | 54.0.0 | Apache-2.0 |
| datafusion-macros | 54.0.0 | Apache-2.0 |
| datafusion-optimizer | 54.0.0 | Apache-2.0 |
| datafusion-physical-expr | 54.0.0 | Apache-2.0 |
| datafusion-physical-expr-adapter | 54.0.0 | Apache-2.0 |
| datafusion-physical-expr-common | 54.0.0 | Apache-2.0 |
| datafusion-physical-optimizer | 54.0.0 | Apache-2.0 |
| datafusion-physical-plan | 54.0.0 | Apache-2.0 |
| datafusion-pruning | 54.0.0 | Apache-2.0 |
| datafusion-session | 54.0.0 | Apache-2.0 |
| datafusion-sql | 54.0.0 | Apache-2.0 |
| datasketches | 0.2.0 | Apache-2.0 |
| delegate | 0.13.5 | MIT OR Apache-2.0 |
| der | 0.7.10 | Apache-2.0 OR MIT |
| deranged | 0.5.8 | MIT OR Apache-2.0 |
| derive_builder | 0.20.2 | MIT OR Apache-2.0 |
| derive_builder_core | 0.20.2 | MIT OR Apache-2.0 |
| derive_builder_macro | 0.20.2 | MIT OR Apache-2.0 |
| digest | 0.10.7 | MIT OR Apache-2.0 |
| digest | 0.11.3 | MIT OR Apache-2.0 |
| dispatch2 | 0.3.1 | Zlib OR Apache-2.0 OR MIT |
| displaydoc | 0.2.6 | MIT OR Apache-2.0 |
| dissimilar | 1.0.11 | Apache-2.0 |
| document-features | 0.2.12 | MIT OR Apache-2.0 |
| downcast-rs | 2.0.2 | MIT OR Apache-2.0 |
| dyn-clone | 1.0.20 | MIT OR Apache-2.0 |
| dyn-stack | 0.13.2 | MIT |
| dyn-stack-macros | 0.1.3 | MIT |
| ecdsa | 0.16.9 | Apache-2.0 OR MIT |
| ed25519 | 2.2.3 | Apache-2.0 OR MIT |
| ed25519-dalek | 2.2.0 | BSD-3-Clause |
| either | 1.16.0 | MIT OR Apache-2.0 |
| elliptic-curve | 0.13.8 | Apache-2.0 OR MIT |
| email_address | 0.2.9 | MIT |
| email-encoding | 0.4.1 | MIT OR Apache-2.0 |
| enum-as-inner | 0.6.1 | MIT/Apache-2.0 |
| env_logger | 0.10.2 | MIT OR Apache-2.0 |
| equivalent | 1.0.2 | Apache-2.0 OR MIT |
| erased-serde | 0.4.10 | MIT OR Apache-2.0 |
| errno | 0.3.14 | MIT OR Apache-2.0 |
| esaxx-rs | 0.1.10 | Apache-2.0 |
| event-listener | 5.4.1 | Apache-2.0 OR MIT |
| event-listener-strategy | 0.5.4 | Apache-2.0 OR MIT |
| expect-test | 1.5.1 | MIT OR Apache-2.0 |
| fancy-regex | 0.17.0 | MIT |
| fast2s | 0.3.1 | MIT |
| fastdivide | 0.4.2 | zlib-acknowledgement OR MIT |
| fast-float2 | 0.2.3 | MIT OR Apache-2.0 |
| fastnum | 0.7.5 | MIT OR Apache-2.0 |
| fastrand | 2.4.1 | Apache-2.0 OR MIT |
| ff | 0.13.1 | MIT/Apache-2.0 |
| fiat-crypto | 0.2.9 | MIT OR Apache-2.0 OR BSD-1-Clause |
| figment | 0.10.19 | MIT OR Apache-2.0 |
| find-msvc-tools | 0.1.9 | MIT OR Apache-2.0 |
| fixedbitset | 0.5.7 | MIT OR Apache-2.0 |
| flatbuffers | 25.12.19 | Apache-2.0 |
| flate2 | 1.1.9 | MIT OR Apache-2.0 |
| float8 | 0.6.1 | MIT |
| fnv | 1.0.7 | Apache-2.0 / MIT |
| foldhash | 0.1.5 | Zlib |
| foldhash | 0.2.0 | Zlib |
| form_urlencoded | 1.2.2 | MIT OR Apache-2.0 |
| fs4 | 0.13.1 | MIT OR Apache-2.0 |
| fst | 0.4.7 | Unlicense/MIT |
| futures | 0.3.32 | MIT OR Apache-2.0 |
| futures-channel | 0.3.32 | MIT OR Apache-2.0 |
| futures-core | 0.3.32 | MIT OR Apache-2.0 |
| futures-executor | 0.3.32 | MIT OR Apache-2.0 |
| futures-io | 0.3.32 | MIT OR Apache-2.0 |
| futures-macro | 0.3.32 | MIT OR Apache-2.0 |
| futures-sink | 0.3.32 | MIT OR Apache-2.0 |
| futures-task | 0.3.32 | MIT OR Apache-2.0 |
| futures-util | 0.3.32 | MIT OR Apache-2.0 |
| fxhash | 0.2.1 | Apache-2.0/MIT |
| gemm | 0.19.0 | MIT |
| gemm-c32 | 0.19.0 | MIT |
| gemm-c64 | 0.19.0 | MIT |
| gemm-common | 0.19.0 | MIT |
| gemm-f16 | 0.19.0 | MIT |
| gemm-f32 | 0.19.0 | MIT |
| gemm-f64 | 0.19.0 | MIT |
| generic-array | 0.14.7 | MIT |
| getrandom | 0.2.17 | MIT OR Apache-2.0 |
| getrandom | 0.3.4 | MIT OR Apache-2.0 |
| getrandom | 0.4.3 | MIT OR Apache-2.0 |
| gimli | 0.32.3 | MIT OR Apache-2.0 |
| glob | 0.3.3 | MIT OR Apache-2.0 |
| globset | 0.4.18 | Unlicense OR MIT |
| gloo-timers | 0.3.0 | MIT OR Apache-2.0 |
| graph | 0.3.2 | MIT |
| graph_builder | 0.4.2 | MIT |
| group | 0.13.0 | MIT/Apache-2.0 |
| h2 | 0.4.15 | MIT |
| half | 2.7.1 | MIT OR Apache-2.0 |
| hashbrown | 0.12.3 | MIT OR Apache-2.0 |
| hashbrown | 0.14.5 | MIT OR Apache-2.0 |
| hashbrown | 0.15.5 | MIT OR Apache-2.0 |
| hashbrown | 0.16.1 | MIT OR Apache-2.0 |
| hashbrown | 0.17.1 | MIT OR Apache-2.0 |
| heck | 0.5.0 | MIT OR Apache-2.0 |
| hermit-abi | 0.5.2 | MIT OR Apache-2.0 |
| hex | 0.4.3 | MIT OR Apache-2.0 |
| hmac | 0.12.1 | MIT OR Apache-2.0 |
| hostname | 0.4.2 | MIT |
| htmlescape | 0.3.1 | Apache-2.0 / MIT / MPL-2.0 |
| http | 1.4.2 | MIT OR Apache-2.0 |
| httparse | 1.10.1 | MIT OR Apache-2.0 |
| http-body | 1.0.1 | MIT |
| http-body-util | 0.1.3 | MIT |
| httpdate | 1.0.3 | MIT OR Apache-2.0 |
| http-range-header | 0.4.2 | MIT |
| humantime | 2.4.0 | MIT OR Apache-2.0 |
| hybrid-array | 0.4.13 | MIT OR Apache-2.0 |
| hyper | 1.10.1 | MIT |
| hyper-rustls | 0.27.9 | Apache-2.0 OR ISC OR MIT |
| hyper-timeout | 0.5.2 | MIT OR Apache-2.0 |
| hyper-util | 0.1.20 | MIT |
| iana-time-zone | 0.1.65 | MIT OR Apache-2.0 |
| iana-time-zone-haiku | 0.1.2 | MIT OR Apache-2.0 |
| icu_collections | 2.2.0 | Unicode-3.0 |
| icu_locale_core | 2.2.0 | Unicode-3.0 |
| icu_normalizer | 2.2.0 | Unicode-3.0 |
| icu_normalizer_data | 2.2.0 | Unicode-3.0 |
| icu_properties | 2.2.0 | Unicode-3.0 |
| icu_properties_data | 2.2.0 | Unicode-3.0 |
| icu_provider | 2.2.0 | Unicode-3.0 |
| ident_case | 1.0.1 | MIT/Apache-2.0 |
| idna | 1.1.0 | MIT OR Apache-2.0 |
| idna_adapter | 1.2.2 | Apache-2.0 OR MIT |
| imbl | 3.0.0 | MPL-2.0+ |
| imbl-sized-chunks | 0.1.3 | MPL-2.0+ |
| indexmap | 1.9.3 | Apache-2.0 OR MIT |
| indexmap | 2.14.0 | Apache-2.0 OR MIT |
| inlinable_string | 0.1.15 | Apache-2.0/MIT |
| integer-encoding | 3.0.4 | MIT |
| inventory | 0.3.24 | MIT OR Apache-2.0 |
| ipnet | 2.12.0 | MIT OR Apache-2.0 |
| ipnetwork | 0.20.0 | MIT OR Apache-2.0 |
| is_ci | 1.2.0 | ISC |
| is-terminal | 0.4.17 | MIT |
| is_terminal_polyfill | 1.70.2 | MIT OR Apache-2.0 |
| itertools | 0.11.0 | MIT OR Apache-2.0 |
| itertools | 0.12.1 | MIT OR Apache-2.0 |
| itertools | 0.13.0 | MIT OR Apache-2.0 |
| itertools | 0.14.0 | MIT OR Apache-2.0 |
| itoa | 1.0.18 | MIT OR Apache-2.0 |
| jieba-rs | 0.6.8 | MIT |
| jobserver | 0.1.35 | MIT OR Apache-2.0 |
| js-sys | 0.3.103 | MIT OR Apache-2.0 |
| lazy_static | 1.5.0 | MIT OR Apache-2.0 |
| lettre | 0.11.22 | MIT |
| levenshtein_automata | 0.2.1 | MIT |
| lexical-core | 1.0.6 | MIT/Apache-2.0 |
| lexical-parse-float | 1.0.6 | MIT/Apache-2.0 |
| lexical-parse-integer | 1.0.6 | MIT/Apache-2.0 |
| lexical-util | 1.0.7 | MIT/Apache-2.0 |
| lexical-write-float | 1.0.6 | MIT/Apache-2.0 |
| lexical-write-integer | 1.0.6 | MIT/Apache-2.0 |
| libbz2-rs-sys | 0.2.5 | bzip2-1.0.6 |
| libc | 0.2.186 | MIT OR Apache-2.0 |
| liblzma | 0.4.7 | MIT OR Apache-2.0 |
| liblzma-sys | 0.4.7 | MIT OR Apache-2.0 |
| libm | 0.2.16 | MIT |
| libyaml-rs | 0.3.0 | MIT |
| line-index | 0.1.2 | MIT OR Apache-2.0 |
| linereader | 0.4.0 | MIT |
| linux-raw-sys | 0.12.1 | Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT |
| litemap | 0.8.2 | Unicode-3.0 |
| litrs | 1.0.0 | MIT OR Apache-2.0 |
| lock_api | 0.4.14 | MIT OR Apache-2.0 |
| log | 0.4.33 | MIT OR Apache-2.0 |
| lru | 0.16.4 | MIT |
| lru-slab | 0.1.2 | MIT OR Apache-2.0 OR Zlib |
| lz4_flex | 0.10.0 | MIT |
| lz4_flex | 0.13.1 | MIT |
| macro_rules_attribute | 0.2.2 | Apache-2.0 OR MIT OR Zlib |
| macro_rules_attribute-proc_macro | 0.2.2 | Apache-2.0 OR MIT OR Zlib |
| matchers | 0.2.0 | MIT |
| matchit | 0.7.3 | MIT AND BSD-3-Clause |
| matchit | 0.8.4 | MIT AND BSD-3-Clause |
| matrixmultiply | 0.3.11 | MIT/Apache-2.0 |
| maxminddb | 0.24.0 | ISC |
| md-5 | 0.10.6 | MIT OR Apache-2.0 |
| md-5 | 0.11.0 | MIT OR Apache-2.0 |
| measure_time | 0.9.0 | MIT |
| memchr | 2.8.2 | Unlicense OR MIT |
| memmap2 | 0.9.11 | MIT OR Apache-2.0 |
| miette | 5.10.0 | Apache-2.0 |
| miette-derive | 5.10.0 | Apache-2.0 |
| mime | 0.3.17 | MIT OR Apache-2.0 |
| mime_guess | 2.0.5 | MIT |
| minimal-lexical | 0.2.1 | MIT/Apache-2.0 |
| miniz_oxide | 0.7.4 | MIT OR Zlib OR Apache-2.0 |
| miniz_oxide | 0.8.9 | MIT OR Zlib OR Apache-2.0 |
| mio | 1.2.1 | MIT |
| moka | 0.12.15 | (MIT OR Apache-2.0) AND Apache-2.0 |
| monostate | 0.1.18 | MIT OR Apache-2.0 |
| monostate-impl | 0.1.18 | MIT OR Apache-2.0 |
| murmur3 | 0.5.2 | MIT/Apache-2.0 |
| murmurhash32 | 0.3.1 | MIT |
| nanorand | 0.8.0 | Zlib |
| ndarray | 0.15.6 | MIT OR Apache-2.0 |
| nix | 0.31.3 | MIT |
| nohash-hasher | 0.2.0 | Apache-2.0 OR MIT |
| nom | 7.1.3 | MIT |
| nom | 8.0.0 | MIT |
| ntapi | 0.4.3 | Apache-2.0 OR MIT |
| nu-ansi-term | 0.50.3 | MIT |
| num | 0.4.3 | MIT OR Apache-2.0 |
| num-bigint | 0.4.8 | MIT OR Apache-2.0 |
| num-complex | 0.4.6 | MIT OR Apache-2.0 |
| num-conv | 0.2.2 | MIT OR Apache-2.0 |
| num_cpus | 1.17.0 | MIT OR Apache-2.0 |
| num-format | 0.4.4 | MIT/Apache-2.0 |
| num-integer | 0.1.46 | MIT OR Apache-2.0 |
| num-iter | 0.1.46 | MIT OR Apache-2.0 |
| num-rational | 0.4.2 | MIT OR Apache-2.0 |
| num-traits | 0.2.19 | MIT OR Apache-2.0 |
| objc2 | 0.6.4 | MIT |
| objc2-core-foundation | 0.3.2 | Zlib OR Apache-2.0 OR MIT |
| objc2-encode | 4.1.0 | MIT |
| objc2-foundation | 0.3.2 | MIT |
| objc2-io-kit | 0.3.2 | Zlib OR Apache-2.0 OR MIT |
| objc2-open-directory | 0.3.2 | Zlib OR Apache-2.0 OR MIT |
| object | 0.37.3 | Apache-2.0 OR MIT |
| object_store | 0.13.2 | MIT/Apache-2.0 |
| once_cell | 1.21.4 | MIT OR Apache-2.0 |
| once_cell_polyfill | 1.70.2 | MIT OR Apache-2.0 |
| oneshot | 0.1.13 | MIT OR Apache-2.0 |
| onig | 6.5.3 | MIT |
| onig_sys | 69.9.3 | MIT |
| openssl-probe | 0.2.1 | MIT OR Apache-2.0 |
| openzl-sys-rs | 0.2.0 | BSD-3-Clause |
| ordered-float | 2.10.1 | MIT |
| ordered-float | 4.6.0 | MIT |
| ordered-float | 5.3.0 | MIT |
| ownedbytes | 0.9.0 | MIT |
| owo-colors | 3.5.0 | MIT |
| p256 | 0.13.2 | Apache-2.0 OR MIT |
| page_size | 0.6.0 | MIT/Apache-2.0 |
| parking | 2.2.1 | Apache-2.0 OR MIT |
| parking_lot | 0.12.5 | MIT OR Apache-2.0 |
| parking_lot_core | 0.9.12 | MIT OR Apache-2.0 |
| parquet | 58.3.0 | Apache-2.0 |
| parse-zoneinfo | 0.3.1 | MIT |
| paste | 1.0.15 | MIT OR Apache-2.0 |
| pastey | 0.2.3 | MIT OR Apache-2.0 |
| pear | 0.2.9 | MIT OR Apache-2.0 |
| pear_codegen | 0.2.9 | MIT OR Apache-2.0 |
| pem-rfc7468 | 0.7.0 | Apache-2.0 OR MIT |
| percent-encoding | 2.3.2 | MIT OR Apache-2.0 |
| pest | 2.8.7 | MIT OR Apache-2.0 |
| pest_derive | 2.8.7 | MIT OR Apache-2.0 |
| pest_generator | 2.8.7 | MIT OR Apache-2.0 |
| pest_meta | 2.8.7 | MIT OR Apache-2.0 |
| petgraph | 0.8.3 | MIT OR Apache-2.0 |
| phf | 0.11.3 | MIT |
| phf | 0.12.1 | MIT |
| phf_codegen | 0.11.3 | MIT |
| phf_generator | 0.11.3 | MIT |
| phf_shared | 0.11.3 | MIT |
| phf_shared | 0.12.1 | MIT |
| pin-project | 1.1.13 | Apache-2.0 OR MIT |
| pin-project-internal | 1.1.13 | Apache-2.0 OR MIT |
| pin-project-lite | 0.2.17 | Apache-2.0 OR MIT |
| pkcs8 | 0.10.2 | Apache-2.0 OR MIT |
| pkg-config | 0.3.33 | MIT OR Apache-2.0 |
| portable-atomic | 1.13.1 | Apache-2.0 OR MIT |
| potential_utf | 0.1.5 | Unicode-3.0 |
| powerfmt | 0.2.0 | MIT OR Apache-2.0 |
| ppv-lite86 | 0.2.21 | MIT OR Apache-2.0 |
| prettyplease | 0.2.37 | MIT OR Apache-2.0 |
| primeorder | 0.13.6 | Apache-2.0 OR MIT |
| priority-queue | 1.4.0 | LGPL-3.0 OR MPL-2.0 |
| process-wrap | 9.1.0 | Apache-2.0 OR MIT |
| proc-macro2 | 1.0.106 | MIT OR Apache-2.0 |
| proc-macro2-diagnostics | 0.10.1 | MIT/Apache-2.0 |
| prost | 0.13.5 | Apache-2.0 |
| prost | 0.14.4 | Apache-2.0 |
| prost-derive | 0.13.5 | Apache-2.0 |
| prost-derive | 0.14.4 | Apache-2.0 |
| prost-types | 0.14.4 | Apache-2.0 |
| psm | 0.1.31 | MIT OR Apache-2.0 |
| pulp | 0.22.3 | MIT |
| pulp-wasm-simd-flag | 0.1.1 | MIT |
| quad-rand | 0.2.3 | MIT |
| quadrature | 0.1.2 | BSD-2-Clause |
| quick-xml | 0.39.4 | MIT |
| quinn | 0.11.11 | MIT OR Apache-2.0 |
| quinn-proto | 0.11.16 | MIT OR Apache-2.0 |
| quinn-udp | 0.5.15 | MIT OR Apache-2.0 |
| quote | 1.0.46 | MIT OR Apache-2.0 |
| quoted_printable | 0.5.2 | 0BSD |
| rand | 0.10.2 | MIT OR Apache-2.0 |
| rand | 0.8.7 | MIT OR Apache-2.0 |
| rand | 0.9.4 | MIT OR Apache-2.0 |
| rand_chacha | 0.3.1 | MIT OR Apache-2.0 |
| rand_chacha | 0.9.0 | MIT OR Apache-2.0 |
| rand_core | 0.10.1 | MIT OR Apache-2.0 |
| rand_core | 0.6.4 | MIT OR Apache-2.0 |
| rand_core | 0.9.5 | MIT OR Apache-2.0 |
| rand_distr | 0.5.1 | MIT OR Apache-2.0 |
| rand_pcg | 0.10.2 | MIT OR Apache-2.0 |
| rand_xoshiro | 0.6.0 | MIT OR Apache-2.0 |
| raw-cpuid | 11.6.0 | MIT |
| rawpointer | 0.2.1 | MIT/Apache-2.0 |
| rayon | 1.12.0 | MIT OR Apache-2.0 |
| rayon-cond | 0.3.0 | Apache-2.0/MIT |
| rayon-core | 1.13.0 | MIT OR Apache-2.0 |
| reborrow | 0.5.5 | MIT |
| recursive | 0.1.1 | MIT |
| recursive-proc-macro-impl | 0.1.1 | MIT |
| redb | 2.6.3 | MIT OR Apache-2.0 |
| redox_syscall | 0.5.18 | MIT |
| ref-cast | 1.0.25 | MIT OR Apache-2.0 |
| ref-cast-impl | 1.0.25 | MIT OR Apache-2.0 |
| r-efi | 5.3.0 | MIT OR Apache-2.0 OR LGPL-2.1-or-later |
| r-efi | 6.0.0 | MIT OR Apache-2.0 OR LGPL-2.1-or-later |
| regex | 1.12.4 | MIT OR Apache-2.0 |
| regex-automata | 0.4.14 | MIT OR Apache-2.0 |
| regex-lite | 0.1.9 | MIT OR Apache-2.0 |
| regex-syntax | 0.8.11 | MIT OR Apache-2.0 |
| reqwest | 0.12.28 | MIT OR Apache-2.0 |
| rfc6979 | 0.4.0 | Apache-2.0 OR MIT |
| ring | 0.17.14 | Apache-2.0 AND ISC |
| rmcp | 1.8.0 | Apache-2.0 |
| rmcp-macros | 1.8.0 | Apache-2.0 |
| rmp | 0.8.15 | MIT |
| rmp-serde | 1.3.1 | MIT |
| rmpv | 1.3.1 | MIT |
| roaring | 0.11.4 | MIT OR Apache-2.0 |
| rsigma-eval | 0.18.0 | MIT |
| rsigma-parser | 0.18.0 | MIT |
| rustc-demangle | 0.1.28 | MIT/Apache-2.0 |
| rustc-hash | 1.1.0 | Apache-2.0/MIT |
| rustc-hash | 2.1.3 | Apache-2.0 OR MIT |
| rustc_version | 0.4.1 | MIT OR Apache-2.0 |
| rustix | 1.1.4 | Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT |
| rustls | 0.23.41 | Apache-2.0 OR ISC OR MIT |
| rustls-native-certs | 0.8.4 | Apache-2.0 OR ISC OR MIT |
| rustls-pki-types | 1.15.0 | MIT OR Apache-2.0 |
| rustls-webpki | 0.103.13 | ISC |
| rust-stemmers | 1.2.0 | MIT/BSD-3-Clause |
| rustversion | 1.0.23 | MIT OR Apache-2.0 |
| ryu | 1.0.23 | Apache-2.0 OR BSL-1.0 |
| safetensors | 0.7.0 | Apache-2.0 |
| same-file | 1.0.6 | Unlicense/MIT |
| schannel | 0.1.29 | MIT |
| schemars | 0.9.0 | MIT |
| schemars | 1.2.1 | MIT |
| schemars_derive | 1.2.1 | MIT |
| scopeguard | 1.2.0 | MIT OR Apache-2.0 |
| sec1 | 0.7.3 | Apache-2.0 OR MIT |
| security-framework | 3.7.0 | MIT OR Apache-2.0 |
| security-framework-sys | 2.17.0 | MIT OR Apache-2.0 |
| self_cell | 1.2.2 | Apache-2.0 OR GPL-2.0-only |
| semver | 1.0.28 | MIT OR Apache-2.0 |
| seq-macro | 0.3.6 | MIT OR Apache-2.0 |
| serde | 1.0.228 | MIT OR Apache-2.0 |
| serde-big-array | 0.5.1 | MIT OR Apache-2.0 |
| serde_bytes | 0.11.19 | MIT OR Apache-2.0 |
| serde_core | 1.0.228 | MIT OR Apache-2.0 |
| serde_derive | 1.0.228 | MIT OR Apache-2.0 |
| serde_derive_internals | 0.29.1 | MIT OR Apache-2.0 |
| serde_json | 1.0.150 | MIT OR Apache-2.0 |
| serde_path_to_error | 0.1.20 | MIT OR Apache-2.0 |
| serde_plain | 1.0.2 | MIT/Apache-2.0 |
| serde_repr | 0.1.20 | MIT OR Apache-2.0 |
| serde_spanned | 0.6.9 | MIT OR Apache-2.0 |
| serde_urlencoded | 0.7.1 | MIT/Apache-2.0 |
| serde_with | 3.21.0 | MIT OR Apache-2.0 |
| serde_with_macros | 3.21.0 | MIT OR Apache-2.0 |
| sha2 | 0.10.9 | MIT OR Apache-2.0 |
| sha2 | 0.11.0 | MIT OR Apache-2.0 |
| sharded-slab | 0.1.7 | MIT |
| shlex | 2.0.1 | MIT OR Apache-2.0 |
| signal-hook-registry | 1.4.8 | MIT OR Apache-2.0 |
| signature | 2.2.0 | Apache-2.0 OR MIT |
| simd-adler32 | 0.3.9 | MIT |
| simdutf8 | 0.1.5 | MIT OR Apache-2.0 |
| siphasher | 1.0.3 | MIT/Apache-2.0 |
| sketches-ddsketch | 0.4.0 | Apache-2.0 |
| slab | 0.4.12 | MIT |
| smallvec | 1.15.2 | MIT OR Apache-2.0 |
| smartstring | 1.0.1 | MPL-2.0+ |
| smawk | 0.3.3 | MIT |
| snap | 1.1.1 | BSD-3-Clause |
| socket2 | 0.6.4 | MIT OR Apache-2.0 |
| spki | 0.7.3 | Apache-2.0 OR MIT |
| spm_precompiled | 0.1.4 | Apache-2.0 |
| sqlparser | 0.62.0 | Apache-2.0 |
| sqlparser_derive | 0.5.0 | Apache-2.0 |
| stable_deref_trait | 1.2.1 | MIT OR Apache-2.0 |
| stacker | 0.1.24 | MIT OR Apache-2.0 |
| static_assertions | 1.1.0 | MIT OR Apache-2.0 |
| streaming-iterator | 0.1.9 | MIT OR Apache-2.0 |
| strsim | 0.11.1 | MIT |
| strum | 0.27.2 | MIT |
| strum_macros | 0.27.2 | MIT |
| subfeature | 1.26.1 | MIT |
| subtle | 2.6.1 | BSD-3-Clause |
| supports-color | 2.1.0 | Apache-2.0 |
| supports-hyperlinks | 2.1.0 | Apache-2.0 |
| supports-unicode | 2.1.0 | Apache-2.0 |
| swapvec | 0.3.0 | MIT |
| syn | 2.0.118 | MIT OR Apache-2.0 |
| sync_wrapper | 1.0.2 | Apache-2.0 |
| synstructure | 0.13.2 | MIT |
| sysctl | 0.6.0 | MIT |
| sysinfo | 0.39.5 | MIT |
| syslog_loose | 0.23.0 | MIT |
| tagptr | 0.2.0 | MIT/Apache-2.0 |
| tantivy | 0.26.1 | MIT |
| tantivy-bitpacker | 0.10.0 | MIT |
| tantivy-columnar | 0.7.0 | MIT |
| tantivy-common | 0.11.0 | MIT |
| tantivy-fst | 0.5.0 | Unlicense/MIT |
| tantivy-query-grammar | 0.26.0 | MIT |
| tantivy-sstable | 0.7.0 | MIT |
| tantivy-stacker | 0.7.0 | MIT |
| tantivy-tokenizer-api | 0.7.0 | MIT |
| tempfile | 3.27.0 | MIT OR Apache-2.0 |
| termcolor | 1.4.1 | Unlicense OR MIT |
| terminal_size | 0.1.17 | MIT OR Apache-2.0 |
| text-size | 1.1.1 | MIT OR Apache-2.0 |
| textwrap | 0.15.2 | MIT |
| thiserror | 1.0.69 | MIT OR Apache-2.0 |
| thiserror | 2.0.18 | MIT OR Apache-2.0 |
| thiserror-impl | 1.0.69 | MIT OR Apache-2.0 |
| thiserror-impl | 2.0.18 | MIT OR Apache-2.0 |
| thread_local | 1.1.9 | MIT OR Apache-2.0 |
| thrift | 0.17.0 | Apache-2.0 |
| time | 0.3.53 | MIT OR Apache-2.0 |
| time-core | 0.1.9 | MIT OR Apache-2.0 |
| time-macros | 0.2.31 | MIT OR Apache-2.0 |
| tiny-keccak | 2.0.2 | CC0-1.0 |
| tinystr | 0.8.3 | Unicode-3.0 |
| tinyvec | 1.11.0 | Zlib OR Apache-2.0 OR MIT |
| tinyvec_macros | 0.1.1 | MIT OR Apache-2.0 OR Zlib |
| tokenizers | 0.20.4 | Apache-2.0 |
| tokio | 1.52.3 | MIT |
| tokio-macros | 2.7.0 | MIT |
| tokio-rustls | 0.26.4 | MIT OR Apache-2.0 |
| tokio-stream | 0.1.18 | MIT |
| tokio-util | 0.7.18 | MIT |
| toml | 0.8.23 | MIT OR Apache-2.0 |
| toml_datetime | 0.6.11 | MIT OR Apache-2.0 |
| toml_edit | 0.22.27 | MIT OR Apache-2.0 |
| toml_write | 0.1.2 | MIT OR Apache-2.0 |
| tonic | 0.14.6 | MIT |
| tonic-prost | 0.14.6 | MIT |
| tower | 0.5.3 | MIT |
| tower-http | 0.6.11 | MIT |
| tower-layer | 0.3.3 | MIT |
| tower-service | 0.3.3 | MIT |
| tracing | 0.1.44 | MIT |
| tracing-attributes | 0.1.31 | MIT |
| tracing-core | 0.1.36 | MIT |
| tracing-log | 0.2.0 | MIT |
| tracing-subscriber | 0.3.23 | MIT |
| tree-sitter | 0.26.10 | MIT |
| tree-sitter-iter | 1.26.1 | MIT |
| tree-sitter-language | 0.1.7 | MIT |
| tree-sitter-yaml | 0.7.2 | MIT |
| try-lock | 0.2.5 | MIT |
| twox-hash | 1.6.3 | MIT |
| twox-hash | 2.1.2 | MIT |
| typed-builder | 0.20.1 | MIT OR Apache-2.0 |
| typed-builder-macro | 0.20.1 | MIT OR Apache-2.0 |
| typed-path | 0.12.3 | MIT OR Apache-2.0 |
| typeid | 1.0.3 | MIT OR Apache-2.0 |
| typenum | 1.20.1 | MIT OR Apache-2.0 |
| typetag | 0.2.22 | MIT OR Apache-2.0 |
| typetag-impl | 0.2.22 | MIT OR Apache-2.0 |
| ucd-trie | 0.1.7 | MIT OR Apache-2.0 |
| uncased | 0.9.10 | MIT OR Apache-2.0 |
| unicase | 2.9.0 | MIT OR Apache-2.0 |
| unicode_categories | 0.1.1 | MIT OR Apache-2.0 |
| unicode-ident | 1.0.24 | (MIT OR Apache-2.0) AND Unicode-3.0 |
| unicode-linebreak | 0.1.5 | Apache-2.0 |
| unicode-normalization | 0.1.25 | MIT OR Apache-2.0 |
| unicode-normalization-alignments | 0.1.12 | MIT/Apache-2.0 |
| unicode-segmentation | 1.13.3 | MIT OR Apache-2.0 |
| unicode-width | 0.1.14 | MIT OR Apache-2.0 |
| unicode-width | 0.2.2 | MIT OR Apache-2.0 |
| untrusted | 0.9.0 | ISC |
| url | 2.5.8 | MIT OR Apache-2.0 |
| utf8_iter | 1.0.4 | Apache-2.0 OR MIT |
| utf8parse | 0.2.2 | Apache-2.0 OR MIT |
| utf8-ranges | 1.0.5 | Unlicense/MIT |
| uuid | 1.23.4 | Apache-2.0 OR MIT |
| valuable | 0.1.1 | MIT |
| version_check | 0.9.5 | MIT/Apache-2.0 |
| walkdir | 2.5.0 | Unlicense/MIT |
| want | 0.3.1 | MIT |
| wasi | 0.11.1+wasi-snapshot-preview1 | Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT |
| wasip2 | 1.0.4+wasi-0.2.12 | Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT |
| wasm-bindgen | 0.2.126 | MIT OR Apache-2.0 |
| wasm-bindgen-futures | 0.4.76 | MIT OR Apache-2.0 |
| wasm-bindgen-macro | 0.2.126 | MIT OR Apache-2.0 |
| wasm-bindgen-macro-support | 0.2.126 | MIT OR Apache-2.0 |
| wasm-bindgen-shared | 0.2.126 | MIT OR Apache-2.0 |
| wasm-streams | 0.4.2 | MIT OR Apache-2.0 |
| webpki-roots | 1.0.8 | CDLA-Permissive-2.0 |
| web-sys | 0.3.103 | MIT OR Apache-2.0 |
| web-time | 1.1.0 | MIT OR Apache-2.0 |
| winapi | 0.3.9 | MIT/Apache-2.0 |
| winapi-i686-pc-windows-gnu | 0.4.0 | MIT/Apache-2.0 |
| winapi-util | 0.1.11 | Unlicense OR MIT |
| winapi-x86_64-pc-windows-gnu | 0.4.0 | MIT/Apache-2.0 |
| windows | 0.62.2 | MIT OR Apache-2.0 |
| windows_aarch64_gnullvm | 0.52.6 | MIT OR Apache-2.0 |
| windows_aarch64_msvc | 0.52.6 | MIT OR Apache-2.0 |
| windows-collections | 0.3.2 | MIT OR Apache-2.0 |
| windows-core | 0.62.2 | MIT OR Apache-2.0 |
| windows-future | 0.3.2 | MIT OR Apache-2.0 |
| windows_i686_gnu | 0.52.6 | MIT OR Apache-2.0 |
| windows_i686_gnullvm | 0.52.6 | MIT OR Apache-2.0 |
| windows_i686_msvc | 0.52.6 | MIT OR Apache-2.0 |
| windows-implement | 0.60.2 | MIT OR Apache-2.0 |
| windows-interface | 0.59.3 | MIT OR Apache-2.0 |
| windows-link | 0.2.1 | MIT OR Apache-2.0 |
| windows-numerics | 0.3.1 | MIT OR Apache-2.0 |
| windows-result | 0.4.1 | MIT OR Apache-2.0 |
| windows-strings | 0.5.1 | MIT OR Apache-2.0 |
| windows-sys | 0.52.0 | MIT OR Apache-2.0 |
| windows-sys | 0.59.0 | MIT OR Apache-2.0 |
| windows-sys | 0.61.2 | MIT OR Apache-2.0 |
| windows-targets | 0.52.6 | MIT OR Apache-2.0 |
| windows-threading | 0.2.1 | MIT OR Apache-2.0 |
| windows_x86_64_gnu | 0.52.6 | MIT OR Apache-2.0 |
| windows_x86_64_gnullvm | 0.52.6 | MIT OR Apache-2.0 |
| windows_x86_64_msvc | 0.52.6 | MIT OR Apache-2.0 |
| winnow | 0.7.15 | MIT |
| wit-bindgen | 0.57.1 | Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT |
| writeable | 0.6.3 | Unicode-3.0 |
| yamlpatch | 1.26.1 | MIT |
| yamlpath | 1.26.1 | MIT |
| yaml_serde | 0.10.4 | MIT OR Apache-2.0 |
| yansi | 1.0.1 | MIT OR Apache-2.0 |
| yoke | 0.8.3 | Unicode-3.0 |
| yoke-derive | 0.8.2 | Unicode-3.0 |
| zerocopy | 0.8.53 | BSD-2-Clause OR Apache-2.0 OR MIT |
| zerocopy-derive | 0.8.53 | BSD-2-Clause OR Apache-2.0 OR MIT |
| zerofrom | 0.1.8 | Unicode-3.0 |
| zerofrom-derive | 0.1.7 | Unicode-3.0 |
| zeroize | 1.9.0 | Apache-2.0 OR MIT |
| zerotrie | 0.2.4 | Unicode-3.0 |
| zerovec | 0.11.6 | Unicode-3.0 |
| zerovec-derive | 0.11.3 | Unicode-3.0 |
| zip | 7.2.0 | MIT |
| zlib-rs | 0.6.5 | Zlib |
| zmij | 1.0.21 | MIT |
| znippy-zoomies | 0.1.15 | MIT |
| zstd | 0.13.3 | MIT |
| zstd-safe | 7.2.4 | MIT OR Apache-2.0 |
| zstd-sys | 2.0.16+zstd.1.5.7 | MIT/Apache-2.0 |

_Path/workspace crates (garmr-*) and vendored path deps are listed above, not here._
