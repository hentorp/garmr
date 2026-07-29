# skade-katalog benchmark: vs Nessie & Apache Polaris

Mirrors holger's vs-Nexus harness. Every competitor implements `iceberg::Catalog`
(skade-katalog via `RedbCatalog`, Nessie/Polaris via the Iceberg REST client), so the
scenarios in `src/scenarios.rs` are identical across all three.

This is a **detached crate** (own `[workspace]`): building it does not touch the
published `skade-katalog` crate's dependency tree.

## Targets

| Target | What runs | Network |
|---|---|---|
| `nornir-embedded` | in-process `RedbCatalog` (the real deployment) | none |
| `nessie` | Project Nessie + RocksDB, Iceberg REST | localhost HTTP |
| `polaris` | Apache Polaris (Quarkus JVM), Iceberg REST | localhost HTTP |

A REST-fronted nornir (axum shim) column — for an apples-to-apples REST-vs-REST
comparison — is the remaining piece (see plan.md); the embedded number is the
"no network hop" reference.

## Run

```bash
# embedded — works out of the box, fully self-contained
BENCH_QUICK=1 cargo run --release -- embedded        # smoke (200 tables)
cargo run --release -- embedded                      # full (10k tables)

# Nessie (RocksDB) in a container, then bench against it
./containers/nessie_up.sh
BENCH_QUICK=1 cargo run --release -- nessie http://localhost:19120/iceberg warehouse
./containers/nessie_down.sh

# Polaris — needs OAuth2 + catalog bootstrap; polaris_up.sh prints the steps
./containers/polaris_up.sh
# …follow the printed token + create-catalog steps, then:
BENCH_REST_PROPS="credential=root:s3cr3t,scope=PRINCIPAL_ROLE:ALL" \
  cargo run --release -- polaris http://localhost:8181/api/catalog warehouse
./containers/polaris_down.sh
```

Output is JSONL (one scenario per line) with `target`, `ops_sec`, and
`p50/p99/p999_us` — ready to append to `bench_history.jsonl` and fold into the
README table, exactly like holger.

## Storage coupling (important)

`load_table` makes the **client** read the metadata file the **server** wrote.
So server and client must share the warehouse. The container scripts bind-mount
a host dir at the same path inside the container and use a `file://` warehouse,
so the client's `LocalFs` FileIO reads the identical bytes. For a realistic
object-store run, stand up MinIO and point both sides at `s3://…` (requires the
iceberg S3 FileIO feature; not wired by default).

## Ægir transport: `ureq` (default) vs `uring` (io_uring)

The S3 data plane runs on **aegir** (`bench/aegir/`), our pure-Rust S3 client
(SigV4 over a pluggable byte transport, zero-copy `Bytes` reads). Two transports:

- **`ureq`** (default) — pure-Rust HTTP over rustls; handles TLS + plaintext.
- **`uring`** (opt-in feature) — an **io_uring** TCP transport for the
  **plaintext** RustFS hot path (`:9000`, no TLS). Built on the pure-Rust
  `io-uring` crate (libc FFI + bitflags + cfg-if only — no C, no bindgen, no
  OpenSSL). Connect via `std` (resolver); the request/response **data path** runs
  through io_uring `Send`/`Recv` SQE/CQE loops, over a **per-thread keep-alive
  connection pool** (so it matches ureq's pooled-agent model — one TCP handshake
  amortised over many ops). SigV4 + request/response semantics are identical;
  only the byte transport swaps. TLS endpoints always fall back to ureq.

Select per-client (`Client::with_transport(Transport::Uring)`) or via
`AEGIR_TRANSPORT=uring`; compile with `--features uring`.

```bash
# RustFS up, then the transport micro-bench (HEAD/GET/PUT, isolates the byte path)
cargo run --release --features uring --example aegir_transport
# or the full data plane on either transport:
AEGIR_TRANSPORT=uring cargo run --release --features uring -- data skade-s3
```

### ureq vs uring — plaintext RustFS micro-bench (8k iters, this box)

| op | ureq ops/s | uring ops/s | ureq p50 | uring p50 |
|---|---|---|---|---|
| HEAD | 3,380 | **3,397** | 281.5 µs | **274.3 µs** |
| GET 4 KiB | **2,539** | 2,500 | 382.4 µs | 370.0 µs |
| PUT 256 B | **1,680** | 1,671 | 558.4 µs | 547.9 µs |

With keep-alive pooling, **uring reaches parity with ureq** (HEAD marginally
ahead on both ops/s and p50); single-connection serial latency is dominated by
RustFS server processing + RTT, so both transports converge once the per-call TCP
handshake is removed. Without pooling, uring was ~30–40 % slower (one handshake
per op) — the pool closes that gap. uring's win is doing it with **no TLS stack
in the path** on the plaintext hot path, pure-Rust io_uring throughout.

## Scenarios (`src/scenarios.rs`)

- `load_table.latency` — warm single-thread `load_table` (the trait method).
- `resolve_metadata.latency` — **nornir-only** fast path: returns
  `Arc<TableMetadata>` and skips `Table::build()`. This is the true catalog read
  speed.
- `create_table.latency` — write path.
- `load_table.throughput.t{N}` — concurrent `load_table` at N threads.

## Reference numbers (this dev box, local NVMe, BENCH_QUICK)

| target | scenario | ops/sec | p50 | p99 |
|---|---|---|---|---|
| nornir-embedded | resolve_metadata | ~760k–1.4M | ~0.5–1.0 µs | 3–10 µs |
| nornir-embedded | load_table | 145,350 | **1.51 µs** | 34.4 µs |
| nornir-embedded | load_table (t8/t32 throughput) | **2.07M / 1.92M** | — | — |
| nornir-embedded | create_table | ~12k | ~80 µs | — |
| nornir-rest | load_table | 8,818 | 109 µs | 178 µs |
| nornir-rest | create_table | 5,275 | 184 µs | 237 µs |

`load_table` (embedded) p50 is **1.5 µs** since the L1.5 built-`Table` handle cache
(`src/table_cache.rs`) + location-first lookup — down from ~15 µs. The old cost was iceberg-rust building a
fresh per-`Table` moka `ObjectCache` on every call (~14 µs, and `disable_cache`
does *not* avoid it — see `examples/cache_ab.rs`); caching the built `Table` by
immutable `metadata_location` and cloning it (shares the `Arc<ObjectCache>`, ~100 ns)
removes it and lets `load_table` scale concurrently (t8 1.53M, t32 1.81M ops/s).
`resolve_metadata` (no `Table` at all) is the ~0.5 µs floor. `nornir-rest` adds
~90–100 µs of HTTP+JSON over embedded and is the apples-to-apples REST baseline.

### REST-vs-REST vs Nessie & Polaris — `table_exists` (pure catalog RPC, storage-free)

Full four-way run (2026-06-06, this box, full 10k-table scale):

| target | p50 | p99 | p999 | ops/sec |
|---|---|---|---|---|
| nornir-embedded | **0.32 µs** | 0.66 µs | 0.87 µs | **2,111,704** |
| nornir-rest (axum) | **36.1 µs** | 56.9 µs | 87.1 µs | **24,535** |
| Nessie RocksDB (JVM) | 147.7 µs | 643.8 µs | 1.44 ms | 5,590 |
| Polaris (JVM) | 288.0 µs | 1.70 ms | 3.81 ms | 2,659 |

REST-vs-REST nornir is **~8.0× lower p50 / ~9.2× more throughput** than Polaris,
and **~4.1× / ~4.4×** vs Nessie; embedded is **~900×** vs Polaris, **~460×** vs
Nessie (`table_exists` is answered from the lock-free pointer mirror — no redb
read, no mutex). Polaris trails Nessie (per-request OAuth/RBAC). The JVMs'
multi-ms p999 is the GC tail; nornir-rest's p999 stays at 87 µs.

Why `table_exists` and not `loadTable` for Nessie/Polaris: both reject (Nessie)
or insecure-block (Polaris) a local `file:` warehouse for the table write path,
and iceberg-rust 0.9.1 ships no S3 FileIO, so MinIO is blocked client-side too.
`table_exists` is a pure catalog RPC with no storage, so it runs on every
backend and isolates server latency. Polaris bootstrap (FILE feature flags +
readiness override + OAuth + catalog create) is automated in
`containers/polaris_up.sh`.

### Durability sweep (`BENCH_DURABILITY=immediate|eventual|none`, create_table)
13.7k / 13.6k / 10.6k ops/sec — barely moves, because the metadata-file write
dominates the redb fsync (see `../REDB_WISHLIST.md`).
