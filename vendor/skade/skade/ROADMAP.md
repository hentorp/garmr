# skade — roadmap / "the list"

Forward-looking work. skade today is a correct, ergonomic, *fast-enough* layer
over iceberg-rust 0.9.1 + the pure-Rust skade-katalog (`RedbCatalog`). The big
arc is **Iceberg v4** (Parquet metadata) — which simultaneously kills Avro + its
C deps and makes *all* our Parquet acceleration apply to metadata too.

---

## 1. Target Iceberg v4 — Parquet metadata  ⟵ the north star

**What:** Iceberg **v4** (proposed Oct 2025) replaces row-based **Avro**
manifests/manifest-lists with columnar **Parquet** — same format as the data, so
engines project only the metadata columns they need (min/max stats) with column
pruning + predicate pushdown on *planning*, not just scanning. Avro stays
readable; new metadata is written as Parquet.
Refs: [v4 state Oct 2025](https://iceberglakehouse.com/posts/2025-10-apache-iceberg-v4-october-2025/) ·
[DISCUSS: Parquet as Metadata File Format](https://www.mail-archive.com/dev@iceberg.apache.org/msg10938.html) ·
[v4 spec (KB)](https://iceberglakehouse.com/iceberg/iceberg-spec-v4/)

**Why it's THE target (kills several birds):**
- **Avro dies** → `apache-avro` + its `zstd-sys` C dep are *gone* (no fork-to-
  patch-avro needed).
- **Metadata becomes Parquet** → `ingest_parallel`'s all-cores encode and the
  nordisk **zero-copy/parallel zstd** apply to metadata as well as data — one
  codec path for both.
- **Columnar metadata** → projection + pushdown = the zero-copy planning win.

**Status (verified):** **NOT buildable today.**
- The v4 spec is a **proposal / IEPs**, not finalized — a moving target.
- **iceberg-rust 0.9.1 hardcodes Avro** for manifests (`spec/manifest/writer.rs`
  → `apache_avro::Writer`); even `FormatVersion::V3` writes Avro. No format
  abstraction, no v4/Parquet-manifest branch or tracking issue yet — iceberg-rust
  is still reaching v3 parity. ([iceberg-rust issues](https://github.com/apache/iceberg-rust/issues))

**The work, when it's time (upstream iceberg-rust — contribute, don't fork-diverge):**
1. Manifest **writer** (`spec/manifest/writer.rs`): Avro → Parquet per the v4
   manifest schema.
2. Manifest **reader** (`spec/manifest/mod.rs`): read Parquet; keep Avro reader
   for v1–v3 back-compat.
3. **Manifest-list / Root Manifest** (v4 replaces the manifest list with a single
   per-snapshot root manifest).
4. `FormatVersion::V4` in `table_metadata.rs` + the snapshot/transaction branches.
5. skade: bump to the v4-capable iceberg, write tables as V4.

**First concrete steps (do now, while the spec settles):**
- **Track** iceberg-rust's v4 work (watch the repo; subscribe to the IEP/discuss
  threads) so we build on it, not cold.
- **Adopt v3 now** (item 2) — it's the foundation and is shipping.

## 2. Support the new Iceberg **v3** formats (available NOW in iceberg-rust 0.9.1)

iceberg-rust 0.9.1 already exposes `FormatVersion::V3`. These v3 features (shipped
in Iceberg 1.8–1.10) are the "new formats" we can support *today* — no waiting on
v4. ([v3 features](https://community.cloudera.com/t5/Developer-Blogs/Apache-Iceberg-Key-Innovations-So-Far-and-What-s-Next-for/ba-p/413024))

- **Binary deletion vectors** (Puffin) — fast row-level deletes.
- **Variant type** — semi-structured (JSON-ish) columns.
- **Native geometry & geography types** — spatial (pairs with znippy's F6 spatial archive).
- **Nanosecond timestamps**.
- **Row lineage** (`_row_id` / `_last_updated_sequence_number`).
- **Default column values**, multi-argument partition transforms, table encryption keys.

**✅ Step 1 done (0.4.2):** `create_table` / `create_partitioned_table` write
**`FormatVersion::V3`**; full stack round-trips V3 (`new_tables_are_format_v3`).

**✅ Step 2 done (0.4.3):** the arrow↔iceberg bridge now maps **timestamp /
timestamptz (µs)**, the **v3 nanosecond timestamps** (`TimestampNs`/`TimestamptzNs`),
**decimal**, and **time** (was bool/int/float/date/string/binary only) — test
`scalar_and_v3_nanosecond_types_round_trip`. skade can now write real schemas
(TPC-H-style decimals/timestamps) and the v3 ns-timestamp type.

**✅ Step 3 done — row lineage:** automatic on V3 (iceberg-rust assigns
`first_row_id` + advances `next_row_id` in the commit path). Since skade writes
V3 it's **free**; verified by `v3_row_lineage_is_active` (next_row_id 0→5→8).

**v3 support tally:**
- ✅ V3 table format · ✅ nanosecond timestamps · ✅ decimal/time/timestamp ·
  ✅ row lineage.
- ⛔ **variant & geometry/geography** — not in iceberg-rust 0.9.1's `PrimitiveType`
  at all (verified). Blocked until iceberg-rust adds the types upstream.
- ⛔ **binary deletion vectors** — the pieces exist (`DeleteVector`, puffin
  `deletion-vector-v1`) but there is **no delete / row-delta / overwrite
  transaction action** in iceberg-rust 0.9.1, so deletes aren't writable. Blocked
  on an upstream `RowDelta`/delete action.

Both blocked items are **upstream iceberg-rust gaps**, tracked here — revisit when
a newer iceberg-rust ships them (watch alongside v4, item 1).

## 3. Compressed Parquet writes + nordisk codec

skade writes **UNCOMPRESSED** Parquet today (`WriterProperties::default`). Expose
a compression knob (zstd/snappy); `ingest_parallel` already fans the whole encode
(incl. compression) across cores, so it's parallelized for free.
The deeper win — nordisk **zero-copy/parallel zstd** (`zstd-sys-rs`) + **parallel
lzma** (`lzip-parallel`) as the codec — needs a **parquet-crate fork** (its codec
is not pluggable; built-in via the `Compression` enum). Once v4 lands (item 1),
this same codec path covers metadata too.

---

## Done
- 0.2.0 — identity-partitioned writes (`create_partitioned_table` + per-commit
  `partition_key_for`).
- 0.3.0 — `sql` opt-in (lean default, drops `liblzma-sys` + datafusion);
  criterion throughput bench (`cargo bench -p skade`).
- 0.4.0 — **gatling multi-core writes**: `ingest_parallel` (+ `Table::ingest_parallel`)
  fans Parquet encoding across all cores via the znippy-zoomies `gatling_forkjoin`
  engine (`gatling_map_owned` — the ONE fork-join engine, no rayon), one sequential
  writer commits every N files; partition-correct. Measured ~**3.8×** on the encode-heavy path
  (1 core 123ms → all cores 32ms; `ingest_parallel_scaling` bench).
- 0.4.1 — `session()` registers **all namespaces** (was `main` only). **Dogfooded**:
  skade-katalog's TPC-H suite gained `build_ctx_skade` +
  `tpch_full_suite_22_queries_through_skade` — **22/22** queries through
  `skade::Warehouse::session`.
- 0.4.2 — new tables are written as **Iceberg `FormatVersion::V3`** (newest the
  spec + iceberg-rust 0.9.1 support) — on-ramp to v4, unlocks the v3 formats.
- 0.4.3 — bridge maps **timestamp/timestamptz (µs), v3 nanosecond timestamps, decimal, time**
  (was bool/int/float/date/string/binary). Variant + geometry remain blocked on iceberg-rust.
- 0.4.5 — **compression** (`Table::compression` / `append_with` / `ingest_parallel_with`; none/snappy/zstd, parallelised free in ingest_parallel) + **projection pushdown read** (`read_columns` / `Table::read_columns`). Roadmap levers #1 + #3 done.
- 0.4.7 — **#2 gatling no-barrier pipeline**: `ingest_pipelined` (+ `Table::ingest_pipelined`) — encoders run ahead of one writer through a bounded channel (overlaps encode+commit, bounds memory). Measured ~**12%** over `ingest_parallel` (28.0→24.7ms, 32×20k) + bounded memory.
- 0.5.1 — **#20 one-engine pipeline**: `ingest_pipelined` re-homed onto the ONE async I/O engine `gatling::io::run_ordered` — the all-core `gatling_forkjoin` encode now feeds the FileIO writes through `run_ordered` (≤ `channel_depth` in flight, no-barrier, backpressured, results re-sequenced into **submission order**), replacing the hand-rolled `spawn_blocking` + mpsc + `blocking_send` pipeline. File sequence + row order now deterministically match input group order (guarded by `tests/pipelined_order.rs`).
