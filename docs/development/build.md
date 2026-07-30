<!--
SPDX-FileCopyrightText: 2026 Vetra Automation AB
SPDX-License-Identifier: CC-BY-4.0
-->

# Building garmr

garmr is a Cargo workspace of `garmr-*` crates plus a few vendored subtrees. This
page covers the toolchain, the build variants, and what each Cargo feature gates.

## Toolchain

- **Edition 2021.** Minimum supported Rust version (MSRV) **1.85**.
- The toolchain is **pinned** via `rust-toolchain.toml` (currently `1.96.0`, with
  `clippy` and `rustfmt`), so CI, contributors, and the reproducible release all
  build with the same `rustc`. `rustup` reads it automatically.

## A default build

```sh
cargo build --release
```

This produces the `garmr` binary and is self-contained: the lakehouse engine
(**skade**), the cold-storage codec (**znippy**), and other heavy pieces are
**vendored** under `vendor/` so a plain `cargo build` needs no external checkout.
The default build is fully usable with no cloud key.

The vendored subtrees (`vendor/skade`, `vendor/znippy`, `vendor/facett`,
`vendor/znippy-zoomies`) are intentionally **excluded** from the workspace and
consumed as path dependencies — update them via `git subtree pull`, not Dependabot.

## Cargo features

All optional capabilities are Cargo features. `znippy` is the only one on by
default.

| Feature | Default | Gates |
|---|---|---|
| `znippy` | **on** | The OpenZL-backed cold-storage archiver. `--no-default-features` drops it and falls back to a pure-Rust zstd-parquet archiver (and removes the OpenZL C dependency). |
| `semantic` | off | Embedding / semantic search (`garmr-embed`, candle/BERT). Adds the `embed-index`, `embed-verify`, and `semantic` subcommands and the `/api/semantic` route. Needs a local model directory at runtime (`GARMR_EMBED_MODEL`). |
| `loki-compat` | off | The Loki push ingest endpoint (`/loki/api/v1/push`). The native endpoint is always available. |
| `flight` | off | The experimental Arrow Flight gRPC ingest endpoint. Off by default — treat as disabled-by-default. |
| `mcp` | off | Builds the `garmr-mcp` server binary. |

Feature definitions live in `crates/garmr-cli/Cargo.toml` (with `loki-compat` and
`flight` re-exported from `crates/garmr-ingest`).

### Common build recipes

```sh
# A full-featured node (semantic search + Loki + Flight ingest):
cargo build --release --features "semantic loki-compat flight"

# A portable / hardened-host build with no OpenZL C dependency:
cargo build --release --no-default-features --bin garmr

# Reproducible, locked build (no lockfile drift):
cargo build --release --locked
```

> **Feature note.** Semantic search additionally needs a local embedding model
> directory (`GARMR_EMBED_MODEL`) at runtime; the feature only compiles the
> capability in. See [../deployment/local-llm.md](../deployment/local-llm.md) and
> the semantic notes in [../architecture/overview.md](../architecture/overview.md).

## Binaries

- `garmr` — the main binary (`serve` + every one-shot subcommand).
- `garmr-mcp` — the MCP server, built only with `--features mcp`.

## Building offline / in an air-gap

Vendor all crates on a connected host, carry them across, and build with
`--offline`. See [../deployment/airgap.md](../deployment/airgap.md) for the full
recipe, including the `--no-default-features` variant that drops the one heavy C
dependency.

## Configuration and secrets at build vs. run time

Nothing secret is baked into the binary. Configuration comes from `garmr.toml`
(copy `garmr.example.toml`) and secrets from the environment at run time — see
[../deployment/quick-start.md](../deployment/quick-start.md) and
[../deployment/secure-deployment.md](../deployment/secure-deployment.md).
