<!--
SPDX-FileCopyrightText: 2026 Vetra Automation AB
SPDX-License-Identifier: CC-BY-4.0
-->

# Air-gapped deployment

Some environments run with no internet at all — classified networks, OT/ICS
segments, regulated estates. garmr is built to run there without giving up anything
that matters offline. Two things make it work: a build that can **drop the one heavy
C dependency**, and a runtime **hard switch** that forbids every egress path.

## What already works offline

garmr is local-first, so most of the system runs air-gapped unchanged:

- **Storage & query** — the embedded lakehouse, cold tier, SQL, full-text, and
  (with the `semantic` build) semantic search are all on-host. Semantic search uses
  a pure-Rust embedder over a **local** model directory (`GARMR_EMBED_MODEL`); no
  runtime download.
- **Detection** — Sigma rules, correlations, frequency baselines, anomaly
  detection, RBA, and the environment model are all local computation.
- **Threat-intel** — the enricher loads GeoIP from a local memory-mapped `.mmdb`
  and IOC lists from **local files** at startup.
- **The LLM agent** — runs against a **local** OpenAI-compatible model (Ollama /
  llama.cpp / vLLM). This is the only supported agent mode under air-gap. See
  [local-llm.md](local-llm.md).
- **Cold tier** — local disk, or an **on-prem** S3 (e.g. MinIO) inside the air-gap.

What is not available offline, by nature: the **external** (Anthropic) LLM backend
and the **online** IOC feed refresh. The air-gap switch turns both off cleanly
rather than leaving them to fail.

## The build — drop OpenZL, fall back to pure-Rust zstd

The default build statically links **OpenZL** via the `znippy` cold-storage codec —
a C library that isn't always available or approved in locked-down environments. The
air-gap build drops it for the pure-Rust `plain` (zstd-parquet) archiver — same
cold-tier semantics, a smaller and more portable dependency surface:

```sh
cargo build --release --no-default-features --bin garmr
```

With `--no-default-features`, OpenZL disappears from the dependency tree entirely.
Cold archives sealed by a `plain`-only build are fully interoperable with the
default build's reader (each archive records its own codec).

### Building from source inside the air-gap

If the air-gap won't accept a prebuilt binary, vendor every crate on a connected
host first, then build offline on the target:

```sh
# connected host:
cargo vendor --locked vendor-crates > .cargo/config.airgap.toml
#   → carry the repo + vendor-crates/ across the boundary

# air-gapped host:
mkdir -p .cargo && cp .cargo/config.airgap.toml .cargo/config.toml
cargo build --release --locked --offline --no-default-features --bin garmr
```

`cargo deny check --offline` and `scripts/sbom.sh` also run with no network, so the
supply-chain gate travels into the air-gap intact (see
[../development/release-process.md](../development/release-process.md)).

## The transfer install

The simpler path — build a signed release on a connected host and carry it in:

```sh
# connected build host:
GARMR_SIGN_KEY=~/.minisign/garmr.key bash scripts/release.sh
#   → dist/{garmr,SHA256SUMS,SHA256SUMS.minisig,sbom.cdx.json,provenance.txt}

# add offline intel to the bundle (optional):
#   dist/iocs/*.txt     one-IP-per-line lists
#   dist/geoip/*.mmdb   DB-IP / MaxMind GeoIP databases

# air-gapped target (as root):
MINISIGN_PUBKEY=<pubkey> scripts/airgap-install.sh /path/to/dist
```

`airgap-install.sh` verifies checksums (and the signature if you pass the pubkey),
installs the binary, seeds the IOC/GeoIP files, and writes an air-gap-locked env
template. It never touches the network. For a fully self-contained, signed,
content-addressed bundle produced *by the binary itself*, see `garmr bundle` in
[../development/release-process.md](../development/release-process.md).

## The runtime hard switch — `GARMR_AIRGAP`

Set `GARMR_AIRGAP=1` (also `true`/`yes`/`on`) and garmr forbids **every** egress
path regardless of any other config:

- the online IOC feed refresh is disabled — even if `GARMR_IOC_FEED_URLS` is set;
- the agent's `allow_online_lookups` is forced off, even if `garmr.toml` enables it;
- every outbound class (external LLM, notifiers, IOC feeds, MCP, S3) is denied at
  the egress chokepoint, and the denial is **unoverridable** by any other config.

`GARMR_AIRGAP=1` **overrides** the `[route.egress]` allowlist. It is deliberately a
single, loud switch: one mis-set knob can't open a hole in an air-gapped SOC. On
startup you'll see a log line confirming air-gap mode is active.

Local file-based IOC feeds and local GeoIP keep working — offline threat-intel is
unaffected. To keep intel fresh, periodically drop updated IOC lists into the seeded
directory (carried across the boundary) and restart.

## The agent, offline

Point `[agent]` at a **local** OpenAI-compatible endpoint and leave the external
backend unused:

```toml
[agent]
backend = "open_ai_compat"
openai_base_url = "http://127.0.0.1:11434/v1"   # e.g. Ollama; llama.cpp: :8080/v1
allow_online_lookups = false
```

The egress chokepoint classifies a loopback / private-range endpoint as **local**;
under `GARMR_AIRGAP=1` external LLM egress is denied outright and cannot be
re-enabled, so an air-gapped garmr can only ever reach a local model and never
silently falls back to a hosted one. Everything the agent reads (SQL, semantic
search, the graph, enrichment) is also available directly through the query API and
the web console, so an analyst keeps the full investigative surface even without the
agent. See [local-llm.md](local-llm.md).
