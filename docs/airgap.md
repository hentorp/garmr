# Airgapped deployment (Skidbladnir)

Some SOCs run with no internet at all — classified networks, OT/ICS segments,
regulated environments. garmr is built to run there without giving anything up
that matters offline. This is the **Skidbladnir** profile (M7-5): the ship that
folds into your pocket and always has a fair wind — garmr, self-contained.

Two things make it work: a build that **drops the OpenZL codec** (the one heavy,
less-portable C dependency) and every network feature, and a runtime **hard
switch** that forbids every egress path.

## What already holds offline

garmr's design is local-first, so most of the SOC works airgapped unchanged:

- **Storage & query** — the skade lakehouse, cold tier, SQL and semantic search
  are all on-host. Semantic search uses a pure-Rust embedder over a *local*
  model directory (`GARMR_EMBED_MODEL`); no model download at runtime.
- **Detection** — rules, correlations, frequency baselines, anomaly detection,
  and risk scoring are all local computation.
- **Threat-intel** — the enricher loads GeoIP from a local memory-mapped `.mmdb`
  and IOC lists from **local files** at startup. Nothing here needs the network.
- **Cold tier** — can stay on local disk, or target an *on-prem* S3 (MinIO) that
  lives inside the airgap.

What is *not* available offline, by nature: the LLM agent (`/api/ask`, triage
narratives) needs the Anthropic API, and the *online* IOC feed refresh needs the
internet. Skidbladnir turns both off cleanly rather than leaving them to fail.

## The build — drop OpenZL, fall back to pure-Rust zstd

The default build uses the `znippy` cold-storage codec, which statically links
**OpenZL** (facebook/openzl, via `openzl-sys-rs`) — a newer C compression
library that isn't always available or approved in locked-down environments. The
airgap build drops it for the `plain` (zstd-parquet) archiver — same cold-tier
semantics, a smaller and more portable dependency surface:

```
cargo build --release --no-default-features --bin garmr
```

Verified: with `--no-default-features`, `openzl-sys-rs` disappears from the tree
entirely (`cargo tree | grep openzl` is empty). This is not a *zero*-C build —
the Arrow/Parquet stack still links the ubiquitous `zstd-sys`/`liblzma-sys` via
`cc`, which every Rust build host already has — but it removes the one
dependency (OpenZL) that an airgapped or hardened host is likely to reject. Cold
archives sealed by a `plain`-only build are fully interoperable with the default
build's reader (each archive records its own codec). CI compiles this
configuration on every push so it never rots.

### Building from source inside the airgap

If the airgap won't accept a prebuilt binary, vendor every crate on a connected
host first, then build offline on the target:

```
# connected host:
cargo vendor --locked vendor-crates > .cargo/config.airgap.toml
#   → carry the repo + vendor-crates/ across the boundary

# airgapped host:
mkdir -p .cargo && cp .cargo/config.airgap.toml .cargo/config.toml
cargo build --release --locked --offline --no-default-features --bin garmr
```

`cargo deny check --offline` and `scripts/sbom.sh` also run with no network, so
the supply-chain gate (see [supply-chain.md](supply-chain.md)) travels into the
airgap intact.

## The transfer install

The simpler path — build a signed release on a connected host and carry it in:

```
# connected build host:
GARMR_SIGN_KEY=~/.minisign/garmr.key bash scripts/release.sh
#   → dist/{garmr,SHA256SUMS,SHA256SUMS.minisig,sbom.cdx.json,provenance.txt}

# add offline intel to the bundle (optional):
#   dist/iocs/*.txt     one-IP-per-line lists   dist/geoip/*.mmdb   DB-IP/MaxMind

# airgapped target (as root):
MINISIGN_PUBKEY=<pubkey> scripts/airgap-install.sh /path/to/dist
```

`airgap-install.sh` verifies checksums (and the signature if you pass the
pubkey), installs the binary, seeds the IOC/GeoIP files, and writes an
airgap-locked env template. It never touches the network.

## The runtime hard switch — `GARMR_AIRGAP`

Set `GARMR_AIRGAP=1` (also `true`/`yes`/`on`) and garmr forbids **every** egress
path regardless of any other config:

- the online IOC feed refresh is disabled — `configured_ioc_feeds()` returns
  empty even if `GARMR_IOC_FEED_URLS` is set;
- the agent's `allow_online_lookups` is forced off in `load_config`, even if
  `garmr.toml` enables it.

It is deliberately a single, loud switch: one mis-set knob can't open a hole in
an airgapped SOC. On startup you'll see:

```
INFO airgap mode active — no network egress (online IOC feeds + lookups disabled)
```

Local file-based IOC feeds and local GeoIP keep working — offline threat-intel
is unaffected. To keep intel fresh, periodically drop updated IOC lists into the
seeded directory (carried across the boundary) and restart, or `SIGHUP` if your
deployment wires a reload.

## The LLM agent, offline

`/api/ask` and triage narratives need the Anthropic API and are unavailable in a
true airgap. Everything the agent *reads* — SQL, semantic search, the graph,
enrichment — is exposed directly through the query API and the desktop UI, so an
analyst keeps the full investigative surface; only the natural-language layer is
absent. If the airgap has a sanctioned on-prem LLM gateway, point
`[agent].openai_base_url` at it (OpenAI-compatible) and leave `GARMR_AIRGAP`
unset — the rest of the offline posture is then yours to configure explicitly.
