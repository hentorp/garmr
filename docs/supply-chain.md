# Supply chain & provenance (modgunn)

garmr is meant to be adopted, not just run — which means an operator has to be
able to trust ~800 transitive crates without auditing them by hand. This is the
machinery that makes that trust checkable rather than assumed. It is the
**modgunn** milestone (M7-5).

Four things are enforced, all reproducible on your own machine:

| Artifact | What it guarantees | How to check |
|---|---|---|
| `deny.toml` | Every license is on an allow-list; no known-vulnerable or yanked crate; every source is crates.io | `cargo deny check` |
| `scripts/sbom.sh` → `supply-chain/sbom.cdx.json` | A complete, deterministic bill of materials (CycloneDX 1.5) | `bash scripts/sbom.sh && git diff --exit-code` |
| `scripts/release.sh` → `dist/SHA256SUMS` | The exact binary + SBOM you got, hashed; optionally signed | `sha256sum -c SHA256SUMS` |
| `.github/workflows/supply-chain.yml` | All of the above run on every push and PR (plus a weekly re-run so a newly published advisory is caught against an unchanged lockfile) | CI status |
| `scripts/check-actions-pinned.sh` | Every external GitHub Action is pinned to a full commit SHA | `bash scripts/check-actions-pinned.sh` |
| `scripts/check-doc-consistency.sh` | Security claims in the docs still match the code | `bash scripts/check-doc-consistency.sh` |

## The dependency gate — `cargo deny`

`cargo deny check` runs four independent gates against [`deny.toml`](../deny.toml):

- **licenses** — allow-list only. A crate whose SPDX license isn't listed fails
  the build, so a copyleft or unknown license can never enter unnoticed. The
  list is the permissive union actually present (MIT/Apache/BSD/ISC/Zlib/…, plus
  the bundled open fonts `OFL-1.1`/`Ubuntu-font-1.0` and the `bzip2` codec).
- **advisories** — the RustSec database. An unpatched vulnerability or a yanked
  version fails the build. Exceptions are listed in `[advisories].ignore`, and
  **each one carries an inline justification and a named follow-up** — see below.
- **bans** — denies wildcard (`*`) version requirements on real dependencies and
  surfaces duplicate-version bloat. garmr's internal crates are marked
  `publish = false` (they are one product, not a crate family for crates.io).
- **sources** — only crates.io is allowed. garmr's tree has **zero** git or
  alternative-registry dependencies; an unexpected one fails the build.

### Audited advisory exceptions

These are the *only* tolerated advisories. Everything else — including a brand
new advisory on any crate in the tree — fails CI until triaged. Each was checked
for reachability by hand:

| Advisory | Crate | Why tolerated | Clears when |
|---|---|---|---|
| RUSTSEC-2026-0041 | lz4_flex 0.10 | Decompression info-leak on invalid input. Transitive + feature-gated; the 0.10 copy is reached only via `cozo` → `swapvec`, which lz4-compresses garmr's **own** locally-spilled graph data — never attacker-supplied compressed input. The arrow/datafusion path uses the patched 0.13.x | `cozo`/`swapvec` bump lz4_flex |
| RUSTSEC-2025-0132 | maxminddb | **Not reachable** — garmr's only call site is `Reader::open_readfile` (reads the GeoIP db into memory); the unsound `open_mmap` is never invoked | maxminddb ships a fixed release to bump to |
| RUSTSEC-2026-0194, -0195 | quick-xml | XML-parse DoS reachable only via `object_store` parsing responses from the **operator-configured** S3 endpoint (the cold tier) — not an arbitrary remote attacker, DoS not RCE. Fixed in quick-xml ≥ 0.41; `object_store` 0.13.2 pins `^0.39` and is itself pinned by the vendored datafusion-54 / iceberg-arrow58 stack | the vendored datafusion/object_store stack reaches quick-xml ≥ 0.41 |
| RUSTSEC-2024-0436 | paste | Build-time proc-macro (candle/gemm, behind the `semantic` feature) — no runtime attack surface; archived upstream with no drop-in replacement | candle migrates off `paste` |
| RUSTSEC-2025-0056/-0057/-0141 | adler, fxhash, bincode | **Unmaintained**, not vulnerable: a zlib checksum, a non-cryptographic hashmap hasher, and a transitive serializer garmr never feeds untrusted input through | upstreams move to adler2 / rustc-hash / bincode 2 |

> The quick-xml path also appears **build-time only** via `wayland-scanner` in
> the optional desktop UI (parsing trusted local Wayland protocol XML). The
> headless `garmr` server binary does not link the UI, so that path is absent
> from a server deployment entirely.

**Reviewed but deliberately not suppressed.** Standalone `cargo audit` also lists
`RUSTSEC-2026-0221` (event-listener 5.4.1 unsoundness). `cargo deny check` does
not flag it against this graph, so adding it to `deny.toml`'s `ignore` would be a
suppression that matches nothing. The review is recorded as a comment in
`deny.toml`: event-listener is transitive only (async-lock → moka → the vendored
iceberg table cache), garmr has no direct dependency on it, and the unsound
`!Send`-tag path is never instantiated here.

**`cargo audit` vs `cargo deny`.** CI runs `cargo deny check` as the *gate* (it
carries the audited exception list) and `cargo audit` as an *informational* step
that reports without the exception list, so a newly published advisory is visible
in the log even while the gate is green.

## Workflow supply chain

CI is itself a supply-chain surface — a mutable action tag is code we did not
review running with our workflow token.

- **Every external GitHub Action is pinned to a full 40-character commit SHA**,
  with the human-readable version in a trailing comment. `scripts/check-actions-pinned.sh`
  runs as the `actions-pinned` CI job and fails the build if an unpinned
  reference, a bare tag, a mutable `docker://` tag, or a SHA without a version
  comment appears. Local actions (`uses: ./...`) are exempt.
- **Downloaded tooling is checksum-verified.** The WebUI job pins the exact
  `trunk` release *and* its SHA-256 in the workflow, verifies the download
  against that in-repo digest first, then cross-checks the publisher's `.sha256`
  asset and fails on any mismatch. Bumping the version without updating the
  digest fails the build.
- **Minimum token permissions.** Every workflow declares `permissions: contents:
  read` at the top level; only the CodeQL analyze job widens that, to
  `security-events: write`, which it needs to upload results.
- **No secrets reach untrusted code.** There is no `pull_request_target`
  anywhere; the only secret referenced is the default `GITHUB_TOKEN`, which
  GitHub issues read-only for fork pull requests. Workflow steps that read
  attacker-controlled values (the `cla` job reads the PR body and author) pass
  them through `env:` and reference them as quoted shell variables, never
  interpolating them into the script text.

## The bill of materials — SBOM

`scripts/sbom.sh` emits a CycloneDX 1.5 SBOM from the **locked** graph using only
`cargo metadata` + `jq` (no extra tooling, works airgapped). It is deterministic:
components are sorted and no timestamp is embedded, so the same `Cargo.lock`
always produces a byte-identical file. CI regenerates it and fails if the
committed `supply-chain/sbom.cdx.json` is stale — the SBOM cannot drift from the
tree unnoticed.

```
bash scripts/sbom.sh          # → supply-chain/sbom.cdx.json  (811 components)
```

## Reproducible, verifiable releases

`scripts/release.sh` builds the binary with `--locked` (no lockfile drift) and
`--remap-path-prefix` (the binary doesn't depend on *where* it was built), then
emits under `dist/`:

- `garmr` — the stripped release binary
- `sbom.cdx.json` — the SBOM for exactly this build
- `provenance.txt` — toolchain versions, git commit, and build flags
- `SHA256SUMS` — sha256 of the binary + SBOM + provenance

Two builds of the same commit with the same toolchain produce the same binary
hash. To verify a release you received:

```
sha256sum -c SHA256SUMS
```

### Signing (operator key)

Signing is opt-in and the key is **yours** — it never lives in the repo (same
rule as every other garmr secret). Generate a minisign keypair once, keep the
secret key in your password manager, and publish the public key:

```
minisign -G                                   # once — creates minisign.key + minisign.pub
GARMR_SIGN_KEY=~/.minisign/garmr.key bash scripts/release.sh
minisign -Vm dist/SHA256SUMS -P <your-pubkey> # verify the signature
```

Without a key the release still ships `SHA256SUMS` (integrity), just without a
signature (authenticity). CI does not sign — release signing is a deliberate,
key-holding human step.

## Airgapped

Everything here runs without network access once the crates are vendored: `cargo
deny check --offline`, `scripts/sbom.sh`, and `scripts/release.sh` need no
registry fetch. See [airgap.md](airgap.md) (Skidbladnir) for the offline build
and threat-intel story.

## First-class signed bundles (`garmr bundle`, Phase 11)

`garmr bundle` produces a VERIFIABLE, self-contained air-gap bundle IN the binary,
complementing the `scripts/release.sh` + minisign outer transport. It is a signed,
content-addressed directory:

```
garmr bundle build ./out            # bin/ + rules/ + correlations/ + hunts/ +
                                    # garmr.example.toml + supply-chain/sbom.txt +
                                    # provenance.txt + release.json + bundle.json +
                                    # public_key.hex  (ed25519-signed with the audit key)
garmr bundle verify ./out --key <hex>   # OFFLINE, fail-closed, non-zero on any tamper
garmr bundle import ./out --key <hex>   # verify → audit → register+promote (serve stopped)
garmr bundle rollback <prev-version>    # offline audited reversal
```

Trust model (fail-closed): `verify`/`import` authenticate against an **out-of-band
trusted key** — an explicit `--key`, else the operator's own local
`audit.dir/public_key.hex`. The public key EMBEDDED in the bundle is **never** a
trust root; with no local trusted key, `verify` reports `UNVERIFIED` and exits
non-zero (never "OK"), and `import` refuses without `--key` (except `--dry-run`,
which writes nothing). `verify` recomputes every file digest + the manifest digest
+ the signature, walks the whole tree rejecting symlinks / escaping paths, treats
any file NOT in the signed manifest as fatal, and re-checks the release binding
(one canonical `release_digest`). `import` verifies BEFORE it applies, audits
fail-closed (an import must be auditable), and is reversible via `rollback` — all
offline, no egress. A bundle never contains a secret: the config is a TEMPLATE and
model weights are never bundled (only a `ModelNote` recording which external model
the release expects). The minisign/`SHA256SUMS` outer path stays as an independent
second signature (belt-and-suspenders).

Residuals: the bundle attests the RELEASE (binary + rules + config template + SBOM
+ provenance), not a reproducible-build attestation of the binary itself, and not
the model weights (an external process). Full SLSA provenance + a TUF-style repo
are deferred.
