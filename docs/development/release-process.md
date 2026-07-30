<!--
SPDX-FileCopyrightText: 2026 Vetra Automation AB
SPDX-License-Identifier: CC-BY-4.0
-->

# Release process and supply chain

garmr is meant to be adopted, not just run — which means an operator has to be able
to trust a large transitive dependency graph without auditing it by hand. This page
describes the release artifacts and the supply-chain gate that makes that trust
checkable rather than assumed. Everything here is reproducible on your own machine,
offline.

## The four enforced artifacts

| Artifact | Guarantee | How to check |
|---|---|---|
| `deny.toml` | Every license is allow-listed; no known-vulnerable or yanked crate; every source is crates.io | `cargo deny check` |
| `scripts/sbom.sh` → `supply-chain/sbom.cdx.json` | A complete, deterministic CycloneDX 1.5 bill of materials | `bash scripts/sbom.sh && git diff --exit-code` |
| `scripts/release.sh` → `dist/SHA256SUMS` | The exact binary + SBOM + provenance, hashed and optionally signed | `sha256sum -c SHA256SUMS` |
| `.github/workflows/supply-chain.yml` | The gate runs on every push / PR | CI status |

## The dependency gate — `cargo deny`

`cargo deny check` runs four independent gates against `deny.toml`:

- **licenses** — allow-list only; a crate whose SPDX license isn't listed fails the
  build, so a copyleft or unknown license can't enter unnoticed.
- **advisories** — the RustSec database; an unpatched vulnerability or a yanked
  version fails the build. Exceptions live in `[advisories].ignore`, and **each
  carries an inline justification and a named follow-up** (checked for reachability
  by hand).
- **bans** — denies wildcard (`*`) version requirements and surfaces
  duplicate-version bloat. Internal crates are `publish = false`.
- **sources** — only crates.io is allowed; the tree has zero git or
  alternative-registry dependencies.

The graph is **locked** in CI (`--locked`): a build that would update `Cargo.lock`
fails instead of drifting.

## The SBOM

`scripts/sbom.sh` emits a CycloneDX 1.5 SBOM from the locked graph using only
`cargo metadata` + `jq` (works air-gapped). It is deterministic — components sorted,
no embedded timestamp — so the same `Cargo.lock` always produces a byte-identical
file, and CI fails if the committed SBOM is stale.

```sh
bash scripts/sbom.sh          # → supply-chain/sbom.cdx.json
```

## Reproducible, verifiable releases

`scripts/release.sh` builds with `--locked` (no lockfile drift) and
`--remap-path-prefix` (the binary doesn't depend on *where* it was built), then
emits under `dist/`:

- `garmr` — the stripped release binary
- `sbom.cdx.json` — the SBOM for exactly this build
- `provenance.txt` — toolchain versions, git commit, and build flags
- `SHA256SUMS` — sha256 of the binary + SBOM + provenance

Two builds of the same commit with the same pinned toolchain produce the same binary
hash. To verify a release you received: `sha256sum -c SHA256SUMS`.

### Signing (operator key)

Signing is **opt-in and the key is yours** — it never lives in the repo. Generate a
minisign keypair once, keep the secret key in your password manager, and publish the
public key:

```sh
minisign -G                                   # once — creates minisign.key + minisign.pub
GARMR_SIGN_KEY=~/.minisign/garmr.key bash scripts/release.sh
minisign -Vm dist/SHA256SUMS -P <your-pubkey> # verify the signature
```

Without a key the release still ships `SHA256SUMS` (integrity), just without a
signature (authenticity). CI does **not** sign — release signing is a deliberate,
key-holding human step.

> `GARMR_SIGN_KEY` is a **release-script** environment variable (a minisign key
> path), **not** a `garmr serve` daemon setting. The in-binary signing key is the
> audit ledger's ed25519 key (`[audit] key_path`).

## First-class signed bundles (`garmr bundle`)

`garmr bundle` produces a verifiable, self-contained air-gap bundle *in* the binary,
complementing the outer minisign transport. It is a signed, content-addressed
directory (binary + rules + config template + SBOM + provenance + release metadata),
ed25519-signed with the audit key:

```sh
garmr bundle build ./out                # assemble + sign
garmr bundle verify ./out --key <hex>   # OFFLINE, fail-closed, non-zero on any tamper
garmr bundle import ./out --key <hex>   # verify → audit → register+promote (serve stopped)
garmr bundle rollback <prev-version>    # offline audited reversal
```

Trust model (fail-closed): `verify`/`import` authenticate against an **out-of-band
trusted key** (an explicit `--key`, else the local `audit.dir/public_key.hex`). The
public key embedded in the bundle is **never** a trust root; with no trusted key,
`verify` reports `UNVERIFIED` and exits non-zero. A bundle never contains a secret
(the config is a template; model weights are never bundled).

Residuals: the bundle attests the release, not a reproducible-build attestation of
the binary itself, and not the model weights (an external process). Full SLSA
provenance and a TUF-style repo are deferred.

## Air-gapped

`cargo deny check --offline`, `scripts/sbom.sh`, and `scripts/release.sh` all run
with no registry fetch once crates are vendored, so the whole gate travels into an
air-gap intact. See [../deployment/airgap.md](../deployment/airgap.md).

## The dependency license report

The full transitive dependency license inventory
(`docs/legal/dependency-license-report.md`) is **generated by the release manager**
from cargo data, not authored by hand. See [../legal/licensing.md](../legal/licensing.md)
and the root `THIRD_PARTY_LICENSES.md`.
