#!/usr/bin/env bash
# Build a release of the garmr binary with provenance (modgunn / M7-5).
#
# Produces, under dist/:
#   garmr                 the stripped release binary
#   SHA256SUMS            sha256 of the binary + SBOM (the integrity manifest)
#   sbom.cdx.json         CycloneDX SBOM of the exact locked tree
#   provenance.txt        toolchain + git commit + build flags (how it was built)
#   SHA256SUMS.minisig    detached signature — ONLY if a signing key is provided
#
# Reproducibility: builds with --locked (no lockfile drift) and
# --remap-path-prefix (strip the absolute build path so the binary doesn't
# depend on WHERE it was built). Two builds of the same commit with the same
# toolchain produce the same binary hash. Verify a downloaded release with:
#   sha256sum -c SHA256SUMS && minisign -Vm SHA256SUMS -P <pubkey>
#
# Signing is opt-in and the key is the operator's (never in the repo): set
# GARMR_SIGN_KEY=/path/to/minisign.key to sign. Without it the release still
# ships SHA256SUMS — checksums without a signature. See docs/supply-chain.md.
set -euo pipefail

cd "$(dirname "$0")/.."
features="${GARMR_RELEASE_FEATURES:-semantic}"
dist="dist"
rm -rf "$dist"; mkdir -p "$dist"

commit="$(git rev-parse HEAD 2>/dev/null || echo unknown)"
dirty=""; git diff --quiet 2>/dev/null || dirty=" (dirty tree)"

echo "==> building garmr (--release --locked --features '$features')"
# Remap the build path so the binary is independent of the checkout location.
RUSTFLAGS="--remap-path-prefix=$(pwd)=/build/garmr ${RUSTFLAGS:-}" \
  cargo build --release --locked --features "$features" --bin garmr

cp target/release/garmr "$dist/garmr"
strip "$dist/garmr"

echo "==> generating SBOM"
./scripts/sbom.sh "$dist/sbom.cdx.json" >/dev/null

echo "==> writing provenance"
{
  echo "garmr provenance"
  echo "commit:   $commit$dirty"
  echo "rustc:    $(rustc --version)"
  echo "cargo:    $(cargo --version)"
  echo "features: $features"
  echo "rustflags: --remap-path-prefix=<checkout>=/build/garmr"
  echo "host:     $(uname -srm)"
} > "$dist/provenance.txt"

echo "==> checksums"
( cd "$dist" && sha256sum garmr sbom.cdx.json provenance.txt > SHA256SUMS )

if [ -n "${GARMR_SIGN_KEY:-}" ]; then
  if command -v minisign >/dev/null 2>&1; then
    echo "==> signing SHA256SUMS with operator key"
    minisign -Sm "$dist/SHA256SUMS" -s "$GARMR_SIGN_KEY"
  else
    echo "!! GARMR_SIGN_KEY set but minisign not installed — shipping unsigned" >&2
  fi
else
  echo "==> no GARMR_SIGN_KEY — shipping SHA256SUMS unsigned (see docs/supply-chain.md)"
fi

echo "==> done. dist/:"
( cd "$dist" && sha256sum -c SHA256SUMS && ls -la )
