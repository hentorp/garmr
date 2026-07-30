#!/usr/bin/env bash
# Generate a deterministic CycloneDX 1.5 SBOM for garmr from the locked
# dependency graph (modgunn / M7-5 supply-chain).
#
# Deterministic by construction: components are sorted by (name, version) and no
# wall-clock timestamp is embedded, so the same Cargo.lock always yields a
# byte-identical SBOM — a diff in supply-chain/sbom.cdx.json means the tree
# actually changed. Uses only `cargo metadata` + `jq` (no cargo-cyclonedx
# needed), so it runs anywhere the toolchain is, including airgapped.
#
# Usage: scripts/sbom.sh [output.json]   (default: supply-chain/sbom.cdx.json)
set -euo pipefail

cd "$(dirname "$0")/.."
out="${1:-supply-chain/sbom.cdx.json}"
mkdir -p "$(dirname "$out")"

app_version="$(cargo metadata --format-version 1 --no-deps 2>/dev/null \
  | jq -r '.packages[] | select(.name=="garmr-cli") | .version')"

# --all-features so feature-gated deps (semantic/mcp/znippy) appear in the SBOM.
cargo metadata --format-version 1 --locked --all-features \
  | jq --arg appver "$app_version" '{
      bomFormat: "CycloneDX",
      specVersion: "1.5",
      version: 1,
      metadata: {
        component: {
          "bom-ref": "pkg:cargo/garmr@\($appver)",
          type: "application",
          name: "garmr",
          version: $appver,
          description: "One-person agentic SOC in Rust."
        }
      },
      components: [
        .packages[]
        | select(.name != "garmr-cli")
        | {
            "bom-ref": ("pkg:cargo/" + .name + "@" + .version),
            type: "library",
            name: .name,
            version: .version,
            purl: ("pkg:cargo/" + .name + "@" + .version),
            licenses: (
              if .license then
                [ .license | {license: {name: .}} ]
              else [] end
            )
          }
      ] | sort_by(.name, .version)
    }' > "$out"

n="$(jq '.components | length' "$out")"
echo "wrote $out — $n components (app garmr $app_version)"
