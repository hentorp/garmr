#!/usr/bin/env bash
# Garmr public-tree verification. Checks a candidate public tree (default: this
# repo) for the invariants a public release must hold. Exits non-zero on any
# failure so it can gate CI and the export script.
#
#   scripts/public-verify.sh [TREE_DIR]   (default: repo root)
set -uo pipefail
TREE="${1:-$(git rev-parse --show-toplevel 2>/dev/null || pwd)}"
cd "$TREE"
HERE="$(cd "$(dirname "$0")" && pwd 2>/dev/null || echo .)"
DENY="${HERE}/../public-export.denylist"
fail=0
note() { echo "  - $1"; }
bad()  { echo "FAIL: $1"; fail=1; }

echo "verifying public tree: $TREE"

# 1) no NESTED .git (imported/submodule history). The tree's OWN top-level .git
#    is expected once the public repo is initialized; only a .git BELOW the root
#    would indicate carried-over history.
if find . -mindepth 2 -name .git -print -quit | grep -q .; then bad "a nested .git directory exists in the tree"; else note "no nested .git in tree"; fi
[ -f .export-manifest.txt ] || note "no export manifest (ok if verifying a committed repo)"

# 2) forbidden content patterns (from denylist PATTERN: lines, plus hard defaults)
PATTERNS='vetra-automation/garmr|tail4eceda|100\.97\.108|/home/rickard|/home/henrik|@ubm\.se|utbetalningsmyndigheten'
if [ -f "$DENY" ]; then
  extra="$(sed -n 's/^PATTERN://p' "$DENY" | paste -sd'|' -)"
  [ -n "$extra" ] && PATTERNS="$PATTERNS|$extra"
fi
# Exclude the files that legitimately DEFINE these patterns (self-reference).
SELF='--exclude=public-export.denylist --exclude=public-verify.sh --exclude=ci.yml'
hits="$(grep -rInE "$PATTERNS" --exclude-dir=.git $SELF . 2>/dev/null || true)"
if [ -n "$hits" ]; then bad "forbidden/internal references present:"; echo "$hits" | head; else note "no forbidden/internal references"; fi

# 3) no private-path / private-git cargo dependencies
manhits="$(grep -rInE 'path\s*=\s*"/|git\s*=\s*"(ssh://|git@)' --include=Cargo.toml . 2>/dev/null || true)"
if [ -n "$manhits" ]; then bad "absolute-path or private-git dependency in a Cargo.toml:"; echo "$manhits"; else note "no private path/git deps"; fi

# 4) no unclear-license vendored dep present
[ -d vendor/facett ] && bad "vendor/facett (unclear license) present" || note "vendor/facett absent"

# 5) required legal / project files
for f in LICENSE NOTICE COMMERCIAL-LICENSING.md TRADEMARKS.md CONTRIBUTING.md CLA.md \
         SECURITY.md CODE_OF_CONDUCT.md THIRD_PARTY_LICENSES.md README.md \
         LICENSES/AGPL-3.0-only.txt LICENSES/CC-BY-4.0.txt; do
  [ -f "$f" ] || bad "missing required file: $f"
done
note "checked required legal/project files"

# 6) license posture: workspace declares AGPL-3.0-only; no MIT/Apache stub left
grep -q '^license = "AGPL-3.0-only"' Cargo.toml || bad "workspace license is not AGPL-3.0-only"
{ [ -f LICENSE-MIT ] || [ -f LICENSE-APACHE ]; } && bad "old MIT/Apache stub license file present" || note "no superseded license stubs"

# 7) SPDX coverage on garmr's own Rust source (sample check)
missing=$(grep -rL 'SPDX-License-Identifier' --include='*.rs' crates 2>/dev/null | wc -l)
[ "$missing" -gt 0 ] && note "note: $missing crate .rs files lack an SPDX header (REUSE.toml may cover them)" || note "all crate .rs files carry SPDX headers"

# 8) manifest integrity (if present)
if [ -f .export-digests.sha256 ]; then
  sha256sum -c --quiet .export-digests.sha256 2>/dev/null && note "export digests verify" || bad "export digest mismatch"
fi

# 9) dependency graph resolves + supply-chain (optional; needs cargo)
if command -v cargo >/dev/null; then
  cargo metadata --format-version 1 --locked --all-features >/dev/null 2>&1 \
    && note "cargo metadata resolves (--locked --all-features)" \
    || note "note: cargo metadata did not resolve offline (run cargo deny/audit in CI)"
fi

if [ "$fail" -ne 0 ]; then echo "VERIFY: FAILED"; exit 1; fi
echo "VERIFY: OK"
