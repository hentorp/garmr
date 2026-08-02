#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Vetra Automation AB
# SPDX-License-Identifier: AGPL-3.0-only
#
# Documentation-consistency gate.
#
# High-impact security and release claims in the docs must match the CODE they
# describe. This script fails when they drift. It deliberately checks STABLE
# ANCHORS — constants, config keys, Cargo feature names, file paths, version
# strings — never prose, so ordinary editing does not break it.
#
# Run locally:  bash scripts/check-doc-consistency.sh
# Runs in CI:   .github/workflows/ci.yml (job: doc-consistency)

set -uo pipefail

cd "$(dirname "$0")/.."

fails=0
checks=0

ok()   { checks=$((checks + 1)); printf '  ok    %s\n' "$1"; }
fail() { checks=$((checks + 1)); fails=$((fails + 1)); printf '  FAIL  %s\n' "$1"; }

# Assert that `needle` (a fixed string) appears in `file`.
has() { # has <file> <needle> <description>
  if [ ! -f "$1" ]; then fail "$3 — missing file: $1"; return; fi
  if grep -qF -- "$2" "$1"; then ok "$3"; else fail "$3 — '$2' not found in $1"; fi
}

# Assert that `needle` does NOT appear in `file`.
lacks() { # lacks <file> <needle> <description>
  if [ ! -f "$1" ]; then fail "$3 — missing file: $1"; return; fi
  if grep -qF -- "$2" "$1"; then fail "$3 — '$2' still present in $1"; else ok "$3"; fi
}

# Extract a Rust string literal returned by a `fn <name>()` default helper.
rust_default() { # rust_default <file> <fn-name>
  grep -A3 "fn $2()" "$1" | grep -oE '"[^"]+"' | head -1 | tr -d '"'
}

echo "== 1. Bind defaults in docs match crates/garmr-core/src/config.rs =="
CFG=crates/garmr-core/src/config.rs
API_BIND=$(rust_default "$CFG" default_api_bind)
INGEST_BIND=$(rust_default "$CFG" default_ingest_bind)
LOKI_BIND=$(rust_default "$CFG" default_loki_bind)

if [ -z "$API_BIND" ] || [ -z "$INGEST_BIND" ] || [ -z "$LOKI_BIND" ]; then
  fail "could not parse bind defaults out of $CFG (api='$API_BIND' ingest='$INGEST_BIND' loki='$LOKI_BIND')"
else
  ok "parsed defaults from code: api=$API_BIND ingest=$INGEST_BIND loki=$LOKI_BIND"
  for doc in README.md docs/deployment/secure-deployment.md docs/security/known-limitations.md; do
    has "$doc" "$API_BIND"    "$doc states the real API bind default ($API_BIND)"
    has "$doc" "$INGEST_BIND" "$doc states the real native ingest bind default ($INGEST_BIND)"
  done
  has docs/deployment/quick-start.md "$API_BIND"    "quick-start states the real API bind default"
  has docs/deployment/quick-start.md "$INGEST_BIND" "quick-start states the real ingest bind default"
  has docs/security/known-limitations.md "$LOKI_BIND" "known-limitations states the real Loki bind default"
fi

# The historical README bug: claiming `serve` is loopback-only. The API is
# loopback by default; native ingest is NOT. This phrasing must never come back.
lacks README.md "binds loopback by default" "README no longer claims serve binds loopback by default"

echo
echo "== 2. Arrow Flight is disabled by default in code and docs =="
# `flight_bind` must have NO serde default fn (=> Option::None => disabled).
if grep -B2 'pub flight_bind' "$CFG" | grep -q 'serde(default = '; then
  fail "flight_bind has a non-None serde default in $CFG — docs claim it is disabled by default"
else
  ok "flight_bind defaults to None (disabled) in $CFG"
fi
has docs/security/known-limitations.md "off by default" "known-limitations says Flight is off by default"
has docs/status/alpha-status.md        "off by default" "alpha-status says Flight is off by default"

echo
echo "== 3. Fail-closed bind gates exist in code where the docs claim them =="
SERVE=crates/garmr-cli/src/serve.rs
has "$SERVE" "check_ingest_bind_auth" "native ingest fail-closed gate is wired in serve.rs"
has "$SERVE" "check_flight_bind_auth" "Arrow Flight fail-closed gate is wired in serve.rs"
# The Loki receiver deliberately has NO gate; the docs must keep saying so.
if grep -A6 'run_loki(' "$SERVE" | grep -q 'check_.*bind_auth'; then
  fail "run_loki now has a bind auth gate — update the docs, which say it does not"
else
  ok "Loki receiver still has no bind gate (matches the documented limitation)"
fi
has docs/security/known-limitations.md "No fail-closed bind gate" "known-limitations documents the missing Loki bind gate"

echo
echo "== 4. Native ingest limit constants match the documented values =="
NATIVE=crates/garmr-ingest/src/native.rs
for c in MAX_BODY_BYTES MAX_EVENTS_PER_REQUEST MAX_FIELD_VALUE_BYTES MAX_MESSAGE_BYTES; do
  has "$NATIVE" "pub const $c" "native ingest defines $c"
  has docs/security/known-limitations.md "$c" "known-limitations names $c"
done

echo
echo "== 5. Arrow Flight limit constants match the documented values =="
FLIGHT=crates/garmr-ingest/src/flight.rs
for c in MAX_FLIGHT_ROWS_PER_BATCH MAX_FLIGHT_BATCHES_PER_STREAM MAX_FLIGHT_ROWS_PER_STREAM FLIGHT_BATCH_RECV_TIMEOUT; do
  has "$FLIGHT" "pub const $c" "flight ingest defines $c"
  has docs/security/known-limitations.md "$c" "known-limitations names $c"
done

echo
echo "== 6. Feature-gated capability names match Cargo features =="
CLI_TOML=crates/garmr-cli/Cargo.toml
for feat in semantic mcp loki-compat flight znippy; do
  if grep -qE "^${feat} = " "$CLI_TOML"; then
    ok "Cargo feature '$feat' exists in $CLI_TOML"
  else
    fail "docs reference Cargo feature '$feat' but it is not defined in $CLI_TOML"
  fi
  has docs/security/known-limitations.md "\`$feat\`" "known-limitations names the '$feat' feature"
done

echo
echo "== 7. Alpha version references are consistent =="
WS_VERSION=$(grep -m1 '^version' Cargo.toml | grep -oE '"[^"]+"' | tr -d '"')
if [ -z "$WS_VERSION" ]; then
  fail "could not parse [workspace.package] version from Cargo.toml"
else
  ok "workspace version is $WS_VERSION"
  # Every alpha tag reference in the docs must be for this version series.
  BAD=$(grep -rhoE 'v[0-9]+\.[0-9]+\.[0-9]+-alpha\.[0-9]+' \
          README.md SECURITY.md CHANGELOG.md docs/ 2>/dev/null \
        | sort -u | grep -v "^v${WS_VERSION}-alpha\." || true)
  if [ -n "$BAD" ]; then
    fail "alpha tag reference(s) do not match workspace version $WS_VERSION: $(echo "$BAD" | tr '\n' ' ')"
  else
    ok "all alpha tag references match workspace version $WS_VERSION"
  fi
  # SECURITY.md's supported-version table must name this series.
  SERIES="${WS_VERSION%.*}"   # 0.1.0 -> 0.1
  has SECURITY.md "${SERIES}.x" "SECURITY.md supported-version table names the ${SERIES}.x series"
fi

echo
echo "== 8. Required legal and security documents exist =="
for f in LICENSE LICENSES/AGPL-3.0-only.txt LICENSES/CC-BY-4.0.txt NOTICE \
         COMMERCIAL-LICENSING.md TRADEMARKS.md CLA.md CONTRIBUTING.md \
         THIRD_PARTY_LICENSES.md SECURITY.md CODE_OF_CONDUCT.md CHANGELOG.md \
         docs/security/known-limitations.md docs/security/threat-model.md \
         docs/status/alpha-status.md docs/deployment/secure-deployment.md; do
  if [ -f "$f" ]; then ok "present: $f"; else fail "missing required document: $f"; fi
done

echo
echo "== 9. Cross-document links resolve (relative markdown links) =="
# Walk every markdown file, resolve each relative link target against the file's
# own directory, and fail on a dangling path. Anchors and URLs are skipped.
while IFS= read -r md; do
  dir=$(dirname "$md")
  grep -oE '\]\([^)#][^)]*\)' "$md" 2>/dev/null \
    | sed -E 's/^\]\(//; s/\)$//' \
    | grep -vE '^(https?:|mailto:|#)' \
    | sed -E 's/#.*$//' \
    | while IFS= read -r target; do
        [ -z "$target" ] && continue
        if [ ! -e "$dir/$target" ]; then
          printf '  FAIL  dangling link in %s -> %s\n' "$md" "$target"
          echo "dangling" >> /tmp/.doc-link-failures.$$
        fi
      done
done < <(find . -name '*.md' -not -path './vendor/*' -not -path './.git/*' -not -path './target/*')
if [ -f "/tmp/.doc-link-failures.$$" ]; then
  n=$(wc -l < "/tmp/.doc-link-failures.$$"); rm -f "/tmp/.doc-link-failures.$$"
  checks=$((checks + 1)); fails=$((fails + 1))
  printf '  FAIL  %s dangling relative markdown link(s)\n' "$n"
else
  ok "no dangling relative markdown links"
fi

echo
echo "== 10. README points at the secure-deployment guide =="
has README.md "docs/deployment/secure-deployment.md" "README links the secure deployment guide"
has README.md "docs/security/known-limitations.md"   "README links known limitations"
has README.md "SECURITY.md"                          "README links the security policy"

echo
echo "== 11. CI toolchain matches rust-toolchain.toml =="
TC=$(grep -m1 '^channel' rust-toolchain.toml | grep -oE '"[^"]+"' | tr -d '"')
if [ -z "$TC" ]; then
  fail "could not parse channel from rust-toolchain.toml"
else
  ok "rust-toolchain.toml pins $TC"
  for wf in .github/workflows/*.yml; do
    # Every dtolnay/rust-toolchain use must request the pinned channel.
    bad=$(grep -A3 'dtolnay/rust-toolchain@' "$wf" | grep -E '^\s+toolchain:' \
          | grep -v "\"$TC\"" | grep -v "'$TC'" | grep -v ": $TC" || true)
    if [ -n "$bad" ]; then
      fail "$wf installs a toolchain other than rust-toolchain.toml's $TC: $bad"
    else
      ok "$(basename "$wf") toolchain pins match $TC"
    fi
  done
fi

echo
echo "== 12. pgAudit runtime wiring matches what the docs claim =="
# The docs state that the RECOMMENDED collector (`garmr pgaudit-ship`) posts raw
# rows to NATIVE ingest and that native ingest does NOT run the pg adapter. If
# either fact changes, the docs must be rewritten.
has crates/garmr-cli/src/cmd/pgaudit.rs "/ingest/v1/events" "pgaudit-ship targets the native ingest endpoint"
if grep -qE 'Adapter|adapter::' crates/garmr-ingest/src/server.rs; then
  fail "the native ingest server now references the adapter registry — update the pgAudit docs"
else
  ok "native ingest does not run source adapters (matches the documented limitation)"
fi
has crates/garmr-ingest/src/loki.rs "postgres-csvlog" "the pg adapter is routed on the Loki path"
has docs/deployment/postgresql-pgaudit.md "Which path parses what" "pgAudit doc carries the path/parsing table"

echo
echo "---------------------------------------------------------------"
if [ "$fails" -eq 0 ]; then
  echo "doc-consistency: $checks checks, all passed"
  exit 0
fi
echo "doc-consistency: $fails of $checks checks FAILED"
exit 1
