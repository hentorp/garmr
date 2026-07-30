#!/usr/bin/env bash
# Skidbladnir — install a garmr release onto an airgapped host from a transfer
# bundle, with no network access (M7-5).
#
# The bundle is what `scripts/release.sh` produced on a connected build host,
# carried across the airgap boundary (USB / data diode / one-way share):
#   garmr  SHA256SUMS  sbom.cdx.json  provenance.txt  [SHA256SUMS.minisig]
# plus, optionally, offline threat-intel you seed yourself:
#   iocs/*.txt          one-IP-per-line IOC lists (abuse.ch/blocklist.de shape)
#   geoip/*.mmdb        DB-IP Lite or MaxMind GeoLite2 (no key, no network)
#
# This script VERIFIES the bundle (checksums, and the signature if a pubkey is
# given), installs the binary, and writes an airgap-locked env template. It
# never touches the network. Run as root on the target.
#
# Usage:
#   MINISIGN_PUBKEY=<key> scripts/airgap-install.sh /path/to/bundle
set -euo pipefail

bundle="${1:?usage: airgap-install.sh <bundle-dir>}"
prefix="${GARMR_PREFIX:-/opt/garmr}"
etc="${GARMR_ETC:-/etc/garmr}"
var="${GARMR_VAR:-/var/lib/garmr}"

cd "$bundle"

echo "==> verifying integrity (offline)"
sha256sum -c SHA256SUMS

if [ -n "${MINISIGN_PUBKEY:-}" ]; then
  if command -v minisign >/dev/null 2>&1; then
    echo "==> verifying signature"
    minisign -Vm SHA256SUMS -P "$MINISIGN_PUBKEY"
  else
    echo "!! MINISIGN_PUBKEY given but minisign not installed — cannot verify authenticity" >&2
    exit 1
  fi
else
  echo "   (no MINISIGN_PUBKEY — integrity checked, authenticity NOT verified)"
fi

echo "==> installing binary → $prefix/bin/garmr"
install -D -m 0755 garmr "$prefix/bin/garmr"
[ "$("$prefix/bin/garmr" --version 2>&1 | head -1)" ] && echo "   $("$prefix/bin/garmr" --version)"

echo "==> seeding offline threat-intel"
install -d -m 0755 "$var/iocs" "$var/geoip"
ioc_files=""
if compgen -G "iocs/*.txt" >/dev/null; then
  cp -v iocs/*.txt "$var/iocs/"
  ioc_files=$(printf '"%s/iocs/%s",' "$var" $(cd iocs && ls *.txt) | sed 's/,$//')
fi
if compgen -G "geoip/*.mmdb" >/dev/null; then
  cp -v geoip/*.mmdb "$var/geoip/"
fi

echo "==> writing airgap env template → $etc/garmr.env.airgap"
install -d -m 0750 "$etc"
umask 027
cat > "$etc/garmr.env.airgap" <<EOF
# Skidbladnir airgap profile — no network egress. Merge into garmr.env.
# The hard switch: blocks online IOC feed refresh AND agent online lookups,
# regardless of any other setting (see load_config / configured_ioc_feeds).
GARMR_AIRGAP=1
# Belt-and-suspenders: explicitly empty online feed list.
GARMR_IOC_FEED_URLS=
# Local GeoIP (offline mmdb) — point config's [agent].geoip_dir here too.
# GARMR_GEOIP_DIR=$var/geoip
EOF
chmod 0640 "$etc/garmr.env.airgap"

echo
echo "installed. Next steps (offline):"
echo "  1. merge $etc/garmr.env.airgap into $etc/garmr.env"
echo "  2. set [agent].ioc_feeds in garmr.toml to the seeded files:"
[ -n "$ioc_files" ] && echo "       ioc_feeds = [$ioc_files]" || echo "       (no IOC lists were in the bundle — add iocs/*.txt and re-run)"
echo "  3. set [agent].geoip_dir = \"$var/geoip\" if you seeded an mmdb"
echo "  4. start garmr; confirm the log line: 'airgap mode active — no network egress'"
