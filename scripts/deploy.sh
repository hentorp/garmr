#!/usr/bin/env bash
# Data-safe update deploy of garmr to an existing host: build the release binary
# + web console, ship them plus the detection/correlation rules, and restart the
# service. It touches ONLY the install prefix ($PREFIX/bin, $PREFIX/ui) and the
# config rule dirs ($ETC/{rules,correlations,hunts}); it NEVER references the
# lakehouse/data dir, so a redeploy cannot wipe events (the one real footgun —
# see docs/ha-design.md). First-time provisioning is scripts/airgap-install.sh.
#
# Everything is parameterized so this works for ANY host, not one environment:
#   GARMR_HOST     required, e.g. root@10.0.0.5 or an ssh alias
#   GARMR_PREFIX   install prefix         (default /opt/garmr)
#   GARMR_ETC      config dir             (default /etc/garmr)
#   GARMR_UNIT     systemd unit name      (default garmr)
#   GARMR_SSH_KEY  optional identity file (else your ssh config/agent)
#   GARMR_FEATURES cargo features         (default semantic)
#   GARMR_HEALTH   health URL on the host (default http://127.0.0.1:3110/health)
#   GARMR_SKIP_UI=1   skip the web-console build/ship (binary+rules only)
#
# Usage:  GARMR_HOST=root@myhost ./scripts/deploy.sh
set -euo pipefail
cd "$(dirname "$0")/.."

: "${GARMR_HOST:?set GARMR_HOST (e.g. root@host or an ssh alias)}"
PREFIX="${GARMR_PREFIX:-/opt/garmr}"
ETC="${GARMR_ETC:-/etc/garmr}"
UNIT="${GARMR_UNIT:-garmr}"
FEATURES="${GARMR_FEATURES:-semantic}"
HEALTH="${GARMR_HEALTH:-http://127.0.0.1:3110/health}"
KEYOPT=(); [ -n "${GARMR_SSH_KEY:-}" ] && KEYOPT=(-i "$GARMR_SSH_KEY" -o IdentitiesOnly=yes)
SSH=(ssh "${KEYOPT[@]}" -o ConnectTimeout=10 "$GARMR_HOST")
SCP=(scp "${KEYOPT[@]}" -o ConnectTimeout=10)

echo "==> build release binary (--release --locked --features $FEATURES)"
cargo build --release --locked --features "$FEATURES" --bin garmr
strip -o /tmp/garmr.deploy target/release/garmr

echo "==> ship binary atomically to $PREFIX/bin/garmr (keeping a .bak)"
"${SCP[@]}" /tmp/garmr.deploy "$GARMR_HOST:$PREFIX/bin/garmr.new"
"${SSH[@]}" "cd $PREFIX/bin && cp -a garmr garmr.bak 2>/dev/null || true; \
             chmod 0755 garmr.new && mv garmr.new garmr"

if [ "${GARMR_SKIP_UI:-0}" != "1" ]; then
  if command -v trunk >/dev/null 2>&1; then
    echo "==> build + ship web console ($PREFIX/ui must stay world-readable / 0755)"
    ( cd crates/garmr-webui && trunk build --release )
    "${SSH[@]}" "rm -rf $PREFIX/ui.new && mkdir -p $PREFIX/ui.new"
    "${SCP[@]}" crates/garmr-webui/dist/* "$GARMR_HOST:$PREFIX/ui.new/"
    "${SSH[@]}" "rm -rf $PREFIX/ui.old && mv $PREFIX/ui $PREFIX/ui.old 2>/dev/null || true; \
                 mv $PREFIX/ui.new $PREFIX/ui && chmod -R a+rX $PREFIX/ui && \
                 find $PREFIX/ui -type d -exec chmod 0755 {} +"
    # The CodeVault map (garmr-map, eframe/WASM) is embedded in the console's
    # Map view via an iframe to /map/ and served from $PREFIX/ui/map/. Its
    # Trunk.toml sets public_url=/map/ so its asset URLs resolve there; without
    # this ship, /map/ 404s and the SPA fallback renders the whole console nested
    # inside the map pane. Goes AFTER the console swap (which replaces $PREFIX/ui).
    echo "==> build + ship the CodeVault map ($PREFIX/ui/map)"
    ( cd crates/garmr-map && trunk build --release )
    "${SSH[@]}" "mkdir -p $PREFIX/ui/map"
    "${SCP[@]}" crates/garmr-map/dist/* "$GARMR_HOST:$PREFIX/ui/map/"
    "${SSH[@]}" "chmod 0755 $PREFIX/ui/map && chmod -R a+rX $PREFIX/ui/map"
  else
    echo "!! trunk not installed — skipping web console (set GARMR_SKIP_UI=1 to silence)" >&2
  fi
fi

echo "==> ship detection + correlation rules to $ETC (data dirs untouched)"
for d in rules correlations hunts; do
  if [ -d "$d" ] && compgen -G "$d/*" >/dev/null; then
    "${SSH[@]}" "mkdir -p $ETC/$d"
    "${SCP[@]}" "$d"/* "$GARMR_HOST:$ETC/$d/"
  fi
done

echo "==> restart $UNIT + verify"
"${SSH[@]}" "systemctl restart $UNIT && sleep 3 && systemctl is-active $UNIT && curl -fsS -m5 $HEALTH && echo"
echo "==> deploy done (lakehouse untouched)."
