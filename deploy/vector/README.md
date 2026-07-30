# PVE host: Alloy → Vector cutover (native garmr ingest)

Replaces the Grafana Alloy `loki.write` pipeline with Vector shipping garmr's
**native canonical events** to `POST /ingest/v1/events` — no Loki wire format.
Config: [`pve-host.toml`](pve-host.toml).

## Why

garmr is Loki-free by default; the native endpoint (`:3100/ingest/v1/events`)
is the go-forward ingest path. Alloy cannot POST canonical JSON (it speaks only
Loki or OTLP), so the host collector is swapped to Vector, which can.

## Preconditions

- garmr built **without** `loki-compat` (default), so it listens on `ingest_bind`
  (`0.0.0.0:3100`) and no longer on `:3105`.
- Vector installed on the pve host (Debian 13, amd64).
- The current Alloy config kept as a rollback point (already at
  `/etc/alloy/config.alloy.pre-*.bak`).

## Field-name validation (do FIRST — before going live)

Vector's `journald` / `docker_logs` field names must match what `pve-host.toml`
reads (`_SYSTEMD_UNIT`, `PRIORITY`, `SYSLOG_IDENTIFIER`, `container_name`, …).
Verify against the real host before cutover:

```sh
vector validate /etc/vector/pve-host.toml
# Dry-run: tap the shaped output and eyeball host/service/source/severity/message
vector top            # or run vector with the sink swapped for a console sink
```

If a field is named differently on this host, fix the `remap` and re-validate.
Everything the shaper emits must be exactly the 8 keys the endpoint accepts
(`host, service, source, environment, severity, log_type, message, ts`) —
`deny_unknown_fields` rejects anything else.

**Validated on pve (Debian 13, systemd 257, Vector 0.57.0):** `vector validate`
passes and a console-sink dry-run confirmed correct shaping — journald service
derivation + transient-scope collapse, PRIORITY→severity, and the kunai
noise-drop + throttle all produce exactly the 8 allowed keys. Two host-specific
findings baked into the config: `current_boot_only = true` is mandatory on
systemd 250–257, and `since_now = true` avoids re-ingesting the whole current
boot (Alloy already shipped that history; garmr does not de-dup by content).

## Cutover (brief ingest gap; fast rollback)

```sh
# 0. Deploy the native binary (data-safe; keeps /opt/garmr/bin/garmr.bak).
#    From the garmr checkout on the workstation:
GARMR_HOST=root@198.51.100.10 GARMR_FEATURES=semantic GARMR_SKIP_UI=1 ./scripts/deploy.sh
#    ↑ new binary listens on :3100 (native) + :3110 (api); :3105 is gone.

# 1. Install + enable Vector (on pve), config in place, validated.
systemctl enable --now vector

# 2. Confirm native ingest is flowing into garmr BEFORE removing Alloy:
curl -fsS http://127.0.0.1:3100/health/live
#    watch the event count climb via the API (token from /etc/garmr/garmr.env):
#    curl -H "Authorization: Bearer $TOK" 'http://127.0.0.1:3110/api/query' ...

# 3. Stop Alloy once native ingest is confirmed.
systemctl disable --now alloy
```

## Rollback

```sh
# garmr: restore the previous (Loki) binary and restart.
cd /opt/garmr/bin && mv garmr garmr.native && mv garmr.bak garmr && systemctl restart garmr
# collector: stop Vector, bring Alloy back.
systemctl disable --now vector
systemctl enable --now alloy
```

## Notes / limitations

- The endpoint does not decode `Content-Encoding: gzip` yet — Vector ships
  uncompressed (local, small batches).
- `ts` is taken from the source event time; garmr falls back to receive time if
  absent.
- kunai volume control (drop `prctl|mmap_exec|io_uring_sqe`, cap ~80/s) is
  reproduced with a `filter` + `throttle` transform, fail-open on unparseable
  lines.
- Other Alloy shippers (e.g. VM guests fanning in via vmbr1) must each be
  migrated the same way before their `loki.write` targets disappear.
