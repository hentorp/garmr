#!/usr/bin/env bash
# Demo / test harness for the access-audit alert rules (correlations/reg-*.toml).
# Pushes synthetic access-audit lookup events to a garmr Loki-push endpoint so
# the rules fire end-to-end (rule -> case -> triage -> alert), for validating a
# deployment or demonstrating the feature.
#
# GENERIC: point GARMR_LOKI_URL at ANY garmr; every event is clearly marked
# (source=demo-audit, environment=demo, log_type=audit) so it is filterable and
# ages out with retention. No real data is touched.
#
#   GARMR_LOKI_URL   required, e.g. http://127.0.0.1:3105 or http://host:3105
#   DEMO_HOST        the `host` label on the events (default pgdemo)
#   BULK_COUNT       lookups for the bulk actor  (default 55; rule default >=50)
#
# Scenarios (one actor each, so alerts are attributable):
#   anna.andersson  BULK_COUNT ticketed lookups      -> reg-bulk-lookups
#   bjorn.blom      2 lookups, watched=true          -> reg-watchlist (critical)
#   cecilia.carlsson 1 lookup, is_self=true          -> reg-self-lookup
#   david.dahl      4 lookups, NO ticket_ref         -> reg-lookup-without-ticket
#   eva.ek          20 normal ticketed lookups       -> (benign — must NOT alert)
#   frank.falk      3 ticketed lookups               -> reg-off-hours (if now is
#                                                       outside the rule's local
#                                                       working hours)
set -euo pipefail
URL="${GARMR_LOKI_URL:?set GARMR_LOKI_URL, e.g. http://127.0.0.1:3105}"
HOST="${DEMO_HOST:-pgdemo}"
BULK="${BULK_COUNT:-55}"

python3 - "$HOST" "$BULK" <<'PY' | curl -sS -XPOST -H 'Content-Type: application/json' --data-binary @- "$URL/loki/api/v1/push"
import json, sys, time

host, bulk = sys.argv[1], int(sys.argv[2])
now = time.time_ns()
n = 0
def ev(actor, target, ticket=None, watched=False, is_self=False, obj="person"):
    global n
    n += 1
    e = {"db_user": actor, "target_person": target, "object_table": obj,
         "client_addr": "10.0.0.%d" % (10 + (n % 200)), "action": "read"}
    if ticket:  e["ticket_ref"] = ticket
    if watched: e["watched"] = True
    if is_self: e["is_self"] = True
    # spread ~3s/event so all events stay inside every rule window (the tightest
    # is the watchlist rule at 900s) while still looking like real activity
    ts = str(now - n * 3_000_000_000)
    return [ts, json.dumps(e, ensure_ascii=False)]

vals = []
# bulk fisher — many distinct subjects, all ticketed
for i in range(bulk):
    vals.append(ev("anna.andersson", "demo-subj-%04d" % i, ticket="AR-2026-%d" % (1000 + i)))
# watchlist hit (also shares subject demo-subj-0007 with anna, for the person pivot)
vals.append(ev("bjorn.blom", "demo-subj-0007", ticket="AR-2026-7", watched=True))
vals.append(ev("bjorn.blom", "demo-vip-0001", ticket="AR-2026-8", watched=True))
# self access
vals.append(ev("cecilia.carlsson", "demo-cecilia-own", ticket="AR-2026-9", is_self=True))
# access without any justification
for i in range(4):
    vals.append(ev("david.dahl", "demo-subj-9%03d" % i))
# benign baseline — normal volume, all ticketed (must NOT alert)
for i in range(20):
    vals.append(ev("eva.ek", "demo-subj-8%03d" % i, ticket="AR-2026-%d" % (2000 + i)))
# off-hours candidate (fires only if 'now' is outside the rule's working hours)
for i in range(3):
    vals.append(ev("frank.falk", "demo-subj-7%03d" % i, ticket="AR-2026-%d" % (3000 + i)))

payload = {"streams": [{
    "stream": {"host": host, "service": "registerlookup", "source": "demo-audit",
               "environment": "demo", "severity": "info", "log_type": "audit"},
    "values": vals}]}
sys.stdout.write(json.dumps(payload))
sys.stderr.write("pushing %d demo access-audit events (host=%s)\n" % (len(vals), host))
PY

echo
echo "pushed. expected alerts once the correlation loop ticks:"
echo "  reg-bulk-lookups          <- anna.andersson (${BULK} lookups)"
echo "  reg-watchlist (critical)  <- bjorn.blom (watched subject)"
echo "  reg-self-lookup           <- cecilia.carlsson (is_self)"
echo "  reg-lookup-without-ticket <- david.dahl (no ticket_ref)"
echo "  reg-off-hours             <- frank.falk (only if now is off working hours)"
echo "  (eva.ek = benign baseline: must NOT alert)"
