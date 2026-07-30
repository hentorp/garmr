# Shadow evaluation — champion vs challenger (DoD 19)

Status: implemented in Phase E. This is the concrete realization of the learning
plane's principle #4 — *champion/challenger, never in-place* (see
[learning-plane](learning-plane.md)) — for the application-audit **stateful
detector** plane.

A **challenger** is an alternative detector configuration you want to evaluate
against live traffic without letting it touch a single case. When one is
registered, `garmr serve` scores every eligible audit event through **both** the
production config (the *champion*) and the challenger, and records where they
disagree. The champion's output — the findings, the fused cases, the learned
baselines — is **never** altered. There is **no auto-promotion**: the plane
surfaces a recommended decision, a human promotes (or rejects) it through the
normal governed registry flow.

## What a challenger varies

The champion stateful plane runs on `StatefulConfig::default()` (the shipped
thresholds — `require_sensitive`, `seq_run_len`, `denied_min_resources`,
`slow_min_subjects`, `bulk_min_rows`, …). A challenger varies those knobs. It is a
`DetectorConfig` registry record carrying the override under
`spec.extra.stateful` as a **partial** `StatefulConfig` (`#[serde(default)]` —
omit every knob you don't change; the rest fall back to the champion defaults),
live on the **`shadow`** promotion channel.

```jsonc
// spec of a DetectorConfig record registered on the `shadow` channel
{
  "extra": {
    "stateful": {
      "seq_run_len": 8,          // tighter sequential-enumeration trip
      "denied_min_resources": 4  // trip denied-probing on fewer distinct denials
    }
  }
}
```

## Two conditions gate the plane (inert by default)

1. `GARMR_SHADOW` must be set (`1|true|yes|on`). Unset → the whole plane is
   dormant and `finish_event` pays a single `Option::is_none()` check per event.
2. A challenger must be **live** on the `shadow` channel (an audit-bound,
   approved, non-retired promotion — the same `registry::active` fold every other
   governed artifact uses). None live → dormant.

So a build ships inert: deploying the binary changes nothing until an operator
opts in *and* registers a challenger. A challenger runs on its **own** in-memory
detector windows; a bug in it can add a spurious shadow row but can **never**
change a champion detection, a case, or the learned state — the champion findings
are committed *before* the challenger is scored, and the challenger's `observe` is
panic-contained (a panicking challenger only disables the shadow plane).

**Fair start (seeded, not cold).** The challenger is seeded from a clone of the
champion's *current* detector windows, not from empty state. Otherwise a warm
champion catching an in-progress long-horizon episode (low-and-slow needs ~40
distinct subjects over up to 14 days; sequential a 12-step run) would show up as a
spurious `champion_only`/`dangerous_miss` against a cold challenger and push the
recommendation to a false REJECT. The one inherent mid-stream limitation: the
challenger inherits the champion's already-reported episodes, so it is never
*credited* for re-flagging an episode the champion reported before the challenger
was registered. Bump the challenger's version to reset its comparison from zero.

## What it records

Per event where champion and challenger disagree, a `ShadowScore` row (an
in-memory ring, cap 200) captures the actor, object, both detector-id sets, the
`added` (challenger-only) and `removed` (champion-only) ids, and whether a removed
id was a **dangerous miss** (a champion detection of `high`/`critical` base level
the challenger dropped).

The durable **decision signal** is the `ShadowSummary` counters, persisted as one
blob (`app_shadow` table) on the normal flush cadence: `events_scored`,
`diff_events`, `challenger_only`, `champion_only`, `dangerous_misses`. A summary
belonging to a *different* challenger `(name, version)` is discarded on load — a
new challenger always starts its comparison from zero.

## Reading it

- `GET /api/shadow/summary` — the counters + `active_challenger` + a recommended
  decision. Always 200 when the app-audit plane is up (reports `enabled` /
  `active_challenger: null` when dormant, so a caller can tell "off" from "idle").
- `GET /api/shadow/scores?limit=N` — recent disagreement examples (newest first).
- `garmr shadow` — the same summary from the CLI (daemon-first; falls back to the
  persisted blob when `serve` is stopped).

## The recommendation is deliberately conservative

Purely a function of the counters — advice, never an action:

| Condition | Recommendation |
|---|---|
| `dangerous_misses > 0` | **REJECT** — the challenger drops high-severity champion catches |
| else `champion_only > 0` | **REVIEW** — the challenger misses some champion catches (none high-severity) |
| else `challenger_only > 0` | **PROMOTE CANDIDATE** — the challenger strictly adds, drops nothing |
| else | **NEUTRAL** — they agree on every scored event |

## Where the real precision/recall comes from

Live traffic has no ground-truth labels, so precision/recall/FPR/FNR are **not**
computable on it — the live plane surfaces the label-free disagreement signal
above. The labeled numbers come from running **both** configs through the
ground-truthed `garmr synth-eval` harness (DoD 21), which scores over the fused
`Detection` set exactly as `serve` raises cases. Use the two together: `synth-eval`
for the labeled score on known scenarios, the live shadow plane to catch
divergence on real traffic the synthetic corpus doesn't model.

## Promotion (unchanged, human-gated)

When the evidence supports it, promote the challenger config to the `production`
channel through the ordinary governed registry flow (draft → review → activate),
which auto-reloads the enforced plane. The shadow plane never promotes anything on
its own.
