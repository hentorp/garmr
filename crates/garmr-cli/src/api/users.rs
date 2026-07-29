// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! `GET /api/users/:id` — a rich per-user **behavioral profile** (DoD 3). The
//! behavioral footprint the plane already learns is exposed here for the first
//! time: for each categorical dimension (the client apps, objects/tables, schemas,
//! databases, query fingerprints, operations, source hosts, subject types the user
//! touches) the distinct values with their hit counts + first/last-seen, plus the
//! hour-of-day / weekday activity histogram and the rows/bytes-read distributions —
//! all read straight from the in-memory baseline snapshot (no scan). On top of that
//! a bounded lakehouse scan summarises **sensitive activity** (exports, privilege,
//! administrative and bulk operations, denials) with recent evidence.
//!
//! Read-only, and — like the rest of the baseline surface — served from the daemon
//! that owns the authoritative store, never a second reader.

use chrono::{DateTime, Utc};

use garmr_baseline::{Dimension, Entity, EntityKind, NumericStat};
use garmr_core::app_audit::Outcome;
use garmr_core::AuditRecord;

use super::behavioral::{dim_footprint, outcome_label};
use super::*;

/// Default sensitive-activity window (7 days), overridable via `?hours=`.
const DEFAULT_SCAN_HOURS: i64 = 168;
const MAX_SCAN_HOURS: i64 = 24 * 90;
/// Cap on the recent-sensitive-access evidence list.
const RECENT_SENSITIVE_CAP: usize = 50;

/// The categorical dimensions the footprint reports, with the JSON label each maps
/// to (the `Dimension` → user-facing footprint key).
const FOOTPRINT_DIMS: &[(Dimension, &str)] = &[
    (Dimension::Client, "clients"),
    (Dimension::Object, "objects"),
    (Dimension::Schema, "schemas"),
    (Dimension::Database, "databases"),
    (Dimension::QueryFingerprint, "query_fingerprints"),
    (Dimension::Operation, "operations"),
    (Dimension::SourceHost, "source_hosts"),
    (Dimension::SubjectType, "subject_types"),
];

/// The actor kinds this endpoint can faithfully profile — ONLY those whose baseline
/// entity id equals the `actor_id` on an audit record, so the sensitive-activity
/// scan (which filters by `actor_id`) is correct. Role / Application / PeerGroup
/// baselines are keyed by role/app/group NAME, not `actor_id`, so an actor-filtered
/// scan would silently return all-zeros for them; those belong to the peers /
/// applications surfaces, not here.
fn parse_user_kind(s: &str) -> Option<EntityKind> {
    Some(
        match s
            .trim()
            .to_ascii_lowercase()
            .replace(['-', '_'], "")
            .as_str()
        {
            "user" => EntityKind::User,
            "serviceaccount" => EntityKind::ServiceAccount,
            _ => return None,
        },
    )
}

fn numeric_json(n: &NumericStat) -> Value {
    json!({
        "count": n.count,
        "mean": n.mean(),
        "stddev": n.stddev(),
        "median": n.median(),
        "min": n.min,
        "max": n.max,
    })
}

/// One of the user's accesses in the scan window, projected to the sensitive-
/// activity signals. Owned so it is independent of the reconstructed `Event`.
struct UserAccess {
    ts: DateTime<Utc>,
    export: bool,
    privilege: bool,
    administrative: bool,
    bulk: bool,
    denied: bool,
    failed: bool,
    outcome: &'static str,
    operation: Option<String>,
    object: Option<String>,
    event_id: Option<String>,
}

/// The reserved-word flags an access carries (for the evidence row + the recent
/// filter). `denied` is a flag; `failed` selects the row but is not itself a flag.
fn access_flags(a: &UserAccess) -> Vec<&'static str> {
    let mut f = Vec::new();
    if a.export {
        f.push("export");
    }
    if a.privilege {
        f.push("privilege");
    }
    if a.administrative {
        f.push("administrative");
    }
    if a.bulk {
        f.push("bulk");
    }
    if a.denied {
        f.push("denied");
    }
    f
}

/// Summarise the user's sensitive activity over the window: per-signal counts plus
/// a capped, newest-first list of the notable accesses (any flag, or a failure).
/// Pure over the projected accesses so it is unit-testable. `truncated` marks that
/// the underlying scan hit its global row cap, so an all-zero summary must NOT be
/// read as an authoritative "no sensitive activity" — older activity in the window
/// may have been beyond the cap.
fn summarize_sensitive(
    accesses: &[UserAccess],
    window_hours: i64,
    scanned: usize,
    truncated: bool,
) -> Value {
    let (mut exports, mut privileged, mut administrative, mut bulk, mut denied, mut failed) =
        (0u64, 0u64, 0u64, 0u64, 0u64, 0u64);
    let mut recent = Vec::new();
    for a in accesses {
        if a.export {
            exports += 1;
        }
        if a.privilege {
            privileged += 1;
        }
        if a.administrative {
            administrative += 1;
        }
        if a.bulk {
            bulk += 1;
        }
        if a.denied {
            denied += 1;
        }
        if a.failed {
            failed += 1;
        }
        let flags = access_flags(a);
        if (!flags.is_empty() || a.failed) && recent.len() < RECENT_SENSITIVE_CAP {
            recent.push(json!({
                "ts": a.ts,
                "operation": a.operation,
                "object": a.object,
                "outcome": a.outcome,
                "flags": flags,
                "event_id": a.event_id,
            }));
        }
    }
    json!({
        "window_hours": window_hours,
        "scanned": scanned,
        "truncated": truncated,
        "user_events": accesses.len(),
        "exports": exports,
        "privileged": privileged,
        "administrative": administrative,
        "bulk": bulk,
        "denied": denied,
        "failed": failed,
        "recent": recent,
    })
}

/// GET /api/users/:id — the per-user behavioral profile. `?kind=` (default: try
/// user then service-account) selects the entity kind; `?hours=` bounds the
/// sensitive-activity scan. 404 when the plane is disabled or the user has no
/// learned baseline.
pub(super) async fn user_by_id(
    State(st): State<ApiState>,
    Path(id): Path<String>,
    Query(p): Query<HashMap<String, String>>,
) -> ApiResult {
    let Some(aa) = &st.app_audit else {
        return Err((
            StatusCode::NOT_FOUND,
            "the application-audit plane is disabled (set detect.app_audit_enabled = true)"
                .to_string(),
        ));
    };
    let store = aa.baseline_snapshot();

    // Resolve the entity: an explicit ?kind=, else the people-kinds in order.
    let kinds: Vec<EntityKind> = match p.get("kind") {
        Some(k) => vec![parse_user_kind(k)
            .ok_or_else(|| bad("unknown ?kind= (user|service-account only)"))?],
        None => vec![EntityKind::User, EntityKind::ServiceAccount],
    };
    let resolved = kinds.iter().find_map(|k| {
        let e = Entity::new(*k, id.as_str());
        store.get(&e).map(|pf| (e, pf))
    });
    let Some((entity, profile)) = resolved else {
        return Err((
            StatusCode::NOT_FOUND,
            format!("no learned baseline for user {id:?}"),
        ));
    };

    // Footprint — the distinct values per categorical dimension (from the baseline).
    let mut footprint = serde_json::Map::new();
    for (dim, label) in FOOTPRINT_DIMS {
        let v = profile
            .categorical
            .get(dim)
            .map(dim_footprint)
            .unwrap_or_else(|| json!({ "distinct": 0, "dropped": 0, "top": [] }));
        footprint.insert(label.to_string(), v);
    }

    // Time-of-day + weekday histograms (both live on the HourOfDay tracker).
    let time_of_day = profile
        .temporal
        .get(&Dimension::HourOfDay)
        .map(|t| json!({ "hour": t.hour, "weekday": t.weekday, "total": t.total }))
        .unwrap_or(Value::Null);

    // Volume distributions.
    let mut volume = serde_json::Map::new();
    if let Some(n) = profile.numeric.get(&Dimension::RowsRead) {
        volume.insert("rows_read".to_string(), numeric_json(n));
    }
    if let Some(n) = profile.numeric.get(&Dimension::BytesRead) {
        volume.insert("bytes_read".to_string(), numeric_json(n));
    }

    // Sensitive-activity summary from a bounded recent scan, filtered to this user.
    let hours = p
        .get("hours")
        .and_then(|s| s.parse::<i64>().ok())
        .unwrap_or(DEFAULT_SCAN_HOURS)
        .clamp(1, MAX_SCAN_HOURS);
    let events = super::policies::scan_audit_events(&st, hours, super::MAX_QUERY_ROWS).await?;
    let scanned = events.len();
    let accesses: Vec<UserAccess> = events
        .iter()
        .filter(|ev| AuditRecord::is_audit_event(ev))
        .filter_map(|ev| {
            let rec = AuditRecord::from_event(ev);
            if rec.actor.actor_id != id {
                return None;
            }
            let a = &rec.action;
            Some(UserAccess {
                ts: ev.ts,
                export: a.export_operation,
                privilege: a.privilege_operation,
                administrative: a.administrative_operation,
                bulk: a.bulk_operation,
                denied: matches!(a.outcome, Outcome::Denied),
                failed: matches!(a.outcome, Outcome::Failure | Outcome::Error),
                outcome: outcome_label(&a.outcome),
                operation: a.operation.clone().or_else(|| a.action.clone()),
                object: a.object_name.clone().or_else(|| a.resource_path.clone()),
                event_id: ev.fields.get("event_id").cloned(),
            })
        })
        .collect();
    // The scan hits a global row cap; if it saturated, this user's window may not be
    // fully covered, so surface it rather than let an empty summary read as "clean".
    let truncated = scanned >= super::MAX_QUERY_ROWS;
    let sensitive_activity = summarize_sensitive(&accesses, hours, scanned, truncated);

    // Bind these before the response so `entity` is read whole (maturity borrows it,
    // kind copies it) before `entity.id` is moved into the JSON.
    let maturity = format!("{:?}", store.maturity(&entity));
    let kind = format!("{:?}", entity.kind);
    Ok(Json(json!({
        "id": entity.id,
        "kind": kind,
        "state": format!("{:?}", profile.state),
        "maturity": maturity,
        "observations": profile.observation_count,
        "first_seen": profile.first_seen,
        "last_seen": profile.last_seen,
        "span_days": profile.span().num_days(),
        "distinct_sources": profile.distinct_sources.len(),
        "data_quality_degraded": profile.data_quality_degraded,
        "footprint": footprint,
        "time_of_day": time_of_day,
        "volume": volume,
        "sensitive_activity": sensitive_activity,
    })))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ts(secs: i64) -> DateTime<Utc> {
        DateTime::<Utc>::from_timestamp(secs, 0).unwrap()
    }

    fn ua(export: bool, privilege: bool, denied: bool, failed: bool) -> UserAccess {
        UserAccess {
            ts: ts(0),
            export,
            privilege,
            administrative: false,
            bulk: false,
            denied,
            failed,
            outcome: if denied { "denied" } else { "success" },
            operation: None,
            object: None,
            event_id: None,
        }
    }

    #[test]
    fn parse_user_kind_accepts_only_actor_kinds() {
        for s in ["user", "User", "USER"] {
            assert_eq!(parse_user_kind(s), Some(EntityKind::User));
        }
        for s in ["service-account", "service_account", "ServiceAccount"] {
            assert_eq!(parse_user_kind(s), Some(EntityKind::ServiceAccount));
        }
        // Non-actor kinds are rejected — the actor-filtered scan can't profile them.
        for s in ["role", "group", "application", "app", "peer-group"] {
            assert_eq!(parse_user_kind(s), None, "{s} must be rejected");
        }
    }

    #[test]
    fn numeric_json_maps_each_field_to_its_accessor() {
        let n = NumericStat {
            count: 4,
            sum: 10.0,
            sum_sq: 30.0,
            min: 1.0,
            max: 4.0,
            sample: vec![1.0, 2.0, 3.0, 4.0],
        };
        let v = numeric_json(&n);
        assert_eq!(v["count"], 4);
        assert_eq!(v["mean"], 2.5);
        assert_eq!(v["median"], 2.5);
        assert_eq!(v["min"], 1.0);
        assert_eq!(v["max"], 4.0);
    }

    #[test]
    fn summarize_sensitive_counts_signals_and_selects_notable_recent() {
        let accesses = vec![
            ua(true, false, false, false),  // export → counted + recent
            ua(false, true, false, false),  // privilege → counted + recent
            ua(false, false, true, false),  // denied → counted + recent
            ua(false, false, false, true),  // plain failure → recent (no flag)
            ua(false, false, false, false), // normal → NOT recent
        ];
        let v = summarize_sensitive(&accesses, 168, 999, false);
        assert_eq!(v["user_events"], 5);
        assert_eq!(v["scanned"], 999);
        assert_eq!(v["window_hours"], 168);
        assert_eq!(v["truncated"], false);
        assert_eq!(v["exports"], 1);
        assert_eq!(v["privileged"], 1);
        assert_eq!(v["denied"], 1);
        assert_eq!(v["failed"], 1);
        // export, privilege, denied, plain-failure → 4 recent; the normal access is excluded.
        assert_eq!(v["recent"].as_array().unwrap().len(), 4);
    }

    #[test]
    fn summarize_sensitive_caps_recent_but_never_the_counters() {
        // 60 exports: the counters must reflect all 60 while `recent` caps at 50.
        let accesses: Vec<UserAccess> = (0..60).map(|_| ua(true, false, false, false)).collect();
        let v = summarize_sensitive(&accesses, 168, 60, true);
        assert_eq!(v["user_events"], 60);
        assert_eq!(v["exports"], 60, "counters are not capped by the evidence list");
        assert_eq!(v["truncated"], true);
        assert_eq!(v["recent"].as_array().unwrap().len(), RECENT_SENSITIVE_CAP);
    }

    #[test]
    fn access_flags_lists_every_raised_signal() {
        let mut a = ua(true, true, true, false);
        a.administrative = true;
        a.bulk = true;
        assert_eq!(
            access_flags(&a),
            vec!["export", "privilege", "administrative", "bulk", "denied"]
        );
        assert!(access_flags(&ua(false, false, false, true)).is_empty());
    }
}