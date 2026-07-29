// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! `GET /api/applications` + `GET /api/applications/:id` — a real application
//! inventory (DoD 4), replacing the old host/event-count inference. It reconciles
//! the **declared** applications (catalog `Application` entries) with the
//! **observed** ones (the Application-kind behavioral baselines the plane learns,
//! plus lakehouse activity) — so an operator sees not just who is active but the
//! governance gaps: **shadow** applications (observed activity, never declared) and
//! **dormant** ones (declared, no activity).
//!
//! The inventory's per-application activity is a SQL `GROUP BY application_name`
//! aggregate over the whole window (NOT a capped scan), so an undeclared app active
//! anywhere in the window still surfaces — the whole point of shadow detection. The
//! per-application detail adds the baseline footprint (what the app touches), top
//! users + objects, and a sensitive-activity summary, from an app-filtered scan.
//! Read-only; declaring an application is a governed registry promotion.

use std::collections::{BTreeSet, HashMap};

use chrono::{DateTime, Utc};
use skade::arrow_array::{Array, Int64Array, StringArray, TimestampMicrosecondArray};

use garmr_baseline::{Dimension, Entity, EntityKind};
use garmr_core::app_audit::Outcome;
use garmr_core::{AuditRecord, Event};

use super::behavioral::{dim_footprint, outcome_failed, outcome_label, top_counts};
use super::*;

const DEFAULT_SCAN_HOURS: i64 = 168;
const MAX_SCAN_HOURS: i64 = 24 * 90;
const SCAN_LIMIT: usize = super::MAX_QUERY_ROWS;
const HISTORY_CAP: usize = 200;
const TOP_N: usize = 10;

/// The categorical dimensions an application's footprint reports (an app baseline
/// aggregates the objects/schemas/etc accessed UNDER that application_name).
const APP_FOOTPRINT_DIMS: &[(Dimension, &str)] = &[
    (Dimension::Object, "objects"),
    (Dimension::Schema, "schemas"),
    (Dimension::Database, "databases"),
    (Dimension::Operation, "operations"),
    (Dimension::QueryFingerprint, "query_fingerprints"),
    (Dimension::Client, "clients"),
    (Dimension::SourceHost, "source_hosts"),
];

/// The whole-window activity of one application, from the SQL aggregate.
#[derive(Default)]
struct AppActivity {
    events: u64,
    distinct_users: u64,
    distinct_objects: u64,
    last: Option<DateTime<Utc>>,
}

/// Per-application activity as a SQL `GROUP BY application_name` aggregate over the
/// FULL window — so the inventory is complete (an undeclared app active anywhere in
/// the window surfaces), not just the newest capped slice. `hours` is a clamped
/// integer; the regexp field extraction mirrors the register-correlation rules
/// (NULLIF nulls a non-matching row so `count(distinct)` doesn't fold it in).
async fn app_activity_sql(
    st: &ApiState,
    hours: i64,
) -> Result<HashMap<String, AppActivity>, (StatusCode, String)> {
    let sql = format!(
        "SELECT regexp_replace(fields, '.*\"application_name\":\"([^\"]+)\".*', '$1') AS app, \
                count(*) AS events, \
                count(DISTINCT NULLIF(regexp_replace(fields, '.*\"db_user\":\"([^\"]+)\".*', '$1'), fields)) AS users, \
                count(DISTINCT NULLIF(regexp_replace(fields, '.*\"object_name\":\"([^\"]+)\".*', '$1'), fields)) AS objects, \
                max(event_ts) AS last \
         FROM events \
         WHERE event_ts >= now() - INTERVAL '{hours} hour' AND log_type = 'audit' \
               AND fields LIKE '%\"application_name\":%' \
         GROUP BY 1"
    );
    let fut = st.store.events.sql(sql);
    let batches = match tokio::time::timeout(
        std::time::Duration::from_secs(super::QUERY_TIMEOUT_SECS),
        fut,
    )
    .await
    {
        Ok(r) => r.map_err(oops)?,
        Err(_) => {
            return Err((
                StatusCode::REQUEST_TIMEOUT,
                "application activity aggregate timed out — narrow the window".to_string(),
            ))
        }
    };
    let mut out: HashMap<String, AppActivity> = HashMap::new();
    for b in &batches {
        let app = b
            .column_by_name("app")
            .and_then(|c| c.as_any().downcast_ref::<StringArray>());
        let events = b
            .column_by_name("events")
            .and_then(|c| c.as_any().downcast_ref::<Int64Array>());
        let users = b
            .column_by_name("users")
            .and_then(|c| c.as_any().downcast_ref::<Int64Array>());
        let objects = b
            .column_by_name("objects")
            .and_then(|c| c.as_any().downcast_ref::<Int64Array>());
        let last = b
            .column_by_name("last")
            .and_then(|c| c.as_any().downcast_ref::<TimestampMicrosecondArray>());
        let iv = |a: Option<&Int64Array>, i: usize| {
            a.filter(|x| !x.is_null(i)).map(|x| x.value(i).max(0) as u64).unwrap_or(0)
        };
        for i in 0..b.num_rows() {
            let Some(name) = app.filter(|x| !x.is_null(i)).map(|x| x.value(i)) else {
                continue;
            };
            if name.is_empty() {
                continue;
            }
            out.insert(
                name.to_string(),
                AppActivity {
                    events: iv(events, i),
                    distinct_users: iv(users, i),
                    distinct_objects: iv(objects, i),
                    last: last
                        .filter(|x| !x.is_null(i))
                        .and_then(|x| DateTime::from_timestamp_micros(x.value(i))),
                },
            );
        }
    }
    Ok(out)
}

/// The governance classification for an application: `shadow` = observed but never
/// declared (a possible undeclared/shadow app); `dormant` = declared but with no
/// observed activity or baseline. Pure, unit-tested.
fn shadow_dormant(declared: bool, observed: bool) -> (bool, bool) {
    (observed && !declared, declared && !observed)
}

/// GET /api/applications — the reconciled application inventory. 404 when the
/// app-audit plane is disabled. Paginated.
pub(super) async fn applications(
    State(st): State<ApiState>,
    Query(p): Query<HashMap<String, String>>,
) -> ApiResult {
    let Some(aa) = &st.app_audit else {
        return Err((
            StatusCode::NOT_FOUND,
            "the application-audit plane is disabled (set detect.app_audit_enabled = true)"
                .to_string(),
        ));
    };
    let hours = DEFAULT_SCAN_HOURS;
    let activity = app_activity_sql(&st, hours).await?;

    let catalog = aa.catalog_snapshot();
    let store = aa.baseline_snapshot();
    let declared: HashMap<String, garmr_catalog::AppDecl> = catalog
        .entries
        .iter()
        .filter_map(|e| e.application_declaration().map(|d| (d.name.clone(), d)))
        .collect();
    let baselines: HashMap<&str, &garmr_baseline::BaselineProfile> = store
        .profiles()
        .filter(|pf| pf.entity.kind == EntityKind::Application)
        .map(|pf| (pf.entity.id.as_str(), pf))
        .collect();

    let mut names: BTreeSet<String> = BTreeSet::new();
    names.extend(declared.keys().cloned());
    names.extend(baselines.keys().map(|s| s.to_string()));
    names.extend(activity.keys().cloned());

    let mut observed_total = 0u64;
    let mut rows: Vec<Value> = names
        .iter()
        .map(|name| {
            let decl = declared.get(name);
            let bl = baselines.get(name.as_str());
            let act = activity.get(name);
            let events = act.map_or(0, |a| a.events);
            let is_declared = decl.is_some();
            let observed = bl.is_some() || events > 0;
            if observed {
                observed_total += 1;
            }
            let (shadow, dormant) = shadow_dormant(is_declared, observed);
            let baseline = bl.map(|pf| {
                json!({
                    "state": format!("{:?}", pf.state),
                    "maturity": format!("{:?}", store.maturity(&Entity::new(EntityKind::Application, name.as_str()))),
                    "observations": pf.observation_count,
                })
            });
            json!({
                "name": name,
                "declared": is_declared,
                "owner": decl.and_then(|d| d.owner.clone()),
                "team": decl.map(|d| d.team.clone()).unwrap_or_default(),
                "business_purpose": decl.and_then(|d| d.business_purpose.clone()),
                "observed": observed,
                "shadow": shadow,
                "dormant": dormant,
                "baseline": baseline,
                "activity": {
                    "events": events,
                    "distinct_users": act.map_or(0, |a| a.distinct_users),
                    "distinct_objects": act.map_or(0, |a| a.distinct_objects),
                    "last": act.and_then(|a| a.last),
                },
            })
        })
        .collect();

    // Shadow apps (undeclared but active) first — the governance signal — then the
    // most active, then by name.
    rows.sort_by(|a, b| {
        let sh = |r: &Value| r["shadow"].as_bool().unwrap_or(false);
        sh(b)
            .cmp(&sh(a))
            .then_with(|| {
                b["activity"]["events"]
                    .as_u64()
                    .unwrap_or(0)
                    .cmp(&a["activity"]["events"].as_u64().unwrap_or(0))
            })
            .then_with(|| a["name"].as_str().unwrap_or("").cmp(b["name"].as_str().unwrap_or("")))
    });

    let mut out = Page::from_query(&p).envelope("applications", rows);
    out["window_hours"] = json!(hours);
    out["declared_total"] = json!(declared.len());
    out["baselined_total"] = json!(baselines.len());
    out["observed_total"] = json!(observed_total);
    Ok(Json(out))
}

/// One projected access to an application, owned so it outlives the reconstructed
/// `Event`. `object` uses `object_name` only, matching the baseline's `objects`
/// dimension (so the footprint and top-objects draw from the same value space).
struct AppAccess {
    ts: DateTime<Utc>,
    actor: String,
    object: Option<String>,
    database: Option<String>,
    operation: Option<String>,
    outcome: &'static str,
    export: bool,
    privilege: bool,
    administrative: bool,
    bulk: bool,
    denied: bool,
    failed: bool,
    event_id: Option<String>,
}

/// Project the (already app-filtered) scan window to the audit accesses that carry
/// the target application name. `app` is the resolved application id.
fn project_app_accesses(events: &[Event], app: &str) -> Vec<AppAccess> {
    events
        .iter()
        .filter(|ev| AuditRecord::is_audit_event(ev))
        .filter_map(|ev| {
            let rec = AuditRecord::from_event(ev);
            if rec.context.application_name.as_deref() != Some(app) {
                return None;
            }
            let a = &rec.action;
            Some(AppAccess {
                ts: ev.ts,
                actor: rec.actor.actor_id.clone(),
                object: a.object_name.clone(),
                database: rec.context.database.clone(),
                operation: a.operation.clone().or_else(|| a.action.clone()),
                outcome: outcome_label(&a.outcome),
                export: a.export_operation,
                privilege: a.privilege_operation,
                administrative: a.administrative_operation,
                bulk: a.bulk_operation,
                denied: matches!(a.outcome, Outcome::Denied),
                failed: outcome_failed(&a.outcome),
                event_id: ev.fields.get("event_id").cloned(),
            })
        })
        .collect()
}

/// The reserved-word flags an access raised (denied included, matching the user
/// view). `failed` selects a row for the recent list but is not itself a flag.
fn access_flags(a: &AppAccess) -> Vec<&'static str> {
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

/// Summarise an application's accesses over the window: the sensitive-signal
/// counters, distinct users, latest, plus a capped newest-first recent list. Pure,
/// so it is unit-testable (the async scan/projection is the only untested glue).
fn summarize_app_activity(hits: &[AppAccess]) -> Value {
    let (mut exports, mut privileged, mut administrative, mut bulk, mut denied, mut failed) =
        (0u64, 0u64, 0u64, 0u64, 0u64, 0u64);
    let mut users: BTreeSet<&str> = BTreeSet::new();
    let mut last: Option<DateTime<Utc>> = None;
    for a in hits {
        exports += a.export as u64;
        privileged += a.privilege as u64;
        administrative += a.administrative as u64;
        bulk += a.bulk as u64;
        denied += a.denied as u64;
        failed += a.failed as u64;
        if !a.actor.is_empty() {
            users.insert(a.actor.as_str());
        }
        last = Some(last.map_or(a.ts, |l| l.max(a.ts)));
    }
    let recent: Vec<Value> = hits
        .iter()
        .take(HISTORY_CAP)
        .map(|a| {
            json!({
                "ts": a.ts,
                "actor": a.actor,
                "object": a.object,
                "operation": a.operation,
                "outcome": a.outcome,
                "flags": access_flags(a),
                "event_id": a.event_id,
            })
        })
        .collect();
    json!({
        "activity_summary": {
            "events": hits.len(),
            "distinct_users": users.len(),
            "last": last,
            "exports": exports,
            "privileged": privileged,
            "administrative": administrative,
            "bulk": bulk,
            "denied": denied,
            "failed": failed,
            "recent_truncated": hits.len() > HISTORY_CAP,
        },
        "recent": recent,
    })
}

/// Escape a value for a single-quoted SQL string literal + `LIKE` metacharacters
/// (with `ESCAPE '\'`), so an application id from the path can be matched safely
/// (quote-doubling defeats injection; `%`/`_`/`\` escaping keeps the match exact).
fn app_like(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_")
        .replace('\'', "''")
}

/// GET /api/applications/:id — one application: its declaration (if any), the
/// baseline footprint, top users + objects, a sensitive-activity summary and recent
/// accesses (from an app-filtered scan, so a low-traffic app isn't starved). 404
/// when nothing (no declaration, no baseline, no activity) names the app.
pub(super) async fn application_by_id(
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
    let hours = p
        .get("hours")
        .and_then(|s| s.parse::<i64>().ok())
        .unwrap_or(DEFAULT_SCAN_HOURS)
        .clamp(1, MAX_SCAN_HOURS);
    // App-filtered scan (safe, escaped LIKE) so this app's window isn't starved by
    // other traffic.
    let where_app = format!(
        " AND fields LIKE '%\"application_name\":\"{}\"%' ESCAPE '\\'",
        app_like(&id)
    );
    let events = super::policies::scan_audit_events_where(&st, hours, SCAN_LIMIT, &where_app).await?;
    let scanned = events.len();
    let hits = project_app_accesses(&events, &id);

    let catalog = aa.catalog_snapshot();
    let store = aa.baseline_snapshot();
    let decl = catalog
        .entries
        .iter()
        .find_map(|e| e.application_declaration().filter(|d| d.name == id));
    let entity = Entity::new(EntityKind::Application, id.as_str());
    let profile = store.get(&entity);

    if decl.is_none() && profile.is_none() && hits.is_empty() {
        return Err((
            StatusCode::NOT_FOUND,
            format!("no application named {id:?} is declared, learned, or active"),
        ));
    }

    let observed = profile.is_some() || !hits.is_empty();
    let (shadow, dormant) = shadow_dormant(decl.is_some(), observed);

    let footprint = profile.map(|pf| {
        let mut m = serde_json::Map::new();
        for (dim, label) in APP_FOOTPRINT_DIMS {
            let v = pf
                .categorical
                .get(dim)
                .map(dim_footprint)
                .unwrap_or_else(|| json!({ "distinct": 0, "dropped": 0, "top": [] }));
            m.insert(label.to_string(), v);
        }
        Value::Object(m)
    });
    let baseline = profile.map(|pf| {
        json!({
            "state": format!("{:?}", pf.state),
            "maturity": format!("{:?}", store.maturity(&entity)),
            "observations": pf.observation_count,
            "first_seen": pf.first_seen,
            "last_seen": pf.last_seen,
            "span_days": pf.span().num_days(),
        })
    });

    let top_users = top_counts(
        hits.iter().filter(|a| !a.actor.is_empty()).map(|a| a.actor.clone()),
        TOP_N,
    );
    let top_objects = top_counts(hits.iter().filter_map(|a| a.object.clone()), TOP_N);
    let top_databases = top_counts(hits.iter().filter_map(|a| a.database.clone()), TOP_N);

    let summary = summarize_app_activity(&hits);
    Ok(Json(json!({
        "name": id,
        "declared": decl.is_some(),
        "observed": observed,
        "shadow": shadow,
        "dormant": dormant,
        "declaration": decl,
        "baseline": baseline,
        "footprint": footprint,
        "window_hours": hours,
        "scanned": scanned,
        "truncated": scanned >= SCAN_LIMIT,
        "activity_summary": summary["activity_summary"].clone(),
        "top_users": top_users,
        "top_objects": top_objects,
        "top_databases": top_databases,
        "recent": summary["recent"].clone(),
    })))
}

#[cfg(test)]
mod tests {
    use super::*;
    use garmr_core::app_audit::keys;
    use std::collections::BTreeMap;

    fn ts(secs: i64) -> DateTime<Utc> {
        DateTime::<Utc>::from_timestamp(secs, 0).unwrap()
    }

    fn acc(actor: &str, object: Option<&str>, export: bool, denied: bool, secs: i64) -> AppAccess {
        AppAccess {
            ts: ts(secs),
            actor: actor.into(),
            object: object.map(str::to_string),
            database: None,
            operation: None,
            outcome: if denied { "denied" } else { "success" },
            export,
            privilege: false,
            administrative: false,
            bulk: false,
            denied,
            failed: false,
            event_id: None,
        }
    }

    /// An `Event` in the audit shape carrying an application name (+ optional actor).
    fn app_event(app: &str, actor: &str) -> Event {
        let mut fields = BTreeMap::new();
        fields.insert(keys::APPLICATION_NAME.to_string(), app.to_string());
        if !actor.is_empty() {
            fields.insert(keys::ACTOR.to_string(), actor.to_string());
        }
        Event {
            ts: ts(0),
            host: "db01".into(),
            service: "postgres".into(),
            source: "pgaudit".into(),
            environment: "prod".into(),
            severity: "info".into(),
            log_type: "audit".into(),
            message: String::new(),
            fields,
        }
    }

    #[test]
    fn shadow_dormant_classifies_governance_state() {
        assert_eq!(shadow_dormant(false, true), (true, false)); // observed, undeclared → shadow
        assert_eq!(shadow_dormant(true, false), (false, true)); // declared, unobserved → dormant
        assert_eq!(shadow_dormant(true, true), (false, false));
        assert_eq!(shadow_dormant(false, false), (false, false));
    }

    #[test]
    fn project_app_accesses_keeps_only_this_apps_audit_events() {
        let mut non_audit = app_event("warehouse", "anna");
        non_audit.log_type = "endpoint".into();
        non_audit.fields.clear(); // no actor/object/app → not an audit event
        let events = vec![
            app_event("warehouse", "anna"),
            app_event("portal", "bob"), // a different app → dropped for `warehouse`
            non_audit,                   // not an audit event → dropped
        ];
        let hits = project_app_accesses(&events, "warehouse");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].actor, "anna");
    }

    #[test]
    fn summarize_app_activity_counts_signals_users_and_caps_recent() {
        let hits = vec![
            acc("anna", Some("raw.persons"), true, false, 100), // export
            acc("anna", Some("raw.persons"), false, true, 300), // denied, later, same user
            acc("bob", Some("curated.orders"), false, false, 200),
            acc("", None, false, false, 250), // empty actor: counted in events, not a user
        ];
        let v = summarize_app_activity(&hits);
        let s = &v["activity_summary"];
        assert_eq!(s["events"], 4);
        assert_eq!(s["distinct_users"], 2, "anna + bob; empty actor excluded");
        assert_eq!(s["exports"], 1);
        assert_eq!(s["denied"], 1);
        assert_eq!(s["last"], json!(ts(300)));
        assert_eq!(s["recent_truncated"], false);
        assert_eq!(v["recent"].as_array().unwrap().len(), 4);
        // The denied access carries a "denied" flag (parity with the user view).
        let denied_row = v["recent"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["outcome"] == "denied")
            .unwrap();
        assert_eq!(denied_row["flags"][0], "denied");
    }
}