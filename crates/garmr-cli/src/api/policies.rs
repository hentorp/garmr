// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! `GET /api/policies` + `GET /api/policies/:id` — read-only exposure of the
//! access policies the application-audit plane already loads from
//! `detect.policies_dir`. Before this, the policy engine evaluated policies but
//! the console had no way to SEE them; Phase 13 needs a Policies area, so this is
//! the smallest read surface that makes the loaded rules inspectable.
//!
//! Reads are strictly read-only. The one POST — `/api/policies/simulate` — is a
//! **non-mutating** backtest: it replays a *draft* policy over recent historical
//! accesses and reports its blast radius. Policy *authoring* (persisting a new
//! policy) stays a file + review + `registry` promotion flow (an audited,
//! out-of-band change); simulate changes nothing, so it is analyst-tier, not an
//! admin write. Policy *violations* are already materialised as triage cases by
//! the plane (e.g. `app-forbidden-access`, `app-missing-justification`), which
//! the console cross-links from `/api/cases`.

use std::collections::BTreeMap;

use axum::extract::{Path, State};
use axum::Json;
use chrono::DateTime;
use serde::Deserialize;
use skade::arrow_array::{Array, RecordBatch, StringArray, TimestampMicrosecondArray};

use garmr_core::{ApprovalState, AuditRecord, Event, RegistryKind, RegistryRecord, RegistrySource};
use garmr_policy::{context_from_event, policy_set_digest, simulate as run_simulate, Policy};
use garmr_store::state::RegisterOutcome;

use super::auth::check_admin;
use super::{bad, oops, ApiResult, ApiState, QUERY_TIMEOUT_SECS};

/// Load every `*.toml` policy in `dir` (one `Policy` per file), newest-invalid
/// skipped loudly. Mirrors the pipeline's loader so the console sees exactly the
/// set the engine enforces.
fn load(dir: &std::path::Path) -> Vec<Policy> {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut out: Vec<Policy> = rd
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("toml"))
        .filter_map(|p| {
            std::fs::read_to_string(&p)
                .ok()
                .and_then(|s| toml::from_str::<Policy>(&s).ok())
        })
        .collect();
    // Stable, meaningful order: most restrictive effect first, then priority.
    out.sort_by(|a, b| {
        b.effect
            .is_restrictive()
            .cmp(&a.effect.is_restrictive())
            .then(b.priority.cmp(&a.priority))
            .then(a.id.cmp(&b.id))
    });
    out
}

/// The access-policy set to display: the **enforced** set the app-audit plane
/// actually evaluates — so it matches what `/api/resources` reports as policy
/// coverage and honors the registry / hot-reload gate — falling back to the file
/// loader only when the plane is disabled. This is what keeps the Policies view
/// and the Resources view from disagreeing about which rules are live.
fn enforced_policies(st: &ApiState) -> (Vec<Policy>, &'static str) {
    match &st.app_audit {
        Some(aa) => (aa.policy_snapshot(), "enforced"),
        None => (load(&st.cfg.detect.policies_dir), "files"),
    }
}

/// `GET /api/policies` — the enforced access-policy set + a content digest (the
/// same digest the engine pins, so the console can show which policy version is
/// live).
pub(super) async fn policies(State(st): State<ApiState>) -> ApiResult {
    let (all, source) = enforced_policies(&st);
    let digest = policy_set_digest(&all);
    let enabled = all.iter().filter(|p| p.enabled).count();
    Ok(axum::Json(serde_json::json!({
        "policies": all,
        "count": all.len(),
        "enabled": enabled,
        "digest": digest,
        "source": source,
        "dir": st.cfg.detect.policies_dir.display().to_string(),
    })))
}

/// `GET /api/policies/:id` — one policy by id. 404 with a clear message when the
/// id is unknown (a useful not-found state for a deep link).
pub(super) async fn policy_by_id(State(st): State<ApiState>, Path(id): Path<String>) -> ApiResult {
    let (all, _) = enforced_policies(&st);
    match all.into_iter().find(|p| p.id == id) {
        Some(p) => Ok(axum::Json(serde_json::json!({ "policy": p }))),
        None => Err((
            axum::http::StatusCode::NOT_FOUND,
            format!("no policy with id {id:?}"),
        )),
    }
}

// -------------------------------------------------------------------------
// POST /api/policies/simulate — backtest a draft policy over recent history
// -------------------------------------------------------------------------

const SIMULATE_DEFAULT_HOURS: i64 = 168; // 7 days
const SIMULATE_MAX_HOURS: i64 = 24 * 90; // 90 days
const SIMULATE_DEFAULT_LIMIT: usize = 5_000;
const SIMULATE_MAX_LIMIT: usize = 20_000;

/// Body of `POST /admin/policies/draft`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PolicyDraftReq {
    /// The policy to draft (a new version of `policy.id`).
    policy: Policy,
    #[serde(default)]
    rationale: String,
}

/// `POST /admin/policies/draft` — register a new DRAFT version of a policy on the
/// governed registry (Phase A `Policy` kind). Server-side: validate the policy,
/// compute its content digest, auto-assign the next version for that id, and
/// register an audited Draft record. Activation is a separate promote
/// (`POST /admin/registry/promote` on `kind=policy`); this only drafts — the draft
/// is inert until promoted. Admin-gated, fail-closed audited.
pub(super) async fn draft(
    State(st): State<ApiState>,
    headers: axum::http::HeaderMap,
    Json(req): Json<PolicyDraftReq>,
) -> ApiResult {
    let who = check_admin(&st, &headers)?;
    req.policy.validate().map_err(bad)?;
    let name = req.policy.id.clone();
    // A per-policy content digest (NOT the enabled-set digest, which would collapse
    // a disabled draft to the empty-set constant and defeat the immutability guard).
    let digest = garmr_policy::policy_digest(&req.policy);
    let spec = serde_json::to_value(&req.policy).map_err(oops)?;

    // Auto-version = max existing integer version + 1. Read→compute→write isn't one
    // transaction, so two concurrent drafts can pick the same version; the store's
    // (kind,name,version) uniqueness rejects the loser as a Conflict — retry with a
    // fresh max so a race yields the NEXT version instead of a spurious error.
    const MAX_TRIES: u32 = 5;
    for attempt in 0..MAX_TRIES {
        let existing = st
            .store
            .state
            .records_for_name(RegistryKind::Policy, &name)
            .map_err(oops)?;
        let prev = existing
            .iter()
            .filter_map(|r| r.version.parse::<u32>().ok())
            .max();
        let next = prev.unwrap_or(0) + 1;
        let coord = format!("{name}@{next}");
        let audit_id = st.record_admin(
            &who,
            garmr_audit::action::POLICY_REGISTER,
            "registry_record",
            Some(&coord),
            Some(&req.rationale),
        )?;
        let rec = RegistryRecord {
            id: uuid::Uuid::new_v4().to_string(),
            kind: RegistryKind::Policy,
            name: name.clone(),
            version: next.to_string(),
            content_digest: digest.clone(),
            parent_version: prev.map(|v| v.to_string()),
            rationale: req.rationale.clone(),
            eval_run_refs: Vec::new(),
            approval: ApprovalState::Draft,
            source: RegistrySource::Operator,
            registered_at: chrono::Utc::now(),
            registered_by: who.user.clone(),
            audit_id,
            spec: spec.clone(),
        };
        match st.store.state.register_record(&rec).map_err(oops)? {
            RegisterOutcome::Conflict { existing_digest } if attempt + 1 < MAX_TRIES => {
                tracing::debug!(
                    policy = %name, version = next, existing = %existing_digest,
                    "policy draft version raced a concurrent draft; retrying"
                );
                continue;
            }
            RegisterOutcome::Conflict { existing_digest } => {
                return Err(bad(format!(
                    "policy {name}@{next} version could not be allocated after {MAX_TRIES} tries \
                     (a concurrent draft holds it; digest {existing_digest}) — retry"
                )))
            }
            outcome => {
                return Ok(Json(
                    serde_json::json!({ "outcome": format!("{outcome:?}"), "record": rec }),
                ))
            }
        }
    }
    Err(oops("policy draft retry loop exhausted"))
}

/// Body of `POST /api/policies/simulate`.
#[derive(Deserialize)]
pub(super) struct SimulateReq {
    /// The draft policy to backtest (not persisted).
    policy: Policy,
    /// Look-back window in hours (default 7 days, clamped to 90 days).
    #[serde(default)]
    hours: Option<i64>,
    /// Max historical accesses to evaluate (default 5000, capped 20000).
    #[serde(default)]
    limit: Option<usize>,
    /// SQL `log_type` filter for the scan. Default `"audit"` (the canonical
    /// application-audit marker). Pass `""` to scan every recent event and gate
    /// by `is_audit_event` in Rust instead. Must be `[A-Za-z0-9_]+`.
    #[serde(default)]
    log_type: Option<String>,
}

/// `POST /api/policies/simulate` — replay a *draft* policy over recent historical
/// accesses and report its blast radius (how many match, what they resolve to,
/// who/what is affected, a false-positive estimate). Reuses the same read-only
/// query path, `AuditRecord` projection, catalog stamp, and `context_from_event`
/// as the live pipeline, so the simulation sees exactly what enforcement would.
/// Non-mutating: it persists nothing and enforces nothing.
pub(super) async fn simulate(
    State(st): State<ApiState>,
    Json(req): Json<SimulateReq>,
) -> ApiResult {
    // A draft must be structurally valid before we spend a history scan on it.
    req.policy.validate().map_err(bad)?;

    let hours = req
        .hours
        .unwrap_or(SIMULATE_DEFAULT_HOURS)
        .clamp(1, SIMULATE_MAX_HOURS);
    let limit = req
        .limit
        .unwrap_or(SIMULATE_DEFAULT_LIMIT)
        .min(SIMULATE_MAX_LIMIT);

    // Sanitize the log_type filter — it is interpolated into the WHERE clause, so
    // only an identifier token is allowed (never free SQL).
    let log_type = req.log_type.unwrap_or_else(|| "audit".to_string());
    let where_lt = if log_type.is_empty() {
        String::new()
    } else if log_type
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_')
    {
        format!(" AND log_type = '{log_type}'")
    } else {
        return Err(bad("log_type must be alphanumeric/underscore"));
    };

    // Pull the recent window, newest first, bounded so a scan can't wedge the box
    // (event_ts pruning + LIMIT, same discipline as /api/tail and /api/query).
    let sql = format!(
        "SELECT event_ts, host, service, source, environment, severity, log_type, message, fields, event_id \
         FROM events WHERE event_ts >= now() - INTERVAL '{hours} hour'{where_lt} \
         ORDER BY event_ts DESC LIMIT {limit}"
    );
    let fut = st.store.events.sql(sql);
    let batches =
        match tokio::time::timeout(std::time::Duration::from_secs(QUERY_TIMEOUT_SECS), fut).await {
            Ok(r) => r.map_err(oops)?,
            Err(_) => {
                return Err((
                    axum::http::StatusCode::REQUEST_TIMEOUT,
                    format!("simulation scan exceeded {QUERY_TIMEOUT_SECS}s — narrow the window"),
                ))
            }
        };

    // Reconstruct up to the requested `limit` (already capped at SIMULATE_MAX_LIMIT)
    // — not the smaller /api/query row cap — so a large scan actually evaluates the
    // window the caller asked for instead of silently truncating at 5000.
    let events = batch_to_events(&batches, limit);
    let scanned = events.len();

    // Keep only the audit-like accesses; build a catalog-stamped record for each
    // (held alive), then borrow them into contexts — the exact projection the live
    // detector pipeline uses. Records must outlive the contexts that borrow them.
    let audit_events: Vec<&Event> = events
        .iter()
        .filter(|ev| AuditRecord::is_audit_event(ev))
        .collect();
    let records: Vec<AuditRecord> = audit_events
        .iter()
        .map(|ev| {
            let mut rec = AuditRecord::from_event(ev);
            if let Some(aa) = &st.app_audit {
                aa.stamp_record(&mut rec);
            }
            rec
        })
        .collect();
    let contexts: Vec<_> = audit_events
        .iter()
        .zip(&records)
        .map(|(ev, rec)| context_from_event(ev, rec))
        .collect();

    let report = run_simulate(&req.policy, &contexts);

    Ok(axum::Json(serde_json::json!({
        "report": report,
        "policy_id": req.policy.id,
        "window_hours": hours,
        "scanned": scanned,
        "audit_accesses": contexts.len(),
        "stamped": st.app_audit.is_some(),
        "limit": limit,
    })))
}

/// Pull a bounded, event-time-pruned window of recent AUDIT events, newest first,
/// reconstructed into `Event`s. The shared read path behind the policy backtest,
/// the resource access history, and the per-user behavioral scan: `event_ts`
/// pruning + `LIMIT` + a timeout, restricted to `log_type = 'audit'`. Only the
/// clamped integer `hours`/`limit` are interpolated — no free SQL reaches the query.
pub(super) async fn scan_audit_events(
    st: &ApiState,
    hours: i64,
    limit: usize,
) -> Result<Vec<Event>, (axum::http::StatusCode, String)> {
    scan_audit_events_where(st, hours, limit, "").await
}

/// As [`scan_audit_events`], with an extra WHERE fragment (e.g. an
/// application-name predicate) appended so a per-entity scan isn't starved by
/// other traffic. **`extra_where` is interpolated verbatim** — the caller MUST
/// pass only a sanitized fragment it constructed (never raw user input); see
/// `api::applications` for the escaped-`LIKE` builder.
pub(super) async fn scan_audit_events_where(
    st: &ApiState,
    hours: i64,
    limit: usize,
    extra_where: &str,
) -> Result<Vec<Event>, (axum::http::StatusCode, String)> {
    let sql = format!(
        "SELECT event_ts, host, service, source, environment, severity, log_type, message, fields, event_id \
         FROM events WHERE event_ts >= now() - INTERVAL '{hours} hour' AND log_type = 'audit'{extra_where} \
         ORDER BY event_ts DESC LIMIT {limit}"
    );
    let fut = st.store.events.sql(sql);
    match tokio::time::timeout(std::time::Duration::from_secs(QUERY_TIMEOUT_SECS), fut).await {
        Ok(r) => Ok(batch_to_events(&r.map_err(oops)?, limit)),
        Err(_) => Err((
            axum::http::StatusCode::REQUEST_TIMEOUT,
            format!("audit scan exceeded {QUERY_TIMEOUT_SECS}s — narrow the window"),
        )),
    }
}

/// Reconstruct `Event`s from the lakehouse batches (typed columns, so timestamps
/// stay exact). The `fields` column is the JSON-serialized attribute map; the
/// `event_id` column is folded back into `fields` so `context_from_event` can
/// recover the evidence id. Shared with the resources workspace (`api::resources`).
pub(super) fn batch_to_events(batches: &[RecordBatch], max_rows: usize) -> Vec<Event> {
    fn sv(a: Option<&StringArray>, i: usize) -> String {
        a.filter(|x| !x.is_null(i))
            .map(|x| x.value(i).to_string())
            .unwrap_or_default()
    }
    let mut out = Vec::new();
    for b in batches {
        let col = |name: &str| {
            b.column_by_name(name)
                .and_then(|c| c.as_any().downcast_ref::<StringArray>())
        };
        let Some(ts) = b
            .column_by_name("event_ts")
            .and_then(|c| c.as_any().downcast_ref::<TimestampMicrosecondArray>())
        else {
            continue;
        };
        let (host, service, source) = (col("host"), col("service"), col("source"));
        let (environment, severity, log_type) =
            (col("environment"), col("severity"), col("log_type"));
        let (message, fields_c, event_id_c) = (col("message"), col("fields"), col("event_id"));
        for i in 0..b.num_rows() {
            if out.len() >= max_rows {
                return out;
            }
            if ts.is_null(i) {
                continue;
            }
            let ts_dt = DateTime::from_timestamp_micros(ts.value(i)).unwrap_or_default();
            let mut fields: BTreeMap<String, String> = fields_c
                .filter(|a| !a.is_null(i))
                .and_then(|a| serde_json::from_str(a.value(i)).ok())
                .unwrap_or_default();
            if event_id_c.is_some_and(|a| !a.is_null(i)) {
                let eid = event_id_c.expect("checked").value(i).to_string();
                fields.entry("event_id".to_string()).or_insert(eid);
            }
            out.push(Event {
                ts: ts_dt,
                host: sv(host, i).into(),
                service: sv(service, i).into(),
                source: sv(source, i).into(),
                environment: sv(environment, i).into(),
                severity: sv(severity, i).into(),
                log_type: sv(log_type, i).into(),
                message: sv(message, i),
                fields,
            });
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use garmr_core::app_audit::keys;
    use garmr_policy::{ConditionMatch, Effect, ResourceMatch, SubjectMatch};
    use garmr_store::schema::build_events_batch;

    fn ts() -> chrono::DateTime<chrono::Utc> {
        // A whole-second instant so micros round-trip exactly.
        chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap()
    }

    fn audit_ev(evid: &str, actor: &str, object: &str) -> Event {
        let mut fields = BTreeMap::new();
        fields.insert("event_id".to_string(), evid.to_string());
        fields.insert(keys::ACTOR.to_string(), actor.to_string());
        fields.insert(keys::OBJECT_NAME.to_string(), object.to_string());
        fields.insert(keys::OBJECT_TYPE.to_string(), "persons".to_string());
        fields.insert(keys::OUTCOME.to_string(), "success".to_string());
        Event {
            ts: ts(),
            host: "db01".into(),
            service: "postgres".into(),
            source: "pgaudit".into(),
            environment: "prod".into(),
            severity: "info".into(),
            log_type: "audit".into(),
            message: "SELECT ...".into(),
            fields,
        }
    }

    fn deny_raw() -> Policy {
        Policy {
            id: "deny-raw".into(),
            version: 1,
            title: String::new(),
            description: String::new(),
            priority: 0,
            enabled: true,
            subject: SubjectMatch::default(),
            resource: ResourceMatch {
                objects: vec!["raw.*".into()],
                ..Default::default()
            },
            condition: ConditionMatch::default(),
            effect: Effect::Deny,
            created_by: "alice".into(),
            approved_by: Some("alice".into()),
        }
    }

    #[test]
    fn batch_to_events_round_trips_ts_fields_and_event_id() {
        let evs = vec![
            audit_ev("e1", "anna", "raw.persons"),
            audit_ev("e2", "bob", "curated.persons"),
        ];
        let batch = build_events_batch(&evs).unwrap();
        let recon = batch_to_events(&[batch], 100);
        assert_eq!(recon.len(), 2);
        let a = &recon[0];
        assert_eq!(
            a.ts,
            ts(),
            "timestamp must round-trip at microsecond precision"
        );
        assert_eq!(a.log_type, "audit");
        assert_eq!(a.host, "db01");
        assert_eq!(a.field(keys::ACTOR), Some("anna"));
        assert_eq!(a.field(keys::OBJECT_NAME), Some("raw.persons"));
        assert_eq!(
            a.field("event_id"),
            Some("e1"),
            "event_id must survive for evidence"
        );
        // And it projects to an audit record the pipeline recognises.
        assert!(AuditRecord::is_audit_event(a));
    }

    #[test]
    fn simulate_backtests_a_deny_policy_over_reconstructed_history() {
        // Two raw.* accesses (would be denied) + one curated (allowed), shipped
        // through the SAME batch round-trip the endpoint uses.
        let evs = vec![
            audit_ev("e1", "anna", "raw.persons"),
            audit_ev("e2", "bob", "raw.accounts"),
            audit_ev("e3", "carol", "curated.persons"),
        ];
        let batch = build_events_batch(&evs).unwrap();
        let events = batch_to_events(&[batch], 100);

        let audit_events: Vec<&Event> = events
            .iter()
            .filter(|e| AuditRecord::is_audit_event(e))
            .collect();
        let records: Vec<AuditRecord> = audit_events
            .iter()
            .copied()
            .map(AuditRecord::from_event)
            .collect();
        let contexts: Vec<_> = audit_events
            .iter()
            .copied()
            .zip(&records)
            .map(|(e, r)| context_from_event(e, r))
            .collect();

        let rep = run_simulate(&deny_raw(), &contexts);
        assert_eq!(rep.evaluated, 3);
        assert_eq!(rep.matched, 2, "both raw.* accesses match");
        assert_eq!(rep.deny, 2);
        assert!(rep.affected_users.contains(&"anna".to_string()));
        assert!(rep.affected_users.contains(&"bob".to_string()));
        assert!(!rep.affected_users.contains(&"carol".to_string()));
        // Evidence ids of the matched accesses are carried through for the analyst.
        assert!(rep.sample_event_ids.contains(&"e1".to_string()));
        assert!(rep.sample_event_ids.contains(&"e2".to_string()));
    }

    #[test]
    fn validate_rejects_an_empty_policy_id() {
        let mut p = deny_raw();
        p.id = "  ".into();
        assert!(p.validate().is_err());
        assert!(deny_raw().validate().is_ok());
    }
}
