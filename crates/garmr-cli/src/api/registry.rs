// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! The governed-registry surface: the read views + the admin write path.
//! Every record carries its derived `effective_state` (the promotion fold);
//! `/active` resolves the live record per `(kind, name)` on the production
//! channel. Register/promote/rollback/retire/reject are admin-gated and
//! enforce the hard invariant: a promotion needs an EXISTING versioned record
//! AND a fail-closed audit event (with auditing disabled the promotion is
//! refused, never persisted inert). A lesson is re-validated at the approval
//! boundary — never trusted from its Draft — and a governed-kind promotion on
//! the production channel auto-reloads the enforced app-audit config.

use garmr_core::{
    active, effective_state, ApprovalState, PromotionEvent, PromotionOp, RegistryKind,
    RegistryRecord, RegistrySource,
};
use garmr_store::state::RegisterOutcome;

use super::auth::check_admin;
use super::*;

/// The audit action for REGISTERING a kind. `None` ⇒ the kind cannot be
/// registered through this surface (only `Unknown`).
fn register_action(kind: RegistryKind) -> Option<&'static str> {
    use garmr_audit::action::*;
    Some(match kind {
        RegistryKind::Model | RegistryKind::EmbeddingModel | RegistryKind::Reranker => {
            MODEL_REGISTER
        }
        RegistryKind::Prompt => PROMPT_PROPOSE,
        RegistryKind::Toolset => TOOLSET_REGISTER,
        RegistryKind::Rule => RULE_PROPOSE,
        RegistryKind::DetectorConfig => THRESHOLD_PROPOSE,
        RegistryKind::Dataset => DATASET_CREATE,
        RegistryKind::EvalRun => EVAL_RUN,
        RegistryKind::Release => RELEASE_REGISTER,
        RegistryKind::FeatureDef => FEATURE_REGISTER,
        RegistryKind::Lesson => LESSON_PROPOSE,
        // Phase A: the governed application-audit catalog domains.
        RegistryKind::Policy => POLICY_REGISTER,
        RegistryKind::Catalog => CATALOG_REGISTER,
        RegistryKind::Application => APPLICATION_REGISTER,
        RegistryKind::Resource => RESOURCE_REGISTER,
        RegistryKind::Monitoring => MONITORING_REGISTER,
        RegistryKind::Unknown => return None,
    })
}

/// The audit action for PROMOTING a kind. `None` ⇒ the kind cannot be promoted
/// (a deferred kind — embedding/reranker/feature — or a leaf like EvalRun).
fn promote_action(kind: RegistryKind) -> Option<&'static str> {
    use garmr_audit::action::*;
    Some(match kind {
        RegistryKind::Model => MODEL_PROMOTE,
        RegistryKind::Prompt => PROMPT_DECIDE,
        RegistryKind::Toolset => TOOLSET_PROMOTE,
        RegistryKind::Rule => RULE_DECIDE,
        RegistryKind::DetectorConfig => THRESHOLD_DECIDE,
        RegistryKind::Dataset => DATASET_PROMOTE,
        RegistryKind::Release => RELEASE_PROMOTE,
        RegistryKind::Lesson => LESSON_PROMOTE,
        // Phase A: the governed application-audit catalog domains.
        RegistryKind::Policy => POLICY_PROMOTE,
        RegistryKind::Catalog => CATALOG_PROMOTE,
        RegistryKind::Application => APPLICATION_PROMOTE,
        RegistryKind::Resource => RESOURCE_PROMOTE,
        RegistryKind::Monitoring => MONITORING_PROMOTE,
        _ => return None,
    })
}

fn parse_kind(s: &str) -> Result<RegistryKind, (StatusCode, String)> {
    RegistryKind::from_tag(s).ok_or_else(|| bad(format!("unknown registry kind '{s}'")))
}

/// A record + its derived effective approval state (additive to the raw record).
fn record_json(r: &RegistryRecord, promotions: &[PromotionEvent]) -> Value {
    let mut v = json!(r);
    if let Some(obj) = v.as_object_mut() {
        obj.insert(
            "effective_state".to_string(),
            json!(format!("{:?}", effective_state(r, promotions))),
        );
    }
    v
}

/// GET /api/registry/:kind — every version of every name of a kind.
pub(super) async fn registry_list(
    State(st): State<ApiState>,
    Path(kind): Path<String>,
    Query(p): Query<HashMap<String, String>>,
) -> ApiResult {
    let kind = parse_kind(&kind)?;
    let records = st.store.state.list_kind(kind).map_err(oops)?;
    let promotions = st.store.state.list_promotions().map_err(oops)?;
    let rows: Vec<Value> = records
        .iter()
        .map(|r| record_json(r, &promotions))
        .collect();
    let mut out = Page::from_query(&p).envelope("records", rows);
    out["kind"] = json!(kind.tag());
    Ok(Json(out))
}

/// GET /api/registry/:kind/:name — all versions + the promotion history and the
/// active version of one `(kind, name)`.
pub(super) async fn registry_show(
    State(st): State<ApiState>,
    Path((kind, name)): Path<(String, String)>,
) -> ApiResult {
    let kind = parse_kind(&kind)?;
    let records = st.store.state.records_for_name(kind, &name).map_err(oops)?;
    let promotions = st.store.state.promotions_for(kind, &name).map_err(oops)?;
    let active_rec = active(kind, &name, "production", &records, &promotions);
    let active_digest = active_rec.map(|r| r.content_digest.clone());
    // The active VERSION is the unambiguous "which one is live" key (two records can
    // share a content_digest — e.g. redrafting the current content — so a consumer
    // must compare on version, not digest).
    let active_version = active_rec.map(|r| r.version.clone());
    let rows: Vec<Value> = records
        .iter()
        .map(|r| record_json(r, &promotions))
        .collect();
    Ok(Json(json!({
        "kind": kind.tag(),
        "name": name,
        "active_digest": active_digest,
        "active_version": active_version,
        "records": rows,
        "promotions": promotions,
    })))
}

/// GET /api/registry/:kind/:name/:version — one exact record.
pub(super) async fn registry_version(
    State(st): State<ApiState>,
    Path((kind, name, version)): Path<(String, String, String)>,
) -> ApiResult {
    let kind = parse_kind(&kind)?;
    match st
        .store
        .state
        .get_record(kind, &name, &version)
        .map_err(oops)?
    {
        Some(r) => {
            let promotions = st.store.state.promotions_for(kind, &name).map_err(oops)?;
            Ok(Json(record_json(&r, &promotions)))
        }
        None => Err((
            StatusCode::NOT_FOUND,
            format!("no {} record {name}@{version}", kind.tag()),
        )),
    }
}

/// GET /api/registry/active — the live record for each `(kind, name)` on the
/// production channel (what the running system should be using).
pub(super) async fn registry_active(State(st): State<ApiState>) -> ApiResult {
    let records = st.store.state.list_registry().map_err(oops)?;
    let promotions = st.store.state.list_promotions().map_err(oops)?;
    let mut seen = std::collections::HashSet::new();
    let mut rows = Vec::new();
    for r in &records {
        let key = format!("{}|{}", r.kind.tag(), r.name);
        if !seen.insert(key) {
            continue;
        }
        if let Some(a) = active(r.kind, &r.name, "production", &records, &promotions) {
            rows.push(json!(a));
        }
    }
    Ok(Json(json!({ "active": rows })))
}

/// GET /api/registry/verify — an integrity pass over every registry row: each
/// promotion is audit-bound and each pointer promotion resolves to a present
/// record. Read-only; `ok` is true iff there are no findings.
pub(super) async fn registry_verify(State(st): State<ApiState>) -> ApiResult {
    let records = st.store.state.list_registry().map_err(oops)?;
    let promotions = st.store.state.list_promotions().map_err(oops)?;
    let findings = garmr_core::verify_registry(&records, &promotions);
    Ok(Json(json!({
        "ok": findings.is_empty(),
        "records": records.len(),
        "promotions": promotions.len(),
        "findings": findings,
    })))
}

// ---- write surface (admin-gated; the HARD INVARIANT lives here) -------------

fn default_channel() -> String {
    "production".to_string()
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RegisterReq {
    kind: String,
    name: String,
    version: String,
    content_digest: String,
    #[serde(default)]
    rationale: String,
    #[serde(default)]
    parent_version: Option<String>,
    #[serde(default)]
    spec: Value,
}

/// POST /admin/registry/register — register an immutable content record. Audited
/// fail-closed (the record's `audit_id` binds it to the ledger).
pub(super) async fn registry_register(
    State(st): State<ApiState>,
    headers: axum::http::HeaderMap,
    Json(req): Json<RegisterReq>,
) -> ApiResult {
    let who = check_admin(&st, &headers)?;
    let kind = parse_kind(&req.kind)?;
    let action = register_action(kind).ok_or_else(|| {
        bad(format!(
            "registry kind '{}' cannot be registered",
            kind.tag()
        ))
    })?;
    if req.content_digest.trim().is_empty() {
        return Err(bad("content_digest is required"));
    }
    let coord = format!("{}@{}", req.name, req.version);
    let audit_id = st.record_admin(
        &who,
        action,
        "registry_record",
        Some(&coord),
        Some(&req.rationale),
    )?;
    let rec = RegistryRecord {
        id: uuid::Uuid::new_v4().to_string(),
        kind,
        name: req.name,
        version: req.version,
        content_digest: req.content_digest,
        parent_version: req.parent_version,
        rationale: req.rationale,
        eval_run_refs: Vec::new(),
        approval: ApprovalState::Draft,
        source: RegistrySource::Operator,
        registered_at: chrono::Utc::now(),
        registered_by: who.user,
        audit_id,
        spec: req.spec,
    };
    match st.store.state.register_record(&rec).map_err(oops)? {
        RegisterOutcome::Conflict { existing_digest } => Err(bad(format!(
            "{}@{} already registered with a different digest ({})",
            rec.name, rec.version, existing_digest
        ))),
        outcome => Ok(Json(
            json!({ "outcome": format!("{outcome:?}"), "record": rec }),
        )),
    }
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PromoteReq {
    kind: String,
    name: String,
    version: String,
    #[serde(default = "default_channel")]
    channel: String,
    #[serde(default)]
    reason: String,
}

/// The shared write path for every channel-pointer op. Enforces BOTH halves of
/// the invariant: (1) the target record MUST exist; (2) the promotion is audited
/// fail-closed and stamped with the returned audit id (an unaudited promotion is
/// inert on read).
async fn do_promotion(
    st: &ApiState,
    headers: &axum::http::HeaderMap,
    req: PromoteReq,
    op: PromotionOp,
    to_state: ApprovalState,
) -> ApiResult {
    let who = check_admin(st, headers)?;
    let kind = parse_kind(&req.kind)?;
    let action = promote_action(kind).ok_or_else(|| {
        bad(format!(
            "registry kind '{}' cannot be promoted (deferred or a leaf kind)",
            kind.tag()
        ))
    })?;
    // (1) the versioned record must exist.
    let rec = st
        .store
        .state
        .get_record(kind, &req.name, &req.version)
        .map_err(oops)?
        .ok_or_else(|| {
            bad(format!(
                "no {} record {}@{} — register it before promoting",
                kind.tag(),
                req.name,
                req.version
            ))
        })?;
    // Phase 9: RE-VALIDATE an approved lesson at the APPROVAL boundary — never
    // trust the stored Draft. ONLY when going live (Promote/Rollback); a
    // Retire/Reject that CLEARS a pointer must ALWAYS succeed, so a bad lesson
    // stays removable (the escape hatch to the safe no-lessons state). This does
    // NOT defend a forged-promotion path (a redb-write attacker forging an
    // audit_id) — that is a pre-existing property of every kind.
    if kind == RegistryKind::Lesson && matches!(op, PromotionOp::Promote | PromotionOp::Rollback) {
        let spec: garmr_core::LessonSetSpec =
            serde_json::from_value(rec.spec.clone()).map_err(|e| {
                bad(format!(
                    "lesson record {}@{} spec will not decode ({e}) — not promotable",
                    req.name, req.version
                ))
            })?;
        let set = garmr_core::LessonSet {
            lessons: spec.lessons.clone(),
        };
        if set.digest() != rec.content_digest {
            return Err(bad(format!(
                "lesson record {}@{} digest does not match its content — not promotable",
                req.name, req.version
            )));
        }
        let findings = garmr_core::validate_lesson_set(&spec.lessons, garmr_core::LESSON_CAPS);
        if !findings.is_empty() {
            return Err(bad(format!(
                "lesson {}@{} failed re-validation at promotion: {} finding(s), first: [{}] {}",
                req.name,
                req.version,
                findings.len(),
                findings[0].kind,
                findings[0].detail
            )));
        }
    }
    // (2) fail-closed audit BEFORE the append.
    let coord = format!("{}@{}", req.name, req.version);
    let reason = format!("op={op:?} channel={} {}", req.channel, req.reason);
    let audit_id = st
        .record_admin(
            &who,
            action,
            "registry_promotion",
            Some(&coord),
            Some(&reason),
        )?
        .unwrap_or_default();
    // The hard invariant: a promotion needs a real audit event. An empty id
    // means auditing is disabled — the promotion would be inert on read anyway,
    // so REFUSE it rather than persist an inert row (which `registry verify`
    // would then flag). This mirrors the rule-approval projection, which skips
    // the promote in the same case. Registration (a Draft record) is unaffected.
    if audit_id.is_empty() {
        return Err(bad(
            "cannot promote with auditing disabled — a promotion requires an audit event (set audit.enabled = true)",
        ));
    }
    // Supersede the prior pointer on this (name, channel).
    let supersedes = st
        .store
        .state
        .promotions_for(kind, &req.name)
        .map_err(oops)?
        .into_iter()
        .rfind(|e| e.channel == req.channel)
        .map(|e| e.promotion_id);
    let ev = PromotionEvent {
        promotion_id: uuid::Uuid::new_v4().to_string(),
        kind,
        name: req.name.clone(),
        op,
        to_version: Some(req.version.clone()),
        from_version: None,
        to_state,
        channel: req.channel.clone(),
        target_digest: rec.content_digest.clone(),
        reason: req.reason,
        actor: who.user.clone(),
        audit_id,
        supersedes,
        at: chrono::Utc::now(),
    };
    st.store.state.append_promotion(&ev).map_err(oops)?;

    // Auto-reload the enforced config so a governed-kind promotion takes effect
    // WITHOUT a separate `/admin/appaudit/reload` call. `reload_if_governed` is a
    // no-op (None) unless this promotion changes what is enforced — a
    // registry-backed policy/catalog/monitoring domain on the production channel
    // (see `AppAudit::reload_if_governed`) — so a Model/Prompt/applications/staging
    // promotion, or a plane still loading from files, rebuilds nothing.
    let reloaded = st
        .app_audit
        .as_ref()
        .and_then(|aa| aa.reload_if_governed(kind, &ev.channel));

    let mut body = json!({ "promotion": ev });
    if let Some((policies, catalog_entries, monitoring_profiles)) = reloaded {
        // The reload is a consequence of an already-durable, already-audited
        // promotion, so its own "enforcement recompiled" record is best-effort:
        // never fail the request (un-acknowledging a committed promotion) because
        // this supplementary audit line failed to write.
        if let Err((_, e)) = st.record_admin(
            &who,
            garmr_audit::action::CONFIG_RELOAD,
            "appaudit_config",
            Some(&coord),
            Some(&format!("auto-reload after {} promotion", kind.tag())),
        ) {
            tracing::warn!(
                error = %e,
                "governed promotion auto-reloaded enforcement but its audit record failed"
            );
        }
        body["reloaded"] = json!({
            "policies": policies,
            "catalog_entries": catalog_entries,
            "monitoring_profiles": monitoring_profiles,
        });
    }
    Ok(Json(body))
}

/// POST /admin/registry/promote — make a version the live/approved one.
pub(super) async fn registry_promote(
    State(st): State<ApiState>,
    headers: axum::http::HeaderMap,
    Json(req): Json<PromoteReq>,
) -> ApiResult {
    do_promotion(
        &st,
        &headers,
        req,
        PromotionOp::Promote,
        ApprovalState::Approved,
    )
    .await
}

/// POST /admin/registry/rollback — re-promote a prior version (fold flips the
/// active pointer; nothing is mutated).
pub(super) async fn registry_rollback(
    State(st): State<ApiState>,
    headers: axum::http::HeaderMap,
    Json(req): Json<PromoteReq>,
) -> ApiResult {
    do_promotion(
        &st,
        &headers,
        req,
        PromotionOp::Rollback,
        ApprovalState::Approved,
    )
    .await
}

/// POST /admin/registry/retire — clear the active pointer on a channel.
pub(super) async fn registry_retire(
    State(st): State<ApiState>,
    headers: axum::http::HeaderMap,
    Json(req): Json<PromoteReq>,
) -> ApiResult {
    do_promotion(
        &st,
        &headers,
        req,
        PromotionOp::Retire,
        ApprovalState::Deprecated,
    )
    .await
}

/// POST /admin/registry/reject — mark a specific version rejected (per-version
/// governance; does not move the active pointer).
pub(super) async fn registry_reject(
    State(st): State<ApiState>,
    headers: axum::http::HeaderMap,
    Json(req): Json<PromoteReq>,
) -> ApiResult {
    do_promotion(
        &st,
        &headers,
        req,
        PromotionOp::Reject,
        ApprovalState::Rejected,
    )
    .await
}
