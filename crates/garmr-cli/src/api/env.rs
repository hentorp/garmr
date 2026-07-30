// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! The admin write surface for the temporal environment model (Phase 5). Every
//! handler here is mounted only behind `GARMR_ADMIN_TOKEN` and enforces the same
//! hard invariant as the registry: a PROTECTED transition needs a fail-closed
//! audit event, and — for a promotion to Trusted — the two INVIOLABLE
//! anti-poisoning blocks (an open/malicious case, a compromised entity) are
//! re-checked here even for an authenticated admin. A blocked attempt is itself
//! audited (`ENV_PROMOTE_DENIED`), never a silent no-op.
//!
//! Demotions (→ Suspicious/KnownMalicious/Retired) are audited fail-closed but
//! are NOT gate-blocked — flagging a compromised entity is always allowed.

use chrono::Utc;
use garmr_core::{
    current_transition, hard_blocks, EntityKind, EntityRef, FactState, FactTransition,
    InventoryFormat, ObservationMode, PromotionContext,
};

use super::auth::check_admin;
use super::*;

// ---- read surface (mounted in the always-on read block) ---------------------

/// The environment model surface is only live when `environment.enabled`. A
/// disabled model answers 404 everywhere (reads AND admin writes), so the flag
/// genuinely gates the query/API surface the way its config doc promises — not
/// just the background loops.
fn require_enabled(st: &ApiState) -> Result<(), (StatusCode, String)> {
    if st.cfg.environment.enabled {
        Ok(())
    } else {
        Err((
            StatusCode::NOT_FOUND,
            "the environment model is disabled (set environment.enabled = true)".to_string(),
        ))
    }
}

/// GET /api/env/facts — every materialized fact (optionally `?state=trusted`).
pub(super) async fn env_facts(
    State(st): State<ApiState>,
    Query(q): Query<HashMap<String, String>>,
) -> ApiResult {
    require_enabled(&st)?;
    let now = Utc::now();
    let ttl = Some(st.cfg.environment.to_policy().fact_ttl);
    let mut facts = st.store.state.list_env_facts(ttl, now).map_err(oops)?;
    if let Some(want) = q.get("state") {
        facts.retain(|f| format!("{:?}", f.state).eq_ignore_ascii_case(want));
    }
    Ok(Json(json!({ "facts": facts })))
}

/// GET /api/env/candidates — facts awaiting promotion (Candidate state).
pub(super) async fn env_candidates(State(st): State<ApiState>) -> ApiResult {
    require_enabled(&st)?;
    let now = Utc::now();
    let ttl = Some(st.cfg.environment.to_policy().fact_ttl);
    let facts: Vec<_> = st
        .store
        .state
        .list_env_facts(ttl, now)
        .map_err(oops)?
        .into_iter()
        .filter(|f| f.state == FactState::Candidate)
        .collect();
    Ok(Json(json!({ "candidates": facts })))
}

/// GET /api/env/entity/:kind/:id — the facts about one entity. `?as_of=<rfc3339>`
/// answers the bitemporal question ("what did we believe at T?").
pub(super) async fn env_entity(
    State(st): State<ApiState>,
    Path((kind, id)): Path<(String, String)>,
    Query(q): Query<HashMap<String, String>>,
) -> ApiResult {
    require_enabled(&st)?;
    let ekind =
        EntityKind::from_tag(&kind).ok_or_else(|| bad(format!("unknown entity kind '{kind}'")))?;
    let now = Utc::now();
    let ttl = Some(st.cfg.environment.to_policy().fact_ttl);

    // The fact ids that belong to this entity (from the current materialization).
    let all = st.store.state.list_env_facts(ttl, now).map_err(oops)?;
    let ours: Vec<&garmr_core::EnvFact> = all
        .iter()
        .filter(|f| f.entity.kind == ekind && f.entity.id == id)
        .collect();

    let as_of = q.get("as_of").and_then(|s| {
        chrono::DateTime::parse_from_rfc3339(s)
            .ok()
            .map(|d| d.with_timezone(&Utc))
    });
    let facts: Vec<garmr_core::EnvFact> = match as_of {
        // Historical belief: re-materialize each of the entity's facts as-of T.
        Some(t) => ours
            .iter()
            .filter_map(|f| st.store.state.env_fact_asof(&f.fact_id, t).ok().flatten())
            .collect(),
        None => ours.into_iter().cloned().collect(),
    };
    Ok(Json(json!({
        "entity": { "kind": ekind.tag(), "id": id },
        "as_of": as_of,
        "facts": facts,
    })))
}

/// GET /api/env/verify — integrity pass over the environment streams.
pub(super) async fn env_verify(State(st): State<ApiState>) -> ApiResult {
    require_enabled(&st)?;
    let obs = st.store.state.list_env_observations().map_err(oops)?;
    let transitions = st.store.state.list_env_transitions().map_err(oops)?;
    let findings = garmr_core::verify_environment(&obs, &transitions);
    Ok(Json(json!({
        "ok": findings.is_empty(),
        "observations": obs.len(),
        "transitions": transitions.len(),
        "findings": findings,
    })))
}

/// GET /api/findings — the detection plane's SecurityFindings (Phase 7), newest
/// scanned; `?host=` narrows to one entity. Read-only (findings are analysis
/// output, not protected state).
pub(super) async fn findings(
    State(st): State<ApiState>,
    Query(q): Query<HashMap<String, String>>,
) -> ApiResult {
    let rows = match q.get("host") {
        Some(h) => st.store.state.findings_for_entity(h).map_err(oops)?,
        None => st.store.state.list_findings().map_err(oops)?,
    };
    Ok(Json(Page::from_query(&q).envelope("findings", rows)))
}

// ---- write surface (admin-gated) --------------------------------------------

/// Build the anti-poisoning context for a fact and run the write. Shared by
/// promote/approve/demote/retire. `enforce_hard_gate` is true only for a
/// promotion to Trusted (an analyst clears the soft blocks but never the hard
/// ones); demotions skip the gate.
async fn do_env_transition(
    st: &ApiState,
    who: &garmr_core::Principal,
    fact_id: &str,
    to_state: FactState,
    action: &'static str,
    reason: &str,
    enforce_hard_gate: bool,
) -> ApiResult {
    require_enabled(st)?;
    let now = Utc::now();
    let policy = st.cfg.environment.to_policy();
    let ttl = Some(policy.fact_ttl);
    let fact = st
        .store
        .state
        .get_env_fact(fact_id, ttl, now)
        .map_err(oops)?
        .ok_or_else(|| bad(format!("no environment fact {fact_id}")))?;

    if enforce_hard_gate {
        let open = st.store.state.open_case_entity_set().map_err(oops)?;
        let comp = st.store.state.compromised_entity_set().map_err(oops)?;
        let windows = st.store.state.change_windows(now).map_err(oops)?;
        let per_source = st
            .store
            .state
            .sighting_for(fact_id)
            .map_err(oops)?
            .map(|s| s.per_source_counts)
            .unwrap_or_default();
        let ctx = PromotionContext {
            fact: &fact,
            now,
            open_case_entities: &open,
            compromised_entities: &comp,
            change_windows: &windows,
            per_source_counts: &per_source,
            policy: &policy,
        };
        let blocks = hard_blocks(&ctx);
        if !blocks.is_empty() {
            // A blocked promotion is evidence — audit it (best-effort; the refusal
            // itself already protects the invariant).
            st.record_env_denied(who, fact_id, &format!("{blocks:?}"));
            return Err((
                StatusCode::CONFLICT,
                format!("promotion blocked by an inviolable anti-poisoning rule: {blocks:?}"),
            ));
        }
    }

    // Fail-closed audit BEFORE the append; a protected transition with an empty
    // audit id is inert on read, so refuse rather than persist one.
    let audit_id = st
        .record_admin(who, action, "env_fact", Some(fact_id), Some(reason))?
        .unwrap_or_default();
    if to_state.is_protected() && audit_id.is_empty() {
        return Err(bad(
            "cannot change a protected environment state with auditing disabled — it requires an audit event (set audit.enabled = true)",
        ));
    }

    // Bless the observation carrying the fact's CURRENT value, so a Trusted value
    // is pinned and cannot float on later observation arithmetic.
    let target_observation_id = st
        .store
        .state
        .observations_for(fact_id)
        .map_err(oops)?
        .into_iter()
        .filter(|o| o.value == fact.value)
        .max_by_key(|o| o.recorded_at)
        .map(|o| o.observation_id)
        .unwrap_or_default();
    let prior = st.store.state.transitions_for(fact_id).map_err(oops)?;
    let supersedes = current_transition(&prior).map(|t| t.transition_id.clone());

    let tr = FactTransition {
        transition_id: uuid::Uuid::new_v4().to_string(),
        fact_id: fact_id.to_string(),
        to_state,
        from_state: fact.state,
        reason: reason.to_string(),
        actor: who.user.clone(),
        target_observation_id,
        quarantine_until: None,
        supersedes,
        audit_id,
        recorded_at: now,
    };
    st.store.state.append_transition(&tr).map_err(oops)?;
    Ok(Json(json!({ "transition": tr })))
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PromoteReq {
    fact_id: String,
    #[serde(default)]
    reason: String,
}

/// POST /admin/env/promote — promote a fact to Trusted (analyst-gated: the hard
/// anti-poisoning blocks are re-checked and inviolable).
pub(super) async fn env_promote(
    State(st): State<ApiState>,
    headers: axum::http::HeaderMap,
    Json(req): Json<PromoteReq>,
) -> ApiResult {
    let who = check_admin(&st, &headers)?;
    do_env_transition(
        &st,
        &who,
        &req.fact_id,
        FactState::Trusted,
        garmr_audit::action::ENV_PROMOTE,
        &req.reason,
        true,
    )
    .await
}

/// POST /admin/env/approve — an analyst's explicit approval of a high-impact
/// fact's promotion to Trusted. Same gate as promote; a distinct audit action.
pub(super) async fn env_approve(
    State(st): State<ApiState>,
    headers: axum::http::HeaderMap,
    Json(req): Json<PromoteReq>,
) -> ApiResult {
    let who = check_admin(&st, &headers)?;
    do_env_transition(
        &st,
        &who,
        &req.fact_id,
        FactState::Trusted,
        garmr_audit::action::ENV_APPROVE,
        &req.reason,
        true,
    )
    .await
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct DemoteReq {
    fact_id: String,
    /// `suspicious` | `known_malicious`.
    state: String,
    #[serde(default)]
    reason: String,
}

/// POST /admin/env/demote — flag a fact Suspicious/KnownMalicious (NOT gated —
/// marking a compromise is always allowed — but fail-closed audited).
pub(super) async fn env_demote(
    State(st): State<ApiState>,
    headers: axum::http::HeaderMap,
    Json(req): Json<DemoteReq>,
) -> ApiResult {
    let who = check_admin(&st, &headers)?;
    let to = match req.state.trim().to_ascii_lowercase().as_str() {
        "suspicious" => FactState::Suspicious,
        "known_malicious" => FactState::KnownMalicious,
        other => {
            return Err(bad(format!(
                "demote state must be suspicious|known_malicious (got {other})"
            )))
        }
    };
    do_env_transition(
        &st,
        &who,
        &req.fact_id,
        to,
        garmr_audit::action::ENV_DEMOTE,
        &req.reason,
        false,
    )
    .await
}

/// POST /admin/env/retire — retire a fact (NOT gated; fail-closed audited).
pub(super) async fn env_retire(
    State(st): State<ApiState>,
    headers: axum::http::HeaderMap,
    Json(req): Json<PromoteReq>,
) -> ApiResult {
    let who = check_admin(&st, &headers)?;
    do_env_transition(
        &st,
        &who,
        &req.fact_id,
        FactState::Retired,
        garmr_audit::action::ENV_RETIRE,
        &req.reason,
        false,
    )
    .await
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ImportReq {
    /// A bounded inventory name (the source id).
    source_id: String,
    /// `toml` | `json`.
    format: String,
    /// The inventory file's content.
    content: String,
    /// Optional trust for this inventory source (else the config default).
    #[serde(default)]
    trust: Option<f32>,
}

/// POST /admin/env/import — import a local inventory file's facts as Asserted
/// observations (air-gap friendly; audited with the content digest).
pub(super) async fn env_import(
    State(st): State<ApiState>,
    headers: axum::http::HeaderMap,
    Json(req): Json<ImportReq>,
) -> ApiResult {
    let who = check_admin(&st, &headers)?;
    require_enabled(&st)?;
    let format = match req.format.trim().to_ascii_lowercase().as_str() {
        "toml" => InventoryFormat::Toml,
        "json" => InventoryFormat::Json,
        other => return Err(bad(format!("format must be toml|json (got {other})"))),
    };
    let policy = st.cfg.environment.to_policy();
    let trust = req.trust.unwrap_or_else(|| {
        *policy
            .source_trust
            .get(&req.source_id)
            .unwrap_or(&policy.default_source_trust)
    });
    let now = Utc::now();
    let obs =
        garmr_core::parse_inventory(req.content.as_bytes(), format, &req.source_id, trust, now)
            .map_err(|e| bad(format!("inventory parse failed: {e}")))?;

    // Audit the import batch (fail-closed) with the content digest.
    let digest = garmr_core::frame(&[req.content.as_bytes()]);
    let reason = format!(
        "import {} facts from {} ({})",
        obs.len(),
        req.source_id,
        &digest[..16]
    );
    st.record_admin(
        &who,
        garmr_audit::action::ENV_IMPORT,
        "env_inventory",
        Some(&req.source_id),
        Some(&reason),
    )?;

    let mut written = 0usize;
    for o in &obs {
        if st.store.state.append_observation(o).map_err(oops)? {
            written += 1;
        }
        st.store
            .state
            .bump_sighting(&o.fact_id, &o.source.source_id, now)
            .map_err(oops)?;
    }
    Ok(Json(json!({
        "source": req.source_id,
        "facts": obs.len(),
        "new_observations": written,
        "digest": digest,
    })))
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ChangeWindowReq {
    /// The entity the maintenance window covers (its id).
    entity_id: String,
    /// RFC3339 window start / end.
    from: chrono::DateTime<Utc>,
    to: chrono::DateTime<Utc>,
    #[serde(default)]
    reason: String,
}

/// POST /admin/env/change-window — record a maintenance/change window (an
/// Asserted ChangeRecord fact whose valid interval is [from, to)). Within a
/// window, expected change is not treated as anomaly (it excuses quarantine).
pub(super) async fn env_change_window(
    State(st): State<ApiState>,
    headers: axum::http::HeaderMap,
    Json(req): Json<ChangeWindowReq>,
) -> ApiResult {
    let who = check_admin(&st, &headers)?;
    require_enabled(&st)?;
    let now = Utc::now();
    // The window is modeled as a ChangeRecord fact targeting the covered entity.
    let entity = EntityRef::new(
        EntityKind::ChangeRecord,
        format!("cw-{}", uuid::Uuid::new_v4()),
    );
    let fid = garmr_core::fact_id(&entity, "window", None, None);
    let value = req.entity_id.clone();
    let observation_id = garmr_core::observation_id(&fid, "change-window", &value);
    let audit_id = st.record_admin(
        &who,
        garmr_audit::action::ENV_CHANGE_WINDOW,
        "env_change_window",
        Some(&req.entity_id),
        Some(&req.reason),
    )?;
    let obs = garmr_core::FactObservation {
        observation_id,
        fact_id: fid,
        entity,
        attribute: "window".to_string(),
        relation: None,
        target_id: Some(req.entity_id.clone()),
        value,
        source: garmr_core::SourceRef {
            kind: garmr_core::SourceKind::Analyst,
            source_id: "change-window".to_string(),
            trust: 1.0,
        },
        confidence: 1.0,
        mode: ObservationMode::Asserted,
        learned_from: format!("change-window:{}", who.user),
        valid_from: req.from,
        valid_to: Some(req.to),
        recorded_at: now,
        audit_id,
    };
    st.store.state.append_observation(&obs).map_err(oops)?;
    st.store
        .state
        .bump_sighting(&obs.fact_id, &obs.source.source_id, now)
        .map_err(oops)?;
    Ok(Json(json!({ "change_window": obs })))
}
