// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! Admin + read surface for the Phase 7/8 application-audit **behavioral
//! baselines**. The daemon holds the authoritative in-memory baseline store
//! (the detectors query it), so — exactly like the environment model — reads and
//! writes go through this HTTP surface, never a second CLI opening the store.
//!
//! Promotion re-checks the inviolable hard blocks (an open case or a prior
//! policy violation touching the entity, or a Suspicious profile) *server-side*,
//! even for an authenticated admin, and is fail-closed audited. Suspect + clear
//! are the taint / human-review lifecycle. Only a Trusted baseline ever drives a
//! behavioral finding, so promotion is the human's explicit grant of trust.

use garmr_audit::action;
use garmr_baseline::{BaselineState, Dimension, Entity, EntityKind, PromotionBlock};

use super::auth::check_admin;
use super::*;

/// GET /api/appaudit/baselines — a compact per-entity summary (kind, id, state,
/// maturity, counts). Read surface; 404 when the plane is disabled.
pub(super) async fn appaudit_baselines(
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
    let store = aa.baseline_snapshot();
    let mut rows = Vec::new();
    for pf in store.profiles() {
        let e = Entity::new(pf.entity.kind, pf.entity.id.clone());
        rows.push(json!({
            "kind": format!("{:?}", pf.entity.kind),
            "id": pf.entity.id,
            "state": format!("{:?}", pf.state),
            "maturity": format!("{:?}", store.maturity(&e)),
            "observations": pf.observation_count,
            "span_days": pf.span().num_days(),
            "distinct_sources": pf.distinct_sources.len(),
            "data_quality_degraded": pf.data_quality_degraded,
        }));
    }
    Ok(Json(Page::from_query(&p).envelope("baselines", rows)))
}

/// The categorical dimensions the peer comparison reports, with a display label.
const PEER_COMPARE_DIMENSIONS: &[(Dimension, &str)] = &[
    (Dimension::Client, "Client"),
    (Dimension::Object, "Object"),
    (Dimension::QueryFingerprint, "QueryFingerprint"),
    (Dimension::SourceHost, "SourceHost"),
    (Dimension::Operation, "Operation"),
    (Dimension::Schema, "Schema"),
];

/// GET /api/appaudit/peers?user=<id>&group=<id>&kind=<role|peer-group|group> —
/// user-vs-peer-group behavioral comparison (Phase 9). For each dimension it
/// reports the values the user uses that NO trusted peer in the group uses
/// (`peer_novelty`). Authoritative only when BOTH baselines are Trusted; otherwise
/// it abstains with an explicit reason (never a false "no deviation"), honouring
/// "candidate data is not trusted normality". `kind` defaults to `role` — a role
/// is the peer group learned automatically alongside each user.
pub(super) async fn appaudit_peers(
    State(st): State<ApiState>,
    Query(p): Query<HashMap<String, String>>,
) -> ApiResult {
    let aa = st.app_audit.as_ref().ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            "the application-audit plane is disabled".to_string(),
        )
    })?;
    let user_id = p
        .get("user")
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| bad("missing ?user="))?;
    let group_id = p
        .get("group")
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| bad("missing ?group= (the peer-group id, e.g. a role name)"))?;
    let kind = parse_kind(p.get("kind").map(String::as_str).unwrap_or("role"))
        .ok_or_else(|| bad("unknown ?kind= (role|group|peer-group|user|application)"))?;

    let store = aa.baseline_snapshot();
    let user = Entity::new(EntityKind::User, user_id);
    let peer = Entity::new(kind, group_id);
    let user_trusted = store
        .get(&user)
        .is_some_and(|pf| pf.state == BaselineState::Trusted);
    let peer_trusted = store
        .get(&peer)
        .is_some_and(|pf| pf.state == BaselineState::Trusted);
    let authoritative = user_trusted && peer_trusted;

    // Explain abstention precisely — never a misleading "no deviation".
    let abstain = if authoritative {
        None
    } else if store.get(&user).is_none() {
        Some(format!("no baseline yet for user '{user_id}'"))
    } else if store.get(&peer).is_none() {
        Some(format!(
            "no baseline yet for peer group '{group_id}' — its accesses have not been observed"
        ))
    } else if !user_trusted {
        Some(format!(
            "the user baseline is not Trusted ({:?}) — promote it to compare",
            store.maturity(&user)
        ))
    } else {
        Some(format!(
            "the peer-group baseline is not Trusted ({:?}) — promote it to compare",
            store.maturity(&peer)
        ))
    };

    let dimensions: Vec<Value> = PEER_COMPARE_DIMENSIONS
        .iter()
        .map(|(d, label)| {
            let user_only = store.peer_novelty(&user, &peer, *d);
            json!({ "dimension": label, "count": user_only.len(), "user_only": user_only })
        })
        .collect();

    Ok(Json(json!({
        "user": { "id": user_id, "maturity": format!("{:?}", store.maturity(&user)), "trusted": user_trusted },
        "peer_group": {
            "kind": format!("{:?}", kind),
            "id": group_id,
            "maturity": format!("{:?}", store.maturity(&peer)),
            "trusted": peer_trusted,
        },
        "authoritative": authoritative,
        "abstain_reason": abstain,
        "dimensions": dimensions,
    })))
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct BaselineReq {
    /// user | role | group | service-account | application | peer-group
    kind: String,
    id: String,
    #[serde(default)]
    reason: String,
}

/// POST /admin/appaudit/baselines/promote — grant Trust to an entity's baseline
/// (analyst action). The hard blocks are re-checked here and are inviolable; a
/// refused attempt is itself audited (`baseline.promote_denied`).
pub(super) async fn appaudit_promote(
    State(st): State<ApiState>,
    headers: axum::http::HeaderMap,
    Json(req): Json<BaselineReq>,
) -> ApiResult {
    let who = check_admin(&st, &headers)?;
    let aa = st
        .app_audit
        .clone()
        .ok_or_else(|| bad("the application-audit plane is disabled"))?;
    let entity = parse_entity(&req.kind, &req.id)?;
    let key = entity_key(&entity);
    let reason = opt_reason(&req.reason);

    // Compute the promotion guards from the case store, then check WITHOUT
    // mutating so a refusal is audited as a denial, and a grant is audited
    // fail-closed BEFORE it is applied.
    let guards = crate::appaudit::baseline_guards(&st.store.state, &entity);
    let blocks = aa.promotion_blocks(&entity, guards);
    if !blocks.is_empty() {
        let _ = st.record_admin(
            &who,
            action::BASELINE_PROMOTE_DENIED,
            "app_baseline",
            Some(&key),
            reason,
        );
        return Err(bad(format!(
            "promotion refused by hard block(s): {}",
            fmt_blocks(&blocks)
        )));
    }
    st.record_admin(
        &who,
        action::BASELINE_PROMOTE,
        "app_baseline",
        Some(&key),
        reason,
    )?;
    aa.promote_baseline(&entity, guards).map_err(|b| {
        oops(format!(
            "promotion raced with a state change: {}",
            fmt_blocks(&b)
        ))
    })?;
    Ok(Json(
        json!({ "promoted": { "kind": req.kind, "id": req.id } }),
    ))
}

/// POST /admin/appaudit/baselines/suspect — mark a baseline Suspicious (it stops
/// answering detector queries; a compromise / policy violation touched it). Not
/// gate-blocked — flagging is always allowed — but fail-closed audited.
pub(super) async fn appaudit_suspect(
    State(st): State<ApiState>,
    headers: axum::http::HeaderMap,
    Json(req): Json<BaselineReq>,
) -> ApiResult {
    let who = check_admin(&st, &headers)?;
    let aa = st
        .app_audit
        .clone()
        .ok_or_else(|| bad("the application-audit plane is disabled"))?;
    let entity = parse_entity(&req.kind, &req.id)?;
    let key = entity_key(&entity);
    st.record_admin(
        &who,
        action::BASELINE_SUSPECT,
        "app_baseline",
        Some(&key),
        opt_reason(&req.reason),
    )?;
    aa.suspect_baseline(&entity);
    Ok(Json(
        json!({ "suspected": { "kind": req.kind, "id": req.id } }),
    ))
}

/// POST /admin/appaudit/baselines/clear — clear a Suspicious marking after human
/// review, returning the profile to Candidate so it can re-learn. Fail-closed
/// audited.
pub(super) async fn appaudit_clear(
    State(st): State<ApiState>,
    headers: axum::http::HeaderMap,
    Json(req): Json<BaselineReq>,
) -> ApiResult {
    let who = check_admin(&st, &headers)?;
    let aa = st
        .app_audit
        .clone()
        .ok_or_else(|| bad("the application-audit plane is disabled"))?;
    let entity = parse_entity(&req.kind, &req.id)?;
    let key = entity_key(&entity);
    st.record_admin(
        &who,
        action::BASELINE_CLEAR,
        "app_baseline",
        Some(&key),
        opt_reason(&req.reason),
    )?;
    aa.clear_baseline(&entity);
    Ok(Json(
        json!({ "cleared": { "kind": req.kind, "id": req.id } }),
    ))
}

/// POST /admin/appaudit/reload — hot-reload the enforced config (access policies +
/// resource catalog + user-monitoring) from files and/or the governed registry,
/// WITHOUT restarting `serve`. The accumulated learning state (behavioral
/// baselines, stateful-detector windows) is untouched. This is what makes a
/// governed change (a registry promotion, or a policy-file edit) take effect
/// immediately, so `GET /api/policies` and enforcement never drift. Fail-closed
/// audited (a protected operational change).
pub(super) async fn appaudit_reload(
    State(st): State<ApiState>,
    headers: axum::http::HeaderMap,
) -> ApiResult {
    let who = check_admin(&st, &headers)?;
    let aa = st
        .app_audit
        .clone()
        .ok_or_else(|| bad("the application-audit plane is disabled"))?;
    st.record_admin(
        &who,
        action::CONFIG_RELOAD,
        "appaudit_config",
        None,
        Some("hot-reload enforced policies/catalog/monitoring"),
    )?;
    let (policies, catalog_entries, monitoring_profiles) = aa.reload();
    Ok(Json(json!({
        "reloaded": {
            "policies": policies,
            "catalog_entries": catalog_entries,
            "monitoring_profiles": monitoring_profiles,
        }
    })))
}

fn parse_entity(kind: &str, id: &str) -> Result<Entity, (StatusCode, String)> {
    let k = parse_kind(kind).ok_or_else(|| {
        bad(format!(
            "unknown entity kind '{kind}' (user|role|group|service-account|application|peer-group)"
        ))
    })?;
    if id.trim().is_empty() {
        return Err(bad("entity id must not be empty"));
    }
    Ok(Entity::new(k, id.trim()))
}

fn parse_kind(s: &str) -> Option<EntityKind> {
    // Accept every spelling the surface round-trips: the hyphenated CLI form
    // (`service-account`), the snake form, and the Debug form this module's own
    // GET emits (`ServiceAccount`, `PeerGroup`). Strip the separators entirely so
    // all three collapse to the same key — otherwise a promote/suspect posted
    // straight back with the `kind` from the baselines list would 400.
    Some(
        match s
            .trim()
            .to_ascii_lowercase()
            .replace(['-', '_'], "")
            .as_str()
        {
            "user" => EntityKind::User,
            "role" => EntityKind::Role,
            "group" => EntityKind::Group,
            "serviceaccount" => EntityKind::ServiceAccount,
            "application" | "app" => EntityKind::Application,
            "peergroup" => EntityKind::PeerGroup,
            _ => return None,
        },
    )
}

fn entity_key(e: &Entity) -> String {
    format!("{:?}:{}", e.kind, e.id)
}

fn opt_reason(reason: &str) -> Option<&str> {
    let t = reason.trim();
    (!t.is_empty()).then_some(t)
}

fn fmt_blocks(blocks: &[PromotionBlock]) -> String {
    blocks
        .iter()
        .map(|b| format!("{b:?}"))
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_kind_round_trips_the_baselines_list_debug_form() {
        // The GET emits `kind` as the Debug form; a promote/suspect must accept
        // exactly that string back, plus the hyphenated CLI and snake forms.
        for s in ["ServiceAccount", "service-account", "service_account"] {
            assert_eq!(parse_kind(s), Some(EntityKind::ServiceAccount), "{s}");
        }
        for s in ["PeerGroup", "peer-group", "peer_group"] {
            assert_eq!(parse_kind(s), Some(EntityKind::PeerGroup), "{s}");
        }
        assert_eq!(parse_kind("User"), Some(EntityKind::User));
        assert_eq!(parse_kind("app"), Some(EntityKind::Application));
        assert_eq!(parse_kind("nope"), None);
    }
}
