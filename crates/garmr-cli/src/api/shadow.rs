// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! `GET /api/shadow/summary` + `GET /api/shadow/scores` — the DoD-19
//! champion/challenger **shadow-evaluation** read surface.
//!
//! When a `DetectorConfig` challenger is live on the `shadow` promotion channel
//! (and `GARMR_SHADOW` is set), the live pipeline scores every audit event
//! through both the production ("champion") stateful config and the challenger,
//! recording where they disagree. This surface reports the accumulated
//! comparison — the disagreement counts, the dangerous-miss count, and a
//! conservative recommended decision — plus recent disagreement examples. It is
//! strictly read-only and advisory: promotion stays a governed, human-gated
//! registry action, never a console write, and there is no auto-promotion.

use super::*;

/// GET /api/shadow/summary — the running champion-vs-challenger comparison and a
/// recommended decision. Always 200 when the app-audit plane is up: it reports
/// `enabled`/`active_challenger` so a caller can tell "off" from "on but idle".
pub(super) async fn shadow_summary(State(st): State<ApiState>) -> ApiResult {
    let Some(aa) = &st.app_audit else {
        return Err((
            StatusCode::NOT_FOUND,
            "the application-audit plane is disabled (set detect.app_audit_enabled = true)"
                .to_string(),
        ));
    };
    match aa.shadow_summary() {
        None => Ok(Json(json!({
            "enabled": crate::shadow::shadow_enabled(),
            "active_challenger": Value::Null,
            "events_scored": 0,
            "recommendation": crate::shadow::recommendation(&Default::default(), false),
        }))),
        Some(s) => {
            let recommendation = crate::shadow::recommendation(&s, true);
            Ok(Json(json!({
                "enabled": true,
                "active_challenger": {
                    "name": s.challenger_name,
                    "version": s.challenger_version,
                },
                "events_scored": s.events_scored,
                "diff_events": s.diff_events,
                "challenger_only": s.challenger_only,
                "champion_only": s.champion_only,
                "dangerous_misses": s.dangerous_misses,
                "updated_at": s.updated_at,
                "recommendation": recommendation,
            })))
        }
    }
}

/// GET /api/shadow/scores?limit=N — recent champion-vs-challenger disagreement
/// examples (newest first), `limit` clamped to `[1, 500]` (default 50). Empty
/// when no challenger is live.
pub(super) async fn shadow_scores(
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
    let limit = p
        .get("limit")
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(50)
        .clamp(1, 500);
    let rows = aa.shadow_recent(limit);
    Ok(Json(json!({ "count": rows.len(), "rows": rows })))
}