// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! Approving a pending proposal — the ACT side, gated behind human
//! authentication (admin bearer on the API; running the CLI is the local
//! human). It re-backtests against fresh data before enabling (a draft can sit
//! pending for days and turn noisy), then atomically flips pending→approved and
//! stages+renames the rule file into its directory so a crash never leaves an
//! unapproved live rule or an approved proposal without its file.

use chrono::Utc;
use garmr_core::{
    ApprovalState, Config, Error, PromotionEvent, PromotionOp, ProposalKind, ProposalStatus,
    RegistryKind, RegistryRecord, RegistrySource, Result, RuleProposal,
};
use garmr_store::Store;

use super::backtest::{backtest_correlation, backtest_sigma};

/// Approve a pending proposal: mark it approved and write the rule file into
/// the matching rule directory. Returns (proposal, written path). This is the
/// ACT side — callers must gate it behind human authentication (admin bearer
/// on the API; running the CLI is the local human).
///
/// Backtesting happens twice on purpose: once at draft time (recorded on the
/// proposal), and again HERE, against fresh data, immediately before the rule
/// goes live. A draft can sit pending for days; re-running the backtest at
/// enable time catches a rule that has since turned into a false-positive
/// cannon (e.g. a new noisy log source appeared) and REFUSES to enable it. The
/// fresh result replaces the recorded one, so the approved proposal carries the
/// backtest that actually justified turning it on. A backtest that fails to
/// *run* (transient store/SQL error) is non-fatal — we don't block a human
/// approval on infra flakiness, only on a rule that is provably too noisy.
/// `audit_id` binds the approval to its `RULE_DECIDE` audit event — the API and
/// the local CLI both audit fail-closed BEFORE calling this and pass the id
/// through. It flows onto the registry projection so the promoted rule record
/// references the exact approval. `None` only when auditing is disabled: the
/// rule still installs and registers, but leaves no live promotion (an
/// unaudited promotion would be inert on read anyway).
pub async fn approve_proposal(
    store: &Store,
    cfg: &Config,
    id: &str,
    audit_id: Option<String>,
) -> Result<(RuleProposal, std::path::PathBuf)> {
    // Resolve first so we can compute the target path for the audit note.
    let mut p = store
        .state
        .get_proposal(id)?
        .ok_or_else(|| Error::store(format!("no proposal matches {id}")))?;
    if p.status != ProposalStatus::Pending {
        return Err(Error::store(format!(
            "the proposal is already {:?}",
            p.status
        )));
    }

    // Re-backtest against fresh data before enabling.
    let fresh = match p.kind {
        ProposalKind::Sigma => backtest_sigma(store, &p.rule_body).await,
        ProposalKind::Correlation => backtest_correlation(store, &p.rule_body).await,
    };
    match fresh {
        Ok(bt) => {
            if bt.health().is_noisy() {
                return Err(Error::store(format!(
                    "refusing to enable '{}': new backtest shows {} — the proposal is rejected, tighten the rule and propose anew",
                    p.title,
                    bt.describe()
                )));
            }
            // Record the fresh backtest so the approved proposal reflects what
            // actually justified enabling it. Still Pending here — the atomic
            // flip happens below.
            p.backtest = bt;
            if let Err(e) = store.state.put_proposal(&p) {
                tracing::warn!(proposal = %p.id, error = %e, "could not persist re-backtest before approval");
            }
        }
        Err(why) => {
            // Couldn't run the backtest (e.g. store/SQL hiccup). Don't block the
            // human on flakiness — proceed with the draft-time backtest, but say so.
            tracing::warn!(proposal = %p.id, reason = %why, "re-backtest at approval did not run — enabling on the draft-time backtest");
        }
    }

    let (dir, ext) = match p.kind {
        ProposalKind::Sigma => (&cfg.detect.rules_dir, "yml"),
        ProposalKind::Correlation => (&cfg.detect.correlations_dir, "toml"),
    };
    // Full uuid in the name: an 8-char prefix can collide and silently
    // overwrite an earlier approval's rule file.
    let path = dir.join(format!("garmr-proposed-{}.{ext}", p.id));
    // Stage to a .tmp (never loaded — the loaders filter on extension), take
    // the atomic pending→approved transition, THEN rename into place. A crash
    // at any point leaves either an inert .tmp or a fully approved rule —
    // never an unapproved live rule, and never an approved proposal without
    // its file. On a lost race the loser removes only its own .tmp; the
    // winner's installed file is untouched.
    std::fs::create_dir_all(dir).map_err(Error::store)?;
    let tmp = dir.join(format!("garmr-proposed-{}.{ext}.tmp", p.id));
    std::fs::write(&tmp, &p.rule_body).map_err(Error::store)?;
    let decided = match store.state.decide_proposal(
        &p.id,
        ProposalStatus::Approved,
        Some(path.display().to_string()),
        Utc::now(),
    ) {
        Ok(d) => d,
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            return Err(e);
        }
    };
    std::fs::rename(&tmp, &path).map_err(Error::store)?;
    tracing::info!(proposal = %decided.id, path = %path.display(), "rule proposal approved and written");

    // Project the approved rule into the versioned registry, bound to the
    // approval's audit event. The rule file + proposal flip above are the source
    // of truth; the registry is an index, so this is best-effort — a projection
    // failure is logged and never undoes an approval that already took effect.
    project_rule_to_registry(store, &decided, &path, audit_id.as_deref());
    Ok((decided, path))
}

/// Register an approved rule as an immutable registry record and — when the
/// approval carries an audit id — promote it live on the production channel.
/// Best-effort and side-effect-only: it never returns an error to the caller.
fn project_rule_to_registry(
    store: &Store,
    p: &RuleProposal,
    path: &std::path::Path,
    audit_id: Option<&str>,
) {
    // Content-addressed version, so re-approving the same body is idempotent.
    let digest = blake3::hash(p.rule_body.as_bytes()).to_hex().to_string();
    let version = format!("v-{}", &digest[..digest.len().min(12)]);
    let rec = RegistryRecord {
        id: uuid::Uuid::new_v4().to_string(),
        kind: RegistryKind::Rule,
        name: p.id.clone(),
        version: version.clone(),
        content_digest: digest.clone(),
        parent_version: None,
        rationale: p.rationale.clone(),
        eval_run_refs: Vec::new(),
        approval: ApprovalState::Approved,
        source: RegistrySource::Operator,
        registered_at: Utc::now(),
        registered_by: "operator".to_string(),
        audit_id: audit_id.map(str::to_string),
        spec: serde_json::json!({
            "kind": format!("{:?}", p.kind),
            "title": p.title,
            "path": path.display().to_string(),
        }),
    };
    if let Err(e) = store.state.register_record(&rec) {
        tracing::warn!(proposal = %p.id, error = %e, "registry projection: register_record failed (approval stands)");
        return;
    }
    // The hard invariant: promote only with an audit id (an unaudited promotion
    // is inert on read). With auditing disabled the rule is registered Approved
    // but has no live promotion.
    let Some(aid) = audit_id.filter(|a| !a.is_empty()) else {
        return;
    };
    let ev = PromotionEvent {
        promotion_id: uuid::Uuid::new_v4().to_string(),
        kind: RegistryKind::Rule,
        name: p.id.clone(),
        op: PromotionOp::Promote,
        to_version: Some(version),
        from_version: None,
        to_state: ApprovalState::Approved,
        channel: "production".to_string(),
        target_digest: digest,
        reason: "rule proposal approved".to_string(),
        actor: "operator".to_string(),
        audit_id: aid.to_string(),
        supersedes: None,
        at: Utc::now(),
    };
    if let Err(e) = store.state.append_promotion(&ev) {
        tracing::warn!(proposal = %p.id, error = %e, "registry projection: append_promotion failed (approval stands)");
    }
}