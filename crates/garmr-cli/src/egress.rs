// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! The ledger-backed egress audit sink + policy install (the air-gap chokepoint,
//! invariant #1). The pure policy lives in `garmr_core::egress`; this attaches
//! the tamper-evident-ledger sink and installs the ONE process-wide policy.

use std::sync::Arc;

use garmr_audit::{ActorType, AuditRecord, Outcome, PolicyDecision};
use garmr_core::{EgressAudit, EgressClass, EgressConfig, EgressPolicy};

/// Records a DENIED egress attempt to the audit ledger, best-effort (a lost line
/// must never crash the denying call path). Only the class + destination HOST +
/// reason are recorded — never the raw URL, which can carry a webhook/SMTP token.
pub(crate) struct LedgerEgressAudit;

impl EgressAudit for LedgerEgressAudit {
    fn on_deny(&self, class: EgressClass, host: &str, reason: &str) {
        crate::audit::record_best_effort(
            AuditRecord::new(garmr_audit::action::EGRESS_DECISION, "egress")
                .actor(
                    ActorType::System,
                    "serve".to_string(),
                    Some("egress-policy"),
                )
                .auth_method("system")
                .outcome(Outcome::Denied)
                .policy(PolicyDecision::Denied)
                .object_id(host)
                .reason(format!("{}: {reason}", class.as_str())),
        );
    }
}

/// Install the ONE process-wide egress policy from config + the `GARMR_AIRGAP`
/// override (env wins), with the ledger sink attached. Idempotent.
pub(crate) fn install_policy(airgap: bool, cfg: &EgressConfig) {
    garmr_core::egress::init(
        EgressPolicy::new(airgap, cfg).with_audit(Arc::new(LedgerEgressAudit)),
    );
}