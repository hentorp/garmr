// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! SLA clocks over the case queue — pure math, no store.
//!
//! Two clocks, two different anchors, because they answer different questions:
//!
//! - the **ack clock** runs while a case sits in the HUMAN QUEUE unowned
//!   (`NeedsHuman`/`Escalated`, no assignee), anchored at `state_changed_at` —
//!   "how long has this been waiting for a person", which resets if the case
//!   re-enters the queue later;
//! - the **resolve clock** runs from `opened_at` until the case closes —
//!   "how long has this incident been open in total", which nothing resets.
//!
//! Every computation takes `now` as an argument and touches no storage, so the
//! breach arithmetic is testable to the second.

use chrono::{DateTime, Duration, Utc};

use crate::config::SlaConfig;
use crate::{Case, CaseState};

/// The computed SLA position of one case. `None` fields mean "that clock does
/// not apply" — disabled by config, or the case is not in that clock's scope.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct SlaStatus {
    pub ack_deadline: Option<DateTime<Utc>>,
    pub ack_breached: bool,
    pub resolve_deadline: Option<DateTime<Utc>>,
    pub resolve_breached: bool,
}

impl SlaStatus {
    pub fn any_breach(&self) -> bool {
        self.ack_breached || self.resolve_breached
    }
}

/// Compute a case's SLA position, or `None` when no clock applies at all —
/// the all-zero config yields `None` for every case, everywhere, which is the
/// disabled posture the defaults promise.
pub fn sla_status(case: &Case, cfg: &SlaConfig, now: DateTime<Utc>) -> Option<SlaStatus> {
    if cfg.ack_minutes == 0 && cfg.resolve_minutes == 0 {
        return None;
    }

    // Ack: only while the case waits for a person and nobody owns it. Taking
    // ownership satisfies the ack SLA even before any state change — the
    // question is "is someone on this", and an assignee is exactly that.
    let in_human_queue = matches!(case.state, CaseState::NeedsHuman | CaseState::Escalated)
        && case.assignee.is_none();
    let (ack_deadline, ack_breached) = if cfg.ack_minutes > 0 && in_human_queue {
        let anchor = case.state_changed_at.unwrap_or(case.opened_at);
        let deadline = anchor + Duration::minutes(cfg.ack_minutes as i64);
        (Some(deadline), now >= deadline)
    } else {
        (None, false)
    };

    // Resolve: from opening until closed, no exceptions and no resets — a case
    // that bounced between states for a week has still been open a week.
    let (resolve_deadline, resolve_breached) =
        if cfg.resolve_minutes > 0 && case.state != CaseState::Closed {
            let deadline = case.opened_at + Duration::minutes(cfg.resolve_minutes as i64);
            (Some(deadline), now >= deadline)
        } else {
            (None, false)
        };

    Some(SlaStatus {
        ack_deadline,
        ack_breached,
        resolve_deadline,
        resolve_breached,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Detection;

    fn case_at(state: CaseState, opened_min_ago: i64, state_changed_min_ago: i64) -> Case {
        let now = Utc::now();
        let mut c = Case::open(Detection {
            rule_id: "r".into(),
            rule_title: "t".into(),
            level: "medium".into(),
            attack: vec![],
            event: crate::Event {
                ts: now,
                host: "h".into(),
                service: "s".into(),
                source: "src".into(),
                environment: "test".into(),
                severity: "info".into(),
                log_type: "system".into(),
                message: "m".into(),
                fields: Default::default(),
            },
            observed_at: now,
            realert_secs: None,
        });
        c.state = state;
        c.opened_at = now - Duration::minutes(opened_min_ago);
        c.state_changed_at = Some(now - Duration::minutes(state_changed_min_ago));
        c
    }

    fn cfg(ack: u64, resolve: u64) -> SlaConfig {
        SlaConfig {
            ack_minutes: ack,
            resolve_minutes: resolve,
        }
    }

    #[test]
    fn the_all_zero_config_yields_none_everywhere() {
        // The disabled posture the defaults promise: a 100%-NeedsHuman queue
        // (LLM-off) with default config must never compute a single breach.
        let c = case_at(CaseState::NeedsHuman, 10_000, 10_000);
        assert_eq!(sla_status(&c, &cfg(0, 0), Utc::now()), None);
    }

    #[test]
    fn ack_breaches_only_unowned_human_queue_cases() {
        let now = Utc::now();
        // In the queue, unowned, past the deadline: breached.
        let c = case_at(CaseState::NeedsHuman, 120, 61);
        let s = sla_status(&c, &cfg(60, 0), now).unwrap();
        assert!(s.ack_breached);

        // Same age but ASSIGNED: someone is on it, no ack breach.
        let mut owned = case_at(CaseState::NeedsHuman, 120, 61);
        owned.assignee = Some("alice".into());
        let s = sla_status(&owned, &cfg(60, 0), now).unwrap();
        assert!(!s.ack_breached);
        assert_eq!(
            s.ack_deadline, None,
            "the clock does not apply to owned cases"
        );

        // Investigating (the agent has it): not the human queue.
        let agent = case_at(CaseState::Investigating, 120, 61);
        let s = sla_status(&agent, &cfg(60, 0), now).unwrap();
        assert!(!s.ack_breached);

        // In the queue but INSIDE the window: deadline set, not breached.
        let fresh = case_at(CaseState::Escalated, 120, 30);
        let s = sla_status(&fresh, &cfg(60, 0), now).unwrap();
        assert!(!s.ack_breached);
        assert!(s.ack_deadline.unwrap() > now);
    }

    #[test]
    fn resolve_runs_from_opening_and_stops_at_closed() {
        let now = Utc::now();
        let open = case_at(CaseState::Triaged, 61, 5);
        let s = sla_status(&open, &cfg(0, 60), now).unwrap();
        assert!(s.resolve_breached, "open past the resolve window breaches");

        let closed = case_at(CaseState::Closed, 10_000, 5);
        let s = sla_status(&closed, &cfg(0, 60), now).unwrap();
        assert!(!s.resolve_breached, "a closed case breaches nothing");
        assert_eq!(s.resolve_deadline, None);
    }
}
