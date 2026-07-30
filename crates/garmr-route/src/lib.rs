// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! `garmr-route` — alert routing: what actually leaves garmr as a notification.
//!
//! garmr already dedups at the *case* level (the realert window collapses
//! repeat detections of one `rule|host|key` into one case). This crate adds the
//! notification-side controls on top — the port of soc-infra's alert-router
//! (dedup / throttle / silence) onto garmr's case machinery:
//!
//! - **Silences**: "don't notify for rule X (optionally: on host H) for N
//!   hours". Human-approved, persisted in the state store (they survive
//!   restarts and are auditable), hard-capped at 7 days, `hours: 0` clears.
//!   A silence suppresses **escalations too** — it is a human's explicit,
//!   bounded decision, and scoping with `host` keeps it narrow (Alertmanager
//!   semantics; documented in the CLI help and example config).
//! - **Throttle**: after a notification for a rule is *delivered*, further ones
//!   for the *same rule* are dropped for a config window — caps the one-rule,
//!   many-hosts flood (a scan tripping 50 hosts opens 50 cases; dedup can't
//!   collapse those, the throttle keeps Matrix readable). Two invariants keep
//!   it fail-open: **escalations are never throttled** (an automatic noise
//!   control must not eat the page a human needs — only a human-approved
//!   silence carries that authority), and the window opens only on a
//!   **successful** send ([`AlertRouter::record_sent`], called by the agent
//!   after Matrix accepts the message) so a failed post can't mute the rule
//!   for a window in which nothing was delivered. In-memory by design: a
//!   restart just means one extra notification.
//!
//! Silences win over throttle. Suppression applies to **outbound notifications
//! only** — cases still open, triage still runs, verdicts persist, and the
//! caller is expected to record the suppression on the case transcript. Nothing
//! is dropped from the record; only the noise is.
//!
//! Capability separation (the APPROVAL_FLOW model): the agent may *propose* a
//! silence in a verdict, but creating one requires the authenticated admin
//! surface (`POST /admin/silence` with `GARMR_ADMIN_TOKEN`, or the operator's
//! CLI) — a secret the agent never holds. The authenticated call *is* the
//! human's approval.

use std::collections::HashMap;
use std::sync::Mutex;

use garmr_core::{Error, Result, Silence};
use garmr_store::StateStore;

/// Longest allowed silence — a stuck silence self-heals within a week.
pub const MAX_SILENCE_HOURS: f64 = 168.0;
/// Bounds on operator input, so a (stolen-)token holder can't bloat the
/// silence table into a per-notification scan cost or a log bomb.
pub const MAX_RULE_BYTES: usize = 256;
pub const MAX_REASON_BYTES: usize = 1024;
pub const MAX_ACTIVE_SILENCES: usize = 1000;

/// The routing decision for one would-be notification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// Deliver it.
    Send,
    /// A human-approved silence matches; carries the silence for the audit
    /// trail (transcript entry, logs).
    Silenced(Silence),
    /// Within the per-rule throttle window (never returned for escalations).
    Throttled,
}

impl Decision {
    pub fn is_send(&self) -> bool {
        matches!(self, Decision::Send)
    }

    /// One-line description for transcripts/logs (`None` for `Send`).
    pub fn describe(&self) -> Option<String> {
        match self {
            Decision::Send => None,
            Decision::Silenced(s) => Some(format!(
                "notification suppressed: silence on rule {}{} until {}{}",
                s.rule,
                s.host
                    .as_deref()
                    .map(|h| format!(" host {h}"))
                    .unwrap_or_default(),
                s.until.format("%Y-%m-%d %H:%M UTC"),
                if s.reason.is_empty() {
                    String::new()
                } else {
                    format!(" ({})", s.reason)
                },
            )),
            Decision::Throttled => {
                Some("notification suppressed: within the per-rule throttle window".into())
            }
        }
    }
}

/// Decides whether a notification for `(rule, host)` goes out.
pub struct AlertRouter {
    state: StateStore,
    throttle_secs: i64,
    /// rule -> unix seconds of the last *delivered* notification. Wall-clock
    /// (not `Instant`): a monotonic clock freezes across suspend, silently
    /// stretching the window on laptop/homelab hosts; with wall-clock a
    /// backwards jump merely over-notifies — the accepted failure direction.
    last_sent: Mutex<HashMap<String, i64>>,
}

impl AlertRouter {
    /// `throttle_secs = 0` disables throttling (silences still apply).
    pub fn new(state: StateStore, throttle_secs: u64) -> Self {
        Self {
            state,
            throttle_secs: throttle_secs.min(i64::MAX as u64) as i64,
            last_sent: Mutex::new(HashMap::new()),
        }
    }

    /// Decide for one notification. Read-only: a `Send` does NOT open the
    /// throttle window — call [`record_sent`](Self::record_sent) after the
    /// message is actually delivered, so a failed send can't burn the window.
    /// `escalate` marks a page-worthy notification (Malicious verdict or
    /// severity over the threshold): those are exempt from the throttle —
    /// only a human-approved silence may suppress them.
    ///
    /// Fail-open: if the silence store is unreadable the notification is sent —
    /// for a SOC, a lost suppression beats a lost escalation.
    pub fn decide(&self, rule: &str, host: &str, escalate: bool) -> Decision {
        match self.state.active_silences(chrono::Utc::now()) {
            Ok(silences) => {
                if let Some(s) = silences.into_iter().find(|s| s.matches(rule, host)) {
                    let _ = self.state.bump_silence_hits(&s.rule);
                    return Decision::Silenced(s);
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, "silence store unreadable; failing open (sending)");
            }
        }
        if self.throttle_secs > 0 && !escalate {
            let last = self.last_sent.lock().unwrap_or_else(|p| p.into_inner());
            let now = chrono::Utc::now().timestamp();
            if let Some(&t) = last.get(rule) {
                if now.saturating_sub(t) < self.throttle_secs {
                    return Decision::Throttled;
                }
            }
        }
        Decision::Send
    }

    /// Open the throttle window for a rule — call after a successful delivery.
    /// The check-then-record gap between two concurrent sends at worst lets one
    /// extra notification through, which is the right failure direction.
    pub fn record_sent(&self, rule: &str) {
        if self.throttle_secs > 0 {
            let mut last = self.last_sent.lock().unwrap_or_else(|p| p.into_inner());
            last.insert(rule.to_string(), chrono::Utc::now().timestamp());
        }
    }
}

/// What a silence write changed — the caller surfaces `replaced` so an operator
/// can see when their set destroyed a differently-scoped silence (one silence
/// per rule; a host-scoped set REPLACES a fleet-wide one and vice versa).
#[derive(Debug, Clone)]
pub struct SilenceChange {
    /// The silence now in effect (`None` when `hours: 0` cleared it).
    pub set: Option<Silence>,
    /// The previous silence for the rule, if one existed.
    pub replaced: Option<Silence>,
}

/// Create (or, with `hours == 0`, clear) a silence. The write path shared by
/// the admin HTTP endpoint and the operator CLI — both are human-authenticated
/// surfaces; the agent has no route here.
pub fn set_silence(
    state: &StateStore,
    rule: &str,
    host: Option<&str>,
    hours: f64,
    reason: &str,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<SilenceChange> {
    let rule = rule.trim();
    if rule.is_empty() {
        return Err(Error::Config("silence: rule must not be empty".into()));
    }
    if rule.len() > MAX_RULE_BYTES {
        return Err(Error::Config(format!(
            "silence: rule exceeds {MAX_RULE_BYTES} bytes"
        )));
    }
    // Control characters in rule/reason would flow into tracing lines and the
    // operator's terminal (log forging / ANSI injection) — reject rather than
    // silently rewrite, so what's stored is exactly what was approved.
    if rule.chars().any(char::is_control) {
        return Err(Error::Config(
            "silence: rule contains control characters".into(),
        ));
    }
    if !(0.0..=MAX_SILENCE_HOURS).contains(&hours) || !hours.is_finite() {
        return Err(Error::Config(format!(
            "silence: hours must be 0..={MAX_SILENCE_HOURS} (0 clears)"
        )));
    }
    let reason = reason.trim();
    if reason.len() > MAX_REASON_BYTES {
        return Err(Error::Config(format!(
            "silence: reason exceeds {MAX_REASON_BYTES} bytes"
        )));
    }
    if reason.chars().any(char::is_control) {
        return Err(Error::Config(
            "silence: reason contains control characters".into(),
        ));
    }
    let host = host.map(|h| h.trim().to_string()).filter(|h| !h.is_empty());
    if let Some(h) = &host {
        if h.len() > MAX_RULE_BYTES || h.chars().any(char::is_control) {
            return Err(Error::Config("silence: invalid host".into()));
        }
    }

    if hours == 0.0 {
        // Clearing must match the stored scope: `--hours 0 --host lab-vm`
        // against a FLEET-WIDE silence would otherwise silently remove far more
        // suppression than the operator named.
        let existing = state.get_silence(rule)?;
        if let (Some(want), Some(cur)) = (&host, &existing) {
            if cur.host.as_deref() != Some(want.as_str()) {
                return Err(Error::Config(format!(
                    "silence: rule {} is silenced with scope {} — clear it without --host, or \
                     with the matching scope",
                    rule,
                    cur.host.as_deref().unwrap_or("all hosts"),
                )));
            }
        }
        state.clear_silence(rule)?;
        return Ok(SilenceChange {
            set: None,
            replaced: existing,
        });
    }

    // Count cap: a (stolen-)token holder must not be able to bloat the table
    // into a per-notification scan cost. Overwriting an existing rule is fine.
    if state.get_silence(rule)?.is_none()
        && state.active_silences(now)?.len() >= MAX_ACTIVE_SILENCES
    {
        return Err(Error::Config(format!(
            "silence: more than {MAX_ACTIVE_SILENCES} active silences — clear some first"
        )));
    }

    let s = Silence {
        rule: rule.to_string(),
        host,
        until: now + chrono::Duration::milliseconds((hours * 3_600_000.0) as i64),
        reason: reason.to_string(),
        created: now,
        hits: 0,
    };
    // put_silence carries `hits`/`created` forward in-txn when overwriting, so
    // extending a silence never erases the suppression count the audit trail
    // exists for.
    let replaced = state.put_silence(&s)?;
    let mut set = s;
    if let Some(prev) = &replaced {
        set.hits = prev.hits;
        set.created = prev.created;
    }
    Ok(SilenceChange {
        set: Some(set),
        replaced,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> StateStore {
        let p = std::env::temp_dir().join(format!("garmr-route-{}.redb", uuid::Uuid::new_v4()));
        StateStore::open(&p).unwrap()
    }

    #[test]
    fn silence_suppresses_matching_rule_and_expires() {
        let st = store();
        let now = chrono::Utc::now();
        set_silence(&st, "ssh_brute", None, 1.0, "known scanner", now).unwrap();

        let r = AlertRouter::new(st.clone(), 0);
        assert!(matches!(
            r.decide("ssh_brute", "pve", false),
            Decision::Silenced(_)
        ));
        assert!(r.decide("other_rule", "pve", false).is_send());

        // Expired silences stop matching (prune is time-based on read).
        let past = now - chrono::Duration::hours(2);
        set_silence(&st, "old_rule", None, 1.0, "", past).unwrap();
        assert!(r.decide("old_rule", "pve", false).is_send());
    }

    #[test]
    fn host_scoped_silence_only_matches_that_host() {
        let st = store();
        set_silence(
            &st,
            "ssh_brute",
            Some("lab-vm"),
            1.0,
            "",
            chrono::Utc::now(),
        )
        .unwrap();
        let r = AlertRouter::new(st, 0);
        assert!(matches!(
            r.decide("ssh_brute", "lab-vm", false),
            Decision::Silenced(_)
        ));
        assert!(
            r.decide("ssh_brute", "pve", false).is_send(),
            "other hosts still notify"
        );
    }

    #[test]
    fn silence_applies_even_to_escalations() {
        // Human-approved silences DO suppress escalations (documented policy) —
        // unlike the automatic throttle, which never may.
        let st = store();
        set_silence(&st, "noisy", None, 1.0, "", chrono::Utc::now()).unwrap();
        let r = AlertRouter::new(st, 0);
        assert!(matches!(
            r.decide("noisy", "h", true),
            Decision::Silenced(_)
        ));
    }

    #[test]
    fn hours_zero_clears_and_bounds_enforced() {
        let st = store();
        let now = chrono::Utc::now();
        set_silence(&st, "r1", None, 1.0, "", now).unwrap();
        let cleared = set_silence(&st, "r1", None, 0.0, "", now).unwrap();
        assert!(cleared.set.is_none());
        assert!(cleared.replaced.is_some(), "clear reports what it removed");
        let r = AlertRouter::new(st.clone(), 0);
        assert!(
            r.decide("r1", "h", false).is_send(),
            "hours=0 cleared the silence"
        );

        assert!(
            set_silence(&st, "r1", None, 200.0, "", now).is_err(),
            "cap at 168h"
        );
        assert!(set_silence(&st, "r1", None, -1.0, "", now).is_err());
        assert!(set_silence(&st, "r1", None, f64::NAN, "", now).is_err());
        assert!(
            set_silence(&st, "  ", None, 1.0, "", now).is_err(),
            "empty rule"
        );
    }

    #[test]
    fn clear_with_mismatched_host_scope_is_rejected() {
        let st = store();
        let now = chrono::Utc::now();
        set_silence(&st, "r1", None, 4.0, "fleet-wide", now).unwrap();
        // Clearing a fleet-wide silence while naming a host must not succeed.
        assert!(set_silence(&st, "r1", Some("lab-vm"), 0.0, "", now).is_err());
        // Un-scoped clear works.
        assert!(set_silence(&st, "r1", None, 0.0, "", now)
            .unwrap()
            .set
            .is_none());
    }

    #[test]
    fn replacing_a_silence_reports_the_old_scope_and_keeps_hits() {
        let st = store();
        let now = chrono::Utc::now();
        set_silence(&st, "r1", None, 4.0, "fleet-wide", now).unwrap();
        let r = AlertRouter::new(st.clone(), 0);
        assert!(matches!(r.decide("r1", "a", false), Decision::Silenced(_)));
        assert!(matches!(r.decide("r1", "b", false), Decision::Silenced(_)));

        // Host-scoped set replaces the fleet-wide one — the change surfaces it,
        // and the hit counter carries forward instead of resetting.
        let change = set_silence(&st, "r1", Some("lab-vm"), 2.0, "", now).unwrap();
        let replaced = change.replaced.expect("old silence surfaced");
        assert_eq!(replaced.host, None, "the destroyed silence was fleet-wide");
        assert_eq!(replaced.hits, 2);
        assert_eq!(change.set.unwrap().hits, 2, "hits carried forward");
        let stored = st.get_silence("r1").unwrap().unwrap();
        assert_eq!(stored.hits, 2);
        assert_eq!(stored.created, replaced.created, "created carried forward");
    }

    #[test]
    fn input_bounds_control_chars_rejected() {
        let st = store();
        let now = chrono::Utc::now();
        assert!(
            set_silence(&st, "bad\x1b[31mrule", None, 1.0, "", now).is_err(),
            "ANSI in rule"
        );
        assert!(
            set_silence(&st, "r1", None, 1.0, "line1\nline2", now).is_err(),
            "newline in reason"
        );
        assert!(
            set_silence(&st, &"x".repeat(300), None, 1.0, "", now).is_err(),
            "rule too long"
        );
        assert!(
            set_silence(&st, "r1", None, 1.0, &"y".repeat(2000), now).is_err(),
            "reason too long"
        );
        assert!(
            set_silence(&st, "r1", Some("h\x07ost"), 1.0, "", now).is_err(),
            "control in host"
        );
    }

    #[test]
    fn throttle_opens_only_after_record_sent_and_is_per_rule() {
        let st = store();
        let r = AlertRouter::new(st, 3600);
        // decide() alone never burns the window — a failed send must not mute
        // the rule.
        assert!(r.decide("burst_rule", "h1", false).is_send());
        assert!(
            r.decide("burst_rule", "h2", false).is_send(),
            "no delivery yet → still open"
        );
        r.record_sent("burst_rule");
        assert_eq!(
            r.decide("burst_rule", "h3", false),
            Decision::Throttled,
            "delivered → window open"
        );
        assert!(
            r.decide("other_rule", "h1", false).is_send(),
            "throttle is per rule"
        );
    }

    #[test]
    fn escalations_are_never_throttled() {
        let st = store();
        let r = AlertRouter::new(st, 3600);
        r.record_sent("scan_rule");
        assert_eq!(
            r.decide("scan_rule", "h2", false),
            Decision::Throttled,
            "routine repeat muted"
        );
        assert!(
            r.decide("scan_rule", "h3", true).is_send(),
            "an escalation must never be eaten by the automatic throttle"
        );
    }

    #[test]
    fn silence_wins_over_throttle_and_counts_hits() {
        let st = store();
        let now = chrono::Utc::now();
        set_silence(&st, "noisy", None, 1.0, "", now).unwrap();
        let r = AlertRouter::new(st.clone(), 3600);
        assert!(matches!(
            r.decide("noisy", "h", false),
            Decision::Silenced(_)
        ));
        assert!(matches!(
            r.decide("noisy", "h", false),
            Decision::Silenced(_)
        ));
        let s = &st.active_silences(now).unwrap()[0];
        assert_eq!(s.hits, 2, "suppressions are counted on the silence");
    }
}
