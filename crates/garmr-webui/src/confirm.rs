// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! Confirmation contracts for consequential actions, and the configuration
//! validate → apply state machine.
//!
//! Two separate concerns that share a theme: an operator should never be able to
//! trigger something irreversible without being told exactly what it will do, and
//! should never be able to apply configuration that was validated in a different
//! shape than the one now staged.
//!
//! The second is the subtle one. "Validate, then Apply" is only meaningful if the
//! bytes that were validated are the bytes that get applied. If an operator
//! validates, edits one more field, and applies, the green tick refers to a
//! configuration that no longer exists. So a passing validation is bound to a
//! fingerprint of the exact staged values, and any edit invalidates it.
//!
//! Pure, like [`crate::auth`] and [`crate::srcstate`] — the rules are unit-tested
//! on the host target rather than clicked through in a browser.

/// What an operator is told before a consequential action proceeds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConfirmSpec {
    /// Short imperative title, e.g. "Revoke API credential".
    pub title: String,
    /// The exact thing being acted on — an id, a name, a revision number. Never
    /// "this item": the operator must be able to check they picked the right one.
    pub target: String,
    /// What will actually change, in plain language.
    pub what_changes: String,
    /// Whether the change can be undone, and how.
    pub reversible: Reversibility,
    /// Whether the change only takes effect after a service restart.
    pub restart_required: bool,
    /// The authorization and audit consequence — every protected action is
    /// server-authorized and written to the tamper-evident ledger, and the
    /// operator should know that before, not after.
    pub authz_note: String,
    /// Label for the confirming button.
    pub confirm_label: String,
    /// Destructive actions get the stronger treatment.
    pub danger: bool,
    /// For the most disruptive actions, an exact phrase the operator must type.
    /// `None` means a plain confirm button is enough.
    pub typed_phrase: Option<String>,
}

/// Whether, and how, an action can be undone.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Reversibility {
    /// Cannot be undone at all.
    Irreversible,
    /// Can be undone by the described route.
    Reversible(String),
    /// Undoing is possible but is itself a new forward change, not a rewind.
    ForwardOnly(String),
}

impl Reversibility {
    pub fn text(&self) -> String {
        match self {
            Reversibility::Irreversible => "This cannot be undone.".to_string(),
            Reversibility::Reversible(how) => format!("Reversible: {how}"),
            Reversibility::ForwardOnly(how) => {
                format!("Not a rewind — {how}")
            }
        }
    }
    pub fn is_irreversible(&self) -> bool {
        matches!(self, Reversibility::Irreversible)
    }
}

impl ConfirmSpec {
    /// A confirmation whose phrasing is complete: every field the operator needs
    /// in order to decide is present.
    pub fn new(
        title: impl Into<String>,
        target: impl Into<String>,
        what_changes: impl Into<String>,
        reversible: Reversibility,
        confirm_label: impl Into<String>,
    ) -> Self {
        Self {
            title: title.into(),
            target: target.into(),
            what_changes: what_changes.into(),
            reversible,
            restart_required: false,
            authz_note: "The server authorizes this independently and records it \
                         in the audit ledger."
                .to_string(),
            confirm_label: confirm_label.into(),
            danger: false,
            typed_phrase: None,
        }
    }
    pub fn danger(mut self) -> Self {
        self.danger = true;
        self
    }
    pub fn needs_restart(mut self) -> Self {
        self.restart_required = true;
        self
    }
    pub fn typed(mut self, phrase: impl Into<String>) -> Self {
        self.typed_phrase = Some(phrase.into());
        self
    }
    pub fn authz(mut self, note: impl Into<String>) -> Self {
        self.authz_note = note.into();
        self
    }
    /// Is the operator's typed input sufficient to enable the confirm button?
    pub fn typed_input_ok(&self, typed: &str) -> bool {
        match &self.typed_phrase {
            None => true,
            Some(p) => typed.trim() == p,
        }
    }
}

// ---- configuration validate → apply ---------------------------------------

/// The result of the last validation round-trip.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub enum Validation {
    /// Never validated in this editing session.
    #[default]
    NotRun,
    /// A validation request is in flight.
    Running,
    /// The server accepted exactly the values whose fingerprint is recorded here.
    Passed {
        fingerprint: String,
        restart_required: bool,
    },
    /// The server rejected the staged values.
    Failed { message: String },
}

/// Whether Apply may be offered, and if not, why.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ApplyGate {
    /// Exactly these staged values passed validation.
    Ready { restart_required: bool },
    /// Nothing has been staged.
    NothingStaged,
    /// Staged, but never validated (or validation still running).
    NotValidated,
    /// Validation ran and failed.
    ValidationFailed(String),
    /// Validation passed, but for a DIFFERENT set of values than what is staged
    /// now — the operator edited something afterwards.
    StaleValidation,
}

impl ApplyGate {
    pub fn can_apply(&self) -> bool {
        matches!(self, ApplyGate::Ready { .. })
    }
    /// Why Apply is unavailable, for the disabled control's explanation.
    pub fn reason(&self) -> String {
        match self {
            ApplyGate::Ready { .. } => String::new(),
            ApplyGate::NothingStaged => "Stage a change first — nothing is pending.".into(),
            ApplyGate::NotValidated => "Validate the staged values before applying them.".into(),
            ApplyGate::ValidationFailed(m) => format!("Validation failed: {m}"),
            ApplyGate::StaleValidation => {
                "The staged values changed after they were validated. Validate again \
                 so that what you apply is what was checked."
                    .into()
            }
        }
    }
}

/// Decide whether the exact staged values may be applied.
pub fn apply_gate(staged_fingerprint: &str, staged_count: usize, v: &Validation) -> ApplyGate {
    if staged_count == 0 {
        return ApplyGate::NothingStaged;
    }
    match v {
        Validation::NotRun | Validation::Running => ApplyGate::NotValidated,
        Validation::Failed { message } => ApplyGate::ValidationFailed(message.clone()),
        Validation::Passed {
            fingerprint,
            restart_required,
        } => {
            if fingerprint == staged_fingerprint {
                ApplyGate::Ready {
                    restart_required: *restart_required,
                }
            } else {
                ApplyGate::StaleValidation
            }
        }
    }
}

/// A stable fingerprint of the staged key/value pairs.
///
/// Order-independent (the caller's map iteration order must not change the
/// answer) and sensitive to every key and value, so editing a single character
/// invalidates a previous validation. FNV-1a keeps the wasm bundle free of a
/// hashing dependency; this guards against accidental mismatch, not an adversary.
pub fn fingerprint(staged: &[(String, String)]) -> String {
    let mut pairs: Vec<String> = staged.iter().map(|(k, v)| format!("{k}\u{1}{v}")).collect();
    pairs.sort();
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in pairs.join("\u{2}").bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(0x1000_0000_01b3);
    }
    format!("{h:016x}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn staged(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    // ---- fingerprinting -----------------------------------------------------

    #[test]
    fn fingerprint_is_order_independent() {
        let a = fingerprint(&staged(&[("a", "1"), ("b", "2")]));
        let b = fingerprint(&staged(&[("b", "2"), ("a", "1")]));
        assert_eq!(a, b);
    }

    #[test]
    fn fingerprint_changes_on_any_edit() {
        let base = fingerprint(&staged(&[("retention_days", "30"), ("level", "info")]));
        // one character in a value
        assert_ne!(
            base,
            fingerprint(&staged(&[("retention_days", "31"), ("level", "info")]))
        );
        // a renamed key
        assert_ne!(
            base,
            fingerprint(&staged(&[("retention_day", "30"), ("level", "info")]))
        );
        // an added field
        assert_ne!(
            base,
            fingerprint(&staged(&[
                ("retention_days", "30"),
                ("level", "info"),
                ("extra", "x")
            ]))
        );
        // a removed field
        assert_ne!(base, fingerprint(&staged(&[("retention_days", "30")])));
    }

    #[test]
    fn fingerprint_cannot_be_confused_by_separators() {
        // Values containing the joining characters must not collide.
        assert_ne!(
            fingerprint(&staged(&[("a", "1"), ("b", "2")])),
            fingerprint(&staged(&[("a", "1\u{1}b\u{1}2"), ("b", "")]))
        );
    }

    // ---- the apply gate -----------------------------------------------------

    #[test]
    fn nothing_staged_blocks_apply() {
        let g = apply_gate("fp", 0, &Validation::NotRun);
        assert_eq!(g, ApplyGate::NothingStaged);
        assert!(!g.can_apply());
    }

    #[test]
    fn staged_but_unvalidated_blocks_apply() {
        assert_eq!(
            apply_gate("fp", 2, &Validation::NotRun),
            ApplyGate::NotValidated
        );
        assert_eq!(
            apply_gate("fp", 2, &Validation::Running),
            ApplyGate::NotValidated
        );
    }

    #[test]
    fn failed_validation_blocks_apply_and_says_why() {
        let g = apply_gate(
            "fp",
            1,
            &Validation::Failed {
                message: "retention_days must be >= 1".into(),
            },
        );
        assert!(!g.can_apply());
        assert!(g.reason().contains("retention_days must be >= 1"));
    }

    #[test]
    fn matching_validation_allows_apply() {
        let fp = fingerprint(&staged(&[("a", "1")]));
        let g = apply_gate(
            &fp,
            1,
            &Validation::Passed {
                fingerprint: fp.clone(),
                restart_required: true,
            },
        );
        assert_eq!(
            g,
            ApplyGate::Ready {
                restart_required: true
            }
        );
        assert!(g.can_apply());
    }

    /// The central requirement: editing after a successful validation must
    /// invalidate it, so an operator can never apply values that were never
    /// checked.
    #[test]
    fn editing_after_validation_invalidates_it() {
        let validated = staged(&[("retention_days", "30")]);
        let fp_validated = fingerprint(&validated);

        let after_edit = staged(&[("retention_days", "3000")]);
        let fp_now = fingerprint(&after_edit);

        let g = apply_gate(
            &fp_now,
            1,
            &Validation::Passed {
                fingerprint: fp_validated,
                restart_required: false,
            },
        );
        assert_eq!(g, ApplyGate::StaleValidation);
        assert!(!g.can_apply());
        assert!(g.reason().contains("Validate again"));
    }

    #[test]
    fn adding_a_second_field_after_validation_also_invalidates() {
        let fp_one = fingerprint(&staged(&[("a", "1")]));
        let fp_two = fingerprint(&staged(&[("a", "1"), ("b", "2")]));
        assert_eq!(
            apply_gate(
                &fp_two,
                2,
                &Validation::Passed {
                    fingerprint: fp_one,
                    restart_required: false
                }
            ),
            ApplyGate::StaleValidation
        );
    }

    #[test]
    fn reverting_an_edit_restores_the_validation() {
        // Edit away and back again: the fingerprint matches once more, so the
        // earlier validation is legitimately still about these exact values.
        let fp = fingerprint(&staged(&[("a", "1")]));
        assert!(apply_gate(
            &fp,
            1,
            &Validation::Passed {
                fingerprint: fp.clone(),
                restart_required: false
            }
        )
        .can_apply());
    }

    // ---- confirmation specs -------------------------------------------------

    #[test]
    fn typed_confirmation_requires_the_exact_phrase() {
        let spec = ConfirmSpec::new(
            "Log out all sessions",
            "every signed-in operator",
            "Ends every passkey session immediately.",
            Reversibility::Reversible("each operator signs in again".into()),
            "Log out everyone",
        )
        .danger()
        .typed("LOG OUT ALL");

        assert!(!spec.typed_input_ok(""));
        assert!(!spec.typed_input_ok("log out all"));
        assert!(!spec.typed_input_ok("LOG OUT"));
        assert!(spec.typed_input_ok("LOG OUT ALL"));
        assert!(spec.typed_input_ok("  LOG OUT ALL  "));
    }

    #[test]
    fn a_spec_without_a_phrase_needs_no_typing() {
        let spec = ConfirmSpec::new(
            "Apply configuration",
            "revision 41",
            "Writes a new revision.",
            Reversibility::ForwardOnly("rollback creates a further revision".into()),
            "Apply",
        );
        assert!(spec.typed_input_ok(""));
    }

    #[test]
    fn reversibility_reads_honestly() {
        assert_eq!(Reversibility::Irreversible.text(), "This cannot be undone.");
        assert!(Reversibility::Irreversible.is_irreversible());
        assert!(Reversibility::ForwardOnly("x".into())
            .text()
            .starts_with("Not a rewind"));
        assert!(!Reversibility::ForwardOnly("x".into()).is_irreversible());
    }

    #[test]
    fn every_spec_carries_an_audit_consequence() {
        let spec = ConfirmSpec::new("t", "x", "y", Reversibility::Irreversible, "Go");
        assert!(spec.authz_note.contains("audit"));
    }
}
