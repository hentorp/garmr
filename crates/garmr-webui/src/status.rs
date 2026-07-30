// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! Domain state / severity → reserved status class (`pass`/`warn`/`bad`/`dim`).
//! One mapping so every view colours the same concept the same way; the CSS
//! turns the class into the theme's reserved colour. Colour is always paired
//! with the value's own text label in the views (never colour-alone).

/// Case / action lifecycle state → status class.
pub fn state_class(v: &str) -> &'static str {
    match v {
        "escalated" | "needs_human" | "failed" => "bad",
        "new" | "investigating" | "proposed" | "approved" | "executing" => "warn",
        "triaged" | "closed" | "executed" | "denied" => "pass",
        _ => "dim",
    }
}

/// Log severity → status class.
pub fn severity_class(v: &str) -> &'static str {
    match v.to_ascii_lowercase().as_str() {
        "critical" | "high" | "error" | "err" => "bad",
        "warning" | "warn" | "medium" | "notice" => "warn",
        "info" | "informational" | "low" | "debug" => "pass",
        _ => "dim",
    }
}

/// Hunt outcome → status class.
pub fn outcome_class(v: &str) -> &'static str {
    match v {
        "findings" | "needs_human" => "bad",
        "clean" => "pass",
        _ => "warn",
    }
}

/// Rule-proposal status → status class.
pub fn proposal_class(v: &str) -> &'static str {
    match v {
        "rejected" => "bad",
        "approved" => "pass",
        _ => "warn", // pending
    }
}

/// Behavioral-baseline state (Phase 7/8) → status class. Trusted is the only
/// state a detector queries; Suspicious is a taint; Candidate is still learning.
pub fn baseline_class(v: &str) -> &'static str {
    match v {
        "Trusted" => "pass",
        "Suspicious" => "bad",
        "Candidate" => "warn",
        _ => "dim", // Retired / Unknown
    }
}

/// De-underscore + sentence-case a raw backend value for display, so snake_case
/// enum variants never leak into the UI (e.g. "needs_human" → "Needs human",
/// "detector_config" → "Detector config"). Empty renders as an em dash.
pub fn humanize(v: &str) -> String {
    let spaced = v.trim().replace(['_', '-'], " ");
    let mut chars = spaced.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
        None => "—".into(),
    }
}

/// Data-classification label → status class, as a sensitivity gradient: the more
/// sensitive the resource, the more alarming the reserved colour. Custom/unknown
/// labels fall through to neutral `dim`.
pub fn classification_class(v: &str) -> &'static str {
    match v.to_ascii_lowercase().as_str() {
        "secret" | "restricted" => "bad",
        "confidential" => "warn",
        "internal" => "dim",
        "public" => "pass",
        _ => "dim",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn reserved_mapping_is_total_over_known_values() {
        assert_eq!(state_class("escalated"), "bad");
        assert_eq!(state_class("investigating"), "warn");
        assert_eq!(state_class("closed"), "pass");
        assert_eq!(severity_class("CRITICAL"), "bad");
        assert_eq!(severity_class("info"), "pass");
        assert_eq!(outcome_class("clean"), "pass");
        assert_eq!(proposal_class("pending"), "warn");
        assert_eq!(baseline_class("Trusted"), "pass");
        assert_eq!(baseline_class("Suspicious"), "bad");
        assert_eq!(baseline_class("Candidate"), "warn");
        assert_eq!(baseline_class("Retired"), "dim");
        assert_eq!(state_class("wat"), "dim");
        assert_eq!(classification_class("secret"), "bad");
        assert_eq!(classification_class("Restricted"), "bad");
        assert_eq!(classification_class("confidential"), "warn");
        assert_eq!(classification_class("internal"), "dim");
        assert_eq!(classification_class("public"), "pass");
        assert_eq!(classification_class("pii-custom"), "dim");
    }

    #[test]
    fn humanize_de_jargons_raw_values() {
        assert_eq!(humanize("needs_human"), "Needs human");
        assert_eq!(humanize("detector_config"), "Detector config");
        assert_eq!(humanize("investigating"), "Investigating");
        assert_eq!(humanize("read-only"), "Read only");
        assert_eq!(humanize(""), "—");
        assert_eq!(humanize("closed"), "Closed");
    }
}