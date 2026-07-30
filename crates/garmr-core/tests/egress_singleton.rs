// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! Integration binary (its OWN process, so the `egress::POLICY` singleton is
//! fresh and no unit test can pollute it) validating the FIX#1 ordering property:
//! calling `global()` BEFORE `init()` must NOT lock the policy to the uninit
//! fallback — a later `init()` always wins.

use garmr_core::egress::{global, init};
use garmr_core::{EgressClass, EgressConfig, EgressDecision, EgressPolicy};

#[test]
fn init_wins_even_after_a_prior_global_call() {
    // Touch the fallback BEFORE init. If global() had used POLICY.get_or_init,
    // this would permanently lock in the empty-allowlist default.
    let _ = global();

    init(EgressPolicy::new(
        false,
        &EgressConfig {
            allow: vec!["example.com".into()],
        },
    ));

    // The installed allowlist must be in effect — proving init() won, not the
    // sink-less, empty-allowlist fallback (which, being allow-all, would have
    // allowed other.com too).
    let p = global();
    assert_eq!(
        p.decide(EgressClass::LlmExternal, "https://api.example.com/v1"),
        EgressDecision::Allow
    );
    assert!(matches!(
        p.decide(EgressClass::LlmExternal, "https://other.com/v1"),
        EgressDecision::Deny(_)
    ));
}
