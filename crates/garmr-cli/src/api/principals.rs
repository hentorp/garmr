// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! `GET /api/principals` — who can act in this deployment.
//!
//! Case assignment, approver pickers and "who approved this?" all need the same
//! thing: the set of named identities, with the role each holds. Until now that
//! set existed only inside the two credential stores, so the console had no way
//! to offer a list of people and every approval was recorded against the literal
//! `"human"`.
//!
//! # Why this cannot leak a secret
//!
//! Both sources return [`Principal`], a struct with exactly a user and a role
//! and **no field a token or credential could occupy**. The safety property is
//! carried by the type rather than by remembering to strip a field before
//! serializing, so a future edit here cannot accidentally widen the response:
//! there is nothing wider to serialize.

use axum::extract::State;
use garmr_core::{Principal, Role};

use super::{ApiResult, ApiState};

/// GET /api/principals — the merged, deduplicated identity list.
///
/// Viewer-gated: knowing who works in the SOC is not public, but every
/// authenticated role needs it (an analyst assigning a case, the approver
/// picker). Deduplicated by name, keeping the **highest** role a given identity
/// holds — a person with both an analyst token and an admin passkey is an admin,
/// and showing them as an analyst would misstate what they can approve.
pub(super) async fn principals(State(st): State<ApiState>) -> ApiResult {
    let mut merged: std::collections::BTreeMap<String, Role> = std::collections::BTreeMap::new();
    let mut absorb = |p: Principal| {
        merged
            .entry(p.user)
            .and_modify(|r| {
                if p.role.allows(*r) {
                    *r = p.role;
                }
            })
            .or_insert(p.role);
    };
    for p in st.auth.principals() {
        absorb(p);
    }
    if st.webauthn.is_some() {
        for p in super::passkey::passkey_principals(&st.store) {
            absorb(p);
        }
    }

    // Serialize Principal itself rather than hand-building objects: the response
    // shape is then whatever the token-free type is, with no second place for a
    // field to be added by mistake.
    let list: Vec<Principal> = merged
        .into_iter()
        .map(|(user, role)| Principal { user, role })
        .collect();
    Ok(axum::Json(serde_json::json!({
        "principals": list,
        "count": list.len(),
    })))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The merge rule, isolated from the handler so it can be asserted without a
    /// store: highest role wins, names dedupe.
    fn merge(input: Vec<Principal>) -> Vec<(String, Role)> {
        let mut merged: std::collections::BTreeMap<String, Role> =
            std::collections::BTreeMap::new();
        for p in input {
            merged
                .entry(p.user)
                .and_modify(|r| {
                    if p.role.allows(*r) {
                        *r = p.role;
                    }
                })
                .or_insert(p.role);
        }
        merged.into_iter().collect()
    }

    fn p(user: &str, role: Role) -> Principal {
        Principal {
            user: user.into(),
            role,
        }
    }

    #[test]
    fn the_highest_role_an_identity_holds_wins() {
        // alice has an analyst token AND an admin passkey. Reporting her as an
        // analyst would understate who is allowed to approve a containment.
        let out = merge(vec![
            p("alice", Role::Analyst),
            p("alice", Role::Admin),
            p("bob", Role::Viewer),
        ]);
        assert_eq!(
            out,
            vec![
                ("alice".to_string(), Role::Admin),
                ("bob".to_string(), Role::Viewer),
            ]
        );
    }

    #[test]
    fn order_of_arrival_does_not_change_the_result() {
        // The two credential stores are read in a fixed order today, but the
        // merge must not depend on it — otherwise the answer changes when a
        // passkey is added before a token.
        let a = merge(vec![p("alice", Role::Admin), p("alice", Role::Viewer)]);
        let b = merge(vec![p("alice", Role::Viewer), p("alice", Role::Admin)]);
        assert_eq!(a, b);
        assert_eq!(a, vec![("alice".to_string(), Role::Admin)]);
    }

    #[test]
    fn a_principal_has_no_field_a_secret_could_live_in() {
        // The listing's safety rests on the TYPE, so pin it: if someone adds a
        // token field to Principal, this serialization grows and the test fails,
        // which is the moment to stop rather than after it ships.
        let json = serde_json::to_value(p("alice", Role::Admin)).unwrap();
        let keys: Vec<&str> = json
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(
            keys,
            vec!["role", "user"],
            "Principal gained a field: {json}"
        );
    }
}
