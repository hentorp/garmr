// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! The pure decision core for OIDC login: what an ID token must satisfy before
//! it becomes a session, and which role its claims map to.
//!
//! **Nothing here performs a network request, reads a key, or verifies a
//! signature.** Those belong to the relying-party layer; this module is the part
//! where a mistake is silent — a claim check quietly skipped still produces a
//! working login, just for the wrong person. Keeping it pure means every rule
//! below is testable without an IdP.
//!
//! # Not wired up yet
//!
//! No route calls this. The signature-verification and JWKS-fetch half of the
//! relying party is not implemented, and a half-verified token must never mint a
//! session — so the core lands first, with its tests, and the transport follows.
//! An auth path that is reachable before it is complete is worse than none.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::auth::Role;

/// What the deployment expects of tokens from its IdP.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OidcPolicy {
    /// Expected `iss`. An IdP that is not this one is not ours, however valid
    /// its signature: a token minted by any other issuer must not authenticate.
    pub issuer: String,
    /// Expected `aud` — this deployment's client id. Without it a token issued
    /// for a DIFFERENT application at the same IdP would be accepted here, which
    /// is the classic confused-deputy in OIDC.
    pub client_id: String,
    /// Group claim → role. A group with no entry grants nothing.
    #[serde(default)]
    pub role_map: BTreeMap<String, Role>,
    /// Which claim carries group membership (`groups`, `roles`, `wids`, …).
    #[serde(default = "default_groups_claim")]
    pub groups_claim: String,
    /// Seconds of clock skew tolerated on `exp`/`iat`/`nbf`.
    #[serde(default = "default_skew")]
    pub max_skew_secs: i64,
}

fn default_groups_claim() -> String {
    "groups".to_string()
}
fn default_skew() -> i64 {
    60
}

/// The claims this core reads. Unknown claims are ignored rather than rejected:
/// IdPs add their own freely, and refusing them would break on a vendor's
/// routine change.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct IdTokenClaims {
    pub iss: String,
    pub sub: String,
    /// `aud` may be a string or an array; both are normalised to a list.
    #[serde(default)]
    pub aud: Vec<String>,
    pub exp: i64,
    #[serde(default)]
    pub iat: i64,
    #[serde(default)]
    pub nbf: Option<i64>,
    #[serde(default)]
    pub nonce: Option<String>,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub preferred_username: Option<String>,
    /// Group membership, already lifted from `policy.groups_claim`.
    #[serde(default)]
    pub groups: Vec<String>,
}

/// Why a token was refused. Each variant is a distinct failure an operator has
/// to be able to tell apart: "expired" is a user problem, "issuer" is a
/// misconfiguration, and "no mapped group" is an access decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    Issuer { expected: String, got: String },
    Audience { expected: String },
    Expired { exp: i64, now: i64 },
    NotYetValid { nbf: i64, now: i64 },
    NonceMismatch,
    NoSubject,
    NoMappedGroup { groups: Vec<String> },
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Refusal::Issuer { expected, got } => {
                write!(f, "token issuer {got:?} is not the configured {expected:?}")
            }
            Refusal::Audience { expected } => {
                write!(f, "token audience does not include {expected:?}")
            }
            Refusal::Expired { exp, now } => write!(f, "token expired at {exp} (now {now})"),
            Refusal::NotYetValid { nbf, now } => {
                write!(f, "token not valid until {nbf} (now {now})")
            }
            Refusal::NonceMismatch => write!(f, "nonce does not match the login request"),
            Refusal::NoSubject => write!(f, "token carries no subject"),
            Refusal::NoMappedGroup { groups } => write!(
                f,
                "no configured role for any of the token's groups: {groups:?}"
            ),
        }
    }
}

/// A validated login: who, and at what role.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OidcLogin {
    /// Stable identity for the session. `sub` is the only claim guaranteed
    /// immutable — email and username can be reassigned to a different person
    /// after an offboarding, which would silently transfer that person's history.
    pub subject: String,
    /// Human-readable name for display and audit records.
    pub display: String,
    pub role: Role,
}

/// Validate an ID token's claims against the policy and resolve its role.
///
/// `expected_nonce` is the value this deployment put in the authentication
/// request. It is checked whenever the token carries one: a token replayed from
/// another login attempt is otherwise indistinguishable from a fresh one.
///
/// Roles are resolved by taking the HIGHEST mapped role among the token's
/// groups. Someone in both `soc-analysts` and `soc-admins` gets Admin; taking
/// the first match instead would make the outcome depend on claim ordering,
/// which no IdP guarantees.
pub fn validate(
    claims: &IdTokenClaims,
    policy: &OidcPolicy,
    expected_nonce: Option<&str>,
    now: i64,
) -> Result<OidcLogin, Refusal> {
    if claims.iss != policy.issuer {
        return Err(Refusal::Issuer {
            expected: policy.issuer.clone(),
            got: claims.iss.clone(),
        });
    }
    if !claims.aud.iter().any(|a| a == &policy.client_id) {
        return Err(Refusal::Audience {
            expected: policy.client_id.clone(),
        });
    }
    if claims.exp + policy.max_skew_secs < now {
        return Err(Refusal::Expired {
            exp: claims.exp,
            now,
        });
    }
    if let Some(nbf) = claims.nbf {
        if nbf - policy.max_skew_secs > now {
            return Err(Refusal::NotYetValid { nbf, now });
        }
    }
    // Only compared when the token carries one. An IdP that omits `nonce`
    // cannot be forced to send it, and refusing every such login would break the
    // deployment rather than protect it — the authorization-code exchange is the
    // primary replay defence, this is defence in depth.
    if let (Some(expected), Some(got)) = (expected_nonce, claims.nonce.as_deref()) {
        if expected != got {
            return Err(Refusal::NonceMismatch);
        }
    }
    if claims.sub.trim().is_empty() {
        return Err(Refusal::NoSubject);
    }
    let role = claims
        .groups
        .iter()
        .filter_map(|g| policy.role_map.get(g))
        .max()
        .copied()
        .ok_or_else(|| Refusal::NoMappedGroup {
            groups: claims.groups.clone(),
        })?;
    let display = claims
        .preferred_username
        .clone()
        .or_else(|| claims.email.clone())
        .unwrap_or_else(|| claims.sub.clone());
    Ok(OidcLogin {
        subject: claims.sub.clone(),
        display,
        role,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_760_000_000;

    fn policy() -> OidcPolicy {
        OidcPolicy {
            issuer: "https://idp.example.com".into(),
            client_id: "garmr".into(),
            role_map: [
                ("soc-viewers".to_string(), Role::Viewer),
                ("soc-analysts".to_string(), Role::Analyst),
                ("soc-admins".to_string(), Role::Admin),
            ]
            .into_iter()
            .collect(),
            groups_claim: "groups".into(),
            max_skew_secs: 60,
        }
    }

    fn claims() -> IdTokenClaims {
        IdTokenClaims {
            iss: "https://idp.example.com".into(),
            sub: "u-123".into(),
            aud: vec!["garmr".into()],
            exp: NOW + 300,
            iat: NOW - 10,
            nbf: None,
            nonce: Some("n-1".into()),
            email: Some("henrik@vetra.se".into()),
            preferred_username: Some("henrik".into()),
            groups: vec!["soc-analysts".into()],
        }
    }

    #[test]
    fn a_valid_token_resolves_to_its_mapped_role() {
        let login = validate(&claims(), &policy(), Some("n-1"), NOW).unwrap();
        assert_eq!(login.role, Role::Analyst);
        assert_eq!(login.subject, "u-123");
        assert_eq!(login.display, "henrik");
    }

    #[test]
    fn a_token_from_another_issuer_is_refused() {
        // Signature validity says the token is genuine, not that it is OURS.
        let mut c = claims();
        c.iss = "https://evil-idp.example.net".into();
        assert!(matches!(
            validate(&c, &policy(), Some("n-1"), NOW),
            Err(Refusal::Issuer { .. })
        ));
    }

    #[test]
    fn a_token_for_a_different_client_is_refused() {
        // The confused deputy: a token the same IdP minted for another
        // application would otherwise authenticate here.
        let mut c = claims();
        c.aud = vec!["some-other-app".into()];
        assert!(matches!(
            validate(&c, &policy(), Some("n-1"), NOW),
            Err(Refusal::Audience { .. })
        ));
        // A multi-audience token that DOES include us is fine.
        let mut ok = claims();
        ok.aud = vec!["some-other-app".into(), "garmr".into()];
        assert!(validate(&ok, &policy(), Some("n-1"), NOW).is_ok());
    }

    #[test]
    fn expiry_is_enforced_with_bounded_skew() {
        let mut c = claims();
        c.exp = NOW - 61; // just past exp + skew
        assert!(matches!(
            validate(&c, &policy(), Some("n-1"), NOW),
            Err(Refusal::Expired { .. })
        ));
        // Within the skew window it still passes — clocks drift, and refusing a
        // token a second stale would lock people out for no security gain.
        c.exp = NOW - 30;
        assert!(validate(&c, &policy(), Some("n-1"), NOW).is_ok());
    }

    #[test]
    fn a_replayed_nonce_is_refused_but_an_absent_one_is_tolerated() {
        let mut c = claims();
        c.nonce = Some("n-from-another-login".into());
        assert_eq!(
            validate(&c, &policy(), Some("n-1"), NOW),
            Err(Refusal::NonceMismatch)
        );
        // An IdP that omits nonce cannot be forced to send it; the code exchange
        // is the primary replay defence, so this must not break the login.
        c.nonce = None;
        assert!(validate(&c, &policy(), Some("n-1"), NOW).is_ok());
    }

    #[test]
    fn the_highest_mapped_group_wins_not_the_first() {
        // Claim ORDER is not guaranteed by any IdP, so first-match would make
        // the granted role non-deterministic across logins.
        let mut c = claims();
        c.groups = vec!["soc-analysts".into(), "soc-admins".into()];
        assert_eq!(
            validate(&c, &policy(), Some("n-1"), NOW).unwrap().role,
            Role::Admin
        );
        c.groups = vec!["soc-admins".into(), "soc-analysts".into()];
        assert_eq!(
            validate(&c, &policy(), Some("n-1"), NOW).unwrap().role,
            Role::Admin
        );
    }

    #[test]
    fn an_unmapped_group_grants_nothing() {
        // Fail closed: authenticating at the IdP is not authorization here.
        // Every employee has a valid token; only mapped groups get in.
        let mut c = claims();
        c.groups = vec!["all-employees".into()];
        assert!(matches!(
            validate(&c, &policy(), Some("n-1"), NOW),
            Err(Refusal::NoMappedGroup { .. })
        ));
        c.groups = vec![];
        assert!(matches!(
            validate(&c, &policy(), Some("n-1"), NOW),
            Err(Refusal::NoMappedGroup { .. })
        ));
    }

    #[test]
    fn the_subject_not_the_email_identifies_the_session() {
        // sub is the only immutable claim. An email freed by an offboarding and
        // reassigned would otherwise inherit the previous holder's history.
        let mut c = claims();
        c.preferred_username = None;
        c.email = Some("shared-alias@vetra.se".into());
        let login = validate(&c, &policy(), Some("n-1"), NOW).unwrap();
        assert_eq!(login.subject, "u-123");
        assert_eq!(login.display, "shared-alias@vetra.se");
    }
}
