// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! RBAC: roles, principals, and a bearer-token → principal registry.
//!
//! garmr historically had two shared secrets: `GARMR_API_TOKEN` (the whole read
//! surface) and `GARMR_ADMIN_TOKEN` (the `/admin` mutating surface). That gives
//! no per-user identity and no least-privilege tier between "read everything" and
//! "do everything" — the single biggest parity gap versus Splunk/Elastic for
//! multi-operator use.
//!
//! This module adds **named principals** with **ordered roles**
//! (`Viewer` < `Analyst` < `Admin`) resolved from bearer tokens. Capability
//! checks are a plain `role >= required`. The two legacy env tokens keep working
//! by mapping to synthetic principals (`api`/`admin`), so nothing breaks; new
//! per-user tokens are configured via `GARMR_USERS` (a JSON array, kept in the
//! environment like every other secret — never the TOML file).

use serde::{Deserialize, Serialize};

/// A role, ordered least → most privileged so a capability check is `role >=
/// required`. Each tier is a superset of the one below.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    /// Read-only: query, search, cases/entities/graph, ATT&CK coverage, the UI.
    Viewer,
    /// Viewer + operator actions: acknowledge, silence a noisy rule, add notes.
    Analyst,
    /// Analyst + governance: approve rules/actions, prune cases, the admin surface.
    Admin,
}

impl Role {
    /// Does this role meet the `required` privilege level?
    pub fn allows(self, required: Role) -> bool {
        self >= required
    }
}

impl std::str::FromStr for Role {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        match s.trim().to_ascii_lowercase().as_str() {
            "viewer" | "read" | "readonly" | "read_only" => Ok(Role::Viewer),
            "analyst" | "operator" => Ok(Role::Analyst),
            "admin" | "administrator" => Ok(Role::Admin),
            other => Err(format!("unknown role: {other} (viewer|analyst|admin)")),
        }
    }
}

/// An authenticated identity: who, and at what role.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Principal {
    pub user: String,
    pub role: Role,
}

/// One configured token → principal binding.
#[derive(Debug, Clone, Deserialize)]
pub struct UserToken {
    pub token: String,
    pub user: String,
    pub role: Role,
}

/// Resolves a presented bearer token to a [`Principal`]. Resolution is
/// constant-time over the whole set — it always checks every entry so response
/// timing never leaks which token (if any) matched.
#[derive(Debug, Clone, Default)]
pub struct AuthRegistry {
    users: Vec<UserToken>,
}

impl AuthRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a named user token (e.g. the legacy `GARMR_API_TOKEN` as
    /// `api`/Analyst, `GARMR_ADMIN_TOKEN` as `admin`/Admin).
    pub fn add(&mut self, user: impl Into<String>, role: Role, token: impl Into<String>) {
        self.users.push(UserToken {
            user: user.into(),
            role,
            token: token.into(),
        });
    }

    /// Merge users from a JSON array string: `[{"token","user","role"}, …]`.
    /// Returns how many were added. Empty/whitespace input is a no-op.
    pub fn add_json(&mut self, json: &str) -> Result<usize, String> {
        if json.trim().is_empty() {
            return Ok(0);
        }
        let list: Vec<UserToken> =
            serde_json::from_str(json).map_err(|e| format!("GARMR_USERS parse error: {e}"))?;
        let n = list.len();
        self.users.extend(list);
        Ok(n)
    }

    /// Resolve a token to its principal, or `None`. Constant-time: every entry is
    /// compared even after a match, so timing does not reveal token order/length.
    pub fn resolve(&self, presented: &str) -> Option<Principal> {
        let mut found: Option<Principal> = None;
        for u in &self.users {
            if ct_eq(presented.as_bytes(), u.token.as_bytes()) {
                found = Some(Principal {
                    user: u.user.clone(),
                    role: u.role,
                });
            }
        }
        found
    }

    pub fn is_empty(&self) -> bool {
        self.users.is_empty()
    }

    pub fn len(&self) -> usize {
        self.users.len()
    }

    /// Is any configured principal at least `role`? (Gates the LLM-spend
    /// endpoints, which require Admin when an admin exists but fall back open
    /// when none is configured — preserving the pre-RBAC behaviour.)
    pub fn has_role(&self, role: Role) -> bool {
        self.users.iter().any(|u| u.role >= role)
    }
}

/// Constant-time secret comparison via fixed-size BLAKE3 digests. Hashing both
/// sides to 32 bytes before the XOR-fold means neither the token's bytes nor its
/// LENGTH leaks through timing (a raw pad-and-compare would reveal length via the
/// loop count, letting an attacker binary-search the secret's length).
pub(crate) fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    let ha = blake3::hash(a);
    let hb = blake3::hash(b);
    ha.as_bytes()
        .iter()
        .zip(hb.as_bytes())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn roles_are_ordered_and_allows_is_superset() {
        assert!(Role::Viewer < Role::Analyst);
        assert!(Role::Analyst < Role::Admin);
        // Admin meets every requirement; Viewer meets only Viewer.
        assert!(Role::Admin.allows(Role::Viewer));
        assert!(Role::Admin.allows(Role::Analyst));
        assert!(Role::Admin.allows(Role::Admin));
        assert!(Role::Analyst.allows(Role::Viewer));
        assert!(!Role::Analyst.allows(Role::Admin));
        assert!(Role::Viewer.allows(Role::Viewer));
        assert!(!Role::Viewer.allows(Role::Analyst));
    }

    #[test]
    fn role_from_str_accepts_aliases_and_rejects_junk() {
        assert_eq!(Role::from_str("viewer").unwrap(), Role::Viewer);
        assert_eq!(Role::from_str("READ_ONLY").unwrap(), Role::Viewer);
        assert_eq!(Role::from_str(" Analyst ").unwrap(), Role::Analyst);
        assert_eq!(Role::from_str("operator").unwrap(), Role::Analyst);
        assert_eq!(Role::from_str("admin").unwrap(), Role::Admin);
        assert!(Role::from_str("superuser").is_err());
    }

    #[test]
    fn registry_resolves_the_right_principal_and_rejects_unknown() {
        let mut reg = AuthRegistry::new();
        reg.add("api", Role::Analyst, "legacy-api-tok");
        reg.add("admin", Role::Admin, "legacy-admin-tok");
        let added = reg
            .add_json(r#"[{"token":"alice-tok","user":"alice","role":"viewer"}]"#)
            .unwrap();
        assert_eq!(added, 1);
        assert_eq!(reg.len(), 3);

        assert_eq!(
            reg.resolve("alice-tok"),
            Some(Principal {
                user: "alice".into(),
                role: Role::Viewer
            })
        );
        assert_eq!(reg.resolve("legacy-admin-tok").unwrap().role, Role::Admin);
        assert_eq!(reg.resolve("legacy-api-tok").unwrap().user, "api");
        // wrong token, empty token, and a prefix of a real token all fail
        assert_eq!(reg.resolve("nope"), None);
        assert_eq!(reg.resolve(""), None);
        assert_eq!(reg.resolve("alice-to"), None);
    }

    #[test]
    fn has_role_reports_the_configured_ceiling() {
        let mut reg = AuthRegistry::new();
        assert!(!reg.has_role(Role::Admin));
        reg.add("v", Role::Viewer, "a");
        assert!(reg.has_role(Role::Viewer));
        assert!(!reg.has_role(Role::Analyst));
        reg.add("adm", Role::Admin, "b");
        assert!(reg.has_role(Role::Admin));
        assert!(reg.has_role(Role::Analyst));
    }

    #[test]
    fn add_json_empty_is_noop_and_bad_json_errors() {
        let mut reg = AuthRegistry::new();
        assert_eq!(reg.add_json("").unwrap(), 0);
        assert_eq!(reg.add_json("   ").unwrap(), 0);
        assert!(reg.is_empty());
        assert!(reg.add_json("not json").is_err());
        assert!(reg.add_json(r#"[{"token":"t","user":"u"}]"#).is_err()); // missing role
    }
}