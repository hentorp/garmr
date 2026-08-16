// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! Scoped machine API credentials — individually identifiable, rotatable,
//! revocable bearer tokens for non-browser clients (collectors, CLI automation,
//! MCP bridges, integrations).
//!
//! The two legacy global env tokens (`GARMR_API_TOKEN`/`GARMR_ADMIN_TOKEN`) keep
//! working during the transition and are surfaced read-only as "legacy
//! environment credentials", but the target is a per-credential model with a
//! principal, role, scopes, expiry, and last-use tracking.
//!
//! Security invariants:
//! - The plaintext token (`garmr_pat_<base64url>`) is shown EXACTLY ONCE at
//!   issuance and never stored — only a keyed BLAKE3 digest is persisted, so the
//!   store cannot reconstruct or re-present a token, and a stolen store row cannot
//!   authenticate (the digest is not the token).
//! - Token comparison is constant-time (BLAKE3 `Hash` equality over the digests).
//! - Issue/rotate/revoke are Admin-gated, require step-up, and are audit
//!   fail-closed (mirroring the passkey-register outbox invariant).

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use base64::Engine;
use serde::{Deserialize, Serialize};

use garmr_core::{Principal, Role};

use super::passkey::require_step_up;
use super::{bad, oops, ApiResult, ApiState};

const B64: base64::engine::general_purpose::GeneralPurpose =
    base64::engine::general_purpose::URL_SAFE_NO_PAD;
const TOKEN_PREFIX: &str = "garmr_pat_";
const STORE_KEY: &str = "api_credentials";

/// The scope vocabulary. Most entries are coarse WRITE/admin capabilities that gate
/// specific privileged ACTIONS via `require_scope`; per-action write access does not
/// otherwise restrict the read surface — a credential's read access follows its ROLE
/// (a Viewer credential reads what a Viewer reads).
///
/// The one read scope, `api:read`, gates the whole `/api/*` read surface for scoped
/// machine credentials (PR #4): a `garmr_pat_…` hitting `/api/*` is rejected in
/// `require_auth` unless it carries `api:read` or the master `system:admin` scope.
/// See `auth::scoped_credential_allows_path`.
///
/// Enforcement status: `secrets:write` (Cycle 1) and `api:read` (PR #4) are wired
/// today; the remaining write scopes are declared for forward-compatibility and
/// become enforced as their endpoints opt in. Per-read-ENDPOINT scoping (finer than
/// the surface-wide `api:read`) is Cycle 4 (see docs/product/roadmap-webui-product.md).
pub(super) const SCOPES: &[&str] = &[
    "api:read",
    "llm:ask",
    "config:write",
    "secrets:write",
    "rules:approve",
    "actions:approve",
    "backup:operate",
    "collectors:ingest",
    "system:admin",
];

/// Ensure a freshly-issued credential can actually reach the read API. With
/// read-scope enforcement (PR #4) a scoped machine credential is rejected on
/// `/api/*` unless it carries `api:read` (or the master `system:admin`), so a PAT
/// issued without it would be dead on arrival. We therefore default `api:read` ON
/// at issuance unless the request already grants read (`api:read`) or full admin
/// (`system:admin`, which subsumes it).
///
/// Migration: credentials issued BEFORE PR #4 do not carry `api:read` and will 403
/// on `/api/*` — they must be re-issued to regain read access (rotation preserves
/// the original scope set, so it alone does not grant the new read scope).
fn with_default_read_scope(mut scopes: Vec<String>) -> Vec<String> {
    if !scopes
        .iter()
        .any(|s| s == "api:read" || s == "system:admin")
    {
        scopes.push("api:read".to_string());
    }
    scopes
}

/// A stored machine credential. The plaintext token is NEVER stored — only
/// `digest` (a keyed hash) and a non-reversible `fingerprint` for display.
#[derive(Serialize, Deserialize, Clone)]
struct ApiCredential {
    id: String,
    name: String,
    principal: String,
    role: Role,
    scopes: Vec<String>,
    created: i64,
    created_by: String,
    expires_at: Option<i64>,
    last_used_at: Option<i64>,
    last_used_source: Option<String>,
    /// "active" | "revoked".
    status: String,
    revoked_at: Option<i64>,
    rotated_from: Option<String>,
    /// Non-secret short id (hash prefix) so the UI can correlate without the token.
    fingerprint: String,
    /// Keyed BLAKE3 digest of the token — the only thing that can verify it, and
    /// useless as a bearer itself.
    digest: Vec<u8>,
    /// Which event sources this credential may read. Absent = unrestricted,
    /// which is what every credential issued before this field existed
    /// deserializes to — introducing data scopes must not silently narrow an
    /// operator's existing access.
    #[serde(default)]
    sources: Option<Vec<String>>,
}

/// Runtime handle: the auth state store plus the keyed-hash key for digests.
#[derive(Clone)]
pub(crate) struct CredentialStore {
    state: garmr_store::StateStore,
    key: [u8; 32],
    /// Serializes the read-modify-write of the single `api_credentials` blob so a
    /// throttled last-use stamp can never clobber (resurrect) a concurrent
    /// revoke/rotate/issue. redb isolates individual transactions, not the
    /// app-level load→mutate→save cycle. Shared across clones (Arc).
    lock: std::sync::Arc<std::sync::Mutex<()>>,
}

impl CredentialStore {
    pub(crate) fn new(store: &garmr_store::Store) -> anyhow::Result<Self> {
        // Fail closed: the credential-hash key MUST come from the store. Never
        // fall back to a static/all-zero key — that would silently key every PAT
        // digest with a known value if the state DB read errored.
        let raw = store
            .state
            .auth_get_or_init("credential_hash_key", rand32)
            .map_err(|e| anyhow::anyhow!("loading credential_hash_key: {e}"))?;
        let key: [u8; 32] = raw.try_into().map_err(|v: Vec<u8>| {
            anyhow::anyhow!("credential_hash_key wrong length: {} (want 32)", v.len())
        })?;
        Ok(Self {
            state: store.state.clone(),
            key,
            lock: std::sync::Arc::new(std::sync::Mutex::new(())),
        })
    }

    /// Take the write lock (poison-tolerant). Hold it around any load→mutate→save
    /// of the credential blob. No `.await` may occur while it is held.
    fn guard(&self) -> std::sync::MutexGuard<'_, ()> {
        self.lock.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn load(&self) -> Vec<ApiCredential> {
        self.state
            .auth_get(STORE_KEY)
            .ok()
            .flatten()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default()
    }

    fn save(&self, creds: &[ApiCredential]) -> Result<(), (StatusCode, String)> {
        let bytes = serde_json::to_vec(creds).map_err(oops)?;
        self.state.auth_put(STORE_KEY, &bytes).map_err(oops)
    }

    fn digest(&self, token: &str) -> [u8; 32] {
        *blake3::keyed_hash(&self.key, token.as_bytes()).as_bytes()
    }

    /// Resolve a presented bearer to a principal + scopes if it matches an active,
    /// unexpired credential. Constant-time digest comparison (BLAKE3 `Hash` eq).
    /// Stamps `last_used` at most once per minute to bound write amplification.
    /// Resolve a presented token to its principal, action scopes, and DATA scope.
    ///
    /// The data scope rides along with resolution rather than being looked up
    /// separately: a second lookup is a second chance to forget it, and a
    /// forgotten data scope fails open — the credential would read everything.
    pub(super) fn resolve(
        &self,
        presented: &str,
        source: Option<&str>,
    ) -> Option<(Principal, Vec<String>, garmr_core::DataScope)> {
        // Fast reject anything that is not one of our tokens (avoids a store read
        // for every legacy/env bearer).
        if !presented.starts_with(TOKEN_PREFIX) {
            return None;
        }
        let want = blake3::Hash::from_bytes(self.digest(presented));
        let creds = self.load();
        let mut hit: Option<usize> = None;
        for (i, c) in creds.iter().enumerate() {
            let Ok(stored) = <[u8; 32]>::try_from(c.digest.as_slice()) else {
                continue;
            };
            // Compare every active credential (constant-time eq); do not early-out.
            if c.status == "active" && blake3::Hash::from_bytes(stored) == want {
                hit = Some(i);
            }
        }
        let i = hit?;
        let now = now();
        if creds[i].expires_at.is_some_and(|exp| exp <= now) {
            return None;
        }
        let principal = Principal {
            user: creds[i].principal.clone(),
            role: creds[i].role,
        };
        let scopes = creds[i].scopes.clone();
        let data_scope = garmr_core::DataScope::from_opt(creds[i].sources.clone());
        // Throttled last-use stamp — under the write lock with a RE-LOAD, so a
        // revoke/rotate/issue that landed between our read and here is preserved
        // (never resurrect a credential another writer just revoked). Skip if the
        // credential is no longer active on re-read.
        if creds[i].last_used_at.is_none_or(|t| now - t >= 60) {
            let id = creds[i].id.clone();
            let _g = self.guard();
            let mut fresh = self.load();
            if let Some(j) = fresh
                .iter()
                .position(|c| c.id == id && c.status == "active")
            {
                fresh[j].last_used_at = Some(now);
                fresh[j].last_used_source = source.map(str::to_string);
                let _ = self.save(&fresh);
            }
        }
        Some((principal, scopes, data_scope))
    }

    /// Mint a credential and persist it, running `audit(id, fingerprint)` UNDER the
    /// write lock and BEFORE the durable save — fail-closed: a failed audit means
    /// no credential is stored. Returns the plaintext token (shown ONCE) and the
    /// credential's public metadata. Shared by the HTTP issue handler and the
    /// offline `garmr recover` path so there is ONE mint path.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn issue_credential(
        &self,
        name: &str,
        principal: &str,
        role: Role,
        scopes: Vec<String>,
        expires_at: Option<i64>,
        created_by: &str,
        sources: Option<Vec<String>>,
        audit: impl FnOnce(&str, &str) -> Result<(), String>,
    ) -> Result<(String, serde_json::Value), String> {
        let token = format!("{TOKEN_PREFIX}{}", B64.encode(rand32()));
        let fp = fingerprint(&token);
        let cred = ApiCredential {
            id: format!("cred_{}", uuid::Uuid::new_v4()),
            name: name.to_string(),
            principal: principal.to_string(),
            role,
            scopes,
            created: now(),
            created_by: created_by.to_string(),
            expires_at,
            last_used_at: None,
            last_used_source: None,
            status: "active".into(),
            revoked_at: None,
            rotated_from: None,
            fingerprint: fp.clone(),
            digest: self.digest(&token).to_vec(),
            sources,
        };
        let id = cred.id.clone();
        let meta = credential_json(&cred);
        let _g = self.guard();
        let mut creds = self.load();
        creds.push(cred);
        audit(&id, &fp)?; // fail-closed — no save if the audit record can't be written
        self.save(&creds).map_err(|(_, m)| m)?;
        Ok((token, meta))
    }
}

fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

/// 32 CSPRNG bytes (two v4 UUIDs).
fn rand32() -> Vec<u8> {
    let mut b = [0u8; 32];
    b[..16].copy_from_slice(uuid::Uuid::new_v4().as_bytes());
    b[16..].copy_from_slice(uuid::Uuid::new_v4().as_bytes());
    b.to_vec()
}

/// Validate a requested scope set against the vocabulary.
fn validate_scopes(scopes: &[String]) -> Result<(), (StatusCode, String)> {
    for s in scopes {
        if !SCOPES.contains(&s.as_str()) {
            return Err(bad(format!("unknown scope: {s}")));
        }
    }
    Ok(())
}

/// The presented bearer secret from the Authorization header (Bearer only — a
/// machine credential is never a Basic-auth password).
fn bearer(headers: &HeaderMap) -> String {
    headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .unwrap_or("")
        .to_string()
}

/// Enforce that the caller holds `scope`. Resolution order:
/// - a legacy env token (`AuthRegistry`) → treated as full-scope (backward compat);
/// - a scoped API credential → must list `scope`;
/// - an Admin passkey session → full-scope.
///
/// A resolved-but-unscoped caller gets 403; no credential gets 401.
pub(super) fn require_scope(
    st: &ApiState,
    headers: &HeaderMap,
    scope: &str,
) -> Result<Principal, (StatusCode, String)> {
    let presented = bearer(headers);
    // Legacy env token → full scope.
    if let Some(p) = st.auth.resolve(&presented) {
        return Ok(p);
    }
    // Scoped credential.
    if let Some((p, scopes, _data_scope)) = st.creds.resolve(&presented, None) {
        if scopes.iter().any(|s| s == scope) || scopes.iter().any(|s| s == "system:admin") {
            return Ok(p);
        }
        return Err((
            StatusCode::FORBIDDEN,
            format!("this credential lacks the required scope: {scope}"),
        ));
    }
    // Admin passkey session → full scope.
    if let (Some(w), Some(c)) = (
        st.webauthn.as_ref(),
        super::passkey::session_cookie(headers),
    ) {
        if let Some((user, role)) = w.verify_cookie(&c) {
            if role.allows(Role::Admin) {
                return Ok(Principal { user, role });
            }
        }
    }
    Err((StatusCode::UNAUTHORIZED, "unauthorized".to_string()))
}

/// The principal for a presented bearer that resolves to a scoped credential
/// holding the master `system:admin` scope — a FULL admin. This is how a
/// host-minted break-glass recovery credential (or an operator-issued full-admin
/// machine token) is recognized by the admin gates + step-up, not merely by
/// `require_scope`. `system:admin` is the master scope: granting it is granting
/// full admin, so it must satisfy the same gates an Admin env-token does.
pub(super) fn system_admin_principal(st: &ApiState, headers: &HeaderMap) -> Option<Principal> {
    let presented = bearer(headers);
    st.creds
        .resolve(&presented, None)
        .and_then(|(who, scopes, _)| scopes.iter().any(|s| s == "system:admin").then_some(who))
}

/// GET /api/credentials — admin-gated. Credential metadata (never a token/digest),
/// plus the legacy env tokens shown read-only.
pub(super) async fn credentials(State(st): State<ApiState>, headers: HeaderMap) -> ApiResult {
    super::auth::check_admin(&st, &headers)?;
    let rows: Vec<serde_json::Value> = st.creds.load().iter().map(credential_json).collect();
    // Legacy env tokens, surfaced read-only.
    let mut legacy = Vec::new();
    if std::env::var("GARMR_API_TOKEN").is_ok() {
        legacy.push(serde_json::json!({
            "principal": "api", "role": "analyst",
            "note": "Legacy environment credential (GARMR_API_TOKEN) — cannot be viewed or rotated here",
        }));
    }
    if std::env::var("GARMR_ADMIN_TOKEN").is_ok() {
        legacy.push(serde_json::json!({
            "principal": "admin", "role": "admin",
            "note": "Legacy environment credential (GARMR_ADMIN_TOKEN) — cannot be viewed or rotated here",
        }));
    }
    Ok(Json(serde_json::json!({
        "credentials": rows,
        "legacy": legacy,
        "scopes": SCOPES,
    })))
}

/// Public metadata for a credential (no secret material).
fn credential_json(c: &ApiCredential) -> serde_json::Value {
    serde_json::json!({
        "id": c.id,
        "name": c.name,
        "principal": c.principal,
        "role": c.role,
        "scopes": c.scopes,
        "created": c.created,
        "created_by": c.created_by,
        "expires_at": c.expires_at,
        "last_used_at": c.last_used_at,
        "last_used_source": c.last_used_source,
        "status": c.status,
        "revoked_at": c.revoked_at,
        "rotated_from": c.rotated_from,
        "fingerprint": c.fingerprint,
        // Null = unrestricted. Shown so an operator can see at a glance which
        // credentials are confined and to what.
        "sources": c.sources,
    })
}

#[derive(Deserialize)]
pub(super) struct IssueReq {
    name: String,
    #[serde(default)]
    principal: Option<String>,
    role: Role,
    #[serde(default)]
    scopes: Vec<String>,
    #[serde(default)]
    expires_in_days: Option<i64>,
    /// Optional data scope. Omitted = unrestricted (today's behaviour); an
    /// explicit empty list means "read no source at all", which is a coherent
    /// thing to issue while a collector is being provisioned.
    #[serde(default)]
    sources: Option<Vec<String>>,
}

/// POST /admin/credentials — issue a new credential. Admin-gated, step-up, audited.
/// Returns the plaintext token ONCE.
pub(super) async fn issue(
    State(st): State<ApiState>,
    headers: HeaderMap,
    Json(req): Json<IssueReq>,
) -> ApiResult {
    let who = super::auth::check_admin(&st, &headers)?;
    require_step_up(&st, &headers)?;
    if req.name.trim().is_empty() {
        return Err(bad("name is required"));
    }
    validate_scopes(&req.scopes)?;
    // Default the read scope ON so a freshly-issued PAT can actually use the
    // `/api/*` surface it was minted for (PR #4); `api:read` is in SCOPES, so the
    // added scope stays within the validated vocabulary.
    let scopes = with_default_read_scope(req.scopes);
    let name = req.name.trim().to_string();
    let principal = req
        .principal
        .filter(|p| !p.trim().is_empty())
        .map(|p| p.trim().to_string())
        .unwrap_or_else(|| name.clone());
    let expires_at = req.expires_in_days.map(|d| now() + d.max(1) * 86_400);
    let (token, meta) = st
        .creds
        .issue_credential(
            &name,
            &principal,
            req.role,
            scopes,
            expires_at,
            &who.user,
            req.sources,
            |id, fp| {
                st.record_admin(
                    &who,
                    garmr_audit::action::CREDENTIAL_ISSUE,
                    "api_credential",
                    Some(id),
                    Some(&format!("issued '{name}' for {principal} ({fp})")),
                )
                .map(|_| ())
                .map_err(|(_, m)| m)
            },
        )
        .map_err(oops)?;
    // The ONLY time the plaintext token is returned.
    Ok(Json(serde_json::json!({
        "token": token,
        "credential": meta,
        "warning": "copy this token now — it is shown once and cannot be retrieved again",
    })))
}

#[derive(Deserialize)]
pub(super) struct IdReq {
    id: String,
}

/// POST /admin/credentials/rotate — issue a fresh token for the same credential,
/// revoking the old one. Admin-gated, step-up, audited. Returns the new token once.
pub(super) async fn rotate(
    State(st): State<ApiState>,
    headers: HeaderMap,
    Json(req): Json<IdReq>,
) -> ApiResult {
    let who = super::auth::check_admin(&st, &headers)?;
    require_step_up(&st, &headers)?;
    let _g = st.creds.guard();
    let mut creds = st.creds.load();
    let idx = creds
        .iter()
        .position(|c| c.id == req.id && c.status == "active")
        .ok_or_else(|| bad("unknown or inactive credential"))?;
    let token = format!("{TOKEN_PREFIX}{}", B64.encode(rand32()));
    let old = creds[idx].clone();
    creds[idx].status = "revoked".into();
    creds[idx].revoked_at = Some(now());
    let fresh = ApiCredential {
        id: format!("cred_{}", uuid::Uuid::new_v4()),
        rotated_from: Some(old.id.clone()),
        created: now(),
        created_by: who.user.clone(),
        last_used_at: None,
        last_used_source: None,
        status: "active".into(),
        revoked_at: None,
        fingerprint: fingerprint(&token),
        digest: st.creds.digest(&token).to_vec(),
        ..old.clone()
    };
    let new_id = fresh.id.clone();
    creds.push(fresh.clone());
    st.record_admin(
        &who,
        garmr_audit::action::CREDENTIAL_ROTATE,
        "api_credential",
        Some(&new_id),
        Some(&format!(
            "rotated '{}' ({} -> {})",
            old.name, old.id, new_id
        )),
    )?;
    st.creds.save(&creds)?;
    Ok(Json(serde_json::json!({
        "token": token,
        "credential": credential_json(&fresh),
        "warning": "copy this token now — it is shown once and cannot be retrieved again",
    })))
}

/// POST /admin/credentials/revoke — revoke a credential. Admin-gated, step-up,
/// audited.
pub(super) async fn revoke(
    State(st): State<ApiState>,
    headers: HeaderMap,
    Json(req): Json<IdReq>,
) -> ApiResult {
    let who = super::auth::check_admin(&st, &headers)?;
    require_step_up(&st, &headers)?;
    let _g = st.creds.guard();
    let mut creds = st.creds.load();
    let c = creds
        .iter_mut()
        .find(|c| c.id == req.id)
        .ok_or_else(|| bad("unknown credential"))?;
    if c.status == "revoked" {
        return Err(bad("already revoked"));
    }
    c.status = "revoked".into();
    c.revoked_at = Some(now());
    let name = c.name.clone();
    st.record_admin(
        &who,
        garmr_audit::action::CREDENTIAL_REVOKE,
        "api_credential",
        Some(&req.id),
        Some(&format!("revoked '{name}'")),
    )?;
    st.creds.save(&creds)?;
    Ok(Json(serde_json::json!({"ok": true})))
}

/// A non-reversible short id for display (BLAKE3 prefix of the token).
fn fingerprint(token: &str) -> String {
    let h = blake3::hash(token.as_bytes());
    format!("pat_{}", hex8(h.as_bytes()))
}

fn hex8(b: &[u8]) -> String {
    b.iter().take(4).map(|x| format!("{x:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> CredentialStore {
        let n = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let p = std::env::temp_dir().join(format!("garmr-cred-test-{n}-{:p}.redb", &n as *const _));
        CredentialStore {
            state: garmr_store::StateStore::open(&p).unwrap(),
            key: [3u8; 32],
            lock: std::sync::Arc::new(std::sync::Mutex::new(())),
        }
    }

    fn mkcred(
        store: &CredentialStore,
        token: &str,
        scopes: &[&str],
        expires_at: Option<i64>,
    ) -> ApiCredential {
        ApiCredential {
            id: "cred_test".into(),
            name: "svc".into(),
            principal: "svc".into(),
            role: Role::Analyst,
            scopes: scopes.iter().map(|s| s.to_string()).collect(),
            created: now(),
            created_by: "admin".into(),
            expires_at,
            last_used_at: None,
            last_used_source: None,
            status: "active".into(),
            revoked_at: None,
            rotated_from: None,
            fingerprint: fingerprint(token),
            digest: store.digest(token).to_vec(),
            sources: None,
        }
    }

    #[test]
    fn resolves_active_token_but_not_the_stored_digest() {
        let s = store();
        let token = "garmr_pat_abc123";
        let cred = mkcred(&s, token, &["secrets:write"], None);
        s.save(std::slice::from_ref(&cred)).unwrap();
        // The real token resolves.
        let (p, scopes, data_scope) = s.resolve(token, None).expect("token resolves");
        assert_eq!(p.user, "svc");
        assert_eq!(p.role, Role::Analyst);
        assert_eq!(scopes, vec!["secrets:write".to_string()]);
        // No `sources` on this credential ⇒ unrestricted, unchanged behaviour.
        assert!(data_scope.is_unrestricted());
        // The stored digest (hex/bytes) must NOT authenticate as a token.
        let digest_as_token = format!("garmr_pat_{}", B64.encode(&cred.digest));
        assert!(
            s.resolve(&digest_as_token, None).is_none(),
            "digest is not a bearer"
        );
        // A non-PAT string is fast-rejected.
        assert!(s.resolve("legacy-env-token", None).is_none());
    }

    #[test]
    fn revoked_and_expired_tokens_fail() {
        let s = store();
        let token = "garmr_pat_zzz";
        let mut cred = mkcred(&s, token, &["secrets:write"], None);
        cred.status = "revoked".into();
        s.save(&[cred]).unwrap();
        assert!(s.resolve(token, None).is_none(), "revoked fails");

        let s2 = store();
        let t2 = "garmr_pat_exp";
        let expired = mkcred(&s2, t2, &["secrets:write"], Some(now() - 10));
        s2.save(&[expired]).unwrap();
        assert!(s2.resolve(t2, None).is_none(), "expired fails");
    }

    #[test]
    fn a_revoke_is_durable_against_a_resolve_stamp() {
        // Regression for the lost-update race: a resolve (which stamps last_used)
        // must never resurrect a credential that has been revoked.
        let s = store();
        let token = "garmr_pat_race";
        let cred = mkcred(&s, token, &["secrets:write"], None);
        s.save(std::slice::from_ref(&cred)).unwrap();
        assert!(s.resolve(token, None).is_some(), "active before revoke");
        // Revoke lands.
        let mut revoked = s.load();
        revoked[0].status = "revoked".into();
        s.save(&revoked).unwrap();
        // A later resolve neither authenticates nor re-activates it.
        assert!(s.resolve(token, None).is_none(), "revoked stays revoked");
        assert_eq!(s.load()[0].status, "revoked", "revoke not clobbered");
    }

    #[test]
    fn scope_validation_rejects_unknown() {
        assert!(validate_scopes(&["secrets:write".into()]).is_ok());
        assert!(validate_scopes(&["secrets:write".into(), "bogus:scope".into()]).is_err());
    }

    #[test]
    fn issue_defaults_api_read_scope_on() {
        // api:read is a recognized scope in the vocabulary.
        assert!(validate_scopes(&["api:read".into()]).is_ok());
        assert!(SCOPES.contains(&"api:read"));
        // A read credential issued with no explicit scopes still gets api:read so a
        // freshly-minted PAT can reach /api/*.
        assert_eq!(
            with_default_read_scope(vec![]),
            vec!["api:read".to_string()]
        );
        // An explicit write-only scope still gains api:read (append, don't replace).
        assert_eq!(
            with_default_read_scope(vec!["secrets:write".into()]),
            vec!["secrets:write".to_string(), "api:read".to_string()]
        );
        // Not duplicated when already requested.
        assert_eq!(
            with_default_read_scope(vec!["api:read".into()]),
            vec!["api:read".to_string()]
        );
        // The master system:admin scope subsumes read — do not append api:read.
        assert_eq!(
            with_default_read_scope(vec!["system:admin".into()]),
            vec!["system:admin".to_string()]
        );
    }

    #[test]
    fn fingerprint_is_stable_and_non_reversible() {
        let f = fingerprint("garmr_pat_secret");
        assert_eq!(f, fingerprint("garmr_pat_secret"));
        assert!(f.starts_with("pat_"));
        assert!(!f.contains("secret"));
    }

    #[test]
    fn a_credential_stored_before_data_scopes_existed_is_unrestricted() {
        // The compatibility guarantee: introducing scopes must not narrow any
        // existing operator's access. An old blob has no `sources` key at all.
        let old = r#"{
            "id":"cred_1","name":"n","principal":"p","role":"analyst","scopes":["api:read"],
            "created":1,"created_by":"admin","expires_at":null,"last_used_at":null,
            "last_used_source":null,"status":"active","revoked_at":null,
            "rotated_from":null,"fingerprint":"ab","digest":[1,2,3]
        }"#;
        let c: ApiCredential = serde_json::from_str(old).expect("old blob still deserializes");
        assert!(c.sources.is_none());
        assert!(garmr_core::DataScope::from_opt(c.sources).is_unrestricted());
    }

    #[test]
    fn an_explicit_empty_source_list_reads_nothing_not_everything() {
        // `sources: []` is a coherent thing to issue while provisioning. Treating
        // it as unrestricted would make the most locked-down credential the most
        // permissive one.
        let blob = r#"{
            "id":"cred_2","name":"n","principal":"p","role":"analyst","scopes":[],
            "created":1,"created_by":"admin","expires_at":null,"last_used_at":null,
            "last_used_source":null,"status":"active","revoked_at":null,
            "rotated_from":null,"fingerprint":"ab","digest":[1],"sources":[]
        }"#;
        let c: ApiCredential = serde_json::from_str(blob).unwrap();
        let scope = garmr_core::DataScope::from_opt(c.sources);
        assert!(!scope.is_unrestricted());
        assert!(!scope.allows_source("hr"));
    }

    #[test]
    fn the_listing_shows_the_scope_and_still_never_a_secret() {
        let c: ApiCredential = serde_json::from_str(
            r#"{"id":"c","name":"n","principal":"p","role":"analyst","scopes":[],
                "created":1,"created_by":"a","expires_at":null,"last_used_at":null,
                "last_used_source":null,"status":"active","revoked_at":null,
                "rotated_from":null,"fingerprint":"fp","digest":[9,9,9],
                "sources":["hr"]}"#,
        )
        .unwrap();
        let j = credential_json(&c);
        assert_eq!(j["sources"][0], "hr");
        let text = j.to_string();
        assert!(
            !text.contains("digest"),
            "the digest must never be listed: {text}"
        );
        assert!(!text.contains("9,9,9"), "{text}");
    }
}
