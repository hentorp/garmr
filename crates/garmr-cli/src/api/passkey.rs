// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! Passkey / WebAuthn login for the console — ES256 (P-256) authenticators
//! (YubiKey, platform passkeys), pure-Rust crypto (p256 + sha2 + ciborium), no
//! openssl. Runtime-enabled when `GARMR_WEBAUTHN_RP_ID` is set; otherwise the
//! surface stays token-only exactly as before.
//!
//! Flow: the operator registers an authenticator once (bootstrapped with the
//! admin bearer token), then logs in with it — a hardware-verified assertion
//! whose success mints a signed, HttpOnly session cookie. Machines keep using
//! the bearer token. WebAuthn requires HTTPS + a real hostname, so garmr sits
//! behind `tailscale serve` (https://<host>.ts.net).
//!
//! Security notes: we verify the assertion the way the spec requires — the
//! clientDataJSON `type`/`challenge`/`origin`, the authenticatorData rpIdHash +
//! user-presence flag, the ES256 signature over `authData || SHA256(clientData)`
//! with the registered public key, and a non-decreasing signature counter. We
//! DON'T verify attestation (the authenticator's model): the operator registers
//! their own key over an admin-authenticated channel, so possession — not
//! provenance — is what matters. Session cookies are MAC'd with a per-install
//! key (blake3 keyed hash) kept in the state store.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use axum::{
    extract::State,
    http::{header, HeaderMap, StatusCode},
    response::{Html, IntoResponse, Response},
    Json,
};
use base64::Engine;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::{bad, oops, ApiResult, ApiState};

/// base64url, no padding — WebAuthn's encoding for binary members.
const B64: base64::engine::general_purpose::GeneralPurpose =
    base64::engine::general_purpose::URL_SAFE_NO_PAD;
const SESSION_COOKIE: &str = "garmr_session";
const SESSION_TTL_SECS: i64 = 12 * 3600;
const CHALLENGE_TTL: Duration = Duration::from_secs(300);
/// Sensitive operations (credential/secret writes) require an interactive login
/// that happened within this window AND was user-verified (PIN/biometric) — a
/// stale or presence-only session must re-authenticate first (step-up).
const STEP_UP_WINDOW_SECS: i64 = 10 * 60;
/// Coalescing window for durable AUTH_LOGIN_FAILED auditing (issue #21). At most
/// one failed-login ledger append is written per window; the rest are traced.
/// Overridable via `GARMR_FAILED_LOGIN_AUDIT_SECS` (0 disables coalescing — every
/// failure writes durably, the pre-fix behaviour). See `FailedAuditThrottle`.
const FAILED_AUDIT_WINDOW_DEFAULT: Duration = Duration::from_secs(60);

use garmr_core::Role;

// ---------------------------------------------------------------- config -----

struct WebauthnCfg {
    rp_id: String,
    origin: String,
    rp_name: String,
}

impl WebauthnCfg {
    /// Built from the environment; `None` (→ passkey disabled) when
    /// `GARMR_WEBAUTHN_RP_ID` is unset. `GARMR_WEBAUTHN_ORIGIN` defaults to
    /// `https://<rp_id>`; both must be the exact browser origin/host the console
    /// is served at (e.g. rp_id `pve.example.ts.net`, origin
    /// `https://pve.example.ts.net`) or WebAuthn refuses to run.
    fn from_env() -> Option<Self> {
        let rp_id = env_trimmed("GARMR_WEBAUTHN_RP_ID")?;
        let origin = env_trimmed("GARMR_WEBAUTHN_ORIGIN")
            .map(|s| s.trim_end_matches('/').to_string())
            .unwrap_or_else(|| format!("https://{rp_id}"));
        let rp_name = env_trimmed("GARMR_WEBAUTHN_RP_NAME").unwrap_or_else(|| "garmr".to_string());
        Some(Self {
            rp_id,
            origin,
            rp_name,
        })
    }
}

fn env_trimmed(k: &str) -> Option<String> {
    std::env::var(k)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

// ------------------------------------------------------------ shared state ---

#[derive(Clone, Copy, PartialEq)]
enum Purpose {
    Register,
    Login,
}

struct Pending {
    challenge_b64: String,
    purpose: Purpose,
    at: Instant,
}

/// The passkey subsystem: config, the per-install session MAC key, and the
/// short-lived challenge map (single-process, so an in-memory map is fine).
pub(super) struct Webauthn {
    cfg: WebauthnCfg,
    session_key: [u8; 32],
    pending: Mutex<HashMap<String, Pending>>,
    /// A handle to the auth state store, so session revocation (the epoch) is
    /// enforced INSIDE `verify_cookie` — every authorization path (require_auth,
    /// check_admin, …) then honours it with no extra call-site work.
    state: garmr_store::StateStore,
}

impl Webauthn {
    /// Build from the environment + state store; `None` when passkey is not
    /// configured. The session MAC key is generated once and persisted so
    /// sessions survive restarts.
    pub(super) fn from_env(store: &garmr_store::Store) -> Option<std::sync::Arc<Self>> {
        let cfg = WebauthnCfg::from_env()?;
        let key_bytes = store.state.auth_get_or_init("session_key", rand32).ok()?;
        let session_key: [u8; 32] = key_bytes.try_into().ok()?;
        tracing::info!(rp_id = %cfg.rp_id, origin = %cfg.origin, "passkey (WebAuthn) login enabled");
        Some(std::sync::Arc::new(Self {
            cfg,
            session_key,
            pending: Mutex::new(HashMap::new()),
            state: store.state.clone(),
        }))
    }

    /// The current session epoch. Every issued session embeds the epoch at mint
    /// time; bumping it (log-out-all) invalidates every outstanding cookie at
    /// once. Missing/garbage → 0 (the initial epoch). A read error also yields 0
    /// so a transient store hiccup does not spuriously invalidate every session
    /// (the MAC + expiry already bound a cookie's validity).
    fn current_epoch(&self) -> u64 {
        self.state
            .auth_get("session_epoch")
            .ok()
            .flatten()
            .and_then(|b| b.try_into().ok())
            .map(u64::from_le_bytes)
            .unwrap_or(0)
    }

    /// Increment the session epoch → every existing session cookie is now invalid.
    fn bump_epoch(&self) -> Result<u64, (StatusCode, String)> {
        let next = self.current_epoch().wrapping_add(1);
        self.state
            .auth_put("session_epoch", &next.to_le_bytes())
            .map_err(oops)?;
        Ok(next)
    }

    /// The browser origin this passkey deployment is bound to (the same origin the
    /// CSRF guard must require) — the single source of truth so the two can never
    /// diverge (review MEDIUM: an RP_ID-only config defaults the origin here, and
    /// a separate env read would leave the CSRF guard's allowed-origin `None`).
    pub(super) fn origin(&self) -> &str {
        &self.cfg.origin
    }

    fn new_challenge(&self, purpose: Purpose) -> (String, String) {
        let challenge_b64 = B64.encode(rand32());
        let id = uuid::Uuid::new_v4().to_string();
        let mut m = self.pending.lock().unwrap();
        m.retain(|_, v| v.at.elapsed() < CHALLENGE_TTL); // opportunistic GC
        m.insert(
            id.clone(),
            Pending {
                challenge_b64: challenge_b64.clone(),
                purpose,
                at: Instant::now(),
            },
        );
        (id, challenge_b64)
    }

    /// Consume a pending challenge (single-use): remove it, and return its value
    /// only if it is unexpired and for the expected purpose.
    fn take_challenge(&self, id: &str, want: Purpose) -> Option<String> {
        let mut m = self.pending.lock().unwrap();
        let p = m.remove(id)?;
        (p.at.elapsed() < CHALLENGE_TTL && p.purpose == want).then_some(p.challenge_b64)
    }

    /// Parse + MAC-verify + expiry-check a cookie — WITHOUT the revocation/epoch
    /// check. Constant-time MAC (blake3::Hash compares in constant time).
    fn parse_session(&self, cookie: &str) -> Option<SessionInfo> {
        let (p_b64, m_b64) = cookie.split_once('.')?;
        let payload = B64.decode(p_b64).ok()?;
        let mac_bytes: [u8; 32] = B64.decode(m_b64).ok()?.try_into().ok()?;
        if blake3::Hash::from_bytes(mac_bytes) != blake3::keyed_hash(&self.session_key, &payload) {
            return None;
        }
        let s = std::str::from_utf8(&payload).ok()?;
        let mut it = s.splitn(6, '|');
        let user = it.next()?.to_string();
        let role: Role = it.next()?.parse().ok()?;
        let exp: i64 = it.next()?.parse().ok()?;
        let auth_time: i64 = it.next()?.parse().ok()?;
        let uv = it.next()? == "1";
        let epoch: u64 = it.next()?.parse().ok()?;
        (exp > chrono::Utc::now().timestamp()).then_some(SessionInfo {
            user,
            role,
            auth_time,
            uv,
            epoch,
        })
    }

    /// Verify a session cookie → `(user, role)`: constant-time MAC, expiry, AND
    /// the current-epoch (revocation) check, so a logged-out-all session is
    /// rejected by every authorization path that resolves a cookie.
    pub(super) fn verify_cookie(&self, cookie: &str) -> Option<(String, Role)> {
        let info = self.parse_session(cookie)?;
        (info.epoch == self.current_epoch()).then_some((info.user, info.role))
    }

    /// The full session info (for step-up checks), including the revocation check.
    fn session_info(&self, cookie: &str) -> Option<SessionInfo> {
        let info = self.parse_session(cookie)?;
        (info.epoch == self.current_epoch()).then_some(info)
    }

    fn make_session(&self, user: &str, role: Role, uv: bool) -> String {
        let now = chrono::Utc::now().timestamp();
        let exp = now + SESSION_TTL_SECS;
        let epoch = self.current_epoch();
        // `user|role|exp|auth_time|uv|epoch`. Role is lowercased explicitly; the
        // username is validated to a delimiter-free lowercase charset at
        // registration, so no global lowercasing (which would corrupt it) is used.
        let payload = format!("{user}|{}|{exp}|{now}|{}|{epoch}", role_str(role), uv as u8);
        let mac = blake3::keyed_hash(&self.session_key, payload.as_bytes());
        format!(
            "{}.{}",
            B64.encode(payload.as_bytes()),
            B64.encode(mac.as_bytes())
        )
    }
}

/// A parsed, MAC-verified, unexpired session.
struct SessionInfo {
    user: String,
    role: Role,
    /// Unix time of the interactive assertion that minted this session.
    auth_time: i64,
    /// Whether that assertion was user-verified (PIN/biometric), for step-up.
    uv: bool,
    epoch: u64,
}

/// Canonical lowercase role token for the session payload (parses back via
/// `Role::from_str`).
fn role_str(r: Role) -> &'static str {
    match r {
        Role::Viewer => "viewer",
        Role::Analyst => "analyst",
        Role::Admin => "admin",
    }
}

/// Validate a passkey username: lowercase, delimiter-free, so it can never break
/// the `|`-delimited session payload or collide by case. Empty → the legacy
/// "operator" identity (backward compatibility).
fn normalize_user(raw: &str) -> Result<String, (StatusCode, String)> {
    let u = raw.trim().to_ascii_lowercase();
    if u.is_empty() {
        return Ok("operator".to_string());
    }
    if u.len() > 64
        || !u
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '_' | '-'))
    {
        return Err(bad("user must be 1–64 chars of [a-z0-9._-]"));
    }
    Ok(u)
}

/// 32 cryptographically-random bytes (two v4 UUIDs, each CSPRNG-backed).
fn rand32() -> Vec<u8> {
    let mut b = [0u8; 32];
    b[..16].copy_from_slice(uuid::Uuid::new_v4().as_bytes());
    b[16..].copy_from_slice(uuid::Uuid::new_v4().as_bytes());
    b.to_vec()
}

// ------------------------------------------------------------ credentials ----

#[derive(Serialize, Deserialize, Clone)]
struct StoredCred {
    /// base64url credential id.
    id: String,
    /// ES256 public-key coordinates (32 bytes each).
    x: Vec<u8>,
    y: Vec<u8>,
    sign_count: u32,
    label: String,
    created: i64,
    /// Named identity this credential logs in as. Defaults to the legacy
    /// "operator" for pre-existing credentials (backward compatible).
    #[serde(default = "default_user")]
    user: String,
    /// Role minted on a successful assertion. Defaults to Admin for pre-existing
    /// credentials (the previous behaviour: every passkey was operator/Admin).
    #[serde(default = "default_admin")]
    role: Role,
    /// Unix time of the last successful login with this credential.
    #[serde(default)]
    last_used: Option<i64>,
    /// A disabled credential cannot log in (soft-revoke; kept for audit history).
    #[serde(default)]
    disabled: bool,
}

fn default_user() -> String {
    "operator".to_string()
}
fn default_admin() -> Role {
    Role::Admin
}

fn load_creds(store: &garmr_store::Store) -> Vec<StoredCred> {
    store
        .state
        .auth_get("passkeys")
        .ok()
        .flatten()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default()
}

fn save_creds(
    store: &garmr_store::Store,
    creds: &[StoredCred],
) -> Result<(), (StatusCode, String)> {
    let bytes = serde_json::to_vec(creds).map_err(oops)?;
    store.state.auth_put("passkeys", &bytes).map_err(oops)
}

// -------------------------------------------------------- ceremony crypto ----

/// The parsed, verified clientDataJSON facts we care about.
fn check_client_data(
    client_data: &[u8],
    want_type: &str,
    want_challenge_b64: &str,
    want_origin: &str,
) -> Result<(), String> {
    let v: serde_json::Value =
        serde_json::from_slice(client_data).map_err(|_| "clientDataJSON: not JSON".to_string())?;
    if v.get("type").and_then(|x| x.as_str()) != Some(want_type) {
        return Err("clientDataJSON: wrong type".into());
    }
    // Challenge is base64url(no-pad) in clientDataJSON; compare the strings.
    if v.get("challenge").and_then(|x| x.as_str()) != Some(want_challenge_b64) {
        return Err("clientDataJSON: challenge does not match".into());
    }
    if v.get("origin").and_then(|x| x.as_str()) != Some(want_origin) {
        return Err("clientDataJSON: wrong origin".into());
    }
    Ok(())
}

/// Verify + parse authenticatorData: rpIdHash == SHA256(rp_id), user-presence
/// flag set. Returns the signature counter and the flags byte.
fn check_auth_data(auth_data: &[u8], rp_id: &str) -> Result<(u32, u8), String> {
    if auth_data.len() < 37 {
        return Err("authenticatorData too short".into());
    }
    let rp_hash = Sha256::digest(rp_id.as_bytes());
    if auth_data[0..32] != rp_hash[..] {
        return Err("authenticatorData: wrong rpIdHash".into());
    }
    let flags = auth_data[32];
    if flags & 0x01 == 0 {
        return Err("user-presence flag missing".into());
    }
    let count = u32::from_be_bytes([auth_data[33], auth_data[34], auth_data[35], auth_data[36]]);
    Ok((count, flags))
}

/// A newly-registered ES256 credential: its id, public-key coordinates, and the
/// authenticator's initial signature counter.
struct ParsedReg {
    cred_id: Vec<u8>,
    x: Vec<u8>,
    y: Vec<u8>,
    count: u32,
}

/// Extract the ES256 public key (x, y) from the attestedCredentialData in an
/// attestationObject's authData, plus the credential id. Verifies it's an EC2 /
/// P-256 / ES256 COSE key.
fn parse_registration(attestation_object: &[u8], rp_id: &str) -> Result<ParsedReg, String> {
    let obj: ciborium::value::Value = ciborium::from_reader(attestation_object)
        .map_err(|_| "attestationObject: not CBOR".to_string())?;
    let auth_data = cbor_map_get(&obj, "authData")
        .and_then(|v| v.as_bytes())
        .ok_or("attestationObject: missing authData")?
        .clone();

    let (count, flags) = check_auth_data(&auth_data, rp_id)?;
    if flags & 0x40 == 0 {
        return Err("authData: missing attested credential data".into());
    }
    // attestedCredentialData: aaguid[16] | credIdLen[2] | credId | COSEKey
    let cred_id_len = u16::from_be_bytes([auth_data[53], auth_data[54]]) as usize;
    let id_start = 55;
    let id_end = id_start + cred_id_len;
    if auth_data.len() < id_end {
        return Err("authData: credential id truncated".into());
    }
    let cred_id = auth_data[id_start..id_end].to_vec();

    let cose: ciborium::value::Value = ciborium::from_reader(&auth_data[id_end..])
        .map_err(|_| "COSE key: not CBOR".to_string())?;
    // kty(1)=2 EC2, alg(3)=-7 ES256, crv(-1)=1 P-256, x(-2), y(-3)
    let kty = cbor_int_get(&cose, 1).and_then(cbor_as_int);
    let alg = cbor_int_get(&cose, 3).and_then(cbor_as_int);
    let crv = cbor_int_get(&cose, -1).and_then(cbor_as_int);
    if kty != Some(2) || alg != Some(-7) || crv != Some(1) {
        return Err("only ES256/P-256 keys are supported".into());
    }
    let x = cbor_int_get(&cose, -2).and_then(|v| v.as_bytes()).cloned();
    let y = cbor_int_get(&cose, -3).and_then(|v| v.as_bytes()).cloned();
    match (x, y) {
        (Some(x), Some(y)) if x.len() == 32 && y.len() == 32 => Ok(ParsedReg {
            cred_id,
            x,
            y,
            count,
        }),
        _ => Err("COSE key is missing valid x/y".into()),
    }
}

/// Verify an ES256 assertion signature over `authData || SHA256(clientData)`.
fn verify_signature(
    x: &[u8],
    y: &[u8],
    auth_data: &[u8],
    client_data: &[u8],
    sig_der: &[u8],
) -> bool {
    use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
    let mut sec1 = Vec::with_capacity(65);
    sec1.push(0x04);
    sec1.extend_from_slice(x);
    sec1.extend_from_slice(y);
    let Ok(vk) = VerifyingKey::from_sec1_bytes(&sec1) else {
        return false;
    };
    let Ok(sig) = Signature::from_der(sig_der) else {
        return false;
    };
    let mut msg = auth_data.to_vec();
    msg.extend_from_slice(&Sha256::digest(client_data));
    vk.verify(&msg, &sig).is_ok()
}

// ---- CBOR helpers ----
fn cbor_map_get<'a>(
    v: &'a ciborium::value::Value,
    key: &str,
) -> Option<&'a ciborium::value::Value> {
    v.as_map()?.iter().find_map(|(k, val)| match k {
        ciborium::value::Value::Text(t) if t == key => Some(val),
        _ => None,
    })
}
fn cbor_int_get(v: &ciborium::value::Value, key: i128) -> Option<&ciborium::value::Value> {
    v.as_map()?.iter().find_map(|(k, val)| match k {
        ciborium::value::Value::Integer(i) if i128::from(*i) == key => Some(val),
        _ => None,
    })
}
fn cbor_as_int(v: &ciborium::value::Value) -> Option<i128> {
    match v {
        ciborium::value::Value::Integer(i) => Some(i128::from(*i)),
        _ => None,
    }
}

// ---------------------------------------------------------------- handlers ---

fn wa(st: &ApiState) -> Result<&std::sync::Arc<Webauthn>, (StatusCode, String)> {
    st.webauthn
        .as_ref()
        .ok_or((StatusCode::NOT_FOUND, "passkey is not enabled".into()))
}

/// Is the caller an Admin (bearer admin token OR an Admin passkey session)? The
/// register bootstrap + admin surface accept either.
pub(super) fn is_admin(st: &ApiState, headers: &HeaderMap) -> bool {
    // bearer admin token
    if let Some(v) = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
    {
        let secret = v.strip_prefix("Bearer ").unwrap_or("");
        if st
            .auth
            .resolve(secret)
            .is_some_and(|p| p.role.allows(garmr_core::Role::Admin))
        {
            return true;
        }
    }
    // Scoped credential holding system:admin (break-glass recovery) → full admin.
    if super::credentials::system_admin_principal(st, headers).is_some() {
        return true;
    }
    // Admin passkey session
    if let (Some(w), Some(c)) = (st.webauthn.as_ref(), session_cookie(headers)) {
        if w.verify_cookie(&c)
            .is_some_and(|(_, r)| r.allows(garmr_core::Role::Admin))
        {
            return true;
        }
    }
    false
}

/// GET /auth/passkey/register/start — admin-gated. Options for creating a new
/// credential (the browser then calls navigator.credentials.create). `?user=`
/// names the identity the credential will log in as (display only; the
/// authoritative binding is set at finish); a stable per-user id lets one
/// operator hold several keys under the same identity.
pub(super) async fn register_start(
    State(st): State<ApiState>,
    axum::extract::Query(p): axum::extract::Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> ApiResult {
    let w = wa(&st)?;
    if !is_admin(&st, &headers) {
        return Err((StatusCode::UNAUTHORIZED, "requires admin".into()));
    }
    let user = normalize_user(p.get("user").map(String::as_str).unwrap_or(""))?;
    let user_id = B64.encode(blake3::hash(user.as_bytes()).as_bytes());
    let (ceremony_id, challenge) = w.new_challenge(Purpose::Register);
    let exclude: Vec<serde_json::Value> = load_creds(&st.store)
        .iter()
        .map(|c| serde_json::json!({"type":"public-key","id": c.id}))
        .collect();
    Ok(Json(serde_json::json!({
        "ceremony_id": ceremony_id,
        "publicKey": {
            "rp": {"id": w.cfg.rp_id, "name": w.cfg.rp_name},
            "user": {"id": user_id, "name": user, "displayName": user},
            "challenge": challenge,
            "pubKeyCredParams": [{"type":"public-key","alg":-7}],
            "authenticatorSelection": {"userVerification":"preferred","residentKey":"discouraged"},
            "timeout": 120000,
            "attestation": "none",
            "excludeCredentials": exclude,
        }
    })))
}

/// POST /auth/passkey/register/finish — admin-gated. Stores the new credential.
pub(super) async fn register_finish(
    State(st): State<ApiState>,
    headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> ApiResult {
    let w = wa(&st)?;
    // Yield the Principal (not a bool) so the registration can be audited under a
    // real actor, fail-closed, BEFORE the credential is persisted.
    let who = super::auth::check_admin(&st, &headers)?;
    // Registration mints a NEW (Admin-by-default) login credential — the most
    // powerful credential write — so it requires step-up like every other
    // credential/secret mutation. The bootstrap path uses the admin bearer token,
    // which require_step_up exempts, so first-key enrollment still works.
    require_step_up(&st, &headers)?;
    let ceremony_id = body
        .get("ceremony_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| bad("missing ceremony_id"))?;
    let challenge = w
        .take_challenge(ceremony_id, Purpose::Register)
        .ok_or_else(|| bad("unknown/expired ceremony"))?;
    let resp = body
        .get("response")
        .ok_or_else(|| bad("missing response"))?;
    let client_data = b64field(resp, "clientDataJSON")?;
    let attestation = b64field(resp, "attestationObject")?;

    check_client_data(&client_data, "webauthn.create", &challenge, &w.cfg.origin).map_err(bad)?;
    let reg = parse_registration(&attestation, &w.cfg.rp_id).map_err(bad)?;

    let id_b64 = B64.encode(&reg.cred_id);
    let label = body
        .get("label")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .unwrap_or("passkey")
        .to_string();
    let user = normalize_user(body.get("user").and_then(|v| v.as_str()).unwrap_or(""))?;
    let role: Role = body
        .get("role")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(|s| s.parse())
        .transpose()
        .map_err(bad)?
        .unwrap_or(Role::Admin);
    let mut creds = load_creds(&st.store);
    if creds.iter().any(|c| c.id == id_b64) {
        return Err(bad("this key is already registered"));
    }
    creds.push(StoredCred {
        id: id_b64,
        x: reg.x,
        y: reg.y,
        sign_count: reg.count,
        label,
        created: chrono::Utc::now().timestamp(),
        user: user.clone(),
        role,
        last_used: None,
        disabled: false,
    });
    // Fail-closed audit BEFORE persisting: this mints a durable login credential,
    // so it must never land without a tamper-evident record (mirrors the
    // admin-surface outbox invariant — record_admin returns a 500 on a durable
    // write failure, aborting before save_creds).
    st.record_admin(
        &who,
        garmr_audit::action::PASSKEY_REGISTER,
        "passkey",
        Some(&user),
        Some(&format!(
            "registered credential '{}' for {user} ({}) (total {})",
            creds.last().map(|c| c.label.as_str()).unwrap_or("?"),
            role_str(role),
            creds.len()
        )),
    )?;
    save_creds(&st.store, &creds)?;
    tracing::info!(count = creds.len(), "passkey registered");
    Ok(Json(
        serde_json::json!({"ok": true, "registered": creds.len()}),
    ))
}

/// GET /auth/passkey/login/start — public. Options for an assertion.
pub(super) async fn login_start(State(st): State<ApiState>) -> ApiResult {
    let w = wa(&st)?;
    let creds = load_creds(&st.store);
    if creds.is_empty() {
        return Err(bad("no passkey registered yet"));
    }
    let (ceremony_id, challenge) = w.new_challenge(Purpose::Login);
    let allow: Vec<serde_json::Value> = creds
        .iter()
        .map(|c| serde_json::json!({"type":"public-key","id": c.id}))
        .collect();
    Ok(Json(serde_json::json!({
        "ceremony_id": ceremony_id,
        "publicKey": {
            "challenge": challenge,
            "rpId": w.cfg.rp_id,
            "timeout": 120000,
            "userVerification": "preferred",
            "allowCredentials": allow,
        }
    })))
}

// ------------------------------------- anonymous failed-login DoS guard (#21) --
//
// `login_finish` is a PUBLIC, unauthenticated endpoint. Recording a durable,
// fsync-capable AUTH_LOGIN_FAILED ledger append on *every* failed attempt lets
// an anonymous caller force unbounded audit-ledger growth (append amplification)
// at request rate — a cheap DoS on the tamper-evident store.
//
// We keep brute-force visibility but move the per-attempt signal off the durable
// path: every failure emits a `tracing::warn!`, while the durable
// AUTH_LOGIN_FAILED record is coalesced to at most one per coalescing window
// (`FAILED_AUDIT_WINDOW_DEFAULT`), annotated with how many failures it accounts
// for. A real brute-force run still
// lands a durable, tamper-evident record (once per window) that carries the true
// attempt count, but the ledger write rate is bounded by wall-clock, not by the
// attacker. The successful-login path is unchanged: it still writes durably every
// time (it is not attacker-amplifiable — a success requires a valid assertion).

/// Bounded, in-memory coalescer for anonymous failed-login audit writes. Pure
/// decision logic (no clock/lock of its own) so it is exhaustively unit-testable;
/// the global instance below owns the clock + lock.
struct FailedAuditThrottle {
    /// When the last durable AUTH_LOGIN_FAILED record was written.
    last_durable: Option<Instant>,
    /// Failures observed since that durable write, awaiting the next window.
    suppressed: u64,
}

impl FailedAuditThrottle {
    /// Register a failed attempt seen at `now`. Returns `Some(n)` when a durable
    /// record should be written now, where `n (>= 1)` is the number of failures
    /// that record accounts for (this one plus any coalesced since the last
    /// durable write); returns `None` when the failure is coalesced (tracing
    /// only). The first failure in each window writes durably; further failures
    /// within the same window are counted and folded into the next durable
    /// record. A zero-length window disables coalescing (every failure durable).
    fn observe(&mut self, now: Instant, window: Duration) -> Option<u64> {
        self.suppressed = self.suppressed.saturating_add(1);
        let due = match self.last_durable {
            None => true,
            Some(t) => now.duration_since(t) >= window,
        };
        if due {
            let n = self.suppressed;
            self.suppressed = 0;
            self.last_durable = Some(now);
            Some(n)
        } else {
            None
        }
    }
}

/// Process-wide throttle state. Single daemon process, so an in-memory guard is
/// sufficient and correct across the shared async handler.
static FAILED_LOGIN_AUDIT: Mutex<FailedAuditThrottle> = Mutex::new(FailedAuditThrottle {
    last_durable: None,
    suppressed: 0,
});

/// The active coalescing window, `GARMR_FAILED_LOGIN_AUDIT_SECS` overriding the
/// default (0 → every failure writes durably, restoring pre-#21 behaviour).
fn failed_audit_window() -> Duration {
    match env_trimmed("GARMR_FAILED_LOGIN_AUDIT_SECS").and_then(|s| s.parse::<u64>().ok()) {
        Some(secs) => Duration::from_secs(secs),
        None => FAILED_AUDIT_WINDOW_DEFAULT,
    }
}

/// Record an anonymous failed login: always trace, but write the durable ledger
/// record only when the throttle says this attempt's window is due.
fn audit_failed_login(msg: &str) {
    tracing::warn!(reason = %msg, "passkey login failed");
    let window = failed_audit_window();
    let decision = FAILED_LOGIN_AUDIT
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .observe(Instant::now(), window);
    let Some(n) = decision else { return };
    // Preserve the true attempt count in the durable record when failures were
    // coalesced, so brute-force volume is still visible to a ledger reader.
    let reason = if n > 1 {
        format!(
            "{msg} ({n} failed passkey logins in the last {}s)",
            window.as_secs()
        )
    } else {
        msg.to_string()
    };
    crate::audit::record_best_effort(
        garmr_audit::AuditRecord::new(garmr_audit::action::AUTH_LOGIN_FAILED, "session")
            .actor(garmr_audit::ActorType::Human, "unknown", None)
            .auth_method("passkey")
            .outcome(garmr_audit::Outcome::Failure)
            .reason(reason),
    );
}

/// POST /auth/passkey/login/finish — public. Verifies the assertion and, on
/// success, sets the session cookie.
pub(super) async fn login_finish(
    State(st): State<ApiState>,
    Json(body): Json<serde_json::Value>,
) -> Response {
    let out = login_finish_inner(&st, &body);
    // Audit auth outcomes best-effort (never block a login on the ledger). This
    // closes the recon gap where auth success/failure was tracing-only.
    match &out {
        Ok(ok) => crate::audit::record_best_effort(
            garmr_audit::AuditRecord::new(garmr_audit::action::AUTH_LOGIN, "session")
                .actor(
                    garmr_audit::ActorType::Human,
                    ok.user.clone(),
                    Some(role_str(ok.role)),
                )
                .auth_method("passkey")
                .outcome(garmr_audit::Outcome::Success),
        ),
        // Route the anonymous failed-attempt signal off the durable ledger path
        // (issue #21): trace every failure, coalesce the durable record. See
        // `audit_failed_login` / `FailedAuditThrottle` above.
        Err((_, msg)) => audit_failed_login(msg),
    }
    match out {
        Ok(ok) => (
            [(header::SET_COOKIE, ok.cookie)],
            Json(serde_json::json!({"ok": true, "user": ok.user, "role": role_str(ok.role)})),
        )
            .into_response(),
        Err((code, msg)) => (code, msg).into_response(),
    }
}

fn login_finish_inner(
    st: &ApiState,
    body: &serde_json::Value,
) -> Result<LoginOk, (StatusCode, String)> {
    let w = wa(st)?;
    let ceremony_id = body
        .get("ceremony_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| bad("missing ceremony_id"))?;
    let challenge = w
        .take_challenge(ceremony_id, Purpose::Login)
        .ok_or_else(|| bad("unknown/expired ceremony"))?;
    let id = body
        .get("id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| bad("missing id"))?;
    let resp = body
        .get("response")
        .ok_or_else(|| bad("missing response"))?;
    let client_data = b64field(resp, "clientDataJSON")?;
    let auth_data = b64field(resp, "authenticatorData")?;
    let signature = b64field(resp, "signature")?;

    let mut creds = load_creds(&st.store);
    let idx = creds
        .iter()
        .position(|c| c.id == id)
        .ok_or_else(|| bad("unknown credential"))?;
    if creds[idx].disabled {
        return Err((StatusCode::UNAUTHORIZED, "credential revoked".into()));
    }

    check_client_data(&client_data, "webauthn.get", &challenge, &w.cfg.origin).map_err(bad)?;
    let (count, flags) = check_auth_data(&auth_data, &w.cfg.rp_id).map_err(bad)?;
    if !verify_signature(
        &creds[idx].x,
        &creds[idx].y,
        &auth_data,
        &client_data,
        &signature,
    ) {
        return Err((
            StatusCode::UNAUTHORIZED,
            "signature verification failed".into(),
        ));
    }
    // Signature-counter cloning check: a non-zero counter must not go backwards.
    if count != 0 && count <= creds[idx].sign_count {
        return Err((
            StatusCode::UNAUTHORIZED,
            "signature counter went backwards (possible clone)".into(),
        ));
    }
    creds[idx].sign_count = count;
    creds[idx].last_used = Some(chrono::Utc::now().timestamp());
    let user = creds[idx].user.clone();
    let role = creds[idx].role;
    // User-Verification flag (0x04): a PIN/biometric was checked, not just
    // presence. Recorded on the session so step-up can require it for sensitive
    // operations while normal login stays UP-only (security-key compatible).
    let uv = flags & 0x04 != 0;
    tracing::info!(cred = %creds[idx].label, user = %user, "passkey login ok");
    save_creds(&st.store, &creds).ok();

    let session = w.make_session(&user, role, uv);
    Ok(LoginOk {
        cookie: session_cookie_str(&session, SESSION_TTL_SECS),
        user,
        role,
    })
}

/// A successful login: the Set-Cookie value plus the resolved identity (so the
/// outcome is audited under the real user, not a hardcoded "operator").
struct LoginOk {
    cookie: String,
    user: String,
    role: Role,
}

/// POST /auth/logout — clears the session cookie.
pub(super) async fn logout() -> Response {
    (
        [(header::SET_COOKIE, session_cookie_str("", 0))],
        Json(serde_json::json!({"ok": true})),
    )
        .into_response()
}

/// GET /auth/status — who am I (for the console to decide login vs app).
pub(super) async fn status(State(st): State<ApiState>, headers: HeaderMap) -> ApiResult {
    let passkey = st.webauthn.is_some();
    let (authed, user, method) = if let Some(v) = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
    {
        let secret = v.strip_prefix("Bearer ").unwrap_or("");
        match st.auth.resolve(secret) {
            Some(p) => (true, p.user, "token"),
            None => (false, String::new(), ""),
        }
    } else if let (Some(w), Some(c)) = (st.webauthn.as_ref(), session_cookie(&headers)) {
        match w.verify_cookie(&c) {
            Some((u, _)) => (true, u, "passkey"),
            None => (false, String::new(), ""),
        }
    } else {
        (false, String::new(), "")
    };
    Ok(Json(serde_json::json!({
        "authenticated": authed, "user": user, "method": method, "passkey_enabled": passkey,
    })))
}

/// GET /login — the self-contained login page (plain HTML + JS, no WASM).
pub(super) async fn login_page() -> Html<&'static str> {
    Html(LOGIN_HTML)
}

// ------------------------------------------- credential + session management --

/// Number of enabled credentials that log in at Admin — the count last-admin
/// protection must never let reach zero.
fn enabled_admin_count(creds: &[StoredCred]) -> usize {
    creds
        .iter()
        .filter(|c| !c.disabled && c.role.allows(Role::Admin))
        .count()
}

/// Enabled Admin-role passkeys registered in the store (for the setup-status
/// read model). 0 when passkeys were never registered.
pub(super) fn admin_passkey_count(store: &garmr_store::Store) -> usize {
    enabled_admin_count(&load_creds(store))
}

/// Enforce step-up for a sensitive operation (credential/secret write): an
/// interactive passkey session that authenticated within `STEP_UP_WINDOW_SECS`
/// AND was user-verified (PIN/biometric). A machine caller holding a valid admin
/// BEARER token is exempt — it is a pre-authorized, non-interactive credential,
/// not a browser session (forcing it through a passkey would break automation).
/// The caller must already be authorized (this is layered on top of `check_admin`).
pub(super) fn require_step_up(
    st: &ApiState,
    headers: &HeaderMap,
) -> Result<(), (StatusCode, String)> {
    // Machine bearer admin token → exempt.
    if let Some(v) = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
    {
        let secret = v.strip_prefix("Bearer ").unwrap_or("");
        if st
            .auth
            .resolve(secret)
            .is_some_and(|p| p.role.allows(Role::Admin))
        {
            return Ok(());
        }
    }
    // A host-minted system:admin (break-glass) credential is at least as strong a
    // human-approval signal as the env admin token → exempt from step-up.
    if super::credentials::system_admin_principal(st, headers).is_some() {
        return Ok(());
    }
    // Interactive passkey session → must be recent AND user-verified.
    if let (Some(w), Some(cookie)) = (st.webauthn.as_ref(), session_cookie(headers)) {
        if let Some(info) = w.session_info(&cookie) {
            let recent = chrono::Utc::now().timestamp() - info.auth_time < STEP_UP_WINDOW_SECS;
            if recent && info.uv {
                return Ok(());
            }
        }
    }
    Err((
        StatusCode::UNAUTHORIZED,
        "sensitive operation: re-authenticate with a user-verified passkey (PIN/biometric) first"
            .to_string(),
    ))
}

/// GET /auth/passkey/credentials — admin-gated. Registered credentials, metadata
/// only (never the raw public-key material).
pub(super) async fn credentials(State(st): State<ApiState>, headers: HeaderMap) -> ApiResult {
    let _ = wa(&st)?;
    super::auth::check_admin(&st, &headers)?;
    let creds = load_creds(&st.store);
    let rows: Vec<serde_json::Value> = creds
        .iter()
        .map(|c| {
            serde_json::json!({
                "id": c.id,
                "label": c.label,
                "user": c.user,
                "role": role_str(c.role),
                "created": c.created,
                "last_used": c.last_used,
                "disabled": c.disabled,
            })
        })
        .collect();
    Ok(Json(serde_json::json!({
        "credentials": rows,
        "enabled_admins": enabled_admin_count(&creds),
    })))
}

/// POST /auth/passkey/credentials/rename {id,label} — admin-gated, audited.
pub(super) async fn credential_rename(
    State(st): State<ApiState>,
    headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> ApiResult {
    let _ = wa(&st)?;
    let who = super::auth::check_admin(&st, &headers)?;
    let id = body
        .get("id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| bad("missing id"))?
        .to_string();
    let label = body
        .get("label")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| bad("missing label"))?
        .to_string();
    let mut creds = load_creds(&st.store);
    let c = creds
        .iter_mut()
        .find(|c| c.id == id)
        .ok_or_else(|| bad("unknown credential"))?;
    let old = c.label.clone();
    c.label = label.clone();
    st.record_admin(
        &who,
        garmr_audit::action::PASSKEY_RENAME,
        "passkey",
        Some(&id),
        Some(&format!("'{old}' -> '{label}'")),
    )?;
    save_creds(&st.store, &creds)?;
    Ok(Json(serde_json::json!({"ok": true})))
}

/// POST /auth/passkey/credentials/revoke {id} — admin-gated, STEP-UP required,
/// audited. Deletes the credential, refusing to remove the LAST enabled Admin
/// credential (lock-out protection).
pub(super) async fn credential_revoke(
    State(st): State<ApiState>,
    headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> ApiResult {
    let _ = wa(&st)?;
    let who = super::auth::check_admin(&st, &headers)?;
    require_step_up(&st, &headers)?;
    let id = body
        .get("id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| bad("missing id"))?
        .to_string();
    let mut creds = load_creds(&st.store);
    let idx = creds
        .iter()
        .position(|c| c.id == id)
        .ok_or_else(|| bad("unknown credential"))?;
    // Last-admin protection: never remove the final route to Admin.
    if !creds[idx].disabled
        && creds[idx].role.allows(Role::Admin)
        && enabled_admin_count(&creds) <= 1
    {
        return Err(bad(
            "refusing to revoke the last enabled Admin credential — register another admin passkey first",
        ));
    }
    let removed = creds.remove(idx);
    st.record_admin(
        &who,
        garmr_audit::action::PASSKEY_REVOKE,
        "passkey",
        Some(&id),
        Some(&format!(
            "revoked '{}' for {} ({})",
            removed.label,
            removed.user,
            role_str(removed.role)
        )),
    )?;
    save_creds(&st.store, &creds)?;
    Ok(Json(
        serde_json::json!({"ok": true, "remaining": creds.len()}),
    ))
}

/// POST /auth/sessions/revoke-all — admin-gated, audited. Bumps the session epoch
/// so every outstanding session cookie (the caller's included) is invalidated at
/// once (the "log out everywhere" control). Machine bearer tokens are unaffected.
pub(super) async fn sessions_revoke_all(
    State(st): State<ApiState>,
    headers: HeaderMap,
) -> ApiResult {
    let w = wa(&st)?;
    let who = super::auth::check_admin(&st, &headers)?;
    // Audit fail-closed BEFORE the bump so the invalidation is always recorded.
    st.record_admin(
        &who,
        garmr_audit::action::SESSION_REVOKE_ALL,
        "session",
        None,
        Some("invalidated all passkey sessions (epoch bump)"),
    )?;
    let epoch = w.bump_epoch()?;
    Ok(Json(serde_json::json!({"ok": true, "epoch": epoch})))
}

// ---- small helpers ----

fn b64field(v: &serde_json::Value, key: &str) -> Result<Vec<u8>, (StatusCode, String)> {
    let s = v
        .get(key)
        .and_then(|x| x.as_str())
        .ok_or_else(|| bad(format!("missing {key}")))?;
    B64.decode(s)
        .map_err(|_| bad(format!("{key}: invalid base64url")))
}

/// Extract the `garmr_session` cookie value from the Cookie header.
pub(super) fn session_cookie(headers: &HeaderMap) -> Option<String> {
    let raw = headers.get(header::COOKIE)?.to_str().ok()?;
    raw.split(';').find_map(|kv| {
        let (k, v) = kv.trim().split_once('=')?;
        (k == SESSION_COOKIE).then(|| v.to_string())
    })
}

fn session_cookie_str(value: &str, max_age: i64) -> String {
    format!(
        "{SESSION_COOKIE}={value}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age={max_age}"
    )
}

static LOGIN_HTML: &str = include_str!("login.html");

/// The compiled-in login page, for the CSP builder to hash its inline script.
pub(super) fn login_html() -> &'static str {
    LOGIN_HTML
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_cookie_carries_all_hardening_flags() {
        // Regression pin (Phase 14 c3): a future edit must not silently drop a
        // flag. HttpOnly (no JS access), Secure (HTTPS only), SameSite=Strict (the
        // primary CSRF defense) must all be present — on both a live session and
        // the max_age=0 logout clear.
        let live = session_cookie_str("tok", SESSION_TTL_SECS);
        let cleared = session_cookie_str("", 0);
        for c in [&live, &cleared] {
            assert!(c.contains("HttpOnly"), "missing HttpOnly in {c}");
            assert!(c.contains("Secure"), "missing Secure in {c}");
            assert!(
                c.contains("SameSite=Strict"),
                "missing SameSite=Strict in {c}"
            );
            assert!(c.contains("Path=/"), "missing Path=/ in {c}");
        }
        assert!(cleared.contains("Max-Age=0"));
    }

    fn tmp_state() -> garmr_store::StateStore {
        let n = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let p =
            std::env::temp_dir().join(format!("garmr-passkey-test-{n}-{:p}.redb", &n as *const _));
        garmr_store::StateStore::open(&p).unwrap()
    }

    fn wh() -> Webauthn {
        Webauthn {
            cfg: WebauthnCfg {
                rp_id: "pve.example.ts.net".into(),
                origin: "https://pve.example.ts.net".into(),
                rp_name: "garmr".into(),
            },
            session_key: [7u8; 32],
            pending: Mutex::new(HashMap::new()),
            state: tmp_state(),
        }
    }

    #[test]
    fn session_roundtrip_and_tamper() {
        let w = wh();
        let c = w.make_session("operator", Role::Admin, true);
        let (u, r) = w.verify_cookie(&c).expect("valid");
        assert_eq!(u, "operator");
        assert_eq!(r, Role::Admin);
        // tamper the payload → MAC fails
        let (p, m) = c.split_once('.').unwrap();
        let forged = format!("{}x.{}", p, m);
        assert!(w.verify_cookie(&forged).is_none());
        // a different key must not validate
        let mut w2 = wh();
        w2.session_key = [9u8; 32];
        assert!(w2.verify_cookie(&c).is_none());
    }

    #[test]
    fn named_session_carries_user_role_and_uv() {
        let w = wh();
        let c = w.make_session("alice", Role::Analyst, false);
        let (u, r) = w.verify_cookie(&c).expect("valid");
        assert_eq!(u, "alice");
        assert_eq!(r, Role::Analyst);
        let info = w.session_info(&c).expect("info");
        assert!(!info.uv, "uv flag round-trips");
        assert!(info.auth_time > 0);
    }

    #[test]
    fn epoch_bump_invalidates_all_sessions() {
        let w = wh();
        let c = w.make_session("operator", Role::Admin, true);
        assert!(w.verify_cookie(&c).is_some(), "valid before revoke-all");
        w.bump_epoch().unwrap();
        assert!(
            w.verify_cookie(&c).is_none(),
            "epoch bump must invalidate the session"
        );
    }

    #[test]
    fn last_admin_protection_counts_only_enabled_admins() {
        let cred = |user: &str, role: Role, disabled: bool| StoredCred {
            id: user.into(),
            x: vec![],
            y: vec![],
            sign_count: 0,
            label: user.into(),
            created: 0,
            user: user.into(),
            role,
            last_used: None,
            disabled,
        };
        let creds = vec![
            cred("a", Role::Admin, false),
            cred("b", Role::Admin, true), // disabled — does not count
            cred("c", Role::Analyst, false),
        ];
        assert_eq!(enabled_admin_count(&creds), 1, "only the one enabled admin");
    }

    #[test]
    fn stored_cred_is_backward_compatible() {
        // A pre-WS3 credential JSON (no user/role/last_used/disabled) must load as
        // the legacy operator/Admin identity so existing passkeys keep working.
        let old = serde_json::json!({
            "id": "abc", "x": [1], "y": [2], "sign_count": 3, "label": "old key", "created": 100
        });
        let c: StoredCred = serde_json::from_value(old).unwrap();
        assert_eq!(c.user, "operator");
        assert_eq!(c.role, Role::Admin);
        assert_eq!(c.last_used, None);
        assert!(!c.disabled);
    }

    #[test]
    fn normalize_user_validates_and_defaults() {
        assert_eq!(normalize_user("").unwrap(), "operator");
        assert_eq!(normalize_user("  Alice  ").unwrap(), "alice");
        assert_eq!(normalize_user("svc-01_a.b").unwrap(), "svc-01_a.b");
        assert!(normalize_user("bad|user").is_err()); // delimiter rejected
        assert!(normalize_user("space bar").is_err());
        assert!(normalize_user(&"x".repeat(65)).is_err());
    }

    #[test]
    fn challenge_is_single_use_and_purpose_bound() {
        let w = wh();
        let (id, ch) = w.new_challenge(Purpose::Login);
        assert!(w.take_challenge(&id, Purpose::Register).is_none()); // wrong purpose
        let (id2, _) = w.new_challenge(Purpose::Login);
        assert_eq!(
            w.take_challenge(&id2, Purpose::Login).unwrap().len(),
            ch.len()
        );
        assert!(w.take_challenge(&id2, Purpose::Login).is_none()); // consumed
    }

    fn fresh_throttle() -> FailedAuditThrottle {
        FailedAuditThrottle {
            last_durable: None,
            suppressed: 0,
        }
    }

    #[test]
    fn failed_login_audit_coalesces_to_one_durable_per_window() {
        // Issue #21: an anonymous flood of failed logins must NOT amplify into an
        // unbounded number of durable AUTH_LOGIN_FAILED ledger appends.
        let window = Duration::from_secs(60);
        let mut t = fresh_throttle();
        let t0 = Instant::now();

        // First failure in a fresh window → one durable write for one attempt.
        assert_eq!(t.observe(t0, window), Some(1));
        // A burst of 998 further failures inside the window → all tracing-only.
        for i in 1..999u64 {
            assert_eq!(
                t.observe(t0 + Duration::from_millis(i), window),
                None,
                "attempt {i} within the window must not write durably"
            );
        }
        // Once the window elapses, the next failure writes durably again and its
        // record accounts for every coalesced attempt (998 suppressed + itself).
        let n = t
            .observe(t0 + window + Duration::from_millis(1), window)
            .expect("durable write is due after the window elapses");
        assert_eq!(n, 999, "coalesced count folds in every suppressed failure");
        // Immediately throttled again.
        assert_eq!(
            t.observe(t0 + window + Duration::from_millis(2), window),
            None
        );
    }

    #[test]
    fn durable_failed_login_writes_are_bounded_by_time_not_attempts() {
        // Hammering the endpoint 10_000 times over ~10s (well inside one 60s
        // window after the first) yields exactly ONE durable write, not 10_000.
        let window = Duration::from_secs(60);
        let mut t = fresh_throttle();
        let start = Instant::now();
        let durable = (0..10_000u64)
            .filter(|&i| {
                t.observe(start + Duration::from_millis(i), window)
                    .is_some()
            })
            .count();
        assert_eq!(
            durable, 1,
            "durable writes must be bounded by elapsed windows, not attempt count"
        );
    }

    #[test]
    fn durable_failed_login_writes_scale_with_windows() {
        // Detection is preserved: a sustained brute-force run still lands a
        // durable record each window (secs 0, 60, 120 over 180 attempts → 3).
        let window = Duration::from_secs(60);
        let mut t = fresh_throttle();
        let start = Instant::now();
        let durable = (0..180u64)
            .filter(|&s| t.observe(start + Duration::from_secs(s), window).is_some())
            .count();
        assert_eq!(durable, 3, "one durable record per elapsed window");
    }

    #[test]
    fn zero_window_disables_coalescing() {
        // The env override `GARMR_FAILED_LOGIN_AUDIT_SECS=0` restores pre-#21
        // behaviour: every failure writes durably (each accounts for 1 attempt).
        let window = Duration::from_secs(0);
        let mut t = fresh_throttle();
        let start = Instant::now();
        for i in 0..5u64 {
            assert_eq!(
                t.observe(start + Duration::from_millis(i), window),
                Some(1),
                "with a zero window every attempt writes durably"
            );
        }
    }

    #[test]
    fn end_to_end_es256_assertion_verifies() {
        use p256::ecdsa::{signature::Signer, Signature, SigningKey};
        use p256::elliptic_curve::sec1::ToSec1Point;
        // Deterministic P-256 "authenticator" key.
        let sk = SigningKey::from_slice(&[0x11u8; 32]).unwrap();
        let pt = sk.verifying_key().as_affine().to_sec1_point(false);
        let (x, y) = (pt.x().unwrap().to_vec(), pt.y().unwrap().to_vec());

        let rp_id = "pve.example.ts.net";
        let origin = "https://pve.example.ts.net";
        let challenge = B64.encode([0xABu8; 32]);
        let client =
            format!(r#"{{"type":"webauthn.get","challenge":"{challenge}","origin":"{origin}"}}"#);
        // authData = rpIdHash(32) | flags(UP) | count(0)
        let mut auth_data = Sha256::digest(rp_id.as_bytes()).to_vec();
        auth_data.push(0x01);
        auth_data.extend_from_slice(&5u32.to_be_bytes());
        let mut msg = auth_data.clone();
        msg.extend_from_slice(&Sha256::digest(client.as_bytes()));
        let sig: Signature = sk.sign(&msg);

        // correct
        assert!(check_client_data(client.as_bytes(), "webauthn.get", &challenge, origin).is_ok());
        assert_eq!(check_auth_data(&auth_data, rp_id).unwrap().0, 5);
        assert!(verify_signature(
            &x,
            &y,
            &auth_data,
            client.as_bytes(),
            sig.to_der().as_bytes()
        ));
        // wrong origin / challenge / rp rejected
        assert!(check_client_data(
            client.as_bytes(),
            "webauthn.get",
            &challenge,
            "https://evil"
        )
        .is_err());
        assert!(check_client_data(client.as_bytes(), "webauthn.get", "AAA", origin).is_err());
        assert!(check_auth_data(&auth_data, "other.host").is_err());
        // tampered authData → signature fails
        let mut bad_auth = auth_data.clone();
        bad_auth[32] = 0x01; // (UP still) but flip a later byte
        bad_auth.extend_from_slice(b"x");
        assert!(!verify_signature(
            &x,
            &y,
            &bad_auth,
            client.as_bytes(),
            sig.to_der().as_bytes()
        ));
    }
}
