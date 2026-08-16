// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! ID-token verification: parse a compact JWS, verify its signature against the
//! IdP's published key, then hand the claims to [`garmr_core::oidc`] for the
//! policy decisions.
//!
//! The split is deliberate. This module answers "did the IdP really sign this,
//! unmodified?" — a cryptographic question with a yes/no answer. Everything
//! about *who the token is for* and *what it grants* lives in the pure core,
//! where it is testable without keys.
//!
//! # Algorithms
//!
//! **ES256 only.** garmr carries `p256` (already used for WebAuthn) and no RSA
//! implementation, and an unimplemented algorithm must be REFUSED rather than
//! waved through — so an RS256 token is rejected with a clear message telling
//! the operator to configure ES256 signing at the IdP. Most IdPs support it;
//! Keycloak, Entra and Okta all do. Adding RS256 means adding an RSA dependency,
//! which is a deliberate decision, not something to slip in silently.
//!
//! # The attacks this refuses by construction
//!
//! - `alg: none` — a token with no signature at all. Historically the single
//!   most common JWT vulnerability.
//! - **Algorithm confusion** — the header is attacker-controlled, so it can
//!   never select the verification method. The algorithm is checked against a
//!   fixed allowlist and the key type decides the primitive.
//! - **Tampering** — the signature covers `header.payload` exactly as
//!   transmitted, so re-encoding differences cannot be exploited.

// Constructed by the JWKS fetch, which is the next piece of the relying party.
// Marked rather than left to look like an oversight: this module lands ahead of
// its caller ON PURPOSE, so that signature verification is reviewed and tested
// before anything can mint a session with it.
#![allow(dead_code)]

use axum::extract::State;
use garmr_core::oidc::IdTokenClaims;

/// Why a token could not be verified. Separate from
/// [`garmr_core::oidc::Refusal`]: this is "the token is not authentic", which an
/// operator must be able to distinguish from "the token is authentic but not
/// for you".
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum VerifyError {
    Malformed(&'static str),
    UnsupportedAlg(String),
    BadSignature,
    UnknownKey(String),
    Claims(String),
    /// The IdP's own metadata or response is unusable — distinct from a bad
    /// token, because the fix is a configuration change, not a re-login.
    Discovery(String),
}

impl std::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VerifyError::Malformed(w) => write!(f, "malformed ID token: {w}"),
            VerifyError::UnsupportedAlg(a) => write!(
                f,
                "unsupported ID-token algorithm {a:?} — garmr verifies ES256; \
                 configure ES256 signing for this client at the IdP"
            ),
            VerifyError::BadSignature => write!(f, "ID-token signature does not verify"),
            VerifyError::UnknownKey(kid) => {
                write!(f, "no published key matches the token's kid {kid:?}")
            }
            VerifyError::Claims(e) => write!(f, "malformed ID-token claims: {e}"),
            VerifyError::Discovery(e) => write!(f, "{e}"),
        }
    }
}

/// One verification key from the IdP's JWKS, narrowed to what ES256 needs.
#[derive(Debug, Clone)]
pub(super) struct Jwk {
    pub kid: String,
    /// P-256 public point coordinates, 32 bytes each.
    pub x: Vec<u8>,
    pub y: Vec<u8>,
}

#[derive(serde::Deserialize)]
struct JoseHeader {
    alg: String,
    #[serde(default)]
    kid: Option<String>,
}

fn b64(part: &str) -> Result<Vec<u8>, VerifyError> {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(part)
        .map_err(|_| VerifyError::Malformed("not base64url"))
}

/// Verify a compact JWS and return its claims.
///
/// `keys` is the IdP's published key set. The token's `kid` selects one; a token
/// without `kid` is accepted only when the IdP publishes exactly one key, since
/// otherwise "try them all" would let a compromised key of any age validate
/// tokens forever.
pub(super) fn verify(token: &str, keys: &[Jwk]) -> Result<IdTokenClaims, VerifyError> {
    use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};

    let mut parts = token.split('.');
    let (h, p, s) = match (parts.next(), parts.next(), parts.next(), parts.next()) {
        (Some(h), Some(p), Some(s), None) => (h, p, s),
        _ => return Err(VerifyError::Malformed("expected three dot-separated parts")),
    };

    let header: JoseHeader =
        serde_json::from_slice(&b64(h)?).map_err(|_| VerifyError::Malformed("bad header JSON"))?;
    // The header is attacker-controlled, so it may narrow but never SELECT the
    // verification method. Anything outside the allowlist — `none` above all —
    // is refused before a key is even looked up.
    if header.alg != "ES256" {
        return Err(VerifyError::UnsupportedAlg(header.alg));
    }

    let key = match (&header.kid, keys) {
        (Some(kid), _) => keys
            .iter()
            .find(|k| &k.kid == kid)
            .ok_or_else(|| VerifyError::UnknownKey(kid.clone()))?,
        // No kid: only unambiguous when the IdP publishes one key. Trying every
        // key would mean a key retired years ago still validates tokens.
        (None, [only]) => only,
        (None, _) => {
            return Err(VerifyError::Malformed(
                "token has no kid and the IdP publishes more than one key",
            ))
        }
    };

    let mut sec1 = Vec::with_capacity(65);
    sec1.push(0x04); // uncompressed point
    sec1.extend_from_slice(&key.x);
    sec1.extend_from_slice(&key.y);
    let vk = VerifyingKey::from_sec1_bytes(&sec1)
        .map_err(|_| VerifyError::Malformed("IdP key is not a valid P-256 point"))?;

    let sig_bytes = b64(s)?;
    // JWS ES256 is the raw 64-byte (r‖s) form, not DER.
    let sig = Signature::from_slice(&sig_bytes)
        .map_err(|_| VerifyError::Malformed("bad signature encoding"))?;

    // Sign over the bytes EXACTLY as transmitted: re-encoding the header or
    // payload before verifying would let two different strings share a
    // signature, which is the whole family of encoding-confusion bugs.
    let signed = format!("{h}.{p}");
    vk.verify(signed.as_bytes(), &sig)
        .map_err(|_| VerifyError::BadSignature)?;

    let raw = b64(p)?;
    parse_claims(&raw)
}

/// Decode the payload into [`IdTokenClaims`], normalising the two shapes real
/// IdPs use for `aud` (a string, or an array of strings).
fn parse_claims(raw: &[u8]) -> Result<IdTokenClaims, VerifyError> {
    let v: serde_json::Value =
        serde_json::from_slice(raw).map_err(|e| VerifyError::Claims(e.to_string()))?;
    let aud = match v.get("aud") {
        Some(serde_json::Value::String(s)) => vec![s.clone()],
        Some(serde_json::Value::Array(a)) => a
            .iter()
            .filter_map(|x| x.as_str().map(str::to_string))
            .collect(),
        _ => Vec::new(),
    };
    let str_at = |k: &str| v.get(k).and_then(|x| x.as_str()).map(str::to_string);
    let i64_at = |k: &str| v.get(k).and_then(serde_json::Value::as_i64);
    Ok(IdTokenClaims {
        iss: str_at("iss").unwrap_or_default(),
        sub: str_at("sub").unwrap_or_default(),
        aud,
        exp: i64_at("exp").unwrap_or(0),
        iat: i64_at("iat").unwrap_or(0),
        nbf: i64_at("nbf"),
        nonce: str_at("nonce"),
        email: str_at("email"),
        preferred_username: str_at("preferred_username"),
        groups: v
            .get("groups")
            .and_then(serde_json::Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default(),
    })
}

// ---------------------------------------------------------------- PKCE ------

/// A PKCE pair for one authorization request (RFC 7636).
///
/// PKCE is what stops an intercepted authorization CODE from being redeemed by
/// anyone else: the token exchange must present the verifier whose hash the
/// authorization request already committed to. Without it a code leaked through
/// a redirect, a proxy log or browser history is enough to obtain a session —
/// which is not a failure mode a SIEM can carry.
pub(super) struct Pkce {
    /// Held locally; sent only in the token exchange.
    pub verifier: String,
    /// Sent in the authorization request; the IdP stores it and compares later.
    pub challenge: String,
}

/// The S256 challenge for a verifier: unpadded base64url(SHA-256(verifier)).
///
/// `plain` is deliberately not implemented. RFC 7636 permits it, but it makes
/// the challenge EQUAL to the verifier, so anyone who observes the
/// authorization request can redeem the code and the protection becomes
/// decorative. An unsupported mode is better than a hollow one.
pub(super) fn s256_challenge(verifier: &str) -> String {
    use base64::Engine;
    use sha2::{Digest, Sha256};
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

impl Pkce {
    /// Generate a fresh pair from 32 CSPRNG bytes (the same source the passkey
    /// challenge uses), rendered base64url — 43 characters, exactly RFC 7636's
    /// floor, and unguessable, which is the property that matters.
    pub(super) fn generate() -> Self {
        use base64::Engine;
        let mut raw = [0u8; 32];
        raw[..16].copy_from_slice(uuid::Uuid::new_v4().as_bytes());
        raw[16..].copy_from_slice(uuid::Uuid::new_v4().as_bytes());
        let verifier = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw);
        let challenge = s256_challenge(&verifier);
        Self {
            verifier,
            challenge,
        }
    }
}

// ---------------------------------------------------------------- JWKS ------

/// Parse an IdP's JWKS document into the P-256 keys this build can verify with.
///
/// Unsupported key types are SKIPPED, not fatal: an IdP commonly publishes RSA
/// and EC keys side by side, and failing the whole document because one entry
/// is unsupported would break a deployment whose ES256 key is right there. An
/// EMPTY result is the caller's signal that this IdP publishes nothing garmr can
/// verify — a configuration problem worth naming, and distinct from a malformed
/// document, which is a different fault.
pub(super) fn parse_jwks(body: &[u8]) -> Result<Vec<Jwk>, VerifyError> {
    use base64::Engine;
    let doc: serde_json::Value =
        serde_json::from_slice(body).map_err(|e| VerifyError::Claims(e.to_string()))?;
    let keys = doc
        .get("keys")
        .and_then(serde_json::Value::as_array)
        .ok_or(VerifyError::Malformed("JWKS has no keys array"))?;
    let dec = |v: Option<&serde_json::Value>| -> Option<Vec<u8>> {
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(v?.as_str()?)
            .ok()
    };
    let mut out = Vec::new();
    for k in keys {
        // Only EC P-256 SIGNING keys. `use: "enc"` is an encryption key and must
        // never verify a signature, however well the curve matches.
        if k.get("kty").and_then(|v| v.as_str()) != Some("EC")
            || k.get("crv").and_then(|v| v.as_str()) != Some("P-256")
            || k.get("use")
                .and_then(|v| v.as_str())
                .is_some_and(|u| u != "sig")
        {
            continue;
        }
        let (Some(x), Some(y)) = (dec(k.get("x")), dec(k.get("y"))) else {
            continue;
        };
        // A P-256 coordinate is exactly 32 bytes. Padding a short one would
        // produce a DIFFERENT point, so reject rather than repair.
        if x.len() != 32 || y.len() != 32 {
            continue;
        }
        out.push(Jwk {
            kid: k
                .get("kid")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string(),
            x,
            y,
        });
    }
    Ok(out)
}

// ----------------------------------------------------------- discovery ------

/// The endpoints garmr needs from an IdP's discovery document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Discovery {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub jwks_uri: String,
}

/// Parse `/.well-known/openid-configuration`, refusing a document that does not
/// belong to the issuer we asked about.
///
/// Two checks, and both are load-bearing:
///
/// - **The document's own `issuer` must equal the configured one.** OIDC
///   Discovery requires this precisely because a mismatch means the response
///   came from somewhere else, and every downstream `iss` check would then be
///   comparing against an attacker's value.
/// - **Every endpoint must be on the issuer's host.** Not mandated by the spec,
///   but a discovery document is fetched before anything is verified, so a
///   tampered one could point `token_endpoint` at an attacker's server — and the
///   token exchange sends the client secret and the authorization code there.
///   That is credential theft with no signature involved, so the host is pinned
///   rather than trusted.
pub(super) fn parse_discovery(
    body: &[u8],
    expected_issuer: &str,
) -> Result<Discovery, VerifyError> {
    let v: serde_json::Value =
        serde_json::from_slice(body).map_err(|e| VerifyError::Claims(e.to_string()))?;
    let get = |k: &str| -> Result<String, VerifyError> {
        v.get(k)
            .and_then(|x| x.as_str())
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .ok_or(VerifyError::Malformed(
                "discovery document is missing a field",
            ))
    };
    let issuer = get("issuer")?;
    if issuer != expected_issuer {
        return Err(VerifyError::Discovery(format!(
            "discovery document declares issuer {issuer:?}, expected {expected_issuer:?}"
        )));
    }
    let d = Discovery {
        authorization_endpoint: get("authorization_endpoint")?,
        token_endpoint: get("token_endpoint")?,
        jwks_uri: get("jwks_uri")?,
        issuer,
    };
    let host =
        garmr_core::host_of(&d.issuer).ok_or(VerifyError::Malformed("issuer is not a URL"))?;
    for (name, url) in [
        ("authorization_endpoint", &d.authorization_endpoint),
        ("token_endpoint", &d.token_endpoint),
        ("jwks_uri", &d.jwks_uri),
    ] {
        // Also refuse a non-https endpoint: the code and the client secret cross
        // this wire, and a downgrade would make every check above irrelevant.
        if !url.starts_with("https://") {
            return Err(VerifyError::Discovery(format!(
                "{name} is not https: {url}"
            )));
        }
        if garmr_core::host_of(url) != Some(host) {
            return Err(VerifyError::Discovery(format!(
                "{name} host does not match the issuer ({url} vs {host})"
            )));
        }
    }
    Ok(d)
}

/// The ID token out of a token-endpoint response.
///
/// Only `id_token` is read. The access token is for calling the IdP's own APIs,
/// which garmr does not do — and holding a credential with no use for it is
/// gratuitous exposure.
pub(super) fn parse_token_response(body: &[u8]) -> Result<String, VerifyError> {
    let v: serde_json::Value =
        serde_json::from_slice(body).map_err(|e| VerifyError::Claims(e.to_string()))?;
    // An OAuth error response is a 4xx with a JSON body; surface its `error`
    // rather than the useless "missing id_token", so a misconfigured client id
    // says so instead of looking like a protocol bug.
    if let Some(err) = v.get("error").and_then(|x| x.as_str()) {
        let desc = v
            .get("error_description")
            .and_then(|x| x.as_str())
            .unwrap_or("");
        return Err(VerifyError::Discovery(format!(
            "token endpoint refused the exchange: {err} {desc}"
        )));
    }
    v.get("id_token")
        .and_then(|x| x.as_str())
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .ok_or(VerifyError::Malformed("token response has no id_token"))
}

// -------------------------------------------------- pending login store -----

/// How long an authorization request may stay outstanding. Long enough for a
/// human to complete an MFA prompt at the IdP, short enough that an abandoned
/// login is not a durable target.
const PENDING_TTL: std::time::Duration = std::time::Duration::from_secs(10 * 60);

/// Cap on outstanding logins, so an unauthenticated caller hitting the start
/// endpoint in a loop cannot grow this map without bound. Ten minutes of real
/// human logins is far below this.
const MAX_PENDING: usize = 256;

/// One authorization request in flight, keyed by its `state`.
struct PendingLogin {
    verifier: String,
    nonce: String,
    at: std::time::Instant,
}

/// The outstanding authorization requests.
///
/// `state` is the CSRF defence and the lookup key at once: the callback carries
/// it back, and an entry that is not here was not started by this server. That
/// is what stops an attacker from feeding a victim a callback URL containing
/// their OWN authorization code — a login-CSRF that would silently attach the
/// victim's browser to the attacker's identity.
#[derive(Default)]
pub(super) struct PendingLogins {
    inner: std::sync::Mutex<std::collections::HashMap<String, PendingLogin>>,
}

impl PendingLogins {
    /// Start a login: mint `state`, PKCE and `nonce`, and remember them.
    pub(super) fn start(&self) -> Option<(String, Pkce, String)> {
        let pkce = Pkce::generate();
        let state = uuid::Uuid::new_v4().to_string();
        let nonce = uuid::Uuid::new_v4().to_string();
        let mut m = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        m.retain(|_, v| v.at.elapsed() < PENDING_TTL); // opportunistic GC
                                                       // Refuse rather than evict: dropping someone else's in-flight login to
                                                       // make room would turn a flood into a denial of service against real
                                                       // users, and the caller here has not authenticated yet.
        if m.len() >= MAX_PENDING {
            return None;
        }
        m.insert(
            state.clone(),
            PendingLogin {
                verifier: pkce.verifier.clone(),
                nonce: nonce.clone(),
                at: std::time::Instant::now(),
            },
        );
        Some((state, pkce, nonce))
    }

    /// The verifier for a pending login WITHOUT consuming it, so the code
    /// exchange can run before the state is spent. A transient IdP outage then
    /// leaves the login restartable instead of burning it.
    pub(super) fn peek_verifier(&self, state: &str) -> Option<String> {
        let m = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let p = m.get(state)?;
        (p.at.elapsed() < PENDING_TTL).then(|| p.verifier.clone())
    }

    /// Consume a pending login (single-use). An unknown, expired or replayed
    /// `state` yields `None`, so a callback can be redeemed exactly once.
    pub(super) fn take(&self, state: &str) -> Option<(String, String)> {
        let mut m = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let p = m.remove(state)?;
        (p.at.elapsed() < PENDING_TTL).then_some((p.verifier, p.nonce))
    }
}

/// Build the IdP authorization URL for a started login.
///
/// `redirect_uri` must be the exact string registered at the IdP — a mismatch is
/// rejected there, which is the desired behaviour: it is the IdP's guarantee
/// that a code cannot be delivered to an attacker's endpoint.
pub(super) fn authorization_url(
    d: &Discovery,
    client_id: &str,
    redirect_uri: &str,
    state: &str,
    nonce: &str,
    challenge: &str,
) -> String {
    let q = |v: &str| urlencode(v);
    format!(
        "{}?response_type=code&client_id={}&redirect_uri={}&scope={}&state={}&nonce={}\
&code_challenge={}&code_challenge_method=S256",
        d.authorization_endpoint,
        q(client_id),
        q(redirect_uri),
        q("openid profile email groups"),
        q(state),
        q(nonce),
        q(challenge),
    )
}

/// Percent-encode for a query value. Hand-rolled over the unreserved set from
/// RFC 3986 — anything not explicitly safe is escaped, so a new character can
/// never be let through by omission.
fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

// ------------------------------------------------------- completing a login -

/// Everything the callback needs that is NOT a network call.
///
/// Split out so the whole decision — state redemption, signature, claims,
/// role — is exercised end to end in tests against a locally signed token, with
/// no IdP and no HTTP. The handler around this only fetches bytes.
pub(super) struct CallbackInput<'a> {
    pub state: &'a str,
    /// The `id_token` from the token endpoint's response.
    pub id_token: &'a str,
    pub keys: &'a [Jwk],
    pub policy: &'a garmr_core::oidc::OidcPolicy,
    pub now: i64,
}

/// Why a callback did not become a session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum LoginFailure {
    /// The `state` was never issued here, already used, or expired.
    UnknownState,
    /// The token is not authentic.
    Verify(VerifyError),
    /// The token is authentic but this deployment will not accept it.
    Policy(String),
}

impl std::fmt::Display for LoginFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            // Deliberately vague to the CALLER (the log carries the detail): an
            // unknown state is either a stale tab or an attack, and telling the
            // two apart is the operator's job, not the visitor's.
            LoginFailure::UnknownState => write!(f, "this login request is not recognised"),
            LoginFailure::Verify(e) => write!(f, "{e}"),
            LoginFailure::Policy(e) => write!(f, "{e}"),
        }
    }
}

/// Turn a callback into a validated login, consuming the pending state.
///
/// Order matters and is not incidental:
///
/// 1. **Redeem the state first.** It is single-use, so even a request that fails
///    every later check has spent it — otherwise a caller could probe repeatedly
///    against one outstanding login.
/// 2. **Signature before claims.** Reading claims from an unverified token means
///    making decisions on attacker-supplied data.
/// 3. **Nonce from the pending entry**, never from the request: a nonce the
///    caller supplies is not a commitment to anything.
pub(super) fn complete_login(
    pending: &PendingLogins,
    input: CallbackInput<'_>,
) -> Result<garmr_core::oidc::OidcLogin, LoginFailure> {
    let (_verifier, nonce) = pending
        .take(input.state)
        .ok_or(LoginFailure::UnknownState)?;
    let claims = verify(input.id_token, input.keys).map_err(LoginFailure::Verify)?;
    garmr_core::oidc::validate(&claims, input.policy, Some(&nonce), input.now)
        .map_err(|r| LoginFailure::Policy(r.to_string()))
}

// -------------------------------------------------------------- the client --

/// OIDC configuration. Absent = the feature does not exist in this deployment:
/// no routes, no button, nothing to misconfigure halfway.
#[derive(Debug, Clone)]
pub(super) struct OidcConfig {
    pub issuer: String,
    pub client_id: String,
    pub client_secret: String,
    /// Must byte-match what is registered at the IdP; the IdP's comparison is
    /// what guarantees a code cannot be delivered to an attacker's endpoint.
    pub redirect_uri: String,
    pub policy: garmr_core::oidc::OidcPolicy,
}

impl OidcConfig {
    /// Build from the environment, or `None` when SSO is not configured.
    ///
    /// All four values must be present. A partially configured IdP is refused
    /// rather than half-enabled — a login button that leads to a broken
    /// redirect teaches operators to ignore errors.
    pub(super) fn from_env() -> Option<Self> {
        let get = |k: &str| std::env::var(k).ok().filter(|v| !v.trim().is_empty());
        let (issuer, client_id, client_secret, redirect_uri) = (
            get("GARMR_OIDC_ISSUER")?,
            get("GARMR_OIDC_CLIENT_ID")?,
            get("GARMR_OIDC_CLIENT_SECRET")?,
            get("GARMR_OIDC_REDIRECT_URI")?,
        );
        // group -> role, as `soc-admins=admin,soc-analysts=analyst`. An empty or
        // unparseable map means nobody can log in, which is the safe direction:
        // a typo locks the door rather than opening it wide.
        let mut role_map = std::collections::BTreeMap::new();
        for pair in get("GARMR_OIDC_ROLE_MAP").unwrap_or_default().split(',') {
            if let Some((g, r)) = pair.split_once('=') {
                if let Ok(role) = r.trim().parse::<garmr_core::Role>() {
                    role_map.insert(g.trim().to_string(), role);
                }
            }
        }
        Some(Self {
            policy: garmr_core::oidc::OidcPolicy {
                issuer: issuer.clone(),
                client_id: client_id.clone(),
                role_map,
                groups_claim: get("GARMR_OIDC_GROUPS_CLAIM").unwrap_or_else(|| "groups".into()),
                max_skew_secs: 60,
            },
            issuer,
            client_id,
            client_secret,
            redirect_uri,
        })
    }
}

/// The relying party: config, the pending-login store, and the IdP metadata it
/// caches.
pub(super) struct OidcClient {
    pub cfg: OidcConfig,
    pub pending: PendingLogins,
    /// Discovery + JWKS, fetched once and refreshed on a verification miss.
    cache: std::sync::Mutex<Option<(Discovery, Vec<Jwk>)>>,
}

impl OidcClient {
    pub(super) fn new(cfg: OidcConfig) -> Self {
        Self {
            cfg,
            pending: PendingLogins::default(),
            cache: std::sync::Mutex::new(None),
        }
    }

    /// Fetch a URL through the egress chokepoint.
    ///
    /// `EgressClass::Idp` means an air-gapped deployment refuses this by
    /// policy — correctly, since an air-gapped node has no external IdP and
    /// silently reaching one would break the whole stance.
    async fn get(&self, url: &str) -> Result<Vec<u8>, VerifyError> {
        garmr_core::egress::global()
            .check(garmr_core::EgressClass::Idp, url)
            .map_err(|e| VerifyError::Discovery(format!("egress denied: {e}")))?;
        let res = idp_client()?
            .get(url)
            .send()
            .await
            .map_err(|e| VerifyError::Discovery(format!("fetching {url}: {e}")))?;
        let status = res.status();
        let body = res
            .bytes()
            .await
            .map_err(|e| VerifyError::Discovery(format!("reading {url}: {e}")))?;
        if !status.is_success() {
            return Err(VerifyError::Discovery(format!("{url} returned {status}")));
        }
        Ok(body.to_vec())
    }

    /// Discovery + JWKS, cached. `refresh` forces a re-fetch, which is how a
    /// rotated signing key is picked up: a token whose `kid` is unknown means
    /// the cache is stale, not that the token is bad.
    async fn metadata(&self, refresh: bool) -> Result<(Discovery, Vec<Jwk>), VerifyError> {
        if !refresh {
            if let Some(c) = self.cache.lock().unwrap_or_else(|e| e.into_inner()).clone() {
                return Ok(c);
            }
        }
        let doc = self
            .get(&format!(
                "{}/.well-known/openid-configuration",
                self.cfg.issuer.trim_end_matches('/')
            ))
            .await?;
        let d = parse_discovery(&doc, &self.cfg.issuer)?;
        let keys = parse_jwks(&self.get(&d.jwks_uri).await?)?;
        if keys.is_empty() {
            return Err(VerifyError::Discovery(format!(
                "{} publishes no EC P-256 signing key — garmr verifies ES256 only",
                d.jwks_uri
            )));
        }
        let pair = (d, keys);
        *self.cache.lock().unwrap_or_else(|e| e.into_inner()) = Some(pair.clone());
        Ok(pair)
    }

    /// Exchange an authorization code for an ID token.
    async fn exchange(
        &self,
        d: &Discovery,
        code: &str,
        verifier: &str,
    ) -> Result<String, VerifyError> {
        garmr_core::egress::global()
            .check(garmr_core::EgressClass::Idp, &d.token_endpoint)
            .map_err(|e| VerifyError::Discovery(format!("egress denied: {e}")))?;
        let res = idp_client()?
            .post(&d.token_endpoint)
            // The secret goes in the POST body, never a query string: URLs end
            // up in proxy logs and browser history, bodies do not.
            .form(&[
                ("grant_type", "authorization_code"),
                ("code", code),
                ("redirect_uri", &self.cfg.redirect_uri),
                ("client_id", &self.cfg.client_id),
                ("client_secret", &self.cfg.client_secret),
                ("code_verifier", verifier),
            ])
            .send()
            .await
            .map_err(|e| VerifyError::Discovery(format!("token exchange: {e}")))?;
        let body = res
            .bytes()
            .await
            .map_err(|e| VerifyError::Discovery(format!("token response: {e}")))?;
        parse_token_response(&body)
    }
}

/// The HTTP client for IdP calls.
///
/// Redirects are REFUSED. Every fetch here is egress-checked against a specific
/// destination, and a followed redirect would land somewhere that check never
/// saw — an IdP (or anyone who can answer as one) could point the JWKS fetch at
/// a link-local metadata address and turn a login into an SSRF. Refusing means
/// a relocated endpoint surfaces as an error an operator fixes in config, which
/// is the correct place for it.
fn idp_client() -> Result<reqwest::Client, VerifyError> {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|e| VerifyError::Discovery(format!("building the IdP client: {e}")))
}

// ------------------------------------------------------------- the routes ---

/// GET /auth/oidc/start — begin a login by redirecting to the IdP.
pub(super) async fn start(State(st): State<super::ApiState>) -> axum::response::Response {
    use axum::response::IntoResponse;
    let Some(client) = st.oidc.as_ref() else {
        return (axum::http::StatusCode::NOT_FOUND, "SSO is not configured").into_response();
    };
    let d = match client.metadata(false).await {
        Ok((d, _)) => d,
        Err(e) => {
            // The operator needs the detail; the visitor gets a generic failure,
            // because this text is reachable without authenticating.
            tracing::error!(error = %e, "OIDC: cannot reach the identity provider");
            return (
                axum::http::StatusCode::BAD_GATEWAY,
                "the identity provider is unreachable",
            )
                .into_response();
        }
    };
    let Some((state, pkce, nonce)) = client.pending.start() else {
        tracing::warn!("OIDC: too many outstanding logins — refusing to start another");
        return (
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            "too many logins in progress, try again shortly",
        )
            .into_response();
    };
    let url = authorization_url(
        &d,
        &client.cfg.client_id,
        &client.cfg.redirect_uri,
        &state,
        &nonce,
        &pkce.challenge,
    );
    axum::response::Redirect::to(&url).into_response()
}

/// GET /auth/oidc/callback?code=&state= — finish the login.
pub(super) async fn callback(
    State(st): State<super::ApiState>,
    axum::extract::Query(q): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    let Some(client) = st.oidc.as_ref() else {
        return (axum::http::StatusCode::NOT_FOUND, "SSO is not configured").into_response();
    };
    // The IdP reports user-facing failures (a denied consent, an expired
    // request) here rather than by not calling back at all.
    if let Some(err) = q.get("error") {
        tracing::warn!(error = %err, "OIDC: the identity provider refused the authorization");
        return (
            axum::http::StatusCode::UNAUTHORIZED,
            "login was not completed",
        )
            .into_response();
    }
    let (Some(code), Some(state)) = (q.get("code"), q.get("state")) else {
        return (axum::http::StatusCode::BAD_REQUEST, "missing code or state").into_response();
    };

    // Peek at the pending entry WITHOUT consuming it: the code exchange is a
    // network round-trip, and spending the state before knowing whether the IdP
    // even answers would make a transient outage look like an attack and force
    // the user to restart. complete_login consumes it immediately after.
    let Some(verifier) = client.pending.peek_verifier(state) else {
        tracing::warn!("OIDC: callback with an unrecognised state");
        return (
            axum::http::StatusCode::UNAUTHORIZED,
            LoginFailure::UnknownState.to_string(),
        )
            .into_response();
    };

    let (d, mut keys) = match client.metadata(false).await {
        Ok(m) => m,
        Err(e) => {
            tracing::error!(error = %e, "OIDC: identity provider metadata unavailable");
            return (
                axum::http::StatusCode::BAD_GATEWAY,
                "the identity provider is unreachable",
            )
                .into_response();
        }
    };
    let id_token = match client.exchange(&d, code, &verifier).await {
        Ok(t) => t,
        Err(e) => {
            tracing::error!(error = %e, "OIDC: token exchange failed");
            return (
                axum::http::StatusCode::UNAUTHORIZED,
                "login was not completed",
            )
                .into_response();
        }
    };

    // An unknown kid means our cached JWKS predates a key rotation, not that the
    // token is forged — refresh once and retry before refusing a real login.
    if let Ok(claims_kid) = kid_of(&id_token) {
        if !keys.iter().any(|k| k.kid == claims_kid) {
            if let Ok((_, fresh)) = client.metadata(true).await {
                keys = fresh;
            }
        }
    }

    let now = chrono::Utc::now().timestamp();
    let login = match complete_login(
        &client.pending,
        CallbackInput {
            state,
            id_token: &id_token,
            keys: &keys,
            policy: &client.cfg.policy,
            now,
        },
    ) {
        Ok(l) => l,
        Err(e) => {
            tracing::warn!(error = %e, "OIDC: login refused");
            crate::audit::record_best_effort(
                garmr_audit::AuditRecord::new(garmr_audit::action::AUTH_LOGIN_FAILED, "session")
                    .actor(garmr_audit::ActorType::Human, "unknown", None)
                    .auth_method("oidc")
                    .outcome(garmr_audit::Outcome::Failure)
                    .reason(e.to_string()),
            );
            return (axum::http::StatusCode::UNAUTHORIZED, e.to_string()).into_response();
        }
    };

    let Some(w) = st.webauthn.as_ref() else {
        // The session layer lives in the passkey module; without it there is
        // nothing to mint. Refuse rather than invent a second session format.
        tracing::error!("OIDC: no session layer configured (GARMR_WEBAUTHN_RP_ID unset)");
        return (
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            "sessions are not configured on this deployment",
        )
            .into_response();
    };
    let cookie = w.mint_federated_session(&login.display, login.role);
    crate::audit::record_best_effort(
        garmr_audit::AuditRecord::new(garmr_audit::action::AUTH_LOGIN, "session")
            .actor(
                garmr_audit::ActorType::Human,
                login.display.clone(),
                Some(&format!("{:?}", login.role)),
            )
            .auth_method("oidc")
            .outcome(garmr_audit::Outcome::Success),
    );
    (
        [(
            axum::http::header::SET_COOKIE,
            super::passkey::session_cookie_str(&cookie, super::passkey::SESSION_TTL_SECS),
        )],
        axum::response::Redirect::to("/"),
    )
        .into_response()
}

/// The `kid` from a token header, without verifying anything — used only to
/// decide whether a cache refresh might help.
fn kid_of(token: &str) -> Result<String, VerifyError> {
    let h = token
        .split('.')
        .next()
        .ok_or(VerifyError::Malformed("no header"))?;
    let v: serde_json::Value =
        serde_json::from_slice(&b64(h)?).map_err(|_| VerifyError::Malformed("bad header JSON"))?;
    Ok(v.get("kid")
        .and_then(|x| x.as_str())
        .unwrap_or_default()
        .to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use p256::ecdsa::{signature::Signer, Signature, SigningKey};

    fn b64e(b: &[u8]) -> String {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
    }

    /// Mint a real ES256 token, the way the IdP would.
    fn issue(kid: &str, payload: &serde_json::Value, sk: &SigningKey) -> String {
        let header = serde_json::json!({"alg": "ES256", "typ": "JWT", "kid": kid});
        let h = b64e(header.to_string().as_bytes());
        let p = b64e(payload.to_string().as_bytes());
        let sig: Signature = sk.sign(format!("{h}.{p}").as_bytes());
        format!("{h}.{p}.{}", b64e(&sig.to_bytes()))
    }

    fn keypair(kid: &str) -> (SigningKey, Jwk) {
        // Deterministic key: a fixed scalar keeps the test reproducible.
        let sk = SigningKey::from_slice(&[7u8; 32]).unwrap();
        let point = sk.verifying_key().to_sec1_point(false);
        let bytes = point.as_bytes();
        (
            sk,
            Jwk {
                kid: kid.to_string(),
                x: bytes[1..33].to_vec(),
                y: bytes[33..65].to_vec(),
            },
        )
    }

    fn payload() -> serde_json::Value {
        serde_json::json!({
            "iss": "https://idp.example.com",
            "sub": "u-123",
            "aud": "garmr",
            "exp": 2_000_000_000i64,
            "groups": ["soc-admins"],
            "preferred_username": "henrik"
        })
    }

    #[test]
    fn a_genuine_token_verifies_and_yields_its_claims() {
        let (sk, jwk) = keypair("k1");
        let claims = verify(&issue("k1", &payload(), &sk), &[jwk]).unwrap();
        assert_eq!(claims.sub, "u-123");
        assert_eq!(claims.aud, vec!["garmr".to_string()]);
        assert_eq!(claims.groups, vec!["soc-admins".to_string()]);
    }

    #[test]
    fn a_tampered_payload_is_refused() {
        // The attack that matters: keep the signature, swap the claims. Here the
        // caller promotes themselves to a group the IdP never asserted.
        let (sk, jwk) = keypair("k1");
        let token = issue("k1", &payload(), &sk);
        let mut parts: Vec<&str> = token.split('.').collect();
        let forged = serde_json::json!({
            "iss": "https://idp.example.com", "sub": "u-123", "aud": "garmr",
            "exp": 2_000_000_000i64, "groups": ["soc-admins", "root"]
        });
        let p = b64e(forged.to_string().as_bytes());
        parts[1] = &p;
        assert_eq!(
            verify(&parts.join("."), &[jwk]).unwrap_err(),
            VerifyError::BadSignature
        );
    }

    #[test]
    fn alg_none_is_refused() {
        // The classic JWT vulnerability: a token asserting it needs no
        // signature. It must die on the algorithm check, before any key lookup.
        let header = b64e(br#"{"alg":"none","typ":"JWT"}"#);
        let p = b64e(payload().to_string().as_bytes());
        let (_, jwk) = keypair("k1");
        assert_eq!(
            verify(&format!("{header}.{p}."), &[jwk]).unwrap_err(),
            VerifyError::UnsupportedAlg("none".into())
        );
    }

    #[test]
    fn an_unimplemented_algorithm_is_refused_not_skipped() {
        // RS256 is what most IdPs default to. garmr has no RSA implementation,
        // and the dangerous outcome would be accepting the token unverified —
        // so it is refused with a message naming the fix.
        let header = b64e(br#"{"alg":"RS256","typ":"JWT","kid":"k1"}"#);
        let p = b64e(payload().to_string().as_bytes());
        let (_, jwk) = keypair("k1");
        let err = verify(&format!("{header}.{p}.sig"), &[jwk]).unwrap_err();
        assert!(err.to_string().contains("ES256"), "{err}");
    }

    #[test]
    fn a_signature_from_the_wrong_key_is_refused() {
        // A token genuinely signed — by someone else's key. Publishing a JWK is
        // not a claim about who may sign for this issuer.
        let (sk, jwk) = keypair("k1");
        let other = SigningKey::from_slice(&[9u8; 32]).unwrap();
        let token = issue("k1", &payload(), &other);
        assert_eq!(
            verify(&token, &[jwk]).unwrap_err(),
            VerifyError::BadSignature
        );
        // And a kid nobody published is an explicit refusal, not a fallback to
        // trying every key.
        let (sk2, jwk2) = keypair("k2");
        let _ = sk2;
        assert!(matches!(
            verify(&issue("k-unknown", &payload(), &sk), &[jwk2]),
            Err(VerifyError::UnknownKey(_))
        ));
    }

    #[test]
    fn a_kidless_token_is_ambiguous_when_several_keys_are_published() {
        // Trying every key would mean a key retired years ago still validates
        // tokens, so ambiguity is refused rather than resolved by guessing.
        let (sk, jwk1) = keypair("k1");
        let (_, jwk2) = keypair("k2");
        let header = b64e(br#"{"alg":"ES256","typ":"JWT"}"#);
        let p = b64e(payload().to_string().as_bytes());
        let sig: Signature = sk.sign(format!("{header}.{p}").as_bytes());
        let token = format!("{header}.{p}.{}", b64e(&sig.to_bytes()));
        assert!(matches!(
            verify(&token, &[jwk1.clone(), jwk2]),
            Err(VerifyError::Malformed(_))
        ));
        // With exactly one published key it is unambiguous, so it verifies.
        assert!(verify(&token, &[jwk1]).is_ok());
    }

    #[test]
    fn malformed_shapes_are_refused_before_any_crypto() {
        let (_, jwk) = keypair("k1");
        for bad in ["", "onlyonepart", "two.parts", "a.b.c.d"] {
            assert!(
                matches!(
                    verify(bad, std::slice::from_ref(&jwk)),
                    Err(VerifyError::Malformed(_))
                ),
                "{bad:?} should be malformed"
            );
        }
    }

    #[test]
    fn an_aud_array_is_normalised_like_a_single_string() {
        // Both shapes appear in the wild; the core's audience check sees a list
        // either way, so a multi-audience token is not silently rejected.
        let (sk, jwk) = keypair("k1");
        let mut pl = payload();
        pl["aud"] = serde_json::json!(["other-app", "garmr"]);
        let claims = verify(&issue("k1", &pl, &sk), &[jwk]).unwrap();
        assert_eq!(
            claims.aud,
            vec!["other-app".to_string(), "garmr".to_string()]
        );
    }

    // ------------------------------------------------------------ PKCE ------

    #[test]
    fn the_s256_challenge_matches_the_rfc_7636_test_vector() {
        // RFC 7636 Appendix B. Matching the published vector is the only way to
        // know the encoding is right: a subtly wrong one still produces a
        // plausible string and fails only against a real IdP, at which point the
        // symptom is "login is broken" with no clue where.
        assert_eq!(
            s256_challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }

    #[test]
    fn generated_verifiers_are_unique_and_not_their_own_challenge() {
        let a = Pkce::generate();
        let b = Pkce::generate();
        assert_ne!(a.verifier, b.verifier, "verifiers must not repeat");
        assert!(
            a.verifier.len() >= 43,
            "RFC 7636 floor: {}",
            a.verifier.len()
        );
        assert_eq!(a.challenge, s256_challenge(&a.verifier));
        // Equal would be `plain` mode: anyone observing the authorization
        // request could redeem the code, which is the whole thing PKCE prevents.
        assert_ne!(a.challenge, a.verifier);
    }

    // ------------------------------------------------------------ JWKS ------

    #[test]
    fn jwks_parsing_keeps_p256_signing_keys_and_skips_the_rest() {
        let (_, jwk) = keypair("k1");
        let doc = serde_json::json!({"keys": [
            // RSA, common alongside EC — skipped, not fatal.
            {"kty": "RSA", "kid": "rsa1", "n": "abc", "e": "AQAB"},
            // Right family, wrong curve.
            {"kty": "EC", "crv": "P-384", "kid": "p384", "x": "AA", "y": "AA"},
            // An ENCRYPTION key on the right curve: must never verify a
            // signature, however well the curve matches.
            {"kty": "EC", "crv": "P-256", "use": "enc", "kid": "enc1",
             "x": b64e(&jwk.x), "y": b64e(&jwk.y)},
            {"kty": "EC", "crv": "P-256", "use": "sig", "kid": "k1",
             "x": b64e(&jwk.x), "y": b64e(&jwk.y)},
        ]});
        let keys = parse_jwks(doc.to_string().as_bytes()).unwrap();
        assert_eq!(keys.len(), 1, "only the P-256 signing key is usable");
        assert_eq!(keys[0].kid, "k1");
        assert_eq!(keys[0].x, jwk.x);
    }

    #[test]
    fn a_parsed_jwks_key_actually_verifies_a_real_token() {
        // The parse and the verifier must agree on coordinate encoding. Testing
        // them separately would let a byte-order or padding mistake pass both.
        let (sk, jwk) = keypair("k1");
        let doc = serde_json::json!({"keys": [
            {"kty": "EC", "crv": "P-256", "use": "sig", "kid": "k1",
             "x": b64e(&jwk.x), "y": b64e(&jwk.y)}
        ]});
        let keys = parse_jwks(doc.to_string().as_bytes()).unwrap();
        let claims = verify(&issue("k1", &payload(), &sk), &keys).unwrap();
        assert_eq!(claims.sub, "u-123");
    }

    #[test]
    fn a_short_coordinate_is_rejected_rather_than_padded() {
        // A truncated coordinate padded to 32 bytes is a DIFFERENT point, so
        // repairing it would verify signatures against a key nobody published.
        let doc = serde_json::json!({"keys": [
            {"kty": "EC", "crv": "P-256", "kid": "short",
             "x": b64e(&[1u8; 31]), "y": b64e(&[2u8; 32])}
        ]});
        assert!(parse_jwks(doc.to_string().as_bytes()).unwrap().is_empty());
    }

    #[test]
    fn no_usable_key_is_empty_but_a_missing_keys_array_is_malformed() {
        let doc = serde_json::json!({"keys": [{"kty": "RSA", "kid": "r1"}]});
        assert!(parse_jwks(doc.to_string().as_bytes()).unwrap().is_empty());
        assert!(matches!(parse_jwks(b"{}"), Err(VerifyError::Malformed(_))));
    }

    // ------------------------------------------------------- discovery ------

    fn disc(issuer: &str, token_ep: &str) -> Vec<u8> {
        serde_json::json!({
            "issuer": issuer,
            "authorization_endpoint": format!("{issuer}/authorize"),
            "token_endpoint": token_ep,
            "jwks_uri": format!("{issuer}/jwks"),
        })
        .to_string()
        .into_bytes()
    }

    #[test]
    fn a_well_formed_discovery_document_parses() {
        let d = parse_discovery(
            &disc("https://idp.example.com", "https://idp.example.com/token"),
            "https://idp.example.com",
        )
        .unwrap();
        assert_eq!(d.token_endpoint, "https://idp.example.com/token");
        assert_eq!(d.jwks_uri, "https://idp.example.com/jwks");
    }

    #[test]
    fn a_document_declaring_another_issuer_is_refused() {
        // Required by OIDC Discovery precisely because a mismatch means the
        // response came from somewhere else — after which every downstream
        // `iss` check compares against an attacker's value.
        let err = parse_discovery(
            &disc("https://evil.example.net", "https://evil.example.net/token"),
            "https://idp.example.com",
        )
        .unwrap_err();
        assert!(err.to_string().contains("declares issuer"), "{err}");
    }

    #[test]
    fn an_endpoint_on_a_foreign_host_is_refused() {
        // THE attack this guards: the discovery document is fetched before
        // anything is verified, and the token exchange sends the client secret
        // and the authorization code to token_endpoint. Pointing it elsewhere is
        // credential theft with no signature involved.
        let err = parse_discovery(
            &disc(
                "https://idp.example.com",
                "https://attacker.example.net/token",
            ),
            "https://idp.example.com",
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("does not match the issuer"),
            "{err}"
        );
    }

    #[test]
    fn a_downgraded_endpoint_is_refused() {
        // http would carry the code and secret in clear, making every check
        // above irrelevant.
        let err = parse_discovery(
            &disc("https://idp.example.com", "http://idp.example.com/token"),
            "https://idp.example.com",
        )
        .unwrap_err();
        assert!(err.to_string().contains("not https"), "{err}");
    }

    #[test]
    fn a_missing_field_is_malformed_rather_than_defaulted() {
        // Defaulting an absent token_endpoint to something plausible is how a
        // login silently talks to the wrong place.
        let body = serde_json::json!({
            "issuer": "https://idp.example.com",
            "authorization_endpoint": "https://idp.example.com/authorize"
        })
        .to_string();
        assert!(matches!(
            parse_discovery(body.as_bytes(), "https://idp.example.com"),
            Err(VerifyError::Malformed(_))
        ));
    }

    #[test]
    fn the_token_response_surfaces_the_idps_own_error() {
        // A misconfigured client id must say so, instead of reporting the
        // useless "no id_token" and sending an operator hunting a protocol bug.
        let body = serde_json::json!({
            "error": "invalid_client",
            "error_description": "client authentication failed"
        })
        .to_string();
        let err = parse_token_response(body.as_bytes()).unwrap_err();
        assert!(err.to_string().contains("invalid_client"), "{err}");
        assert!(
            err.to_string().contains("client authentication failed"),
            "{err}"
        );
    }

    #[test]
    fn only_the_id_token_is_taken_from_the_response() {
        // The access token is for the IdP's own APIs, which garmr does not call.
        // Holding a credential with no use for it is gratuitous exposure.
        let body = serde_json::json!({
            "id_token": "a.b.c",
            "access_token": "secret-access-token",
            "token_type": "Bearer"
        })
        .to_string();
        assert_eq!(parse_token_response(body.as_bytes()).unwrap(), "a.b.c");
    }

    // -------------------------------------------------- pending logins ------

    #[test]
    fn a_callback_state_is_single_use() {
        // Replay defence: the same state must not redeem twice, or an
        // intercepted callback URL could be replayed to mint a second session.
        let p = PendingLogins::default();
        let (state, pkce, nonce) = p.start().unwrap();
        let (v, n) = p.take(&state).unwrap();
        assert_eq!(v, pkce.verifier);
        assert_eq!(n, nonce);
        assert!(p.take(&state).is_none(), "state must not redeem twice");
    }

    #[test]
    fn an_unknown_state_is_refused() {
        // THE login-CSRF defence: a callback carrying a state this server never
        // issued was not started here. Without it an attacker can feed a victim
        // a callback URL containing the ATTACKER's code, silently attaching the
        // victim's browser to the attacker's identity.
        let p = PendingLogins::default();
        assert!(p.take("state-we-never-issued").is_none());
    }

    #[test]
    fn outstanding_logins_are_bounded_and_refuse_rather_than_evict() {
        // An unauthenticated caller can hit the start endpoint in a loop. The
        // cap must not be enforced by dropping someone else's in-flight login —
        // that would turn a flood into a denial of service against real users.
        let p = PendingLogins::default();
        let mut first = None;
        for i in 0..MAX_PENDING {
            let (s, ..) = p.start().expect("under the cap");
            if i == 0 {
                first = Some(s);
            }
        }
        assert!(p.start().is_none(), "at the cap, a new login is refused");
        // The earliest login is still redeemable — it was not sacrificed.
        assert!(p.take(&first.unwrap()).is_some());
    }

    #[test]
    fn every_started_login_gets_distinct_state_nonce_and_verifier() {
        // Reuse across logins would break both the CSRF binding and the replay
        // defence at once.
        let p = PendingLogins::default();
        let (s1, k1, n1) = p.start().unwrap();
        let (s2, k2, n2) = p.start().unwrap();
        assert_ne!(s1, s2);
        assert_ne!(n1, n2);
        assert_ne!(k1.verifier, k2.verifier);
    }

    // -------------------------------------------- authorization request -----

    #[test]
    fn the_authorization_url_carries_pkce_and_escapes_its_parameters() {
        let d = parse_discovery(
            &disc("https://idp.example.com", "https://idp.example.com/token"),
            "https://idp.example.com",
        )
        .unwrap();
        let url = authorization_url(
            &d,
            "garmr client",
            "https://soc.example.com/auth/oidc/callback",
            "st/ate",
            "no nce",
            "chal+lenge",
        );
        assert!(url.starts_with("https://idp.example.com/authorize?"));
        assert!(url.contains("code_challenge_method=S256"), "{url}");
        assert!(url.contains("response_type=code"), "{url}");
        // Every value is percent-encoded: an unescaped `&` or `/` in state would
        // let a caller inject additional authorization parameters.
        assert!(url.contains("state=st%2Fate"), "{url}");
        assert!(url.contains("nonce=no%20nce"), "{url}");
        assert!(url.contains("code_challenge=chal%2Blenge"), "{url}");
        assert!(
            url.contains("redirect_uri=https%3A%2F%2Fsoc.example.com%2Fauth%2Foidc%2Fcallback"),
            "{url}"
        );
    }

    // ------------------------------------------------- the whole flow -------

    /// A stub IdP: the same key that signs tokens is the one published in the
    /// JWKS, which is the only relationship that matters for these tests.
    fn stub_idp() -> (
        p256::ecdsa::SigningKey,
        Vec<Jwk>,
        garmr_core::oidc::OidcPolicy,
    ) {
        let (sk, jwk) = keypair("k1");
        let policy = garmr_core::oidc::OidcPolicy {
            issuer: "https://idp.example.com".into(),
            client_id: "garmr".into(),
            role_map: [("soc-analysts".to_string(), garmr_core::Role::Analyst)]
                .into_iter()
                .collect(),
            groups_claim: "groups".into(),
            max_skew_secs: 60,
        };
        (sk, vec![jwk], policy)
    }

    fn id_token(sk: &p256::ecdsa::SigningKey, nonce: &str, groups: serde_json::Value) -> String {
        issue(
            "k1",
            &serde_json::json!({
                "iss": "https://idp.example.com",
                "sub": "u-1",
                "aud": "garmr",
                "exp": 4_000_000_000i64,
                "nonce": nonce,
                "preferred_username": "henrik",
                "groups": groups
            }),
            sk,
        )
    }

    #[test]
    fn a_full_login_round_trip_yields_the_mapped_role() {
        // Start → IdP signs a token bound to OUR nonce → callback → session.
        let (sk, keys, policy) = stub_idp();
        let pending = PendingLogins::default();
        let (state, _pkce, nonce) = pending.start().unwrap();
        let login = complete_login(
            &pending,
            CallbackInput {
                state: &state,
                id_token: &id_token(&sk, &nonce, serde_json::json!(["soc-analysts"])),
                keys: &keys,
                policy: &policy,
                now: 1_760_000_000,
            },
        )
        .unwrap();
        assert_eq!(login.role, garmr_core::Role::Analyst);
        assert_eq!(login.subject, "u-1");
        assert_eq!(login.display, "henrik");
    }

    #[test]
    fn a_token_bound_to_another_logins_nonce_is_refused() {
        // The replay this whole dance exists to stop: a genuine, correctly
        // signed token from a DIFFERENT login attempt must not complete this one.
        let (sk, keys, policy) = stub_idp();
        let pending = PendingLogins::default();
        let (state_a, _, _nonce_a) = pending.start().unwrap();
        let (_state_b, _, nonce_b) = pending.start().unwrap();
        let err = complete_login(
            &pending,
            CallbackInput {
                state: &state_a,
                id_token: &id_token(&sk, &nonce_b, serde_json::json!(["soc-analysts"])),
                keys: &keys,
                policy: &policy,
                now: 1_760_000_000,
            },
        )
        .unwrap_err();
        assert!(matches!(err, LoginFailure::Policy(_)), "{err}");
    }

    #[test]
    fn the_state_is_spent_even_when_the_token_is_rejected() {
        // Otherwise one outstanding login could be probed repeatedly — with a
        // forged token, a wrong key, anything — until something got through.
        let (sk, keys, policy) = stub_idp();
        let pending = PendingLogins::default();
        let (state, _, nonce) = pending.start().unwrap();
        // Unmapped group: authentic token, refused by policy.
        let bad = id_token(&sk, &nonce, serde_json::json!(["all-employees"]));
        assert!(complete_login(
            &pending,
            CallbackInput {
                state: &state,
                id_token: &bad,
                keys: &keys,
                policy: &policy,
                now: 1_760_000_000
            }
        )
        .is_err());
        // The same state must now be gone, even with a perfect token.
        let good = id_token(&sk, &nonce, serde_json::json!(["soc-analysts"]));
        assert_eq!(
            complete_login(
                &pending,
                CallbackInput {
                    state: &state,
                    id_token: &good,
                    keys: &keys,
                    policy: &policy,
                    now: 1_760_000_000
                }
            )
            .unwrap_err(),
            LoginFailure::UnknownState
        );
    }

    #[test]
    fn a_forged_token_never_reaches_the_claim_stage() {
        // Signature before claims: reading claims from an unverified token is
        // deciding on attacker-supplied data.
        let (_sk, keys, policy) = stub_idp();
        let attacker = p256::ecdsa::SigningKey::from_slice(&[3u8; 32]).unwrap();
        let pending = PendingLogins::default();
        let (state, _, nonce) = pending.start().unwrap();
        let forged = id_token(&attacker, &nonce, serde_json::json!(["soc-analysts"]));
        assert_eq!(
            complete_login(
                &pending,
                CallbackInput {
                    state: &state,
                    id_token: &forged,
                    keys: &keys,
                    policy: &policy,
                    now: 1_760_000_000
                }
            )
            .unwrap_err(),
            LoginFailure::Verify(VerifyError::BadSignature)
        );
    }

    #[test]
    fn the_failure_shown_to_a_visitor_does_not_say_which_check_failed() {
        // An unknown state is either a stale browser tab or an attack in
        // progress; distinguishing them is the operator's job from the log, not
        // something to hand the caller.
        let msg = LoginFailure::UnknownState.to_string();
        assert!(!msg.contains("state"), "{msg}");
        assert!(!msg.contains("expired"), "{msg}");
    }

    // ------------------------------------------------------ config gate -----

    #[test]
    fn peeking_does_not_spend_the_state_but_taking_does() {
        // The callback peeks before the network round-trip so a transient IdP
        // outage leaves the login restartable instead of burning it.
        let p = PendingLogins::default();
        let (state, pkce, _) = p.start().unwrap();
        assert_eq!(p.peek_verifier(&state).unwrap(), pkce.verifier);
        assert_eq!(
            p.peek_verifier(&state).unwrap(),
            pkce.verifier,
            "peek is idempotent"
        );
        assert!(p.take(&state).is_some());
        assert!(p.peek_verifier(&state).is_none(), "take consumed it");
    }

    #[test]
    fn a_partially_configured_idp_yields_no_client_at_all() {
        // A login button leading to a broken redirect teaches operators to
        // ignore errors, so half-configuration is refused outright.
        // (Serialised via a mutex: these mutate process-wide env.)
        static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let keys = [
            "GARMR_OIDC_ISSUER",
            "GARMR_OIDC_CLIENT_ID",
            "GARMR_OIDC_CLIENT_SECRET",
            "GARMR_OIDC_REDIRECT_URI",
            "GARMR_OIDC_ROLE_MAP",
        ];
        for k in keys {
            std::env::remove_var(k);
        }
        assert!(OidcConfig::from_env().is_none(), "unconfigured = absent");

        // Three of four set: still absent.
        std::env::set_var("GARMR_OIDC_ISSUER", "https://idp.example.com");
        std::env::set_var("GARMR_OIDC_CLIENT_ID", "garmr");
        std::env::set_var("GARMR_OIDC_CLIENT_SECRET", "s3cret");
        assert!(OidcConfig::from_env().is_none(), "partial = absent");

        std::env::set_var("GARMR_OIDC_REDIRECT_URI", "https://soc.example.com/cb");
        std::env::set_var(
            "GARMR_OIDC_ROLE_MAP",
            "soc-admins=admin, soc-analysts=analyst",
        );
        let cfg = OidcConfig::from_env().expect("fully configured");
        assert_eq!(
            cfg.policy.role_map.get("soc-admins"),
            Some(&garmr_core::Role::Admin)
        );
        assert_eq!(
            cfg.policy.role_map.get("soc-analysts"),
            Some(&garmr_core::Role::Analyst)
        );
        // An unparseable entry is DROPPED, not defaulted to some role: a typo
        // must lock the door, never open it wider than intended.
        std::env::set_var("GARMR_OIDC_ROLE_MAP", "soc-admins=wizard");
        let cfg = OidcConfig::from_env().unwrap();
        assert!(
            cfg.policy.role_map.is_empty(),
            "an unknown role grants nothing"
        );

        for k in keys {
            std::env::remove_var(k);
        }
    }
}
