// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! The authorization-decision core for the API client.
//!
//! Everything here is a pure function of explicit inputs — no `web_sys`, no
//! `gloo`, no globals. That is deliberate: the console's authorization rules are
//! the part most likely to break silently (a missing header makes a read view
//! look "empty", a stray redirect makes it loop), and pure functions can be
//! unit-tested on the host target with plain `cargo test`, without a wasm test
//! runner. [`crate::api`] is the thin browser shell that feeds these functions
//! the real location/token state and acts on the answer.
//!
//! Two decisions live here:
//!
//! 1. **Whether to attach the operator bearer token** — never to a foreign
//!    origin, so a crafted `?api=//evil.tld` cannot exfiltrate the admin token.
//! 2. **What to do about a 401/403** — bounce to the passkey login page only
//!    when passkey auth is actually available, never when we are already on
//!    `/login` (that is the console↔login loop), and never for a 403, which
//!    means "authenticated but not permitted" and would loop forever.

/// How the deployment authenticates browser callers, derived from the public
/// capability manifest (`GET /api/capabilities`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum AuthMode {
    /// The manifest has not loaded yet. We must not guess "passkey" here: a
    /// wrong guess redirects, and if passkey is in fact disabled the login page
    /// bounces straight back. Treated as token-only (actionable, never looping).
    #[default]
    Unknown,
    /// No auth configured at all (loopback dev): a 401 is a server bug, not a
    /// missing credential.
    Open,
    /// Passkey sessions are enabled — a 401 genuinely means "log in".
    Passkey,
    /// Auth is on but passkey is not enabled, so bearer tokens are the only way
    /// in. A 401 must NOT redirect: there is nothing to log in with.
    TokenOnly,
}

impl AuthMode {
    /// Derive the mode from the capability manifest's `auth` block.
    pub fn from_caps(auth_enabled: bool, passkey_enabled: bool) -> Self {
        match (auth_enabled, passkey_enabled) {
            (_, true) => AuthMode::Passkey,
            (true, false) => AuthMode::TokenOnly,
            (false, false) => AuthMode::Open,
        }
    }
    /// True when a passkey login page can actually resolve a 401.
    pub fn passkey_available(self) -> bool {
        matches!(self, AuthMode::Passkey)
    }
}

/// What the caller should do about a non-2xx authorization response.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UnauthorizedAction {
    /// Send the browser to the passkey login page, remembering where to return.
    RedirectToLogin { next: String },
    /// Token-only (or not-yet-known) deployment: render an actionable
    /// authorization state that routes to System › Access, rather than a dead
    /// redirect. The view offers Retry once a token has been set.
    PromptForOperatorToken,
    /// Authenticated, but this principal may not do that. More privilege is
    /// required; redirecting would loop.
    Forbidden,
    /// Not an authorization failure — the caller handles it as a normal error.
    None,
}

/// Query parameters that must never be copied into a `next=` destination, so a
/// credential can never reach a URL, the history stack, or a server log.
const SENSITIVE_PARAMS: &[&str] = &[
    "token",
    "access_token",
    "bearer",
    "api_key",
    "apikey",
    "key",
    "secret",
    "password",
    "code",
];

/// Decide what a 401/403 means for this deployment.
///
/// `current_path` is the in-app path+query the user was on (e.g. `/system?tab=access`).
/// `mode` comes from the capability manifest.
pub fn unauthorized_action(
    status: u16,
    mode: AuthMode,
    current_path: &str,
    has_token: bool,
) -> UnauthorizedAction {
    match status {
        // 403 = authenticated but not permitted. A login round-trip cannot fix
        // it, and redirecting would bounce the operator forever.
        403 => UnauthorizedAction::Forbidden,
        401 => {
            // Never redirect away from the login page itself: that is the loop.
            if is_login_path(current_path) {
                return UnauthorizedAction::None;
            }
            if mode.passkey_available() {
                UnauthorizedAction::RedirectToLogin {
                    next: safe_next(current_path),
                }
            } else {
                // Token-only / open / unknown: an actionable panel beats a
                // redirect to a page that cannot help. If a token was already
                // held it is wrong or expired — same actionable state, and the
                // view says so.
                let _ = has_token;
                UnauthorizedAction::PromptForOperatorToken
            }
        }
        _ => UnauthorizedAction::None,
    }
}

/// Is this path the login page (in any of its spellings)?
pub fn is_login_path(path: &str) -> bool {
    let p = path.split('?').next().unwrap_or(path).trim_end_matches('/');
    p == "/login" || p.is_empty() && path.starts_with("/login")
}

/// Sanitize a destination before it is put in a `next=` parameter: keep the path
/// and non-sensitive query, drop anything credential-shaped, and refuse anything
/// that is not a same-site absolute path (so `next=//evil.tld` cannot become an
/// open redirect).
pub fn safe_next(path_and_query: &str) -> String {
    // Reject protocol-relative and absolute URLs outright — only in-app paths.
    if !path_and_query.starts_with('/') || path_and_query.starts_with("//") {
        return "/".to_string();
    }
    let (path, query) = match path_and_query.split_once('?') {
        Some((p, q)) => (p, Some(q)),
        None => (path_and_query, None),
    };
    let Some(q) = query else {
        return path.to_string();
    };
    let kept: Vec<&str> = q
        .split('&')
        .filter(|kv| !kv.is_empty())
        .filter(|kv| {
            let k = kv.split('=').next().unwrap_or("").to_ascii_lowercase();
            !SENSITIVE_PARAMS.contains(&k.as_str())
        })
        .collect();
    if kept.is_empty() {
        path.to_string()
    } else {
        format!("{path}?{}", kept.join("&"))
    }
}

/// Should the operator bearer token be attached to a request to `api_base`?
///
/// `api_base` is [`crate::api::base`] — empty for the normal same-origin case,
/// or an absolute/protocol-relative URL in a debug build driven by `?api=`.
/// `page_origin` is the console's own origin (`https://host:port`).
///
/// The token goes out only when the request provably stays on the console's own
/// origin. Anything else — a different host, a different scheme, an unparseable
/// base — is treated as foreign and gets no credential.
pub fn should_attach_token(api_base: &str, page_origin: &str, has_token: bool) -> bool {
    if !has_token {
        return false;
    }
    let base = api_base.trim();
    // Same-origin: the normal production path (relative URLs).
    if base.is_empty() || base.starts_with('/') && !base.starts_with("//") {
        return true;
    }
    match origin_of(base, page_origin) {
        Some(o) => origins_match(&o, page_origin),
        None => false,
    }
}

/// Extract the origin (`scheme://host[:port]`) from an absolute or
/// protocol-relative URL. Protocol-relative (`//host/x`) inherits the page's
/// scheme, which is why `page_origin` is needed.
fn origin_of(url: &str, page_origin: &str) -> Option<String> {
    let (scheme, rest) = if let Some(r) = url.strip_prefix("//") {
        // Inherit the page scheme.
        let s = page_origin.split("://").next().unwrap_or("https");
        (s.to_string(), r)
    } else {
        let (s, r) = url.split_once("://")?;
        if s.is_empty()
            || !s
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '-')
        {
            return None;
        }
        (s.to_ascii_lowercase(), r)
    };
    // Authority ends at the first '/', '?' or '#'.
    let authority = rest
        .split(['/', '?', '#'])
        .next()
        .filter(|a| !a.is_empty())?;
    // Credentials in the authority (`user:pass@host`) are never acceptable here.
    if authority.contains('@') {
        return None;
    }
    Some(format!("{scheme}://{}", authority.to_ascii_lowercase()))
}

/// Compare two origins, treating the default port as equivalent to an explicit one.
fn origins_match(a: &str, b: &str) -> bool {
    normalize_origin(a) == normalize_origin(b)
}

fn normalize_origin(o: &str) -> String {
    let o = o.trim_end_matches('/').to_ascii_lowercase();
    let Some((scheme, host)) = o.split_once("://") else {
        return o;
    };
    let default_port = match scheme {
        "https" => ":443",
        "http" => ":80",
        _ => "",
    };
    let host = if !default_port.is_empty() {
        host.strip_suffix(default_port).unwrap_or(host)
    } else {
        host
    };
    format!("{scheme}://{host}")
}

#[cfg(test)]
mod tests {
    use super::*;

    const ORIGIN: &str = "https://pve.example.ts.net";

    // ---- AuthMode derivation ------------------------------------------------

    #[test]
    fn mode_from_caps() {
        assert_eq!(AuthMode::from_caps(true, true), AuthMode::Passkey);
        assert_eq!(AuthMode::from_caps(true, false), AuthMode::TokenOnly);
        assert_eq!(AuthMode::from_caps(false, false), AuthMode::Open);
        // Passkey enabled implies auth is on, whatever the `enabled` flag says.
        assert_eq!(AuthMode::from_caps(false, true), AuthMode::Passkey);
    }

    // ---- Regression matrix required by the hardening task --------------------
    // Six credential situations for a protected GET.

    /// 1. A passkey session: the cookie authorizes, no bearer is attached, and a
    ///    2xx never produces an authorization action.
    #[test]
    fn protected_get_with_passkey_session() {
        assert!(!should_attach_token("", ORIGIN, false));
        assert_eq!(
            unauthorized_action(200, AuthMode::Passkey, "/investigations", false),
            UnauthorizedAction::None
        );
    }

    /// 2. A valid operator bearer token on a same-origin request: attached.
    ///    This is the defect the pass fixes — `send_get` used to send nothing.
    #[test]
    fn protected_get_with_operator_token() {
        assert!(should_attach_token("", ORIGIN, true));
        assert!(should_attach_token("/api", ORIGIN, true));
        assert!(should_attach_token(ORIGIN, ORIGIN, true));
    }

    /// 3. No credentials at all on a passkey deployment → login, with the
    ///    destination preserved so the operator lands back where they were.
    #[test]
    fn protected_get_without_credentials_redirects_and_preserves_destination() {
        assert_eq!(
            unauthorized_action(401, AuthMode::Passkey, "/system?tab=access", false),
            UnauthorizedAction::RedirectToLogin {
                next: "/system?tab=access".into()
            }
        );
    }

    /// 4. An expired passkey session behaves exactly like case 3 — the server
    ///    reports 401 and the console must not silently render an empty view.
    #[test]
    fn expired_passkey_session_redirects_to_login() {
        match unauthorized_action(401, AuthMode::Passkey, "/audit?q=ssh", false) {
            UnauthorizedAction::RedirectToLogin { next } => {
                assert_eq!(next, "/audit?q=ssh")
            }
            other => panic!("expected a login redirect, got {other:?}"),
        }
    }

    /// 5. An invalid bearer token on a token-only deployment: an actionable
    ///    prompt, never a redirect — there is no passkey to log in with.
    #[test]
    fn invalid_bearer_token_prompts_instead_of_redirecting() {
        assert_eq!(
            unauthorized_action(401, AuthMode::TokenOnly, "/detections", true),
            UnauthorizedAction::PromptForOperatorToken
        );
    }

    /// 6. A token-only deployment with no token yet: same actionable state, and
    ///    the token is still attached to same-origin requests once it is set.
    #[test]
    fn token_only_deployment_never_bounces_to_login() {
        assert_eq!(
            unauthorized_action(401, AuthMode::TokenOnly, "/", false),
            UnauthorizedAction::PromptForOperatorToken
        );
        assert_eq!(
            unauthorized_action(401, AuthMode::Unknown, "/", false),
            UnauthorizedAction::PromptForOperatorToken
        );
        assert_eq!(
            unauthorized_action(401, AuthMode::Open, "/", false),
            UnauthorizedAction::PromptForOperatorToken
        );
    }

    // ---- Loop protection ----------------------------------------------------

    #[test]
    fn never_redirects_when_already_on_login() {
        for mode in [AuthMode::Passkey, AuthMode::TokenOnly, AuthMode::Unknown] {
            assert_eq!(
                unauthorized_action(401, mode, "/login", false),
                UnauthorizedAction::None,
                "{mode:?} must not redirect away from /login"
            );
            assert_eq!(
                unauthorized_action(401, mode, "/login?next=/system", false),
                UnauthorizedAction::None
            );
        }
    }

    #[test]
    fn forbidden_is_never_a_redirect() {
        for mode in [AuthMode::Passkey, AuthMode::TokenOnly, AuthMode::Open] {
            assert_eq!(
                unauthorized_action(403, mode, "/system", true),
                UnauthorizedAction::Forbidden,
                "403 under {mode:?} must not redirect"
            );
        }
    }

    #[test]
    fn non_auth_statuses_are_not_auth_actions() {
        for s in [200, 204, 400, 404, 422, 500, 503] {
            assert_eq!(
                unauthorized_action(s, AuthMode::Passkey, "/x", false),
                UnauthorizedAction::None
            );
        }
    }

    // ---- Token never leaves the origin --------------------------------------

    #[test]
    fn token_is_never_sent_to_a_foreign_origin() {
        for foreign in [
            "https://evil.tld",
            "http://evil.tld",
            "//evil.tld",
            "https://pve.example.ts.net.evil.tld",
            "https://evil.tld/pve.example.ts.net",
            "http://pve.example.ts.net", // scheme downgrade
        ] {
            assert!(
                !should_attach_token(foreign, ORIGIN, true),
                "{foreign} must not receive the operator token"
            );
        }
    }

    #[test]
    fn token_is_not_sent_to_an_authority_with_embedded_credentials() {
        assert!(!should_attach_token(
            "https://user:pw@pve.example.ts.net",
            ORIGIN,
            true
        ));
    }

    #[test]
    fn no_token_means_no_header_anywhere() {
        for base in ["", "/api", ORIGIN, "https://evil.tld"] {
            assert!(!should_attach_token(base, ORIGIN, false));
        }
    }

    #[test]
    fn default_ports_match_explicit_ones() {
        assert!(should_attach_token(
            "https://pve.example.ts.net:443",
            ORIGIN,
            true
        ));
        assert!(should_attach_token(
            "http://localhost",
            "http://localhost:80",
            true
        ));
        assert!(!should_attach_token(
            "https://pve.example.ts.net:8443",
            ORIGIN,
            true
        ));
    }

    // ---- No credential ever reaches a URL -----------------------------------

    #[test]
    fn safe_next_strips_credential_shaped_parameters() {
        assert_eq!(safe_next("/system?token=abc123"), "/system");
        assert_eq!(safe_next("/x?a=1&secret=s&b=2"), "/x?a=1&b=2");
        assert_eq!(safe_next("/x?API_KEY=k"), "/x");
        assert_eq!(safe_next("/audit?q=ssh&limit=50"), "/audit?q=ssh&limit=50");
    }

    #[test]
    fn safe_next_refuses_open_redirects() {
        for hostile in [
            "//evil.tld",
            "https://evil.tld/x",
            "http://evil.tld",
            "evil.tld",
        ] {
            assert_eq!(safe_next(hostile), "/", "{hostile} must not survive");
        }
    }

    #[test]
    fn login_path_detection() {
        assert!(is_login_path("/login"));
        assert!(is_login_path("/login/"));
        assert!(is_login_path("/login?next=/system"));
        assert!(!is_login_path("/"));
        assert!(!is_login_path("/system"));
        assert!(!is_login_path("/login-history"));
    }
}
