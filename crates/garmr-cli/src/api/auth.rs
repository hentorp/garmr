// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! Request authentication + RBAC: resolve the presented bearer/basic secret OR
//! a passkey session cookie to a principal (require_auth), and the admin gate
//! for /admin/* + LLM-spend endpoints (check_admin). Passkey login (see
//! `passkey`) is additive — the bearer token keeps working for machines.

use axum::http::header;

use super::passkey::{session_cookie, Webauthn};
use super::*;

/// Bearer-token gate for the admin routes + LLM-spend endpoints. Accepts the
/// admin bearer token OR an Admin-role passkey session (a hardware-verified
/// operator is at least as strong a human-approval signal as the token).
pub(super) fn check_admin(
    st: &ApiState,
    headers: &axum::http::HeaderMap,
) -> Result<garmr_core::Principal, (StatusCode, String)> {
    let presented = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .map(presented_secret)
        .unwrap_or_default();
    // Bearer admin token — constant-time resolution; a non-admin/unknown secret
    // is an indistinguishable 401.
    if let Some(who) = st
        .auth
        .resolve(&presented)
        .filter(|p| p.role.allows(garmr_core::Role::Admin))
    {
        tracing::info!(user = %who.user, role = ?who.role, "admin action authorized (token)");
        return Ok(who);
    }
    // Scoped credential holding the master system:admin scope (e.g. a host-minted
    // break-glass recovery credential) — a full-admin bearer.
    if let Some(who) = super::credentials::system_admin_principal(st, headers) {
        tracing::info!(user = %who.user, "admin action authorized (system:admin credential)");
        return Ok(who);
    }
    // Admin passkey session.
    if let (Some(w), Some(cookie)) = (st.webauthn.as_ref(), session_cookie(headers)) {
        if let Some((user, role)) = w.verify_cookie(&cookie) {
            if role.allows(garmr_core::Role::Admin) {
                tracing::info!(user = %user, "admin action authorized (passkey)");
                return Ok(garmr_core::Principal { user, role });
            }
        }
    }
    Err((StatusCode::UNAUTHORIZED, "unauthorized".to_string()))
}

/// Analyst-tier gate for feedback/decision writes (one rung below `check_admin`).
/// Accepts an Analyst-or-higher bearer/basic token OR passkey session. When NO
/// tokens are configured (`auth.len() == 0`, the open-loopback dev posture where
/// `require_auth` isn't even layered), a synthetic local Analyst is returned so
/// local `curl` keeps working. An authenticated-but-underprivileged caller gets
/// a 403 (audited best-effort), distinct from the 401 for no credentials.
pub(super) fn check_analyst(
    st: &ApiState,
    headers: &axum::http::HeaderMap,
) -> Result<garmr_core::Principal, (StatusCode, String)> {
    if st.auth.is_empty() {
        return Ok(garmr_core::Principal {
            user: "local".to_string(),
            role: garmr_core::Role::Analyst,
        });
    }
    let presented = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .map(presented_secret)
        .unwrap_or_default();
    // Try the token, then FALL THROUGH to a passkey session (like check_admin):
    // an underprivileged token must not short-circuit a qualifying passkey. Only
    // a credential that resolved-but-underprivileged yields a 403; no credential
    // at all is a 401.
    let mut denied_user: Option<String> = None;
    if let Some(who) = st.auth.resolve(&presented) {
        if who.role.allows(garmr_core::Role::Analyst) {
            return Ok(who);
        }
        denied_user = Some(who.user);
    }
    if let (Some(w), Some(cookie)) = (st.webauthn.as_ref(), session_cookie(headers)) {
        if let Some((user, role)) = w.verify_cookie(&cookie) {
            if role.allows(garmr_core::Role::Analyst) {
                return Ok(garmr_core::Principal { user, role });
            }
            denied_user = Some(user);
        }
    }
    match denied_user {
        Some(u) => Err(deny_analyst(&u)),
        None => Err((StatusCode::UNAUTHORIZED, "unauthorized".to_string())),
    }
}

/// Record a denied privileged attempt (best-effort) and return a 403.
fn deny_analyst(user: &str) -> (StatusCode, String) {
    crate::audit::record_best_effort(
        garmr_audit::AuditRecord::new(garmr_audit::action::AUTHZ_DENIED, "feedback")
            .actor(garmr_audit::ActorType::Human, user.to_string(), None)
            .outcome(garmr_audit::Outcome::Denied)
            .policy(garmr_audit::PolicyDecision::Denied)
            .reason("analyst role required"),
    );
    (
        StatusCode::FORBIDDEN,
        "this action requires the analyst role".to_string(),
    )
}

/// Extract the presented secret from an `Authorization` header value, for both
/// `Bearer <token>` (API clients / curl) and `Basic <base64(user:pass)>` (a
/// browser's native login prompt — the username is ignored, the password is
/// the token). Returns "" for anything else.
/// Who is calling, when that is only needed for attribution rather than for an
/// authorization decision — the caller has already passed `require_auth`.
///
/// Returns `None` for the open loopback/no-token stance, where there is no
/// identity to attribute. Never used to GRANT anything: the role checks above
/// are the gates, and this must not become a second, weaker one.
pub(super) fn attributed_principal(
    st: &ApiState,
    headers: &axum::http::HeaderMap,
) -> Option<garmr_core::Principal> {
    let presented = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .map(presented_secret)
        .unwrap_or_default();
    if let Some(who) = st.auth.resolve(&presented) {
        return Some(who);
    }
    if let (Some(w), Some(cookie)) = (st.webauthn.as_ref(), session_cookie(headers)) {
        if let Some((user, role)) = w.verify_cookie(&cookie) {
            return Some(garmr_core::Principal { user, role });
        }
    }
    super::credentials::system_admin_principal(st, headers)
}

fn presented_secret(header: &str) -> String {
    if let Some(t) = header.strip_prefix("Bearer ") {
        return t.to_string();
    }
    if let Some(b64) = header.strip_prefix("Basic ") {
        use base64::Engine;
        if let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(b64.trim()) {
            if let Ok(decoded) = std::str::from_utf8(&bytes) {
                // "user:pass" — the token is the password half (everything
                // after the first ':'; a missing ':' yields "").
                return decoded
                    .split_once(':')
                    .map(|(_, p)| p.to_string())
                    .unwrap_or_default();
            }
        }
    }
    String::new()
}

/// Paths reachable WITHOUT authentication: the liveness probe, the login page,
/// and the passkey login/logout/status endpoints (you must be able to log in
/// before you hold a session). Everything else — the SPA, /api/*, /admin/*, and
/// the passkey REGISTER endpoints (bootstrapped with the admin token) — is gated.
fn is_public(path: &str) -> bool {
    // Exact matches only — a prefix match (`starts_with("/auth/passkey/login/")`)
    // could be widened by a crafted sub-path; the two real login routes are named
    // explicitly (Phase 14 c4).
    matches!(
        path,
        "/health"
            // Readiness: a load balancer or kubelet probe cannot carry a
            // credential. /metrics is deliberately NOT here — it leaks posture.
            | "/ready"
            | "/login"
            | "/auth/status"
            | "/auth/logout"
            // The SSO entry points, like the passkey ones: reachable before a
            // session exists, by definition.
            | "/auth/oidc/start"
            | "/auth/oidc/callback"
            | "/auth/passkey/login/start"
            | "/auth/passkey/login/finish"
    )
}

/// Static front-end assets reachable WITHOUT authentication.
///
/// The web console is a WASM single-page app built by trunk: the browser loads the
/// gated `index.html` navigation (still behind `require_auth`, so an anonymous hit
/// redirects to `/login`) and then pulls its `*.js` glue + `*_bg.wasm` module. Trunk
/// tags those subresource links `crossorigin="anonymous"`, which forces a
/// CREDENTIAL-LESS fetch — the `Secure` session cookie is not sent — so under a
/// blanket auth gate the js/wasm 401, the loader feeds the 401 body to
/// `WebAssembly.instantiateStreaming`, the module's top-level await throws, and
/// `main()` never runs: a blank page on every fresh (not-yet-cached) deploy.
///
/// These bytes are the compiled public frontend — identical for every visitor and
/// carrying no secrets — so serving them unauthenticated is the conventional SPA
/// posture. This exemption is deliberately narrow: only static-asset *extensions*
/// on safe methods qualify, HTML navigations stay gated (preserving the `/login`
/// redirect), and anything under the `/api`, `/admin`, or `/auth` namespaces is
/// refused outright — so it can never widen the authenticated API/admin surface.
/// See docs/webui/deploy-loader-auth-issue.md.
fn is_public_asset(method: &axum::http::Method, path: &str) -> bool {
    use axum::http::Method;
    // Only cheap, side-effect-free reads of a static file — never a mutator.
    if *method != Method::GET && *method != Method::HEAD {
        return false;
    }
    // Defence in depth: the authenticated surfaces are prefix-namespaced, so never
    // treat anything under them as a static asset even if a route ever ended in one
    // of the extensions below.
    if path.starts_with("/api/") || path.starts_with("/admin/") || path.starts_with("/auth/") {
        return false;
    }
    // `.wasm`/`.js` are the two the trunk loader actually fetches credential-less
    // (console at `/`, embedded map at `/map/`); the rest are the conventional
    // static types a future bundle may add (styles, fonts, icons/images) — all
    // public, none secret. No API/admin/auth route ends in any of these.
    const PUBLIC_ASSET_EXT: &[&str] = &[
        ".wasm", ".js", ".css", ".woff2", ".woff", ".ttf", ".ico", ".png", ".svg", ".webp", ".jpg",
        ".jpeg", ".gif",
    ];
    PUBLIC_ASSET_EXT.iter().any(|ext| path.ends_with(ext))
}

/// The read scope a scoped machine credential must carry to reach the `/api/*`
/// surface (PR #4). Kept as a module const so the enforcement point and its test
/// agree on the literal; `system:admin` (the master scope) also satisfies it.
const API_READ_SCOPE: &str = "api:read";

/// Whether a scoped machine credential with `scopes` may proceed to `path`.
///
/// The `/api/*` read surface is gated: a scoped credential (`garmr_pat_…`) hitting
/// `/api/*` is allowed ONLY if its scopes include `api:read` or the master
/// `system:admin` scope. Every non-`/api/` path (the SPA, `/admin/*`, …) falls
/// through unchanged — those surfaces keep their existing role/scope handler checks
/// (`check_admin`, `require_scope`), so this predicate never widens them.
fn scoped_credential_allows_path(scopes: &[String], path: &str) -> bool {
    if !path.starts_with("/api/") {
        return true;
    }
    scopes
        .iter()
        .any(|s| s == API_READ_SCOPE || s == "system:admin")
}

/// API-authentication gate (whole surface) — active only when `GARMR_API_TOKEN`
/// is set, and REQUIRED for a non-loopback bind (enforced at startup). A request
/// is authenticated by the API/admin bearer token OR (when passkey is enabled) a
/// valid session cookie. On a miss: browsers are redirected to `/login` when
/// passkey is on, otherwise get a `Basic` challenge (unchanged legacy behaviour).
/// The lanes a source-restricted credential may reach.
///
/// This is an ALLOW-LIST on purpose. A deny-list would have to be extended in
/// lockstep with every endpoint ever added, and the failure mode of forgetting
/// one is a silent cross-source data leak — the exact thing scoping exists to
/// prevent. With an allow-list, forgetting an endpoint means a scoped credential
/// gets a 403 it did not expect: visible, reported, and fixed in an hour.
///
/// A lane belongs here only once it ACTUALLY enforces the scope — not once it is
/// planned to. The SQL lanes below pipe through `constrain_sources`; the
/// full-text, hybrid, semantic and tail lanes do not yet (that is M3/M4), so
/// they are absent and a restricted credential gets a 403 there rather than
/// unfiltered rows. `/api/entity`, `/api/graph` and `/api/ask` are absent for
/// the same reason: they answer from the full corpus.
///
/// The two non-data entries carry no event rows at all — `/api/capabilities`
/// reports what this build can do and `/api/principals` lists names and roles —
/// so scoping them would confine nothing while breaking a console that cannot
/// render without them.
pub(super) const ENFORCED_LANES: &[&str] = &[
    // Data lanes that apply the source constraint.
    "/api/query",
    "/api/query/cold",
    "/api/cold-query",
    "/api/search",
    "/api/hsearch",
    "/api/reproduce",
    "/api/semantic",
    // No event rows at all: what this build can do, and who can act. Scoping
    // them would confine nothing while breaking a console that cannot render
    // without them.
    "/api/capabilities",
    "/api/principals",
    "/health",
    "/ready",
];

fn scope_enforced_lane(path: &str) -> bool {
    // Exact matches, never prefixes: a prefix match on "/api/query" would also
    // admit a future "/api/query-anything" that nobody checked.
    ENFORCED_LANES.contains(&path)
}

pub(super) async fn require_auth(
    auth: std::sync::Arc<garmr_core::AuthRegistry>,
    creds: super::credentials::CredentialStore,
    webauthn: Option<std::sync::Arc<Webauthn>>,
    mut req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    if is_public(req.uri().path()) {
        return next.run(req).await;
    }
    // Static SPA assets (js/wasm/css/fonts/icons) are public: the trunk loader
    // fetches them credential-less, so gating them blanks every fresh deploy while
    // protecting nothing (they carry no secrets). See `is_public_asset`.
    if is_public_asset(req.method(), req.uri().path()) {
        return next.run(req).await;
    }
    let presented = req
        .headers()
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .map(presented_secret)
        .unwrap_or_default();
    // Bearer/basic env token → named principal.
    if let Some(principal) = auth.resolve(&presented) {
        req.extensions_mut().insert(principal);
        req.extensions_mut()
            .insert(garmr_core::DataScope::Unrestricted);
        return next.run(req).await;
    }
    // Scoped machine credential (garmr_pat_…) → principal. The credential's ROLE
    // gates the read surface like any principal; its scopes further restrict
    // specific privileged ACTIONS at the handler via require_scope (Cycle 1:
    // secrets:write). The `/api/*` read surface additionally requires an explicit
    // `api:read` (or `system:admin`) scope (PR #4) — non-/api/ paths fall through
    // to the existing handler checks unchanged.
    if let Some((principal, scopes, data_scope)) = creds.resolve(&presented, None) {
        if scoped_credential_allows_path(&scopes, req.uri().path()) {
            // Deny-by-default for a source-restricted credential: it may reach
            // only the lanes that have been taught to enforce a data scope.
            // Every other handler would answer from the full corpus, so an
            // allow-list is the only safe shape — a deny-list would have to be
            // updated in lockstep with every new endpoint, and the failure mode
            // of forgetting is a silent leak.
            if !data_scope.is_unrestricted() && !scope_enforced_lane(req.uri().path()) {
                return (
                    StatusCode::FORBIDDEN,
                    "this credential is restricted to specific sources, and this endpoint \
                     cannot yet enforce that restriction"
                        .to_string(),
                )
                    .into_response();
            }
            req.extensions_mut().insert(principal);
            req.extensions_mut().insert(data_scope);
            return next.run(req).await;
        }
        // Resolved, but its scopes do not cover the /api/* read surface — a
        // resolved-but-underprivileged 403 (distinct from the 401 for no creds),
        // mirroring require_scope. Does not fall through to a passkey session: a
        // bearer that resolved to a credential is already an authenticated caller.
        return (
            StatusCode::FORBIDDEN,
            format!("this credential lacks the required scope: {API_READ_SCOPE}"),
        )
            .into_response();
    }
    // Passkey session cookie.
    if let Some(w) = &webauthn {
        if let Some(cookie) = session_cookie(req.headers()) {
            if let Some((user, role)) = w.verify_cookie(&cookie) {
                // Resolved from the STORE on every request, never carried in the
                // cookie, so narrowing or revoking an identity's sources takes
                // effect on the next request rather than whenever the holder's
                // session happens to expire. A scope baked into the cookie would
                // leave a window — up to the full session TTL — in which an
                // identity an admin has just confined still reads everything,
                // which is precisely the window that matters after a suspected
                // compromise.
                let scope = w.data_scope_for(&user);
                if !scope.is_unrestricted() && !scope_enforced_lane(req.uri().path()) {
                    return (
                        StatusCode::FORBIDDEN,
                        "this identity is restricted to specific sources, and this endpoint \
                         cannot yet enforce that restriction"
                            .to_string(),
                    )
                        .into_response();
                }
                req.extensions_mut()
                    .insert(garmr_core::Principal { user, role });
                req.extensions_mut().insert(scope);
                return next.run(req).await;
            }
        }
    }
    // Unauthenticated on a protected path.
    if webauthn.is_some() {
        let wants_html = req
            .headers()
            .get(header::ACCEPT)
            .and_then(|v| v.to_str().ok())
            .map(|a| a.contains("text/html"))
            .unwrap_or(false);
        if wants_html {
            // Send browsers to the passkey login page instead of a dead 401.
            return (StatusCode::FOUND, [(header::LOCATION, "/login")]).into_response();
        }
        return (StatusCode::UNAUTHORIZED, "unauthorized").into_response();
    }
    // Legacy token-only: keep the Basic challenge so browsers get a prompt.
    (
        StatusCode::UNAUTHORIZED,
        [(
            axum::http::header::WWW_AUTHENTICATE,
            "Basic realm=\"garmr\", charset=\"UTF-8\"",
        )],
        "unauthorized",
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::{
        is_public, is_public_asset, scope_enforced_lane, scoped_credential_allows_path,
        ENFORCED_LANES,
    };
    use axum::http::Method;

    fn scopes(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn scoped_credential_read_scope_gates_api_only() {
        // /api/* is rejected without api:read or system:admin.
        assert!(!scoped_credential_allows_path(&scopes(&[]), "/api/query"));
        assert!(!scoped_credential_allows_path(
            &scopes(&["secrets:write"]),
            "/api/query"
        ));
        // api:read or the master system:admin scope allows /api/*.
        assert!(scoped_credential_allows_path(
            &scopes(&["api:read"]),
            "/api/query"
        ));
        assert!(scoped_credential_allows_path(
            &scopes(&["system:admin"]),
            "/api/entity/host/h1"
        ));
        assert!(scoped_credential_allows_path(
            &scopes(&["secrets:write", "api:read"]),
            "/api/query"
        ));
        // Non-/api/ paths fall through regardless of scopes (/admin/* keeps its
        // own handler checks; the SPA is role-gated).
        for p in [
            "/admin/secrets",
            "/admin/silence",
            "/cases/123",
            "/",
            "/index.html",
        ] {
            assert!(
                scoped_credential_allows_path(&scopes(&[]), p),
                "{p} must fall through"
            );
        }
    }

    #[test]
    fn is_public_is_exact_match_only() {
        // The real public routes.
        for p in [
            "/health",
            "/login",
            "/auth/status",
            "/auth/logout",
            "/auth/passkey/login/start",
            "/auth/passkey/login/finish",
        ] {
            assert!(is_public(p), "{p} should be public");
        }
        // A crafted sub-path under the old prefix must NOT be public (Phase 14 c4).
        for p in [
            "/auth/passkey/login/../register/finish",
            "/auth/passkey/login/anything",
            "/auth/passkey/register/finish",
            "/api/query",
            "/admin/silence",
        ] {
            assert!(!is_public(p), "{p} must be gated");
        }
    }

    #[test]
    fn is_public_asset_exempts_spa_bytes_only() {
        // The trunk loader's credential-less subresources — the actual deploy bug
        // (console at `/`, embedded map at `/map/`), plus conventional static types.
        for p in [
            "/garmr-webui-abc123.js",
            "/garmr-webui-abc123_bg.wasm",
            "/map/garmr-map-def456.js",
            "/map/garmr-map-def456_bg.wasm",
            "/style.css",
            "/fonts/inter.woff2",
            "/favicon.ico",
        ] {
            assert!(
                is_public_asset(&Method::GET, p),
                "{p} should be a public asset"
            );
            assert!(
                is_public_asset(&Method::HEAD, p),
                "{p} should be a public asset (HEAD)"
            );
        }
        // HTML navigations stay gated, so an anonymous hit still redirects to /login.
        for p in ["/", "/index.html", "/cases/123", "/map/", "/map/index.html"] {
            assert!(
                !is_public_asset(&Method::GET, p),
                "{p} must stay gated (navigation)"
            );
        }
        // The authenticated surfaces are never exempt — even a GET, even if a path
        // under them ends in an asset extension.
        for p in [
            "/api/query",
            "/api/entity/host/build.js",
            "/admin/secrets",
            "/auth/passkey/register/finish",
        ] {
            assert!(
                !is_public_asset(&Method::GET, p),
                "{p} must stay gated (protected)"
            );
        }
        // A `.json` path must not be caught by the `.js` suffix, and a non-safe
        // method never qualifies (defence in depth).
        assert!(!is_public_asset(&Method::GET, "/data.json"));
        assert!(!is_public_asset(&Method::POST, "/garmr-webui-abc123.js"));
    }

    #[test]
    fn a_restricted_credential_reaches_only_scope_enforcing_lanes() {
        // These lanes apply the rewrite, so a restricted credential is safe on
        // them.
        for ok in [
            "/api/query",
            "/api/query/cold",
            "/api/cold-query",
            "/api/search",
            "/api/hsearch",
            "/api/reproduce",
            "/api/semantic",
        ] {
            assert!(scope_enforced_lane(ok), "{ok} should be enforceable");
        }
        // Still NOT filtering by source. Admitting a lane before it enforces is
        // admitting a leak, which is the precise thing the allow-list shape
        // exists to prevent. `/api/tail` streams straight from the live pipeline
        // with no source predicate.
        assert!(
            !scope_enforced_lane("/api/tail"),
            "/api/tail streams from the live pipeline with no source predicate, so it \
             does not filter by source yet and must not be reachable"
        );
        // These answer from the FULL corpus today. Admitting them would be
        // admitting a cross-source leak, so they must stay out until they
        // enforce the scope themselves.
        for leaky in [
            "/api/entity",
            "/api/graph",
            "/api/ask",
            "/api/cases",
            "/api/risk",
            "/api/findings",
        ] {
            assert!(
                !scope_enforced_lane(leaky),
                "{leaky} does not enforce a data scope and must not be reachable"
            );
        }
    }

    #[test]
    fn the_lane_list_matches_exactly_and_never_by_prefix() {
        // A prefix match would admit any future sibling path nobody reviewed.
        assert!(scope_enforced_lane("/api/query"));
        assert!(!scope_enforced_lane("/api/query-anything"));
        assert!(!scope_enforced_lane("/api/queryx"));
        assert!(!scope_enforced_lane("/api/search/all"));
    }

    /// The documented lane list must BE the enforced one.
    ///
    /// A doc that drifts from the code is worse than no doc here: an operator
    /// reads this page to decide whether a confined credential is safe to hand
    /// out, and a stale list would tell them a lane is protected when it is not.
    #[test]
    fn the_documented_lanes_match_the_enforced_lanes() {
        let doc = include_str!("../../../../docs/enterprise/data-authorization.md");
        let block = doc
            .split("<!-- ENFORCED_LANES:start -->")
            .nth(1)
            .and_then(|s| s.split("<!-- ENFORCED_LANES:end -->").next())
            .expect("the doc must carry a delimited lane list");
        let documented: Vec<&str> = block
            .lines()
            .filter_map(|l| l.trim().strip_prefix("- `"))
            .filter_map(|l| l.strip_suffix('`'))
            .collect();
        assert_eq!(
            documented,
            ENFORCED_LANES.to_vec(),
            "docs/enterprise/data-authorization.md is out of sync with ENFORCED_LANES"
        );
    }

    #[test]
    fn every_enforced_lane_is_an_absolute_exact_path() {
        // A relative or wildcard entry would silently never match, leaving a
        // lane the operator believes is reachable permanently 403 — or, if the
        // matcher were ever loosened to prefixes, admit siblings nobody vetted.
        for lane in ENFORCED_LANES {
            assert!(lane.starts_with('/'), "{lane} must be an absolute path");
            assert!(!lane.contains('*'), "{lane} must not be a pattern");
            assert!(
                !lane.ends_with('/'),
                "{lane} must not have a trailing slash"
            );
        }
    }
}
