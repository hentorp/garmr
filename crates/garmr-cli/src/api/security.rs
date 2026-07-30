// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! Phase 14 — API security hardening. The response-decoration layers are wired
//! OUTERMOST + UNCONDITIONALLY in `build_router`, so they cover EVERY response
//! including auth's own 401s, the static web-console, 404/500, and — crucially —
//! the loopback / no-token default deployment:
//!
//! - static security headers (X-Content-Type-Options, X-Frame-Options,
//!   Referrer-Policy, COOP/CORP, Permissions-Policy);
//! - a same-origin **Content-Security-Policy** (`connect-src 'self'` is the
//!   browser-enforced counterpart to the server-side egress chokepoint), built at
//!   startup by hashing the login page's inline script (+ any mounted SPA), so
//!   `script-src` stays strict with no `'unsafe-inline'`;
//! - a cookie-scoped **CSRF Origin guard** (belt-and-suspenders over
//!   SameSite=Strict + Json-only mutators).
//!
//! Plus the read-only `/api/security/posture` + `/api/ha/status` reads.

use std::sync::Arc;

use axum::extract::Request;
use axum::http::{header::HeaderName, HeaderMap, HeaderValue, Method, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

/// The static security headers, as `(name, value)` pairs. All values are constant
/// (no per-request state), so they are cheap `from_static` inserts.
///
/// - `X-Content-Type-Options: nosniff` — no MIME sniffing.
/// - `X-Frame-Options: SAMEORIGIN` — same-origin framing only (the console embeds
///   the CodeVault map at /map/); cross-origin framing stays blocked (clickjacking).
/// - `Referrer-Policy: no-referrer` — never leak a URL to another origin.
/// - `Cross-Origin-Opener-Policy: same-origin` — isolate the browsing context.
/// - `Cross-Origin-Resource-Policy: same-origin` — no cross-origin embedding.
/// - `Permissions-Policy` — deny powerful features. It deliberately does NOT
///   restrict `publickey-credentials-get/create`, which the passkey/WebAuthn login
///   flow needs.
const SECURITY_HEADERS: &[(&str, &str)] = &[
    ("x-content-type-options", "nosniff"),
    ("x-frame-options", "SAMEORIGIN"),
    ("referrer-policy", "no-referrer"),
    ("cross-origin-opener-policy", "same-origin"),
    ("cross-origin-resource-policy", "same-origin"),
    (
        "permissions-policy",
        "accelerometer=(),camera=(),geolocation=(),gyroscope=(),magnetometer=(),\
         microphone=(),payment=(),usb=()",
    ),
];

/// Insert the static security headers into `headers` (overwriting any existing).
/// Pure and testable without a live server.
pub(super) fn apply_security_headers(headers: &mut HeaderMap) {
    for (name, value) in SECURITY_HEADERS {
        headers.insert(
            HeaderName::from_static(name),
            HeaderValue::from_static(value),
        );
    }
}

/// The outermost middleware: run the inner stack, then decorate the response with
/// the security headers. Applied to EVERY response, on every deployment.
pub(super) async fn security_headers_layer(req: Request, next: Next) -> Response {
    let mut resp = next.run(req).await;
    apply_security_headers(resp.headers_mut());
    resp
}

/// Should this request be rejected as a cross-site forgery? A belt-and-suspenders
/// Origin check on top of the primary defenses (`SameSite=Strict` on the session
/// cookie + `Json`-only mutators that make an HTML cross-site form 415, + no CORS
/// so a cross-origin `fetch` is preflight-blocked).
///
/// It fires ONLY on an UNSAFE-method request that either carries the browser
/// session cookie (an ambient credential a cross-site page could ride) or targets
/// `/auth/logout` (the one public POST — this closes forced-logout CSRF). A
/// bearer/basic/curl client (no session cookie) is NEVER affected — machine
/// traffic is untouched. When it fires, the `Origin` header must be present AND
/// equal the allowed origin; a missing or foreign `Origin` is treated as a
/// forgery. Safe methods (GET/HEAD/OPTIONS) never fire.
pub(super) fn csrf_blocked(
    method: &Method,
    path: &str,
    headers: &HeaderMap,
    allowed: Option<&str>,
) -> bool {
    if matches!(*method, Method::GET | Method::HEAD | Method::OPTIONS) {
        return false;
    }
    let has_session = super::passkey::session_cookie(headers).is_some();
    if !has_session && path != "/auth/logout" {
        return false; // machine path (bearer/basic) — no ambient cookie to ride
    }
    let origin = headers
        .get(axum::http::header::ORIGIN)
        .and_then(|v| v.to_str().ok());
    match (origin, allowed) {
        // Present + a configured allowed origin → must match exactly.
        (Some(o), Some(a)) => o != a,
        // A cookie-authenticated state change with NO Origin is a forgery.
        (None, _) => true,
        // No configured allowed origin (passkey off ⇒ no real session cookie);
        // nothing to validate against — do not block.
        (Some(_), None) => false,
    }
}

/// Extract the `sha256-<base64>` CSP source tokens for every INLINE `<script>` in
/// `html` (one whose opening tag has no `src=`). The browser hashes the exact
/// bytes between `<script …>` and `</script>`, so a page with an inline bootstrap
/// (the login page; a Trunk-built SPA) can keep a strict `script-src` with NO
/// `'unsafe-inline'`. Positions are found on an ASCII-lowercased copy (same byte
/// length), and the ORIGINAL-case body is what is hashed.
pub(super) fn inline_script_hashes(html: &str) -> Vec<String> {
    use base64::Engine;
    use sha2::{Digest, Sha256};

    let lower = html.to_ascii_lowercase();
    let mut out = Vec::new();
    let mut i = 0usize;
    while let Some(rel) = lower[i..].find("<script") {
        let tag_start = i + rel;
        let Some(gt) = lower[tag_start..].find('>') else {
            break;
        };
        let open_end = tag_start + gt + 1;
        let open_tag = &lower[tag_start..open_end];
        let Some(close_rel) = lower[open_end..].find("</script>") else {
            break;
        };
        let body_end = open_end + close_rel;
        let body = &html[open_end..body_end];
        if !open_tag.contains("src=") && !body.trim().is_empty() {
            let digest = Sha256::digest(body.as_bytes());
            out.push(format!(
                "sha256-{}",
                base64::engine::general_purpose::STANDARD.encode(digest)
            ));
        }
        i = body_end + "</script>".len();
    }
    out
}

/// Build the Content-Security-Policy. Same-origin by construction — `connect-src
/// 'self'` is the browser-enforced counterpart to the server-side egress
/// chokepoint (an air-gapped console makes no external request), and there is NO
/// `http`/`https` token anywhere. `script-src` gets `'self' 'wasm-unsafe-eval'`
/// (the WASM console) plus the exact inline-script hashes — NEVER `'unsafe-inline'`.
/// `style-src` keeps `'unsafe-inline'` (Leptos/SVG dynamic `style=` attributes; a
/// style injection carries no script-execution risk) — a conscious tradeoff.
pub(super) fn build_csp(script_hashes: &[String]) -> String {
    let mut script = String::from("'self' 'wasm-unsafe-eval'");
    for h in script_hashes {
        script.push_str(" '");
        script.push_str(h);
        script.push('\'');
    }
    // `frame-src 'self'` + `frame-ancestors 'self'`: the console embeds the
    // CodeVault map (garmr-map, served same-origin at /map/) in an iframe, so it
    // must be allowed to load AND to be framed — but only by same-origin pages,
    // so cross-origin clickjacking stays blocked.
    format!(
        "default-src 'none'; base-uri 'none'; frame-src 'self'; frame-ancestors 'self'; \
         form-action 'self'; object-src 'none'; img-src 'self' data:; font-src 'self'; \
         style-src 'self' 'unsafe-inline'; connect-src 'self'; script-src {script}"
    )
}

/// CSP middleware: adds the (startup-built) `Content-Security-Policy` to every
/// response. Separate from the static-header layer because the value carries the
/// deployment's inline-script hashes.
pub(super) async fn csp_layer(csp: Arc<String>, req: Request, next: Next) -> Response {
    let mut resp = next.run(req).await;
    if let Ok(v) = HeaderValue::from_str(&csp) {
        resp.headers_mut()
            .insert(HeaderName::from_static("content-security-policy"), v);
    }
    resp
}

/// CSRF Origin-guard middleware. Blocks with 403 before the handler; logs the
/// block. `allowed` is the configured browser origin (`GARMR_WEBAUTHN_ORIGIN`).
pub(super) async fn csrf_layer(allowed: Arc<Option<String>>, req: Request, next: Next) -> Response {
    if csrf_blocked(
        req.method(),
        req.uri().path(),
        req.headers(),
        allowed.as_deref(),
    ) {
        tracing::warn!(
            method = %req.method(),
            path = %req.uri().path(),
            "CSRF: blocked a cookie-authenticated cross-site request (missing/foreign Origin)"
        );
        return (StatusCode::FORBIDDEN, "cross-site request blocked").into_response();
    }
    next.run(req).await
}

/// `GET /api/security/posture` — a read-only self-report of the API's security
/// stance so a "loopback open, no token" dev deployment is never invisible. It
/// REPORTS the egress posture from the chokepoint policy; it never opens egress.
pub(super) async fn security_posture(
    axum::extract::State(st): axum::extract::State<super::ApiState>,
) -> super::ApiResult {
    Ok(axum::Json(serde_json::json!({
        "auth_enabled": !st.auth.is_empty(),
        "security_headers": true,
        "csrf_guard": true,
        "cors_configured": false,
        "airgap": garmr_core::egress::global().is_airgap(),
        "audit_ledger_enabled": st.audit.is_some(),
        "passkey_enabled": st.webauthn.is_some(),
        "read_only": st.read_only,
    })))
}

/// `GET /api/ha/status` — this node's HA role. `read_only` (a follower) is what
/// lets the console disable write affordances on a replica. Behind the surface
/// auth (any principal), NOT public — never leak posture to the network unauthed.
pub(super) async fn ha_status(
    axum::extract::State(st): axum::extract::State<super::ApiState>,
) -> super::ApiResult {
    Ok(axum::Json(serde_json::json!({
        "role": if st.read_only { "follower" } else { "leader" },
        "read_only": st.read_only,
    })))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_security_header_is_applied() {
        let mut h = HeaderMap::new();
        apply_security_headers(&mut h);
        assert_eq!(h.get("x-content-type-options").unwrap(), "nosniff");
        assert_eq!(h.get("x-frame-options").unwrap(), "SAMEORIGIN");
        assert_eq!(h.get("referrer-policy").unwrap(), "no-referrer");
        assert_eq!(h.get("cross-origin-opener-policy").unwrap(), "same-origin");
        assert_eq!(
            h.get("cross-origin-resource-policy").unwrap(),
            "same-origin"
        );
        assert!(h
            .get("permissions-policy")
            .unwrap()
            .to_str()
            .unwrap()
            .contains("camera=()"));
    }

    #[test]
    fn permissions_policy_does_not_block_webauthn() {
        // The passkey login flow needs publickey-credentials-*; the policy must not
        // name (and thus restrict) them.
        let mut h = HeaderMap::new();
        apply_security_headers(&mut h);
        let pp = h.get("permissions-policy").unwrap().to_str().unwrap();
        assert!(!pp.contains("publickey-credentials"));
    }

    #[test]
    fn apply_overwrites_a_prior_value() {
        let mut h = HeaderMap::new();
        h.insert(
            HeaderName::from_static("x-frame-options"),
            HeaderValue::from_static("DENY"),
        );
        apply_security_headers(&mut h);
        assert_eq!(h.get("x-frame-options").unwrap(), "SAMEORIGIN");
    }

    const ALLOWED: &str = "https://garmr.example";

    fn hm(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.insert(
                HeaderName::from_bytes(k.as_bytes()).unwrap(),
                HeaderValue::from_str(v).unwrap(),
            );
        }
        h
    }

    #[test]
    fn csrf_blocks_a_cookie_request_with_a_foreign_or_missing_origin() {
        // Cookie present + foreign Origin → blocked.
        assert!(csrf_blocked(
            &Method::POST,
            "/api/feedback",
            &hm(&[("cookie", "garmr_session=abc"), ("origin", "https://evil")]),
            Some(ALLOWED),
        ));
        // Cookie present + NO Origin → blocked.
        assert!(csrf_blocked(
            &Method::POST,
            "/api/feedback",
            &hm(&[("cookie", "garmr_session=abc")]),
            Some(ALLOWED),
        ));
    }

    #[test]
    fn csrf_allows_same_origin_and_machine_clients() {
        // Cookie + matching Origin → allowed.
        assert!(!csrf_blocked(
            &Method::POST,
            "/api/feedback",
            &hm(&[("cookie", "garmr_session=abc"), ("origin", ALLOWED)]),
            Some(ALLOWED),
        ));
        // Bearer machine client (no cookie), foreign/absent Origin → NEVER blocked.
        assert!(!csrf_blocked(
            &Method::POST,
            "/api/feedback",
            &hm(&[("authorization", "Bearer tok"), ("origin", "https://evil")]),
            Some(ALLOWED),
        ));
        assert!(!csrf_blocked(
            &Method::POST,
            "/api/feedback",
            &hm(&[("authorization", "Bearer tok")]),
            Some(ALLOWED),
        ));
    }

    #[test]
    fn inline_script_hashes_hashes_inline_but_skips_src_scripts() {
        use base64::Engine;
        use sha2::{Digest, Sha256};
        let html = r#"<html><head>
            <script src="/app.js"></script>
            <script>console.log("hi");</script>
        </head></html>"#;
        let hashes = inline_script_hashes(html);
        assert_eq!(hashes.len(), 1, "only the inline script is hashed");
        let want = format!(
            "sha256-{}",
            base64::engine::general_purpose::STANDARD
                .encode(Sha256::digest(b"console.log(\"hi\");"))
        );
        assert_eq!(hashes[0], want);
    }

    #[test]
    fn csp_is_same_origin_strict_and_carries_hashes_no_unsafe_inline_script() {
        let csp = build_csp(&["sha256-ABC".to_string()]);
        assert!(csp.contains("default-src 'none'"));
        assert!(csp.contains("connect-src 'self'")); // browser-enforced airgap
                                                     // Same-origin framing for the embedded /map/ iframe; external framing blocked.
        assert!(csp.contains("frame-ancestors 'self'"));
        assert!(csp.contains("frame-src 'self'"));
        assert!(csp.contains("script-src 'self' 'wasm-unsafe-eval' 'sha256-ABC'"));
        // Airgap: no external host anywhere in the policy.
        assert!(!csp.contains("http://") && !csp.contains("https://"));
        // script-src must never allow inline scripts (styles are a conscious tradeoff).
        let script_src = csp.split("script-src").nth(1).unwrap();
        assert!(!script_src.contains("'unsafe-inline'"));
    }

    #[test]
    fn csrf_covers_forced_logout_but_not_safe_methods() {
        // /auth/logout is a public no-body POST; a foreign-Origin logout is blocked
        // even without a cookie (forced-logout CSRF).
        assert!(csrf_blocked(
            &Method::POST,
            "/auth/logout",
            &hm(&[("origin", "https://evil")]),
            Some(ALLOWED),
        ));
        // A GET never fires (safe method).
        assert!(!csrf_blocked(
            &Method::GET,
            "/api/cases",
            &hm(&[("cookie", "garmr_session=abc"), ("origin", "https://evil")]),
            Some(ALLOWED),
        ));
    }
}
