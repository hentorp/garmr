// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! The serve-API client (browser fetch via gloo-net). Same REST surface the
//! facett console used; the frontend deserializes JSON directly (no
//! garmr-core dep — it pulls figment, which isn't wasm-safe).
//!
//! `base()` is empty by default: the SPA is served BY `garmr serve`, so
//! same-origin relative paths hit the API with no CORS. A `?api=` query param
//! overrides it for dev against a separate origin.

use serde_json::Value;

use std::cell::RefCell;

thread_local! {
    /// An optional operator (admin) bearer token, held in memory for the session.
    /// In production the passkey session cookie authorizes admin actions and this
    /// stays `None`; on a token-only / loopback lab deployment the operator can
    /// paste the admin token (System › Access) so protected controls resolve to an
    /// Admin principal — exactly how a CLI/machine caller holds the token. It is
    /// never placed in a URL and never persisted to disk by the app.
    static OPERATOR_TOKEN: RefCell<Option<String>> = const { RefCell::new(None) };
}

/// Set (or clear) the in-memory operator token used to authorize admin actions.
pub fn set_operator_token(tok: Option<String>) {
    OPERATOR_TOKEN.with(|t| *t.borrow_mut() = tok.filter(|s| !s.trim().is_empty()));
}
/// Is an operator token held this session?
pub fn has_operator_token() -> bool {
    OPERATOR_TOKEN.with(|t| t.borrow().is_some())
}
fn operator_token() -> Option<String> {
    OPERATOR_TOKEN.with(|t| t.borrow().clone())
}

/// A structured API error: the HTTP status (0 = transport/parse failure) plus a
/// message. Views switch on `status` to render the right state — 401/403 →
/// "authorize as an operator", 400/422 → validation, 5xx → server failure.
#[derive(Clone, Debug)]
pub struct ApiError {
    pub status: u16,
    pub message: String,
}

impl ApiError {
    pub fn transport(msg: impl Into<String>) -> Self {
        Self {
            status: 0,
            message: msg.into(),
        }
    }
    /// True for an authorization failure (needs credentials / more privilege).
    pub fn is_authz(&self) -> bool {
        self.status == 401 || self.status == 403
    }
    /// A short human phrase for the state header.
    pub fn kind(&self) -> &'static str {
        match self.status {
            401 => "not authorized",
            403 => "forbidden",
            400 | 422 => "invalid request",
            404 => "not found",
            0 => "unreachable",
            s if s >= 500 => "server error",
            _ => "request failed",
        }
    }
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.status == 0 {
            write!(f, "{}", self.message)
        } else {
            write!(f, "HTTP {}: {}", self.status, self.message)
        }
    }
}

/// API base URL — same-origin (""). A `?api=<url>` query param can override it,
/// but ONLY in debug builds (dev against a separate origin). Release bundles
/// ignore it and always use the same-origin base, so a crafted console URL
/// (`…/?api=//evil.tld`) can never repoint the SOC's data source to a foreign
/// origin (a spoofing vector on the now network-exposed console).
pub fn base() -> String {
    if !cfg!(debug_assertions) {
        return String::new();
    }
    web_sys::window()
        .and_then(|w| w.location().search().ok())
        .and_then(|s| {
            s.trim_start_matches('?')
                .split('&')
                .find_map(|kv| kv.strip_prefix("api=").map(|v| v.to_string()))
        })
        .map(|v| {
            js_sys::decode_uri_component(&v)
                .map(String::from)
                .unwrap_or(v)
        })
        .unwrap_or_default()
        .trim_end_matches('/')
        .to_string()
}

/// GET `path` and parse JSON. `path` starts with `/`.
pub async fn get(path: &str) -> Result<Value, String> {
    let url = format!("{}{path}", base());
    let resp = gloo_net::http::Request::get(&url)
        .send()
        .await
        .map_err(|e| format!("GET {path}: {e}"))?;
    if !resp.ok() {
        // 401 = no/expired session → bounce to the passkey login page (when the
        // deployment runs passkey auth; token-only deployments 401 as before).
        if resp.status() == 401 {
            if let Some(w) = web_sys::window() {
                let _ = w.location().set_href("/login");
            }
        }
        return Err(format!("GET {path}: HTTP {}", resp.status()));
    }
    resp.json::<Value>()
        .await
        .map_err(|e| format!("GET {path}: bad JSON: {e}"))
}

/// POST JSON body to `path`, optionally with a bearer token. Used by logout and
/// the Ops write controls (rule/action approve/reject/deny). The admin endpoints
/// are authorized by the same-origin passkey session cookie (which fetch sends
/// automatically) resolving to an Admin principal, so `bearer` is normally
/// `None` from the browser; it stays for machine/dev callers.
pub async fn post(path: &str, body: Value, bearer: Option<&str>) -> Result<Value, String> {
    let url = format!("{}{path}", base());
    let mut req = gloo_net::http::Request::post(&url);
    if let Some(t) = bearer {
        req = req.header("Authorization", &format!("Bearer {t}"));
    }
    let resp = req
        .json(&body)
        .map_err(|e| format!("POST {path}: {e}"))?
        .send()
        .await
        .map_err(|e| format!("POST {path}: {e}"))?;
    let status = resp.status();
    let text = resp.text().await.unwrap_or_default();
    if !(200..300).contains(&status) {
        return Err(format!("POST {path}: HTTP {status}: {text}"));
    }
    serde_json::from_str::<Value>(&text).map_err(|e| format!("POST {path}: bad JSON: {e}"))
}

/// Structured GET: like [`get`] but returns an [`ApiError`] carrying the status
/// so views can distinguish 401/403/404/5xx. Still bounces to `/login` on a 401
/// when a passkey deployment expects a session.
pub async fn send_get(path: &str) -> Result<Value, ApiError> {
    let url = format!("{}{path}", base());
    let resp = gloo_net::http::Request::get(&url)
        .send()
        .await
        .map_err(|e| ApiError::transport(format!("GET {path}: {e}")))?;
    let status = resp.status();
    if !resp.ok() {
        let body = resp.text().await.unwrap_or_default();
        return Err(ApiError {
            status,
            message: trim_body(&body, path),
        });
    }
    resp.json::<Value>()
        .await
        .map_err(|e| ApiError::transport(format!("GET {path}: bad JSON: {e}")))
}

/// Admin/analyst-aware POST. Attaches the in-memory operator token as a bearer
/// when one is held (so a token-only/lab deployment can drive protected actions);
/// otherwise relies on the same-origin session cookie (passkey → Admin). Returns
/// a structured [`ApiError`] so the caller renders the right auth/validation/
/// server state and can surface the audit reference on success.
pub async fn send_post(path: &str, body: Value) -> Result<Value, ApiError> {
    let url = format!("{}{path}", base());
    let mut req = gloo_net::http::Request::post(&url);
    if let Some(t) = operator_token() {
        req = req.header("Authorization", &format!("Bearer {t}"));
    }
    let resp = req
        .json(&body)
        .map_err(|e| ApiError::transport(format!("POST {path}: {e}")))?
        .send()
        .await
        .map_err(|e| ApiError::transport(format!("POST {path}: {e}")))?;
    let status = resp.status();
    let text = resp.text().await.unwrap_or_default();
    if !(200..300).contains(&status) {
        return Err(ApiError {
            status,
            message: trim_body(&text, path),
        });
    }
    if text.trim().is_empty() {
        return Ok(Value::Null);
    }
    serde_json::from_str::<Value>(&text)
        .map_err(|e| ApiError::transport(format!("POST {path}: bad JSON: {e}")))
}

/// Pull a human message out of a possibly-JSON error body; fall back to the raw
/// (trimmed) text, then to the path.
fn trim_body(body: &str, path: &str) -> String {
    let t = body.trim();
    if t.is_empty() {
        return path.to_string();
    }
    if let Ok(v) = serde_json::from_str::<Value>(t) {
        if let Some(m) = v.get("error").and_then(Value::as_str) {
            return m.to_string();
        }
        if let Some(m) = v.get("message").and_then(Value::as_str) {
            return m.to_string();
        }
    }
    t.chars().take(300).collect()
}

/// Minimal percent-encoding, path/query safe.
pub fn enc(v: &str) -> String {
    let mut out = String::with_capacity(v.len());
    for b in v.bytes() {
        match b {
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            b' ' => out.push_str("%20"),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

// ---- JSON helpers ---------------------------------------------------------

/// A JSON `Value` string field, or "".
pub fn s(v: &Value, k: &str) -> String {
    v.get(k).and_then(Value::as_str).unwrap_or("").to_string()
}
/// First 8 chars of a string field (short id).
pub fn short(v: &Value, k: &str) -> String {
    s(v, k).chars().take(8).collect()
}
/// A count field that may be an int or a stringly int.
pub fn num(v: &Value, k: &str) -> i64 {
    v.get(k)
        .and_then(|x| {
            x.as_i64()
                .or_else(|| x.as_str().and_then(|s| s.parse().ok()))
        })
        .unwrap_or(0)
}
/// Format an epoch-microseconds timestamp as `YYYY-MM-DD HH:MM:SS` (UTC). Uses
/// the browser's `Date` so the wasm bundle needs no date crate. `/api/search`
/// hits carry `ts_micros` (unlike `/api/tail`, which pre-formats `event_ts`).
pub fn ts_iso(micros: i64) -> String {
    let d = js_sys::Date::new(&wasm_bindgen::JsValue::from_f64(micros as f64 / 1000.0));
    let iso = String::from(d.to_iso_string()); // 2026-07-12T08:25:39.244Z
    iso.split('.').next().unwrap_or(&iso).replace('T', " ")
}
/// Epoch-millis → ISO-8601 UTC (`2026-07-23T14:00:00.000Z`) for a SQL timestamp
/// literal. Uses the browser's `Date`, so the wasm bundle needs no date crate.
pub fn iso_ms(ms: i64) -> String {
    let d = js_sys::Date::new(&wasm_bindgen::JsValue::from_f64(ms as f64));
    String::from(d.to_iso_string())
}
/// Parse an `<input type="datetime-local">` value ("2026-07-23T14:00", LOCAL
/// time) to epoch millis, or `None` if empty/invalid.
pub fn parse_local(s: &str) -> Option<i64> {
    if s.trim().is_empty() {
        return None;
    }
    let t = js_sys::Date::new(&wasm_bindgen::JsValue::from_str(s)).get_time();
    (!t.is_nan()).then_some(t as i64)
}
/// Local wall-clock `HH:MM:SS` for "now" — timestamps activity-center entries
/// without a date crate in the wasm bundle.
pub fn now_hms() -> String {
    let d = js_sys::Date::new_0();
    format!(
        "{:02}:{:02}:{:02}",
        d.get_hours(),
        d.get_minutes(),
        d.get_seconds()
    )
}

/// Compact LOCAL-time label for epoch millis (`07-23 14:00`), for the picker chip.
pub fn local_dt(ms: i64) -> String {
    let d = js_sys::Date::new(&wasm_bindgen::JsValue::from_f64(ms as f64));
    format!(
        "{:02}-{:02} {:02}:{:02}",
        d.get_month() + 1,
        d.get_date(),
        d.get_hours(),
        d.get_minutes()
    )
}

/// Strip terminal/control chars from model/log-derived text (defense against
/// spoofing the display; the browser renders text nodes, so this is belt-and-
/// suspenders against control chars leaking into attributes/logs).
pub fn clean(v: &str) -> String {
    v.chars()
        .filter(|c| !c.is_control() || *c == '\n' || *c == '\t')
        .collect()
}

/// Clip long text to `max` chars (appending an ellipsis) for an always-rendered
/// table cell. A single k8s/kubevirt log line can be ~100 KB; rendering the full
/// message across a 300-row feed floods the DOM and hangs the WASM console. The
/// full value stays available in the expanded row detail. Iterates at most
/// `max + 1` chars, so it does not pay an O(n) pass over a huge message.
pub fn clip(v: &str, max: usize) -> String {
    match v.char_indices().nth(max) {
        Some((idx, _)) => {
            let mut t = v[..idx].to_string();
            t.push('…');
            t
        }
        None => v.to_string(),
    }
}