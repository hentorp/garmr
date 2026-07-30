// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! Bounded, jittered retry + timeouts for the LLM HTTP round-trip.
//!
//! The two providers (`anthropic`, `openai_compat`) previously built a
//! `reqwest::Client` with only a redirect policy — no connect timeout, no
//! request timeout, no retry — so a hung provider socket blocked triage/hunt
//! indefinitely and a transient 429/5xx was terminal. Every *other* reqwest
//! client in the workspace already sets timeouts; this brings the LLM path in
//! line and adds a small, safe retry.
//!
//! Only **safe transient** failures retry: a connect error, a timeout, or an
//! HTTP 429/5xx. Auth failures (401/403), other 4xx, egress denials, and decode
//! errors are terminal — retrying them is pointless or unsafe (invariant: no
//! silent re-POST to an unchecked host is possible either way, because redirects
//! are refused).

use std::time::Duration;

use garmr_core::{Error, Result};

/// HTTP client tuning for an LLM provider, derived from [`garmr_core::AgentConfig`].
#[derive(Clone, Copy, Debug)]
pub struct LlmHttpConfig {
    pub connect_timeout: Duration,
    pub request_timeout: Duration,
    pub max_retries: u32,
}

impl Default for LlmHttpConfig {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(10),
            request_timeout: Duration::from_secs(120),
            max_retries: 2,
        }
    }
}

impl LlmHttpConfig {
    /// Read the tunables from the environment
    /// (`GARMR_LLM_CONNECT_TIMEOUT_SECS`, `GARMR_LLM_REQUEST_TIMEOUT_SECS`,
    /// `GARMR_LLM_MAX_RETRIES`), falling back to the defaults. Env-driven (not a
    /// config-struct field) so it needs no change to the widely-constructed
    /// `AgentConfig`.
    pub fn from_env() -> Self {
        let c = std::env::var("GARMR_LLM_CONNECT_TIMEOUT_SECS").ok();
        let r = std::env::var("GARMR_LLM_REQUEST_TIMEOUT_SECS").ok();
        let n = std::env::var("GARMR_LLM_MAX_RETRIES").ok();
        Self::resolve(c.as_deref(), r.as_deref(), n.as_deref())
    }

    /// Pure parse + clamp (a zero timeout would mean "no timeout" in reqwest —
    /// the opposite of intent, so clamp to ≥1; retries capped at ≤10).
    fn resolve(connect: Option<&str>, request: Option<&str>, retries: Option<&str>) -> Self {
        let secs = |v: Option<&str>, d: u64| v.and_then(|s| s.parse().ok()).unwrap_or(d).max(1);
        Self {
            connect_timeout: Duration::from_secs(secs(connect, 10)),
            request_timeout: Duration::from_secs(secs(request, 120)),
            max_retries: retries.and_then(|s| s.parse().ok()).unwrap_or(2u32).min(10),
        }
    }

    /// Build the shared provider client: refuse redirects (a 3xx must not re-POST
    /// a possibly-confidential prompt to an un-egress-checked host) AND bound
    /// connect + total request time.
    pub(crate) fn client(&self) -> reqwest::Client {
        reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(self.connect_timeout)
            .timeout(self.request_timeout)
            .build()
            .unwrap_or_default()
    }
}

/// Retry only HTTP 429 (rate limit) and 5xx (server) — a 4xx is the caller's
/// fault and will fail identically on retry.
pub(crate) fn retryable_status(status: u16) -> bool {
    status == 429 || (500..=599).contains(&status)
}

/// The pure retry decision, unit-tested exhaustively: retry iff the failure is
/// transient AND we have attempts left.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Retry {
    Now,
    Stop,
}

pub(crate) fn should_retry(attempt: u32, max_retries: u32, transient: bool) -> Retry {
    if transient && attempt < max_retries {
        Retry::Now
    } else {
        Retry::Stop
    }
}

/// Jittered exponential backoff, capped. Pure so the schedule is testable;
/// `jitter_ms` is supplied by the caller (wall-clock nanos in production).
pub(crate) fn backoff(attempt: u32, jitter_ms: u64) -> Duration {
    const BASE_MS: u64 = 250;
    const CAP_MS: u64 = 8_000;
    // 250, 500, 1000, 2000, 4000, then capped at 8000.
    let exp = BASE_MS.saturating_mul(1u64 << attempt.min(5));
    Duration::from_millis(exp.min(CAP_MS) + (jitter_ms % BASE_MS))
}

fn jitter_ms() -> u64 {
    // Cheap, non-crypto jitter from the wall clock — retry spacing needs no rng
    // dependency. Falls back to 0 if the clock is before the epoch.
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos() as u64)
        .unwrap_or(0)
}

/// Send a request with bounded retry. The request is built once and cloned per
/// attempt (`try_clone` succeeds for our JSON bodies), so each retry re-sends the
/// identical, already-egress-checked request. Returns the response for the caller
/// to decode; a non-retryable status (2xx or 4xx) is returned as-is.
pub(crate) async fn send_with_retry(
    req: reqwest::RequestBuilder,
    max_retries: u32,
    label: &str,
) -> Result<reqwest::Response> {
    let mut attempt = 0u32;
    loop {
        let this = req
            .try_clone()
            .ok_or_else(|| Error::Llm(format!("{label} request: not retry-cloneable")))?;
        match this.send().await {
            Ok(resp) => {
                let transient = retryable_status(resp.status().as_u16());
                if should_retry(attempt, max_retries, transient) == Retry::Now {
                    tokio::time::sleep(backoff(attempt, jitter_ms())).await;
                    attempt += 1;
                    continue;
                }
                return Ok(resp);
            }
            Err(e) => {
                let transient = e.is_timeout() || e.is_connect();
                if should_retry(attempt, max_retries, transient) == Retry::Now {
                    tokio::time::sleep(backoff(attempt, jitter_ms())).await;
                    attempt += 1;
                    continue;
                }
                return Err(Error::Llm(format!("{label} request: {e}")));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_429_and_5xx_are_retryable() {
        for s in [429u16, 500, 502, 503, 599] {
            assert!(retryable_status(s), "{s} should retry");
        }
        for s in [200u16, 201, 400, 401, 403, 404, 409, 422] {
            assert!(!retryable_status(s), "{s} should NOT retry");
        }
    }

    #[test]
    fn transient_retries_until_budget_exhausted() {
        // attempts 0 and 1 retry, attempt 2 (== max) stops.
        assert_eq!(should_retry(0, 2, true), Retry::Now);
        assert_eq!(should_retry(1, 2, true), Retry::Now);
        assert_eq!(should_retry(2, 2, true), Retry::Stop);
    }

    #[test]
    fn terminal_never_retries_even_with_budget() {
        assert_eq!(should_retry(0, 5, false), Retry::Stop);
    }

    #[test]
    fn zero_max_retries_disables_retry() {
        assert_eq!(should_retry(0, 0, true), Retry::Stop);
    }

    #[test]
    fn backoff_is_monotonic_capped_and_jitter_bounded() {
        // Monotonic up to the cap, then flat at CAP + jitter (jitter < BASE_MS).
        let d0 = backoff(0, 0).as_millis();
        let d1 = backoff(1, 0).as_millis();
        let d5 = backoff(5, 0).as_millis();
        let d9 = backoff(9, 0).as_millis();
        assert_eq!(d0, 250);
        assert_eq!(d1, 500);
        assert_eq!(d5, 8_000);
        assert_eq!(d9, 8_000, "capped");
        // Jitter only ever adds < BASE_MS (250).
        assert!(backoff(0, 249).as_millis() < 500);
        assert!(
            backoff(0, 100_000).as_millis() < 500,
            "jitter is modulo-bounded"
        );
    }

    #[test]
    fn resolve_clamps_bounds_and_defaults() {
        let h = LlmHttpConfig::resolve(Some("0"), Some("0"), Some("99"));
        assert_eq!(h.connect_timeout, Duration::from_secs(1), "0 clamps to >=1");
        assert_eq!(h.request_timeout, Duration::from_secs(1));
        assert_eq!(h.max_retries, 10, "clamped to <=10");
        // Unset / unparseable → the defaults.
        let d = LlmHttpConfig::resolve(None, Some("junk"), None);
        assert_eq!(d.connect_timeout, Duration::from_secs(10));
        assert_eq!(d.request_timeout, Duration::from_secs(120));
        assert_eq!(d.max_retries, 2);
    }

    #[test]
    fn defaults_are_sane() {
        let h = LlmHttpConfig::default();
        assert_eq!(h.connect_timeout, Duration::from_secs(10));
        assert_eq!(h.request_timeout, Duration::from_secs(120));
        assert_eq!(h.max_retries, 2);
    }
}
