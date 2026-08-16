// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! The single air-gap egress chokepoint (invariant #1).
//!
//! Every outbound network client in the daemon is built through
//! [`global`]`().check(class, dest)`. In air-gap mode (`GARMR_AIRGAP`, which
//! OVERRIDES config) all non-local egress is denied fail-closed; a loopback / LAN
//! destination (a local model, a mirror) is still allowed (invariant #6).
//! Otherwise a configured `[route.egress] allow` list governs external hosts (an
//! empty list is allow-all, preserving today's behavior).
//!
//! Pure std, no deps. The decision ([`EgressPolicy::decide`]) is a side-effect-
//! free function; [`EgressPolicy::check`] adds the audit + tracing on a deny and
//! is what callers use. Only the destination HOST (never the raw URL, which can
//! carry a webhook/SMTP token) is ever logged or audited.
//!
//! Scope of the guarantee: this governs garmr's OWN autonomous egress. A
//! human-approved SOAR playbook command (a separate subprocess) and separate
//! operator control-plane processes are outside this in-process policy — see the
//! model-routing doc.

use std::net::IpAddr;
use std::sync::{Arc, OnceLock};

use serde::{Deserialize, Serialize};

/// The kind of egress a site performs — for policy + audit provenance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EgressClass {
    /// An external hosted LLM API (e.g. Anthropic).
    LlmExternal,
    /// A local/LAN OpenAI-compatible model endpoint.
    LlmLocal,
    /// An online threat-intel / IOC feed fetch.
    IocFeed,
    /// An outbound notification (Matrix / webhook / SMTP).
    Notify,
    /// An object store (S3-compatible) for cold storage / HA.
    ObjectStore,
    /// Spawning an external MCP server child process (unconstrainable egress).
    McpRemote,
    /// Telemetry export (reserved — no site yet).
    Telemetry,
    /// A model artifact download (reserved — no site yet).
    ModelDownload,
    /// An update/version check (reserved — no site yet).
    UpdateCheck,
    /// An identity provider: the OIDC discovery, JWKS and token endpoints.
    ///
    /// Its own class because an air-gapped deployment has no external IdP by
    /// definition, and folding this into a general allowance would let an
    /// operator open the SSO path and unrelated egress in one move.
    Idp,
}

impl EgressClass {
    pub fn as_str(self) -> &'static str {
        match self {
            EgressClass::LlmExternal => "llm_external",
            EgressClass::LlmLocal => "llm_local",
            EgressClass::IocFeed => "ioc_feed",
            EgressClass::Notify => "notify",
            EgressClass::ObjectStore => "object_store",
            EgressClass::McpRemote => "mcp_remote",
            EgressClass::Idp => "idp",
            EgressClass::Telemetry => "telemetry",
            EgressClass::ModelDownload => "model_download",
            EgressClass::UpdateCheck => "update_check",
        }
    }
}

/// A denied egress attempt. Carries only the sanitized HOST (never the raw dest),
/// so mapping it into an error message or a log can't leak a token in a URL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EgressDenied {
    pub class: EgressClass,
    pub host: String,
    pub reason: String,
}

impl std::fmt::Display for EgressDenied {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "egress denied [{}] to {}: {}",
            self.class.as_str(),
            self.host,
            self.reason
        )
    }
}

impl std::error::Error for EgressDenied {}

/// A sink for denied-egress audit events (implemented in garmr-cli over the
/// ledger, so garmr-core stays free of the garmr-audit dep).
pub trait EgressAudit: Send + Sync {
    fn on_deny(&self, class: EgressClass, host: &str, reason: &str);
}

/// The pure decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EgressDecision {
    Allow,
    Deny(String),
}

/// The `[route.egress]` config: an allowlist of external hosts (exact or a
/// dotted-suffix parent domain). Empty = allow-all (today's behavior).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EgressConfig {
    #[serde(default)]
    pub allow: Vec<String>,
}

/// The single egress policy.
#[derive(Clone)]
pub struct EgressPolicy {
    airgap: bool,
    allow: Vec<String>,
    audit: Option<Arc<dyn EgressAudit>>,
}

impl std::fmt::Debug for EgressPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EgressPolicy")
            .field("airgap", &self.airgap)
            .field("allow", &self.allow)
            .field("audit", &self.audit.is_some())
            .finish()
    }
}

impl EgressPolicy {
    pub fn new(airgap: bool, cfg: &EgressConfig) -> Self {
        Self {
            airgap,
            allow: cfg.allow.clone(),
            audit: None,
        }
    }

    pub fn with_audit(mut self, audit: Arc<dyn EgressAudit>) -> Self {
        self.audit = Some(audit);
        self
    }

    /// Test ctor: non-airgap, empty allowlist (allow-all).
    pub fn permissive() -> Self {
        Self {
            airgap: false,
            allow: Vec::new(),
            audit: None,
        }
    }

    /// Test ctor: airgap.
    pub fn airgap() -> Self {
        Self {
            airgap: true,
            allow: Vec::new(),
            audit: None,
        }
    }

    pub fn is_airgap(&self) -> bool {
        self.airgap
    }

    fn allow_matches(&self, host: &str) -> bool {
        let hl = host.to_ascii_lowercase();
        self.allow.iter().any(|a| {
            let al = a.trim().to_ascii_lowercase();
            !al.is_empty() && (hl == al || hl.ends_with(&format!(".{al}")))
        })
    }

    /// The pure decision. No side effects. The DECISION is driven by the actual
    /// destination host (a caller cannot bypass by mislabeling the class), except
    /// `McpRemote`, which is categorically non-local (a spawned server is an
    /// unconstrainable egress channel).
    pub fn decide(&self, class: EgressClass, dest: &str) -> EgressDecision {
        if class == EgressClass::McpRemote {
            return if self.airgap {
                EgressDecision::Deny("air-gap: external MCP server spawn forbidden".into())
            } else if !self.allow.is_empty() {
                // A non-empty allowlist is an explicit lockdown posture. A spawned
                // MCP server is an unconstrainable egress channel we cannot
                // host-check, so it fails closed under lockdown — it is allowed
                // only when airgap is off AND no allowlist is configured.
                EgressDecision::Deny(
                    "external MCP server spawn not permitted under an egress allowlist".into(),
                )
            } else {
                EgressDecision::Allow
            };
        }
        // FIX#4: an unparseable destination is NON-local, so it fails closed.
        let local = host_of(dest).map(is_local).unwrap_or(false);
        if local {
            return EgressDecision::Allow; // invariant #6: local egress always allowed
        }
        if self.airgap {
            return EgressDecision::Deny("air-gap: external egress forbidden".into());
        }
        // Non-airgap: an empty allowlist is allow-all (backward-compatible).
        if self.allow.is_empty() {
            return EgressDecision::Allow;
        }
        match host_of(dest) {
            Some(h) if self.allow_matches(h) => EgressDecision::Allow,
            _ => EgressDecision::Deny("host not in the egress allowlist".into()),
        }
    }

    /// Decide + audit/log on a deny. The ONLY thing callers use. Logs/audits the
    /// host only (never the raw dest).
    ///
    /// A deny surfaces two ways: the returned [`EgressDenied`] (the caller logs
    /// it), and the audit sink's `on_deny` when one is installed — both with the
    /// host only, never the raw dest. (garmr-core stays runtime-free — no
    /// `tracing` dep — so the logging lives at the call sites / sink.)
    pub fn check(&self, class: EgressClass, dest: &str) -> Result<(), EgressDenied> {
        match self.decide(class, dest) {
            EgressDecision::Allow => Ok(()),
            EgressDecision::Deny(reason) => {
                let host = host_of(dest).unwrap_or("<unparsed>");
                if let Some(a) = &self.audit {
                    a.on_deny(class, host, &reason);
                }
                Err(EgressDenied {
                    class,
                    host: host.to_string(),
                    reason,
                })
            }
        }
    }
}

/// Parse the ONE `GARMR_AIRGAP` truthy set — the single source of the env parse.
pub fn airgap_from_env() -> bool {
    matches!(
        std::env::var("GARMR_AIRGAP").ok().as_deref(),
        Some("1") | Some("true") | Some("yes") | Some("on")
    )
}

/// Extract the authority HOST from a destination (URL, `host:port`, or bare host
/// for SMTP / an MCP command). Terminates the authority at the first `/?#` — and
/// at `\`, which the WHATWG URL spec treats as `/` for special schemes (http(s)),
/// so `http://evil.com\@127.0.0.1/` connects to `evil.com`, NOT the loopback the
/// userinfo split would otherwise yield: matching reqwest's `url`-crate parser is
/// what keeps this locality check from diverging from where the bytes actually go.
/// Then takes the host AFTER the last `@` (drops userinfo — the SSRF bypass),
/// unwraps `[..]` IPv6, and strips a single `:port` only when the remainder is
/// not a bare IPv6.
pub fn host_of(dest: &str) -> Option<&str> {
    let s = dest.trim();
    if s.is_empty() {
        return None;
    }
    let after_scheme = match s.find("://") {
        Some(i) => &s[i + 3..],
        None => s,
    };
    let authority = after_scheme
        .split(['/', '?', '#', '\\'])
        .next()
        .unwrap_or(after_scheme);
    if authority.is_empty() {
        return None;
    }
    // Host is AFTER the last '@' (drop any user[:pass]@).
    let host_port = authority.rsplit('@').next().unwrap_or(authority);
    if host_port.is_empty() {
        return None;
    }
    // Bracketed IPv6: [addr] or [addr]:port.
    if let Some(rest) = host_port.strip_prefix('[') {
        return match rest.split(']').next() {
            Some(h) if !h.is_empty() => Some(h),
            _ => None,
        };
    }
    // Bare IPv6 (2+ colons, unbracketed): the whole thing is the host.
    if host_port.matches(':').count() >= 2 {
        return Some(host_port);
    }
    // host[:port] — strip a single :port.
    match host_port.split(':').next() {
        Some(h) if !h.is_empty() => Some(h),
        _ => None,
    }
}

fn ip_is_local(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_loopback() || v4.is_private() || v4.is_link_local(),
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return v4.is_loopback() || v4.is_private() || v4.is_link_local();
            }
            // loopback ::1, ULA fc00::/7, link-local fe80::/10.
            v6.is_loopback()
                || (v6.segments()[0] & 0xfe00) == 0xfc00
                || (v6.segments()[0] & 0xffc0) == 0xfe80
        }
    }
}

/// Is `host` local/private (loopback, RFC1918, link-local, localhost)? A non-IP,
/// non-localhost host is NOT local — fail-closed, and NO DNS is performed.
pub fn is_local(host: &str) -> bool {
    let h = host.trim();
    if h.is_empty() {
        return false;
    }
    let hl = h.to_ascii_lowercase();
    // FIX#2: dotted boundary — "evillocalhost" must NOT read as local.
    if hl == "localhost" || hl.ends_with(".localhost") {
        return true;
    }
    match h.parse::<IpAddr>() {
        Ok(ip) => ip_is_local(ip),
        Err(_) => false,
    }
}

// ---- the process-wide singleton --------------------------------------------

static POLICY: OnceLock<EgressPolicy> = OnceLock::new();

/// Install the ONE policy (call once, early — in `load_config`). Idempotent.
pub fn init(policy: EgressPolicy) {
    let _ = POLICY.set(policy);
}

/// The installed policy. If `init` has not run, returns a SEPARATE lazily-built
/// airgap-honoring default (from `GARMR_AIRGAP`), so air-gap is fail-closed even
/// on a path that skipped init — WITHOUT ever occupying `POLICY`, so a later
/// `init` always wins (FIX#1).
pub fn global() -> &'static EgressPolicy {
    POLICY.get().unwrap_or_else(|| {
        static FALLBACK: OnceLock<EgressPolicy> = OnceLock::new();
        FALLBACK.get_or_init(|| EgressPolicy::new(airgap_from_env(), &EgressConfig::default()))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_of_drops_userinfo_and_port_and_path() {
        // FIX#3: the host is AFTER the last '@' — the SSRF bypass.
        assert_eq!(
            host_of("http://api.anthropic.com@evil.com/v1"),
            Some("evil.com")
        );
        assert_eq!(
            host_of("https://hooks.slack.com/services/T/B/xxx"),
            Some("hooks.slack.com")
        );
        assert_eq!(host_of("smtp.gmail.com:587"), Some("smtp.gmail.com"));
        assert_eq!(
            host_of("http://user:pass@host.example:8080/x"),
            Some("host.example")
        );
        assert_eq!(host_of("http://[::1]:11434/v1"), Some("::1"));
        assert_eq!(host_of("fe80::1"), Some("fe80::1")); // bare IPv6, not split
        assert_eq!(host_of("localhost:11434"), Some("localhost"));
        assert_eq!(host_of(""), None);
        // Backslash terminates the authority (WHATWG special-scheme behaviour, as
        // reqwest's `url` parser does): the bytes go to `evil.com`, so locality
        // must too — never the loopback the userinfo split would otherwise yield.
        assert_eq!(host_of("http://evil.com\\@127.0.0.1/x"), Some("evil.com"));
        assert_eq!(host_of("http://127.0.0.1\\@evil.com/x"), Some("127.0.0.1"));
    }

    #[test]
    fn backslash_host_is_not_misread_as_local() {
        // The divergence bug: `\@` made `host_of` return 127.0.0.1 (local →
        // allowed, confidential data permitted) while reqwest connects to
        // evil.com. With the fix the external host is seen and denied under airgap.
        let p = EgressPolicy::airgap();
        assert!(matches!(
            p.decide(EgressClass::LlmExternal, "http://evil.com\\@127.0.0.1/v1"),
            EgressDecision::Deny(_)
        ));
    }

    #[test]
    fn mcp_remote_fails_closed_under_an_allowlist() {
        // A configured allowlist is a lockdown posture: an unconstrainable spawned
        // server is refused even off-airgap (an empty allowlist stays allow-all).
        let cfg = EgressConfig {
            allow: vec!["anthropic.com".into()],
        };
        let p = EgressPolicy::new(false, &cfg);
        assert!(matches!(
            p.decide(EgressClass::McpRemote, "npx some-server"),
            EgressDecision::Deny(_)
        ));
        assert_eq!(
            EgressPolicy::permissive().decide(EgressClass::McpRemote, "npx some-server"),
            EgressDecision::Allow
        );
    }

    #[test]
    fn is_local_uses_a_dotted_localhost_boundary() {
        // FIX#2.
        assert!(is_local("localhost"));
        assert!(is_local("db.localhost"));
        assert!(!is_local("evillocalhost"));
        assert!(!is_local("myhost.notlocalhost"));
        assert!(!is_local("localhost.evil.com"));
    }

    #[test]
    fn is_local_ip_ranges() {
        assert!(is_local("127.0.0.1"));
        assert!(is_local("10.1.2.3"));
        assert!(is_local("192.168.0.9"));
        assert!(is_local("172.16.5.5"));
        assert!(is_local("169.254.1.1"));
        assert!(is_local("::1"));
        assert!(is_local("fe80::1"));
        assert!(is_local("fc00::1"));
        assert!(is_local("::ffff:127.0.0.1")); // IPv4-mapped
        assert!(!is_local("8.8.8.8"));
        assert!(!is_local("api.anthropic.com"));
        assert!(!is_local("::ffff:8.8.8.8"));
    }

    #[test]
    fn airgap_denies_external_allows_local() {
        let p = EgressPolicy::airgap();
        assert_eq!(
            p.decide(EgressClass::LlmExternal, "https://api.anthropic.com/v1"),
            EgressDecision::Deny("air-gap: external egress forbidden".into())
        );
        assert_eq!(
            p.decide(EgressClass::LlmLocal, "http://127.0.0.1:11434/v1"),
            EgressDecision::Allow
        );
        // local by host even if class says external (no mislabel bypass).
        assert_eq!(
            p.decide(EgressClass::LlmExternal, "http://localhost:11434/v1"),
            EgressDecision::Allow
        );
    }

    #[test]
    fn airgap_denies_all_external_mcp_and_an_unparseable_dest() {
        let p = EgressPolicy::airgap();
        assert!(matches!(
            p.decide(EgressClass::McpRemote, "npx some-server"),
            EgressDecision::Deny(_)
        ));
        // FIX#4: unparseable → non-local → denied under airgap.
        assert!(matches!(
            p.decide(EgressClass::Notify, ""),
            EgressDecision::Deny(_)
        ));
    }

    #[test]
    fn allowlist_uses_dotted_suffix_and_env_wins() {
        let cfg = EgressConfig {
            allow: vec!["anthropic.com".into()],
        };
        let p = EgressPolicy::new(false, &cfg);
        assert_eq!(
            p.decide(EgressClass::LlmExternal, "https://api.anthropic.com/v1"),
            EgressDecision::Allow
        );
        assert!(matches!(
            p.decide(EgressClass::LlmExternal, "https://evilanthropic.com/v1"),
            EgressDecision::Deny(_)
        ));
        // Airgap overrides a non-empty allowlist (env wins, allowlist can't re-open).
        let ap = EgressPolicy::new(true, &cfg);
        assert!(matches!(
            ap.decide(EgressClass::LlmExternal, "https://api.anthropic.com/v1"),
            EgressDecision::Deny(_)
        ));
    }

    #[test]
    fn non_airgap_empty_allowlist_is_allow_all() {
        let p = EgressPolicy::permissive();
        assert_eq!(
            p.decide(EgressClass::Notify, "https://hooks.slack.com/x"),
            EgressDecision::Allow
        );
        assert_eq!(
            p.decide(EgressClass::McpRemote, "npx server"),
            EgressDecision::Allow
        );
    }
}
