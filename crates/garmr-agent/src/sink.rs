// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! Multi-channel alert delivery. The daemon posts a case's verdict to every
//! configured channel: Matrix (rooms), a generic outbound webhook (Slack /
//! Teams / Discord-slack / PagerDuty / ntfy / anything that accepts a JSON POST),
//! and SMTP email. The per-rule throttle + human silences (garmr-route) gate the
//! whole fan-out uniformly at the call site; a channel opens the throttle window
//! only when at least one sink actually delivered.
//!
//! Endpoints + credentials come from the environment (never the toml), matching
//! the `GARMR_MATRIX_TOKEN` convention:
//!   GARMR_WEBHOOK_URL         — enable the webhook sink (the URL is a secret).
//!   GARMR_WEBHOOK_ALL         — if set, webhook fires on every verdict, not just escalations.
//!   GARMR_SMTP_HOST/PORT      — enable the email sink (host required).
//!   GARMR_SMTP_FROM / _TO     — sender + comma-separated recipients (both required).
//!   GARMR_SMTP_USER / _PASSWORD — optional SMTP auth.
//!   GARMR_SMTP_STARTTLS       — set for STARTTLS (587); default is implicit TLS (465).
//!   GARMR_SMTP_ALL            — if set, email fires on every verdict, not just escalations.

use std::sync::Arc;

use async_trait::async_trait;
use garmr_core::{Case, Error, Result, Verdict};
use serde_json::json;

use crate::notify::{format_verdict, Matrix};

/// A rendered, channel-agnostic alert built from a case verdict.
pub struct Notification {
    pub subject: String,
    pub body: String,
    pub escalate: bool,
    pub severity: u8,
    pub disposition: String,
    pub case_id: String,
    pub rule: String,
    pub host: String,
    pub src_ip: Option<String>,
    /// The acting register case officer (Postgres access-audit cases only), so a
    /// downstream receiver reads "case officer X looked up person Y" without
    /// parsing the body.
    pub db_user: Option<String>,
    /// The person whose record was looked up (Postgres access-audit cases only).
    pub target_person: Option<String>,
}

/// Build the channel-agnostic notification for a verdict. The body reuses the
/// same text Matrix posts, so every channel is consistent.
pub fn render(
    case: &Case,
    verdict: &Verdict,
    escalate: bool,
    profile: garmr_core::DomainProfileKind,
) -> Notification {
    Notification {
        subject: format!(
            "garmr {}[{:?}] {} on {}",
            if escalate {
                "\u{1F6A8} ESCALATION "
            } else {
                ""
            },
            verdict.disposition,
            case.trigger.rule_id,
            case.trigger.event.host,
        ),
        body: format_verdict(case, verdict, profile),
        escalate,
        severity: verdict.severity,
        disposition: format!("{:?}", verdict.disposition),
        case_id: case.id.clone(),
        rule: case.trigger.rule_id.clone(),
        host: case.trigger.event.host.to_string(),
        src_ip: case.trigger.event.src_ip().map(str::to_string),
        db_user: case.trigger.event.field("db_user").map(str::to_string),
        target_person: case
            .trigger
            .event
            .field("target_person")
            .map(str::to_string),
    }
}

/// One delivery channel.
#[async_trait]
pub trait AlertSink: Send + Sync {
    fn name(&self) -> &'static str;
    /// When true, this sink only fires for escalations (the "page me" channel).
    fn escalations_only(&self) -> bool;
    async fn deliver(&self, n: &Notification) -> Result<()>;
}

/// Generic outbound webhook: POSTs a JSON body carrying a Slack-compatible
/// `text` field plus garmr's structured fields, so it works with Slack, Teams,
/// Discord (slack-compat), PagerDuty Events, ntfy, or a bespoke receiver.
pub struct WebhookSink {
    client: reqwest::Client,
    url: String,
    escalations_only: bool,
}

impl WebhookSink {
    pub fn from_env() -> Option<Self> {
        let url = std::env::var("GARMR_WEBHOOK_URL")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())?;
        // Egress chokepoint: a denied webhook host → disabled. Only the host is
        // audited (the URL path can carry a Slack/Discord token).
        garmr_core::egress::global()
            .check(garmr_core::EgressClass::Notify, &url)
            .ok()?;
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(15))
            // The host is egress-checked once above; refuse redirects so a 3xx
            // can't re-POST the verdict payload to an un-checked host (invariant #1).
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .ok()?;
        Some(Self {
            client,
            url,
            escalations_only: std::env::var_os("GARMR_WEBHOOK_ALL").is_none(),
        })
    }
}

#[async_trait]
impl AlertSink for WebhookSink {
    fn name(&self) -> &'static str {
        "webhook"
    }
    fn escalations_only(&self) -> bool {
        self.escalations_only
    }
    async fn deliver(&self, n: &Notification) -> Result<()> {
        let payload = json!({
            "text": format!("{}\n{}", n.subject, n.body),
            "subject": n.subject,
            "escalate": n.escalate,
            "severity": n.severity,
            "disposition": n.disposition,
            "case_id": n.case_id,
            "rule": n.rule,
            "host": n.host,
            "src_ip": n.src_ip,
            "db_user": n.db_user,
            "target_person": n.target_person,
        });
        let resp = self
            .client
            .post(&self.url)
            .json(&payload)
            .send()
            // `without_url` strips the URL: reqwest attaches it to transport
            // errors (timeout/DNS/reset) and Display prints it — and the webhook
            // URL is a secret (Slack/Discord embed a token in the path).
            .await
            .map_err(|e| Error::Agent(format!("webhook post: {}", e.without_url())))?;
        if !resp.status().is_success() {
            let s = resp.status();
            let b = resp.text().await.unwrap_or_default();
            let snippet: String = b.chars().take(200).collect();
            return Err(Error::Agent(format!("webhook post {s}: {snippet}")));
        }
        Ok(())
    }
}

/// SMTP email sink (lettre, async tokio + rustls).
pub struct EmailSink {
    transport: lettre::AsyncSmtpTransport<lettre::Tokio1Executor>,
    from: lettre::message::Mailbox,
    to: Vec<lettre::message::Mailbox>,
    escalations_only: bool,
}

impl EmailSink {
    pub fn from_env() -> Option<Self> {
        use lettre::transport::smtp::authentication::Credentials;
        use lettre::AsyncSmtpTransport;

        let host = std::env::var("GARMR_SMTP_HOST")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())?;
        // Egress chokepoint: a denied SMTP relay → email disabled, checked BEFORE
        // building the lettre transport.
        garmr_core::egress::global()
            .check(garmr_core::EgressClass::Notify, &host)
            .ok()?;
        let from_raw = std::env::var("GARMR_SMTP_FROM").ok()?;
        let to_raw = std::env::var("GARMR_SMTP_TO").ok()?;
        let from: lettre::message::Mailbox = from_raw.trim().parse().ok()?;
        let wanted: Vec<&str> = to_raw
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .collect();
        let to: Vec<lettre::message::Mailbox> =
            wanted.iter().filter_map(|s| s.parse().ok()).collect();
        if to.is_empty() {
            return None;
        }
        if to.len() < wanted.len() {
            tracing::warn!(
                parsed = to.len(),
                given = wanted.len(),
                "email sink: some GARMR_SMTP_TO recipients were unparseable and dropped"
            );
        }

        let port: u16 = std::env::var("GARMR_SMTP_PORT")
            .ok()
            .and_then(|p| p.parse().ok())
            .unwrap_or(465);
        let starttls = std::env::var_os("GARMR_SMTP_STARTTLS").is_some();
        // STARTTLS (typically 587) vs implicit TLS (465). Both use rustls.
        let mut builder = if starttls {
            AsyncSmtpTransport::<lettre::Tokio1Executor>::starttls_relay(&host).ok()?
        } else {
            AsyncSmtpTransport::<lettre::Tokio1Executor>::relay(&host).ok()?
        }
        .port(port)
        // A down/black-hole relay would otherwise stall the sequential triage
        // loop for lettre's 60s default per case; cap it lower.
        .timeout(Some(std::time::Duration::from_secs(15)));
        if let (Ok(user), Ok(pass)) = (
            std::env::var("GARMR_SMTP_USER"),
            std::env::var("GARMR_SMTP_PASSWORD"),
        ) {
            builder = builder.credentials(Credentials::new(user, pass));
        }
        Some(Self {
            transport: builder.build(),
            from,
            to,
            escalations_only: std::env::var_os("GARMR_SMTP_ALL").is_none(),
        })
    }
}

#[async_trait]
impl AlertSink for EmailSink {
    fn name(&self) -> &'static str {
        "email"
    }
    fn escalations_only(&self) -> bool {
        self.escalations_only
    }
    async fn deliver(&self, n: &Notification) -> Result<()> {
        use lettre::{AsyncTransport, Message};
        let mut builder = Message::builder()
            .from(self.from.clone())
            .subject(&n.subject);
        for rcpt in &self.to {
            builder = builder.to(rcpt.clone());
        }
        let msg = builder
            .body(n.body.clone())
            .map_err(|e| Error::Agent(format!("email build: {e}")))?;
        self.transport
            .send(msg)
            .await
            .map_err(|e| Error::Agent(format!("email send: {e}")))?;
        Ok(())
    }
}

/// Fans a verdict out to every configured channel (Matrix + extra sinks).
pub struct Notifier {
    matrix: Option<Arc<Matrix>>,
    sinks: Vec<Arc<dyn AlertSink>>,
    /// Domain profile deciding the actor/subject wording in the alert body.
    profile: garmr_core::DomainProfileKind,
}

impl Notifier {
    pub fn new(
        matrix: Option<Arc<Matrix>>,
        sinks: Vec<Arc<dyn AlertSink>>,
        profile: garmr_core::DomainProfileKind,
    ) -> Self {
        Self {
            matrix,
            sinks,
            profile,
        }
    }

    /// A notifier with no channels — a no-op (used in tests / headless).
    pub fn disabled() -> Self {
        Self {
            matrix: None,
            sinks: Vec::new(),
            profile: garmr_core::DomainProfileKind::default(),
        }
    }

    /// Build the standard set of sinks from the environment (webhook + email),
    /// logging which ones activated.
    pub fn sinks_from_env() -> Vec<Arc<dyn AlertSink>> {
        let mut sinks: Vec<Arc<dyn AlertSink>> = Vec::new();
        if let Some(w) = WebhookSink::from_env() {
            tracing::info!(
                escalations_only = w.escalations_only,
                "webhook alert sink enabled (GARMR_WEBHOOK_URL)"
            );
            sinks.push(Arc::new(w));
        }
        if let Some(e) = EmailSink::from_env() {
            tracing::info!(
                escalations_only = e.escalations_only,
                "email alert sink enabled (GARMR_SMTP_*)"
            );
            sinks.push(Arc::new(e));
        }
        sinks
    }

    /// No channels configured — the caller can skip the routing gate entirely.
    pub fn is_empty(&self) -> bool {
        self.matrix.is_none() && self.sinks.is_empty()
    }

    /// Deliver a verdict to every channel. Returns true if AT LEAST ONE channel
    /// accepted the message, so the caller opens the throttle window only on a
    /// real delivery. Per-channel failures are logged, never fatal, and never
    /// block the other channels. A sink whose `escalations_only` is set is
    /// skipped for a non-escalation (not a failure).
    pub async fn deliver_verdict(&self, case: &Case, verdict: &Verdict, escalate: bool) -> bool {
        let n = render(case, verdict, escalate, self.profile);
        let mut delivered = false;
        if let Some(m) = &self.matrix {
            match m.post_verdict(case, verdict, escalate, self.profile).await {
                Ok(()) => delivered = true,
                Err(e) => tracing::warn!(case = %case.id, error = %e, "matrix post failed"),
            }
        }
        for sink in &self.sinks {
            if sink.escalations_only() && !n.escalate {
                continue;
            }
            match sink.deliver(&n).await {
                Ok(()) => delivered = true,
                Err(e) => {
                    tracing::warn!(case = %case.id, sink = sink.name(), error = %e, "alert sink delivery failed")
                }
            }
        }
        delivered
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use garmr_core::{Case, Detection, Disposition, Event, Verdict};
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[derive(Default)]
    struct RecordingSink {
        escalations_only: bool,
        fail: bool,
        calls: AtomicUsize,
    }
    #[async_trait]
    impl AlertSink for RecordingSink {
        fn name(&self) -> &'static str {
            "recording"
        }
        fn escalations_only(&self) -> bool {
            self.escalations_only
        }
        async fn deliver(&self, _n: &Notification) -> Result<()> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if self.fail {
                Err(Error::Agent("boom".into()))
            } else {
                Ok(())
            }
        }
    }

    fn case_and_verdict(sev: u8) -> (Case, Verdict) {
        let case = Case::open(Detection {
            rule_id: "r".into(),
            rule_title: "t".into(),
            level: "high".into(),
            attack: vec![],
            event: Event {
                ts: chrono::Utc::now(),
                host: "pve".into(),
                service: "sshd".into(),
                source: "journald".into(),
                environment: "test".into(),
                severity: "warning".into(),
                log_type: "system".into(),
                message: "m".into(),
                fields: Default::default(),
            },
            observed_at: chrono::Utc::now(),
            realert_secs: None,
        });
        let verdict = Verdict {
            disposition: Disposition::Suspicious,
            severity: sev,
            confidence: 0.8,
            rationale: "r".into(),
            proposed_action: None,
        };
        (case, verdict)
    }

    async fn deliver_with(sink: Arc<RecordingSink>, escalate: bool) -> (bool, usize) {
        let n = Notifier::new(
            None,
            vec![sink.clone()],
            garmr_core::DomainProfileKind::default(),
        );
        let (c, v) = case_and_verdict(5);
        let delivered = n.deliver_verdict(&c, &v, escalate).await;
        (delivered, sink.calls.load(Ordering::SeqCst))
    }

    #[test]
    fn verdict_body_labels_follow_the_domain_profile() {
        use garmr_core::DomainProfileKind;
        let (mut case, verdict) = case_and_verdict(5);
        case.trigger
            .event
            .fields
            .insert("db_user".into(), "alice".into());
        case.trigger
            .event
            .fields
            .insert("target_person".into(), "bob".into());
        // Default (Generic) uses domain-neutral labels; the register profile opts
        // into its own wording. The register terms must NOT leak under Generic.
        let generic = crate::notify::format_verdict(&case, &verdict, DomainProfileKind::Generic);
        assert!(generic.contains("Actor: alice"));
        assert!(generic.contains("Data subject: bob"));
        assert!(!generic.contains("Case officer"));
        let register = crate::notify::format_verdict(&case, &verdict, DomainProfileKind::Register);
        assert!(register.contains("Case officer: alice"));
        assert!(register.contains("Looked-up person: bob"));
    }

    #[tokio::test]
    async fn escalations_only_sink_skips_non_escalation_but_fires_on_escalation() {
        let s = Arc::new(RecordingSink {
            escalations_only: true,
            ..Default::default()
        });
        // non-escalation → skipped (not called), nothing delivered
        assert_eq!(deliver_with(s.clone(), false).await, (false, 0));
        // escalation → fires, delivered
        assert_eq!(deliver_with(s, true).await, (true, 1));
    }

    #[tokio::test]
    async fn all_channel_sink_fires_on_every_verdict() {
        let s = Arc::new(RecordingSink {
            escalations_only: false,
            ..Default::default()
        });
        assert_eq!(deliver_with(s, false).await, (true, 1));
    }

    #[tokio::test]
    async fn failed_delivery_is_not_counted_as_delivered() {
        let s = Arc::new(RecordingSink {
            escalations_only: false,
            fail: true,
            ..Default::default()
        });
        // called once, but delivered=false → caller must NOT open the throttle window
        assert_eq!(deliver_with(s, true).await, (false, 1));
    }

    #[tokio::test]
    async fn disabled_notifier_is_empty_and_delivers_nothing() {
        let n = Notifier::disabled();
        assert!(n.is_empty());
        let (c, v) = case_and_verdict(9);
        assert!(!n.deliver_verdict(&c, &v, true).await);
    }
}
