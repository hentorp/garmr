// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! Matrix escalation — the human interface for M1.
//!
//! Posts triaged verdicts to the investigation room, and escalations (high
//! severity or a malicious disposition) also to the alerts room. Talks the
//! Matrix client-server API directly with a `garmr-bot` access token, the same
//! pattern as the existing `@hermes-bot` / `@alert-router-bot`. No SDK.

use garmr_core::{Case, DomainProfileKind, Error, MatrixConfig, Result, Verdict};
use serde_json::json;

pub struct Matrix {
    client: reqwest::Client,
    homeserver: String,
    token: String,
    cfg: MatrixConfig,
}

impl Matrix {
    /// Build from config + a `GARMR_MATRIX_TOKEN` access token. `None` if the
    /// token isn't set, so the pipeline runs headless (degraded mode).
    pub fn from_env(cfg: &MatrixConfig) -> Option<Self> {
        let token = std::env::var("GARMR_MATRIX_TOKEN").ok()?;
        // Egress chokepoint (invariant #1): a denied homeserver → headless (the
        // existing degraded convention). Denial is audited inside check().
        garmr_core::egress::global()
            .check(garmr_core::EgressClass::Notify, &cfg.homeserver)
            .ok()?;
        Some(Self {
            // Bounded so a hung/black-hole homeserver can't stall the (sequential)
            // triage loop indefinitely — the post is awaited inline per case.
            client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                // The homeserver host is egress-checked once above; refuse
                // redirects so a 3xx can't re-send to an un-checked host (#1).
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .unwrap_or_default(),
            homeserver: cfg.homeserver.trim_end_matches('/').to_string(),
            token,
            cfg: cfg.clone(),
        })
    }

    /// Confirm the token works — used by `garmr selftest`.
    pub async fn whoami(&self) -> Result<String> {
        let url = format!("{}/_matrix/client/v3/account/whoami", self.homeserver);
        let v: serde_json::Value = self
            .client
            .get(&url)
            .bearer_auth(&self.token)
            .send()
            .await
            .map_err(|e| Error::Agent(format!("matrix whoami: {e}")))?
            .json()
            .await
            .map_err(|e| Error::Agent(format!("matrix whoami decode: {e}")))?;
        v.get("user_id")
            .and_then(serde_json::Value::as_str)
            .map(str::to_string)
            .ok_or_else(|| Error::Agent(format!("matrix whoami: unexpected response {v}")))
    }

    /// Post a case's verdict: always to #investigation, and to #alerts only
    /// when the agent's single escalation decision (made in `finish`) says so —
    /// this method no longer recomputes it, so the alerts room can never
    /// contradict the case's persisted state.
    pub async fn post_verdict(
        &self,
        case: &Case,
        verdict: &Verdict,
        escalate: bool,
        profile: DomainProfileKind,
    ) -> Result<()> {
        let body = format_verdict(case, verdict, profile);
        self.send(&self.cfg.investigation_room, &body).await?;
        if escalate {
            self.send(&self.cfg.alerts_room, &format!("🚨 ESCALATION\n{body}"))
                .await?;
        }
        Ok(())
    }

    /// Post a plain notice (degraded-mode banners, selftest pings).
    pub async fn notice(&self, room: &str, text: &str) -> Result<()> {
        self.send(room, text).await
    }

    async fn send(&self, room: &str, text: &str) -> Result<()> {
        let room_id = self.resolve_room(room).await?;
        // A fresh UUID per send: a process-static counter reseeds to the same
        // values after a restart, and Synapse treats the reused (token, txnId)
        // as a retransmit — it returns the original event id and creates no
        // message, so a genuine escalation would silently vanish.
        let txn = uuid::Uuid::new_v4();
        let url = format!(
            "{}/_matrix/client/v3/rooms/{}/send/m.room.message/garmr_{}",
            self.homeserver,
            urlencode(&room_id),
            txn
        );
        let body = json!({ "msgtype": "m.text", "body": text });
        // Synapse rate-limits bursts with 429 M_LIMIT_EXCEEDED (retry_after_ms).
        // Honor it and retry the SAME txn (idempotent — Synapse dedups on
        // txnId) so a genuine alert isn't silently dropped under load, instead
        // of returning an error the caller just logs.
        const MAX_ATTEMPTS: u32 = 5;
        for attempt in 1..=MAX_ATTEMPTS {
            let resp = self
                .client
                .put(&url)
                .bearer_auth(&self.token)
                .json(&body)
                .send()
                .await
                .map_err(|e| Error::Agent(format!("matrix send: {e}")))?;
            let s = resp.status();
            if s.is_success() {
                return Ok(());
            }
            let b = resp.text().await.unwrap_or_default();
            if s.as_u16() == 429 && attempt < MAX_ATTEMPTS {
                let wait_ms = serde_json::from_str::<serde_json::Value>(&b)
                    .ok()
                    .and_then(|v| v.get("retry_after_ms").and_then(serde_json::Value::as_u64))
                    .unwrap_or(1000)
                    .min(10_000);
                tokio::time::sleep(std::time::Duration::from_millis(wait_ms + 100)).await;
                continue;
            }
            return Err(Error::Agent(format!("matrix send {s}: {b}")));
        }
        Ok(())
    }

    /// Accept a room id (`!id:server`) directly, or resolve an alias
    /// (`#name:server`).
    async fn resolve_room(&self, room: &str) -> Result<String> {
        if room.starts_with('!') {
            return Ok(room.to_string());
        }
        let url = format!(
            "{}/_matrix/client/v3/directory/room/{}",
            self.homeserver,
            urlencode(room)
        );
        let v: serde_json::Value = self
            .client
            .get(&url)
            .bearer_auth(&self.token)
            .send()
            .await
            .map_err(|e| Error::Agent(format!("matrix resolve {room}: {e}")))?
            .json()
            .await
            .map_err(|e| Error::Agent(format!("matrix resolve decode: {e}")))?;
        v.get("room_id")
            .and_then(serde_json::Value::as_str)
            .map(str::to_string)
            .ok_or_else(|| Error::Agent(format!("matrix resolve {room}: {v}")))
    }
}

pub(crate) fn format_verdict(case: &Case, v: &Verdict, profile: DomainProfileKind) -> String {
    let e = &case.trigger.event;
    let action = v
        .proposed_action
        .as_deref()
        .map(|a| format!("\nProposal: {a}"))
        .unwrap_or_default();
    // Name the actor and the accessed data-subject in the body (leads with its
    // own newline; empty when neither field is present). The LABELS are
    // domain-neutral by default; the register profile opts into its own wording,
    // so the configured DomainProfileKind — not a hardcoded assumption — decides.
    let (actor_label, subject_label) = match profile {
        DomainProfileKind::Register => ("Case officer", "Looked-up person"),
        DomainProfileKind::Generic | DomainProfileKind::Unknown => ("Actor", "Data subject"),
    };
    let audit = match (e.field("db_user"), e.field("target_person")) {
        (Some(u), Some(t)) => format!("\n{actor_label}: {u}  {subject_label}: {t}"),
        (Some(u), None) => format!("\n{actor_label}: {u}"),
        (None, Some(t)) => format!("\n{subject_label}: {t}"),
        (None, None) => String::new(),
    };
    format!(
        "garmr-verdict [{}]\nRule: {} ({})\nHost: {}  Source IP: {}  Events: {}{}\nDisposition: {:?}  Severity: {}/10  Confidence: {:.0}%\n{}{}",
        case.id.get(..8).unwrap_or(&case.id),
        case.trigger.rule_title,
        case.trigger.rule_id,
        e.host,
        e.src_ip().unwrap_or("-"),
        case.event_count,
        audit,
        v.disposition,
        v.severity,
        v.confidence * 100.0,
        v.rationale,
        action,
    )
}

/// Minimal path-segment percent-encoding (room ids/aliases contain `!`, `#`,
/// `:`). Avoids pulling a URL-encoding crate for three characters.
fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 3);
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