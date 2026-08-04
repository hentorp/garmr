// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! `garmr-detect` — Sigma detection over the normalised event stream.
//!
//! Rules are loaded from a directory of Sigma YAML files via `rsigma-parser`
//! and evaluated per event with `rsigma-eval`. A match becomes a
//! [`Detection`]; the pipeline collapses a burst of the same detection (same
//! rule + host + IP) into one case using the store's suppression window.

mod mapping;

use std::path::Path;

use chrono::Utc;
use garmr_core::{Detection, Error, Event, Result};
use rsigma_eval::{Engine, JsonEvent};
use rsigma_parser::parse_sigma_directory;

/// A loaded Sigma rule set ready to evaluate events.
pub struct Detector {
    engine: Engine,
    rule_count: usize,
}

impl Detector {
    /// Load every Sigma rule under `dir`.
    pub fn load(dir: &Path) -> Result<Self> {
        let collection = parse_sigma_directory(dir)
            .map_err(|e| Error::Detect(format!("parsing rules in {}: {e}", dir.display())))?;
        let mut engine = Engine::new();
        engine
            .add_collection(&collection)
            .map_err(|e| Error::Detect(format!("loading rules: {e}")))?;
        let rule_count = engine.rule_count();
        tracing::info!(dir = %dir.display(), rules = rule_count, "sigma rules loaded");
        Ok(Self { engine, rule_count })
    }

    /// Build a detector from YAML text (tests / embedded defaults).
    pub fn from_yaml(yaml: &str) -> Result<Self> {
        let collection = rsigma_parser::parse_sigma_yaml(yaml)
            .map_err(|e| Error::Detect(format!("parsing rules: {e}")))?;
        let mut engine = Engine::new();
        engine
            .add_collection(&collection)
            .map_err(|e| Error::Detect(format!("loading rules: {e}")))?;
        let rule_count = engine.rule_count();
        Ok(Self { engine, rule_count })
    }

    /// Number of loaded rules.
    pub fn rule_count(&self) -> usize {
        self.rule_count
    }
}

/// A Sigma rule's identity + normalized ATT&CK tags, for coverage reporting.
#[derive(Clone, Debug)]
pub struct RuleMeta {
    pub id: String,
    pub title: String,
    pub level: String,
    /// ATT&CK technique ids, e.g. `T1110`, `T1078.004`.
    pub techniques: Vec<String>,
    /// ATT&CK tactic names (hyphenated), e.g. `credential-access`.
    pub tactics: Vec<String>,
}

/// Parse the Sigma rules under `dir` for coverage reporting — per-rule id/title/
/// level plus normalized ATT&CK techniques/tactics from each rule's `tags:`.
/// Best-effort inventory: a per-document parse error skips that document rather
/// than failing the whole call.
pub fn rule_metas(dir: &Path) -> Result<Vec<RuleMeta>> {
    let collection = parse_sigma_directory(dir)
        .map_err(|e| Error::Detect(format!("parsing rules in {}: {e}", dir.display())))?;
    Ok(collection
        .rules
        .iter()
        .map(|r| {
            let (techniques, tactics) = split_attack_tags(&r.tags);
            RuleMeta {
                id: r.id.clone().unwrap_or_else(|| r.title.clone()),
                title: r.title.clone(),
                level: r
                    .level
                    .map(|l| format!("{l:?}").to_lowercase())
                    .unwrap_or_else(|| "medium".into()),
                techniques,
                tactics,
            }
        })
        .collect())
}

/// Split Sigma `attack.*` tags into (technique ids, tactic names). `attack.t1110`
/// → technique `T1110`; `attack.t1110.001` → `T1110.001`; `attack.credential_access`
/// → tactic `credential-access`. Non-`attack.` and group/software tags are ignored
/// for tactics only when they aren't a technique. Deduped + sorted.
pub fn split_attack_tags(tags: &[String]) -> (Vec<String>, Vec<String>) {
    let mut techniques = Vec::new();
    let mut tactics = Vec::new();
    for tag in tags {
        let tag = tag.to_ascii_lowercase();
        let Some(rest) = tag.strip_prefix("attack.") else {
            continue;
        };
        match rest.strip_prefix('t') {
            // technique: `t` followed by a digit (T1110 / T1110.001)
            Some(num) if num.starts_with(|c: char| c.is_ascii_digit()) => {
                techniques.push(format!("T{num}"));
            }
            _ => tactics.push(rest.replace('_', "-")),
        }
    }
    techniques.sort();
    techniques.dedup();
    tactics.sort();
    tactics.dedup();
    (techniques, tactics)
}

impl Detector {
    /// Evaluate one event, returning a [`Detection`] per fired rule.
    pub fn evaluate(&self, event: &Event) -> Vec<Detection> {
        let json = mapping::event_to_json(event);
        let je = JsonEvent::borrow(&json);
        let observed_at = Utc::now();
        self.engine
            .evaluate(&je)
            .into_iter()
            .filter(|r| r.is_detection())
            .map(|r| {
                let h = &r.header;
                Detection {
                    rule_id: h.rule_id.clone().unwrap_or_else(|| h.rule_title.clone()),
                    rule_title: h.rule_title.clone(),
                    level: h
                        .level
                        .map(|l| format!("{l:?}").to_lowercase())
                        .unwrap_or_else(|| "medium".to_string()),
                    attack: h.tags.clone(),
                    event: event.clone(),
                    observed_at,
                    realert_secs: None, // Sigma detections use the global window.
                }
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use std::collections::BTreeMap;

    const SSH_RULE: &str = r#"
title: SSH failed password
id: garmr-ssh-failed-password
status: experimental
logsource:
    product: linux
    service: sshd
detection:
    selection:
        service: sshd
        message|contains: 'Failed password'
    condition: selection
level: medium
tags:
    - attack.credential_access
    - attack.t1110
"#;

    fn ev(message: &str, service: &str) -> Event {
        let mut fields = BTreeMap::new();
        fields.insert("src_ip".to_string(), "203.0.113.7".to_string());
        Event {
            ts: Utc::now(),
            host: "pve".into(),
            service: service.into(),
            source: "journald".into(),
            environment: "prod".into(),
            severity: "info".into(),
            log_type: "system".into(),
            message: message.into(),
            fields,
        }
    }

    #[test]
    fn fires_on_failed_password() {
        let d = Detector::from_yaml(SSH_RULE).unwrap();
        assert_eq!(d.rule_count(), 1);
        let hits = d.evaluate(&ev(
            "Failed password for root from 203.0.113.7 port 22 ssh2",
            "sshd",
        ));
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].rule_id, "garmr-ssh-failed-password");
        assert!(hits[0].attack.iter().any(|t| t.contains("t1110")));
        assert_eq!(
            hits[0].dedup_key(),
            "garmr-ssh-failed-password|pve|203.0.113.7"
        );
    }

    #[test]
    fn no_fire_on_benign() {
        let d = Detector::from_yaml(SSH_RULE).unwrap();
        assert!(d
            .evaluate(&ev("Accepted publickey for henrik", "sshd"))
            .is_empty());
    }

    #[test]
    fn ecs_keyed_rule_matches_via_alias() {
        // A community-style rule keyed on ECS field names must fire against a
        // garmr event, proving the nested ECS alias layer works through rsigma.
        const ECS_RULE: &str = r#"
title: Suspicious curl exec
id: test-ecs-curl
logsource:
    product: linux
detection:
    selection:
        process.command_line|contains: 'curl'
        destination.ip: '203.0.113.9'
    condition: selection
level: medium
"#;
        let d = Detector::from_yaml(ECS_RULE).unwrap();
        let mut fields = BTreeMap::new();
        fields.insert("cmdline".to_string(), "curl http://evil".to_string());
        fields.insert("dst_ip".to_string(), "203.0.113.9".to_string());
        let e = Event {
            ts: Utc::now(),
            host: "pve".into(),
            service: "kunai".into(),
            source: "kunai".into(),
            environment: "prod".into(),
            severity: "info".into(),
            log_type: "endpoint".into(),
            message: "connect".into(),
            fields,
        };
        assert_eq!(
            d.evaluate(&e).len(),
            1,
            "ECS-keyed rule should match via alias"
        );
    }

    #[test]
    fn split_attack_tags_separates_techniques_from_tactics() {
        let (tech, tac) = split_attack_tags(&[
            "attack.credential_access".into(),
            "attack.t1110".into(),
            "attack.t1110.001".into(),
            "attack.privilege_escalation".into(),
            "cve.2021-1234".into(), // non-attack tag ignored
            "attack.g0016".into(),  // group tag → not a technique
        ]);
        assert_eq!(tech, vec!["T1110", "T1110.001"]);
        assert_eq!(
            tac,
            vec!["credential-access", "g0016", "privilege-escalation"]
        );
    }
}
