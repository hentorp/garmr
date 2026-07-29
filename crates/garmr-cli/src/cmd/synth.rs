// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! `garmr synth-eval` — a synthetic labeled dataset + a precision/recall harness
//! (DoD 21). It generates audit events with **exact ground truth** — normal traffic
//! plus one injected scenario for **every shipped app-audit detector family** (the
//! three policy detectors, the three standalone record detectors, all five
//! cross-event stateful detectors, and the fused insider-risk path) — and runs each
//! through the SAME application-audit
//! detection path `serve` runs per event — resource catalog → access policy →
//! stateless record detectors → cross-event stateful detectors → ensemble fusion
//! (`fuse_access` → `Detection`), the exact tail of [`AppAudit::finish_event`],
//! minus only the learned behavioral baselines (a fresh install has none). It then
//! reports which scenarios `serve` would raise a case for, and how many normal
//! events false-positived. This validates every detector shipped so far on
//! realistic, ground-truthed data WITHOUT touching a live warehouse.
//!
//! Scoring is over the FUSED `Detection.rule_id` set, not raw finding ids, so a
//! "catch" means the case `serve` actually raises — e.g. a lone errored read is
//! folded into `app-insider-risk-*`, exactly as in production, not surfaced under
//! `app-failed-access`. The stateful plane runs on `StatefulConfig::default()` —
//! the shipped config, no lab overrides — so a green result reflects the deployed
//! behavior.
//!
//! [`AppAudit::finish_event`]: crate::appaudit::AppAudit::finish_event

use std::collections::{BTreeMap, BTreeSet};

use anyhow::Result;
use chrono::{DateTime, Utc};

use garmr_analytics::ensemble::{fuse_access, EnsemblePolicy};
use garmr_appdetect::stateful::{StatefulConfig, StatefulDetectors};
use garmr_appdetect::{classification_criticality, detect_access, is_deterministic_policy, is_standalone};
use garmr_catalog::{Catalog, CatalogEntry, CatalogSource, DataClassification, Resource, Table};
use garmr_core::app_audit::keys;
use garmr_core::{AuditRecord, Event};
use garmr_policy::{context_from_event, ConditionMatch, Effect, Policy, ResourceMatch, SubjectMatch};

use crate::cli::Cli;

/// One labeled synthetic access.
struct Sample {
    ev: Event,
    /// Ground-truth scenario label ("normal" for benign traffic).
    label: &'static str,
    /// For an attack label: the detector id we expect to fire (a family prefix).
    expect: &'static str,
}

fn ts(secs: i64) -> DateTime<Utc> {
    DateTime::<Utc>::from_timestamp(1_770_000_000 + secs, 0).unwrap()
}

/// Build one audit event.
fn ev(
    id: &str,
    actor: &str,
    object: &str,
    action: &str,
    outcome: &str,
    ticket: Option<&str>,
    secs: i64,
) -> Event {
    let mut f = BTreeMap::new();
    f.insert(keys::ACTOR.to_string(), actor.to_string());
    f.insert(keys::OBJECT_NAME.to_string(), object.to_string());
    f.insert(keys::ACTION.to_string(), action.to_string());
    f.insert(keys::OPERATION.to_string(), action.to_string());
    f.insert(keys::OUTCOME.to_string(), outcome.to_string());
    if let Some(t) = ticket {
        f.insert(keys::TICKET.to_string(), t.to_string());
    }
    f.insert("event_id".to_string(), id.to_string());
    Event {
        ts: ts(secs),
        host: "db01".into(),
        service: "postgres".into(),
        source: "postgres-csvlog".into(),
        environment: "prod".into(),
        severity: "info".into(),
        log_type: "audit".into(),
        message: format!("AUDIT: {action} {object}"),
        fields: f,
    }
}

/// The enforced set the eval runs against: sensitive tables + a deny-raw and a
/// require-justification policy.
fn plane() -> (Catalog, Vec<Policy>) {
    let mut entries = Vec::new();
    for name in ["raw.persons", "curated.persons", "curated.salaries"] {
        let mut e = CatalogEntry::candidate(
            format!("table:{name}"),
            Resource::Table(Table {
                name: name.into(),
                classification: Some(DataClassification::Confidential),
                sensitive: true,
                ..Default::default()
            }),
            CatalogSource::Manual,
        );
        e.promote("synth");
        entries.push(e);
    }
    let catalog = Catalog::new(entries);

    let deny_raw = Policy {
        id: "deny-raw".into(),
        version: 1,
        title: "No raw person data".into(),
        description: String::new(),
        priority: 100,
        enabled: true,
        subject: SubjectMatch::default(),
        resource: ResourceMatch {
            objects: vec!["raw.*".into()],
            ..Default::default()
        },
        condition: ConditionMatch::default(),
        effect: Effect::Deny,
        created_by: "synth".into(),
        approved_by: Some("synth".into()),
    };
    let require_ticket = Policy {
        id: "require-ticket-for-sensitive".into(),
        version: 1,
        title: "Sensitive access needs a ticket".into(),
        description: String::new(),
        priority: 10,
        enabled: true,
        subject: SubjectMatch::default(),
        resource: ResourceMatch::default(),
        condition: ConditionMatch {
            sensitive_resource: Some(true),
            ..Default::default()
        },
        effect: Effect::RequireJustification,
        created_by: "synth".into(),
        approved_by: Some("synth".into()),
    };
    // Salary access additionally needs an approval reference (a higher bar than a
    // ticket) — exercises the RequireApproval effect + the app-missing-approval
    // detector.
    let require_approval = Policy {
        id: "require-approval-for-salaries".into(),
        version: 1,
        title: "Salary access needs an approval reference".into(),
        description: String::new(),
        priority: 20,
        enabled: true,
        subject: SubjectMatch::default(),
        resource: ResourceMatch {
            objects: vec!["curated.salaries".into()],
            ..Default::default()
        },
        condition: ConditionMatch::default(),
        effect: Effect::RequireApproval,
        created_by: "synth".into(),
        approved_by: Some("synth".into()),
    };
    (catalog, vec![deny_raw, require_ticket, require_approval])
}

/// Generate the labeled dataset: benign traffic + injected scenarios.
fn generate() -> Vec<Sample> {
    let mut out = Vec::new();
    let mut t = 0i64;
    let mut id = 0u64;
    let mut next = |a: &str, o: &str, act: &str, oc: &str, tk: Option<&str>, tt: &mut i64| {
        id += 1;
        *tt += 7;
        ev(&format!("e{id}"), a, o, act, oc, tk, *tt)
    };

    // --- normal: analysts read curated (non-sensitive) tables WITH a ticket ---
    for user in ["anna", "bob", "carol"] {
        for _ in 0..10 {
            out.push(Sample {
                ev: next(user, "curated.orders", "select", "success", Some("JIRA-1"), &mut t),
                label: "normal",
                expect: "",
            });
        }
    }

    // --- normal, but adversarially close to the detectors (FPR must stay 0) ---
    // Justified SENSITIVE reads: exercise the require-justification policy's
    // satisfied path + the sensitivity gate — a ticketed sensitive read is normal.
    for _ in 0..8 {
        out.push(Sample {
            ev: next("gina", "curated.persons", "select", "success", Some("JIRA-5"), &mut t),
            label: "normal",
            expect: "",
        });
    }
    // A benign SHORT sequential id walk (below seq_run_len): a paginated report,
    // not a scrape — the sequential detector must NOT trip under its threshold.
    for i in 0..8 {
        let mut e = next("harry", "curated.persons", "select", "success", Some("JIRA-6"), &mut t);
        e.fields.insert(keys::RECORD_ID.to_string(), (900 + i).to_string());
        e.fields.insert(keys::OBJECT_TYPE.to_string(), "persons".to_string());
        out.push(Sample { ev: e, label: "normal", expect: "" });
    }
    // Justified reads of a handful of DISTINCT subjects (below slow_min_subjects):
    // a case worker touching several records with a ticket — not enumeration.
    for i in 0..10 {
        let mut e = next("iris", "curated.persons", "select", "success", Some("JIRA-8"), &mut t);
        e.fields.insert(keys::RECORD_ID.to_string(), format!("subj-{i}"));
        e.fields.insert(keys::OBJECT_TYPE.to_string(), "persons".to_string());
        out.push(Sample { ev: e, label: "normal", expect: "" });
    }

    // --- forbidden-access: a read of a raw.* table (deny policy) ---
    for _ in 0..3 {
        out.push(Sample {
            ev: next("dave", "raw.persons", "select", "success", Some("JIRA-2"), &mut t),
            label: "forbidden-access",
            expect: "app-forbidden-access",
        });
    }

    // --- missing-justification: a sensitive read with NO ticket ---
    for _ in 0..3 {
        out.push(Sample {
            ev: next("erin", "curated.persons", "select", "success", None, &mut t),
            label: "missing-justification",
            expect: "app-missing-justification",
        });
    }

    // --- failed-access: an operation that errored. The `app-failed-access`
    //     finding is a WEAK indicator: serve fuses it into `app-insider-risk-*`
    //     (it is neither a policy nor a standalone finding), so that is the case
    //     an analyst actually sees — the harness scores what serve raises. ---
    for _ in 0..3 {
        out.push(Sample {
            ev: next("frank", "curated.orders", "select", "failure", Some("JIRA-3"), &mut t),
            label: "failed-access",
            expect: "app-insider-risk",
        });
    }

    // --- denied-probing (stateful): one actor probing MANY DISTINCT forbidden raw
    //     tables (the detector trips on distinct denied resources, not repetition) ---
    for i in 0..15 {
        out.push(Sample {
            ev: next("mallory", &format!("raw.probe{i:02}"), "select", "success", None, &mut t),
            label: "denied-probing",
            expect: "app-denied-probing",
        });
    }

    // --- enumeration (stateful sequential): one actor walking ADJACENT numeric
    //     record ids of one sensitive table — a scripted scrape. The sequential
    //     detector keys on adjacent numeric subject/record ids per object type
    //     (not the object name), so we stamp record_id + object_table. ---
    for i in 0..20 {
        let mut e = next("scanner", "curated.persons", "select", "success", Some("JIRA-9"), &mut t);
        e.fields
            .insert(keys::RECORD_ID.to_string(), (100_000 + i).to_string());
        e.fields
            .insert(keys::OBJECT_TYPE.to_string(), "persons".to_string());
        out.push(Sample {
            ev: e,
            label: "enumeration",
            expect: "app-enumeration-sequential",
        });
    }

    // --- self-access: reading one's own record. A weak record-derived signal —
    //     serve fuses it into app-insider-risk-*. ---
    for _ in 0..3 {
        let mut e = next("nina", "curated.persons", "select", "success", Some("JIRA-SELF"), &mut t);
        e.fields.insert(keys::IS_SELF.to_string(), "true".to_string());
        out.push(Sample { ev: e, label: "self-access", expect: "app-insider-risk" });
    }

    // --- watched-subject access: a flagged subject is touched (standalone case). ---
    for _ in 0..3 {
        let mut e = next("olof", "curated.persons", "select", "success", Some("JIRA-W"), &mut t);
        e.fields.insert(keys::WATCHED.to_string(), "true".to_string());
        out.push(Sample { ev: e, label: "watched-subject", expect: "app-watched-subject-access" });
    }

    // --- privilege change: a GRANT/ALTER-ROLE style privileged operation. ---
    for _ in 0..3 {
        let mut e = next("dba", "curated.roles", "grant", "success", Some("JIRA-P"), &mut t);
        e.fields.insert(keys::PRIVILEGE_OPERATION.to_string(), "true".to_string());
        out.push(Sample { ev: e, label: "privilege-change", expect: "app-privilege-change" });
    }

    // --- service-account misuse: a service account driven from an interactive
    //     client (psql), not its application. ---
    for _ in 0..3 {
        let mut e = next("svc-etl", "curated.orders", "select", "success", Some("JIRA-SA"), &mut t);
        e.fields.insert(keys::SERVICE_ACCOUNT.to_string(), "true".to_string());
        e.fields.insert(keys::CLIENT_APPLICATION.to_string(), "psql".to_string());
        out.push(Sample { ev: e, label: "service-account-misuse", expect: "app-service-account-misuse" });
    }

    // --- low-and-slow enumeration: many DISTINCT sensitive subjects, drip-fed over
    //     ~8h across several sessions (the tell that separates it from a burst). ---
    for i in 0..45 {
        let mut e = ev(
            &format!("slow{i}"),
            "creeper",
            "curated.persons",
            "select",
            "success",
            Some("JIRA-LS"),
            100_000 + i * 660,
        );
        e.fields.insert(keys::SUBJECT.to_string(), format!("person{i}"));
        e.fields.insert(keys::SESSION_ID.to_string(), format!("ls-sess-{}", i % 3));
        out.push(Sample { ev: e, label: "low-and-slow", expect: "app-enumeration-low-and-slow" });
    }

    // --- split-bulk extraction: many sub-threshold reads whose rows sum to a bulk
    //     export (not flagged as a bulk/export op — the point is it is SPLIT). ---
    for _ in 0..15 {
        let mut e = next("harvester", "curated.persons", "select", "success", Some("JIRA-B"), &mut t);
        e.fields.insert(keys::ROWS_READ.to_string(), "10000".to_string());
        out.push(Sample { ev: e, label: "split-bulk", expect: "app-split-bulk-extraction" });
    }

    // --- missing-approval: a salary read carries a ticket (justification) but no
    //     approval reference, which the RequireApproval policy demands. ---
    for _ in 0..3 {
        out.push(Sample {
            ev: next("quentin", "curated.salaries", "select", "success", Some("JIRA-A"), &mut t),
            label: "missing-approval",
            expect: "app-missing-approval",
        });
    }

    // --- cross-domain access: one session reaching across two distinct sensitive
    //     data domains (schemas) — lateral reach, not a single-domain workflow. ---
    for (obj, schema) in [("curated.persons", "hr"), ("curated.salaries", "finance")] {
        let mut e = next("rover", obj, "select", "success", Some("JIRA-X"), &mut t);
        e.fields.insert(keys::SESSION_ID.to_string(), "xd-sess-1".to_string());
        e.fields.insert(keys::DATABASE_SCHEMA.to_string(), schema.to_string());
        out.push(Sample { ev: e, label: "cross-domain", expect: "app-cross-domain-access" });
    }

    out
}

/// Per-scenario result.
struct ScenarioResult {
    label: &'static str,
    events: usize,
    detected: bool,
    fired: BTreeSet<String>,
}

/// Run the dataset through the SAME per-event detection tail as
/// [`AppAudit::finish_event`](crate::appaudit::AppAudit::finish_event) and score
/// it over the fused `Detection` set — the cases `serve` would actually raise.
fn evaluate(samples: &[Sample]) -> (Vec<ScenarioResult>, usize, usize) {
    let (catalog, policies) = plane();
    let index = catalog.object_index();
    // The SHIPPED stateful config — no lab overrides. `require_sensitive` stays
    // true (the sensitive scenarios read catalog-sensitive tables, so they gate
    // through exactly as in production; validating the deployed config, not a
    // permissive variant).
    let mut stateful = StatefulDetectors::new(StatefulConfig::default());
    // The ensemble default (serve tunes crit/corr coefficients from config; the
    // default coefficients are the harness baseline).
    let ensemble = EnsemblePolicy::default();

    // Accumulate per-scenario the FUSED detection rule-ids raised on ANY of its
    // events.
    let mut by_label: BTreeMap<&'static str, (usize, BTreeSet<String>, &'static str)> =
        BTreeMap::new();
    let mut normal_events = 0usize;
    let mut normal_fp_events = 0usize;

    for s in samples {
        let mut rec = AuditRecord::from_event(&s.ev);
        index.stamp(&catalog.entries, &mut rec);
        let ctx = context_from_event(&s.ev, &rec);
        let decision = garmr_policy::evaluate(&ctx, &policies);
        let forbidden = decision.decision == Effect::Deny;
        // The production negative-outcome predicate (Denied | Failure | Error).
        let failed = rec.action.outcome.is_negative();

        // Stateless (record + policy) findings, then the cross-event stateful
        // findings — finish_event's exact order.
        let mut findings = detect_access(&s.ev, &rec, &decision, s.ev.field("event_id"));
        findings.extend(stateful.observe(&s.ev, &rec, forbidden, failed));
        // Stamp asset-criticality onto every finding before fusion, as
        // finish_event does (it drives the ensemble crit multiplier).
        let criticality = classification_criticality(&rec);
        for f in &mut findings {
            f.env_basis.criticality = criticality;
        }
        // Fuse into the final detection set (monitor_mult = 1.0 — no monitoring
        // registry in the harness) and score over the rule-ids serve would raise.
        let fired: BTreeSet<String> =
            fuse_access(findings, &ensemble, is_deterministic_policy, is_standalone, 1.0)
                .into_iter()
                .map(|f| f.into_detection().rule_id)
                .collect();

        if s.label == "normal" {
            normal_events += 1;
            if !fired.is_empty() {
                normal_fp_events += 1;
            }
        } else {
            let e = by_label.entry(s.label).or_insert((0, BTreeSet::new(), s.expect));
            e.0 += 1;
            e.1.extend(fired);
        }
    }

    let results: Vec<ScenarioResult> = by_label
        .into_iter()
        .map(|(label, (events, fired, expect))| ScenarioResult {
            label,
            events,
            detected: fired.iter().any(|d| d.starts_with(expect)),
            fired,
        })
        .collect();
    (results, normal_events, normal_fp_events)
}

/// `garmr synth-eval` — generate the labeled dataset, run detection, print metrics.
pub(crate) async fn synth_eval(_cli: &Cli) -> Result<()> {
    let samples = generate();
    let (results, normal_events, normal_fp) = evaluate(&samples);

    let attacks = results.len();
    let caught = results.iter().filter(|r| r.detected).count();
    let recall = if attacks == 0 { 0.0 } else { caught as f64 / attacks as f64 };
    let fpr = if normal_events == 0 {
        0.0
    } else {
        normal_fp as f64 / normal_events as f64
    };

    println!("garmr synthetic detection eval — {} events", samples.len());
    println!("  scenarios : {attacks}   normal events: {normal_events}");
    println!();
    println!("  {:<24} {:>6}  {:<8}  detectors fired", "scenario", "events", "caught");
    for r in &results {
        println!(
            "  {:<24} {:>6}  {:<8}  {}",
            r.label,
            r.events,
            if r.detected { "YES" } else { "MISS" },
            r.fired.iter().cloned().collect::<Vec<_>>().join(", ")
        );
    }
    println!();
    println!("  recall (scenarios caught) : {caught}/{attacks} = {:.0}%", recall * 100.0);
    println!(
        "  false-positive rate (normal): {normal_fp}/{normal_events} = {:.1}%",
        fpr * 100.0
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_labels_every_event() {
        let s = generate();
        assert!(s.len() > 50);
        assert!(s.iter().any(|x| x.label == "normal"));
        assert!(s.iter().any(|x| x.label == "forbidden-access"));
    }

    #[test]
    fn eval_catches_every_injected_scenario_with_zero_normal_fp() {
        let (results, normal_events, normal_fp) = evaluate(&generate());
        // The corpus injects one scenario per shipped app-audit detector family
        // (all three policy detectors, all three standalone record detectors, all
        // five cross-event stateful detectors, and the fused insider-risk path).
        // EVERY one must be caught over the deployed pipeline + config.
        assert!(results.len() >= 13, "expected the full detector-family catalog, got {}", results.len());
        for r in &results {
            assert!(r.detected, "scenario '{}' was not caught (detectors fired: {:?})", r.label, r.fired);
        }
        // Every shipped detector family is represented — guard against a silently
        // dropped scenario.
        for label in [
            "forbidden-access", "missing-justification", "missing-approval",
            "watched-subject", "privilege-change", "service-account-misuse",
            "enumeration", "low-and-slow", "split-bulk", "denied-probing", "cross-domain",
            "self-access", "failed-access",
        ] {
            assert!(results.iter().any(|r| r.label == label), "missing scenario '{label}'");
        }
        // Normal traffic — including adversarially-close benign reads — must NOT
        // false-positive.
        assert_eq!(normal_fp, 0, "{normal_fp}/{normal_events} normal events false-positived");
    }
}