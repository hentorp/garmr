// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! Agent state in an embedded redb database, kept entirely separate from the
//! events lakehouse: cases + their transcripts, the per-rule suppression
//! window, the daily budget ledger, per-host baselines, the cold-storage
//! manifest, rule/action proposals, hunt reports, and notification silences.
//!
//! redb is synchronous and embedded; every operation here is microsecond-scale
//! for a single-person SOC, so the methods are plain sync calls rather than
//! actor messages. The `Database` is `Send + Sync`, so a clone of the `Arc` can
//! be handed to any task.
//!
//! [`StateStore`] is one type whose methods are split by persistence domain
//! across the sibling modules — [`cases`], [`budget`], [`baselines`],
//! [`hunts`], [`proposals`], [`actions`], [`cold`], [`silences`], and
//! [`detection_memory`] (suppression window + new-template memory) — each a
//! thin `impl StateStore` block over one or two redb tables. The table
//! definitions and the open-all-tables constructor live here so every domain
//! shares one schema.

use std::sync::Arc;

use garmr_core::{Error, Result};
use redb::{Database, TableDefinition};

mod actions;
mod app_baselines;
mod app_shadow;
mod app_stateful;
mod auth;
mod baselines;
mod budget;
mod cases;
mod cold;
mod datasets;
mod detection_memory;
mod environment;
mod findings;
mod hunts;
mod ingest_seq;
mod proposals;
mod query_plans;
mod records;
mod registry;
mod silences;

pub use budget::BudgetReservation;
pub use datasets::DatasetPutOutcome;
pub use ingest_seq::{SeqHealth, SeqVerdict};
pub use registry::RegisterOutcome;

const CASES: TableDefinition<&str, &[u8]> = TableDefinition::new("cases");
/// dedup_key -> unix seconds of the last case opened for it (realert window).
const SUPPRESSION: TableDefinition<&str, u64> = TableDefinition::new("suppression");
/// "YYYY-MM-DD" -> spend in micro-USD (integer to avoid float value types).
const BUDGET: TableDefinition<&str, u64> = TableDefinition::new("budget");
/// host -> JSON baseline blob.
const BASELINES: TableDefinition<&str, &[u8]> = TableDefinition::new("baselines");
/// window id ("YYYY-MM-DD") -> JSON `ColdArchive` (the cold-storage manifest).
const COLD_ARCHIVES: TableDefinition<&str, &[u8]> = TableDefinition::new("cold_archives");
/// report id (uuid) -> JSON `HuntReport` (the threat-hunt audit trail).
const HUNTS: TableDefinition<&str, &[u8]> = TableDefinition::new("hunts");
/// proposal id (uuid) -> JSON `RuleProposal` (agent-authored, human-decided).
const PROPOSALS: TableDefinition<&str, &[u8]> = TableDefinition::new("proposals");
/// action id (uuid) -> JSON `ActionProposal` (the response/SOAR audit trail).
const ACTIONS: TableDefinition<&str, &[u8]> = TableDefinition::new("actions");
/// template id (short sha) -> first-seen unix micros (new-template anomaly).
const TEMPLATES: TableDefinition<&str, i64> = TableDefinition::new("templates");
/// Single-key scalars for the retention job (e.g. "watermark_us" -> i64).
const COLD_META: TableDefinition<&str, i64> = TableDefinition::new("cold_meta");
/// rule id -> JSON `Silence` (human-approved notification silences; one per rule).
const SILENCES: TableDefinition<&str, &[u8]> = TableDefinition::new("silences");
/// Small auth KV: the session-cookie MAC key + the registered passkeys blob
/// (opaque bytes; the console layer owns the serialization).
const AUTH: TableDefinition<&str, &[u8]> = TableDefinition::new("auth");
// --- Phase 3: append-only prediction/decision/outcome records (never
// overwritten). Case-scoped tables key on `{case_id}|{nanos}|{id}`; the
// caseless-capable tables key on the record's own id. See `records.rs`. ---
/// `{case_id}|{nanos}|{prediction_id}` -> JSON `AgentPrediction`.
const PREDICTIONS: TableDefinition<&str, &[u8]> = TableDefinition::new("predictions");
/// `{case_id}|{nanos}|{decision_id}` -> JSON `AnalystDecision`.
const DECISIONS: TableDefinition<&str, &[u8]> = TableDefinition::new("decisions");
/// `outcome_id` -> JSON `IncidentOutcome` (case_id optional).
const INCIDENT_OUTCOMES: TableDefinition<&str, &[u8]> = TableDefinition::new("incident_outcomes");
/// `feedback_id` -> JSON `FeedbackRecord`.
const FEEDBACK_REC: TableDefinition<&str, &[u8]> = TableDefinition::new("feedback");
/// `fn_id` -> JSON `FalseNegativeRecord` (case_id optional — a never-cased miss).
const FALSE_NEGATIVES: TableDefinition<&str, &[u8]> = TableDefinition::new("false_negatives");
/// `mistake_id` -> JSON `MistakeRecord`.
const MISTAKES: TableDefinition<&str, &[u8]> = TableDefinition::new("mistakes");
// --- Phase 4: versioned registries. `registry` holds IMMUTABLE content records
// keyed `{kind}|{name}|{version}` (guarded-unique insert); `registry_promotions`
// is the APPEND-ONLY governance stream keyed `{kind}|{name}|{nanos}|{id}`. See
// `registry.rs`. ---
/// `{kind}|{name}|{version}` -> JSON `RegistryRecord` (immutable).
const REGISTRY: TableDefinition<&str, &[u8]> = TableDefinition::new("registry");
/// `{kind}|{name}|{nanos}|{promotion_id}` -> JSON `PromotionEvent` (append-only).
const REGISTRY_PROMOTIONS: TableDefinition<&str, &[u8]> =
    TableDefinition::new("registry_promotions");
// --- Phase 5: the temporal environment model. `env_observations` is the
// content-keyed append-only evidence log; `env_transitions` is the audit-bound
// promotion state machine; `env_sightings` is a monotonic per-fact scalar. See
// `environment.rs`. ---
/// `{fact_id}|{observation_id}` -> JSON `FactObservation` (content-keyed).
const ENV_OBSERVATIONS: TableDefinition<&str, &[u8]> = TableDefinition::new("env_observations");
/// `{fact_id}|{nanos}|{transition_id}` -> JSON `FactTransition` (append-only).
const ENV_TRANSITIONS: TableDefinition<&str, &[u8]> = TableDefinition::new("env_transitions");
/// `{fact_id}` -> JSON `Sighting` (monotonic merge).
const ENV_SIGHTINGS: TableDefinition<&str, &[u8]> = TableDefinition::new("env_sightings");
/// `{host}|{nanos}|{finding_id}` -> JSON `SecurityFinding` (Phase 7, append-only).
const FINDINGS: TableDefinition<&str, &[u8]> = TableDefinition::new("findings");
/// `{digest}` -> JSON `DatasetSnapshot` (Phase 8, content-keyed, immutable).
const DATASETS: TableDefinition<&str, &[u8]> = TableDefinition::new("datasets");
/// `{collector_id}|{epoch}` -> JSON `SeqState` (Phase 12, per-collector ingest
/// sequence: last seq + gap/replay counters for delivery observability).
const INGEST_SEQ: TableDefinition<&str, &[u8]> = TableDefinition::new("ingest_seq");

/// Phase 7/8 application-audit behavioral-baseline store — a single serialized
/// `garmr_baseline::BaselineStore` blob (all per-entity behavior profiles),
/// stored under one reserved key. Distinct from [`BASELINES`], which the
/// analytics anomaly plane keys per host.
const APP_BASELINES: TableDefinition<&str, &[u8]> = TableDefinition::new("app_baselines");

/// Phase 8 application-audit **stateful detector** plane — a single serialized
/// `garmr_appdetect::stateful::StatefulState` blob (per-actor cross-event
/// windows), stored under one reserved key. Lets an in-progress enumeration /
/// probing episode survive a restart.
const APP_STATEFUL: TableDefinition<&str, &[u8]> = TableDefinition::new("app_stateful");

/// Compiled query plans: `query_id` (content id of the plan) -> the typed
/// `HybridQuery` IR JSON, so a natural-language `ask` can be reproduced
/// deterministically without the model. See `query_plans.rs`.
const QUERY_PLANS: TableDefinition<&str, &[u8]> = TableDefinition::new("query_plans");

/// DoD 19 champion/challenger **shadow-evaluation** summary — a single serialized
/// counter blob (the durable decision signal), under one reserved key. The recent
/// disagreement examples are in-memory only; only these counters survive a restart.
const APP_SHADOW: TableDefinition<&str, &[u8]> = TableDefinition::new("app_shadow");

#[derive(Clone)]
pub struct StateStore {
    db: Arc<Database>,
}

impl StateStore {
    /// Open (or create) the state database and ensure every table exists so
    /// later read transactions never fail on a missing table.
    pub fn open(path: &std::path::Path) -> Result<Self> {
        let db = Database::create(path).map_err(Error::store)?;
        let wtx = db.begin_write().map_err(Error::store)?;
        {
            wtx.open_table(CASES).map_err(Error::store)?;
            wtx.open_table(SUPPRESSION).map_err(Error::store)?;
            wtx.open_table(BUDGET).map_err(Error::store)?;
            wtx.open_table(BASELINES).map_err(Error::store)?;
            wtx.open_table(COLD_ARCHIVES).map_err(Error::store)?;
            wtx.open_table(COLD_META).map_err(Error::store)?;
            wtx.open_table(SILENCES).map_err(Error::store)?;
            wtx.open_table(AUTH).map_err(Error::store)?;
            wtx.open_table(HUNTS).map_err(Error::store)?;
            wtx.open_table(PROPOSALS).map_err(Error::store)?;
            wtx.open_table(ACTIONS).map_err(Error::store)?;
            wtx.open_table(TEMPLATES).map_err(Error::store)?;
            // Phase 3 append-only record tables (auto-created so a pre-Phase-3
            // DB upgrades transparently and read txns never fault).
            wtx.open_table(PREDICTIONS).map_err(Error::store)?;
            wtx.open_table(DECISIONS).map_err(Error::store)?;
            wtx.open_table(INCIDENT_OUTCOMES).map_err(Error::store)?;
            wtx.open_table(FEEDBACK_REC).map_err(Error::store)?;
            wtx.open_table(FALSE_NEGATIVES).map_err(Error::store)?;
            wtx.open_table(MISTAKES).map_err(Error::store)?;
            // Phase 4 registry tables (auto-created so a pre-Phase-4 DB upgrades).
            wtx.open_table(REGISTRY).map_err(Error::store)?;
            wtx.open_table(REGISTRY_PROMOTIONS).map_err(Error::store)?;
            // Phase 5 environment-model tables (auto-created so a pre-Phase-5 DB
            // upgrades transparently).
            wtx.open_table(ENV_OBSERVATIONS).map_err(Error::store)?;
            wtx.open_table(ENV_TRANSITIONS).map_err(Error::store)?;
            wtx.open_table(ENV_SIGHTINGS).map_err(Error::store)?;
            // Phase 7 findings table (auto-created).
            wtx.open_table(FINDINGS).map_err(Error::store)?;
            // Phase 8 datasets table (auto-created so a pre-Phase-8 DB upgrades).
            wtx.open_table(DATASETS).map_err(Error::store)?;
            // Phase 12 per-collector ingest sequence table (auto-created).
            wtx.open_table(INGEST_SEQ).map_err(Error::store)?;
            // Phase 7/8 application-audit behavioral-baseline store (auto-created
            // so a pre-Phase-7 DB upgrades transparently).
            wtx.open_table(APP_BASELINES).map_err(Error::store)?;
            // Phase 8 application-audit stateful-detector state (auto-created so a
            // pre-Phase-8 DB upgrades transparently).
            wtx.open_table(APP_STATEFUL).map_err(Error::store)?;
            // Stored query plans for deterministic reproduce (auto-created).
            wtx.open_table(QUERY_PLANS).map_err(Error::store)?;
            // DoD 19 shadow-evaluation summary (auto-created so a pre-DoD-19 DB
            // upgrades transparently).
            wtx.open_table(APP_SHADOW).map_err(Error::store)?;
        }
        wtx.commit().map_err(Error::store)?;
        Ok(Self { db: Arc::new(db) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use garmr_core::{
        Case, Detection, EntityKind, EntityRef, Event, FactObservation, FactTransition,
    };
    use std::collections::BTreeMap;
    use std::sync::atomic::{AtomicU32, Ordering};

    fn tmp_state() -> (StateStore, std::path::PathBuf) {
        static N: AtomicU32 = AtomicU32::new(0);
        let p = std::env::temp_dir().join(format!(
            "garmr-state-test-{}-{}.redb",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_file(&p);
        (StateStore::open(&p).unwrap(), p)
    }

    #[test]
    fn whole_file_backup_preserves_all_tables_including_app_stateful() {
        // `garmr backup` copies state.redb as a WHOLE FILE (see backup.rs:
        // `std::fs::copy(state_db, …/state.redb)`, under the offline redb-exclusion
        // fence), so a newly-added table (`app_stateful`) is captured automatically
        // — no per-table enumeration to keep in sync. Prove the restore preserves
        // the app-audit baselines, the stateful-detector windows, AND a case.
        let (store, path) = tmp_state();
        store.put_app_baselines(b"BASELINE-BLOB").unwrap();
        store.put_app_stateful(b"STATEFUL-BLOB").unwrap();
        store.put_case(&Case::open(det("garmr-x", "src"))).unwrap();
        // Quiesce: redb commits synchronously per write, but drop the handle to
        // mirror the backup's writer-stopped fence before the file copy.
        drop(store);

        let restored = path.with_extension("restored.redb");
        let _ = std::fs::remove_file(&restored);
        std::fs::copy(&path, &restored).unwrap();

        let r = StateStore::open(&restored).unwrap();
        assert_eq!(
            r.get_app_baselines().unwrap().as_deref(),
            Some(&b"BASELINE-BLOB"[..]),
            "app-audit baselines survive the restore"
        );
        assert_eq!(
            r.get_app_stateful().unwrap().as_deref(),
            Some(&b"STATEFUL-BLOB"[..]),
            "stateful-detector windows survive the restore (the new table)"
        );
        assert_eq!(
            r.list_cases().unwrap().len(),
            1,
            "the case survives the restore"
        );

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(&restored);
    }

    #[test]
    fn query_plans_round_trip_and_are_idempotent() {
        let (store, path) = tmp_state();
        assert!(store.get_query_plan("q1:absent").unwrap().is_none());
        let plan = br#"{"text":{"query":"failed logins"},"limit":50}"#;
        store.put_query_plan("q1:abc", plan).unwrap();
        assert_eq!(
            store.get_query_plan("q1:abc").unwrap().as_deref(),
            Some(&plan[..])
        );
        // Content-addressed re-store of the same plan is idempotent.
        store.put_query_plan("q1:abc", plan).unwrap();
        assert_eq!(
            store.get_query_plan("q1:abc").unwrap().as_deref(),
            Some(&plan[..])
        );
        let _ = std::fs::remove_file(&path);
    }

    fn det(rule_id: &str, source: &str) -> Detection {
        Detection {
            rule_id: rule_id.to_string(),
            rule_title: "t".to_string(),
            level: "high".to_string(),
            attack: vec![],
            event: Event {
                ts: chrono::Utc::now(),
                host: "h".into(),
                service: "s".into(),
                source: source.into(),
                environment: "test".into(),
                severity: "warning".into(),
                log_type: "system".into(),
                message: "m".to_string(),
                fields: BTreeMap::new(),
            },
            observed_at: chrono::Utc::now(),
            realert_secs: None,
        }
    }

    fn mk_pred(case_id: &str, id: &str, at_secs: i64) -> garmr_core::AgentPrediction {
        let mut p: garmr_core::AgentPrediction = serde_json::from_str("{}").unwrap();
        p.case_id = case_id.into();
        p.prediction_id = id.into();
        p.disposition = garmr_core::Disposition::Malicious;
        p.created_at = chrono::DateTime::from_timestamp(at_secs, 0).unwrap();
        p
    }

    #[test]
    fn predictions_are_append_only_and_case_scoped() {
        let (st, _p) = tmp_state();
        // Two predictions for c1 (a re-triage), one for c2.
        st.append_prediction(&mk_pred("c1", "p1", 100)).unwrap();
        st.append_prediction(&mk_pred("c1", "p2", 200)).unwrap();
        st.append_prediction(&mk_pred("c2", "p3", 150)).unwrap();

        let c1 = st.predictions_for("c1").unwrap();
        assert_eq!(c1.len(), 2, "both predictions kept (no overwrite)");
        assert_eq!(c1[0].prediction_id, "p1", "chronological");
        assert_eq!(c1[1].prediction_id, "p2");
        assert_eq!(st.predictions_for("c2").unwrap().len(), 1);
        assert_eq!(st.list_predictions().unwrap().len(), 3);
        // The core fold picks the newest as current.
        assert_eq!(
            garmr_core::current_prediction(&c1).unwrap().prediction_id,
            "p2"
        );
    }

    #[test]
    fn scan_case_limited_caps_at_limit_newest_and_stays_case_scoped() {
        // Issue #19: a case's append-only history must read back bounded and
        // never leak a sibling case whose id shares its prefix.
        let (st, _p) = tmp_state();
        // 5 predictions for c1 (100..104), 2 for the prefix-sibling c10, 1 for c2.
        for i in 0..5 {
            st.append_prediction(&mk_pred("c1", &format!("p{i}"), 100 + i as i64))
                .unwrap();
        }
        st.append_prediction(&mk_pred("c10", "x0", 500)).unwrap();
        st.append_prediction(&mk_pred("c10", "x1", 501)).unwrap();
        st.append_prediction(&mk_pred("c2", "y0", 300)).unwrap();

        // Newest-first, capped at 2 → the two most recent c1 predictions, and
        // NONE of the c10 rows even though `c10` shares the `c1` prefix (digit
        // `0` sorts below the `|` separator, so `c10|…` is excluded from `c1|`).
        let newest: Vec<garmr_core::AgentPrediction> = st
            .scan_case_limited(PREDICTIONS, "c1", 2, "prediction")
            .unwrap();
        assert_eq!(newest.len(), 2, "capped at the limit");
        assert_eq!(newest[0].prediction_id, "p4", "newest-first");
        assert_eq!(newest[1].prediction_id, "p3");
        assert!(
            newest.iter().all(|p| p.case_id == "c1"),
            "no prefix-sibling (c10) row leaks into the c1 range"
        );

        // A limit above the row count returns exactly that case's rows.
        let all_c1: Vec<garmr_core::AgentPrediction> = st
            .scan_case_limited(PREDICTIONS, "c1", 1000, "prediction")
            .unwrap();
        assert_eq!(all_c1.len(), 5);
        // c10 is its own case, unaffected by the c1 scan.
        let c10: Vec<garmr_core::AgentPrediction> = st
            .scan_case_limited(PREDICTIONS, "c10", 1000, "prediction")
            .unwrap();
        assert_eq!(c10.len(), 2);
    }

    #[test]
    fn list_false_negatives_limited_caps_the_read() {
        // The uuid-keyed caseless read must never return more than the window.
        let (st, _p) = tmp_state();
        for i in 0..10 {
            let mut fnr: garmr_core::FalseNegativeRecord = serde_json::from_str("{}").unwrap();
            fnr.fn_id = format!("fn{i}");
            st.append_false_negative(&fnr).unwrap();
        }
        assert_eq!(st.list_false_negatives().unwrap().len(), 10, "all present");
        assert_eq!(
            st.list_false_negatives_limited(3).unwrap().len(),
            3,
            "bounded to the requested window"
        );
        assert_eq!(
            st.list_false_negatives_limited(100).unwrap().len(),
            10,
            "a window above the row count returns them all, no more"
        );
    }

    #[test]
    fn case_view_is_bounded_yet_preserves_chronological_order() {
        let (st, _p) = tmp_state();
        st.append_prediction(&mk_pred("cX", "p1", 100)).unwrap();
        st.append_prediction(&mk_pred("cX", "p2", 200)).unwrap();
        for (id, at) in [("d1", 150), ("d2", 250)] {
            let mut d: garmr_core::AnalystDecision = serde_json::from_str("{}").unwrap();
            d.decision_id = id.into();
            d.case_id = "cX".into();
            d.created_at = chrono::DateTime::from_timestamp(at, 0).unwrap();
            st.append_decision(&d).unwrap();
        }
        let view = st.case_view("cX").unwrap();
        // Bounded read still returns the case's rows oldest → newest (reversed
        // back from the newest-first scan) so the core fold picks the right one.
        assert_eq!(view.predictions.len(), 2);
        assert_eq!(view.predictions[0].prediction_id, "p1", "oldest → newest");
        assert_eq!(view.predictions[1].prediction_id, "p2");
        assert_eq!(view.decisions.len(), 2);
        assert_eq!(view.decisions[0].decision_id, "d1");
        assert_eq!(view.decisions[1].decision_id, "d2");
        assert_eq!(
            garmr_core::current_prediction(&view.predictions)
                .unwrap()
                .prediction_id,
            "p2"
        );
    }

    #[test]
    fn readers_tolerantly_skip_undecodable_rows() {
        let (st, _p) = tmp_state();
        let mut d: garmr_core::AnalystDecision = serde_json::from_str("{}").unwrap();
        d.decision_id = "d1".into();
        d.case_id = "c1".into();
        st.append_decision(&d).unwrap();
        // Hand-insert a garbage row into the decisions table.
        let wtx = st.db.begin_write().unwrap();
        {
            let mut t = wtx.open_table(DECISIONS).unwrap();
            t.insert("c1|00000000000000000000|garbage", b"not json".as_slice())
                .unwrap();
        }
        wtx.commit().unwrap();
        // The valid decision still returns; the poison row is skipped, not fatal.
        let ds = st.list_decisions().unwrap();
        assert_eq!(ds.len(), 1);
        assert_eq!(ds[0].decision_id, "d1");
    }

    #[test]
    fn caseless_false_negative_is_listed_but_not_case_scoped() {
        let (st, _p) = tmp_state();
        let mut fnr: garmr_core::FalseNegativeRecord = serde_json::from_str("{}").unwrap();
        fnr.fn_id = "fn1".into();
        fnr.case_id = None; // an incident that never generated a case
        st.append_false_negative(&fnr).unwrap();
        assert_eq!(st.list_false_negatives().unwrap().len(), 1);
        assert!(st.false_negatives_for_case("anything").unwrap().is_empty());
    }

    fn mk_record(
        kind: garmr_core::RegistryKind,
        name: &str,
        version: &str,
        digest: &str,
    ) -> garmr_core::RegistryRecord {
        let mut r: garmr_core::RegistryRecord = serde_json::from_str("{}").unwrap();
        r.id = format!("{}-{version}", kind.tag());
        r.kind = kind;
        r.name = name.into();
        r.version = version.into();
        r.content_digest = digest.into();
        r
    }

    #[test]
    fn registry_register_is_guarded_and_idempotent() {
        use garmr_core::RegistryKind::Prompt;
        let (st, _p) = tmp_state();
        let r = mk_record(Prompt, "system", "v1", "digestA");
        assert_eq!(st.register_record(&r).unwrap(), RegisterOutcome::Inserted);
        // Same coordinate + same content → idempotent no-op.
        assert_eq!(
            st.register_record(&r).unwrap(),
            RegisterOutcome::AlreadyIdentical
        );
        // Same coordinate + DIFFERENT content → Conflict (immutability guard).
        let r2 = mk_record(Prompt, "system", "v1", "digestB");
        match st.register_record(&r2).unwrap() {
            RegisterOutcome::Conflict { existing_digest } => assert_eq!(existing_digest, "digestA"),
            o => panic!("expected Conflict, got {o:?}"),
        }
        // A new version is a new record; v1 is untouched.
        assert_eq!(
            st.register_record(&mk_record(Prompt, "system", "v2", "digestB"))
                .unwrap(),
            RegisterOutcome::Inserted
        );
        assert_eq!(st.records_for_name(Prompt, "system").unwrap().len(), 2);
        assert_eq!(st.list_kind(Prompt).unwrap().len(), 2);
        assert_eq!(
            st.get_record(Prompt, "system", "v1")
                .unwrap()
                .unwrap()
                .content_digest,
            "digestA"
        );
    }

    #[test]
    fn registry_key_is_injective_across_a_pipe_in_name_or_version() {
        use garmr_core::RegistryKind::Prompt;
        let (st, _p) = tmp_state();
        // Two DISTINCT coordinates that differ only in where a '|' falls. An
        // unescaped "{kind}|{name}|{version}" key would collapse them into one.
        assert_eq!(
            st.register_record(&mk_record(Prompt, "sys", "a|b", "digest1"))
                .unwrap(),
            RegisterOutcome::Inserted
        );
        assert_eq!(
            st.register_record(&mk_record(Prompt, "sys|a", "b", "digest2"))
                .unwrap(),
            RegisterOutcome::Inserted,
            "the colliding coordinate must be a distinct record, not a false Conflict"
        );
        // Each resolves to its OWN content, not the other's.
        assert_eq!(
            st.get_record(Prompt, "sys", "a|b")
                .unwrap()
                .unwrap()
                .content_digest,
            "digest1"
        );
        assert_eq!(
            st.get_record(Prompt, "sys|a", "b")
                .unwrap()
                .unwrap()
                .content_digest,
            "digest2"
        );
    }

    #[test]
    fn registry_promotions_are_append_only_and_scoped() {
        use garmr_core::{PromotionEvent, RegistryKind::Prompt};
        let (st, _p) = tmp_state();
        for (i, d) in ["a", "b"].iter().enumerate() {
            let mut e: PromotionEvent = serde_json::from_str("{}").unwrap();
            e.promotion_id = format!("p{i}");
            e.kind = Prompt;
            e.name = "system".into();
            e.target_digest = (*d).into();
            e.audit_id = "aud".into();
            e.at = chrono::DateTime::from_timestamp(100 + i as i64, 0).unwrap();
            st.append_promotion(&e).unwrap();
        }
        let ps = st.promotions_for(Prompt, "system").unwrap();
        assert_eq!(ps.len(), 2, "both kept (append-only)");
        assert_eq!(ps[0].promotion_id, "p0", "chronological");
        assert_eq!(st.list_promotions().unwrap().len(), 2);
        assert!(st.promotions_for(Prompt, "other").unwrap().is_empty());
    }

    // ---- Phase 5 environment store ----

    fn mk_obs(fid: &str, oid: &str, kind: EntityKind, id: &str, value: &str) -> FactObservation {
        FactObservation {
            observation_id: oid.into(),
            fact_id: fid.into(),
            entity: EntityRef::new(kind, id),
            value: value.into(),
            ..Default::default()
        }
    }

    #[test]
    fn env_observation_is_content_keyed_and_idempotent() {
        let (st, _p) = tmp_state();
        let o = mk_obs("fA", "o1", EntityKind::Host, "web01", "server");
        assert!(st.append_observation(&o).unwrap(), "first write inserts");
        assert!(
            !st.append_observation(&o).unwrap(),
            "identical content is an idempotent no-op"
        );
        assert_eq!(st.observations_for("fA").unwrap().len(), 1);
        // A genuinely different observation of the same fact is a new row.
        let o2 = mk_obs("fA", "o2", EntityKind::Host, "web01", "router");
        assert!(st.append_observation(&o2).unwrap());
        assert_eq!(st.observations_for("fA").unwrap().len(), 2);
    }

    #[test]
    fn env_sighting_merges_monotonically() {
        let (st, _p) = tmp_state();
        let t1 = chrono::DateTime::from_timestamp(1000, 0).unwrap();
        let t2 = chrono::DateTime::from_timestamp(2000, 0).unwrap();
        st.bump_sighting("fA", "sX", t1).unwrap();
        st.bump_sighting("fA", "sY", t2).unwrap();
        st.bump_sighting("fA", "sX", t1).unwrap(); // an older repeat
        let s = st.sighting_for("fA").unwrap().unwrap();
        assert_eq!(s.observation_count, 3);
        assert_eq!(s.last_seen, t2, "last_seen never goes backward");
        assert_eq!(s.per_source_counts.get("sX"), Some(&2));
        assert_eq!(s.per_source_counts.get("sY"), Some(&1));
    }

    #[test]
    fn open_case_set_covers_non_closed_cases_only() {
        let (st, _p) = tmp_state();
        // det() builds a Detection on host "h"; Case::open keeps state New (open).
        let open = Case::open(det("r1", "src"));
        st.put_case(&open).unwrap();
        let mut closed = Case::open(det("r2", "src"));
        closed.state = garmr_core::CaseState::Closed;
        st.put_case(&closed).unwrap();
        let set = st.open_case_entity_set().unwrap();
        assert!(set.contains(&EntityRef::new(EntityKind::Host, "h")));
        // A closed benign case does not keep its entity blocked (the only case is
        // on the same host "h", so the set still has it via the open one — assert
        // the closed-only path is empty instead).
        let (st2, _p2) = tmp_state();
        st2.put_case(&closed).unwrap();
        assert!(st2.open_case_entity_set().unwrap().is_empty());
    }

    #[test]
    fn compromised_set_from_audited_transition_is_immune_to_absence_of_a_retire() {
        let (st, _p) = tmp_state();
        // A fact about host "mal01" with an audited KnownMalicious transition.
        let o = mk_obs("fM", "o1", EntityKind::Host, "mal01", "bad");
        st.append_observation(&o).unwrap();
        let tr = FactTransition {
            transition_id: "t1".into(),
            fact_id: "fM".into(),
            to_state: garmr_core::FactState::KnownMalicious,
            audit_id: "aud-1".into(),
            recorded_at: chrono::DateTime::from_timestamp(100, 0).unwrap(),
            ..Default::default()
        };
        st.append_transition(&tr).unwrap();
        let set = st.compromised_entity_set().unwrap();
        assert!(set.contains(&EntityRef::new(EntityKind::Host, "mal01")));

        // A FORGED (unaudited) KnownMalicious transition does NOT count.
        let (st2, _p2) = tmp_state();
        st2.append_observation(&o).unwrap();
        let forged = FactTransition {
            audit_id: String::new(),
            ..tr.clone()
        };
        st2.append_transition(&forged).unwrap();
        assert!(st2.compromised_entity_set().unwrap().is_empty());
    }

    #[test]
    fn promotable_candidate_auto_promotes_until_a_case_opens_on_it() {
        use garmr_core::{
            fact_id, may_auto_promote, observation_id, FactState, ObservationMode,
            PromotionContext, PromotionPolicy, SourceKind, SourceRef,
        };
        use std::collections::HashSet;

        let (st, _p) = tmp_state();
        let host = EntityRef::new(EntityKind::Host, "web01");
        let fid = fact_id(&host, "role", None, None);
        let old = chrono::Utc::now() - chrono::Duration::days(2);
        // Two sources, three sightings each (6 total ≥ min, balanced influence),
        // first seen two days ago (past the 24h quarantine).
        for src in ["sA", "sB"] {
            let o = FactObservation {
                observation_id: observation_id(&fid, src, "server"),
                fact_id: fid.clone(),
                entity: host.clone(),
                attribute: "role".into(),
                value: "server".into(),
                source: SourceRef {
                    kind: SourceKind::EventStream,
                    source_id: src.into(),
                    trust: 1.0,
                },
                confidence: 1.0,
                mode: ObservationMode::Observed,
                valid_from: old,
                recorded_at: old,
                ..Default::default()
            };
            st.append_observation(&o).unwrap();
            for _ in 0..3 {
                st.bump_sighting(&fid, src, old).unwrap();
            }
        }
        let now = chrono::Utc::now();
        let ttl = Some(chrono::Duration::days(90));
        let fact = st.get_env_fact(&fid, ttl, now).unwrap().unwrap();
        assert_eq!(fact.state, FactState::Candidate);
        let policy = PromotionPolicy::default();
        let per_source = st.sighting_for(&fid).unwrap().unwrap().per_source_counts;
        let gate = |open: &HashSet<EntityRef>, comp: &HashSet<EntityRef>| {
            may_auto_promote(&PromotionContext {
                fact: &fact,
                now,
                open_case_entities: open,
                compromised_entities: comp,
                change_windows: &[],
                per_source_counts: &per_source,
                policy: &policy,
            })
        };
        // Clean: the candidate is promotable end to end (store context + gate).
        assert!(gate(
            &st.open_case_entity_set().unwrap(),
            &st.compromised_entity_set().unwrap()
        ));
        // Open a case ON web01 → the store's open-case set now taints it and the
        // gate hard-blocks: an open case can never teach the Trusted baseline.
        let mut c = Case::open(det("r", "s"));
        c.trigger.event.host = "web01".into();
        st.put_case(&c).unwrap();
        assert!(
            !gate(
                &st.open_case_entity_set().unwrap(),
                &st.compromised_entity_set().unwrap()
            ),
            "an open case on the entity blocks auto-promotion"
        );
    }

    #[test]
    fn compromised_set_honors_a_human_decision_over_the_agent_verdict() {
        // The core-invariant regression the Phase 5 review found: an agent closes
        // a case Benign, then a HUMAN decides Malicious. The human's ground truth
        // must keep the entity out of the promotable set even though case.verdict
        // still reads Benign.
        let (st, _p) = tmp_state();
        let mut c = Case::open(det("r1", "src"));
        c.state = garmr_core::CaseState::Closed;
        c.verdict = Some(garmr_core::Verdict {
            disposition: garmr_core::Disposition::Benign,
            severity: 1,
            confidence: 0.9,
            rationale: "agent thought benign".into(),
            proposed_action: None,
        });
        st.put_case(&c).unwrap();
        // The agent-benign case alone leaves the entity promotable.
        assert!(st.compromised_entity_set().unwrap().is_empty());
        // A human analyst decision of Malicious on that case...
        let mut d: garmr_core::AnalystDecision = serde_json::from_str("{}").unwrap();
        d.decision_id = "d1".into();
        d.case_id = c.id.clone();
        d.disposition = garmr_core::Disposition::Malicious;
        st.append_decision(&d).unwrap();
        // ...now marks the entity compromised (human over agent).
        assert!(
            st.compromised_entity_set()
                .unwrap()
                .contains(&EntityRef::new(EntityKind::Host, "h")),
            "a human Malicious decision must block, even on an agent-closed-benign case"
        );
    }

    #[test]
    fn findings_are_append_only_and_entity_scoped() {
        let (st, _p) = tmp_state();
        let mk = |id: &str, host: &str| garmr_core::SecurityFinding {
            finding_id: id.into(),
            detector: "env-new-edge".into(),
            title: "t".into(),
            base_level: "medium".into(),
            attack: vec![],
            event: {
                let mut e = det("r", "src").event;
                e.host = host.into();
                e
            },
            observed_at: chrono::Utc::now(),
            signals: vec![],
            score: 5.0,
            band: garmr_core::SeverityBand::Medium,
            level: "medium".into(),
            env_basis: Default::default(),
            subject: None,
        };
        st.put_finding(&mk("f1", "web01")).unwrap();
        st.put_finding(&mk("f2", "web01")).unwrap();
        st.put_finding(&mk("f3", "web02")).unwrap();
        assert_eq!(st.list_findings().unwrap().len(), 3);
        assert_eq!(st.findings_for_entity("web01").unwrap().len(), 2);
        assert_eq!(st.findings_for_entity("web02").unwrap().len(), 1);
        assert!(st.findings_for_entity("nope").unwrap().is_empty());
    }

    #[test]
    fn compromised_set_includes_malicious_closed_cases() {
        let (st, _p) = tmp_state();
        // A case closed with a Malicious verdict must keep its entity compromised.
        let mut c = Case::open(det("r1", "src"));
        c.state = garmr_core::CaseState::Closed;
        c.verdict = Some(garmr_core::Verdict {
            disposition: garmr_core::Disposition::Malicious,
            severity: 9,
            confidence: 0.9,
            rationale: "confirmed".into(),
            proposed_action: None,
        });
        st.put_case(&c).unwrap();
        let set = st.compromised_entity_set().unwrap();
        assert!(
            set.contains(&EntityRef::new(EntityKind::Host, "h")),
            "a malicious-closed case keeps its entity out of the promotable set"
        );
    }

    #[test]
    fn delete_cases_removes_only_the_given_ids_idempotently() {
        let (st, path) = tmp_state();
        let mut ids = Vec::new();
        for i in 0..5 {
            let c = Case::open(det(&format!("rule{i}"), "kube-audit"));
            ids.push(c.id.clone());
            st.put_case(&c).unwrap();
        }
        assert_eq!(st.list_cases().unwrap().len(), 5);

        // delete the first two
        assert_eq!(st.delete_cases(&ids[0..2]).unwrap(), 2);
        assert_eq!(st.list_cases().unwrap().len(), 3);

        // idempotent: deleting already-gone ids removes nothing more
        assert_eq!(st.delete_cases(&ids[0..2]).unwrap(), 0);
        assert_eq!(st.list_cases().unwrap().len(), 3);

        // survivors are exactly ids[2..5]
        let mut survivors: Vec<String> =
            st.list_cases().unwrap().into_iter().map(|c| c.id).collect();
        survivors.sort();
        let mut expected: Vec<String> = ids[2..5].to_vec();
        expected.sort();
        assert_eq!(survivors, expected);

        let _ = std::fs::remove_file(&path);
    }
}