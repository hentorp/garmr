// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! The application-audit / insider-risk detection plane, wired into `serve`.
//!
//! [`AppAudit`] bundles the file-loaded access-policy set, resource [`Catalog`],
//! and user-monitoring [`MonitoringRegistry`], and runs the per-audit-event
//! pipeline:
//!
//! ```text
//! gate (is_audit_event?) → project (AuditRecord) → enrich (catalog.stamp)
//!   → evaluate access policy → run application-audit detectors
//!   → lower each SecurityFinding into a Detection (the existing case/triage sink)
//! ```
//!
//! Loaded ONCE at `serve` startup and held for the process lifetime, behind
//! `detect.app_audit_enabled` (it adds per-event CPU on an audit firehose). A
//! non-audit event is rejected by the cheap [`AuditRecord::is_audit_event`]
//! gate, so a non-`pg` firehose pays almost nothing.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};

use garmr_analytics::ensemble::EnsemblePolicy;
use garmr_appdetect::stateful::{StatefulConfig, StatefulDetectors, StatefulState};
use garmr_baseline::{BaselineStore, Entity, PromotionBlock, PromotionGuards};
use garmr_catalog::{Catalog, CatalogEntry};
use garmr_core::{AuditRecord, Detection, Event, RegistryKind, SecurityFinding};
use garmr_monitor::{MonitoringRegistry, UserMonitoringProfile};
use garmr_policy::{Effect, Policy};
use garmr_store::StateStore;

/// Persist the whole baseline store to redb after this many new observations. A
/// crash loses at most this many folds of learning (the audit events themselves
/// are durably in the lakehouse), so learning is cheap-to-lose, never evidence.
const BASELINE_FLUSH_EVERY: u64 = 200;

/// The hot-swappable enforced configuration — everything the per-event stateless
/// prefix reads (the access policies, the resource catalog + its prebuilt object
/// index, and the user-monitoring registry). Rebuilt atomically by
/// [`AppAudit::reload`] and swapped in behind the `config` lock, so a governance
/// change takes effect WITHOUT restarting `serve`. A reader holds an `Arc`
/// snapshot for the life of one event, so a swap never tears a single evaluation.
struct ConfigSet {
    policies: Vec<Policy>,
    catalog: Catalog,
    /// Prebuilt name index over `catalog`, so the per-event object stamp is
    /// O(matching entries) instead of a full O(entries) scan. Recomputed whenever
    /// the catalog changes (i.e. on every rebuild).
    catalog_index: garmr_catalog::ObjectIndex,
    monitoring: MonitoringRegistry,
}

impl ConfigSet {
    /// Build the enforced config from files and/or the governed registry, honoring
    /// the per-domain `GARMR_REGISTRY_*` gates. The single source of truth for both
    /// the initial [`AppAudit::load`] and every [`AppAudit::reload`].
    fn build(
        policies_dir: &Path,
        catalog_file: Option<&Path>,
        monitoring_file: Option<&Path>,
        state: Option<&StateStore>,
    ) -> ConfigSet {
        let policies = if registry_backed_policies() {
            state.map(active_policies_from_registry).unwrap_or_default()
        } else {
            load_policies(policies_dir)
        };
        let catalog = if registry_backed_catalog() {
            state.map(active_catalog_from_registry).unwrap_or_default()
        } else {
            catalog_file.map(load_catalog).unwrap_or_default()
        };
        let monitoring = if registry_backed_monitoring() {
            state
                .map(active_monitoring_from_registry)
                .unwrap_or_default()
        } else {
            monitoring_file.map(load_monitoring).unwrap_or_default()
        };
        let catalog_index = catalog.object_index();
        ConfigSet {
            policies,
            catalog,
            catalog_index,
            monitoring,
        }
    }
}

/// The loaded application-audit plane, held for the `serve` lifetime.
pub struct AppAudit {
    /// The hot-swappable enforced config (see [`ConfigSet`]). Read once per event
    /// via a cheap `Arc` clone on the parallel `prepare_event` path (concurrent
    /// readers; the lock is contended only by the rare [`reload`](Self::reload)).
    config: RwLock<Arc<ConfigSet>>,
    /// The inputs [`reload`](Self::reload) re-reads to rebuild the config (files
    /// and/or the governed registry, per the `GARMR_REGISTRY_*` gates).
    policies_dir: PathBuf,
    catalog_file: Option<PathBuf>,
    monitoring_file: Option<PathBuf>,
    /// Phase 7/8 behavioral baselines. Interior-mutable: every audit event both
    /// queries the Trusted profiles (detect) and folds itself into the Candidate
    /// profiles (learn). Serialized to `state` on a flush interval.
    baselines: RwLock<BaselineStore>,
    /// Phase 8 stateful (cross-event) detector plane: bounded per-actor windows
    /// for low-and-slow / sequential enumeration, split-bulk extraction, denied
    /// probing, and cross-domain access. Interior-mutable and updated in the same
    /// serial, event-ordered `finish_event` tail as the baselines. Serialized to
    /// `state` on the flush interval so an in-progress episode survives a restart.
    stateful: RwLock<StatefulDetectors>,
    /// State store for persisting the baselines (None in unit tests).
    state: Option<StateStore>,
    /// New observations since the last flush.
    dirty: AtomicU64,
    /// Ensemble fusion coefficients (shared tuning with the env-edge plane).
    ensemble: EnsemblePolicy,
    /// DoD 19 champion/challenger **shadow-evaluation** plane. `None` unless
    /// `GARMR_SHADOW` is set AND a `DetectorConfig` challenger is live on the
    /// `shadow` channel; when present, each event is scored through a second
    /// (challenger) stateful config and the champion-vs-challenger diff is
    /// recorded. A pure observer — it NEVER alters a champion detection or a case.
    shadow: RwLock<Option<crate::shadow::ShadowPlane>>,
}

/// The pure, per-event-independent product of [`AppAudit::prepare_event`] —
/// everything computed WITHOUT the baseline lock, carried across the ingest
/// fan-out to [`AppAudit::finish_event`]. All fields are owned (`Send`) so the
/// value crosses a gatling worker boundary with no borrow of `AppAudit`.
pub struct PreparedAudit {
    /// The projected + catalog-enriched audit record.
    rec: AuditRecord,
    /// Policy decision was `Deny` — never fold a forbidden access into baselines.
    forbidden: bool,
    /// Access outcome was negative (failed) — never learn a failure as normal.
    failed: bool,
    /// Findings from the stateless (record + policy) detectors.
    findings: Vec<SecurityFinding>,
    /// Asset-criticality for the ensemble crit multiplier.
    criticality: f32,
    /// Display asset_role fallback (the record's data_classification).
    asset_role: Option<String>,
    /// Monitoring severity-band multiplier (>= 1.0), monotonic-up.
    monitor_mult: f64,
}

impl AppAudit {
    /// Load policies (a dir of `*.toml`), the catalog (one TOML file), and the
    /// monitoring profiles (one JSON file) from config, plus the persisted
    /// behavioral baselines from `state`. Missing/empty inputs yield empty
    /// defaults — the record-derived detectors still fire; the whole plane is
    /// gated by `app_audit_enabled`.
    pub fn load(
        cfg: &garmr_core::DetectConfig,
        ensemble: EnsemblePolicy,
        state: Option<StateStore>,
    ) -> Self {
        // Phase A: the enforced config (policies + catalog + monitoring) comes from
        // files and/or the governed registry per the GARMR_REGISTRY_* gates, built
        // once here and held behind a swap lock so `reload` can install a new set
        // without a restart. Default (all gates unset) keeps the file loaders, so
        // the live deployment is unchanged until an operator migrates.
        let config = ConfigSet::build(
            &cfg.policies_dir,
            cfg.catalog_file.as_deref(),
            cfg.monitoring_file.as_deref(),
            state.as_ref(),
        );
        let baselines = state.as_ref().and_then(load_baselines).unwrap_or_default();
        let stateful_cfg = StatefulConfig::default();
        let stateful = state
            .as_ref()
            .and_then(load_stateful)
            .map(|s| StatefulDetectors::from_state(stateful_cfg.clone(), s))
            .unwrap_or_else(|| StatefulDetectors::new(stateful_cfg));
        // DoD 19: the shadow challenger, if one is live on the `shadow` channel
        // (and GARMR_SHADOW is set) — seeded with the persisted counters iff they
        // belong to the same challenger, and with the champion's CURRENT windows so
        // the comparison is fair from the first event. `None` (inert) by default;
        // the champion-state clone is only paid when the plane is enabled.
        let shadow = match state.as_ref() {
            Some(st) if crate::shadow::shadow_enabled() => crate::shadow::load_shadow_challenger(
                st,
                load_shadow_summary(st),
                stateful.state().clone(),
            ),
            _ => None,
        };
        tracing::info!(
            policies = config.policies.len(),
            catalog_entries = config.catalog.entries.len(),
            monitoring_profiles = config.monitoring.profiles().len(),
            baseline_profiles = baselines.len(),
            stateful_actors = stateful.tracked_actors(),
            "application-audit detection plane loaded"
        );
        AppAudit {
            config: RwLock::new(Arc::new(config)),
            policies_dir: cfg.policies_dir.clone(),
            catalog_file: cfg.catalog_file.clone(),
            monitoring_file: cfg.monitoring_file.clone(),
            baselines: RwLock::new(baselines),
            stateful: RwLock::new(stateful),
            state,
            dirty: AtomicU64::new(0),
            ensemble,
            shadow: RwLock::new(shadow),
        }
    }

    /// A cheap `Arc` snapshot of the enforced config, for one event's evaluation.
    /// The RwLock is held only for the clone (concurrent readers), so the parallel
    /// `prepare_event` path never serializes on it; a [`reload`](Self::reload)
    /// swaps a fresh `Arc` in without tearing any in-flight evaluation.
    fn config(&self) -> Arc<ConfigSet> {
        self.config
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// Rebuild the enforced config (policies + catalog + monitoring) from its
    /// sources and swap it in atomically — a governance change (a registry
    /// promotion, or a policy-file edit) takes effect WITHOUT restarting `serve`.
    /// Learning state (baselines, stateful windows) is untouched. Returns the new
    /// `(policies, catalog entries, monitoring profiles)` counts.
    pub fn reload(&self) -> (usize, usize, usize) {
        let fresh = ConfigSet::build(
            &self.policies_dir,
            self.catalog_file.as_deref(),
            self.monitoring_file.as_deref(),
            self.state.as_ref(),
        );
        let counts = (
            fresh.policies.len(),
            fresh.catalog.entries.len(),
            fresh.monitoring.profiles().len(),
        );
        *self.config.write().unwrap_or_else(|e| e.into_inner()) = Arc::new(fresh);
        tracing::info!(
            policies = counts.0,
            catalog_entries = counts.1,
            monitoring_profiles = counts.2,
            "application-audit config hot-reloaded"
        );
        counts
    }

    /// Auto-reload hook for a governed-kind registry promotion. Reloads (and
    /// returns the new `(policies, catalog entries, monitoring profiles)` counts)
    /// only when the promotion actually changes what THIS plane enforces — a
    /// config-consuming domain (policy / catalog / monitoring) that is
    /// registry-backed, on the `production` channel enforcement composes from. For
    /// any other kind / channel, or a domain still loading from files, it is a
    /// no-op returning `None` (the promotion is recorded but enforcement is
    /// unchanged), so the promotion path need not special-case which kinds matter.
    pub fn reload_if_governed(
        &self,
        kind: RegistryKind,
        channel: &str,
    ) -> Option<(usize, usize, usize)> {
        // DoD 19: a DetectorConfig promotion on the `shadow` channel swaps the
        // challenger plane — orthogonal to the enforced production config, so it
        // never rebuilds enforcement (returns None below) but does hot-swap the
        // shadow evaluator.
        if kind == RegistryKind::DetectorConfig && channel == crate::shadow::SHADOW_CHANNEL {
            self.reload_shadow();
        }
        promotion_touches_enforcement(kind, channel, env_registry_gate).then(|| self.reload())
    }

    /// Rebuild the DoD-19 shadow challenger from the registry — called when a
    /// `DetectorConfig` promotion on the `shadow` channel changes which challenger
    /// is live (a new one, a rollback, or a retirement clears it). The loader
    /// seeds counters from the persisted summary only for the SAME challenger
    /// identity, so promoting a new challenger starts its comparison fresh.
    /// A no-op when `GARMR_SHADOW` is unset or `serve` has no state store.
    pub fn reload_shadow(&self) {
        let Some(state) = &self.state else { return };
        // Skip the champion-state clone entirely when the plane is disabled, and
        // clear any existing challenger.
        if !crate::shadow::shadow_enabled() {
            *self.shadow.write().unwrap_or_else(|e| e.into_inner()) = None;
            return;
        }
        // Snapshot the champion's current windows (stateful read released before the
        // shadow write — preserves the baselines→stateful→shadow lock order) to seed
        // the challenger, so a (re)loaded challenger starts fair, not cold.
        let champion_state = {
            let sd = self.stateful.read().unwrap_or_else(|e| e.into_inner());
            sd.state().clone()
        };
        let fresh = crate::shadow::load_shadow_challenger(
            state,
            load_shadow_summary(state),
            champion_state,
        );
        let active = fresh.as_ref().map(|p| (p.name.clone(), p.version.clone()));
        *self.shadow.write().unwrap_or_else(|e| e.into_inner()) = fresh;
        match active {
            Some((n, v)) => {
                tracing::info!(challenger = %n, version = %v, "shadow challenger reloaded")
            }
            None => tracing::info!("shadow challenger cleared (none live on the shadow channel)"),
        }
    }

    /// A snapshot of the shadow-evaluation summary (DoD 19), or `None` when no
    /// challenger is live.
    pub fn shadow_summary(&self) -> Option<crate::shadow::ShadowSummary> {
        self.shadow
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            .map(|p| p.summary())
    }

    /// The most recent champion-vs-challenger disagreement examples (newest first),
    /// capped at `limit`. Empty when no challenger is live.
    pub fn shadow_recent(&self, limit: usize) -> Vec<crate::shadow::ShadowScore> {
        self.shadow
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            .map(|p| p.recent(limit))
            .unwrap_or_default()
    }

    /// Run the per-event application-audit pipeline, returning zero or more
    /// `Detection`s (already lowered from findings) for the case/triage sink. A
    /// non-audit event returns an empty vec via the cheap gate.
    ///
    /// Kept as the serial single-event entry point (tests, non-firehose callers);
    /// the ingest firehose splits it into [`prepare_event`](Self::prepare_event)
    /// (fanned across cores) + [`finish_event`](Self::finish_event) (serial,
    /// ordered) so the CPU-heavy stateless prefix saturates the box while the
    /// baseline learning stays strictly ordered.
    ///
    /// The firehose no longer calls this (it uses the split directly), so in a
    /// non-test build it is the retained serial entry point for future
    /// non-firehose callers; tests exercise it as the reference serial path.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn detect_event(&self, ev: &Event, collector_id: Option<&str>) -> Vec<Detection> {
        match self.prepare_event(ev, collector_id) {
            Some(prep) => self.finish_event(ev, prep),
            None => Vec::new(),
        }
    }

    /// **Stage A (pure, parallel-safe).** The CPU-heavy, per-event-independent
    /// prefix: gate → project (`AuditRecord`) → enrich (`catalog.stamp`) →
    /// evaluate access policy → stateless detectors → monitoring multiplier +
    /// asset-criticality. Touches only immutable, post-load state (`policies`,
    /// `catalog`, `monitoring`) — **no baseline lock** — so it runs across every
    /// core in the ingest fan-out. Returns `None` for a non-audit event (the
    /// cheap gate). The stateful behavioral read+observe is deferred to
    /// [`finish_event`](Self::finish_event).
    ///
    /// `collector_id` is the AUTHENTICATED collector attribution stamped on the
    /// event at ingest (Phase 12 source-trust). #14: the app-audit / insider-risk
    /// plane draws conclusions about *people* from access records, so it must only
    /// ever run on events whose provenance a trusted collector vouched for. An
    /// audit event with NO authenticated collector (`None`/empty) is therefore
    /// SHORT-CIRCUITED here — no prepared audit, no detectors, no baseline fold —
    /// rather than evaluated on unattributed data. NOTE (fail-closed by design):
    /// in a default-off deployment with no collectors configured, every event
    /// arrives with a NULL collector_id, so this SILENCES the whole app-audit
    /// plane. That is deliberate: authenticated ingest is a prerequisite for this
    /// plane, never a best-effort add-on — an unauthenticated firehose must not be
    /// able to manufacture insider-risk cases against named actors.
    pub fn prepare_event(&self, ev: &Event, collector_id: Option<&str>) -> Option<PreparedAudit> {
        if !AuditRecord::is_audit_event(ev) {
            return None;
        }
        // Require authenticated collector attribution for every audit event on the
        // live path (#14). Treat an empty id as unauthenticated too, so a blank
        // stamp cannot pass the gate.
        match collector_id {
            Some(c) if !c.is_empty() => {}
            _ => return None,
        }
        // One consistent snapshot of the enforced config for this whole event
        // (a cheap Arc clone); a concurrent `reload` swap never tears it.
        let cfg = self.config();
        let mut rec = AuditRecord::from_event(ev);
        // Enrich in place: stamp data_classification / sensitive_resource from
        // Trusted catalog entries so the policy + detectors can key on them.
        // Via the prebuilt index (O(matching entries), not a full O(entries) scan)
        // — byte-identical to `catalog.stamp`, proven by
        // `object_index_matches_linear_resolve`.
        cfg.catalog_index.stamp(&cfg.catalog.entries, &mut rec);
        let ctx = garmr_policy::context_from_event(ev, &rec);
        let decision = garmr_policy::evaluate(&ctx, &cfg.policies);
        let objects = ctx.objects.clone();

        // Stateless (record + policy) detectors.
        let findings = garmr_appdetect::detect_access(ev, &rec, &decision, ev.field("event_id"));

        // Asset-criticality + display asset_role, and the monitoring multiplier —
        // all pure functions of the record / the config snapshot, so precomputed
        // here and applied/consumed serially in `finish_event`.
        let criticality = garmr_appdetect::classification_criticality(&rec);
        let asset_role = rec.classification.data_classification.clone();
        let monitor_mult = cfg.monitoring.multiplier_for_access(&rec, &objects, ev.ts);
        let forbidden = decision.decision == Effect::Deny;
        let failed = rec.action.outcome.is_negative();

        Some(PreparedAudit {
            rec,
            forbidden,
            failed,
            findings,
            criticality,
            asset_role,
            monitor_mult,
        })
    }

    /// **Stage B (serial, ordered).** Consumes a [`PreparedAudit`] and does the
    /// one part that carries a within-batch dependency: query the TRUSTED
    /// baselines for this access and fold it into the CANDIDATE baselines — but
    /// NEVER learn a forbidden (policy `Deny`) or failed access as normal
    /// behavior (the core invariant: a forbidden action is never legitimized by
    /// frequency). Run in event order so a later event sees an earlier event's
    /// `observe`, identical to the old serial loop; the baseline write lock makes
    /// this the fan-out's ordered tail. Then stamp criticality and fuse.
    pub fn finish_event(&self, ev: &Event, prep: PreparedAudit) -> Vec<Detection> {
        let PreparedAudit {
            rec,
            forbidden,
            failed,
            mut findings,
            criticality,
            asset_role,
            monitor_mult,
        } = prep;

        {
            let mut store = self.baselines.write().unwrap_or_else(|e| e.into_inner());
            findings.extend(garmr_appdetect::detect_behavioral(
                ev,
                &rec,
                &store,
                ev.field("event_id"),
            ));
            // Phase 8 stateful (cross-event) detectors — run in the same serial,
            // event-ordered tail so per-actor windows advance exactly once per
            // access, in event order. A forbidden/failed access still feeds the
            // denied-probing detector (its signal) but is never counted as a
            // successful sensitive read by the enumeration/bulk detectors.
            {
                let mut sd = self.stateful.write().unwrap_or_else(|e| e.into_inner());
                let champ_stateful = sd.observe(ev, &rec, forbidden, failed);
                // Commit the champion findings BEFORE the challenger runs — the
                // challenger is then a pure observer *structurally*, not just by
                // convention: it cannot drop a champion detection even by panicking.
                findings.extend(champ_stateful.iter().cloned());
                // DoD 19 shadow evaluation: score the SAME event through the
                // challenger and record the champion-vs-challenger diff. The lock
                // body runs only when a challenger is live; the challenger observe
                // is wrapped in `catch_unwind` so a panicking challenger detector can
                // only DISABLE the shadow plane (logged), never poison the lock or
                // unwind the event pipeline. Champion output is already committed.
                let mut shadow = self.shadow.write().unwrap_or_else(|e| e.into_inner());
                if shadow.is_some() {
                    let scored = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        shadow.as_mut().expect("checked is_some").observe(
                            ev,
                            &rec,
                            forbidden,
                            failed,
                            &champ_stateful,
                        );
                    }));
                    if scored.is_err() {
                        tracing::error!(
                            "shadow challenger panicked scoring an event; disabling the shadow plane (champion unaffected)"
                        );
                        *shadow = None;
                    }
                }
            }
            if !forbidden && !failed {
                store.observe(&rec, ev.ts, &ev.source);
                if (self.dirty.fetch_add(1, Ordering::Relaxed) + 1) % BASELINE_FLUSH_EVERY == 0 {
                    self.flush_locked(&store);
                }
            }
        }

        // Stamp asset-criticality (drives the ensemble crit_mult) + a display
        // asset_role onto every raw finding before fusion.
        for f in &mut findings {
            f.env_basis.criticality = criticality;
            if f.env_basis.asset_role.is_none() {
                f.env_basis.asset_role = asset_role.clone();
            }
        }

        // Fuse: deterministic policy findings + standalone-notable findings each
        // stay their own case; the weak behavioral indicators for THIS access are
        // corroborated into one `app-insider-risk` finding whose confidence
        // reflects how many co-fired. Preserves policy≠anomaly + monotonic-up.
        // Monitoring only RAISES attention (multiplier >= 1.0); it never
        // suppresses — a monotonic-up multiplier on the SEVERITY BAND.
        garmr_analytics::ensemble::fuse_access(
            findings,
            &self.ensemble,
            garmr_appdetect::is_deterministic_policy,
            garmr_appdetect::is_standalone,
            monitor_mult,
        )
        .into_iter()
        .map(|f| f.into_detection())
        .collect()
    }

    /// Serialize + persist the baseline store AND the stateful-detector state.
    /// Called on the flush interval and on shutdown; a persistence error is
    /// logged, never fatal (both are reconstructible from the durable audit
    /// stream — they are cheap-to-lose learning, never evidence).
    fn flush_locked(&self, store: &BaselineStore) {
        let Some(state) = &self.state else { return };
        match serde_json::to_vec(store) {
            Ok(bytes) => {
                if let Err(e) = state.put_app_baselines(&bytes) {
                    tracing::warn!(error = %e, "failed to persist app-audit baselines");
                } else {
                    self.dirty.store(0, Ordering::Relaxed);
                }
            }
            Err(e) => tracing::warn!(error = %e, "failed to serialize app-audit baselines"),
        }
        // Persist the stateful-detector windows (consistent lock order: the
        // baseline lock is held by the caller; we take the stateful read lock).
        let sd = self.stateful.read().unwrap_or_else(|e| e.into_inner());
        match serde_json::to_vec(sd.state()) {
            Ok(bytes) => {
                if let Err(e) = state.put_app_stateful(&bytes) {
                    tracing::warn!(error = %e, "failed to persist app-audit stateful state");
                }
            }
            Err(e) => tracing::warn!(error = %e, "failed to serialize app-audit stateful state"),
        }
        // DoD 19: persist the shadow-evaluation summary counters (the durable
        // decision signal) when a challenger is live. Cheap single-key blob.
        let shadow = self.shadow.read().unwrap_or_else(|e| e.into_inner());
        if let Some(plane) = shadow.as_ref() {
            match serde_json::to_vec(&plane.summary()) {
                Ok(bytes) => {
                    if let Err(e) = state.put_app_shadow_summary(&bytes) {
                        tracing::warn!(error = %e, "failed to persist shadow-evaluation summary");
                    }
                }
                Err(e) => {
                    tracing::warn!(error = %e, "failed to serialize shadow-evaluation summary")
                }
            }
        }
    }

    /// Flush the baselines to the state store (call on graceful shutdown).
    pub fn flush(&self) {
        let store = self.baselines.read().unwrap_or_else(|e| e.into_inner());
        self.flush_locked(&store);
    }

    /// Promote an entity's behavioral baseline to Trusted (analyst action). Only
    /// then do its behavioral detectors fire. Hard blocks (open case / compromise
    /// / policy violation / parser integrity) are inviolable; on success the
    /// store is persisted immediately.
    pub fn promote_baseline(
        &self,
        entity: &Entity,
        guards: PromotionGuards,
    ) -> Result<(), Vec<PromotionBlock>> {
        let mut store = self.baselines.write().unwrap_or_else(|e| e.into_inner());
        let r = store.promote(entity, true, guards);
        if r.is_ok() {
            self.flush_locked(&store);
        }
        r
    }

    /// The hard/threshold blocks that WOULD prevent promoting `entity` right now,
    /// WITHOUT mutating — so the admin API can audit fail-closed before applying
    /// (empty ⇒ allowed). Analyst semantics (threshold blocks are clearable).
    pub fn promotion_blocks(
        &self,
        entity: &Entity,
        guards: PromotionGuards,
    ) -> Vec<PromotionBlock> {
        self.baselines
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .promotion_blocks(entity, true, guards)
    }

    /// Entities whose baseline is still a **Candidate** — the auto-promote pass's
    /// work-list (Trusted/Suspicious/Retired are excluded). Restricted to the
    /// ACTOR kinds the behavioral detectors actually consult (User /
    /// ServiceAccount, via `actor_entity`): an Application/Role/PeerGroup baseline
    /// is never read by a detector today AND `baseline_guards` can't match a case
    /// to it (its hard blocks would be dead), so it is deliberately NOT
    /// auto-promoted — that must wait until a detector consults it and its guards
    /// are wired.
    pub fn candidate_baselines(&self) -> Vec<Entity> {
        use garmr_baseline::{BaselineState, EntityKind};
        let store = self.baselines.read().unwrap_or_else(|e| e.into_inner());
        store
            .profiles()
            .filter(|p| p.state == BaselineState::Candidate)
            .filter(|p| matches!(p.entity.kind, EntityKind::User | EntityKind::ServiceAccount))
            .map(|p| Entity::new(p.entity.kind, p.entity.id.clone()))
            .collect()
    }

    /// The blocks that WOULD prevent an AUTOMATIC promotion of `entity` (empty ⇒
    /// safe to auto-promote). Auto semantics: BOTH the inviolable hard blocks AND
    /// the maturity thresholds must be clear — an auto-promote never clears a
    /// threshold the way an analyst can.
    pub fn auto_promotion_blocks(
        &self,
        entity: &Entity,
        guards: PromotionGuards,
    ) -> Vec<PromotionBlock> {
        self.baselines
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .promotion_blocks(entity, false, guards)
    }

    /// Promote `entity` AUTOMATICALLY (no analyst): the gate must be fully clear
    /// (`may_auto_promote` — hard blocks AND thresholds). Returns whether it was
    /// promoted; persists on success. The caller MUST fail-closed audit first.
    pub fn auto_promote_baseline(&self, entity: &Entity, guards: PromotionGuards) -> bool {
        let mut store = self.baselines.write().unwrap_or_else(|e| e.into_inner());
        let ok = store.promote(entity, false, guards).is_ok();
        if ok {
            self.flush_locked(&store);
        }
        ok
    }

    /// Mark an entity's baseline Suspicious (it stops answering detector queries);
    /// persisted immediately.
    pub fn suspect_baseline(&self, entity: &Entity) {
        let mut store = self.baselines.write().unwrap_or_else(|e| e.into_inner());
        store.mark_suspicious(entity);
        self.flush_locked(&store);
    }

    /// Clear a Suspicious marking after review (→ Candidate, re-learns);
    /// persisted immediately.
    pub fn clear_baseline(&self, entity: &Entity) {
        let mut store = self.baselines.write().unwrap_or_else(|e| e.into_inner());
        store.clear_suspicion(entity);
        self.flush_locked(&store);
    }

    /// A clone of the current baseline store (for the admin/list surface).
    pub fn baseline_snapshot(&self) -> BaselineStore {
        self.baselines
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// Enrich a projected record in place with the Trusted catalog's
    /// classifications — byte-identical to the stamp the ingest pipeline applies
    /// in [`prepare_event`](Self::prepare_event). Exposed so the policy-simulation
    /// endpoint can replay historical accesses with the SAME classification a live
    /// evaluation would see (a classification-scoped policy would otherwise never
    /// match in a simulation over un-stamped records).
    pub fn stamp_record(&self, rec: &mut AuditRecord) {
        let cfg = self.config();
        cfg.catalog_index.stamp(&cfg.catalog.entries, rec);
    }

    /// A clone of the ENFORCED resource catalog (the same set `stamp_record` uses),
    /// so a read surface can list resources that reflect exactly what classifies
    /// live traffic — file-loaded or registry-backed, honoring the hot-reload/
    /// `GARMR_REGISTRY_CATALOG` gate. Mirrors [`baseline_snapshot`](Self::baseline_snapshot):
    /// clone out under the read lock, never hand out a borrow of the swap cell.
    pub fn catalog_snapshot(&self) -> Catalog {
        self.config().catalog.clone()
    }

    /// A clone of the ENFORCED access-policy set (what the plane actually evaluates),
    /// so a read surface can report per-resource policy coverage against the live
    /// rules rather than re-reading files (which can drift under the registry gate).
    pub fn policy_snapshot(&self) -> Vec<Policy> {
        self.config().policies.clone()
    }
}

/// The set of entity ids the system considers COMPROMISED — a fact whose current
/// audited transition is Suspicious/KnownMalicious, OR any case adjudged
/// Suspicious-or-worse (agent verdict / analyst decision / incident outcome)
/// REGARDLESS of case state. Reuses the environment model's poison-door-closing
/// source ([`garmr_store::StateStore::compromised_entity_set`]); flattened to ids
/// so a baseline actor id can be matched against it. Over-matching only ever
/// BLOCKS an auto-promotion, so a coincidental id collision is fail-safe.
pub(crate) fn compromised_ids(state: &StateStore) -> std::collections::HashSet<String> {
    state
        .compromised_entity_set()
        .unwrap_or_default()
        .into_iter()
        .map(|e| e.id)
        .collect()
}

/// Derive the [`PromotionGuards`] for `entity` — the single source of truth for
/// the admin promote path (one-shot; recomputes the sets). See
/// [`baseline_guards_from`] for the loop's precomputed-sets variant.
pub(crate) fn baseline_guards(state: &StateStore, entity: &Entity) -> PromotionGuards {
    let cases = state.list_cases().unwrap_or_default();
    let compromised = compromised_ids(state);
    baseline_guards_from(&cases, &compromised, entity)
}

/// Derive the [`PromotionGuards`] for `entity` from precomputed system state: an
/// open (non-closed) case touching the entity, a forbidden-access case for it, or
/// an entity the system holds COMPROMISED is an inviolable hard block — a
/// forbidden action can never be learned as normal, and an entity under
/// investigation / adjudged malicious (even after its case is CLOSED) is never
/// auto-trusted. This closes the same poison door the environment auto-promote
/// loop guards: a closed-but-malicious verdict must not re-open trust.
pub(crate) fn baseline_guards_from(
    cases: &[garmr_core::Case],
    compromised_ids: &std::collections::HashSet<String>,
    entity: &Entity,
) -> PromotionGuards {
    let mut g = PromotionGuards {
        entity_compromised: compromised_ids.contains(&entity.id),
        ..Default::default()
    };
    for c in cases {
        let rec = AuditRecord::from_event(&c.trigger.event);
        if garmr_baseline::actor_entity(&rec).as_ref() != Some(entity) {
            continue;
        }
        if c.state != garmr_core::CaseState::Closed {
            g.entity_has_open_case = true;
        }
        if c.trigger.rule_id == "app-forbidden-access" {
            g.policy_violation_in_window = true;
        }
    }
    g
}

/// Load + deserialize the persisted baseline store; a corrupt/absent blob yields
/// `None` (fresh start) rather than a crash.
fn load_baselines(state: &StateStore) -> Option<BaselineStore> {
    let bytes = state.get_app_baselines().ok().flatten()?;
    match serde_json::from_slice::<BaselineStore>(&bytes) {
        Ok(s) => Some(s),
        Err(e) => {
            tracing::warn!(error = %e, "persisted app-audit baselines unparseable; starting fresh");
            None
        }
    }
}

/// Load + deserialize the persisted stateful-detector state; a corrupt/absent
/// blob yields `None` (fresh start) rather than a crash.
fn load_stateful(state: &StateStore) -> Option<StatefulState> {
    let bytes = state.get_app_stateful().ok().flatten()?;
    match serde_json::from_slice::<StatefulState>(&bytes) {
        Ok(s) => Some(s),
        Err(e) => {
            tracing::warn!(error = %e, "persisted app-audit stateful state unparseable; starting fresh");
            None
        }
    }
}

/// Load + deserialize the persisted DoD-19 shadow-evaluation summary; a
/// corrupt/absent blob yields `None` (the challenger's counters start fresh).
fn load_shadow_summary(state: &StateStore) -> Option<crate::shadow::ShadowSummary> {
    let bytes = state.get_app_shadow_summary().ok().flatten()?;
    match serde_json::from_slice::<crate::shadow::ShadowSummary>(&bytes) {
        Ok(s) => Some(s),
        Err(e) => {
            tracing::warn!(error = %e, "persisted shadow-evaluation summary unparseable; starting fresh");
            None
        }
    }
}

/// True when the operator has opted the access-policy set into the governed
/// registry (`GARMR_REGISTRY_POLICIES=1`). Off by default — the file loader stays
/// the source of truth until a deployment migrates.
fn registry_backed_policies() -> bool {
    matches!(
        std::env::var("GARMR_REGISTRY_POLICIES").ok().as_deref(),
        Some("1" | "true" | "yes")
    )
}

/// Compose the ACTIVE access-policy set from the governed registry: for each
/// distinct `Policy` name, the record the promotion stream currently points at on
/// the `production` channel (approved + audit-bound — [`registry::active`] returns
/// `None` for a retired, non-approved, or un-audited pointer), with its `spec`
/// deserialized back into a [`Policy`]. This is the registry-backed alternative to
/// [`load_policies`]: policies gain the same versioning / approval / rollback /
/// audit lineage the model + prompt registry already gives every other artifact,
/// and `GET /api/policies` (which reads the same set) then reflects exactly what is
/// enforced. A record whose `spec` no longer deserializes to a `Policy` is skipped
/// loudly rather than faulting the whole load.
fn active_policies_from_registry(state: &StateStore) -> Vec<Policy> {
    let records = state.list_kind(RegistryKind::Policy).unwrap_or_default();
    let promotions = state.list_promotions().unwrap_or_default();
    let mut names: Vec<&str> = records.iter().map(|r| r.name.as_str()).collect();
    names.sort_unstable();
    names.dedup();
    let mut out = Vec::new();
    for name in names {
        let Some(rec) = garmr_core::active(
            RegistryKind::Policy,
            name,
            "production",
            &records,
            &promotions,
        ) else {
            continue; // no live (approved, audit-bound) version for this name
        };
        match serde_json::from_value::<Policy>(rec.spec.clone()) {
            Ok(p) => out.push(p),
            Err(e) => tracing::warn!(
                policy = name,
                version = %rec.version,
                error = %e,
                "active registry policy record has an unparseable spec; skipping"
            ),
        }
    }
    out
}

/// True when the resource catalog is opted into the governed registry
/// (`GARMR_REGISTRY_CATALOG=1`). Off by default — the TOML loader stays the source
/// of truth until a deployment migrates.
fn registry_backed_catalog() -> bool {
    matches!(
        std::env::var("GARMR_REGISTRY_CATALOG").ok().as_deref(),
        Some("1" | "true" | "yes")
    )
}

/// Compose the resource [`Catalog`] from the governed registry: for each distinct
/// catalog-entry name, the [`registry::active`] (approved + audit-bound) record on
/// the `production` channel, its `spec` deserialized into a [`CatalogEntry`] and
/// treated as **Trusted** — the registry promotion is the operator's vouching,
/// exactly like [`load_catalog`] promotes every file entry with `promote`. So the
/// live entries actually resolve (resolution reads Trusted only), with the version
/// / approval / rollback / audit lineage the registry gives every artifact.
fn active_catalog_from_registry(state: &StateStore) -> Catalog {
    let records = state.list_kind(RegistryKind::Catalog).unwrap_or_default();
    let promotions = state.list_promotions().unwrap_or_default();
    let mut names: Vec<&str> = records.iter().map(|r| r.name.as_str()).collect();
    names.sort_unstable();
    names.dedup();
    let mut entries = Vec::new();
    for name in names {
        let Some(rec) = garmr_core::active(
            RegistryKind::Catalog,
            name,
            "production",
            &records,
            &promotions,
        ) else {
            continue;
        };
        match serde_json::from_value::<CatalogEntry>(rec.spec.clone()) {
            Ok(mut e) => {
                // The audit-bound registry promotion vouches for the entry — treat
                // it as Trusted so it resolves (mirrors the file-import promote).
                e.promote("registry");
                entries.push(e);
            }
            Err(err) => tracing::warn!(
                entry = name,
                version = %rec.version,
                error = %err,
                "active registry catalog record has an unparseable spec; skipping"
            ),
        }
    }
    Catalog::new(entries)
}

/// True when user-monitoring is opted into the governed registry
/// (`GARMR_REGISTRY_MONITORING=1`). Off by default — the JSON loader stays the
/// source of truth until a deployment migrates.
fn registry_backed_monitoring() -> bool {
    matches!(
        std::env::var("GARMR_REGISTRY_MONITORING").ok().as_deref(),
        Some("1" | "true" | "yes")
    )
}

/// Map a governed application-audit domain to its live `GARMR_REGISTRY_*` gate
/// (false for every non-config kind). This is the production gate injected into
/// [`promotion_touches_enforcement`].
fn env_registry_gate(kind: RegistryKind) -> bool {
    match kind {
        RegistryKind::Policy => registry_backed_policies(),
        RegistryKind::Catalog => registry_backed_catalog(),
        RegistryKind::Monitoring => registry_backed_monitoring(),
        _ => false,
    }
}

/// The pure decision behind [`AppAudit::reload_if_governed`]: does a promotion of
/// `kind` on `channel` change what the plane enforces? True only for a
/// config-consuming domain (policy / catalog / monitoring) whose gate `backed`
/// reports on, on the `production` channel enforcement composes from — applications
/// and resources are storable governed kinds with no engine consumer yet, and a
/// non-production promotion never touches the active set. The gate is injected so
/// the whole matrix is unit-testable without process env.
fn promotion_touches_enforcement(
    kind: RegistryKind,
    channel: &str,
    backed: impl Fn(RegistryKind) -> bool,
) -> bool {
    matches!(
        kind,
        RegistryKind::Policy | RegistryKind::Catalog | RegistryKind::Monitoring
    ) && channel == "production"
        && backed(kind)
}

/// Compose the [`MonitoringRegistry`] from the governed registry: for each distinct
/// monitoring-profile name, the [`registry::active`] (approved + audit-bound) record
/// on the `production` channel, its `spec` deserialized into a
/// [`UserMonitoringProfile`]. Unlike the catalog there is no Trusted marking —
/// being the *live* registry record already means the monitoring is in effect (the
/// profile's own expiry/window still governs at runtime, and monitoring only ever
/// RAISES attention, never declares guilt). So starting/modifying/ending monitoring
/// becomes a register + audited promotion / rollback, with full version history.
fn active_monitoring_from_registry(state: &StateStore) -> MonitoringRegistry {
    let records = state
        .list_kind(RegistryKind::Monitoring)
        .unwrap_or_default();
    let promotions = state.list_promotions().unwrap_or_default();
    let mut names: Vec<&str> = records.iter().map(|r| r.name.as_str()).collect();
    names.sort_unstable();
    names.dedup();
    let mut profiles = Vec::new();
    for name in names {
        let Some(rec) = garmr_core::active(
            RegistryKind::Monitoring,
            name,
            "production",
            &records,
            &promotions,
        ) else {
            continue;
        };
        match serde_json::from_value::<UserMonitoringProfile>(rec.spec.clone()) {
            Ok(p) => profiles.push(p),
            Err(err) => tracing::warn!(
                profile = name,
                version = %rec.version,
                error = %err,
                "active registry monitoring record has an unparseable spec; skipping"
            ),
        }
    }
    MonitoringRegistry::with_profiles(profiles)
}

/// Load every `*.toml` policy in `dir` (one `Policy` per file). A missing dir
/// means no policies (allow-by-default); an unparseable file is skipped loudly.
fn load_policies(dir: &Path) -> Vec<Policy> {
    let mut out = Vec::new();
    let Ok(rd) = std::fs::read_dir(dir) else {
        return out;
    };
    for entry in rd.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("toml") {
            continue;
        }
        match std::fs::read_to_string(&path)
            .ok()
            .and_then(|s| toml::from_str::<Policy>(&s).ok())
        {
            Some(p) => out.push(p),
            None => tracing::warn!(path = %path.display(), "skipping unparseable policy file"),
        }
    }
    out
}

/// Load the catalog from a TOML file and PROMOTE its entries to Trusted:
/// resolution reads Trusted only, and configuring the file is the operator's
/// vouching, so a file-imported catalog must resolve or `stamp` is inert.
fn load_catalog(path: &Path) -> Catalog {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) => {
            tracing::warn!(path = %path.display(), error = %e, "catalog file unreadable");
            return Catalog::default();
        }
    };
    let mut cat = match Catalog::from_toml(&text) {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(path = %path.display(), error = %e, "catalog file unparseable");
            return Catalog::default();
        }
    };
    for entry in &mut cat.entries {
        entry.promote("file-import");
    }
    cat
}

/// Load user-monitoring profiles from a JSON array file.
fn load_monitoring(path: &Path) -> MonitoringRegistry {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) => {
            tracing::warn!(path = %path.display(), error = %e, "monitoring file unreadable");
            return MonitoringRegistry::default();
        }
    };
    match serde_json::from_str::<Vec<UserMonitoringProfile>>(&text) {
        Ok(profiles) => MonitoringRegistry::with_profiles(profiles),
        Err(e) => {
            tracing::warn!(path = %path.display(), error = %e, "monitoring file unparseable");
            MonitoringRegistry::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use garmr_catalog::Catalog;
    use garmr_core::app_audit::keys;
    use garmr_monitor::MonitoringRegistry;
    use garmr_policy::{ConditionMatch, Effect, Policy, ResourceMatch, SubjectMatch};
    use std::collections::BTreeMap;

    /// An authenticated collector id for the tests: #14 requires every audit
    /// event on the prepare/detect path to carry a trusted collector attribution,
    /// so the reference serial path stands in for the live, authenticated firehose.
    const AUTHED: Option<&str> = Some("collector-test");

    fn audit_ev(fields: &[(&str, &str)]) -> Event {
        Event {
            ts: chrono::Utc::now(),
            host: "db01".into(),
            service: "postgres".into(),
            source: "pgaudit".into(),
            environment: "prod".into(),
            severity: "info".into(),
            log_type: "audit".into(),
            message: "SELECT 1".into(),
            fields: fields
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect::<BTreeMap<_, _>>(),
        }
    }

    /// A swappable config bundle over `policies` (empty catalog + monitoring) for
    /// the test constructors — mirrors the shape `ConfigSet::build` produces.
    fn cfgset(policies: Vec<Policy>) -> RwLock<Arc<ConfigSet>> {
        RwLock::new(Arc::new(ConfigSet {
            policies,
            catalog: Catalog::default(),
            catalog_index: Default::default(),
            monitoring: MonitoringRegistry::default(),
        }))
    }

    fn empty() -> AppAudit {
        AppAudit {
            config: cfgset(vec![]),
            policies_dir: PathBuf::new(),
            catalog_file: None,
            monitoring_file: None,
            baselines: RwLock::new(BaselineStore::default()),
            stateful: RwLock::new(StatefulDetectors::new(StatefulConfig::default())),
            state: None,
            dirty: AtomicU64::new(0),
            ensemble: EnsemblePolicy::default(),
            shadow: RwLock::new(None),
        }
    }

    #[test]
    fn record_derived_detector_fires_without_any_policy() {
        // A watched-subject access fires the record-derived detector end to end,
        // lowering into a Detection whose rule_id is the detector name.
        let aa = empty();
        let ev = audit_ev(&[
            (keys::ACTOR, "anna"),
            (keys::SUBJECT, "p1"),
            (keys::OBJECT_TYPE, "persons"),
            (keys::WATCHED, "true"),
        ]);
        let dets = aa.detect_event(&ev, AUTHED);
        assert!(dets
            .iter()
            .any(|d| d.rule_id == "app-watched-subject-access"));
    }

    #[test]
    fn explicit_policy_deny_produces_a_forbidden_finding() {
        let aa = AppAudit {
            config: cfgset(vec![Policy {
                id: "deny-raw".into(),
                version: 1,
                title: String::new(),
                description: String::new(),
                priority: 0,
                enabled: true,
                subject: SubjectMatch::default(),
                resource: ResourceMatch {
                    objects: vec!["raw.*".into()],
                    ..Default::default()
                },
                condition: ConditionMatch::default(),
                effect: Effect::Deny,
                created_by: "henrik".into(),
                approved_by: Some("henrik".into()),
            }]),
            policies_dir: PathBuf::new(),
            catalog_file: None,
            monitoring_file: None,
            baselines: RwLock::new(BaselineStore::default()),
            stateful: RwLock::new(StatefulDetectors::new(StatefulConfig::default())),
            state: None,
            dirty: AtomicU64::new(0),
            ensemble: EnsemblePolicy::default(),
            shadow: RwLock::new(None),
        };
        let ev = audit_ev(&[
            (keys::ACTOR, "bruno"),
            (keys::OBJECT_NAME, "raw.persons"),
            (keys::OBJECT_TYPE, "persons"),
        ]);
        let dets = aa.detect_event(&ev, AUTHED);
        assert!(
            dets.iter().any(|d| d.rule_id == "app-forbidden-access"),
            "expected forbidden-access, got {:?}",
            dets.iter().map(|d| &d.rule_id).collect::<Vec<_>>()
        );
    }

    #[test]
    fn non_audit_event_is_ignored() {
        let mut ev = audit_ev(&[("message", "kernel oops")]);
        ev.log_type = "system".into();
        ev.fields.clear();
        assert!(empty().detect_event(&ev, AUTHED).is_empty());
    }

    #[test]
    fn unauthenticated_audit_event_is_ignored_on_the_prepare_path() {
        // #14: the live path is `prepare_event` + `finish_event`. An audit event
        // with NO authenticated collector attribution must be short-circuited in
        // `prepare_event` (no PreparedAudit at all) — no detectors run and nothing
        // is folded into a baseline — while the SAME event WITH an authenticated
        // collector is processed normally. This protects the real firehose path,
        // not just the serial `detect_event` wrapper.
        let aa = empty();
        let ev = audit_ev(&[
            (keys::ACTOR, "anna"),
            (keys::SUBJECT, "p1"),
            (keys::OBJECT_TYPE, "persons"),
            (keys::WATCHED, "true"),
        ]);

        // Unauthenticated (None) → no prepared audit, no detections.
        assert!(
            aa.prepare_event(&ev, None).is_none(),
            "an audit event without an authenticated collector must not prepare"
        );
        assert!(
            aa.detect_event(&ev, None).is_empty(),
            "the unauthenticated path yields no detections"
        );
        // An empty collector id is treated as unauthenticated too.
        assert!(aa.prepare_event(&ev, Some("")).is_none());

        // Authenticated → the same event prepares and fires end to end.
        assert!(
            aa.prepare_event(&ev, AUTHED).is_some(),
            "an authenticated audit event still prepares"
        );
        assert!(aa
            .detect_event(&ev, AUTHED)
            .iter()
            .any(|d| d.rule_id == "app-watched-subject-access"));
    }

    // ---- behavioral plane (Phase 7/8) integration -----------------------

    use garmr_baseline::{Dimension, EntityKind, Maturity};

    fn access(actor: &str, client: &str, object: &str) -> Event {
        audit_ev(&[
            (keys::ACTOR, actor),
            (keys::CLIENT_APPLICATION, client),
            (keys::OBJECT_NAME, object),
            (keys::OBJECT_TYPE, "persons"),
            (keys::OUTCOME, "success"),
        ])
    }

    fn learn(aa: &AppAudit, actor: &str, client: &str, object: &str, n: usize) {
        for _ in 0..n {
            aa.detect_event(&access(actor, client, object), AUTHED);
        }
    }

    /// Feed `n` accesses spread over ~`n`*4h so a baseline meets the DEFAULT
    /// promotion policy (>=30 observations, >=3-day span) and matures to Candidate.
    fn learn_spread(aa: &AppAudit, actor: &str, n: usize) {
        let base = chrono::Utc::now() - chrono::Duration::days(6);
        for i in 0..n {
            let mut e = access(actor, "jupyter", "curated.persons");
            e.ts = base + chrono::Duration::hours(i as i64 * 4);
            aa.detect_event(&e, AUTHED);
        }
    }

    /// The ingest firehose runs `prepare_event` across cores (order-independent)
    /// then `finish_event` in event order. That must be identical to the serial
    /// `detect_event` loop — same detections in order AND byte-identical learned
    /// baselines. This test runs EVERY prepare before ANY finish (the strongest
    /// stand-in for the parallel stage: no `observe` has happened when the prepares
    /// run), so if any baseline-dependent work ever leaks into `prepare_event`,
    /// the later events would see empty baselines here and the assertion goes red.
    #[test]
    fn split_prepare_finish_matches_serial_including_baselines() {
        let events: Vec<Event> = (0..40)
            .map(|i| {
                let mut e = access(
                    if i % 2 == 0 { "anna" } else { "bruno" },
                    "jupyter",
                    "curated.persons",
                );
                e.ts = chrono::Utc::now() - chrono::Duration::hours((40 - i) as i64);
                e
            })
            .collect();

        // Path 1 — fully serial: prepare+finish interleaved per event.
        let serial_aa = empty();
        let mut serial_rules: Vec<String> = Vec::new();
        for ev in &events {
            serial_rules.extend(
                serial_aa
                    .detect_event(ev, AUTHED)
                    .into_iter()
                    .map(|d| d.rule_id),
            );
        }

        // Path 2 — the firehose split: ALL prepares first, THEN ordered finishes.
        let split_aa = empty();
        let preps: Vec<Option<PreparedAudit>> = events
            .iter()
            .map(|ev| split_aa.prepare_event(ev, AUTHED))
            .collect();
        let mut split_rules: Vec<String> = Vec::new();
        for (ev, prep) in events.iter().zip(preps) {
            if let Some(prep) = prep {
                split_rules.extend(
                    split_aa
                        .finish_event(ev, prep)
                        .into_iter()
                        .map(|d| d.rule_id),
                );
            }
        }

        assert_eq!(
            serial_rules, split_rules,
            "detections must match, in event order"
        );

        // The learned baselines must be byte-identical: proof that running every
        // prepare before any finish did not disturb the observe order.
        let s = serde_json::to_vec(&*serial_aa.baselines.read().unwrap()).unwrap();
        let p = serde_json::to_vec(&*split_aa.baselines.read().unwrap()).unwrap();
        assert_eq!(
            s, p,
            "baseline learning must be identical after the prepare/finish split"
        );
    }

    #[test]
    fn auto_promote_succeeds_only_when_the_full_gate_is_clear() {
        let aa = empty();
        learn_spread(&aa, "anna", 30);
        let anna = Entity::new(EntityKind::User, "anna");
        // Met the default thresholds → Candidate, and on the auto-promote worklist.
        assert_eq!(aa.baseline_snapshot().maturity(&anna), Maturity::Candidate);
        assert!(aa.candidate_baselines().contains(&anna));
        // Clear guards → auto-promotable → Trusted.
        assert!(aa
            .auto_promotion_blocks(&anna, PromotionGuards::default())
            .is_empty());
        assert!(aa.auto_promote_baseline(&anna, PromotionGuards::default()));
        assert_eq!(aa.baseline_snapshot().maturity(&anna), Maturity::Stable);
        // No longer a Candidate → off the worklist.
        assert!(!aa.candidate_baselines().contains(&anna));
    }

    #[test]
    fn baseline_guards_flag_open_case_and_policy_violation() {
        let dir = tempfile::tempdir().unwrap();
        let state = StateStore::open(&dir.path().join("s.redb")).unwrap();
        let anna = Entity::new(EntityKind::User, "anna");
        // No cases → clear guards.
        let g0 = crate::appaudit::baseline_guards(&state, &anna);
        assert!(!g0.entity_has_open_case && !g0.policy_violation_in_window);
        // A forbidden-access case for anna sets BOTH hard-block guards.
        let ev = audit_ev(&[(keys::ACTOR, "anna"), (keys::OBJECT_NAME, "raw.persons")]);
        let det = Detection {
            rule_id: "app-forbidden-access".into(),
            rule_title: "forbidden".into(),
            level: "critical".into(),
            attack: vec![],
            event: ev,
            observed_at: chrono::Utc::now(),
            realert_secs: None,
        };
        state.put_case(&garmr_core::Case::open(det)).unwrap();
        let g = crate::appaudit::baseline_guards(&state, &anna);
        assert!(g.entity_has_open_case, "an open case touches the entity");
        assert!(
            g.policy_violation_in_window,
            "a forbidden-access case is a policy violation → never auto-trusted"
        );
        // A different entity is unaffected.
        let bob = Entity::new(EntityKind::User, "bob");
        assert!(!crate::appaudit::baseline_guards(&state, &bob).entity_has_open_case);
    }

    #[test]
    fn compromised_entity_is_never_auto_promoted_even_after_case_close() {
        // The poison door the review caught: a known-malicious actor whose case is
        // CLOSED (no open case, no forbidden-rule) must still be blocked via the
        // compromised set. `baseline_guards_from` sets entity_compromised from it.
        let anna = Entity::new(EntityKind::User, "anna");
        let compromised: std::collections::HashSet<String> = ["anna".to_string()].into();
        let g = crate::appaudit::baseline_guards_from(&[], &compromised, &anna);
        assert!(
            g.entity_compromised,
            "a compromised actor is flagged regardless of case state"
        );
        // And that guard is a hard block in the store gate.
        let aa = empty();
        learn_spread(&aa, "anna", 30); // meets thresholds
        assert!(
            !aa.auto_promotion_blocks(&anna, g).is_empty(),
            "compromise blocks auto-promotion even at full maturity"
        );
        assert!(!aa.auto_promote_baseline(&anna, g));
    }

    #[test]
    fn auto_promote_is_blocked_by_a_hard_guard() {
        let aa = empty();
        learn_spread(&aa, "anna", 30);
        let anna = Entity::new(EntityKind::User, "anna");
        // An open case touching the entity is an inviolable hard block.
        let guards = PromotionGuards {
            entity_has_open_case: true,
            ..Default::default()
        };
        assert!(!aa.auto_promotion_blocks(&anna, guards).is_empty());
        assert!(!aa.auto_promote_baseline(&anna, guards));
        assert_eq!(aa.baseline_snapshot().maturity(&anna), Maturity::Candidate);
    }

    #[test]
    fn auto_promote_is_stricter_than_analyst_below_thresholds() {
        let aa = empty();
        // Only 6 observations, all same-instant → below the 30-obs / 3-day gate.
        learn(&aa, "anna", "jupyter", "curated.persons", 6);
        let anna = Entity::new(EntityKind::User, "anna");
        // Auto-promote refuses (thresholds are a block it cannot clear)...
        assert!(!aa
            .auto_promotion_blocks(&anna, PromotionGuards::default())
            .is_empty());
        assert!(!aa.auto_promote_baseline(&anna, PromotionGuards::default()));
        // ...but an ANALYST may still promote (clears threshold blocks).
        assert!(aa
            .promote_baseline(&anna, PromotionGuards::default())
            .is_ok());
        assert_eq!(aa.baseline_snapshot().maturity(&anna), Maturity::Stable);
    }

    fn deny_raw() -> AppAudit {
        AppAudit {
            config: cfgset(vec![Policy {
                id: "deny-raw".into(),
                version: 1,
                title: String::new(),
                description: String::new(),
                priority: 0,
                enabled: true,
                subject: SubjectMatch::default(),
                resource: ResourceMatch {
                    objects: vec!["raw.*".into()],
                    ..Default::default()
                },
                condition: ConditionMatch::default(),
                effect: Effect::Deny,
                created_by: "henrik".into(),
                approved_by: Some("henrik".into()),
            }]),
            policies_dir: PathBuf::new(),
            catalog_file: None,
            monitoring_file: None,
            baselines: RwLock::new(BaselineStore::default()),
            stateful: RwLock::new(StatefulDetectors::new(StatefulConfig::default())),
            state: None,
            dirty: AtomicU64::new(0),
            ensemble: EnsemblePolicy::default(),
            shadow: RwLock::new(None),
        }
    }

    #[test]
    fn behavioral_detector_fires_only_after_promotion() {
        let aa = empty();
        learn(&aa, "anna", "jupyter", "curated.persons", 6);
        let anna = Entity::new(EntityKind::User, "anna");
        // Below the default promotion thresholds → still Learning (never fires).
        assert_eq!(aa.baseline_snapshot().maturity(&anna), Maturity::Learning);

        // Learning baseline: a novel client raises NOTHING (still learning).
        let dets = aa.detect_event(&access("anna", "tableplus", "curated.persons"), AUTHED);
        assert!(!dets
            .iter()
            .any(|d| signals_of(d).contains("app-new-client")));

        // Analyst promotes → Trusted; only now does behavioral novelty fire. The
        // weak indicator surfaces FUSED as an `app-insider-risk` case whose
        // `finding_signals` name the exact detector(s) that fired.
        aa.promote_baseline(&anna, PromotionGuards::default())
            .unwrap();
        assert_eq!(aa.baseline_snapshot().maturity(&anna), Maturity::Stable);
        let dets = aa.detect_event(&access("anna", "dbeaver", "curated.persons"), AUTHED);
        let fused = dets
            .iter()
            .find(|d| d.rule_id.starts_with("app-insider-risk"))
            .unwrap_or_else(|| {
                panic!(
                    "expected app-insider-risk-*, got {:?}",
                    dets.iter().map(|d| &d.rule_id).collect::<Vec<_>>()
                )
            });
        assert!(
            signals_of(fused).contains("app-new-client"),
            "fused finding must name the detector: {:?}",
            fused.event.field("finding_signals")
        );
        // A known client stays quiet (no fused behavioral case at all).
        assert!(!aa
            .detect_event(&access("anna", "jupyter", "curated.persons"), AUTHED)
            .iter()
            .any(|d| d.rule_id.starts_with("app-insider-risk")));
    }

    /// The per-signal breakdown stamped onto a lowered detection.
    fn signals_of(d: &Detection) -> String {
        d.event
            .field("finding_signals")
            .unwrap_or_default()
            .to_string()
    }

    #[test]
    fn forbidden_and_failed_accesses_are_not_learned() {
        let aa = deny_raw();
        // A forbidden (policy Deny) access fires, but is NEVER folded into a
        // baseline — a forbidden action can never become "normal".
        let denied = access("mallory", "psql", "raw.persons");
        assert!(aa
            .detect_event(&denied, AUTHED)
            .iter()
            .any(|d| d.rule_id == "app-forbidden-access"));
        // A DB-failed access (allowed object, negative outcome) is also not learned.
        let mut failed = access("mallory", "psql", "curated.persons");
        failed.fields.insert(keys::OUTCOME.into(), "denied".into());
        aa.detect_event(&failed, AUTHED);

        // No baseline profile exists for mallory: nothing was learned.
        assert!(aa
            .baseline_snapshot()
            .get(&Entity::new(EntityKind::User, "mallory"))
            .is_none());
    }

    #[test]
    fn promotion_is_hard_blocked_by_a_prior_policy_violation() {
        let aa = empty();
        learn(&aa, "anna", "jupyter", "curated.persons", 6);
        let anna = Entity::new(EntityKind::User, "anna");
        // A prior policy violation is an inviolable hard block, even for an analyst.
        let guards = PromotionGuards {
            policy_violation_in_window: true,
            ..Default::default()
        };
        let err = aa.promote_baseline(&anna, guards).unwrap_err();
        assert!(err.contains(&PromotionBlock::PolicyViolationInWindow));
        // Cleared → promotion succeeds.
        aa.promote_baseline(&anna, PromotionGuards::default())
            .unwrap();
    }

    #[test]
    fn baselines_persist_and_trusted_state_survives_reload() {
        let dir = tempfile::tempdir().unwrap();
        let state = StateStore::open(&dir.path().join("state.redb")).unwrap();
        let anna = Entity::new(EntityKind::User, "anna");
        {
            let aa = AppAudit {
                config: cfgset(vec![]),
                policies_dir: PathBuf::new(),
                catalog_file: None,
                monitoring_file: None,
                baselines: RwLock::new(BaselineStore::default()),
                stateful: RwLock::new(StatefulDetectors::new(StatefulConfig::default())),
                state: Some(state.clone()),
                dirty: AtomicU64::new(0),
                ensemble: EnsemblePolicy::default(),
                shadow: RwLock::new(None),
            };
            learn(&aa, "anna", "jupyter", "curated.persons", 6);
            // Promotion persists the store (flush on success).
            aa.promote_baseline(&anna, PromotionGuards::default())
                .unwrap();
        }
        // Reload straight from the persisted blob: trusted state + learned values
        // survive, so novelty answers correctly after a restart.
        let reloaded = load_baselines(&state).expect("persisted baselines present");
        assert_eq!(reloaded.maturity(&anna), Maturity::Stable);
        assert!(reloaded.novelty(&anna, Dimension::Client, "dbeaver").novel);
        assert!(!reloaded.novelty(&anna, Dimension::Client, "jupyter").novel);
    }

    // ---- Phase 8 stateful plane: end-to-end through the serve pipeline -------

    /// A sensitive access with an adjacent-id subject (for sequential runs).
    fn seq_access(actor: &str, id: i64, tag: &str) -> Event {
        let sid = format!("acct-{id}");
        audit_ev(&[
            (keys::ACTOR, actor),
            (keys::SUBJECT, &sid),
            (keys::OBJECT_TYPE, "accounts"),
            (keys::OBJECT_NAME, "curated.accounts"),
            (keys::SENSITIVE_RESOURCE, "true"),
            (keys::OUTCOME, "success"),
            ("event_id", tag),
        ])
    }

    fn aa_with_state(state: StateStore, sd: StatefulDetectors) -> AppAudit {
        AppAudit {
            config: cfgset(vec![]),
            policies_dir: PathBuf::new(),
            catalog_file: None,
            monitoring_file: None,
            baselines: RwLock::new(BaselineStore::default()),
            stateful: RwLock::new(sd),
            state: Some(state),
            dirty: AtomicU64::new(0),
            ensemble: EnsemblePolicy::default(),
            shadow: RwLock::new(None),
        }
    }

    #[test]
    fn stateful_sequential_enumeration_surfaces_as_a_detection() {
        // A 12-long adjacent-id run (the default seq_run_len) must surface, through
        // the full detect_event pipeline (prepare + finish + fuse + lower), as its
        // OWN standalone detection — proving the stateful plane is wired end to end.
        let aa = empty();
        let mut fired = false;
        for i in 0..12 {
            let dets = aa.detect_event(&seq_access("mallory", 1000 + i, &format!("e{i}")), AUTHED);
            if dets
                .iter()
                .any(|d| d.rule_id == "app-enumeration-sequential")
            {
                fired = true;
            }
        }
        assert!(
            fired,
            "a full adjacent-id run must lower into an app-enumeration-sequential detection"
        );
    }

    #[test]
    fn stateful_state_persists_and_survives_reload() {
        let dir = tempfile::tempdir().unwrap();
        let state = StateStore::open(&dir.path().join("state.redb")).unwrap();
        // Build a run of 11 adjacent ids — one short of the threshold — then flush.
        {
            let aa = aa_with_state(
                state.clone(),
                StatefulDetectors::new(StatefulConfig::default()),
            );
            for i in 0..11 {
                let dets =
                    aa.detect_event(&seq_access("mallory", 1000 + i, &format!("e{i}")), AUTHED);
                assert!(
                    !dets
                        .iter()
                        .any(|d| d.rule_id == "app-enumeration-sequential"),
                    "run of 11 must NOT fire yet"
                );
            }
            aa.flush();
        }
        // Reload the persisted stateful state and feed the 12th id: the in-progress
        // episode completes after a restart — restart recovery, proven end to end.
        let reloaded = load_stateful(&state).expect("stateful state was persisted");
        let aa2 = aa_with_state(
            state.clone(),
            StatefulDetectors::from_state(StatefulConfig::default(), reloaded),
        );
        let dets = aa2.detect_event(&seq_access("mallory", 1011, "e11"), AUTHED);
        assert!(
            dets.iter()
                .any(|d| d.rule_id == "app-enumeration-sequential"),
            "the episode must complete after a reload, got {:?}",
            dets.iter().map(|d| &d.rule_id).collect::<Vec<_>>()
        );
    }

    // ---- Phase A: registry-backed (governed) access policies -----------------

    fn deny_raw_policy(id: &str, version: u32) -> Policy {
        Policy {
            id: id.into(),
            version,
            title: String::new(),
            description: String::new(),
            priority: 0,
            enabled: true,
            subject: SubjectMatch::default(),
            resource: ResourceMatch {
                objects: vec!["raw.*".into()],
                ..Default::default()
            },
            condition: ConditionMatch::default(),
            effect: Effect::Deny,
            created_by: "henrik".into(),
            approved_by: Some("henrik".into()),
        }
    }

    /// A `Policy` registry record built from a JSON literal (every field is
    /// `#[serde(default)]`, so only the identity + spec need naming).
    fn policy_record(
        name: &str,
        version: &str,
        digest: &str,
        p: &Policy,
    ) -> garmr_core::RegistryRecord {
        serde_json::from_value(serde_json::json!({
            "kind": "policy", "name": name, "version": version,
            "content_digest": digest, "spec": serde_json::to_value(p).unwrap(),
        }))
        .unwrap()
    }

    fn promotion(
        id: &str,
        name: &str,
        op: &str,
        digest: &str,
        at: &str,
    ) -> garmr_core::PromotionEvent {
        serde_json::from_value(serde_json::json!({
            "promotion_id": id, "kind": "policy", "name": name, "op": op,
            "to_version": "v2", "to_state": "approved", "channel": "production",
            "target_digest": digest, "actor": "henrik", "audit_id": format!("audit-{id}"),
            "at": at,
        }))
        .unwrap()
    }

    #[test]
    fn active_policies_from_registry_folds_the_promotion_stream() {
        let dir = tempfile::tempdir().unwrap();
        let state = StateStore::open(&dir.path().join("s.redb")).unwrap();

        // Two versions of deny-raw + an unrelated, never-promoted policy.
        state
            .register_record(&policy_record(
                "deny-raw",
                "v1",
                "d1",
                &deny_raw_policy("deny-raw", 1),
            ))
            .unwrap();
        state
            .register_record(&policy_record(
                "deny-raw",
                "v2",
                "d2",
                &deny_raw_policy("deny-raw", 2),
            ))
            .unwrap();
        state
            .register_record(&policy_record(
                "allow-x",
                "v1",
                "dx",
                &deny_raw_policy("allow-x", 1),
            ))
            .unwrap();

        // Nothing promoted yet → nothing enforced (a registered draft is not live).
        assert!(active_policies_from_registry(&state).is_empty());

        // Promote deny-raw v2 (approved, audit-bound) on production.
        state
            .append_promotion(&promotion(
                "p1",
                "deny-raw",
                "promote",
                "d2",
                "2026-01-01T00:00:00Z",
            ))
            .unwrap();
        let active = active_policies_from_registry(&state);
        assert_eq!(active.len(), 1, "only the promoted policy is enforced");
        assert_eq!(active[0].id, "deny-raw");
        assert_eq!(
            active[0].version, 2,
            "the PROMOTED version, not the draft v1"
        );

        // Retire it (a later audit-bound append) → no longer enforced.
        state
            .append_promotion(&promotion(
                "p2",
                "deny-raw",
                "retire",
                "d2",
                "2026-01-02T00:00:00Z",
            ))
            .unwrap();
        assert!(
            active_policies_from_registry(&state).is_empty(),
            "a retired policy is no longer enforced (rollback/retire is another append)"
        );
    }

    #[test]
    fn active_catalog_from_registry_folds_and_marks_trusted() {
        let dir = tempfile::tempdir().unwrap();
        let state = StateStore::open(&dir.path().join("s.redb")).unwrap();

        // A catalog entry spec (a sensitive table). Only id + resource are required.
        let cat_record = |name: &str, digest: &str| -> garmr_core::RegistryRecord {
            serde_json::from_value(serde_json::json!({
                "kind": "catalog", "name": name, "version": "v1", "content_digest": digest,
                "spec": { "id": name, "resource": { "kind": "table", "name": name, "sensitive": true } },
            }))
            .unwrap()
        };
        state
            .register_record(&cat_record("curated.persons", "c1"))
            .unwrap();
        // A second entry that is registered but never promoted (a draft).
        state
            .register_record(&cat_record("raw.internal", "c2"))
            .unwrap();

        // Nothing promoted → the catalog is empty (a draft resolves nothing).
        assert!(active_catalog_from_registry(&state).entries.is_empty());

        // Promote curated.persons v1 (audit-bound) on production.
        let promo: garmr_core::PromotionEvent = serde_json::from_value(serde_json::json!({
            "promotion_id": "cp1", "kind": "catalog", "name": "curated.persons",
            "op": "promote", "to_version": "v1", "to_state": "approved",
            "channel": "production", "target_digest": "c1",
            "actor": "henrik", "audit_id": "audit-cp1", "at": "2026-01-01T00:00:00Z",
        }))
        .unwrap();
        state.append_promotion(&promo).unwrap();

        let cat = active_catalog_from_registry(&state);
        assert_eq!(cat.entries.len(), 1, "only the promoted entry is live");
        assert_eq!(cat.entries[0].id, "curated.persons");
        assert!(
            cat.entries[0].is_trusted(),
            "an audit-bound registry promotion makes the entry Trusted"
        );
        assert!(
            cat.resolve_object("curated.persons").is_some(),
            "a Trusted entry resolves (the security gate reads Trusted only)"
        );
    }

    #[test]
    fn active_monitoring_from_registry_folds_the_promotion_stream() {
        use garmr_monitor::{MonitoringState, MonitoringTarget};
        let dir = tempfile::tempdir().unwrap();
        let state = StateStore::open(&dir.path().join("s.redb")).unwrap();

        let profile = |user: &str| -> UserMonitoringProfile {
            UserMonitoringProfile::new(
                MonitoringTarget::User(user.into()),
                MonitoringState::Investigation,
                chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap(),
                "henrik",
            )
        };
        let mon_record = |user: &str, digest: &str| -> garmr_core::RegistryRecord {
            serde_json::from_value(serde_json::json!({
                "kind": "monitoring", "name": user, "version": "v1", "content_digest": digest,
                "spec": serde_json::to_value(profile(user)).unwrap(),
            }))
            .unwrap()
        };
        state.register_record(&mon_record("mallory", "m1")).unwrap();
        // A second profile, registered but never promoted (a draft — not in effect).
        state.register_record(&mon_record("bruno", "m2")).unwrap();

        // Nothing promoted → no monitoring is in effect.
        assert!(active_monitoring_from_registry(&state)
            .profiles()
            .is_empty());

        // Promote mallory's profile (audit-bound) on production.
        let promo: garmr_core::PromotionEvent = serde_json::from_value(serde_json::json!({
            "promotion_id": "mp1", "kind": "monitoring", "name": "mallory",
            "op": "promote", "to_version": "v1", "to_state": "approved",
            "channel": "production", "target_digest": "m1",
            "actor": "henrik", "audit_id": "audit-mp1", "at": "2026-01-01T00:00:00Z",
        }))
        .unwrap();
        state.append_promotion(&promo).unwrap();

        let m = active_monitoring_from_registry(&state);
        assert_eq!(
            m.profiles().len(),
            1,
            "only the promoted profile is in effect"
        );
        assert_eq!(m.profiles()[0].user_id, "mallory");
    }

    #[test]
    fn reload_swaps_the_enforced_config_without_restart_and_preserves_learning() {
        use garmr_baseline::EntityKind;
        let dir = tempfile::tempdir().unwrap();
        let aa = AppAudit {
            config: cfgset(vec![]),
            policies_dir: dir.path().to_path_buf(),
            catalog_file: None,
            monitoring_file: None,
            baselines: RwLock::new(BaselineStore::default()),
            stateful: RwLock::new(StatefulDetectors::new(StatefulConfig::default())),
            state: None,
            dirty: AtomicU64::new(0),
            ensemble: EnsemblePolicy::default(),
            shadow: RwLock::new(None),
        };
        let raw = || {
            audit_ev(&[
                (keys::ACTOR, "mallory"),
                (keys::OBJECT_NAME, "raw.persons"),
                (keys::OBJECT_TYPE, "persons"),
            ])
        };

        // Learn some behavior (populates a candidate baseline); no policy yet, so a
        // raw.* access is NOT forbidden.
        for _ in 0..3 {
            aa.detect_event(&access("anna", "jupyter", "curated.persons"), AUTHED);
        }
        let anna = Entity::new(EntityKind::User, "anna");
        assert!(aa.baseline_snapshot().get(&anna).is_some());
        assert!(!aa
            .detect_event(&raw(), AUTHED)
            .iter()
            .any(|d| d.rule_id == "app-forbidden-access"));

        // Drop a deny-raw policy FILE, then HOT-RELOAD — no restart, no new AppAudit.
        std::fs::write(
            dir.path().join("deny-raw.toml"),
            "id = \"deny-raw\"\neffect = \"deny\"\nversion = 1\n[resource]\nobjects = [\"raw.*\"]\n",
        )
        .unwrap();
        let (policies, _, _) = aa.reload();
        assert_eq!(policies, 1, "the newly-dropped policy is now enforced");

        // The SAME plane now denies the raw access …
        assert!(
            aa.detect_event(&raw(), AUTHED)
                .iter()
                .any(|d| d.rule_id == "app-forbidden-access"),
            "the hot-reloaded policy takes effect without a restart"
        );
        // … and the learned baseline SURVIVED the reload (only config was swapped).
        assert!(
            aa.baseline_snapshot().get(&anna).is_some(),
            "hot-reload swaps only config — learning state is untouched"
        );
    }

    #[test]
    fn promotion_touches_enforcement_only_for_gated_production_config_kinds() {
        let on = |_k: RegistryKind| true;
        let off = |_k: RegistryKind| false;
        for k in [
            RegistryKind::Policy,
            RegistryKind::Catalog,
            RegistryKind::Monitoring,
        ] {
            // A consumed domain, on production, with its gate on → enforcement
            // changes, so the promotion must trigger a reload.
            assert!(promotion_touches_enforcement(k, "production", on), "{k:?}");
            // Gate off (still file-backed) → the registry promotion is recorded but
            // does not change what is enforced, so NO reload.
            assert!(
                !promotion_touches_enforcement(k, "production", off),
                "{k:?} gate off"
            );
            // Enforcement composes only the production channel — a staging promotion
            // never touches the active set.
            assert!(
                !promotion_touches_enforcement(k, "staging", on),
                "{k:?} staging"
            );
        }
        // Storable-but-unconsumed governed kinds (applications, resources) and
        // unrelated kinds never trigger a reload, even with every gate reported on.
        for k in [
            RegistryKind::Application,
            RegistryKind::Resource,
            RegistryKind::Rule,
            RegistryKind::Model,
        ] {
            assert!(
                !promotion_touches_enforcement(k, "production", on),
                "{k:?} is not a consumed config domain"
            );
        }
    }
}
