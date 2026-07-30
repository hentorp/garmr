// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! Phase 4 registry persistence: immutable content records + an append-only
//! promotion stream.
//!
//! `register_record` is a **guarded-unique** insert (get→compare→insert in one
//! write txn, like `decide_proposal`): re-registering the same `(kind, name,
//! version)` with the SAME content is an idempotent no-op; with DIFFERENT content
//! it is a `Conflict` (the immutability guard — a version is never rewritten).
//! Promotions are append-only. All readers tolerantly skip an undecodable row.

use garmr_core::{Error, PromotionEvent, RegistryKind, RegistryRecord, Result};
use redb::ReadableTable;

use super::{StateStore, REGISTRY, REGISTRY_PROMOTIONS};

/// The result of registering a content record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegisterOutcome {
    /// A new version was stored.
    Inserted,
    /// The exact same content was already registered (idempotent no-op).
    AlreadyIdentical,
    /// The `(kind, name, version)` exists with DIFFERENT content — refused.
    Conflict { existing_digest: String },
}

/// Escape the `|` field delimiter (and the escape char itself) so a component
/// can never bleed across it. Without this the key is non-injective:
/// (name="a", version="b|c") and (name="a|b", version="c") would collapse to the
/// same key, so a legitimate second coordinate is refused as a false Conflict
/// and a lookup returns the wrong record. `kind.tag()` is a fixed charset with
/// no `|`/`\`, so only name/version need escaping.
fn esc(s: &str) -> String {
    s.replace('\\', "\\\\").replace('|', "\\|")
}

fn rec_key(kind: RegistryKind, name: &str, version: &str) -> String {
    format!("{}|{}|{}", kind.tag(), esc(name), esc(version))
}

fn promo_key(e: &PromotionEvent) -> String {
    // The trailing promotion_id (a uuid) already makes this unique, but escape
    // the name too so the key stays unambiguous.
    format!(
        "{}|{}|{:020}|{}",
        e.kind.tag(),
        esc(&e.name),
        e.at.timestamp_nanos_opt().unwrap_or(0),
        e.promotion_id
    )
}

impl StateStore {
    /// Register an immutable content record. Idempotent by content; refuses a
    /// re-registration of the same coordinate with different content.
    pub fn register_record(&self, r: &RegistryRecord) -> Result<RegisterOutcome> {
        let key = rec_key(r.kind, &r.name, &r.version);
        let wtx = self.db.begin_write().map_err(Error::store)?;
        let outcome;
        {
            let mut t = wtx.open_table(REGISTRY).map_err(Error::store)?;
            let existing: Option<RegistryRecord> = t
                .get(key.as_str())
                .map_err(Error::store)?
                .map(|v| serde_json::from_slice(v.value()))
                .transpose()
                .map_err(Error::store)?;
            match existing {
                Some(cur) if cur.content_digest == r.content_digest => {
                    outcome = RegisterOutcome::AlreadyIdentical;
                }
                Some(cur) => {
                    outcome = RegisterOutcome::Conflict {
                        existing_digest: cur.content_digest,
                    };
                }
                None => {
                    let bytes = serde_json::to_vec(r).map_err(Error::store)?;
                    t.insert(key.as_str(), bytes.as_slice())
                        .map_err(Error::store)?;
                    outcome = RegisterOutcome::Inserted;
                }
            }
        }
        wtx.commit().map_err(Error::store)?;
        Ok(outcome)
    }

    /// Fetch one record by exact `(kind, name, version)`.
    pub fn get_record(
        &self,
        kind: RegistryKind,
        name: &str,
        version: &str,
    ) -> Result<Option<RegistryRecord>> {
        let key = rec_key(kind, name, version);
        let rtx = self.db.begin_read().map_err(Error::store)?;
        let t = rtx.open_table(REGISTRY).map_err(Error::store)?;
        match t.get(key.as_str()).map_err(Error::store)? {
            Some(v) => Ok(Some(
                serde_json::from_slice(v.value()).map_err(Error::store)?,
            )),
            None => Ok(None),
        }
    }

    /// All records (across every kind).
    pub fn list_registry(&self) -> Result<Vec<RegistryRecord>> {
        self.scan_tolerant(REGISTRY, "registry_record")
    }

    /// All records of one kind.
    pub fn list_kind(&self, kind: RegistryKind) -> Result<Vec<RegistryRecord>> {
        Ok(self
            .list_registry()?
            .into_iter()
            .filter(|r| r.kind == kind)
            .collect())
    }

    /// All versions of one `(kind, name)`.
    pub fn records_for_name(&self, kind: RegistryKind, name: &str) -> Result<Vec<RegistryRecord>> {
        Ok(self
            .list_registry()?
            .into_iter()
            .filter(|r| r.kind == kind && r.name == name)
            .collect())
    }

    /// Append a governance event (never overwrites).
    pub fn append_promotion(&self, e: &PromotionEvent) -> Result<()> {
        let bytes = serde_json::to_vec(e).map_err(Error::store)?;
        let key = promo_key(e);
        let wtx = self.db.begin_write().map_err(Error::store)?;
        {
            let mut t = wtx.open_table(REGISTRY_PROMOTIONS).map_err(Error::store)?;
            t.insert(key.as_str(), bytes.as_slice())
                .map_err(Error::store)?;
        }
        wtx.commit().map_err(Error::store)?;
        Ok(())
    }

    /// All promotion events (across every kind).
    pub fn list_promotions(&self) -> Result<Vec<PromotionEvent>> {
        self.scan_tolerant(REGISTRY_PROMOTIONS, "promotion_event")
    }

    /// Promotion events for one `(kind, name)`, oldest → newest.
    pub fn promotions_for(&self, kind: RegistryKind, name: &str) -> Result<Vec<PromotionEvent>> {
        let mut v: Vec<PromotionEvent> = self
            .list_promotions()?
            .into_iter()
            .filter(|e| e.kind == kind && e.name == name)
            .collect();
        v.sort_by_key(|e| e.at);
        Ok(v)
    }

    /// The active (live, production) approved procedural-memory LessonSet + its
    /// registry version (Phase 9), or `None` when none is promoted. The caller
    /// (serve) MUST re-validate the returned set before binding it — the active
    /// fold trusts a non-empty audit id, so a forged promotion is not caught here.
    pub fn active_lesson_set(&self) -> Result<Option<(String, garmr_core::LessonSet)>> {
        let records = self.list_kind(garmr_core::RegistryKind::Lesson)?;
        let promotions = self.promotions_for(garmr_core::RegistryKind::Lesson, "triage")?;
        match garmr_core::active(
            garmr_core::RegistryKind::Lesson,
            "triage",
            "production",
            &records,
            &promotions,
        ) {
            Some(rec) => {
                let spec: garmr_core::LessonSetSpec =
                    serde_json::from_value(rec.spec.clone()).map_err(Error::store)?;
                Ok(Some((
                    rec.version.clone(),
                    garmr_core::LessonSet {
                        lessons: spec.lessons,
                    },
                )))
            }
            None => Ok(None),
        }
    }
}
