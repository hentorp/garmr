// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! Notification-silence persistence: human-approved, one-per-rule silences in
//! the `silences` table. `active_silences` reads with a snapshot txn (no
//! writer-lock contention on the hot routing path) and prunes expired entries
//! only when it finds them; `put_silence` carries the hit count + created
//! timestamp forward so extending a silence never erases its audit trail.

use garmr_core::{Error, Result, Silence};
use redb::ReadableTable;

use super::{StateStore, SILENCES};

impl StateStore {
    /// Persist a silence (insert or overwrite by rule id — one silence per
    /// rule). When overwriting, `hits` and `created` are carried forward from
    /// the previous entry **inside the write transaction** (mirroring
    /// `put_case`'s event_count merge), so extending a silence never erases the
    /// suppression count the audit trail exists for. Returns the replaced
    /// silence so callers can surface a scope change to the operator.
    pub fn put_silence(&self, s: &Silence) -> Result<Option<Silence>> {
        let wtx = self.db.begin_write().map_err(Error::store)?;
        let replaced;
        {
            let mut t = wtx.open_table(SILENCES).map_err(Error::store)?;
            replaced = t
                .get(s.rule.as_str())
                .map_err(Error::store)?
                .and_then(|v| serde_json::from_slice::<Silence>(v.value()).ok());
            let mut to_write = s.clone();
            if let Some(prev) = &replaced {
                to_write.hits = prev.hits;
                to_write.created = prev.created;
            }
            let bytes = serde_json::to_vec(&to_write).map_err(Error::store)?;
            t.insert(s.rule.as_str(), bytes.as_slice())
                .map_err(Error::store)?;
        }
        wtx.commit().map_err(Error::store)?;
        Ok(replaced)
    }

    /// Fetch a rule's silence regardless of expiry (the write paths need the
    /// stored scope; expiry filtering belongs to `active_silences`).
    pub fn get_silence(&self, rule: &str) -> Result<Option<Silence>> {
        let rtx = self.db.begin_read().map_err(Error::store)?;
        let t = rtx.open_table(SILENCES).map_err(Error::store)?;
        match t.get(rule).map_err(Error::store)? {
            Some(v) => Ok(Some(
                serde_json::from_slice(v.value()).map_err(Error::store)?,
            )),
            None => Ok(None),
        }
    }

    /// Remove a rule's silence (no-op if none).
    pub fn clear_silence(&self, rule: &str) -> Result<()> {
        let wtx = self.db.begin_write().map_err(Error::store)?;
        {
            let mut t = wtx.open_table(SILENCES).map_err(Error::store)?;
            t.remove(rule).map_err(Error::store)?;
        }
        wtx.commit().map_err(Error::store)?;
        Ok(())
    }

    /// Silences still active at `now`. Reads with a snapshot transaction (no
    /// writer-lock contention — this runs on every routing decision, which is
    /// exactly when `put_case` traffic peaks); a write transaction is opened
    /// only when expired entries were actually found, to prune them.
    pub fn active_silences(&self, now: chrono::DateTime<chrono::Utc>) -> Result<Vec<Silence>> {
        let mut live = Vec::new();
        let mut expired = Vec::new();
        {
            let rtx = self.db.begin_read().map_err(Error::store)?;
            let t = rtx.open_table(SILENCES).map_err(Error::store)?;
            for row in t.iter().map_err(Error::store)? {
                let (k, v) = row.map_err(Error::store)?;
                match serde_json::from_slice::<Silence>(v.value()) {
                    Ok(s) if s.until > now => live.push(s),
                    _ => expired.push(k.value().to_string()),
                }
            }
        }
        if !expired.is_empty() {
            let wtx = self.db.begin_write().map_err(Error::store)?;
            {
                let mut t = wtx.open_table(SILENCES).map_err(Error::store)?;
                for k in &expired {
                    // Re-check inside the txn: a concurrent set may have
                    // replaced the expired entry with a live one.
                    let still_expired = t
                        .get(k.as_str())
                        .map_err(Error::store)?
                        .and_then(|v| serde_json::from_slice::<Silence>(v.value()).ok())
                        .is_none_or(|s| s.until <= now);
                    if still_expired {
                        t.remove(k.as_str()).map_err(Error::store)?;
                    }
                }
            }
            wtx.commit().map_err(Error::store)?;
        }
        live.sort_by_key(|s| s.until);
        Ok(live)
    }

    /// Count one suppressed notification on a rule's silence (audit trail).
    pub fn bump_silence_hits(&self, rule: &str) -> Result<()> {
        let wtx = self.db.begin_write().map_err(Error::store)?;
        {
            let mut t = wtx.open_table(SILENCES).map_err(Error::store)?;
            let Some(bytes) = t
                .get(rule)
                .map_err(Error::store)?
                .map(|v| v.value().to_vec())
            else {
                return Ok(());
            };
            let mut s: Silence = serde_json::from_slice(&bytes).map_err(Error::store)?;
            s.hits += 1;
            let out = serde_json::to_vec(&s).map_err(Error::store)?;
            t.insert(rule, out.as_slice()).map_err(Error::store)?;
        }
        wtx.commit().map_err(Error::store)?;
        Ok(())
    }
}
