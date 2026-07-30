// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! The daily LLM-spend ledger (micro-USD per `YYYY-MM-DD`) and the
//! cancellation-safe [`BudgetReservation`] RAII guard. All arithmetic is on
//! integer micro-USD to avoid float value types in redb, and the atomic
//! reserve/settle path is the race-free cap check for concurrent spenders.

use garmr_core::{Error, Result};
use redb::ReadableTable;

use super::{StateStore, BUDGET};

impl StateStore {
    /// Current spend for a day (micro-USD).
    pub fn budget_spent_micros(&self, day: &str) -> Result<u64> {
        let rtx = self.db.begin_read().map_err(Error::store)?;
        let t = rtx.open_table(BUDGET).map_err(Error::store)?;
        Ok(t.get(day)
            .map_err(Error::store)?
            .map(|v| v.value())
            .unwrap_or(0))
    }

    /// Add spend to a day's ledger and return the new total (micro-USD).
    pub fn budget_add_micros(&self, day: &str, add: u64) -> Result<u64> {
        let wtx = self.db.begin_write().map_err(Error::store)?;
        let total;
        {
            let mut t = wtx.open_table(BUDGET).map_err(Error::store)?;
            let cur = t
                .get(day)
                .map_err(Error::store)?
                .map(|v| v.value())
                .unwrap_or(0);
            total = cur + add;
            t.insert(day, total).map_err(Error::store)?;
        }
        wtx.commit().map_err(Error::store)?;
        Ok(total)
    }

    /// Atomically reserve spend against a cap: read + compare + insert in ONE
    /// write transaction. Returns `false` (and reserves nothing) when the day's
    /// spend plus `reserve` would exceed `cap`. This is the race-free check for
    /// concurrent spenders — a check-then-act around [`budget_add_micros`] lets
    /// N callers all pass the check before any charge lands.
    pub fn budget_try_reserve_micros(&self, day: &str, reserve: u64, cap: u64) -> Result<bool> {
        let wtx = self.db.begin_write().map_err(Error::store)?;
        let ok;
        {
            let mut t = wtx.open_table(BUDGET).map_err(Error::store)?;
            let cur = t
                .get(day)
                .map_err(Error::store)?
                .map(|v| v.value())
                .unwrap_or(0);
            ok = cur.saturating_add(reserve) <= cap;
            if ok {
                t.insert(day, cur + reserve).map_err(Error::store)?;
            }
        }
        wtx.commit().map_err(Error::store)?;
        Ok(ok)
    }

    /// Settle a reservation against actual cost: apply `actual - reserved`
    /// (saturating at zero — a refund never drives the ledger negative).
    pub fn budget_settle_micros(&self, day: &str, reserved: u64, actual: u64) -> Result<u64> {
        let wtx = self.db.begin_write().map_err(Error::store)?;
        let total;
        {
            let mut t = wtx.open_table(BUDGET).map_err(Error::store)?;
            let cur = t
                .get(day)
                .map_err(Error::store)?
                .map(|v| v.value())
                .unwrap_or(0);
            total = cur.saturating_sub(reserved).saturating_add(actual);
            t.insert(day, total).map_err(Error::store)?;
        }
        wtx.commit().map_err(Error::store)?;
        Ok(total)
    }

    /// Reserve spend as an RAII guard: on success the amount is committed to
    /// the ledger and the returned [`BudgetReservation`] refunds it on Drop
    /// unless [`settle`](BudgetReservation::settle)d first. This is the
    /// CANCELLATION-SAFE form — an async caller dropped at an await point
    /// between reserve and settle (HTTP timeout, client disconnect, shutdown)
    /// must not leak its worst-case reservation into the day's ledger.
    /// Returns `None` when the reservation would exceed `cap`.
    pub fn budget_reserve(
        &self,
        day: &str,
        reserve: u64,
        cap: u64,
    ) -> Result<Option<BudgetReservation>> {
        if !self.budget_try_reserve_micros(day, reserve, cap)? {
            return Ok(None);
        }
        Ok(Some(BudgetReservation {
            state: self.clone(),
            day: day.to_string(),
            reserve,
            armed: true,
        }))
    }
}

/// An armed budget reservation (see [`StateStore::budget_reserve`]). Dropping
/// it unsettled refunds the full reservation — redb writes are synchronous, so
/// the refund runs even when an async caller is cancelled at an await point.
/// A failed refund is logged; it self-heals at the day rollover.
pub struct BudgetReservation {
    state: StateStore,
    day: String,
    reserve: u64,
    armed: bool,
}

impl BudgetReservation {
    /// Settle against actual cost and disarm the guard.
    pub fn settle(mut self, actual: u64) -> Result<()> {
        self.armed = false;
        self.state
            .budget_settle_micros(&self.day, self.reserve, actual)?;
        Ok(())
    }
}

impl Drop for BudgetReservation {
    fn drop(&mut self) {
        if self.armed {
            if let Err(e) = self.state.budget_settle_micros(&self.day, self.reserve, 0) {
                tracing::warn!(day = %self.day, reserve = self.reserve, error = %e,
                    "budget reservation refund failed — day ledger overcharged until rollover");
            }
        }
    }
}
