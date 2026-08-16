// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! The safety window an ONLINE warehouse capture must finish inside.
//!
//! An online capture pins the current Iceberg snapshot and copies the files it
//! references. Iceberg data files are immutable, so a pinned snapshot is a
//! coherent view — but compaction retires superseded data directories and, after
//! `store.compact_gc_grace_secs`, DELETES them. A copy that overruns that grace
//! can therefore lose files it already listed.
//!
//! The failure is silent, which is what makes it dangerous: the copy simply
//! finds fewer files than the snapshot named, and an image that looks complete
//! restores a warehouse that is not. skade's own heal path calls this class
//! "total data loss masked as success".
//!
//! So the window is enforced at CAPTURE time rather than estimated in advance:
//! the capture records when it started and refuses to emit an image if it ran
//! too close to the grace. Refusing costs an operator a retry with a shorter
//! interval or a longer grace; not refusing costs them the backup, discovered
//! at restore.

// Called by the online capture path, which lands next. Marked rather than left
// to look like an oversight: the rule and its refusal message are reviewed and
// tested BEFORE anything can emit an image that depends on them.
#![allow(dead_code)]

use std::time::Duration;

/// How much of the grace period a capture may consume before it is refused.
///
/// Not 100%: the deletion sweep and the copy race, so finishing at 99% of the
/// grace is not safe, merely lucky. Two thirds leaves room for the sweep's own
/// scheduling jitter while still permitting a copy that takes minutes.
const SAFE_FRACTION: f64 = 2.0 / 3.0;

/// Whether a capture that took `elapsed` is within the safety window for a
/// deployment configured with `grace`.
///
/// A grace of zero means compaction deletes retired directories immediately, so
/// there is no window at all and NO online capture is safe — the caller must
/// refuse rather than treat it as unlimited.
pub(crate) fn within_safety_window(elapsed: Duration, grace: Duration) -> bool {
    if grace.is_zero() {
        return false;
    }
    elapsed.as_secs_f64() < grace.as_secs_f64() * SAFE_FRACTION
}

/// The message shown when a capture overruns. Names the two real remedies, so
/// the operator is not left to guess which knob applies.
pub(crate) fn overrun_message(elapsed: Duration, grace: Duration) -> String {
    if grace.is_zero() {
        return "online capture needs store.compact_gc_grace_secs > 0: with no grace period, \
                compaction can delete a data directory the moment it is retired, so no copy \
                is safe. Raise the grace, or take an offline backup."
            .to_string();
    }
    format!(
        "online capture took {:.0}s, too close to the {:.0}s compaction grace \
         (store.compact_gc_grace_secs) to be trusted — compaction may have deleted a data \
         directory this image had already listed, which would restore a warehouse that looks \
         complete and is not. Refusing to write the image. Either raise \
         store.compact_gc_grace_secs, or take an offline backup.",
        elapsed.as_secs_f64(),
        grace.as_secs_f64()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_fast_capture_is_inside_the_window() {
        assert!(within_safety_window(
            Duration::from_secs(10),
            Duration::from_secs(300)
        ));
    }

    #[test]
    fn a_capture_that_nearly_fills_the_grace_is_refused() {
        // Finishing at 99% of the grace is not safe, it is lucky: the deletion
        // sweep and the copy are racing, and the sweep's scheduling jitter is
        // not bounded by anything the capture can see.
        assert!(!within_safety_window(
            Duration::from_secs(299),
            Duration::from_secs(300)
        ));
        // Two thirds is the line.
        assert!(!within_safety_window(
            Duration::from_secs(200),
            Duration::from_secs(300)
        ));
        assert!(within_safety_window(
            Duration::from_secs(199),
            Duration::from_secs(300)
        ));
    }

    #[test]
    fn a_zero_grace_makes_every_online_capture_unsafe() {
        // The dangerous reading would be "no grace configured = no limit".
        // With grace 0 compaction can delete a retired directory immediately,
        // so there is no window to finish inside at all.
        assert!(!within_safety_window(
            Duration::from_millis(1),
            Duration::ZERO
        ));
        assert!(overrun_message(Duration::from_millis(1), Duration::ZERO)
            .contains("compact_gc_grace_secs > 0"));
    }

    #[test]
    fn the_overrun_message_names_both_remedies() {
        // A refusal that does not say what to change gets worked around, and
        // the workaround is usually "ignore the error".
        let m = overrun_message(Duration::from_secs(250), Duration::from_secs(300));
        assert!(m.contains("compact_gc_grace_secs"), "{m}");
        assert!(m.contains("offline backup"), "{m}");
        assert!(m.contains("looks complete and is not"), "{m}");
    }
}
