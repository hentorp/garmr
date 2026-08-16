// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! Which backups a scheduled run may delete.
//!
//! Pure, and separated from the deletion itself for the same reason the cold-tier
//! expiry policy is: this decides what to destroy, and a scheduled process that
//! gets it wrong destroys the thing you would use to recover from the mistake.
//! Every rule here is therefore a function with a test rather than a condition
//! inside a loop that also does the deleting.

/// One backup the pruner can see.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackupEntry {
    /// Directory or artifact name, used to delete it.
    pub id: String,
    /// From the manifest. Newest = largest.
    pub created_at_us: i64,
    /// A create-time self-verify verdict of `degraded`, or a manifest that would
    /// not verify at all.
    pub degraded: bool,
}

/// What a prune would do.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PrunePlan {
    /// Deleted, oldest first.
    pub delete: Vec<String>,
    /// Kept, newest first.
    pub keep: Vec<String>,
    /// Why the plan is smaller than `keep` would suggest, when it is.
    pub note: Option<String>,
}

/// Choose which backups to delete so that `keep` remain.
///
/// Four rules, each of which exists because its absence has a specific failure:
///
/// - **`keep = 0` deletes nothing.** The reading "keep zero backups, so delete
///   them all" is catastrophic and is exactly what an unset or mis-parsed
///   config would produce. Zero means "no pruning configured".
/// - **Newest are kept.** Ordering is by `created_at_us` from the manifest, not
///   by filename or mtime: a restored or copied directory has a misleading
///   mtime, and a filename is whatever someone typed.
/// - **At least one NON-DEGRADED backup always survives.** Pruning to a set that
///   contains only images which already failed their own verification leaves a
///   deployment with no usable recovery point while reporting success.
/// - **A tie in timestamps is broken by id**, so the plan is deterministic. Two
///   backups can share a microsecond; a nondeterministic prune makes an
///   incident postmortem impossible to reconstruct.
pub fn plan_prune(mut backups: Vec<BackupEntry>, keep: usize) -> PrunePlan {
    if keep == 0 {
        return PrunePlan {
            keep: backups.into_iter().map(|b| b.id).collect(),
            note: Some("keep = 0 means no pruning is configured; nothing deleted".into()),
            ..Default::default()
        };
    }
    // Newest first, deterministic on ties.
    backups.sort_by(|a, b| {
        b.created_at_us
            .cmp(&a.created_at_us)
            .then_with(|| a.id.cmp(&b.id))
    });
    if backups.len() <= keep {
        return PrunePlan {
            keep: backups.into_iter().map(|b| b.id).collect(),
            ..Default::default()
        };
    }

    let (mut kept, mut doomed): (Vec<_>, Vec<_>) = {
        let tail = backups.split_off(keep);
        (backups, tail)
    };

    // If nothing kept can actually be restored, promote the newest healthy
    // doomed backup into the kept set rather than deleting it. Reporting a
    // successful prune while leaving no usable recovery point is the worst
    // outcome this function can produce.
    let mut note = None;
    if !kept.iter().any(|b| !b.degraded) {
        if let Some(pos) = doomed.iter().position(|b| !b.degraded) {
            let rescued = doomed.remove(pos);
            note = Some(format!(
                "kept {} beyond the retention count: every backup within it is degraded, \
                 and pruning would have left no verifiable recovery point",
                rescued.id
            ));
            kept.push(rescued);
        } else {
            note = Some(
                "every backup is degraded — pruning proceeded, but this deployment has no \
                 verifiable recovery point"
                    .into(),
            );
        }
    }

    // Delete oldest first, so an interrupted run has removed the least valuable.
    doomed.sort_by(|a, b| {
        a.created_at_us
            .cmp(&b.created_at_us)
            .then_with(|| a.id.cmp(&b.id))
    });
    PrunePlan {
        delete: doomed.into_iter().map(|b| b.id).collect(),
        keep: kept.into_iter().map(|b| b.id).collect(),
        note,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn b(id: &str, at: i64) -> BackupEntry {
        BackupEntry {
            id: id.into(),
            created_at_us: at,
            degraded: false,
        }
    }
    fn bad(id: &str, at: i64) -> BackupEntry {
        BackupEntry {
            degraded: true,
            ..b(id, at)
        }
    }

    #[test]
    fn keep_zero_deletes_nothing() {
        // The catastrophic misreading: "keep zero backups" = delete them all.
        // An unset or mis-parsed config lands here, so it must mean "no pruning".
        let p = plan_prune(vec![b("a", 1), b("c", 3)], 0);
        assert!(p.delete.is_empty());
        assert_eq!(p.keep.len(), 2);
        assert!(p.note.unwrap().contains("no pruning"));
    }

    #[test]
    fn the_newest_survive_and_the_oldest_go_first() {
        let p = plan_prune(vec![b("old", 1), b("mid", 2), b("new", 3)], 2);
        assert_eq!(p.keep, vec!["new".to_string(), "mid".to_string()]);
        // Oldest first, so an interrupted run has removed the least valuable.
        assert_eq!(p.delete, vec!["old".to_string()]);
    }

    #[test]
    fn ordering_uses_the_manifest_timestamp_not_the_name() {
        // A restored or copied directory has a misleading mtime, and a filename
        // is whatever someone typed — neither can decide what to destroy.
        let p = plan_prune(vec![b("zzz", 9), b("aaa", 1)], 1);
        assert_eq!(p.keep, vec!["zzz".to_string()]);
        assert_eq!(p.delete, vec!["aaa".to_string()]);
    }

    #[test]
    fn a_healthy_backup_is_rescued_when_every_kept_one_is_degraded() {
        // Pruning to a set of images that already failed their own verification
        // leaves no usable recovery point while reporting success.
        let p = plan_prune(vec![bad("new", 3), bad("mid", 2), b("old", 1)], 2);
        assert!(p.keep.contains(&"old".to_string()), "{p:?}");
        assert!(p.delete.is_empty(), "nothing else was old enough to drop");
        assert!(p.note.unwrap().contains("no verifiable recovery point"));
    }

    #[test]
    fn all_degraded_prunes_but_says_so_plainly() {
        // Nothing can be rescued, so the prune proceeds — but silence here would
        // let a deployment believe it has backups when it has none that verify.
        let p = plan_prune(vec![bad("a", 1), bad("b", 2), bad("c", 3)], 1);
        assert_eq!(p.keep, vec!["c".to_string()]);
        assert_eq!(p.delete, vec!["a".to_string(), "b".to_string()]);
        assert!(p.note.unwrap().contains("no verifiable recovery point"));
    }

    #[test]
    fn fewer_backups_than_the_keep_count_is_a_no_op() {
        let p = plan_prune(vec![b("a", 1)], 5);
        assert!(p.delete.is_empty());
        assert_eq!(p.keep, vec!["a".to_string()]);
    }

    #[test]
    fn a_timestamp_tie_is_broken_deterministically() {
        // Two backups can share a microsecond. A nondeterministic prune makes an
        // incident postmortem impossible to reconstruct.
        let first = plan_prune(vec![b("b", 5), b("a", 5), b("c", 9)], 2);
        let again = plan_prune(vec![b("a", 5), b("b", 5), b("c", 9)], 2);
        assert_eq!(first.delete, again.delete);
        assert_eq!(first.keep, again.keep);
    }
}
