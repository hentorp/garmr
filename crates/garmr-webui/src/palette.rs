// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! Global search for the command palette: what may appear as a result, and how
//! results are grouped and bounded.
//!
//! The palette used to end every search with two fabricated rows —
//! `Open user "<whatever you typed>"` and `Open host "<whatever you typed>"` —
//! presented alongside real hits. Typing `asdf` produced a confident-looking
//! "user asdf" that navigated to a page for an entity that does not exist. In a
//! SOC console that is not a cosmetic problem: an analyst can come away believing
//! they checked a subject that was never in the data.
//!
//! The rule enforced here is simple and tested: **an entity result may only exist
//! because a backend row produced it.** Free text can produce exactly one thing —
//! an explicit, clearly-labelled *action* to go and search for that text — and an
//! action is never dressed up as an entity.
//!
//! Pure module; the UI in [`crate::command`] renders what these functions decide.

/// What a result is, which decides its group and how it is announced.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ResultKind {
    /// An explicit "go and search for this" action. The only kind that may be
    /// built from arbitrary typed text.
    SearchAction,
    Investigation,
    User,
    Application,
    Resource,
    Policy,
    /// A console destination (area or sub-tab).
    Page,
}

impl ResultKind {
    /// The group heading results of this kind appear under.
    pub fn group(self) -> &'static str {
        match self {
            ResultKind::SearchAction => "Search",
            ResultKind::Investigation => "Investigations",
            ResultKind::User => "Users",
            ResultKind::Application => "Applications",
            ResultKind::Resource => "Resources",
            ResultKind::Policy => "Policies",
            ResultKind::Page => "Pages",
        }
    }
    /// True when a result of this kind names a real entity from the backend, and
    /// therefore must never be synthesized from typed text.
    pub fn is_entity(self) -> bool {
        !matches!(self, ResultKind::SearchAction | ResultKind::Page)
    }
    /// Display order of the groups.
    pub const ORDER: [ResultKind; 7] = [
        ResultKind::SearchAction,
        ResultKind::Investigation,
        ResultKind::User,
        ResultKind::Application,
        ResultKind::Resource,
        ResultKind::Policy,
        ResultKind::Page,
    ];
}

/// How many results per kind the console ASKS the server for.
///
/// The server enforces its own hard ceiling regardless; this is the palette
/// saying what it can usefully show, not a bound it relies on. Capping now
/// belongs to `/api/entities/search`, which is the only place that can do it
/// without first shipping the rows it would discard.
pub const PER_GROUP_CAP: usize = 6;

/// Does `haystack` match the (already lower-cased, trimmed) query?
///
/// Deliberately a plain substring test: the palette narrows an already-bounded
/// set the server returned, it is not a ranking engine.
pub fn matches(haystack: &str, query_lc: &str) -> bool {
    !query_lc.is_empty() && haystack.to_lowercase().contains(query_lc)
}

/// Per-source status, so a palette can say "Applications failed" instead of
/// quietly showing fewer groups — the same fail-closed principle the command
/// center uses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SourceStatus {
    Loading,
    Ok,
    Failed,
}

/// Summarise the sources behind a search for the palette's status line.
pub fn partial_failure_note(sources: &[(&str, SourceStatus)]) -> Option<String> {
    let failed: Vec<&str> = sources
        .iter()
        .filter(|(_, s)| *s == SourceStatus::Failed)
        .map(|(n, _)| *n)
        .collect();
    if failed.is_empty() {
        return None;
    }
    Some(format!(
        "Some sources could not be searched: {}. Results below are incomplete.",
        failed.join(", ")
    ))
}

/// Is the palette still waiting on anything?
pub fn any_loading(sources: &[(&str, SourceStatus)]) -> bool {
    sources.iter().any(|(_, s)| *s == SourceStatus::Loading)
}

/// Move the highlighted index by `delta`, wrapping, over `len` results.
///
/// Wrapping matters: pressing Down on the last result should return to the first
/// rather than dead-ending, which is what a keyboard-first surface needs.
pub fn move_highlight(current: usize, delta: i32, len: usize) -> usize {
    if len == 0 {
        return 0;
    }
    let n = len as i32;
    (((current as i32 + delta) % n) + n) as usize % len
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The defect this workstream exists to remove: arbitrary text must never
    /// become an entity result.
    #[test]
    fn only_actions_and_pages_may_come_from_typed_text() {
        for k in ResultKind::ORDER {
            match k {
                ResultKind::SearchAction | ResultKind::Page => assert!(
                    !k.is_entity(),
                    "{k:?} may be built from typed text, so it must not be an entity"
                ),
                _ => assert!(
                    k.is_entity(),
                    "{k:?} names a real thing and must come from a backend row"
                ),
            }
        }
    }

    #[test]
    fn search_action_sorts_first_and_pages_last() {
        let mut ks = vec![
            ResultKind::Page,
            ResultKind::Policy,
            ResultKind::SearchAction,
            ResultKind::Investigation,
        ];
        ks.sort();
        assert_eq!(ks[0], ResultKind::SearchAction);
        assert_eq!(*ks.last().unwrap(), ResultKind::Page);
    }

    #[test]
    fn every_kind_has_a_group_heading() {
        for k in ResultKind::ORDER {
            assert!(!k.group().is_empty(), "{k:?} has no group");
        }
    }

    #[test]
    fn matching_is_case_insensitive_and_needs_a_query() {
        assert!(matches("PVE-Daemon", "pve"));
        assert!(matches("root@pam", "ROOT".to_lowercase().as_str()));
        assert!(!matches("anything", ""), "an empty query must not match");
        assert!(!matches("abc", "xyz"));
    }

    #[test]
    fn highlight_wraps_in_both_directions() {
        assert_eq!(move_highlight(0, 1, 3), 1);
        assert_eq!(
            move_highlight(2, 1, 3),
            0,
            "Down on the last wraps to first"
        );
        assert_eq!(move_highlight(0, -1, 3), 2, "Up on the first wraps to last");
        assert_eq!(move_highlight(1, -1, 3), 0);
    }

    #[test]
    fn highlight_is_safe_with_no_results() {
        assert_eq!(move_highlight(0, 1, 0), 0);
        assert_eq!(move_highlight(5, -1, 0), 0);
    }

    #[test]
    fn a_failed_source_is_named_not_hidden() {
        let note = partial_failure_note(&[
            ("Investigations", SourceStatus::Ok),
            ("Applications", SourceStatus::Failed),
            ("Policies", SourceStatus::Failed),
        ])
        .expect("a note is required when a source failed");
        assert!(note.contains("Applications"));
        assert!(note.contains("Policies"));
        assert!(note.contains("incomplete"));
    }

    #[test]
    fn no_note_when_everything_answered() {
        assert_eq!(
            partial_failure_note(&[("Investigations", SourceStatus::Ok)]),
            None
        );
        // Still loading is not the same as failed.
        assert_eq!(
            partial_failure_note(&[("Applications", SourceStatus::Loading)]),
            None
        );
        assert!(any_loading(&[("Applications", SourceStatus::Loading)]));
    }
}
