// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! Validation and URL round-tripping for the global time range.
//!
//! The picker looked global but was not: `to_slug`/`from_slug` existed and were
//! never called, so the range lived only in memory. A reload lost it, the browser
//! Back button could not restore it, and a link shared with a colleague showed
//! them a different window of time than the one being discussed — the worst
//! failure mode for an investigation tool.
//!
//! Custom ranges were worse than lost: `apply_custom` parsed both fields and, if
//! either failed or the order was reversed, did **nothing at all**. No error, no
//! change, no clue. Silent rejection of operator input is not a small bug in a
//! console people use to answer "what happened between 02:00 and 04:00".
//!
//! Pure module, unit-tested on the host target.

use crate::TimeRange;

/// Why a custom `[from, to)` range was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RangeError {
    /// One or both endpoints were left empty.
    Missing { from: bool, to: bool },
    /// A value could not be parsed as a local date-time.
    Unparseable { from: bool, to: bool },
    /// `to` is before `from`.
    Reversed,
    /// `from == to`, so the range selects nothing.
    Empty,
}

impl RangeError {
    /// The message shown next to the inputs. Always says which field and what to
    /// do — never a bare "invalid".
    pub fn message(&self) -> String {
        match self {
            RangeError::Missing {
                from: true,
                to: true,
            } => "Enter both a start and an end time.".into(),
            RangeError::Missing { from: true, .. } => "Enter a start time.".into(),
            RangeError::Missing { .. } => "Enter an end time.".into(),
            RangeError::Unparseable {
                from: true,
                to: true,
            } => "Neither time could be read. Use the date-time pickers.".into(),
            RangeError::Unparseable { from: true, .. } => {
                "The start time could not be read. Use the date-time picker.".into()
            }
            RangeError::Unparseable { .. } => {
                "The end time could not be read. Use the date-time picker.".into()
            }
            RangeError::Reversed => {
                "The end time is before the start time — swap them or pick a later end.".into()
            }
            RangeError::Empty => {
                "The start and end times are identical, so the range contains nothing.".into()
            }
        }
    }
}

/// Validate a custom range from the two raw picker values.
///
/// `parsed_from`/`parsed_to` are the already-parsed epoch-millis (`None` when the
/// raw text could not be read); `raw_from`/`raw_to` distinguish "left empty" from
/// "typed something unreadable", which are different operator mistakes and get
/// different advice.
pub fn validate_custom(
    raw_from: &str,
    raw_to: &str,
    parsed_from: Option<i64>,
    parsed_to: Option<i64>,
) -> Result<TimeRange, RangeError> {
    let from_empty = raw_from.trim().is_empty();
    let to_empty = raw_to.trim().is_empty();
    if from_empty || to_empty {
        return Err(RangeError::Missing {
            from: from_empty,
            to: to_empty,
        });
    }
    match (parsed_from, parsed_to) {
        (Some(f), Some(t)) => {
            if f == t {
                Err(RangeError::Empty)
            } else if t < f {
                Err(RangeError::Reversed)
            } else {
                Ok(TimeRange::Absolute(f, t))
            }
        }
        (f, t) => Err(RangeError::Unparseable {
            from: f.is_none(),
            to: t.is_none(),
        }),
    }
}

/// The query-parameter name carrying the range. Short, and never holds anything
/// sensitive — only a preset name or two epoch-millis integers.
pub const PARAM: &str = "t";

/// Merge the range into an existing query string, replacing any previous `t=`.
///
/// Other parameters keep their order and values, so putting the range in the URL
/// never disturbs a view's own filters.
pub fn write_param(query: &str, range: TimeRange) -> String {
    let mut parts: Vec<String> = query
        .split('&')
        .filter(|kv| !kv.is_empty())
        .filter(|kv| {
            let k = kv.split('=').next().unwrap_or("");
            k != PARAM
        })
        .map(str::to_string)
        .collect();
    parts.push(format!("{PARAM}={}", range.to_slug()));
    parts.join("&")
}

/// Read the range out of a query string, if present and valid.
///
/// An unreadable `t=` yields `None` — the caller keeps the current range rather
/// than silently snapping to a default the operator did not choose.
pub fn read_param(query: &str) -> Option<TimeRange> {
    query
        .split('&')
        .filter_map(|kv| kv.split_once('='))
        .find(|(k, _)| *k == PARAM)
        .and_then(|(_, v)| TimeRange::from_slug(v))
}

/// Carry the range out of an existing query string into a freshly built one.
///
/// A view that rebuilds its own query from scratch — publishing a search, a
/// pivot — must not drop the window the analyst chose on the way there. Keeping
/// that in one place beats every publishing view remembering to re-add `t=`,
/// which is exactly what they forgot: switching Audit's mode or Intelligence's
/// tab silently widened the range back out.
pub fn carry(from: &str, into: &str) -> String {
    // A caller that names its own range wins: the picker publishes the window
    // the operator just chose, and Investigations' "reproduce" names the case's
    // own — carrying the outgoing URL's range over either would undo the
    // choice, and the shell's restore effect would then pull the picker there.
    if into
        .split('&')
        .any(|kv| kv.split('=').next() == Some(PARAM))
    {
        return into.to_string();
    }
    match read_param(from) {
        Some(tr) => write_param(into, tr),
        None => into.to_string(),
    }
}

/// Does the global range actually govern this area?
///
/// Being honest about this is the point. The Command Center's sources
/// (`/api/cases`, `/api/risk`, `/api/ingest/health`, `/api/audit/status`) report
/// current posture and take no range, so showing an active range control there
/// implies a filter that does not exist. Where the range does nothing, the
/// control is hidden and the reason stated rather than left as a lie.
pub fn governs(area_label: &str) -> bool {
    matches!(
        area_label,
        "Audit Explorer" | "Intelligence" | "Investigations" | "Users" | "Applications"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slugs_round_trip() {
        for tr in [
            TimeRange::Live,
            TimeRange::Last(24),
            TimeRange::Last(72),
            TimeRange::Last(168),
            TimeRange::Last(720),
            TimeRange::Absolute(1_754_179_200_000, 1_754_265_600_000),
        ] {
            let slug = tr.to_slug();
            assert_eq!(
                TimeRange::from_slug(&slug),
                Some(tr),
                "slug {slug} did not round-trip"
            );
        }
    }

    #[test]
    fn a_shared_link_reproduces_the_same_window() {
        let tr = TimeRange::Absolute(1_754_179_200_000, 1_754_265_600_000);
        let q = write_param("tab=events&q=ssh", tr);
        // The colleague opening this link gets exactly the same range.
        assert_eq!(read_param(&q), Some(tr));
    }

    #[test]
    fn writing_the_range_preserves_other_filters() {
        let q = write_param("tab=events&q=ssh", TimeRange::Last(24));
        assert!(q.contains("tab=events"));
        assert!(q.contains("q=ssh"));
        assert!(q.contains("t=24h"));
    }

    #[test]
    fn writing_replaces_a_previous_range_rather_than_appending() {
        let q = write_param("t=live&tab=events", TimeRange::Last(72));
        assert_eq!(q.matches("t=").count(), 1, "duplicate range params in {q}");
        assert_eq!(read_param(&q), Some(TimeRange::Last(72)));
    }

    #[test]
    fn an_unreadable_range_param_is_ignored_not_guessed() {
        assert_eq!(read_param("t=nonsense"), None);
        assert_eq!(read_param("t="), None);
        assert_eq!(read_param("tab=events"), None);
        assert_eq!(read_param(""), None);
    }

    #[test]
    fn the_range_is_carried_into_a_rebuilt_query() {
        // A search or pivot rebuilds its own query; the window must survive it.
        let q = carry(
            "tab=relationships&t=24h",
            "tab=relationships&kind=host&name=pve",
        );
        assert_eq!(read_param(&q), Some(TimeRange::Last(24)));
        assert!(q.contains("name=pve"), "the new query was lost: {q}");
        assert_eq!(q.matches("t=").count(), 1, "duplicate range params in {q}");
    }

    #[test]
    fn a_caller_that_names_its_own_range_keeps_it() {
        // The picker writes t= itself; carrying the old one over it would undo
        // the operator's choice.
        let next = write_param("mode=text", TimeRange::Last(72));
        assert_eq!(carry("mode=text&t=24h", &next), "mode=text&t=72h");
    }

    #[test]
    fn a_pivot_that_names_its_window_is_not_overwritten_by_the_one_it_leaves() {
        // Investigations' "reproduce" opens the Audit Explorer on the case's
        // own 72 h. The window it happens to be leaving (here 24 h) must not
        // win, or the button reproduces a case in the wrong window.
        let next = write_param("q=web01&mode=text", TimeRange::Last(72));
        assert_eq!(carry("q=other&t=24h", &next), "q=web01&mode=text&t=72h");
    }

    #[test]
    fn carrying_nothing_invents_nothing() {
        // No range chosen yet is not a reason to write one into the URL.
        assert_eq!(carry("tab=map", "tab=relationships"), "tab=relationships");
        assert_eq!(carry("", "mode=text"), "mode=text");
        // An unreadable range is dropped rather than guessed at.
        assert_eq!(carry("t=nonsense", "mode=text"), "mode=text");
    }

    // ---- custom range validation: never silently ignored --------------------

    #[test]
    fn a_valid_custom_range_is_accepted() {
        assert_eq!(
            validate_custom("2026-08-01T02:00", "2026-08-01T04:00", Some(100), Some(200)),
            Ok(TimeRange::Absolute(100, 200))
        );
    }

    #[test]
    fn missing_endpoints_name_the_missing_field() {
        assert_eq!(
            validate_custom("", "2026-08-01T04:00", None, Some(200)),
            Err(RangeError::Missing {
                from: true,
                to: false
            })
        );
        assert_eq!(
            validate_custom("2026-08-01T02:00", "  ", Some(100), None),
            Err(RangeError::Missing {
                from: false,
                to: true
            })
        );
        assert!(validate_custom("", "", None, None)
            .unwrap_err()
            .message()
            .contains("both"));
    }

    #[test]
    fn a_reversed_range_is_refused_with_advice() {
        let e = validate_custom("2026-08-01T04:00", "2026-08-01T02:00", Some(200), Some(100))
            .unwrap_err();
        assert_eq!(e, RangeError::Reversed);
        assert!(e.message().contains("before the start"));
    }

    #[test]
    fn an_empty_range_is_refused() {
        assert_eq!(
            validate_custom("2026-08-01T02:00", "2026-08-01T02:00", Some(100), Some(100)),
            Err(RangeError::Empty)
        );
    }

    #[test]
    fn unreadable_input_says_which_field() {
        assert_eq!(
            validate_custom("garbage", "2026-08-01T04:00", None, Some(200)),
            Err(RangeError::Unparseable {
                from: true,
                to: false
            })
        );
    }

    #[test]
    fn every_error_produces_actionable_text() {
        for e in [
            RangeError::Missing {
                from: true,
                to: true,
            },
            RangeError::Missing {
                from: true,
                to: false,
            },
            RangeError::Missing {
                from: false,
                to: true,
            },
            RangeError::Unparseable {
                from: true,
                to: false,
            },
            RangeError::Unparseable {
                from: false,
                to: true,
            },
            RangeError::Reversed,
            RangeError::Empty,
        ] {
            let m = e.message();
            assert!(m.len() > 12, "{e:?} message too terse: {m}");
            assert!(m.ends_with('.'), "{e:?} message should be a sentence");
        }
    }

    // ---- the range reaches the search request -------------------------------

    #[test]
    fn hsearch_time_carries_the_active_window_as_ir_micros() {
        // Live is the IR's default (no time clause) — nothing to claim.
        assert_eq!(TimeRange::Live.hsearch_time(), None);
        // A preset stays relative; the server anchors it to its own clock.
        assert_eq!(
            TimeRange::Last(24).hsearch_time(),
            Some(serde_json::json!({ "last_hours": 24 }))
        );
        // An absolute range converts millis → the IR's micros.
        assert_eq!(
            TimeRange::Absolute(1_754_179_200_000, 1_754_265_600_000).hsearch_time(),
            Some(serde_json::json!({
                "from_micros": 1_754_179_200_000_000i64,
                "to_micros": 1_754_265_600_000_000i64,
            }))
        );
        // A nonsense slug saturates to an empty window (finds nothing) rather
        // than dropping the bound and searching unbounded behind the picker.
        assert_eq!(
            TimeRange::Absolute(i64::MAX, i64::MAX).hsearch_time(),
            Some(serde_json::json!({
                "from_micros": i64::MAX,
                "to_micros": i64::MAX,
            }))
        );
    }

    #[test]
    fn search_params_carry_the_active_window() {
        // Live is the endpoint's default (unbounded) — no parameter to claim.
        assert_eq!(TimeRange::Live.search_params(), "");
        // Presets and absolute ranges append the same window /map understands.
        assert_eq!(TimeRange::Last(24).search_params(), "&hours=24");
        assert_eq!(
            TimeRange::Absolute(1_754_179_200_000, 1_754_265_600_000).search_params(),
            "&from=1754179200000&to=1754265600000"
        );
    }

    // ---- honesty about scope ------------------------------------------------

    #[test]
    fn the_range_is_only_claimed_where_it_applies() {
        assert!(governs("Audit Explorer"));
        assert!(governs("Intelligence"));
        // The Command Center reports current posture from range-less endpoints,
        // so a range control there would imply a filter that does not exist.
        assert!(!governs("Command Center"));
        assert!(!governs("System"));
        assert!(!governs("Data Sources"));
    }

    #[test]
    fn no_sensitive_value_can_reach_the_url() {
        // The slug vocabulary is closed: a preset word or two integers. There is
        // no path by which a query, token or entity name enters the range param.
        for tr in [
            TimeRange::Live,
            TimeRange::Last(24),
            TimeRange::Absolute(1, 2),
        ] {
            let s = tr.to_slug();
            assert!(
                s.chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == 'h'),
                "unexpected characters in slug {s}"
            );
        }
    }
}
