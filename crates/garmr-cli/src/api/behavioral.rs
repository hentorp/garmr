// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! Small shared read-side helpers for the behavioral product surfaces (users,
//! applications, resources): outcome labelling, the per-dimension footprint
//! projection, and top-N counting. One home so the three surfaces stay consistent
//! (the same value renders the same way everywhere).

use garmr_baseline::CategoricalStat;
use garmr_core::app_audit::Outcome;

use super::*;

/// How many top values per categorical dimension a footprint reports.
pub(super) const TOP_VALUES: usize = 15;

/// The canonical lowercase outcome label.
pub(super) fn outcome_label(o: &Outcome) -> &'static str {
    match o {
        Outcome::Success => "success",
        Outcome::Failure => "failure",
        Outcome::Denied => "denied",
        Outcome::Error => "error",
        Outcome::Unknown => "unknown",
    }
}

/// Whether an outcome is a non-success (denied / failed / errored) access.
pub(super) fn outcome_failed(o: &Outcome) -> bool {
    matches!(o, Outcome::Failure | Outcome::Denied | Outcome::Error)
}

/// A categorical dimension's footprint: its cardinality, how many distinct values
/// were dropped after the per-dimension cap, and the top values by hit count.
pub(super) fn dim_footprint(stat: &CategoricalStat) -> Value {
    let mut vals: Vec<_> = stat.values.iter().collect();
    // Most-used first, ties broken by value for a stable order.
    vals.sort_by(|a, b| b.1.count.cmp(&a.1.count).then_with(|| a.0.cmp(b.0)));
    let top: Vec<Value> = vals
        .iter()
        .take(TOP_VALUES)
        .map(|(v, o)| {
            json!({ "value": v, "count": o.count, "first_seen": o.first_seen, "last_seen": o.last_seen })
        })
        .collect();
    json!({ "distinct": stat.distinct(), "dropped": stat.dropped, "top": top })
}

/// Top-N `(value, count)` pairs over an iterator of owned strings, highest count
/// first, ties broken by value for a stable order.
pub(super) fn top_counts(values: impl Iterator<Item = String>, n: usize) -> Vec<Value> {
    let mut counts: std::collections::HashMap<String, u64> = std::collections::HashMap::new();
    for v in values {
        *counts.entry(v).or_insert(0) += 1;
    }
    let mut pairs: Vec<(String, u64)> = counts.into_iter().collect();
    pairs.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    pairs
        .into_iter()
        .take(n)
        .map(|(value, count)| json!({ "value": value, "count": count }))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{DateTime, Utc};
    use garmr_baseline::ValueObs;

    fn ts(secs: i64) -> DateTime<Utc> {
        DateTime::<Utc>::from_timestamp(secs, 0).unwrap()
    }
    fn vobs(count: u64) -> ValueObs {
        ValueObs {
            count,
            first_seen: ts(0),
            last_seen: ts(count as i64),
        }
    }

    #[test]
    fn outcome_labels_and_failed_cover_every_variant() {
        for (o, label, failed) in [
            (Outcome::Success, "success", false),
            (Outcome::Failure, "failure", true),
            (Outcome::Denied, "denied", true),
            (Outcome::Error, "error", true),
            (Outcome::Unknown, "unknown", false),
        ] {
            assert_eq!(outcome_label(&o), label);
            assert_eq!(outcome_failed(&o), failed, "{label}");
        }
    }

    #[test]
    fn dim_footprint_ranks_top_values_and_reports_cardinality() {
        let mut stat = CategoricalStat::default();
        stat.values.insert("psql".into(), vobs(10));
        stat.values.insert("jupyter".into(), vobs(3));
        stat.values.insert("dbeaver".into(), vobs(7));
        stat.dropped = 2;
        let v = dim_footprint(&stat);
        assert_eq!(v["distinct"], 3);
        assert_eq!(v["dropped"], 2);
        assert_eq!(v["top"][0]["value"], "psql");
        assert_eq!(v["top"][0]["count"], 10);
        assert_eq!(v["top"][1]["value"], "dbeaver");
        assert_eq!(v["top"][2]["value"], "jupyter");
    }

    #[test]
    fn dim_footprint_caps_top_at_top_values_but_reports_full_cardinality() {
        let mut stat = CategoricalStat::default();
        for i in 0..20u64 {
            stat.values.insert(format!("v{i:02}"), vobs(i + 1));
        }
        let v = dim_footprint(&stat);
        assert_eq!(v["distinct"], 20);
        assert_eq!(v["top"].as_array().unwrap().len(), TOP_VALUES);
        assert_eq!(v["top"][0]["value"], "v19");
        assert_eq!(v["top"][0]["count"], 20);
    }

    #[test]
    fn top_counts_ranks_by_count_then_value() {
        let vals = ["b", "a", "a", "c", "a", "b"].iter().map(|s| s.to_string());
        let top = top_counts(vals, 2);
        assert_eq!(top.len(), 2);
        assert_eq!(top[0]["value"], "a");
        assert_eq!(top[0]["count"], 3);
        assert_eq!(top[1]["value"], "b");
        assert_eq!(top[1]["count"], 2);
    }
}
