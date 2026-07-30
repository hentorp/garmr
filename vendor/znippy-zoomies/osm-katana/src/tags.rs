use std::collections::BTreeMap;

/// Serialise an OSM tag list to the `tags` JSON column.
///
/// **Deterministic by construction.** This used to collect into a
/// `std::collections::HashMap`, whose iteration order is seeded per process by
/// `RandomState` — so two converts of the *same* input produced the same tag
/// SET in a different key ORDER, and therefore different `tags` strings,
/// different parquet bytes, and different row content. That made any
/// "output unchanged?" check on this converter impossible to state, let alone
/// pass (three back-to-back liechtenstein converts gave three different content
/// digests, with 809 / 938 relation rows differing purely in key order).
///
/// A `BTreeMap` keeps the same last-wins duplicate-key semantics as the
/// `HashMap` it replaces, but emits keys in a canonical sorted order, so the
/// output is reproducible run-to-run and machine-to-machine. Sorted keys also
/// group similar tag prefixes together (`name`, `name:de`, `name:en`, …), which
/// is strictly friendlier to the parquet zstd dictionary.
pub fn serialize_tags<'a>(tags: impl Iterator<Item = (&'a str, &'a str)>) -> String {
    let map: BTreeMap<&str, &str> = tags.collect();
    serde_json::to_string(&map).unwrap_or_else(|_| String::from("{}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RED-when-broken: tag serialisation must not depend on the order the pairs
    /// arrive in. This is the property the whole output-equivalence gate rests
    /// on; a regression to `HashMap` (or to an insertion-ordered map) turns it
    /// red immediately.
    #[test]
    fn serialize_tags_is_order_independent_and_sorted() {
        let a = serialize_tags([("name", "X"), ("amenity", "cafe"), ("name:de", "X")].into_iter());
        let b = serialize_tags([("name:de", "X"), ("name", "X"), ("amenity", "cafe")].into_iter());
        assert_eq!(a, b, "input pair order must not change the JSON");
        assert_eq!(a, r#"{"amenity":"cafe","name":"X","name:de":"X"}"#);
    }

    /// Duplicate keys keep the HashMap semantics they replaced: last wins.
    #[test]
    fn serialize_tags_last_duplicate_wins() {
        let s = serialize_tags([("k", "first"), ("k", "second")].into_iter());
        assert_eq!(s, r#"{"k":"second"}"#);
    }

    #[test]
    fn serialize_tags_empty_is_empty_object() {
        assert_eq!(serialize_tags(std::iter::empty()), "{}");
    }
}
