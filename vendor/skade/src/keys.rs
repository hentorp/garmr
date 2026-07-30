// Apache-2.0 licensed.

//! Key encoding for redb tables.
//!
//! redb stores raw bytes; we use `\x1f` (ASCII Unit Separator) between
//! `(catalog_name, namespace_path, leaf)` components. Iceberg namespace
//! parts cannot themselves contain `\x1f`, and we additionally forbid `.`
//! inside any component (Iceberg's own conventions enforce this).

use iceberg::{NamespaceIdent, TableIdent};

pub(crate) const SEP: char = '\x1f';

/// Byte length of the dot-joined namespace path — the exact capacity the parts
/// occupy once written with `.` separators, computed WITHOUT allocating. `SEP`
/// and `.` are each one UTF-8 byte, so `len-1` dots join `len` parts.
#[inline]
fn ns_path_len(ns: &[String]) -> usize {
    ns.iter().map(|p| p.len()).sum::<usize>() + ns.len().saturating_sub(1)
}

/// Append the dot-joined namespace path to `buf` by reference — no intermediate
/// `String`. Byte-identical to writing `ns.join(".")`.
#[inline]
fn push_ns_path(buf: &mut String, ns: &[String]) {
    for (i, part) in ns.iter().enumerate() {
        if i > 0 {
            buf.push('.');
        }
        buf.push_str(part);
    }
}

/// Encode a namespace path. Multi-part namespaces are joined with `.`,
/// matching `iceberg-catalog-sql` behaviour. `NamespaceIdent` derefs to
/// `[String]`, so we join by reference — no `clone()`/`inner()` copy.
pub(crate) fn ns_path(ns: &NamespaceIdent) -> String {
    ns.join(".")
}

/// Key for `NAMESPACES` table: `"{catalog}\x1f{ns_path}"`.
///
/// Allocation-lean (hot path — every namespace lookup/create/update): one
/// pre-sized `String`, pushing the namespace parts by reference. Avoids the
/// intermediate `ns_path` join `String` + the `format!` allocation (2→1).
/// Byte-identical to `format!("{catalog}{SEP}{ns_joined_by_dot}")` — pinned by
/// `ns_keys_are_byte_identical_to_legacy_format` below.
pub(crate) fn namespace_key(catalog: &str, ns: &NamespaceIdent) -> String {
    let ns: &[String] = ns;
    let mut key = String::with_capacity(catalog.len() + 1 + ns_path_len(ns));
    key.push_str(catalog);
    key.push(SEP);
    push_ns_path(&mut key, ns);
    key
}

/// Key for `NAMESPACE_PROPS` table: `"{catalog}\x1f{ns_path}\x1f{prop}"`.
///
/// Single pre-sized `String` (2 allocs → 1); byte-identical to the legacy
/// `format!("{catalog}{SEP}{ns_path}{SEP}{prop}")`.
pub(crate) fn namespace_prop_key(catalog: &str, ns: &NamespaceIdent, prop: &str) -> String {
    let ns: &[String] = ns;
    let mut key = String::with_capacity(catalog.len() + 1 + ns_path_len(ns) + 1 + prop.len());
    key.push_str(catalog);
    key.push(SEP);
    push_ns_path(&mut key, ns);
    key.push(SEP);
    key.push_str(prop);
    key
}

/// Inclusive lower bound for scanning all property entries of a namespace.
///
/// Single pre-sized `String` (2 allocs → 1); byte-identical to the legacy
/// `format!("{catalog}{SEP}{ns_path}{SEP}")`.
pub(crate) fn namespace_prop_prefix(catalog: &str, ns: &NamespaceIdent) -> String {
    let ns: &[String] = ns;
    let mut key = String::with_capacity(catalog.len() + 1 + ns_path_len(ns) + 1);
    key.push_str(catalog);
    key.push(SEP);
    push_ns_path(&mut key, ns);
    key.push(SEP);
    key
}

/// Key for `TABLES` table: `"{catalog}\x1f{ns_path}\x1f{table}"`.
///
/// Allocation-lean (hot path — one per commit + every catalog op): builds the
/// key into a SINGLE pre-sized `String`, pushing the namespace parts by
/// reference. Avoids the old `ns.clone().inner()` copy, the intermediate
/// `ns_path` `String`, and the `format!` machinery. Byte-identical to
/// `format!("{catalog}{SEP}{ns_joined_by_dot}{SEP}{name}")` — pinned by
/// `table_key_is_byte_identical_to_legacy_format` below.
pub(crate) fn table_key(catalog: &str, table: &TableIdent) -> String {
    let ns: &[String] = table.namespace();
    let name = table.name();
    let mut key = String::with_capacity(catalog.len() + 1 + ns_path_len(ns) + 1 + name.len());
    key.push_str(catalog);
    key.push(SEP);
    push_ns_path(&mut key, ns);
    key.push(SEP);
    key.push_str(name);
    key
}

/// Inclusive lower bound for scanning all tables in a namespace.
///
/// Single pre-sized `String` (2 allocs → 1); byte-identical to the legacy
/// `format!("{catalog}{SEP}{ns_path}{SEP}")`. (Same byte shape as
/// `namespace_prop_prefix` — kept a distinct fn for call-site clarity.)
pub(crate) fn table_prefix(catalog: &str, ns: &NamespaceIdent) -> String {
    let ns: &[String] = ns;
    let mut key = String::with_capacity(catalog.len() + 1 + ns_path_len(ns) + 1);
    key.push_str(catalog);
    key.push(SEP);
    push_ns_path(&mut key, ns);
    key.push(SEP);
    key
}

/// Inclusive lower bound for scanning all keys in a catalog.
pub(crate) fn catalog_prefix(catalog: &str) -> String {
    let mut key = String::with_capacity(catalog.len() + 1);
    key.push_str(catalog);
    key.push(SEP);
    key
}

/// Compute an exclusive upper bound for a string prefix by incrementing the
/// last byte. Used to bound redb range scans.
pub(crate) fn prefix_upper(prefix: &str) -> String {
    let mut bytes = prefix.as_bytes().to_vec();
    // Walk back, incrementing the last non-0xFF byte.
    while let Some(last) = bytes.last_mut() {
        if *last < 0xFF {
            *last += 1;
            // After incrementing, the byte sequence may not be valid UTF-8 in
            // general, but since our prefixes always end with ASCII `\x1f` or
            // an ASCII catalog name + `\x1f`, incrementing yields ASCII again.
            return String::from_utf8(bytes).expect("prefix increment stays ASCII");
        } else {
            bytes.pop();
        }
    }
    // All bytes were 0xFF — caller should treat this as "scan to end".
    String::new()
}

#[cfg(test)]
mod tests {
    use super::*;
    use iceberg::{NamespaceIdent, TableIdent};

    fn ns(parts: &[&str]) -> NamespaceIdent {
        NamespaceIdent::from_strs(parts.iter().copied()).unwrap()
    }

    fn table(ns_parts: &[&str], name: &str) -> TableIdent {
        TableIdent::new(ns(ns_parts), name.to_string())
    }

    #[test]
    fn ns_path_joins_multi_part_with_dot() {
        assert_eq!(ns_path(&ns(&["a"])), "a");
        assert_eq!(ns_path(&ns(&["a", "b", "c"])), "a.b.c");
    }

    #[test]
    fn keys_place_the_separator_between_every_component() {
        // The SEP byte (US, 0x1f) — not `.` — is what delimits catalog / ns / leaf,
        // so a namespace part containing `.` can never be confused for a boundary.
        assert_eq!(
            namespace_key("cat", &ns(&["a", "b"])),
            format!("cat{SEP}a.b")
        );
        assert_eq!(
            namespace_prop_key("cat", &ns(&["a"]), "owner"),
            format!("cat{SEP}a{SEP}owner")
        );
        assert_eq!(
            table_key("cat", &table(&["a", "b"], "t")),
            format!("cat{SEP}a.b{SEP}t")
        );
        assert_eq!(
            namespace_prop_prefix("cat", &ns(&["a"])),
            format!("cat{SEP}a{SEP}")
        );
        assert_eq!(table_prefix("cat", &ns(&["a"])), format!("cat{SEP}a{SEP}"));
        assert_eq!(catalog_prefix("cat"), format!("cat{SEP}"));
    }

    /// The table key must fall INSIDE its namespace's table-scan range
    /// `[table_prefix, prefix_upper(table_prefix))` — the exact contract redb
    /// range scans rely on.
    #[test]
    fn table_key_lies_within_its_namespace_scan_range() {
        let lower = table_prefix("cat", &ns(&["a"]));
        let upper = prefix_upper(&lower);
        let k = table_key("cat", &table(&["a"], "orders"));
        assert!(k.as_str() >= lower.as_str(), "key >= inclusive lower bound");
        assert!(k.as_str() < upper.as_str(), "key < exclusive upper bound");
    }

    #[test]
    fn prefix_upper_is_a_true_exclusive_successor() {
        // For a scan [prefix, prefix_upper): every string starting with `prefix`
        // must be < prefix_upper, and prefix_upper itself must exceed `prefix`.
        let prefix = format!("cat{SEP}");
        let upper = prefix_upper(&prefix);
        assert!(upper > prefix, "successor strictly exceeds the prefix");
        // The trailing 0x1f increments to 0x20 (space) — still ASCII.
        assert_eq!(upper, "cat ".to_string(), "0x1f + 1 == 0x20 == ' '");
        for suffix in ["", "a", "zzz", "\u{1f}deep", "\u{7f}"] {
            let key = format!("{prefix}{suffix}");
            assert!(key >= prefix, "{key:?} within lower bound");
            assert!(
                key < upper,
                "{key:?} strictly below the exclusive upper bound"
            );
        }
    }

    /// The property that stops a scan of one catalog leaking into the next: a key
    /// belonging to a lexicographically-adjacent catalog whose name extends this
    /// one (`cat` vs `cat2`) sorts at/above the exclusive upper bound.
    #[test]
    fn scan_range_excludes_sibling_catalog_keys() {
        let lower = catalog_prefix("cat");
        let upper = prefix_upper(&lower); // "cat "
        let sibling = table_key("cat2", &table(&["a"], "t")); // "cat2\x1fa\x1ft"
        assert!(
            sibling.as_str() >= upper.as_str(),
            "cat2's keys are outside the cat scan"
        );
        // And a genuine `cat` key stays inside.
        let mine = table_key("cat", &table(&["a"], "t"));
        assert!(mine.as_str() >= lower.as_str() && mine.as_str() < upper.as_str());
    }

    /// MANDATORY: the allocation-lean `table_key` must be **byte-identical** to
    /// the legacy `format!` it replaced — it is a lookup key, so a single byte
    /// drift silently orphans every existing catalog entry. This pins the exact
    /// old formula against the new builder across the shapes that matter.
    #[test]
    fn table_key_is_byte_identical_to_legacy_format() {
        // The exact pre-optimization implementation.
        fn legacy(catalog: &str, table: &TableIdent) -> String {
            format!(
                "{catalog}{SEP}{}{SEP}{}",
                table.namespace().clone().inner().join("."),
                table.name()
            )
        }
        let cases = [
            ("cat", table(&["a"], "orders")),
            ("cat", table(&["a", "b", "c"], "t")), // multi-part ns → dots
            ("my_catalog", table(&["ns"], "table_name")),
            ("c", table(&["only"], "x")),               // single-part ns
            ("cat", table(&["a-b", "c.d?no"], "名前")), // non-ascii leaf, len via bytes
        ];
        for (cat, tbl) in &cases {
            let new = table_key(cat, tbl);
            let old = legacy(cat, tbl);
            assert_eq!(new, old, "table_key drifted from legacy for {cat}/{tbl:?}");
            assert_eq!(
                new.as_bytes(),
                old.as_bytes(),
                "byte drift for {cat}/{tbl:?}"
            );
        }
    }

    /// Micro-bench `skade.catalog_key` (in-crate — the fn is `pub(crate)`, so it
    /// can't live in the separate `skade-katalog-bench` crate without leaking the
    /// internal). `#[ignore]` so it never adds time/noise to the normal suite —
    /// run on demand: `cargo test -p skade keys::tests::bench_catalog_key -- --ignored --nocapture`.
    /// Non-flaky by design: it asserts only byte-identity per iteration and PRINTS
    /// both timings (the win — one pre-sized alloc vs clone+join+format — is
    /// structural, so we report it rather than assert a fragile timing bound).
    /// Heavy corpus runs belong on the quiet bench box (Loki/Odin), not here.
    /// MANDATORY byte-identity guard for the namespace/prefix key builders that
    /// went from 2 allocs (`ns_path` join + `format!`) to 1 pre-sized `String`.
    /// Each is a lookup key or a range-scan bound, so a single byte of drift
    /// silently orphans catalog entries or breaks a scan boundary. Pins the new
    /// builders against the exact legacy `format!` across single/multi-part
    /// namespaces + a non-ASCII part (length must come from bytes, not chars).
    #[test]
    fn ns_keys_are_byte_identical_to_legacy_format() {
        fn legacy_ns_path(ns: &NamespaceIdent) -> String {
            ns.clone().inner().join(".")
        }
        let cases = [
            ("cat", ns(&["a"]), "owner"),
            ("cat", ns(&["a", "b", "c"]), "retention"),
            ("my_catalog", ns(&["ns"]), "location"),
            ("c", ns(&["only"]), "k"),
            ("cat", ns(&["a-b", "名前"]), "所有者"),
        ];
        for (cat, namespace, prop) in &cases {
            let p = legacy_ns_path(namespace);
            assert_eq!(namespace_key(cat, namespace), format!("{cat}{SEP}{p}"));
            assert_eq!(
                namespace_prop_key(cat, namespace, prop),
                format!("{cat}{SEP}{p}{SEP}{prop}")
            );
            assert_eq!(
                namespace_prop_prefix(cat, namespace),
                format!("{cat}{SEP}{p}{SEP}")
            );
            assert_eq!(table_prefix(cat, namespace), format!("{cat}{SEP}{p}{SEP}"));
            assert_eq!(catalog_prefix(cat), format!("{cat}{SEP}"));
        }
    }

    #[test]
    #[ignore = "micro-bench; run with --ignored --nocapture"]
    fn bench_catalog_key() {
        use std::time::Instant;
        fn legacy_tk(catalog: &str, table: &TableIdent) -> String {
            format!(
                "{catalog}{SEP}{}{SEP}{}",
                table.namespace().clone().inner().join("."),
                table.name()
            )
        }
        fn legacy_nk(catalog: &str, ns: &NamespaceIdent) -> String {
            format!("{catalog}{SEP}{}", ns.clone().inner().join("."))
        }
        fn legacy_tp(catalog: &str, ns: &NamespaceIdent) -> String {
            format!("{catalog}{SEP}{}{SEP}", ns.clone().inner().join("."))
        }
        let tbl = table(&["analytics", "warehouse"], "orders");
        let nsx = ns(&["analytics", "warehouse"]);
        // Byte-identity is asserted ONCE, outside the timed loops — never inside
        // (or the new loop would also pay legacy()+compare and mismeasure).
        assert_eq!(table_key("my_catalog", &tbl), legacy_tk("my_catalog", &tbl));
        assert_eq!(
            namespace_key("my_catalog", &nsx),
            legacy_nk("my_catalog", &nsx)
        );
        assert_eq!(
            table_prefix("my_catalog", &nsx),
            legacy_tp("my_catalog", &nsx)
        );
        let n = 200_000u32;
        let mut sink = 0usize;

        macro_rules! time {
            ($label:literal, $e:expr) => {{
                let t = Instant::now();
                for _ in 0..n {
                    sink = sink.wrapping_add($e.len());
                }
                let per = t.elapsed().as_nanos() / n as u128;
                eprintln!(concat!("  ", $label, " {} ns/op"), per);
            }};
        }
        eprintln!("skade.catalog_key micro-bench (N={n}):");
        time!("table_key   legacy   ", legacy_tk("my_catalog", &tbl));
        time!("table_key   zero-copy", table_key("my_catalog", &tbl));
        time!("namespace   legacy   ", legacy_nk("my_catalog", &nsx));
        time!("namespace   zero-copy", namespace_key("my_catalog", &nsx));
        time!("table_prefix legacy  ", legacy_tp("my_catalog", &nsx));
        time!("table_prefix zerocopy", table_prefix("my_catalog", &nsx));
        eprintln!("  (sink={sink})");
    }

    #[test]
    fn prefix_upper_carries_over_trailing_max_bytes() {
        // Trailing 0xFF bytes are popped and the preceding byte incremented — the
        // carry that keeps the successor a valid exclusive bound.
        // Build from raw bytes (the 0xFF bytes aren't valid UTF-8 in a literal).
        let raw = unsafe { String::from_utf8_unchecked(vec![b'a', 0xFF, 0xFF]) };
        let up = prefix_upper(&raw);
        assert_eq!(
            up.as_bytes(),
            b"b",
            "a\\xff\\xff → b (pop both maxed bytes, bump 'a')"
        );
    }

    #[test]
    fn prefix_upper_all_max_bytes_is_scan_to_end_sentinel() {
        // A prefix that is all 0xFF has no finite successor → empty string, the
        // documented "scan to end" sentinel the caller special-cases.
        let raw = unsafe { String::from_utf8_unchecked(vec![0xFF, 0xFF]) };
        assert_eq!(prefix_upper(&raw), String::new());
        assert_eq!(
            prefix_upper(""),
            String::new(),
            "empty prefix has no successor"
        );
    }
}
