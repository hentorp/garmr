// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! [`Label`] — an interned, `Arc<str>`-backed string for the low-cardinality
//! label fields of an [`Event`](crate::Event).
//!
//! ## Why this exists
//!
//! A firehose of events carries only a handful of distinct `host`, `service`,
//! `source`, `environment`, `severity`, and `log_type` values across millions of
//! records, yet the old `String` fields heap-allocated all six *afresh* on every
//! event. Under the gatling fan-out that becomes the ceiling: N worker threads
//! serialise in `malloc`/`free` on the shared heap, so `cores_busy` climbs to
//! 19–30/32 while wall speedup stalls at 2–5×.
//!
//! [`Label`] replaces those `String`s. Constructing one from a value that has
//! been seen before is an **atomic refcount bump on a shared `Arc<str>`, not a
//! heap allocation** — the interner touches the heap only on first sight of a
//! value. The cache is bounded, so unexpectedly high-cardinality or oversized
//! values remain ordinary `Arc<str>` allocations and are freed with their last
//! user. There is no C here (the charter forbids a C allocator); the pool is a
//! sharded, read-mostly table of pure-Rust `std` primitives.
//!
//! ## Drop-in for `String`
//!
//! `Label` derefs to `str`, so every read site that used `&event.host` as a
//! `&str` keeps compiling. It also carries `PartialEq<&str>` / `PartialEq<str>` /
//! `PartialEq<String>`, `Display`, `From<&str>` / `From<String>`, `Default`, and
//! hand-rolled serde that ser/de as a plain string — so `event.host == "pve"`,
//! `"pve".into()`, NDJSON, and the Flight wire stay byte-identical to the old
//! `String` version. `From` interns, so every existing `"pve".into()`
//! construction site gains dedup with no edit.

use std::borrow::Borrow;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::ops::Deref;
use std::sync::{Arc, OnceLock, RwLock};

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Number of independent shards in the interner pool. Each shard has its own
/// lock, so the gatling fan-out spreads interner traffic across 64 locks instead
/// of contending on one — the pool must not trade allocator contention for
/// lock contention (design guard).
const SHARDS: usize = 64;

/// Bound permanent interner storage. Labels beyond either limit still work,
/// but are not retained by the process-global pool. Keeping the limits local to
/// each shard avoids a global counter (and therefore a new contention point).
const MAX_ENTRIES_PER_SHARD: usize = 256;
const MAX_INTERNED_LABEL_BYTES: usize = 1024;

/// The global interner: `SHARDS` independently-locked sets of `Arc<str>`.
///
/// Read-mostly by construction — a value is inserted once (on first sight) then
/// only ever looked up. The common path takes the shard's read lock, finds the
/// existing `Arc`, and clones it (an atomic increment); only a genuinely new
/// value takes the write lock.
struct Pool {
    shards: Box<[RwLock<HashSetStr>]>,
}

impl Pool {
    fn new() -> Self {
        let mut shards = Vec::with_capacity(SHARDS);
        for _ in 0..SHARDS {
            shards.push(RwLock::new(HashSetStr::new()));
        }
        Self {
            shards: shards.into_boxed_slice(),
        }
    }
}

/// Thin alias so the shard type reads clearly.
type HashSetStr = std::collections::HashSet<Arc<str>>;

fn pool() -> &'static Pool {
    static POOL: OnceLock<Pool> = OnceLock::new();
    POOL.get_or_init(Pool::new)
}

/// FNV-1a — a tiny, pure-Rust hash used only to pick a shard. Cheap and
/// deterministic; the per-shard `HashSet` uses `std`'s SipHash for the actual
/// membership test.
fn shard_of(s: &str) -> usize {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in s.as_bytes() {
        h ^= *b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    (h as usize) & (SHARDS - 1)
}

/// Intern `s`, returning a shared `Arc<str>` when it fits in the bounded cache.
/// Values encountered after their shard is full, and oversized values, remain
/// valid labels but are not retained globally. Thread-safe and deterministic.
pub fn intern(s: &str) -> Arc<str> {
    intern_in(pool(), s)
}

fn intern_in(pool: &Pool, s: &str) -> Arc<str> {
    // Do not let a single attacker-controlled value consume arbitrary amounts
    // of permanent memory.
    if s.len() > MAX_INTERNED_LABEL_BYTES {
        return Arc::from(s);
    }

    let shard = &pool.shards[shard_of(s)];
    // Fast, read-mostly path: the value is almost always already present.
    if let Some(found) = shard.read().unwrap().get(s) {
        return found.clone();
    }
    // First sight (or a race): take the write lock and insert once.
    let mut w = shard.write().unwrap();
    if let Some(found) = w.get(s) {
        return found.clone();
    }
    // Native ingest labels can be sender-controlled. Once this shard reaches
    // its budget, preserve label semantics without retaining new values for
    // the lifetime of the process.
    if w.len() >= MAX_ENTRIES_PER_SHARD {
        return Arc::from(s);
    }
    let arc: Arc<str> = Arc::from(s);
    w.insert(arc.clone());
    arc
}

/// Number of distinct strings currently interned (across all shards). For tests
/// and diagnostics only.
pub fn interned_len() -> usize {
    pool().shards.iter().map(|s| s.read().unwrap().len()).sum()
}

/// An interned, cheaply-cloneable string for a low-cardinality label field.
///
/// See the [module docs](self). Backed by an `Arc<str>` drawn from the bounded
/// global [`intern`] pool when possible; `clone` is an atomic refcount bump,
/// not an allocation.
#[derive(Clone)]
pub struct Label(Arc<str>);

impl Label {
    /// Intern `s` into a `Label`.
    #[inline]
    pub fn new(s: &str) -> Self {
        Label(intern(s))
    }

    /// The underlying string slice.
    #[inline]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Default for Label {
    #[inline]
    fn default() -> Self {
        Label::new("")
    }
}

impl Deref for Label {
    type Target = str;
    #[inline]
    fn deref(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for Label {
    #[inline]
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl Borrow<str> for Label {
    #[inline]
    fn borrow(&self) -> &str {
        &self.0
    }
}

impl From<&str> for Label {
    #[inline]
    fn from(s: &str) -> Self {
        Label(intern(s))
    }
}

impl From<String> for Label {
    #[inline]
    fn from(s: String) -> Self {
        Label(intern(&s))
    }
}

impl From<&String> for Label {
    #[inline]
    fn from(s: &String) -> Self {
        Label(intern(s))
    }
}

impl From<Arc<str>> for Label {
    #[inline]
    fn from(s: Arc<str>) -> Self {
        Label(intern(&s))
    }
}

impl From<Label> for String {
    #[inline]
    fn from(l: Label) -> String {
        l.0.to_string()
    }
}

impl fmt::Display for Label {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Debug for Label {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Print like a plain string so Event's derived Debug is unchanged.
        fmt::Debug::fmt(&*self.0, f)
    }
}

// --- Equality / ordering / hashing: all by string *content*, matching `String`.
// `Arc<str>` already forwards these to the `str` pointee, but spelling them out
// keeps `Label` comparable to `str`/`&str`/`String` the way `String` was.

impl PartialEq for Label {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        *self.0 == *other.0
    }
}
impl Eq for Label {}

impl PartialEq<str> for Label {
    #[inline]
    fn eq(&self, other: &str) -> bool {
        &*self.0 == other
    }
}
impl PartialEq<&str> for Label {
    #[inline]
    fn eq(&self, other: &&str) -> bool {
        &*self.0 == *other
    }
}
impl PartialEq<String> for Label {
    #[inline]
    fn eq(&self, other: &String) -> bool {
        &*self.0 == other.as_str()
    }
}
impl PartialEq<Label> for str {
    #[inline]
    fn eq(&self, other: &Label) -> bool {
        self == &*other.0
    }
}
impl PartialEq<Label> for &str {
    #[inline]
    fn eq(&self, other: &Label) -> bool {
        *self == &*other.0
    }
}
impl PartialEq<Label> for String {
    #[inline]
    fn eq(&self, other: &Label) -> bool {
        self.as_str() == &*other.0
    }
}

impl PartialOrd for Label {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for Label {
    #[inline]
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        (*self.0).cmp(&*other.0)
    }
}

impl Hash for Label {
    #[inline]
    fn hash<H: Hasher>(&self, state: &mut H) {
        // Hash the string content so `Label` and `str` hash identically —
        // required for `Borrow<str>` lookups and to match the old `String`.
        (*self.0).hash(state)
    }
}

impl Serialize for Label {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for Label {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        // A visitor that interns straight from the (possibly borrowed) input.
        //
        // NOTE: we deliberately do NOT go through `Cow<str>` here — serde's
        // `Deserialize for Cow<str>` always yields `Cow::Owned`, i.e. it heap-
        // allocates a `String` even when the input could be borrowed, which is
        // exactly the per-event allocation we are trying to kill. Driving a
        // visitor with `deserialize_str` instead lets serde_json hand us a
        // `visit_borrowed_str` slice pointing into the parse buffer (no alloc)
        // on the common unescaped path; either way `intern` only touches the
        // heap on first sight of a value, so a repeated label costs nothing.
        struct LabelVisitor;
        impl serde::de::Visitor<'_> for LabelVisitor {
            type Value = Label;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a string label")
            }
            fn visit_str<E>(self, v: &str) -> Result<Label, E> {
                Ok(Label(intern(v)))
            }
            fn visit_string<E>(self, v: String) -> Result<Label, E> {
                Ok(Label(intern(&v)))
            }
        }
        deserializer.deserialize_str(LabelVisitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interns_identical_values_to_same_alloc() {
        let a = intern("prod");
        let b = intern("prod");
        assert!(
            Arc::ptr_eq(&a, &b),
            "equal strings must share one allocation"
        );
        let c = intern("lab");
        assert!(!Arc::ptr_eq(&a, &c));
    }

    #[test]
    fn label_is_semantically_a_string() {
        let l: Label = "sshd".into();
        assert_eq!(l, "sshd"); // PartialEq<&str>
        assert_eq!(l.as_str(), "sshd");
        assert_eq!(&*l, "sshd"); // Deref
        assert_eq!(format!("{l}"), "sshd"); // Display
        assert_eq!(l.len(), 4); // via Deref to str
        assert!(l.starts_with("ss"));
        let s: String = l.clone().into();
        assert_eq!(s, "sshd");
    }

    #[test]
    fn from_string_and_str_intern_equally() {
        let a: Label = "journald".into();
        let b: Label = String::from("journald").into();
        assert!(Arc::ptr_eq(&a.0, &b.0));
    }

    #[test]
    fn serde_round_trips_as_a_plain_string() {
        let l: Label = "warning".into();
        let json = serde_json::to_string(&l).unwrap();
        assert_eq!(json, "\"warning\"");
        let back: Label = serde_json::from_str(&json).unwrap();
        assert_eq!(back, "warning");
        // Deserialised value shares the interned allocation.
        assert!(Arc::ptr_eq(&intern("warning"), &back.0));
    }

    #[test]
    fn default_is_empty() {
        let l = Label::default();
        assert_eq!(l, "");
        assert!(l.is_empty());
    }

    #[test]
    fn ordering_and_hashing_match_str() {
        use std::collections::HashMap;
        let a: Label = "a".into();
        let b: Label = "b".into();
        assert!(a < b);
        let mut m: HashMap<Label, u8> = HashMap::new();
        m.insert("x".into(), 1);
        // Borrow<str> lets us look up by &str.
        assert_eq!(m.get("x"), Some(&1));
    }

    #[test]
    fn oversized_values_are_not_retained() {
        let value = "x".repeat(MAX_INTERNED_LABEL_BYTES + 1);
        let a = intern(&value);
        let b = intern(&value);
        assert_eq!(a, b);
        assert!(!Arc::ptr_eq(&a, &b));
    }

    #[test]
    fn full_shards_do_not_retain_more_values() {
        let pool = Pool::new();
        let target = shard_of("bounded-interner-test");
        let mut candidate = 0usize;
        while pool.shards[target].read().unwrap().len() < MAX_ENTRIES_PER_SHARD {
            let value = format!("bounded-interner-fill-{candidate}");
            candidate += 1;
            if shard_of(&value) == target {
                intern_in(&pool, &value);
            }
        }

        let overflow = loop {
            let value = format!("bounded-interner-overflow-{candidate}");
            candidate += 1;
            if shard_of(&value) == target
                && !pool.shards[target].read().unwrap().contains(value.as_str())
            {
                break value;
            }
        };
        let before = pool.shards[target].read().unwrap().len();
        let a = intern_in(&pool, &overflow);
        let b = intern_in(&pool, &overflow);
        assert_eq!(a, b);
        assert!(!Arc::ptr_eq(&a, &b));
        assert_eq!(pool.shards[target].read().unwrap().len(), before);
    }
}
