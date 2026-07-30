//! S-tree **range** index over sorted `u32` ranges — Ragnar's third width/use.
//!
//! Built on [`crate::stree32::STree32`] (Ragnar Groot Koerkamp's cache-optimal
//! implicit S+-tree; see `stree32.rs` for the full attribution). Where `STree32`
//! answers *exact membership* over sorted keys, this answers **range containment
//! + range→value**: given a key, find the `[start, end]` range that contains it
//! and return its payload. That is precisely what IPv4/CIDR membership and
//! GeoIP-style IP→ASN/country need — a **floor/predecessor** query the exact-match
//! tree could not express.
//!
//! It works because `STree32::find_exact` already computes the **lower bound**
//! (index of the first stored key `>= q`) during its SIMD descent; `stree32.rs`
//! now exposes that as `lower_bound` / `lower_bound_batch::<P>`, and the floor
//! (greatest start `<= key`) follows in O(1). The **batch** path is the point —
//! Ragnar's software-pipelined prefetch resolves a whole event-batch of keys per
//! pass, the 2M-req/s regime skade's catalog runs in.
//!
//! Build: `RangeStree32::new(ranges)` — O(n log n) sort + O(n) tree build.
//! Query: `lookup(key)` — O(log₁₇ n); `lookup_batch::<P>(keys)` — pipelined.

use crate::stree32::STree32;

/// Immutable index over **non-overlapping** inclusive `[start, end]` `u32`
/// ranges, each carrying a value `V`. A lookup floors to the greatest `start`
/// `<= key` (via the S+-tree) and checks `key <= end` (containment).
pub struct RangeStree32<V> {
    starts: STree32,
    start_vals: Vec<u32>,
    ends: Vec<u32>,
    values: Vec<V>,
}

impl<V> RangeStree32<V> {
    /// Build from `(start, end, value)` ranges. Sorted by `start` internally;
    /// ranges must be non-overlapping and `start <= end` (debug-asserted).
    pub fn new(mut ranges: Vec<(u32, u32, V)>) -> Self {
        assert!(!ranges.is_empty(), "RangeStree32::new: empty input");
        ranges.sort_by_key(|r| r.0);
        #[cfg(debug_assertions)]
        for w in ranges.windows(2) {
            debug_assert!(w[0].0 <= w[0].1, "RangeStree32: start > end");
            debug_assert!(w[0].1 < w[1].0, "RangeStree32: overlapping ranges");
        }
        let start_vals: Vec<u32> = ranges.iter().map(|r| r.0).collect();
        let ends: Vec<u32> = ranges.iter().map(|r| r.1).collect();
        let values: Vec<V> = ranges.into_iter().map(|r| r.2).collect();
        let starts = STree32::new(&start_vals);
        Self {
            starts,
            start_vals,
            ends,
            values,
        }
    }

    /// Given `key` and its lower-bound `pos` (index of the first start `>= key`),
    /// resolve the containing range index, or `None`.
    #[inline]
    fn resolve(&self, key: u32, pos: usize) -> Option<usize> {
        // The greatest start <= key is `pos` when start[pos] == key, else pos-1.
        let ri = if pos < self.start_vals.len() && self.start_vals[pos] == key {
            pos
        } else if pos > 0 {
            pos - 1
        } else {
            return None; // key is below the smallest start
        };
        // Containment: the floored range covers `key` only if key <= its end.
        (key <= self.ends[ri]).then_some(ri)
    }

    /// The value of the range containing `key`, or `None`. O(log₁₇ n).
    #[inline]
    pub fn lookup(&self, key: u32) -> Option<&V> {
        let pos = self.starts.lower_bound(key);
        self.resolve(key, pos).map(|ri| &self.values[ri])
    }

    /// Whether any range contains `key`.
    #[inline]
    pub fn contains(&self, key: u32) -> bool {
        self.lookup(key).is_some()
    }

    /// **Batch lookup — the throughput path.** Resolve a whole slice of keys in
    /// one software-pipelined floor pass (`P` = pipeline depth, e.g. 32/64/128)
    /// followed by the O(1) containment check per key. This is how Ragnar is
    /// meant to be driven: one call per event-batch, all cores' cache-miss
    /// latency overlapped.
    pub fn lookup_batch<const P: usize>(&self, keys: &[u32]) -> Vec<Option<&V>> {
        let poss = self.starts.lower_bound_batch::<P>(keys);
        keys.iter()
            .zip(poss)
            .map(|(&k, pos)| self.resolve(k, pos).map(|ri| &self.values[ri]))
            .collect()
    }

    /// Number of ranges.
    pub fn len(&self) -> usize {
        self.values.len()
    }

    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }
}

/// Convert an IPv4 CIDR `base/prefix_len` to its inclusive `[network, broadcast]`
/// `u32` range — the natural input for [`RangeStree32`] as an IP-CIDR index
/// (build one from a feed's CIDRs, then `lookup_batch` a batch of event `src_ip`
/// values). `prefix_len` is clamped to 32.
pub fn ipv4_cidr_range(base: std::net::Ipv4Addr, prefix_len: u8) -> (u32, u32) {
    let b = u32::from(base);
    let p = prefix_len.min(32);
    if p == 0 {
        return (0, u32::MAX);
    }
    let mask: u32 = u32::MAX << (32 - p);
    let network = b & mask;
    let broadcast = network | !mask;
    (network, broadcast)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    /// Linear reference: the range containing `key` in non-overlapping ranges.
    fn reference<'a, V>(ranges: &'a [(u32, u32, V)], key: u32) -> Option<&'a V> {
        ranges
            .iter()
            .find(|(s, e, _)| *s <= key && key <= *e)
            .map(|(_, _, v)| v)
    }

    #[test]
    fn point_and_gap_membership() {
        let idx = RangeStree32::new(vec![(5u32, 5, 'a'), (10, 10, 'b'), (20, 25, 'c')]);
        assert_eq!(idx.lookup(5), Some(&'a'));
        assert_eq!(idx.lookup(10), Some(&'b'));
        assert_eq!(idx.lookup(22), Some(&'c'));
        assert_eq!(idx.lookup(25), Some(&'c'));
        assert_eq!(idx.lookup(7), None); // in a gap
        assert_eq!(idx.lookup(4), None); // below the smallest start
        assert_eq!(idx.lookup(26), None); // above the largest end
    }

    #[test]
    fn ipv4_cidr_containment() {
        // 10.0.0.0/24 -> [10.0.0.0, 10.0.0.255]; 192.168.1.0/30 -> [.0, .3]
        let (s1, e1) = ipv4_cidr_range(Ipv4Addr::new(10, 0, 0, 0), 24);
        let (s2, e2) = ipv4_cidr_range(Ipv4Addr::new(192, 168, 1, 0), 30);
        assert_eq!(
            (s1, e1),
            (
                u32::from(Ipv4Addr::new(10, 0, 0, 0)),
                u32::from(Ipv4Addr::new(10, 0, 0, 255))
            )
        );
        let idx = RangeStree32::new(vec![(s1, e1, "lan"), (s2, e2, "pt")]);
        assert_eq!(
            idx.lookup(u32::from(Ipv4Addr::new(10, 0, 0, 5))),
            Some(&"lan")
        );
        assert_eq!(
            idx.lookup(u32::from(Ipv4Addr::new(10, 0, 0, 255))),
            Some(&"lan")
        );
        assert_eq!(idx.lookup(u32::from(Ipv4Addr::new(10, 0, 1, 0))), None);
        assert_eq!(
            idx.lookup(u32::from(Ipv4Addr::new(192, 168, 1, 3))),
            Some(&"pt")
        );
        assert_eq!(idx.lookup(u32::from(Ipv4Addr::new(192, 168, 1, 4))), None);
    }

    #[test]
    fn floor_matches_reference_and_batch_matches_single() {
        // Build many disjoint ranges: [i*100+10, i*100+60] -> i, for i in 0..2000.
        let ranges: Vec<(u32, u32, u32)> = (0u32..2000)
            .map(|i| (i * 100 + 10, i * 100 + 60, i))
            .collect();
        let idx = RangeStree32::new(ranges.clone());

        // Probe a mix of hits (inside, edges) and misses (gaps, out of bounds).
        let mut keys: Vec<u32> = Vec::new();
        for i in 0..2000u32 {
            keys.push(i * 100 + 10); // start edge (hit)
            keys.push(i * 100 + 35); // interior (hit)
            keys.push(i * 100 + 60); // end edge (hit)
            keys.push(i * 100 + 80); // gap (miss)
        }
        keys.push(0);
        keys.push(u32::MAX);

        // Single lookups match the linear reference.
        for &k in &keys {
            assert_eq!(
                idx.lookup(k).copied(),
                reference(&ranges, k).copied(),
                "key {k}"
            );
        }
        // Batch (pipelined) matches single lookups exactly.
        let batched: Vec<Option<u32>> = idx
            .lookup_batch::<32>(&keys)
            .into_iter()
            .map(|o| o.copied())
            .collect();
        let single: Vec<Option<u32>> = keys.iter().map(|&k| idx.lookup(k).copied()).collect();
        assert_eq!(batched, single, "batch::<32> must equal single lookups");
    }
}
