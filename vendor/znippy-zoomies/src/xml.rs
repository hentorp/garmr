//! Generic VTD-style parallel XML element scanner.
//!
//! The scanning machinery extracted from [`crate::vtd`] (which remains the OSM
//! specialization layered on top of this module). Nothing here knows about
//! nodes/ways/relations — the set of element names to index is caller-supplied
//! as a [`TagSet`] mapping each name to a caller-meaningful `u8` kind id.
//!
//! Pass 1: SIMD forward scan (memchr/AVX2) over a borrowed `&[u8]` buffer.
//!         Emits one `(kind, ElemSpan)` callback per matched top-level element.
//!         Zero-copy: spans are byte offsets, never owned data.
//!
//! Parallel split = candidate offset + forward seek: each worker takes a
//! nominal byte offset and seeks forward to the next safe top-level element
//! start ([`find_top_level_start`]); slot/slice ends are trimmed back to the
//! last complete element ([`find_safe_slot_end`]). No element is ever split
//! across slices, and no barrier exists between slices.
//!
//! Design laws (inherited from vtd):
//!   - scanners borrow, never copy input
//!   - no allocation in the hot path (the [`TagSet`] is pre-built; callbacks
//!     receive spans/slices)
//!   - deterministic: output is identical for any worker count

use anyhow::Result;
use memchr::memchr;

// ── TagSet: caller-supplied element table ────────────────────────────────────

/// One indexed element name. Closing tag bytes (`</name>`) are pre-built at
/// construction so the scan loop never allocates.
#[derive(Debug, Clone)]
struct TagEntry {
    name: Box<[u8]>,
    closing: Box<[u8]>, // b"</name>"
    kind: u8,
}

/// Pre-built table of element names to index, each mapped to a caller-defined
/// `u8` kind id. Built once (allocates), then shared read-only across workers.
///
/// ```
/// use znippy_zoomies::xml::TagSet;
/// let tags = TagSet::new(&[(&b"node"[..], 0), (b"way", 1), (b"relation", 2)]);
/// ```
#[derive(Debug, Clone)]
pub struct TagSet {
    entries: Vec<TagEntry>,
}

impl TagSet {
    /// Build a tag table from `(element_name, kind_id)` pairs.
    pub fn new<N: AsRef<[u8]>>(tags: &[(N, u8)]) -> Self {
        let entries = tags
            .iter()
            .map(|(name, kind)| {
                let name = name.as_ref();
                let mut closing = Vec::with_capacity(name.len() + 3);
                closing.extend_from_slice(b"</");
                closing.extend_from_slice(name);
                closing.push(b'>');
                TagEntry {
                    name: name.into(),
                    closing: closing.into_boxed_slice(),
                    kind: *kind,
                }
            })
            .collect();
        Self { entries }
    }

    /// Match a bare tag name (the bytes between `<` and the first space / `>`).
    #[inline]
    fn entry_for(&self, name: &[u8]) -> Option<&TagEntry> {
        self.entries.iter().find(|e| &*e.name == name)
    }

    /// Does `rest` (the bytes just after a `<`) start a tracked element?
    /// Requires the name to be followed by space or tab — same discipline as
    /// the original OSM scanner: only attribute-bearing start tags qualify as
    /// top-level seek targets.
    #[inline]
    fn starts_element(&self, rest: &[u8]) -> bool {
        self.entries.iter().any(|e| {
            rest.len() > e.name.len()
                && rest.starts_with(&e.name)
                && matches!(rest[e.name.len()], b' ' | b'\t')
        })
    }
}

// ── ElemSpan: one indexed element ────────────────────────────────────────────

/// Byte span of one matched element. 24 bytes; carries everything a caller
/// needs to re-slice the element zero-copy:
///
/// ```text
///   <node id="1" lat="2.0">…</node>
///   ^offset                        offset+len^
///    ^── tag bytes: &buf[rel+1 .. rel+1+tag_len] ──^ (between '<' and '>')
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ElemSpan {
    /// Absolute byte offset of the element's opening `<` (slice offset + base).
    pub offset: u64,
    /// Total element bytes — opening `<` through final `>` of the closing tag
    /// (or of the `/>` for self-closing elements).
    pub len: u32,
    /// Raw start-tag bytes between `<` and `>`, *including* a trailing `/` for
    /// self-closing elements.
    pub tag_len: u32,
    /// True if the start tag ends in `/>`.
    pub self_closing: bool,
}

// ── SIMD forward scanner primitives ──────────────────────────────────────────

/// Scan `bytes` for the next `<` at or after `pos`.
/// Uses AVX2 via the memchr crate — ~32 bytes/cycle on hot paths.
#[inline]
pub(crate) fn next_open(bytes: &[u8], pos: usize) -> Option<usize> {
    memchr(b'<', &bytes[pos..]).map(|rel| pos + rel)
}

/// Scan `bytes` for the next `>` at or after `pos`. Sequential — tags are short.
#[inline]
pub(crate) fn next_close(bytes: &[u8], pos: usize) -> Option<usize> {
    memchr(b'>', &bytes[pos..]).map(|rel| pos + rel)
}

/// Read attribute value: find the next `"..."` pair starting at `pos`.
/// Returns `(value_slice, pos_after_closing_quote)`.
#[inline]
fn attr_value<'a>(bytes: &'a [u8], pos: usize) -> Option<(&'a [u8], usize)> {
    // skip to opening quote
    let open = memchr(b'"', &bytes[pos..])? + pos;
    let close = memchr(b'"', &bytes[open + 1..])? + open + 1;
    Some((&bytes[open + 1..close], close + 1))
}

/// Find the value of attribute `name` within a tag byte slice `tag` (the bytes
/// between `<` and `>`). Returns the raw (possibly escaped) value bytes.
pub fn find_attr<'a>(tag: &'a [u8], name: &[u8]) -> Option<&'a [u8]> {
    let mut pos = 0;
    while pos < tag.len() {
        // find next `=`
        let eq = memchr(b'=', &tag[pos..])? + pos;
        // the attribute name ends at the `=`; scan back past whitespace
        let name_end = eq;
        let mut name_start = name_end;
        while name_start > 0 && tag[name_start - 1] != b' ' && tag[name_start - 1] != b'\n' {
            name_start -= 1;
        }
        if &tag[name_start..name_end] == name {
            // found — read value
            let (val, _after) = attr_value(tag, eq + 1)?;
            return Some(val);
        }
        // skip past the `=` and its value
        if let Some((_, after)) = attr_value(tag, eq + 1) {
            pos = after;
        } else {
            break;
        }
    }
    None
}

/// Parse a decimal integer from ASCII bytes. No allocation, no UTF-8 decode.
pub fn parse_i64(bytes: &[u8]) -> i64 {
    let (neg, digits) = match bytes.first() {
        Some(&b'-') => (true, &bytes[1..]),
        _ => (false, bytes),
    };
    let mut v: i64 = 0;
    for &b in digits {
        if b.is_ascii_digit() {
            v = v.wrapping_mul(10).wrapping_add((b - b'0') as i64);
        }
    }
    if neg { -v } else { v }
}

// ── Safe split points ────────────────────────────────────────────────────────

/// Scan forward from `from` to the start of the next top-level element tracked
/// by `tags`. Returns the byte offset of the `<`, or `bytes.len()` if none.
///
/// This is the forward-seek half of the parallel split: a candidate offset
/// (e.g. `i * chunk_size`) is resolved to the nearest safe element boundary at
/// or after it, so no slice ever begins mid-element.
pub fn find_top_level_start(bytes: &[u8], from: usize, tags: &TagSet) -> usize {
    let mut pos = from;
    while pos < bytes.len() {
        let Some(rel) = memchr(b'<', &bytes[pos..]) else {
            break;
        };
        let lt = pos + rel;
        let rest = bytes.get(lt + 1..).unwrap_or_default();
        if tags.starts_element(rest) {
            return lt;
        }
        pos = lt + 1;
    }
    bytes.len()
}

/// Position just past the last complete top-level element in `bytes` — the
/// safe place to cut a streaming slot so no element is split across slots.
/// Searches only the last `max_elem_bytes` to bound work. Returns 0 if none.
///
/// Two boundary shapes are recognised:
///   - `paired`:       a full closing tag `</name>` of any tracked name
///   - `self_closing`: `<name … />` — found by rfind `"/>"` then verifying the
///     preceding `<name` (much faster than scanning every `>`; `/>` is rare)
///
/// The two sets are separate because formats may have names that only ever
/// appear in one shape (vtd passes a wider self-closing set, e.g. OSM
/// `<bound …/>`).
pub fn find_safe_slot_end(
    bytes: &[u8],
    max_elem_bytes: usize,
    paired: &TagSet,
    self_closing: &TagSet,
) -> usize {
    use memchr::{memmem, memrchr};
    let search_start = bytes.len().saturating_sub(max_elem_bytes);
    let tail = &bytes[search_start..];
    let offset = search_start;
    let mut best = 0usize;

    // Full closing tags.
    for entry in &paired.entries {
        if let Some(p) = memmem::rfind(tail, &entry.closing) {
            best = best.max(offset + p + entry.closing.len());
        }
    }

    // Self-closing top-level elements: memmem rfind for "/>" then verify name.
    let mut search_end = tail.len();
    loop {
        match memmem::rfind(&tail[..search_end], b"/>") {
            None => break,
            Some(p) => {
                if let Some(lt) = memrchr(b'<', &tail[..p]) {
                    let rest = &tail[lt + 1..];
                    if self_closing.starts_element(rest) {
                        best = best.max(offset + p + 2);
                        break;
                    }
                }
                if p == 0 {
                    break;
                }
                search_end = p;
            }
        }
    }

    best
}

/// Count tracked top-level elements in `slice` without full parsing.
/// Scans for `<name ` / `<name\t` — these byte sequences only appear as
/// element starts in valid XML (text containing `<` must be escaped as
/// `&lt;`). ~10× faster than a full parse.
pub fn count_elements(slice: &[u8], tags: &TagSet) -> usize {
    let mut count = 0usize;
    let mut pos = 0;
    while pos < slice.len() {
        let Some(rel) = memchr(b'<', &slice[pos..]) else {
            break;
        };
        let lt = pos + rel;
        let rest = slice.get(lt + 1..).unwrap_or_default();
        if tags.starts_element(rest) {
            count += 1;
        }
        pos = lt + 1;
    }
    count
}

// ── Core scanner ─────────────────────────────────────────────────────────────

/// Core scanner: emit one `(kind, ElemSpan)` per tracked top-level element in
/// `slice`. `base` is added to every `offset` so spans carry absolute
/// positions into the original buffer (not positions within the slice).
///
/// Skips closing tags and `<!…>` constructs (comments / CDATA / doctype) by
/// jumping to the next `>` — same single-`>` discipline as the original vtd
/// scanner: a comment containing a literal `>` terminates the skip early.
/// Untracked start tags are stepped over without element-end resolution.
///
/// For a tracked non-self-closing element, the element end is the *first*
/// occurrence of its own closing tag — nested same-name elements are not
/// balanced (OSM-grade XML has no such nesting; callers needing it must not).
pub fn scan_slice(
    slice: &[u8],
    base: usize,
    tags: &TagSet,
    on_elem: &mut impl FnMut(u8, ElemSpan),
) -> u64 {
    let mut pos = 0usize;
    let mut count = 0u64;

    while let Some(open_pos) = next_open(slice, pos) {
        let tag_start = open_pos + 1;

        // closing-tag or comment — skip
        if slice.get(tag_start) == Some(&b'/') || slice.get(tag_start) == Some(&b'!') {
            pos = match next_close(slice, tag_start) {
                Some(p) => p + 1,
                None => break,
            };
            continue;
        }

        let close_pos = match next_close(slice, tag_start) {
            Some(p) => p,
            None => break,
        };

        let raw_tag = &slice[tag_start..close_pos];
        let self_closing = raw_tag.last() == Some(&b'/');
        let tag = if self_closing {
            &raw_tag[..raw_tag.len() - 1]
        } else {
            raw_tag
        };

        let name_end = memchr(b' ', tag).unwrap_or(tag.len());
        let name = &tag[..name_end];

        let Some(entry) = tags.entry_for(name) else {
            pos = close_pos + 1;
            continue;
        };

        let elem_end = if self_closing {
            close_pos + 1
        } else {
            // First occurrence of this element's own closing tag.
            let closing = &*entry.closing;
            let mut search = close_pos + 1;
            loop {
                match next_open(slice, search) {
                    None => break slice.len(),
                    Some(p) => {
                        if slice[p..].starts_with(closing) {
                            break p + closing.len();
                        }
                        search = p + 1;
                    }
                }
            }
        };

        #[allow(
            clippy::cast_possible_truncation,
            reason = "element length fits u32 for any sane XML element"
        )]
        on_elem(
            entry.kind,
            ElemSpan {
                offset: (open_pos + base) as u64,
                len: (elem_end - open_pos) as u32,
                tag_len: raw_tag.len() as u32,
                self_closing,
            },
        );
        count += 1;
        pos = elem_end;
    }

    count
}

/// Single-threaded scan over a whole buffer. Kept for tests and small files.
pub fn scan<F>(bytes: &[u8], tags: &TagSet, mut on_elem: F) -> Result<u64>
where
    F: FnMut(u8, ElemSpan),
{
    Ok(scan_slice(bytes, 0, tags, &mut on_elem))
}

// ── Parallel scanner ─────────────────────────────────────────────────────────

/// Parallel scan: OVERSPLITS the buffer into many more top-level-aligned
/// sub-chunks than there are cores and lets the one gatling engine self-dispatch
/// them (workers = 0 ⇒ one per core, shared atomic cursor), so a denser region
/// no longer strands a single worker while the others sit idle.
///
/// Borders are computed independently — no adjacent-thread `AtomicU64`
/// rendezvous. For border `i`, `find_top_level_start(bytes, i * chunk)` seeks
/// forward from the nominal offset to the first tracked top-level element; the
/// same call at `i+1` is that sub-chunk's end, so every `[start, end)` slice is
/// clean (no element straddles a cut) and the units are fully independent. Each
/// unit maps its elements through `map` *on the worker*, so per-element decoding
/// runs in parallel, not serialised on the caller.
///
/// Per-unit results are merged in file order and fed to `on_item` on the calling
/// thread — output is deterministic and byte-identical to the serial scan for
/// any worker count (the finer partition only changes WHICH core parses each
/// element, never the element set or its order).
pub fn scan_parallel<T, M, F>(
    bytes: &[u8],
    n_workers: usize,
    tags: &TagSet,
    map: M,
    mut on_item: F,
) -> Result<u64>
where
    T: Send,
    M: Fn(u8, ElemSpan) -> T + Sync,
    F: FnMut(T),
{
    let n = n_workers.max(1);

    // Not worth the thread overhead for tiny files.
    if n == 1 || bytes.len() < 4 * 1024 * 1024 {
        return Ok(scan_slice(bytes, 0, tags, &mut |kind, span| {
            on_item(map(kind, span))
        }));
    }

    // OVERSPLIT: many more sub-chunks than cores so the engine's self-dispatch
    // can spread a dense region across all cores. `SPLIT` sub-chunks per worker
    // balances without over-fragmenting the boundary seeks.
    const SPLIT: usize = 8;
    let units = (n * SPLIT).min(bytes.len().max(1)).max(1);
    let chunk_size = (bytes.len() / units).max(1);

    // Top-level-aligned borders, computed independently (no rendezvous). border[i]
    // is this unit's start; border[i+1] is its end. `find_top_level_start` is
    // monotonic in the nominal offset, so borders are non-decreasing and the
    // slices never overlap; adjacent-equal borders just yield an empty unit.
    let mut borders = Vec::with_capacity(units + 1);
    for i in 0..units {
        borders.push(find_top_level_start(bytes, i * chunk_size, tags));
    }
    borders.push(bytes.len());

    let partials: Vec<Vec<T>> = crate::gatling_forkjoin::gatling_for_each(units, 0, |i| {
        let start = borders[i];
        let end = borders[i + 1];
        let mut local: Vec<T> = Vec::new();
        scan_slice(&bytes[start..end], start, tags, &mut |kind, span| {
            local.push(map(kind, span))
        });
        local
    });

    let mut total = 0u64;
    for partial in partials {
        total += partial.len() as u64;
        for item in partial {
            on_item(item);
        }
    }
    Ok(total)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn tags() -> TagSet {
        TagSet::new(&[(b"alpha".as_slice(), 0), (b"beta".as_slice(), 1)])
    }

    /// Collect (kind, span) pairs from a sequential scan.
    fn scan_all(bytes: &[u8], tags: &TagSet) -> Vec<(u8, ElemSpan)> {
        let mut out = Vec::new();
        scan(bytes, tags, |k, s| out.push((k, s))).unwrap();
        out
    }

    /// Deterministic synthetic corpus with both element shapes and untracked noise.
    fn synth(n: usize) -> Vec<u8> {
        use std::fmt::Write as _;
        let mut s = String::from("<?xml version=\"1.0\"?>\n<root>\n");
        for i in 0..n {
            match i % 4 {
                0 => {
                    let _ = writeln!(s, " <alpha id=\"{i}\" x=\"{}\"/>", i * 7);
                }
                1 => {
                    let _ = writeln!(s, " <alpha id=\"{i}\">");
                    let _ = writeln!(s, "  <tag k=\"key{}\" v=\"val\"/>", i % 9);
                    let _ = writeln!(s, " </alpha>");
                }
                2 => {
                    let _ = writeln!(s, " <beta id=\"{i}\" y=\"-{i}\"/>");
                }
                _ => {
                    let _ = writeln!(s, " <gamma id=\"{i}\"/>");
                } // untracked
            }
        }
        s.push_str("</root>\n");
        s.into_bytes()
    }

    #[test]
    fn empty_input() {
        let t = tags();
        assert_eq!(scan_all(b"", &t).len(), 0);
        assert_eq!(count_elements(b"", &t), 0);
        assert_eq!(find_top_level_start(b"", 0, &t), 0);
        assert_eq!(find_safe_slot_end(b"", 1024, &t, &t), 0);
    }

    #[test]
    fn kinds_and_spans() {
        let xml = b"<alpha id=\"1\"/>\n<beta id=\"2\">x</beta>\n";
        let t = tags();
        let elems = scan_all(xml, &t);
        assert_eq!(elems.len(), 2);

        let (k0, s0) = elems[0];
        assert_eq!(k0, 0);
        assert_eq!(s0.offset, 0);
        assert_eq!(&xml[..s0.len as usize], b"<alpha id=\"1\"/>");
        assert!(s0.self_closing);

        let (k1, s1) = elems[1];
        assert_eq!(k1, 1);
        let start = s1.offset as usize;
        assert_eq!(
            &xml[start..start + s1.len as usize],
            b"<beta id=\"2\">x</beta>"
        );
        assert!(!s1.self_closing);
    }

    #[test]
    fn attributes_via_generic_path() {
        let xml = b"<alpha id=\"-42\" name=\"hi\" count=\"7\"/>";
        let t = tags();
        let elems = scan_all(xml, &t);
        assert_eq!(elems.len(), 1);
        let (_, span) = elems[0];

        // Re-slice the start tag exactly the way downstream callers do.
        let rel = span.offset as usize;
        let raw = &xml[rel + 1..rel + 1 + span.tag_len as usize];
        let tag = if span.self_closing {
            &raw[..raw.len() - 1]
        } else {
            raw
        };
        assert_eq!(find_attr(tag, b"id").map(parse_i64), Some(-42));
        assert_eq!(find_attr(tag, b"name"), Some(b"hi".as_slice()));
        assert_eq!(find_attr(tag, b"count").map(parse_i64), Some(7));
        assert_eq!(find_attr(tag, b"missing"), None);
    }

    #[test]
    fn untracked_elements_skipped() {
        let xml = b"<gamma id=\"1\"/><alpha id=\"2\"/><delta id=\"3\">t</delta><beta id=\"4\"/>";
        let elems = scan_all(xml, &tags());
        assert_eq!(
            elems.iter().map(|(k, _)| *k).collect::<Vec<_>>(),
            vec![0, 1]
        );
    }

    #[test]
    fn nested_same_name_ends_at_first_closing_tag() {
        // The scanner does NOT balance nested same-name elements — the span ends
        // at the first closing tag. This matches the original vtd behavior
        // (OSM-grade XML never nests node/way/relation).
        let xml = b"<alpha id=\"1\"><alpha id=\"9\"/></alpha><beta id=\"2\"/>";
        let elems = scan_all(xml, &tags());
        // outer alpha swallows the self-closing inner one (span ends at </alpha>),
        // then scanning resumes after it.
        assert_eq!(elems.len(), 2);
        let (_, s0) = elems[0];
        assert_eq!(
            &xml[..s0.len as usize],
            b"<alpha id=\"1\"><alpha id=\"9\"/></alpha>"
        );
        assert_eq!(elems[1].0, 1);
    }

    #[test]
    fn comments_and_cdata_skipped() {
        // `<!…>` constructs are skipped to the next `>` — same single-`>`
        // discipline as the original vtd scanner (a literal `>` inside a
        // comment terminates the skip early; OSM escapes those as &gt;).
        let xml =
            b"<!-- a comment --><alpha id=\"1\"/><![CDATA[ no angle stuff ]]><beta id=\"2\"/>";
        let elems = scan_all(xml, &tags());
        assert_eq!(elems.len(), 2);
        assert_eq!(elems[0].0, 0);
        assert_eq!(elems[1].0, 1);

        // A commented-out element whose `/>` supplies the first `>` is not indexed.
        let xml2 = b"<!-- <alpha id=\"9\"/> --><beta id=\"2\"/>";
        let elems2 = scan_all(xml2, &tags());
        assert_eq!(elems2.len(), 1);
        assert_eq!(elems2[0].0, 1);
    }

    #[test]
    fn find_top_level_start_seeks_forward() {
        let xml = b"junk text <gamma x=\"1\"/> more <alpha id=\"5\"/> tail";
        let t = tags();
        let pos = find_top_level_start(xml, 0, &t);
        assert!(xml[pos..].starts_with(b"<alpha "));
        // from past the only element → end of buffer
        assert_eq!(find_top_level_start(xml, pos + 1, &t), xml.len());
    }

    #[test]
    fn safe_slot_end_never_splits_elements() {
        let xml = synth(500);
        let t = tags();

        let full = scan_all(&xml, &t);
        assert!(full.len() > 100);

        // Cut at every 1000-byte candidate: find_safe_slot_end on the head must
        // land just past a complete element, and head+tail rescans must
        // reproduce the full scan exactly.
        for candidate in (1000..xml.len()).step_by(1000) {
            let head = &xml[..candidate];
            let safe = find_safe_slot_end(head, 64 * 1024, &t, &t);
            assert!(safe <= candidate);
            assert_eq!(
                head[..safe].last(),
                Some(&b'>'),
                "cut at {candidate} not after a '>'"
            );

            let mut joined = scan_all(&xml[..safe], &t);
            let tail_start = find_top_level_start(&xml, safe, &t);
            let mut tail = Vec::new();
            scan_slice(&xml[tail_start..], tail_start, &t, &mut |k, s| {
                tail.push((k, s))
            });
            joined.extend(tail);
            assert_eq!(
                joined, full,
                "split at safe={safe} (candidate {candidate}) diverged"
            );
        }
    }

    #[test]
    fn safe_slot_end_respects_separate_shape_sets() {
        // `omega` only counts as a boundary via the self-closing set.
        let paired = TagSet::new(&[(b"alpha".as_slice(), 0)]);
        let selfc = TagSet::new(&[(b"alpha".as_slice(), 0), (b"omega".as_slice(), 0)]);
        let xml = b"<alpha id=\"1\">x</alpha>\n<omega id=\"2\"/>\n<alpha id=\"3\">unterminated";
        let safe = find_safe_slot_end(xml, 4096, &paired, &selfc);
        assert_eq!(
            &xml[..safe],
            b"<alpha id=\"1\">x</alpha>\n<omega id=\"2\"/>".as_slice()
        );
        // Without omega in the self-closing set, the boundary falls back to </alpha>.
        let safe2 = find_safe_slot_end(xml, 4096, &paired, &paired);
        assert_eq!(&xml[..safe2], b"<alpha id=\"1\">x</alpha>".as_slice());
    }

    #[test]
    fn count_matches_scan() {
        let xml = synth(2000);
        let t = tags();
        assert_eq!(
            count_elements(&xml, &t) as u64,
            scan(&xml, &t, |_, _| {}).unwrap()
        );
    }

    #[test]
    fn parallel_matches_sequential() {
        // > 4 MiB so the parallel path actually splits; elements deliberately
        // straddle every candidate boundary chunk_size, 2*chunk_size, …
        let mut xml = synth(50_000);
        while xml.len() < 5 * 1024 * 1024 {
            let more = synth(50_000);
            xml.extend_from_slice(&more);
        }
        let t = tags();

        let seq = scan_all(&xml, &t);
        for n in [2, 3, 4, 8] {
            let mut par = Vec::new();
            let total = scan_parallel(&xml, n, &t, |k, s| (k, s), |e| par.push(e)).unwrap();
            assert_eq!(total as usize, seq.len(), "n={n}: count mismatch");
            assert_eq!(par, seq, "n={n}: element stream diverged");
        }
    }

    #[test]
    fn parallel_small_input_uses_sequential_path() {
        let xml = synth(50); // far below the 4 MiB threshold
        let t = tags();
        let seq = scan_all(&xml, &t);
        let mut par = Vec::new();
        scan_parallel(&xml, 8, &t, |k, s| (k, s), |e| par.push(e)).unwrap();
        assert_eq!(par, seq);
    }

    #[test]
    fn parallel_map_runs_per_element() {
        // The map closure decodes attributes on worker threads — verify the
        // decoded values survive the in-order merge.
        let xml = b"<alpha id=\"10\"/><beta id=\"20\"/><alpha id=\"30\"/>";
        let t = tags();
        let mut ids = Vec::new();
        scan_parallel(
            xml,
            4,
            &t,
            |_, span| {
                let rel = span.offset as usize;
                let raw = &xml[rel + 1..rel + 1 + span.tag_len as usize];
                let tag = if span.self_closing {
                    &raw[..raw.len() - 1]
                } else {
                    raw
                };
                find_attr(tag, b"id").map(parse_i64).unwrap_or(0)
            },
            |id| ids.push(id),
        )
        .unwrap();
        assert_eq!(ids, vec![10, 20, 30]);
    }

    /// Oversplit correctness under SKEW: a corpus with alternating dense
    /// (tracked-element-heavy) and sparse (untracked-noise-heavy) regions is
    /// exactly the shape that tail-chokes a one-slice-per-worker split. The
    /// oversplit + self-dispatch path must still reproduce the sequential scan
    /// byte-for-byte, in order, for high worker counts (which fan out into many
    /// more sub-chunks than cores). The finer partition only changes WHICH core
    /// parses each element — never the element set or order.
    #[test]
    fn parallel_oversplit_matches_sequential_skewed() {
        use std::fmt::Write as _;
        // Build > 4 MiB of alternating dense/sparse bands so element density is
        // wildly uneven across byte offsets.
        let mut s = String::from("<?xml version=\"1.0\"?>\n<root>\n");
        let mut band = 0usize;
        while s.len() < 6 * 1024 * 1024 {
            if band % 2 == 0 {
                // Dense band: many tiny tracked elements.
                for i in 0..2000 {
                    let _ = writeln!(s, " <alpha id=\"{i}\" x=\"{}\"/>", i * 3);
                    let _ = writeln!(s, " <beta id=\"{i}\" y=\"-{i}\"/>");
                }
            } else {
                // Sparse band: long untracked noise, few tracked elements.
                for i in 0..300 {
                    let _ = writeln!(s, " <gamma id=\"{i}\" note=\"{}\"/>", "x".repeat(200));
                }
                let _ = writeln!(s, " <alpha id=\"{band}\"/>");
            }
            band += 1;
        }
        s.push_str("</root>\n");
        let xml = s.into_bytes();
        let t = tags();

        let seq = scan_all(&xml, &t);
        assert!(seq.len() > 1000, "sanity: {} tracked elements", seq.len());
        // High worker counts → units = n * SPLIT sub-chunks, many more than cores.
        for n in [2usize, 4, 8, 16, 32, 64] {
            let mut par = Vec::new();
            let total = scan_parallel(&xml, n, &t, |k, s| (k, s), |e| par.push(e)).unwrap();
            assert_eq!(total as usize, seq.len(), "n={n}: count mismatch");
            assert_eq!(par, seq, "n={n}: skewed oversplit element stream diverged");
        }
    }
}
