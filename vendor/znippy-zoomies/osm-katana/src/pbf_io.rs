/// Position of one OSMData blob inside a mmap'd PBF file.
pub struct BlobPos {
    pub offset: usize,
    pub length: usize,
}

/// Parallel version of `scan_blob_positions`.
///
/// Splits the file into one slice per core (scoped-thread worker pool, no
/// rayon). Thread 0 starts at offset 0 (known valid frame boundary). Each other
/// thread self-aligns by scanning forward from its nominal slice start until it
/// finds a valid 4-byte BlobHeader length followed by a parseable BlobHeader
/// protobuf and a plausible next-frame header. This disambiguates any false
/// positives and is fast in practice (OSM blob headers are 13-18 bytes;
/// compressed blob payloads rarely contain the byte pattern
/// `\x00\x00\x00\x{0d..12}` that would fool the heuristic).
///
/// Results are returned in file order.
pub fn scan_blob_positions_par(data: &[u8]) -> Vec<BlobPos> {
    let n = std::thread::available_parallelism()
        .map(|x| x.get())
        .unwrap_or(1)
        .max(1);
    let chunk = (data.len() / n).max(1);

    let parts: Vec<Vec<BlobPos>> = crate::par::par_map(n, |i| {
        let slice_start = i * chunk;
        if slice_start >= data.len() {
            return Vec::new();
        }
        let slice_end = if i + 1 == n {
            data.len()
        } else {
            ((i + 1) * chunk).min(data.len())
        };
        let blob_start = if i == 0 {
            0
        } else {
            match find_blob_boundary(data, slice_start) {
                Some(p) => p,
                None => return Vec::new(),
            }
        };
        collect_blobs_in_slice(data, blob_start, slice_end)
    });

    parts.into_iter().flatten().collect()
}

/// Largest OSMData blob payload + header the spec permits (32 MB payload, plus
/// generous header room). Used to bound the cheap TAIL scan that computes
/// `consumed` without walking every blob in the slot.
const MAX_BLOB_WINDOW: usize = 64 * 1024 * 1024;

/// Coarse Gatling split for a PBF slot — the cure for the per-blob ceiling.
///
/// Instead of the old serial main-thread walk that emitted one `(offset, length)`
/// segment per OSMData blob (~1000 tiny segments / 64 MB slot → channel-lock
/// contention + ~1000 sink stub-stitches), this divides the slot into roughly
/// `n_segments` (≈ `2 * n_workers`) **coarse candidate byte ranges** by cheap
/// O(n_workers) arithmetic — NO blob walk on the main thread.
///
/// Each segment is a candidate range `(cand_start, cand_end)`. The worker's
/// `transform` calls [`align_and_collect`] to (a) seek its own first blob
/// boundary at/after `cand_start` via [`find_blob_boundary`] and (b) decode every
/// OSMData blob whose frame START lies in `[boundary(cand_start), boundary(cand_end))`.
/// Because adjacent segments share an endpoint (`cand_end_i == cand_start_{i+1}`)
/// and `find_blob_boundary` is deterministic, the ranges tile the slot exactly:
/// every blob is owned by exactly one worker — no duplicates, no skips.
///
/// `consumed` is the end offset of the last *complete* blob in the slot,
/// computed by a bounded TAIL scan only (last `MAX_BLOB_WINDOW` bytes) so the
/// main thread does ~O(1) work regardless of slot size. Everything from
/// `consumed` on becomes Gatling carry for the next slot.
///
/// `n_segments` is clamped to ≥1 and to ≤ the number of bytes in the slot's
/// complete-blob span (so a tiny slot never produces sub-blob fragments).
pub fn coarse_split_slot(data: &[u8], n_segments: usize) -> (Vec<(usize, usize)>, usize) {
    // `consumed`: cheap bounded TAIL scan — find the last COMPLETE blob's end.
    let consumed = tail_consumed(data);
    if consumed == 0 {
        // No complete blob yet (slot smaller than one frame): emit nothing so the
        // engine carries the whole slot, grown, into the next read.
        return (Vec::new(), 0);
    }

    // Coarse candidate ranges over [0, consumed) by cheap division. The worker
    // aligns each cand_start to a real blob boundary itself.
    let span = consumed;
    let n = n_segments.max(1).min(span.max(1)); // never more segments than bytes
    let step = (span / n).max(1);

    let mut segments: Vec<(usize, usize)> = Vec::with_capacity(n);
    let mut cand = 0usize;
    while cand < span {
        let next = if segments.len() + 1 == n {
            span
        } else {
            (cand + step).min(span)
        };
        segments.push((cand, next));
        if next >= span {
            break;
        }
        cand = next;
    }
    (segments, consumed)
}

/// End offset of the last COMPLETE blob in `data`, via a bounded tail scan.
///
/// OSM blobs are spec-capped at 32 MB; we seek a frame boundary no further back
/// than `MAX_BLOB_WINDOW` from the end, then walk the (few) blobs in that window
/// to the last whose frame fully fits in `data`. This avoids walking all ~1000
/// blobs in the slot. Falls back to a single-pass walk only for slots smaller
/// than the window (where the walk is itself cheap).
fn tail_consumed(data: &[u8]) -> usize {
    if data.len() < 8 {
        return 0;
    }
    if data.len() <= MAX_BLOB_WINDOW {
        // Small slot: a full walk from 0 is already cheap and is exact.
        return walk_last_complete_end(data, 0);
    }
    let window_start = data.len() - MAX_BLOB_WINDOW;
    match find_blob_boundary(data, window_start) {
        Some(b) => walk_last_complete_end(data, b),
        // No boundary found in the tail window (pathological / huge blob):
        // fall back to the full walk for correctness.
        None => walk_last_complete_end(data, 0),
    }
}

/// Walk frames from `start` (a valid boundary), returning the end offset of the
/// last frame that fits entirely within `data`.
fn walk_last_complete_end(data: &[u8], start: usize) -> usize {
    let mut pos = start;
    let mut last_end = start;
    while pos + 4 <= data.len() {
        let hlen =
            u32::from_be_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]) as usize;
        let hdr_start = pos + 4;
        let hdr_end = hdr_start.saturating_add(hlen);
        if hdr_end > data.len() {
            break;
        }
        let Some((_btype, dsize)) = try_parse_blob_header(&data[hdr_start..hdr_end]) else {
            break;
        };
        let blob_end = hdr_end.saturating_add(dsize);
        if blob_end > data.len() {
            break;
        }
        last_end = blob_end;
        pos = blob_end;
    }
    last_end
}

/// Worker-side: align `cand_start` to a real blob boundary, then collect every
/// OSMData blob whose frame START is in `[start, end_limit)`, where `end_limit`
/// is the boundary aligned from `cand_end`. Returns `(offset, length)` pairs.
///
/// This is the per-segment work that used to happen serially on main: now it is
/// DISTRIBUTED across all workers and each worker locks the work channel once per
/// slot for its whole range. Zero-copy: returns offsets into the borrowed slot.
pub fn align_and_collect(data: &[u8], cand_start: usize, cand_end: usize) -> Vec<(usize, usize)> {
    let start = if cand_start == 0 {
        0
    } else {
        match find_blob_boundary(data, cand_start) {
            Some(p) => p,
            None => return Vec::new(),
        }
    };
    // Half-open end: the next worker's aligned start. find_blob_boundary is
    // deterministic so this equals worker(i+1)'s `start` exactly → no dup/skip.
    // For the last segment (cand_end at/after the data tail) there is no further
    // boundary; collect_blobs_in_slice naturally stops at the last complete blob.
    let end_limit = if cand_end >= data.len() {
        data.len()
    } else {
        find_blob_boundary(data, cand_end).unwrap_or(data.len())
    };
    if start >= end_limit {
        return Vec::new();
    }
    collect_blobs_in_slice(data, start, end_limit)
        .into_iter()
        .map(|p| (p.offset, p.length))
        .collect()
}

/// Scan forward from `hint` for the first valid PBF blob frame boundary.
/// Returns the offset of the 4-byte header-length field, or None if not found.
fn find_blob_boundary(data: &[u8], hint: usize) -> Option<usize> {
    let mut p = hint;
    while p + 4 <= data.len() {
        // Fast pre-filter: hlen ∈ [1, 65535] requires the first two bytes to be 0.
        if data[p] != 0 {
            p += 1;
            continue;
        }
        if data[p + 1] != 0 {
            p += 2;
            continue;
        }

        let hlen = u16::from_be_bytes([data[p + 2], data[p + 3]]) as usize;
        if hlen == 0 {
            p += 1;
            continue;
        }

        let hdr_start = p + 4;
        let hdr_end = hdr_start + hlen;
        if hdr_end > data.len() {
            p += 1;
            continue;
        }

        if let Some((btype, dsize)) = try_parse_blob_header(&data[hdr_start..hdr_end]) {
            if dsize > 0 && (btype == b"OSMData" || btype == b"OSMHeader") {
                // Confirm the next frame also looks valid to rule out false positives.
                let next = hdr_end + dsize;
                let last_blob_ok = next <= data.len()
                    && (next + 4 > data.len() || {
                        let nh = u32::from_be_bytes([
                            data[next],
                            data[next + 1],
                            data[next + 2],
                            data[next + 3],
                        ]) as usize;
                        nh >= 1 && nh <= 65_535
                    });
                if last_blob_ok {
                    return Some(p);
                }
            }
        }
        p += 1;
    }
    None
}

/// Walk forward from `start` (a valid blob frame boundary), collecting
/// OSMData blobs whose frame position is < `end`.
fn collect_blobs_in_slice(data: &[u8], start: usize, end: usize) -> Vec<BlobPos> {
    let mut pos = start;
    let mut out = Vec::new();
    while pos < end && pos + 4 <= data.len() {
        let hlen =
            u32::from_be_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]) as usize;
        let hdr_start = pos + 4;
        let hdr_end = hdr_start.saturating_add(hlen);
        if hdr_end > data.len() {
            break;
        }

        let Some((btype, dsize)) = try_parse_blob_header(&data[hdr_start..hdr_end]) else {
            break;
        };
        let blob_start = hdr_end;
        let blob_end = blob_start.saturating_add(dsize);
        if blob_end > data.len() {
            break;
        }

        if btype == b"OSMData" {
            out.push(BlobPos {
                offset: blob_start,
                length: dsize,
            });
        }
        pos = blob_end;
    }
    out
}

/// Non-allocating BlobHeader parser — returns `None` on any malformed input.
fn try_parse_blob_header(bytes: &[u8]) -> Option<(&[u8], usize)> {
    let mut pos = 0usize;
    let mut btype = &bytes[0..0];
    let mut dsize = 0usize;
    while pos < bytes.len() {
        let (tag, n) = try_read_varint(bytes, pos)?;
        pos += n;
        let field = (tag >> 3) as u32;
        let wire_type = (tag & 7) as u32;
        match (field, wire_type) {
            (1, 2) | (2, 2) => {
                let (len, n2) = try_read_varint(bytes, pos)?;
                pos += n2;
                let end = pos.saturating_add(len as usize);
                if end > bytes.len() {
                    return None;
                }
                if field == 1 {
                    btype = &bytes[pos..end];
                }
                pos = end;
            }
            (3, 0) => {
                let (v, n2) = try_read_varint(bytes, pos)?;
                pos += n2;
                dsize = v as usize;
            }
            (_, 0) => {
                let (_, n2) = try_read_varint(bytes, pos)?;
                pos += n2;
            }
            (_, 2) => {
                let (len, n2) = try_read_varint(bytes, pos)?;
                pos = pos.saturating_add(n2).saturating_add(len as usize);
            }
            _ => break,
        }
    }
    Some((btype, dsize))
}

/// Non-allocating varint decoder.  Returns `(value, bytes_consumed)` or `None`.
fn try_read_varint(bytes: &[u8], start: usize) -> Option<(u64, usize)> {
    let mut value = 0u64;
    let mut shift = 0u32;
    let mut pos = start;
    loop {
        let b = *bytes.get(pos)?;
        pos += 1;
        value |= u64::from(b & 0x7f) << shift;
        shift = shift.saturating_add(7);
        if b & 0x80 == 0 {
            break;
        }
        if shift >= 64 {
            return None;
        }
    }
    Some((value, pos - start))
}

/// Returns (value, bytes_consumed).
pub fn read_varint(bytes: &[u8], start: usize) -> anyhow::Result<(u64, usize)> {
    let mut value = 0u64;
    let mut shift = 0u32;
    let mut pos = start;

    loop {
        let b = bytes
            .get(pos)
            .copied()
            .ok_or_else(|| anyhow::anyhow!("varint truncated at byte {pos}"))?;
        pos = pos.saturating_add(1);
        value |= ((b & 0x7f) as u64) << shift;
        shift = shift.saturating_add(7);
        if b & 0x80 == 0 {
            break;
        }
        if shift >= 64 {
            anyhow::bail!("varint too long");
        }
    }

    Ok((value, pos.saturating_sub(start)))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Encode a varint.
    fn varint(mut v: u64, out: &mut Vec<u8>) {
        loop {
            let mut b = (v & 0x7f) as u8;
            v >>= 7;
            if v != 0 {
                b |= 0x80;
            }
            out.push(b);
            if v == 0 {
                break;
            }
        }
    }

    /// Build one valid PBF frame: 4-byte BE header len, BlobHeader protobuf
    /// (field1=type string, field3=datasize varint), then `dsize` payload bytes.
    /// Payload is filler `0xAB` (the split path never decompresses; it only walks
    /// frame boundaries). Returns the encoded frame.
    fn frame(btype: &str, dsize: usize) -> Vec<u8> {
        let mut hdr = Vec::new();
        // field 1, wire 2 (type)
        hdr.push((1 << 3) | 2);
        varint(btype.len() as u64, &mut hdr);
        hdr.extend_from_slice(btype.as_bytes());
        // field 3, wire 0 (datasize)
        hdr.push((3 << 3) | 0);
        varint(dsize as u64, &mut hdr);

        let mut out = Vec::new();
        out.extend_from_slice(&(hdr.len() as u32).to_be_bytes());
        out.extend_from_slice(&hdr);
        out.extend(std::iter::repeat(0xABu8).take(dsize));
        out
    }

    /// Walk every OSMData blob in `data` (ground truth, serial) → frame START
    /// offsets and the consumed end. Mirrors the OLD per-blob walk for comparison.
    fn ground_truth(data: &[u8]) -> (Vec<usize>, usize) {
        let mut pos = 0usize;
        let mut starts = Vec::new();
        while pos + 4 <= data.len() {
            let hlen = u32::from_be_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]])
                as usize;
            let hs = pos + 4;
            let he = hs + hlen;
            if he > data.len() {
                break;
            }
            let Some((bt, ds)) = try_parse_blob_header(&data[hs..he]) else {
                break;
            };
            let bstart = he;
            let bend = bstart + ds;
            if bend > data.len() {
                break;
            }
            if bt == b"OSMData" {
                starts.push(bstart);
            }
            pos = bend;
        }
        (starts, pos)
    }

    /// INJECT-ASSERT: feed a synthetic multi-blob PBF buffer through the coarse
    /// split + per-worker align_and_collect; assert the UNION of all workers'
    /// decoded blob starts == every OSMData blob exactly once (no dup, no skip)
    /// and `consumed` is the last complete blob end.
    #[test]
    fn coarse_split_covers_every_blob_once() {
        // A header blob then a run of data blobs of varied size, ending with an
        // INCOMPLETE trailing frame (truncated payload) that must NOT be consumed.
        let mut buf = Vec::new();
        buf.extend(frame("OSMHeader", 50));
        let sizes = [
            120usize, 4096, 777, 9001, 33, 65000, 1234, 2048, 888, 4095, 17, 6000,
        ];
        for &s in &sizes {
            buf.extend(frame("OSMData", s));
        }
        let complete_len = buf.len();
        // Truncated trailing data frame (header says 9999 but we cut the payload).
        let mut tail = frame("OSMData", 9999);
        tail.truncate(tail.len() - 5000);
        buf.extend(tail);

        let (gt_starts, gt_consumed) = ground_truth(&buf[..complete_len]);
        assert_eq!(gt_starts.len(), sizes.len(), "ground truth blob count");

        // Try several worker counts incl. degenerate ones.
        for n in [1usize, 2, 3, 4, 8, 32] {
            let (segs, consumed) = coarse_split_slot(&buf, n);
            assert_eq!(
                consumed, gt_consumed,
                "consumed must be last COMPLETE blob end (n={n}); truncated tail excluded"
            );
            assert!(consumed < buf.len(), "truncated tail not consumed (n={n})");

            // Collect every worker's owned blob starts.
            let mut got: Vec<usize> = Vec::new();
            for (cs, ce) in &segs {
                for (off, _len) in align_and_collect(&buf, *cs, *ce) {
                    got.push(off);
                }
            }
            got.sort_unstable();

            // No dup.
            let mut dedup = got.clone();
            dedup.dedup();
            assert_eq!(dedup.len(), got.len(), "a blob was decoded twice (n={n})");
            // Exactly the ground-truth set, no skip.
            assert_eq!(
                got, gt_starts,
                "union != every OSMData blob exactly once (n={n})"
            );
        }
    }

    /// A slot whose first frame is incomplete (no complete blob) must consume 0.
    #[test]
    fn coarse_split_incomplete_first_frame() {
        let mut buf = frame("OSMData", 50000);
        buf.truncate(20); // cut mid-payload
        let (segs, consumed) = coarse_split_slot(&buf, 8);
        assert_eq!(consumed, 0, "no complete blob → consume nothing");
        assert!(segs.is_empty());
    }
}
