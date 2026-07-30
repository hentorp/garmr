//! DEFLATE full-flush boundary scanner — shared parallel split (ljar + lzip).
//!
//! The SIMD scanner itself lives in the shared `linflate` crate
//! (`linflate::deflate_scan`); this module keeps only the crate-local parallel
//! split-point search, which fans out through the shared gatling fork-join
//! engine.  It is identical for JAR and ZIP, so it lives here once.

use linflate::deflate_scan::find_next_flush;

pub use linflate::deflate_scan::{FlushBoundary, find_all_flushes};

/// Parallel split-point search: N−1 gatling workers each find the nearest flush
/// boundary at or after their nominal byte offset.
///
/// `n_splits` is typically the number of physical cores.
/// Returns up to `n_splits − 1` boundaries, sorted and deduplicated.
pub fn split_boundaries_parallel(buf: &[u8], n_splits: usize) -> Vec<FlushBoundary> {
    if n_splits <= 1 || buf.len() < 8 {
        return Vec::new();
    }

    // Indices 1..n_splits ⇒ gatling units 0..n_splits-1 (unit k ⇒ split i=k+1).
    let mut found: Vec<Option<FlushBoundary>> =
        gatling::gatling_forkjoin::gatling_for_each(n_splits - 1, 0, |k| {
            let i = k + 1;
            let nominal = buf.len() * i / n_splits;
            find_next_flush(buf, nominal)
        });

    let mut result: Vec<FlushBoundary> = found.drain(..).flatten().collect();
    result.sort_by_key(|b| b.start);
    result.dedup_by_key(|b| b.start);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_flush_marker() -> Vec<u8> {
        vec![0x00, 0x00, 0x00, 0xFF, 0xFF]
    }

    #[test]
    fn split_finds_markers() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&[0xAA; 32]);
        buf.extend_from_slice(&make_flush_marker());
        buf.extend_from_slice(&[0xBB; 32]);
        // Raw pattern scan must locate the synthetic boundary.
        let all = find_all_flushes(&buf);
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].start, 37);
    }
}
