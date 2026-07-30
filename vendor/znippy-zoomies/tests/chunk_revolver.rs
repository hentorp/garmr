//! Integration tests for the `chunk_revolver` zero-allocation slot pool.
//!
//! The revolver hands out fixed-size slots to a single reader (`try_get_chunk`)
//! and recycles them on `return_chunk`. The two correctness properties that
//! matter are:
//!   1. **No aliasing** — every slot that is simultaneously leased points at a
//!      distinct, non-overlapping region of backing memory.
//!   2. **Lifecycle** — the pool exposes exactly its capacity, blocks (returns
//!      `None`) when exhausted, and makes the same capacity available again once
//!      slots are returned. Writes through a leased slot persist and are readable
//!      via the zero-copy `get_chunk_slice` view.

use znippy_zoomies::chunk_revolver::{ChunkRevolver, get_chunk_slice};

/// Drain every available slot, recording each lease's identity and the raw
/// (pointer, len) of its data region. The `Chunk`'s `&mut` borrow is released
/// immediately (we only keep the captured identity), which lets us pop the next
/// slot — dropping a `Chunk` does NOT return it to the ring, so the pool drains.
fn drain_all(rev: &mut ChunkRevolver) -> Vec<(u8, u64, usize, usize)> {
    let mut leases = Vec::new();
    while let Some(chunk) = rev.try_get_chunk() {
        let ring_nr = chunk.ring_nr;
        let index = chunk.index;
        let ptr = chunk.data.as_ptr() as usize;
        let len = chunk.data.len();
        leases.push((ring_nr, index, ptr, len));
    }
    leases
}

#[test]
fn drains_full_capacity_then_recycles() {
    // 2 rings × 4 slots each = 8 leasable slots.
    let chunk_size = 64;
    let mut rev = ChunkRevolver::new(chunk_size, 8, 2);
    assert_eq!(rev.num_rings(), 2);
    assert_eq!(rev.chunk_size(), chunk_size);

    let leases = drain_all(&mut rev);
    assert_eq!(leases.len(), 8, "pool did not expose its full capacity");
    // Exhausted: no more slots until something is returned.
    assert!(
        rev.try_get_chunk().is_none(),
        "drained pool still handed out a slot"
    );

    // Return everything, then the same capacity must be leasable again.
    for &(ring_nr, index, _, _) in &leases {
        rev.return_chunk(ring_nr, index);
    }
    let again = drain_all(&mut rev);
    assert_eq!(again.len(), 8, "returned slots were not recycled");
}

#[test]
fn leases_do_not_alias() {
    let chunk_size = 128;
    let mut rev = ChunkRevolver::new(chunk_size, 8, 4);
    let leases = drain_all(&mut rev);
    assert_eq!(leases.len(), 8);

    // Every leased slot must report the configured size.
    for &(_, _, _, len) in &leases {
        assert_eq!(len, chunk_size, "slot length != chunk_size");
    }

    // (ring_nr, index) pairs must be unique — no slot leased twice.
    let mut ids: Vec<(u8, u64)> = leases.iter().map(|&(r, i, _, _)| (r, i)).collect();
    ids.sort_unstable();
    let unique = ids.len();
    ids.dedup();
    assert_eq!(ids.len(), unique, "a slot was leased more than once");

    // Memory ranges [ptr, ptr+len) must be pairwise disjoint (no aliasing).
    let mut ranges: Vec<(usize, usize)> = leases.iter().map(|&(_, _, p, l)| (p, p + l)).collect();
    ranges.sort_unstable();
    for w in ranges.windows(2) {
        assert!(
            w[0].1 <= w[1].0,
            "leased slots alias: [{:#x},{:#x}) overlaps [{:#x},{:#x})",
            w[0].0,
            w[0].1,
            w[1].0,
            w[1].1
        );
    }
}

#[test]
fn round_robin_rotation_across_rings() {
    // With 4 rings each holding ≥1 slot, the first four leases must visit each
    // ring once in rotation (0,1,2,3), per the round-robin `next_ring` cursor.
    let mut rev = ChunkRevolver::new(32, 8, 4);
    let mut seen = Vec::new();
    for _ in 0..4 {
        let c = rev.try_get_chunk().expect("slot available");
        seen.push(c.ring_nr);
    }
    assert_eq!(seen, vec![0, 1, 2, 3], "leases did not rotate round-robin");
}

#[test]
fn writes_persist_and_are_readable_via_zero_copy_view() {
    // Write a distinct per-slot pattern through each lease, then read it back
    // through the unsafe zero-copy `get_chunk_slice` view using the ring's base
    // pointer + slot index. Values must survive (real I/O through the pool).
    let chunk_size = 16;
    let mut rev = ChunkRevolver::new(chunk_size, 8, 2);
    let bases = rev.base_ptrs();

    // (ring_nr, index, tag) of everything we wrote.
    let mut written = Vec::new();
    let mut tag: u8 = 1;
    while let Some(chunk) = rev.try_get_chunk() {
        let ring_nr = chunk.ring_nr;
        let index = chunk.index;
        for b in chunk.data.iter_mut() {
            *b = tag;
        }
        written.push((ring_nr, index, tag));
        tag = tag.wrapping_add(1);
    }
    assert_eq!(written.len(), 8);

    for &(ring_nr, index, tag) in &written {
        let base = bases[ring_nr as usize].as_ptr();
        // SAFETY: `base` is the pointer for `ring_nr` from `base_ptrs()`, the slot
        // at `index` is still in-flight (we never called return_chunk), and we
        // read exactly `chunk_size` bytes that we just wrote.
        let view = unsafe { get_chunk_slice(base, chunk_size, index as u32, chunk_size) };
        assert!(
            view.iter().all(|&b| b == tag),
            "slot (ring {ring_nr}, idx {index}) did not retain its written pattern"
        );
    }
}

#[test]
#[should_panic(expected = "ring overflow on return")]
fn double_return_panics() {
    // Returning a slot that is already in the free list overflows its ring; the
    // pool's safety guard must catch this rather than silently corrupt state.
    let mut rev = ChunkRevolver::new(64, 8, 2);
    // Drain ring 0 fully so we know its valid indices, then over-return.
    let mut ring0_indices = Vec::new();
    let leases = drain_all(&mut rev);
    for (r, i, _, _) in leases {
        if r == 0 {
            ring0_indices.push(i);
        }
    }
    // Return all of ring 0's slots (fills the ring to capacity)...
    for &i in &ring0_indices {
        rev.return_chunk(0, i);
    }
    // ...then one extra return overflows it.
    rev.return_chunk(0, ring0_indices[0]);
}
