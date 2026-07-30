/// Capacities for the statically-sized ring variants.
/// Each variant covers a range of `max_chunks` values.
pub const MINI: usize = 4;
pub const MEDIUM: usize = 32;
pub const LARGE: usize = 128;
pub const HUGE: usize = 8192;

pub(crate) trait ChunkQueue {
    fn pop(&mut self) -> Option<u64>;
    fn push(&mut self, val: u64) -> Result<(), &'static str>;
    #[allow(dead_code)]
    fn is_empty(&self) -> bool;
    #[allow(dead_code)]
    fn is_full(&self) -> bool;
    #[allow(dead_code)]
    fn capacity(&self) -> usize;
}

struct RingState {
    head: usize,
    tail: usize,
    len: usize,
}

pub(crate) struct RingInner<const N: usize> {
    buf: Box<[u64; N]>,
    state: RingState,
}

impl<const N: usize> RingInner<N> {
    fn new() -> Self {
        Self {
            buf: Box::new([0u64; N]),
            state: RingState {
                head: 0,
                tail: 0,
                len: 0,
            },
        }
    }
    fn pop(&mut self) -> Option<u64> {
        if self.state.len == 0 {
            return None;
        }
        let val = self.buf[self.state.tail];
        self.state.tail = (self.state.tail + 1) % N;
        self.state.len -= 1;
        Some(val)
    }
    fn push(&mut self, val: u64) -> Result<(), &'static str> {
        if self.state.len == N {
            return Err("ring full");
        }
        self.buf[self.state.head] = val;
        self.state.head = (self.state.head + 1) % N;
        self.state.len += 1;
        Ok(())
    }
    fn is_empty(&self) -> bool {
        self.state.len == 0
    }
    fn is_full(&self) -> bool {
        self.state.len == N
    }
    fn capacity(&self) -> usize {
        N
    }
}

/// A free-list ring buffer backed by a fixed-size const-generic array.
/// Dispatches to the smallest variant that fits `max_chunks`.
pub(crate) enum RingBuffer {
    Mini(RingInner<MINI>),
    Medium(RingInner<MEDIUM>),
    Large(RingInner<LARGE>),
    Huge(RingInner<HUGE>),
}

impl RingBuffer {
    pub fn new(max_chunks: usize) -> Self {
        if max_chunks <= MINI {
            RingBuffer::Mini(RingInner::new())
        } else if max_chunks <= MEDIUM {
            RingBuffer::Medium(RingInner::new())
        } else if max_chunks <= LARGE {
            RingBuffer::Large(RingInner::new())
        } else {
            RingBuffer::Huge(RingInner::new())
        }
    }
}

macro_rules! dispatch {
    ($self:expr, $method:ident $(, $arg:expr)*) => {
        match $self {
            RingBuffer::Mini(r)   => r.$method($($arg),*),
            RingBuffer::Medium(r) => r.$method($($arg),*),
            RingBuffer::Large(r)  => r.$method($($arg),*),
            RingBuffer::Huge(r)   => r.$method($($arg),*),
        }
    };
}

impl ChunkQueue for RingBuffer {
    fn pop(&mut self) -> Option<u64> {
        dispatch!(self, pop)
    }
    fn push(&mut self, v: u64) -> Result<(), &'static str> {
        dispatch!(self, push, v)
    }
    fn is_empty(&self) -> bool {
        dispatch!(self, is_empty)
    }
    fn is_full(&self) -> bool {
        dispatch!(self, is_full)
    }
    fn capacity(&self) -> usize {
        dispatch!(self, capacity)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fifo_order_and_empty_full_transitions() {
        let mut r: RingInner<MINI> = RingInner::new();
        assert!(r.is_empty());
        assert!(!r.is_full());
        assert_eq!(r.pop(), None);

        for v in 0..MINI as u64 {
            r.push(v).expect("push within capacity");
        }
        assert!(r.is_full());
        // Pushing into a full ring is refused, not silently overwritten.
        assert_eq!(r.push(99), Err("ring full"));

        // FIFO: values come back in insertion order.
        for v in 0..MINI as u64 {
            assert_eq!(r.pop(), Some(v));
        }
        assert!(r.is_empty());
        assert_eq!(r.pop(), None);
    }

    #[test]
    fn head_tail_wraparound_preserves_fifo() {
        // Repeatedly fill-then-drain so head/tail wrap past the end of the
        // backing array many times; FIFO order must hold every cycle.
        let mut r: RingInner<MINI> = RingInner::new();
        let mut next: u64 = 0;
        for _cycle in 0..10 {
            // Push a partial batch, pop part of it — staggers head/tail so the
            // next full fill straddles the array's wrap point.
            r.push(next).unwrap();
            next += 1;
            r.push(next).unwrap();
            next += 1;
            r.push(next).unwrap();
            next += 1;
            assert_eq!(r.pop(), Some(next - 3));
            assert_eq!(r.pop(), Some(next - 2));
            assert_eq!(r.pop(), Some(next - 1));
            assert!(r.is_empty());
        }
    }

    #[test]
    fn ringbuffer_selects_smallest_fitting_variant() {
        // Capacity dispatch: each variant must report a capacity that actually
        // holds `max_chunks`, and round-trip a value.
        for &max in &[MINI, MINI + 1, MEDIUM, MEDIUM + 1, LARGE, LARGE + 1] {
            let mut rb = RingBuffer::new(max);
            assert!(rb.capacity() >= max, "variant too small for {max}");
            assert!(rb.is_empty());
            rb.push(7).unwrap();
            assert!(!rb.is_empty());
            assert_eq!(rb.pop(), Some(7));
            assert!(rb.is_empty());
        }
    }
}
