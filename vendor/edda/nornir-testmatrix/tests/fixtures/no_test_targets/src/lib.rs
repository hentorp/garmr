//! Deliberately empty: this fixture exists to have NO `tests/` directory, so the
//! audit scans zero test targets. See `Cargo.toml` for why that must be a RED.

/// A function nobody tests — which is the entire point of the fixture.
pub fn untested() -> u8 {
    42
}
