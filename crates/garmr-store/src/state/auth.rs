// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! A tiny opaque key/value store for the console's auth state — the
//! session-cookie MAC key and the registered-passkeys blob. The store keeps
//! only bytes; the serialization (and all crypto) lives in the console layer,
//! so garmr-store stays ignorant of WebAuthn.

use garmr_core::{Error, Result};

use super::{StateStore, AUTH};

impl StateStore {
    /// Read an auth value (opaque bytes) by key.
    pub fn auth_get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        let rtx = self.db.begin_read().map_err(Error::store)?;
        let t = rtx.open_table(AUTH).map_err(Error::store)?;
        Ok(t.get(key)
            .map_err(Error::store)?
            .map(|v| v.value().to_vec()))
    }

    /// Write an auth value (opaque bytes) under a key.
    pub fn auth_put(&self, key: &str, val: &[u8]) -> Result<()> {
        let wtx = self.db.begin_write().map_err(Error::store)?;
        {
            let mut t = wtx.open_table(AUTH).map_err(Error::store)?;
            t.insert(key, val).map_err(Error::store)?;
        }
        wtx.commit().map_err(Error::store)?;
        Ok(())
    }

    /// Get the value under `key`, or generate one with `init`, persist it, and
    /// return it — the get-or-create used for the session MAC key so it is
    /// stable across restarts without any config.
    pub fn auth_get_or_init(&self, key: &str, init: impl FnOnce() -> Vec<u8>) -> Result<Vec<u8>> {
        if let Some(v) = self.auth_get(key)? {
            return Ok(v);
        }
        let v = init();
        self.auth_put(key, &v)?;
        Ok(v)
    }
}

#[cfg(test)]
mod tests {
    use super::super::StateStore;

    fn tmp() -> StateStore {
        let n = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let p = std::env::temp_dir().join(format!("garmr-auth-test-{n}.redb"));
        StateStore::open(&p).unwrap()
    }

    #[test]
    fn put_get_roundtrip_and_get_or_init_is_stable() {
        let s = tmp();
        assert_eq!(s.auth_get("k").unwrap(), None);
        s.auth_put("k", b"hello").unwrap();
        assert_eq!(s.auth_get("k").unwrap().as_deref(), Some(&b"hello"[..]));

        let first = s.auth_get_or_init("key", || vec![1, 2, 3]).unwrap();
        let second = s.auth_get_or_init("key", || vec![9, 9, 9]).unwrap();
        assert_eq!(first, vec![1, 2, 3]);
        assert_eq!(second, first, "get_or_init must not regenerate");
    }
}
