use crate::client;
use crate::error::TLSError;
use crate::key;
use crate::msgs::enums::SignatureScheme;
use crate::sign;

use std::collections;
use std::sync::{Arc, Mutex};
use std::num::NonZeroUsize;
use std::collections::hash_map::Entry;

/// An implementer of `StoresClientSessions` which does nothing.
pub struct NoClientSessionStorage {}

impl client::StoresClientSessions for NoClientSessionStorage {
    fn put(&self, _key: Vec<u8>, _value: Vec<u8>) -> bool {
        false
    }

    fn get(&self, _key: &[u8]) -> Option<Vec<u8>> {
        None
    }
}

/// An implementer of `StoresClientSessions` that stores everything
/// in memory.  It enforces a limit on the number of entries
/// to bound memory usage.
pub struct ClientSessionMemoryCache {
    cache: Mutex<collections::HashMap<Vec<u8>, Vec<u8>>>,
    max_entries: NonZeroUsize,
}

impl ClientSessionMemoryCache {
    /// Make a new ClientSessionMemoryCache.  `size` is the
    /// maximum number of stored sessions.
    pub fn new(size: NonZeroUsize) -> Arc<ClientSessionMemoryCache> {
        Arc::new(ClientSessionMemoryCache {
            cache: Mutex::new(collections::HashMap::new()),
            max_entries: size,
        })
    }
}

impl client::StoresClientSessions for ClientSessionMemoryCache {
    fn put(&self, key: Vec<u8>, value: Vec<u8>) -> bool {
        let mut cache = self.cache
            .lock()
            .unwrap();

        // Always replace an existing entry with the same key instead of
        // evicting any other entry.
        let len = cache.len();
        let key = match cache.entry(key) {
            Entry::Occupied(mut existing) => {
                existing.insert(value);
                return true;
            },
            Entry::Vacant(vacant) if len < self.max_entries.get() => {
                vacant.insert(value);
                return true;
            },
            Entry::Vacant(vacant) => {
                vacant.into_key()
            }
        };

        // The cache is full. Evict an entry to make room for the new entry.

        debug_assert_eq!(cache.len(), self.max_entries.get());
        debug_assert!(!cache.is_empty());

        // Remove an arbitrary entry.
        // TODO(issue 469): Implement a better eviction policy.
        let to_remove = cache.keys().next().unwrap().clone();
        cache.remove(&to_remove);

        debug_assert_eq!(cache.len(), self.max_entries.get() - 1);

        // Unfortunately, we have to do another search to insert the new entry.
        cache.insert(key, value);

        debug_assert_eq!(cache.len(), self.max_entries.get());

        true
    }

    fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.cache
            .lock()
            .unwrap()
            .get(key)
            .cloned()
    }
}

pub struct FailResolveClientCert {}

impl client::ResolvesClientCert for FailResolveClientCert {
    fn resolve(
        &self,
        _acceptable_issuers: &[&[u8]],
        _sigschemes: &[SignatureScheme],
    ) -> Option<sign::CertifiedKey> {
        None
    }

    fn has_certs(&self) -> bool {
        false
    }
}

pub struct AlwaysResolvesClientCert(sign::CertifiedKey);

impl AlwaysResolvesClientCert {
    pub fn new(
        chain: Vec<key::Certificate>,
        priv_key: &key::PrivateKey,
    ) -> Result<AlwaysResolvesClientCert, TLSError> {
        let key = sign::any_supported_type(priv_key)
            .map_err(|_| TLSError::General("invalid private key".into()))?;
        Ok(AlwaysResolvesClientCert(sign::CertifiedKey::new(
            chain,
            Arc::new(key),
        )))
    }
}

impl client::ResolvesClientCert for AlwaysResolvesClientCert {
    fn resolve(
        &self,
        _acceptable_issuers: &[&[u8]],
        _sigschemes: &[SignatureScheme],
    ) -> Option<sign::CertifiedKey> {
        Some(self.0.clone())
    }

    fn has_certs(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::StoresClientSessions;

    fn four() -> NonZeroUsize {
        NonZeroUsize::new(4).unwrap()
    }

    #[test]
    fn test_noclientsessionstorage_drops_put() {
        let c = NoClientSessionStorage {};
        assert_eq!(c.put(vec![0x01], vec![0x02]), false);
    }

    #[test]
    fn test_noclientsessionstorage_denies_gets() {
        let c = NoClientSessionStorage {};
        c.put(vec![0x01], vec![0x02]);
        assert_eq!(c.get(&[]), None);
        assert_eq!(c.get(&[0x01]), None);
        assert_eq!(c.get(&[0x02]), None);
    }

    #[test]
    fn test_clientsessionmemorycache_accepts_put() {
        let c = ClientSessionMemoryCache::new(four());
        assert_eq!(c.put(vec![0x01], vec![0x02]), true);
    }

    #[test]
    fn test_clientsessionmemorycache_persists_put() {
        let c = ClientSessionMemoryCache::new(four());
        assert_eq!(c.put(vec![0x01], vec![0x02]), true);
        assert_eq!(c.get(&[0x01]), Some(vec![0x02]));
        assert_eq!(c.get(&[0x01]), Some(vec![0x02]));
    }

    #[test]
    fn test_clientsessionmemorycache_overwrites_put() {
        let c = ClientSessionMemoryCache::new(four());
        assert_eq!(c.put(vec![0x01], vec![0x02]), true);
        assert_eq!(c.put(vec![0x01], vec![0x04]), true);
        assert_eq!(c.get(&[0x01]), Some(vec![0x04]));
    }

    #[test]
    fn test_clientsessionmemorycache_drops_to_maintain_size_invariant() {
        let c = ClientSessionMemoryCache::new(four());
        assert_eq!(c.put(vec![0x01], vec![0x02]), true);
        assert_eq!(c.put(vec![0x03], vec![0x04]), true);
        assert_eq!(c.put(vec![0x05], vec![0x06]), true);
        assert_eq!(c.put(vec![0x07], vec![0x08]), true);
        assert_eq!(c.put(vec![0x09], vec![0x0a]), true);

        let mut count = 0;
        if c.get(&[0x01]).is_some() {
            count += 1;
        }
        if c.get(&[0x03]).is_some() {
            count += 1;
        }
        if c.get(&[0x05]).is_some() {
            count += 1;
        }
        if c.get(&[0x07]).is_some() {
            count += 1;
        }
        if c.get(&[0x09]).is_some() {
            count += 1;
        }

        assert_eq!(count, 4);
    }
}
