use crate::client;
use crate::error::Error;
use crate::key;
use crate::limited_cache;
use crate::msgs::enums::SignatureScheme;
use crate::sign;

use std::sync::{Arc, Mutex};

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
    cache: Mutex<limited_cache::LimitedCache<Vec<u8>, Vec<u8>>>,
}

impl ClientSessionMemoryCache {
    /// Make a new ClientSessionMemoryCache.  `size` is the
    /// maximum number of stored sessions.
    pub fn new(size: usize) -> Arc<Self> {
        debug_assert!(size > 0);
        Arc::new(Self {
            cache: Mutex::new(limited_cache::LimitedCache::new(size)),
        })
    }
}

impl client::StoresClientSessions for ClientSessionMemoryCache {
    fn put(&self, key: Vec<u8>, value: Vec<u8>) -> bool {
        self.cache
            .lock()
            .unwrap()
            .insert(key, value);
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

pub(super) struct FailResolveClientCert {}

impl client::ResolvesClientCert for FailResolveClientCert {
    fn resolve(
        &self,
        _acceptable_issuers: &[&[u8]],
        _sigschemes: &[SignatureScheme],
    ) -> Option<Arc<sign::CertifiedKey>> {
        None
    }

    fn has_certs(&self) -> bool {
        false
    }
}

pub(super) struct AlwaysResolvesClientCert(Arc<sign::CertifiedKey>);

impl AlwaysResolvesClientCert {
    pub(super) fn new(
        chain: Vec<key::Certificate>,
        priv_key: &key::PrivateKey,
    ) -> Result<Self, Error> {
        let key = sign::any_supported_type(priv_key)
            .map_err(|_| Error::General("invalid private key".into()))?;
        Ok(Self(Arc::new(sign::CertifiedKey::new(chain, key))))
    }
}

impl client::ResolvesClientCert for AlwaysResolvesClientCert {
    fn resolve(
        &self,
        _acceptable_issuers: &[&[u8]],
        _sigschemes: &[SignatureScheme],
    ) -> Option<Arc<sign::CertifiedKey>> {
        Some(Arc::clone(&self.0))
    }

    fn has_certs(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::client::StoresClientSessions;

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
        let c = ClientSessionMemoryCache::new(4);
        assert_eq!(c.put(vec![0x01], vec![0x02]), true);
    }

    #[test]
    fn test_clientsessionmemorycache_persists_put() {
        let c = ClientSessionMemoryCache::new(4);
        assert_eq!(c.put(vec![0x01], vec![0x02]), true);
        assert_eq!(c.get(&[0x01]), Some(vec![0x02]));
        assert_eq!(c.get(&[0x01]), Some(vec![0x02]));
    }

    #[test]
    fn test_clientsessionmemorycache_overwrites_put() {
        let c = ClientSessionMemoryCache::new(4);
        assert_eq!(c.put(vec![0x01], vec![0x02]), true);
        assert_eq!(c.put(vec![0x01], vec![0x04]), true);
        assert_eq!(c.get(&[0x01]), Some(vec![0x04]));
    }

    #[test]
    fn test_clientsessionmemorycache_drops_to_maintain_size_invariant() {
        let c = ClientSessionMemoryCache::new(2);
        assert_eq!(c.put(vec![0x01], vec![0x02]), true);
        assert_eq!(c.put(vec![0x03], vec![0x04]), true);
        assert_eq!(c.put(vec![0x05], vec![0x06]), true);
        assert_eq!(c.put(vec![0x07], vec![0x08]), true);
        assert_eq!(c.put(vec![0x09], vec![0x0a]), true);

        let count = c.get(&[0x01]).iter().count()
            + c.get(&[0x03]).iter().count()
            + c.get(&[0x05]).iter().count()
            + c.get(&[0x07]).iter().count()
            + c.get(&[0x09]).iter().count();

        assert!(count < 5);
    }
}
