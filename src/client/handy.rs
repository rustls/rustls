use msgs::enums::SignatureScheme;
use sign;
use key;
use client;

use std::collections;
use std::sync::{Arc, Mutex};

/// An implementor of `StoresClientSessions` which does nothing.
pub struct NoSessionStorage {}

impl client::StoresClientSessions for NoSessionStorage {
    fn put(&self, _key: Vec<u8>, _value: Vec<u8>) -> bool {
        false
    }

    fn get(&self, _key: &[u8]) -> Option<Vec<u8>> {
        None
    }
}

/// An implementor of `StoresClientSessions` that stores everything
/// in memory.  It enforces a limit on the number of sessions
/// to bound memory usage.
pub struct ClientSessionMemoryCache {
    cache: Mutex<collections::HashMap<Vec<u8>, Vec<u8>>>,
    max_entries: usize,
}

impl ClientSessionMemoryCache {
    /// Make a new ClientSessionMemoryCache.  `size` is the
    /// maximum number of stored sessions.
    pub fn new(size: usize) -> Arc<ClientSessionMemoryCache> {
        debug_assert!(size > 0);
        Arc::new(ClientSessionMemoryCache {
            cache: Mutex::new(collections::HashMap::new()),
            max_entries: size,
        })
    }

    fn limit_size(&self) {
        let mut cache = self.cache.lock().unwrap();
        while cache.len() > self.max_entries {
            let k = cache.keys().next().unwrap().clone();
            cache.remove(&k);
        }
    }
}

impl client::StoresClientSessions for ClientSessionMemoryCache {
    fn put(&self, key: Vec<u8>, value: Vec<u8>) -> bool {
        self.cache.lock()
            .unwrap()
            .insert(key, value);
        self.limit_size();
        true
    }

    fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.cache.lock()
            .unwrap()
            .get(key).cloned()
    }
}

pub struct FailResolveClientCert {}

impl client::ResolvesClientCert for FailResolveClientCert {
    fn resolve(&self,
               _acceptable_issuers: &[&[u8]],
               _sigschemes: &[SignatureScheme])
               -> Option<sign::CertifiedKey> {
        None
    }

    fn has_certs(&self) -> bool {
        false
    }
}

pub struct AlwaysResolvesClientCert(sign::CertifiedKey);

impl AlwaysResolvesClientCert {
    pub fn new_rsa(chain: Vec<key::Certificate>,
                   priv_key: &key::PrivateKey) -> AlwaysResolvesClientCert {
        let key = sign::RSASigningKey::new(priv_key).expect("Invalid RSA private key");
        let key: Arc<Box<sign::SigningKey>> = Arc::new(Box::new(key));
        AlwaysResolvesClientCert(sign::CertifiedKey::new(chain, key))
    }
}

impl client::ResolvesClientCert for AlwaysResolvesClientCert {
    fn resolve(&self,
               _acceptable_issuers: &[&[u8]],
               _sigschemes: &[SignatureScheme])
               -> Option<sign::CertifiedKey> {
        Some(self.0.clone())
    }

    fn has_certs(&self) -> bool {
        true
    }
}
