use msgs::enums::SignatureScheme;
use msgs::handshake::SessionID;
use msgs::codec::Codec;
use rand;
use sign;
use key;
use webpki;
use server;

use std::collections;
use std::sync::{Arc, Mutex};

/// Something which never stores sessions.
pub struct NoSessionStorage {}

impl server::StoresServerSessions for NoSessionStorage {
    fn generate(&self) -> SessionID {
        SessionID::empty()
    }
    fn put(&self, _id: &SessionID, _sec: Vec<u8>) -> bool {
        false
    }
    fn get(&self, _id: &SessionID) -> Option<Vec<u8>> {
        None
    }
    fn del(&self, _id: &SessionID) -> bool {
        false
    }
}

/// An implementor of `StoresServerSessions` that stores everything
/// in memory.  If enforces a limit on the number of stored sessions
/// to bound memory usage.
pub struct ServerSessionMemoryCache {
    cache: Mutex<collections::HashMap<Vec<u8>, Vec<u8>>>,
    max_entries: usize,
}

impl ServerSessionMemoryCache {
    /// Make a new ServerSessionMemoryCache.  `size` is the maximum
    /// number of stored sessions.
    pub fn new(size: usize) -> Arc<ServerSessionMemoryCache> {
        debug_assert!(size > 0);
        Arc::new(ServerSessionMemoryCache {
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

impl server::StoresServerSessions for ServerSessionMemoryCache {
    fn generate(&self) -> SessionID {
        let mut v = [0u8; 32];
        rand::fill_random(&mut v);
        SessionID::new(&v)
    }

    fn put(&self, id: &SessionID, sec: Vec<u8>) -> bool {
        self.cache.lock()
            .unwrap()
            .insert(id.get_encoding(), sec);
        self.limit_size();
        true
    }

    fn get(&self, id: &SessionID) -> Option<Vec<u8>> {
        self.cache.lock()
            .unwrap()
            .get(&id.get_encoding()).cloned()
    }

    fn del(&self, id: &SessionID) -> bool {
        self.cache.lock()
            .unwrap()
            .remove(&id.get_encoding()).is_some()
    }
}

/// Something which never produces tickets.
pub struct NeverProducesTickets {}

impl server::ProducesTickets for NeverProducesTickets {
    fn enabled(&self) -> bool {
        false
    }
    fn get_lifetime(&self) -> u32 {
        0
    }
    fn encrypt(&self, _bytes: &[u8]) -> Option<Vec<u8>> {
        None
    }
    fn decrypt(&self, _bytes: &[u8]) -> Option<Vec<u8>> {
        None
    }
}

/// Something which never resolves a certificate.
pub struct FailResolveChain {}

impl server::ResolvesServerCert for FailResolveChain {
    fn resolve(&self,
               _server_name: Option<webpki::DNSNameRef>,
               _sigschemes: &[SignatureScheme])
               -> Option<sign::CertifiedKey> {
        None
    }
}

/// Something which always resolves to the same cert chain.
pub struct AlwaysResolvesChain(sign::CertifiedKey);

impl AlwaysResolvesChain {
    pub fn new_rsa(chain: Vec<key::Certificate>,
                   priv_key: &key::PrivateKey) -> AlwaysResolvesChain {
        let key = sign::RSASigningKey::new(priv_key)
            .expect("Invalid RSA private key");
        let key: Arc<Box<sign::SigningKey>> = Arc::new(Box::new(key));
        AlwaysResolvesChain(sign::CertifiedKey::new(chain, key))
    }

    pub fn new_rsa_with_extras(chain: Vec<key::Certificate>,
                               priv_key: &key::PrivateKey,
                               ocsp: Vec<u8>,
                               scts: Vec<u8>) -> AlwaysResolvesChain {
        let mut r = AlwaysResolvesChain::new_rsa(chain, priv_key);
        if !ocsp.is_empty() {
            r.0.ocsp = Some(ocsp);
        }
        if !scts.is_empty() {
            r.0.sct_list = Some(scts);
        }
        r
    }
}

impl server::ResolvesServerCert for AlwaysResolvesChain {
    fn resolve(&self,
               _server_name: Option<webpki::DNSNameRef>,
               _sigschemes: &[SignatureScheme])
               -> Option<sign::CertifiedKey> {
        Some(self.0.clone())
    }
}
