use crate::builder::sealed::Sealed;
use crate::client;
use crate::enums::SignatureScheme;
use crate::error::Error;
use crate::key;
use crate::limited_cache;
use crate::msgs::persist;
use crate::sign;
use crate::NamedGroup;
use crate::ServerName;

use std::collections::VecDeque;
use std::fmt;
use std::sync::{Arc, Mutex};

use super::ClientSessionStore;

/// An implementer of `ClientSessionStore` which does nothing.
pub struct NoClientSessionStorage {}

impl ClientSessionStore for NoClientSessionStorage {
    fn set_kx_hint(&self, _: &ServerName, _: NamedGroup) {}

    fn kx_hint(&self, _: &ServerName) -> Option<NamedGroup> {
        None
    }

    fn set_tls12_session(&self, _: &ServerName, _: persist::Tls12ClientSessionValue) {}

    fn tls12_session(&self, _: &ServerName) -> Option<persist::Tls12ClientSessionValue> {
        None
    }

    fn remove_tls12_session(&self, _: &ServerName) {}

    fn insert_tls13_ticket(&self, _: &ServerName, _: persist::Tls13ClientSessionValue) {}

    fn take_tls13_ticket(&self, _: &ServerName) -> Option<persist::Tls13ClientSessionValue> {
        None
    }
}

impl Sealed for NoClientSessionStorage {}

const MAX_TLS13_TICKETS_PER_SERVER: usize = 8;

struct ServerData {
    kx_hint: Option<NamedGroup>,

    // Zero or one TLS1.2 sessions.
    #[cfg(feature = "tls12")]
    tls12: Option<persist::Tls12ClientSessionValue>,

    // Up to MAX_TLS13_TICKETS_PER_SERVER TLS1.3 tickets, oldest first.
    tls13: VecDeque<persist::Tls13ClientSessionValue>,
}

impl Default for ServerData {
    fn default() -> Self {
        Self {
            kx_hint: None,
            #[cfg(feature = "tls12")]
            tls12: None,
            tls13: VecDeque::with_capacity(MAX_TLS13_TICKETS_PER_SERVER),
        }
    }
}

/// An implementer of `ClientSessionStore` that stores everything
/// in memory.
///
/// It enforces a limit on the number of entries to bound memory usage.
pub struct ClientSessionMemoryCache {
    servers: Mutex<limited_cache::LimitedCache<ServerName, ServerData>>,
}

impl ClientSessionMemoryCache {
    /// Make a new ClientSessionMemoryCache.  `size` is the
    /// maximum number of stored sessions.
    pub fn new(size: usize) -> Arc<Self> {
        let max_servers =
            size.saturating_add(MAX_TLS13_TICKETS_PER_SERVER - 1) / MAX_TLS13_TICKETS_PER_SERVER;
        Arc::new(Self {
            servers: Mutex::new(limited_cache::LimitedCache::new(max_servers)),
        })
    }
}

impl ClientSessionStore for ClientSessionMemoryCache {
    fn set_kx_hint(&self, server_name: &ServerName, group: NamedGroup) {
        self.servers
            .lock()
            .unwrap()
            .get_or_insert_default_and_edit(server_name.clone(), |data| data.kx_hint = Some(group));
    }

    fn kx_hint(&self, server_name: &ServerName) -> Option<NamedGroup> {
        self.servers
            .lock()
            .unwrap()
            .get(server_name)
            .and_then(|sd| sd.kx_hint)
    }

    fn set_tls12_session(
        &self,
        _server_name: &ServerName,
        _value: persist::Tls12ClientSessionValue,
    ) {
        #[cfg(feature = "tls12")]
        self.servers
            .lock()
            .unwrap()
            .get_or_insert_default_and_edit(_server_name.clone(), |data| data.tls12 = Some(_value));
    }

    fn tls12_session(&self, _server_name: &ServerName) -> Option<persist::Tls12ClientSessionValue> {
        #[cfg(not(feature = "tls12"))]
        return None;

        #[cfg(feature = "tls12")]
        self.servers
            .lock()
            .unwrap()
            .get(_server_name)
            .and_then(|sd| sd.tls12.as_ref().cloned())
    }

    fn remove_tls12_session(&self, _server_name: &ServerName) {
        #[cfg(feature = "tls12")]
        self.servers
            .lock()
            .unwrap()
            .get_mut(_server_name)
            .and_then(|data| data.tls12.take());
    }

    fn insert_tls13_ticket(
        &self,
        server_name: &ServerName,
        value: persist::Tls13ClientSessionValue,
    ) {
        self.servers
            .lock()
            .unwrap()
            .get_or_insert_default_and_edit(server_name.clone(), |data| {
                if data.tls13.len() == data.tls13.capacity() {
                    data.tls13.pop_front();
                }
                data.tls13.push_back(value);
            });
    }

    fn take_tls13_ticket(
        &self,
        server_name: &ServerName,
    ) -> Option<persist::Tls13ClientSessionValue> {
        self.servers
            .lock()
            .unwrap()
            .get_mut(server_name)
            .and_then(|data| data.tls13.pop_front())
    }
}

impl Sealed for ClientSessionMemoryCache {}

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

/// Test-only: used for the bogo shim.
#[doc(hidden)]
pub struct ClientCacheWithoutKxHints {
    delay: u32,
    storage: Arc<ClientSessionMemoryCache>,
}

impl ClientCacheWithoutKxHints {
    /// Create new cache.
    pub fn new(delay: u32) -> Arc<Self> {
        Arc::new(Self {
            delay,
            storage: ClientSessionMemoryCache::new(32),
        })
    }
}

impl ClientSessionStore for ClientCacheWithoutKxHints {
    fn set_kx_hint(&self, _: &ServerName, _: NamedGroup) {}
    fn kx_hint(&self, _: &ServerName) -> Option<NamedGroup> {
        None
    }

    fn set_tls12_session(
        &self,
        server_name: &ServerName,
        #[allow(unused_mut)] mut value: super::Tls12ClientSessionValue,
    ) {
        #[cfg(feature = "tls12")]
        value.rewind_epoch(self.delay);
        self.storage
            .set_tls12_session(server_name, value);
    }

    fn tls12_session(&self, server_name: &ServerName) -> Option<super::Tls12ClientSessionValue> {
        self.storage.tls12_session(server_name)
    }

    fn remove_tls12_session(&self, server_name: &ServerName) {
        self.storage
            .remove_tls12_session(server_name);
    }

    fn insert_tls13_ticket(
        &self,
        server_name: &ServerName,
        mut value: super::Tls13ClientSessionValue,
    ) {
        value.rewind_epoch(self.delay);
        self.storage
            .insert_tls13_ticket(server_name, value);
    }

    fn take_tls13_ticket(
        &self,
        server_name: &ServerName,
    ) -> Option<super::Tls13ClientSessionValue> {
        self.storage
            .take_tls13_ticket(server_name)
    }
}

impl Sealed for ClientCacheWithoutKxHints {}

/// Test-only.
#[doc(hidden)]
pub struct ClientSessionStoreMock {
    storage: Arc<dyn ClientSessionStore>,
    ops: Mutex<Vec<ClientStorageOp>>,
}

impl ClientSessionStoreMock {
    /// Create a new tracker.
    pub fn new() -> Self {
        Self {
            storage: ClientSessionMemoryCache::new(1024),
            ops: Mutex::new(Vec::new()),
        }
    }

    /// Get the current list of operations.
    #[cfg(feature = "tls12")]
    pub fn ops(&self) -> Vec<ClientStorageOp> {
        self.ops.lock().unwrap().clone()
    }

    /// Get the current list of operations and reset the list.
    #[cfg(feature = "tls12")]
    pub fn ops_and_reset(&self) -> Vec<ClientStorageOp> {
        std::mem::take(&mut self.ops.lock().unwrap())
    }
}

impl ClientSessionStore for ClientSessionStoreMock {
    fn set_kx_hint(&self, server_name: &ServerName, group: NamedGroup) {
        self.ops
            .lock()
            .unwrap()
            .push(ClientStorageOp::SetKxHint(server_name.clone(), group));
        self.storage
            .set_kx_hint(server_name, group)
    }

    fn kx_hint(&self, server_name: &ServerName) -> Option<NamedGroup> {
        let rc = self.storage.kx_hint(server_name);
        self.ops
            .lock()
            .unwrap()
            .push(ClientStorageOp::GetKxHint(server_name.clone(), rc));
        rc
    }

    fn set_tls12_session(&self, server_name: &ServerName, value: client::Tls12ClientSessionValue) {
        self.ops
            .lock()
            .unwrap()
            .push(ClientStorageOp::SetTls12Session(server_name.clone()));
        self.storage
            .set_tls12_session(server_name, value)
    }

    fn tls12_session(&self, server_name: &ServerName) -> Option<client::Tls12ClientSessionValue> {
        let rc = self.storage.tls12_session(server_name);
        self.ops
            .lock()
            .unwrap()
            .push(ClientStorageOp::GetTls12Session(
                server_name.clone(),
                rc.is_some(),
            ));
        rc
    }

    fn remove_tls12_session(&self, server_name: &ServerName) {
        self.ops
            .lock()
            .unwrap()
            .push(ClientStorageOp::RemoveTls12Session(server_name.clone()));
        self.storage
            .remove_tls12_session(server_name);
    }

    fn insert_tls13_ticket(
        &self,
        server_name: &ServerName,
        value: client::Tls13ClientSessionValue,
    ) {
        self.ops
            .lock()
            .unwrap()
            .push(ClientStorageOp::InsertTls13Ticket(server_name.clone()));
        self.storage
            .insert_tls13_ticket(server_name, value);
    }

    fn take_tls13_ticket(
        &self,
        server_name: &ServerName,
    ) -> Option<client::Tls13ClientSessionValue> {
        let rc = self
            .storage
            .take_tls13_ticket(server_name);
        self.ops
            .lock()
            .unwrap()
            .push(ClientStorageOp::TakeTls13Ticket(
                server_name.clone(),
                rc.is_some(),
            ));
        rc
    }
}

impl fmt::Debug for ClientSessionStoreMock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "(ops: {:?})", self.ops.lock().unwrap())
    }
}

impl Sealed for ClientSessionStoreMock {}

#[doc(hidden)]
#[derive(Debug, Clone)]
pub enum ClientStorageOp {
    SetKxHint(ServerName, NamedGroup),
    GetKxHint(ServerName, Option<NamedGroup>),
    SetTls12Session(ServerName),
    GetTls12Session(ServerName, bool),
    RemoveTls12Session(ServerName),
    InsertTls13Ticket(ServerName),
    TakeTls13Ticket(ServerName, bool),
}

#[cfg(test)]
mod test {
    use super::NoClientSessionStorage;
    use crate::client::ClientSessionStore;
    use crate::msgs::enums::NamedGroup;
    #[cfg(feature = "tls12")]
    use crate::msgs::handshake::SessionID;
    use crate::msgs::persist::Tls13ClientSessionValue;
    use crate::suites::SupportedCipherSuite;
    use std::convert::TryInto;

    #[test]
    fn test_noclientsessionstorage_does_nothing() {
        let c = NoClientSessionStorage {};
        let name = "example.com".try_into().unwrap();
        let now = crate::ticketer::TimeBase::now().unwrap();

        c.set_kx_hint(&name, NamedGroup::X25519);
        assert_eq!(None, c.kx_hint(&name));

        #[cfg(feature = "tls12")]
        {
            use crate::msgs::persist::Tls12ClientSessionValue;
            let tls12_suite = match crate::cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 {
                SupportedCipherSuite::Tls12(inner) => inner,
                _ => unreachable!(),
            };

            c.set_tls12_session(
                &name,
                Tls12ClientSessionValue::new(
                    tls12_suite,
                    SessionID::empty(),
                    Vec::new(),
                    Vec::new(),
                    Vec::new(),
                    now,
                    0,
                    true,
                ),
            );
            assert!(c.tls12_session(&name).is_none());
            c.remove_tls12_session(&name);
        }

        let tls13_suite = match crate::cipher_suite::TLS13_AES_256_GCM_SHA384 {
            SupportedCipherSuite::Tls13(inner) => inner,
            #[cfg(feature = "tls12")]
            _ => unreachable!(),
        };
        c.insert_tls13_ticket(
            &name,
            Tls13ClientSessionValue::new(
                tls13_suite,
                Vec::new(),
                Vec::new(),
                Vec::new(),
                now,
                0,
                0,
                0,
            ),
        );
        assert!(c.take_tls13_ticket(&name).is_none());
    }
}
