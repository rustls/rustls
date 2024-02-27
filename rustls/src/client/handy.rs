use crate::client;
use crate::enums::SignatureScheme;
use crate::error::Error;
use crate::limited_cache;
use crate::msgs::handshake::CertificateChain;
use crate::msgs::persist;
use crate::sign;
use crate::NamedGroup;

use pki_types::ServerName;

use alloc::collections::VecDeque;
use alloc::sync::Arc;
use core::fmt;
use std::sync::Mutex;

/// An implementer of `ClientSessionStore` which does nothing.
#[derive(Debug)]
pub(super) struct NoClientSessionStorage;

impl client::ClientSessionStore for NoClientSessionStorage {
    fn set_kx_hint(&self, _: ServerName<'static>, _: NamedGroup) {}

    fn kx_hint(&self, _: &ServerName<'_>) -> Option<NamedGroup> {
        None
    }

    fn set_tls12_session(&self, _: ServerName<'static>, _: persist::Tls12ClientSessionValue) {}

    fn tls12_session(&self, _: &ServerName<'_>) -> Option<persist::Tls12ClientSessionValue> {
        None
    }

    fn remove_tls12_session(&self, _: &ServerName<'_>) {}

    fn insert_tls13_ticket(&self, _: ServerName<'static>, _: persist::Tls13ClientSessionValue) {}

    fn take_tls13_ticket(&self, _: &ServerName<'_>) -> Option<persist::Tls13ClientSessionValue> {
        None
    }
}

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
    servers: Mutex<limited_cache::LimitedCache<ServerName<'static>, ServerData>>,
}

impl ClientSessionMemoryCache {
    /// Make a new ClientSessionMemoryCache.  `size` is the
    /// maximum number of stored sessions.
    pub fn new(size: usize) -> Self {
        let max_servers =
            size.saturating_add(MAX_TLS13_TICKETS_PER_SERVER - 1) / MAX_TLS13_TICKETS_PER_SERVER;
        Self {
            servers: Mutex::new(limited_cache::LimitedCache::new(max_servers)),
        }
    }
}

impl client::ClientSessionStore for ClientSessionMemoryCache {
    fn set_kx_hint(&self, server_name: ServerName<'static>, group: NamedGroup) {
        self.servers
            .lock()
            .unwrap()
            .get_or_insert_default_and_edit(server_name, |data| data.kx_hint = Some(group));
    }

    fn kx_hint(&self, server_name: &ServerName<'_>) -> Option<NamedGroup> {
        self.servers
            .lock()
            .unwrap()
            .get(server_name)
            .and_then(|sd| sd.kx_hint)
    }

    fn set_tls12_session(
        &self,
        _server_name: ServerName<'static>,
        _value: persist::Tls12ClientSessionValue,
    ) {
        #[cfg(feature = "tls12")]
        self.servers
            .lock()
            .unwrap()
            .get_or_insert_default_and_edit(_server_name.clone(), |data| data.tls12 = Some(_value));
    }

    fn tls12_session(
        &self,
        _server_name: &ServerName<'_>,
    ) -> Option<persist::Tls12ClientSessionValue> {
        #[cfg(not(feature = "tls12"))]
        return None;

        #[cfg(feature = "tls12")]
        self.servers
            .lock()
            .unwrap()
            .get(_server_name)
            .and_then(|sd| sd.tls12.as_ref().cloned())
    }

    fn remove_tls12_session(&self, _server_name: &ServerName<'static>) {
        #[cfg(feature = "tls12")]
        self.servers
            .lock()
            .unwrap()
            .get_mut(_server_name)
            .and_then(|data| data.tls12.take());
    }

    fn insert_tls13_ticket(
        &self,
        server_name: ServerName<'static>,
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
        server_name: &ServerName<'static>,
    ) -> Option<persist::Tls13ClientSessionValue> {
        self.servers
            .lock()
            .unwrap()
            .get_mut(server_name)
            .and_then(|data| data.tls13.pop_back())
    }
}

impl fmt::Debug for ClientSessionMemoryCache {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Note: we omit self.servers as it may contain sensitive data.
        f.debug_struct("ClientSessionMemoryCache")
            .finish()
    }
}

#[derive(Debug)]
pub(super) struct FailResolveClientCert {}

impl client::ResolvesClientCert for FailResolveClientCert {
    fn resolve(
        &self,
        _root_hint_subjects: &[&[u8]],
        _sigschemes: &[SignatureScheme],
    ) -> Option<Arc<sign::CertifiedKey>> {
        None
    }

    fn has_certs(&self) -> bool {
        false
    }
}

#[derive(Debug)]
pub(super) struct AlwaysResolvesClientCert(Arc<sign::CertifiedKey>);

impl AlwaysResolvesClientCert {
    pub(super) fn new(
        private_key: Arc<dyn sign::SigningKey>,
        chain: CertificateChain,
    ) -> Result<Self, Error> {
        Ok(Self(Arc::new(sign::CertifiedKey::new(
            chain.0,
            private_key,
        ))))
    }
}

impl client::ResolvesClientCert for AlwaysResolvesClientCert {
    fn resolve(
        &self,
        _root_hint_subjects: &[&[u8]],
        _sigschemes: &[SignatureScheme],
    ) -> Option<Arc<sign::CertifiedKey>> {
        Some(Arc::clone(&self.0))
    }

    fn has_certs(&self) -> bool {
        true
    }
}

#[cfg(all(test, any(feature = "ring", feature = "aws_lc_rs")))]
mod tests {
    use super::NoClientSessionStorage;
    use crate::client::ClientSessionStore;
    use crate::msgs::enums::NamedGroup;
    use crate::msgs::handshake::CertificateChain;
    #[cfg(feature = "tls12")]
    use crate::msgs::handshake::SessionId;
    use crate::msgs::persist::Tls13ClientSessionValue;
    use crate::suites::SupportedCipherSuite;
    use crate::test_provider::cipher_suite;
    use alloc::vec::Vec;

    use pki_types::{ServerName, UnixTime};

    #[test]
    fn test_noclientsessionstorage_does_nothing() {
        let c = NoClientSessionStorage {};
        let name = ServerName::try_from("example.com").unwrap();
        let now = UnixTime::now();

        c.set_kx_hint(name.clone(), NamedGroup::X25519);
        assert_eq!(None, c.kx_hint(&name));

        #[cfg(feature = "tls12")]
        {
            use crate::msgs::persist::Tls12ClientSessionValue;
            let SupportedCipherSuite::Tls12(tls12_suite) =
                cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
            else {
                unreachable!()
            };

            c.set_tls12_session(
                name.clone(),
                Tls12ClientSessionValue::new(
                    tls12_suite,
                    SessionId::empty(),
                    Vec::new(),
                    &[],
                    CertificateChain::default(),
                    now,
                    0,
                    true,
                ),
            );
            assert!(c.tls12_session(&name).is_none());
            c.remove_tls12_session(&name);
        }

        #[cfg_attr(not(feature = "tls12"), allow(clippy::infallible_destructuring_match))]
        let tls13_suite = match cipher_suite::TLS13_AES_256_GCM_SHA384 {
            SupportedCipherSuite::Tls13(inner) => inner,
            #[cfg(feature = "tls12")]
            _ => unreachable!(),
        };
        c.insert_tls13_ticket(
            name.clone(),
            Tls13ClientSessionValue::new(
                tls13_suite,
                Vec::new(),
                &[],
                CertificateChain::default(),
                now,
                0,
                0,
                0,
            ),
        );
        assert!(c.take_tls13_ticket(&name).is_none());
    }
}
