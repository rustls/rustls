use core::hash::Hasher;

use super::{ClientSessionKey, CredentialRequest};
use crate::client;
use crate::crypto::SelectedCredential;
use crate::crypto::kx::NamedGroup;
use crate::enums::CertificateType;
use crate::msgs::persist;

/// An implementer of `ClientSessionStore` which does nothing.
#[derive(Debug)]
pub(super) struct NoClientSessionStorage;

impl client::ClientSessionStore for NoClientSessionStorage {
    fn set_kx_hint(&self, _: ClientSessionKey<'static>, _: NamedGroup) {}

    fn kx_hint(&self, _: &ClientSessionKey<'_>) -> Option<NamedGroup> {
        None
    }

    fn set_tls12_session(&self, _: ClientSessionKey<'static>, _: persist::Tls12ClientSessionValue) {
    }

    fn tls12_session(&self, _: &ClientSessionKey<'_>) -> Option<persist::Tls12ClientSessionValue> {
        None
    }

    fn remove_tls12_session(&self, _: &ClientSessionKey<'_>) {}

    fn insert_tls13_ticket(
        &self,
        _: ClientSessionKey<'static>,
        _: persist::Tls13ClientSessionValue,
    ) {
    }

    fn take_tls13_ticket(
        &self,
        _: &ClientSessionKey<'_>,
    ) -> Option<persist::Tls13ClientSessionValue> {
        None
    }
}

#[cfg(any(feature = "std", feature = "hashbrown"))]
mod cache {
    use alloc::collections::VecDeque;
    use core::fmt;

    use super::ClientSessionKey;
    use crate::crypto::kx::NamedGroup;
    use crate::limited_cache;
    use crate::lock::Mutex;
    use crate::msgs::persist;

    const MAX_TLS13_TICKETS_PER_SERVER: usize = 8;

    struct ServerData {
        kx_hint: Option<NamedGroup>,

        // Zero or one TLS1.2 sessions.
        tls12: Option<persist::Tls12ClientSessionValue>,

        // Up to MAX_TLS13_TICKETS_PER_SERVER TLS1.3 tickets, oldest first.
        tls13: VecDeque<persist::Tls13ClientSessionValue>,
    }

    impl Default for ServerData {
        fn default() -> Self {
            Self {
                kx_hint: None,
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
        servers: Mutex<limited_cache::LimitedCache<ClientSessionKey<'static>, ServerData>>,
    }

    impl ClientSessionMemoryCache {
        /// Make a new ClientSessionMemoryCache.  `size` is the
        /// maximum number of stored sessions.
        #[cfg(feature = "std")]
        pub fn new(size: usize) -> Self {
            let max_servers = size.saturating_add(MAX_TLS13_TICKETS_PER_SERVER - 1)
                / MAX_TLS13_TICKETS_PER_SERVER;
            Self {
                servers: Mutex::new(limited_cache::LimitedCache::new(max_servers)),
            }
        }

        /// Make a new ClientSessionMemoryCache.  `size` is the
        /// maximum number of stored sessions.
        #[cfg(not(feature = "std"))]
        pub fn new<M: crate::lock::MakeMutex>(size: usize) -> Self {
            let max_servers = size.saturating_add(MAX_TLS13_TICKETS_PER_SERVER - 1)
                / MAX_TLS13_TICKETS_PER_SERVER;
            Self {
                servers: Mutex::new::<M>(limited_cache::LimitedCache::new(max_servers)),
            }
        }
    }

    impl super::client::ClientSessionStore for ClientSessionMemoryCache {
        fn set_kx_hint(&self, key: ClientSessionKey<'static>, group: NamedGroup) {
            self.servers
                .lock()
                .unwrap()
                .get_or_insert_default_and_edit(key, |data| data.kx_hint = Some(group));
        }

        fn kx_hint(&self, key: &ClientSessionKey<'_>) -> Option<NamedGroup> {
            self.servers
                .lock()
                .unwrap()
                .get(key)
                .and_then(|sd| sd.kx_hint)
        }

        fn set_tls12_session(
            &self,
            key: ClientSessionKey<'static>,
            value: persist::Tls12ClientSessionValue,
        ) {
            self.servers
                .lock()
                .unwrap()
                .get_or_insert_default_and_edit(key.clone(), |data| data.tls12 = Some(value));
        }

        fn tls12_session(
            &self,
            key: &ClientSessionKey<'_>,
        ) -> Option<persist::Tls12ClientSessionValue> {
            self.servers
                .lock()
                .unwrap()
                .get(key)
                .and_then(|sd| sd.tls12.as_ref().cloned())
        }

        fn remove_tls12_session(&self, key: &ClientSessionKey<'static>) {
            self.servers
                .lock()
                .unwrap()
                .get_mut(key)
                .and_then(|data| data.tls12.take());
        }

        fn insert_tls13_ticket(
            &self,
            key: ClientSessionKey<'static>,
            value: persist::Tls13ClientSessionValue,
        ) {
            self.servers
                .lock()
                .unwrap()
                .get_or_insert_default_and_edit(key.clone(), |data| {
                    if data.tls13.len() == data.tls13.capacity() {
                        data.tls13.pop_front();
                    }
                    data.tls13.push_back(value);
                });
        }

        fn take_tls13_ticket(
            &self,
            key: &ClientSessionKey<'static>,
        ) -> Option<persist::Tls13ClientSessionValue> {
            self.servers
                .lock()
                .unwrap()
                .get_mut(key)
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
}

#[cfg(any(feature = "std", feature = "hashbrown"))]
pub use cache::ClientSessionMemoryCache;

#[derive(Debug)]
pub(super) struct FailResolveClientCert {}

impl client::ClientCredentialResolver for FailResolveClientCert {
    fn resolve(&self, _: &CredentialRequest<'_>) -> Option<SelectedCredential> {
        None
    }

    fn supported_certificate_types(&self) -> &'static [CertificateType] {
        &[]
    }

    fn hash_config(&self, _: &mut dyn Hasher) {}
}

#[cfg(test)]
mod tests {
    use core::time::Duration;
    use std::prelude::v1::*;

    use pki_types::{CertificateDer, ServerName, UnixTime};

    use super::NoClientSessionStorage;
    use crate::TEST_PROVIDERS;
    use crate::client::{ClientSessionKey, ClientSessionStore};
    use crate::crypto::kx::NamedGroup;
    use crate::crypto::{CertificateIdentity, CipherSuite, Identity, tls12_suite, tls13_suite};
    use crate::msgs::base::PayloadU16;
    use crate::msgs::handshake::SessionId;
    use crate::msgs::persist::{Tls12ClientSessionValue, Tls13ClientSessionValue};
    use crate::sync::Arc;

    #[test]
    fn test_noclientsessionstorage_does_nothing() {
        let c = NoClientSessionStorage {};
        let server_name = ServerName::try_from("example.com").unwrap();
        let key = ClientSessionKey {
            config_hash: Default::default(),
            server_name,
        };
        let now = UnixTime::now();

        c.set_kx_hint(key.clone(), NamedGroup::X25519);
        assert_eq!(None, c.kx_hint(&key));

        for provider in TEST_PROVIDERS {
            {
                c.set_tls12_session(
                    key.clone(),
                    Tls12ClientSessionValue::new(
                        tls12_suite(CipherSuite::Unknown(0xff12), provider),
                        SessionId::empty(),
                        Arc::new(PayloadU16::empty()),
                        &[0u8; 48],
                        Identity::X509(CertificateIdentity {
                            end_entity: CertificateDer::from(&[][..]),
                            intermediates: Vec::new(),
                        }),
                        now,
                        Duration::ZERO,
                        true,
                    ),
                );
                assert!(c.tls12_session(&key).is_none());
                c.remove_tls12_session(&key);
            }

            c.insert_tls13_ticket(
                key.clone(),
                Tls13ClientSessionValue::new(
                    tls13_suite(CipherSuite::Unknown(0xff13), provider),
                    Arc::new(PayloadU16::empty()),
                    &[],
                    Identity::X509(CertificateIdentity {
                        end_entity: CertificateDer::from(&[][..]),
                        intermediates: Vec::new(),
                    }),
                    now,
                    Duration::ZERO,
                    0,
                    0,
                ),
            );

            assert!(c.take_tls13_ticket(&key).is_none());
        }
    }
}
