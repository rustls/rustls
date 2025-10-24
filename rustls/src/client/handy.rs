use core::hash::Hash;

use super::{ClientSessionKey, CredentialRequest};
use crate::crypto::{Credentials, SelectedCredential};
use crate::enums::CertificateType;
use crate::msgs::persist;
use crate::{NamedGroup, client};

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
    use crate::lock::Mutex;
    use crate::msgs::persist;
    use crate::{NamedGroup, limited_cache};

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

    fn hash_config(&self, _: &mut dyn core::hash::Hasher) {}
}

/// An exemplar `ClientCredentialResolver` implementation that always resolves to a single
/// [RFC 7250] raw public key.
///
/// [RFC 7250]: https://tools.ietf.org/html/rfc7250
#[derive(Debug)]
pub struct AlwaysResolvesClientRawPublicKeys(Credentials);

impl AlwaysResolvesClientRawPublicKeys {
    /// Create a new `AlwaysResolvesClientRawPublicKeys` instance.
    pub fn new(credentials: Credentials) -> Self {
        Self(credentials)
    }
}

impl client::ClientCredentialResolver for AlwaysResolvesClientRawPublicKeys {
    fn resolve(&self, request: &CredentialRequest<'_>) -> Option<SelectedCredential> {
        match request.negotiated_type() {
            CertificateType::RawPublicKey => self
                .0
                .signer(request.signature_schemes()),
            _ => None,
        }
    }

    fn supported_certificate_types(&self) -> &'static [CertificateType] {
        &[CertificateType::RawPublicKey]
    }

    fn hash_config(&self, h: &mut dyn core::hash::Hasher) {
        self.0
            .hash(&mut crate::core_hash_polyfill::DynHasher(h));
    }
}

#[cfg(test)]
#[macro_rules_attribute::apply(test_for_each_provider)]
mod tests {
    use std::prelude::v1::*;

    use pki_types::{CertificateDer, ServerName, UnixTime};

    use super::NoClientSessionStorage;
    use super::provider::cipher_suite;
    use crate::client::{ClientSessionKey, ClientSessionStore};
    use crate::crypto::{CertificateIdentity, Identity};
    use crate::msgs::base::PayloadU16;
    use crate::msgs::enums::NamedGroup;
    use crate::msgs::handshake::SessionId;
    use crate::msgs::persist::Tls13ClientSessionValue;
    use crate::sync::Arc;

    #[test]
    fn test_noclientsessionstorage_does_nothing() {
        let c = NoClientSessionStorage {};
        let server_name = ServerName::try_from("example.com").unwrap();
        let key = ClientSessionKey {
            partition: Default::default(),
            server_name,
        };
        let now = UnixTime::now();

        c.set_kx_hint(key.clone(), NamedGroup::X25519);
        assert_eq!(None, c.kx_hint(&key));

        {
            use crate::msgs::persist::Tls12ClientSessionValue;

            c.set_tls12_session(
                key.clone(),
                Tls12ClientSessionValue::new(
                    cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
                    SessionId::empty(),
                    Arc::new(PayloadU16::empty()),
                    &[0u8; 48],
                    Identity::X509(CertificateIdentity {
                        end_entity: CertificateDer::from(&[][..]),
                        intermediates: Vec::new(),
                    }),
                    now,
                    0,
                    true,
                ),
            );
            assert!(c.tls12_session(&key).is_none());
            c.remove_tls12_session(&key);
        }

        c.insert_tls13_ticket(
            key.clone(),
            Tls13ClientSessionValue::new(
                cipher_suite::TLS13_AES_256_GCM_SHA384,
                Arc::new(PayloadU16::empty()),
                &[],
                Identity::X509(CertificateIdentity {
                    end_entity: CertificateDer::from(&[][..]),
                    intermediates: Vec::new(),
                }),
                now,
                0,
                0,
                0,
            ),
        );
        assert!(c.take_tls13_ticket(&key).is_none());
    }
}
