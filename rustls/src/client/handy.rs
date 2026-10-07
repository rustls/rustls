use core::hash::Hasher;

use super::config::{ClientCredentialResolver, ClientSessionStore};
use super::{ClientSessionKey, CredentialRequest, Tls12Session, Tls13Session};
use crate::crypto::SelectedCredential;
use crate::crypto::kx::NamedGroup;
use crate::enums::CertificateType;

/// An implementer of [`ClientSessionStore`] which does nothing.
#[derive(Debug)]
pub(super) struct NoClientSessionStorage;

impl ClientSessionStore for NoClientSessionStorage {
    fn set_kx_hint(&self, _: ClientSessionKey<'static>, _: NamedGroup) {}

    fn kx_hint(&self, _: &ClientSessionKey<'_>) -> Option<NamedGroup> {
        None
    }

    fn set_tls12_session(&self, _: ClientSessionKey<'static>, _: Tls12Session) {}

    fn tls12_session(&self, _: &ClientSessionKey<'_>) -> Option<Tls12Session> {
        None
    }

    fn remove_tls12_session(&self, _: &ClientSessionKey<'_>) {}

    fn insert_tls13_ticket(&self, _: ClientSessionKey<'static>, _: Tls13Session) {}

    fn take_tls13_ticket(&self, _: &ClientSessionKey<'_>) -> Option<Tls13Session> {
        None
    }
}

mod cache {
    use alloc::collections::VecDeque;
    use core::fmt;

    use super::*;
    use crate::client::Tls13Session;
    use crate::crypto::kx::NamedGroup;
    use crate::limited_cache;
    use crate::lock::Mutex;

    const MAX_TLS13_TICKETS_PER_SERVER: usize = 8;

    struct ServerData {
        kx_hint: Option<NamedGroup>,

        // Zero or one TLS1.2 sessions.
        tls12: Option<Tls12Session>,

        // Up to MAX_TLS13_TICKETS_PER_SERVER TLS1.3 tickets, oldest first.
        tls13: VecDeque<Tls13Session>,
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
        /// Make a new `ClientSessionMemoryCache`.
        ///
        /// `size` determines the maximum number of servers to remember:
        /// `size` divided by `MAX_TLS13_TICKETS_PER_SERVER` (8), rounded
        /// up. Each server keeps up to 8 TLS 1.3 tickets. When the maximum
        /// is reached, the server that was added first is evicted.
        ///
        /// For example, `new(100)` remembers up to 13 servers. Any `size`
        /// from 1 to 8 remembers one server, and a `size` of 0 remembers
        /// none.
        pub fn new(size: usize) -> Self {
            // Round up so that any non-zero size holds at least one server.
            let max_servers = size.saturating_add(MAX_TLS13_TICKETS_PER_SERVER - 1)
                / MAX_TLS13_TICKETS_PER_SERVER;
            Self {
                servers: Mutex::new(limited_cache::LimitedCache::new(max_servers)),
            }
        }
    }

    impl ClientSessionStore for ClientSessionMemoryCache {
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

        fn set_tls12_session(&self, key: ClientSessionKey<'static>, value: Tls12Session) {
            self.servers
                .lock()
                .unwrap()
                .get_or_insert_default_and_edit(key, |data| data.tls12 = Some(value));
        }

        fn tls12_session(&self, key: &ClientSessionKey<'_>) -> Option<Tls12Session> {
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

        fn insert_tls13_ticket(&self, key: ClientSessionKey<'static>, value: Tls13Session) {
            self.servers
                .lock()
                .unwrap()
                .get_or_insert_default_and_edit(key, |data| {
                    if data.tls13.len() == data.tls13.capacity() {
                        data.tls13.pop_front();
                    }
                    data.tls13.push_back(value);
                });
        }

        fn take_tls13_ticket(&self, key: &ClientSessionKey<'static>) -> Option<Tls13Session> {
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
                .finish_non_exhaustive()
        }
    }
}

pub use cache::ClientSessionMemoryCache;

#[derive(Debug)]
pub(super) struct FailResolveClientCert {}

impl ClientCredentialResolver for FailResolveClientCert {
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
    use alloc::vec::Vec;
    use core::time::Duration;

    use pki_types::{CertificateDer, ServerName, UnixTime};

    use super::{ClientSessionMemoryCache, NoClientSessionStorage};
    use crate::client::{
        ClientSessionKey, ClientSessionStore, Tls12Session, Tls13ClientSessionInput, Tls13Session,
    };
    use crate::crypto::kx::NamedGroup;
    use crate::crypto::{
        CertificateIdentity, CipherSuite, Identity, TEST_PROVIDER, tls12_suite, tls13_suite,
    };
    use crate::msgs::{
        NewSessionTicketExtensions, NewSessionTicketPayloadTls13, SessionId, SizedPayload,
    };
    use crate::sync::Arc;
    use crate::tls13::Tls13ProtocolSuite;
    use crate::verify::VerifiedIdentity;

    #[test]
    fn test_noclientsessionstorage_does_nothing() {
        let c = NoClientSessionStorage {};
        let key = session_key("example.com");
        let now = UnixTime::now();

        c.set_kx_hint(key.clone(), NamedGroup::X25519);
        assert_eq!(None, c.kx_hint(&key));

        {
            c.set_tls12_session(
                key.clone(),
                Tls12Session::new(
                    tls12_suite(CipherSuite(0xff12), &TEST_PROVIDER),
                    SessionId::empty(),
                    Arc::new(SizedPayload::empty()),
                    &[0u8; 48],
                    VerifiedIdentity::assertion(Identity::X509(CertificateIdentity {
                        end_entity: CertificateDer::from(&[][..]),
                        intermediates: Vec::new(),
                    })),
                    now,
                    Duration::ZERO,
                    true,
                ),
            );
            assert!(c.tls12_session(&key).is_none());
            c.remove_tls12_session(&key);
        }

        c.insert_tls13_ticket(key.clone(), tls13_session(now));
        assert!(c.take_tls13_ticket(&key).is_none());
    }

    /// For each `size` from 1 to 8, the cache keeps one server's key
    /// exchange hint and TLS 1.3 ticket.
    #[test]
    fn test_clientsessionmemorycache_small_sizes_retain_server() {
        for size in 1..=8 {
            let c = ClientSessionMemoryCache::new(size);
            let key = session_key("example.com");

            c.set_kx_hint(key.clone(), NamedGroup::X25519);
            assert_eq!(c.kx_hint(&key), Some(NamedGroup::X25519), "size {size}");

            c.insert_tls13_ticket(key.clone(), tls13_session(UnixTime::now()));
            assert!(c.take_tls13_ticket(&key).is_some(), "size {size}");
        }
    }

    /// A cache of size 9 remembers two servers: after three servers are
    /// added, the first is evicted and the other two remain.
    #[test]
    fn test_clientsessionmemorycache_evicts_oldest_server() {
        let c = ClientSessionMemoryCache::new(9);
        let first = session_key("first.example.com");
        let second = session_key("second.example.com");
        let third = session_key("third.example.com");

        c.set_kx_hint(first.clone(), NamedGroup::X25519);
        c.set_kx_hint(second.clone(), NamedGroup::X25519);
        c.set_kx_hint(third.clone(), NamedGroup::X25519);

        assert_eq!(c.kx_hint(&first), None);
        assert_eq!(c.kx_hint(&second), Some(NamedGroup::X25519));
        assert_eq!(c.kx_hint(&third), Some(NamedGroup::X25519));
    }

    /// Test helper: builds a cache key for `name` with a fixed (all-zero)
    /// config hash, so keys differ only by server name.
    fn session_key(name: &'static str) -> ClientSessionKey<'static> {
        ClientSessionKey {
            config_hash: Default::default(),
            server_name: ServerName::try_from(name).unwrap(),
        }
    }

    /// Test helper: builds a placeholder TLS 1.3 ticket. Its contents are
    /// empty or dummy values; the tests only check whether the cache
    /// keeps it.
    fn tls13_session(now: UnixTime) -> Tls13Session {
        Tls13Session::new(
            &NewSessionTicketPayloadTls13 {
                lifetime: Duration::ZERO,
                age_add: 0,
                nonce: SizedPayload::empty(),
                ticket: Arc::new(SizedPayload::empty()),
                extensions: NewSessionTicketExtensions {
                    max_early_data_size: None,
                },
            },
            Tls13ClientSessionInput {
                suite: Tls13ProtocolSuite::Tcp(tls13_suite(CipherSuite(0xff13), &TEST_PROVIDER)),
                peer_identity: VerifiedIdentity::assertion(Identity::X509(CertificateIdentity {
                    end_entity: CertificateDer::from(&[][..]),
                    intermediates: Vec::new(),
                })),
                quic_params: None,
            },
            &[],
            now,
        )
    }
}
