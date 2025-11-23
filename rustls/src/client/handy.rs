use pki_types::ServerName;

use super::CredentialRequest;
use crate::client;
use crate::crypto::SelectedCredential;
use crate::crypto::kx::NamedGroup;
use crate::enums::CertificateType;
use crate::msgs::persist;

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

#[cfg(any(feature = "std", feature = "hashbrown"))]
mod cache {
    use alloc::collections::VecDeque;
    use core::fmt;

    use pki_types::ServerName;

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
        servers: Mutex<limited_cache::LimitedCache<ServerName<'static>, ServerData>>,
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
            server_name: ServerName<'static>,
            value: persist::Tls12ClientSessionValue,
        ) {
            self.servers
                .lock()
                .unwrap()
                .get_or_insert_default_and_edit(server_name.clone(), |data| {
                    data.tls12 = Some(value)
                });
        }

        fn tls12_session(
            &self,
            server_name: &ServerName<'_>,
        ) -> Option<persist::Tls12ClientSessionValue> {
            self.servers
                .lock()
                .unwrap()
                .get(server_name)
                .and_then(|sd| sd.tls12.as_ref().cloned())
        }

        fn remove_tls12_session(&self, server_name: &ServerName<'static>) {
            self.servers
                .lock()
                .unwrap()
                .get_mut(server_name)
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
}

#[cfg(test)]
mod tests {
    use core::time::Duration;
    use std::prelude::v1::*;

    use pki_types::{CertificateDer, ServerName, UnixTime};

    use super::NoClientSessionStorage;
    use crate::TEST_PROVIDERS;
    use crate::client::danger::{HandshakeSignatureValid, PeerVerified, ServerVerifier};
    use crate::client::{ClientCredentialResolver, ClientSessionStore, CredentialRequest};
    use crate::crypto::kx::NamedGroup;
    use crate::crypto::{
        CertificateIdentity, CipherSuite, Identity, SelectedCredential, SignatureScheme,
        tls12_suite, tls13_suite,
    };
    use crate::enums::CertificateType;
    use crate::error::Error;
    use crate::msgs::base::PayloadU16;
    use crate::msgs::handshake::SessionId;
    use crate::msgs::persist::{Tls12ClientSessionValue, Tls13ClientSessionValue};
    use crate::sync::Arc;
    use crate::verify::{ServerIdentity, SignatureVerificationInput};

    #[test]
    fn test_noclientsessionstorage_does_nothing() {
        let c = NoClientSessionStorage {};
        let name = ServerName::try_from("example.com").unwrap();
        let now = UnixTime::now();
        let server_cert_verifier: Arc<dyn ServerVerifier> = Arc::new(DummyServerVerifier);
        let resolves_client_cert: Arc<dyn ClientCredentialResolver> =
            Arc::new(DummyClientCredentialResolver);

        c.set_kx_hint(name.clone(), NamedGroup::X25519);
        assert_eq!(None, c.kx_hint(&name));

        for provider in TEST_PROVIDERS {
            {
                c.set_tls12_session(
                    name.clone(),
                    Tls12ClientSessionValue::new(
                        tls12_suite(
                            CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
                            provider,
                        ),
                        SessionId::empty(),
                        Arc::new(PayloadU16::empty()),
                        &[0u8; 48],
                        Identity::X509(CertificateIdentity {
                            end_entity: CertificateDer::from(&[][..]),
                            intermediates: Vec::new(),
                        }),
                        &server_cert_verifier,
                        &resolves_client_cert,
                        now,
                        Duration::ZERO,
                        true,
                    ),
                );
                assert!(c.tls12_session(&name).is_none());
                c.remove_tls12_session(&name);
            }

            c.insert_tls13_ticket(
                name.clone(),
                Tls13ClientSessionValue::new(
                    tls13_suite(CipherSuite::TLS13_AES_256_GCM_SHA384, provider),
                    Arc::new(PayloadU16::empty()),
                    &[],
                    Identity::X509(CertificateIdentity {
                        end_entity: CertificateDer::from(&[][..]),
                        intermediates: Vec::new(),
                    }),
                    &server_cert_verifier,
                    &resolves_client_cert,
                    now,
                    Duration::ZERO,
                    0,
                    0,
                ),
            );

            assert!(c.take_tls13_ticket(&name).is_none());
        }
    }

    #[derive(Debug)]
    struct DummyServerVerifier;

    impl ServerVerifier for DummyServerVerifier {
        #[cfg_attr(coverage_nightly, coverage(off))]
        fn verify_identity(&self, _identity: &ServerIdentity<'_>) -> Result<PeerVerified, Error> {
            unreachable!()
        }

        #[cfg_attr(coverage_nightly, coverage(off))]
        fn verify_tls12_signature(
            &self,
            _input: &SignatureVerificationInput<'_>,
        ) -> Result<HandshakeSignatureValid, Error> {
            unreachable!()
        }

        #[cfg_attr(coverage_nightly, coverage(off))]
        fn verify_tls13_signature(
            &self,
            _input: &SignatureVerificationInput<'_>,
        ) -> Result<HandshakeSignatureValid, Error> {
            unreachable!()
        }

        #[cfg_attr(coverage_nightly, coverage(off))]
        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            unreachable!()
        }

        #[cfg_attr(coverage_nightly, coverage(off))]
        fn request_ocsp_response(&self) -> bool {
            unreachable!()
        }
    }

    #[derive(Debug)]
    struct DummyClientCredentialResolver;

    impl ClientCredentialResolver for DummyClientCredentialResolver {
        #[cfg_attr(coverage_nightly, coverage(off))]
        fn resolve(&self, _: &CredentialRequest<'_>) -> Option<SelectedCredential> {
            unreachable!()
        }

        #[cfg_attr(coverage_nightly, coverage(off))]
        fn supported_certificate_types(&self) -> &'static [CertificateType] {
            unreachable!()
        }
    }
}
