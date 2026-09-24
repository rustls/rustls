use alloc::vec::Vec;
use core::fmt;
use core::ops::Deref;
use core::time::Duration;

use pki_types::UnixTime;
use zeroize::Zeroizing;

use crate::crypto::cipher::Payload;
use crate::crypto::{CipherSuite, CryptoProvider, Identity, SelectedCredential, SignatureScheme};
use crate::enums::{ApplicationProtocol, CertificateType};
use crate::error::{ApiMisuse, Error, InvalidMessage};
use crate::msgs::{
    CertificateChain, Codec, ExtensionType, MaybeEmpty, NewSessionTicketPayloadTls13, Reader,
    SessionId, SizedPayload,
};
use crate::sync::Arc;
use crate::tls13::Tls13ProtocolSuite;
use crate::tracing::{debug, trace};
use crate::verify::{DistinguishedName, VerifiedIdentity};
#[cfg(feature = "webpki")]
pub use crate::webpki::{
    ServerVerifierBuilder, VerifierBuilderError, WebPkiServerVerifier,
    verify_identity_signed_by_trust_anchor, verify_server_name,
};
use crate::{Tls12CipherSuite, compress};

mod config;
pub use config::{
    ClientConfig, ClientCredentialResolver, ClientSessionKey, ClientSessionStore,
    CredentialRequest, Resumption, TicketRequest, Tls12Resumption, WantsClientCert,
};

mod connection;
pub use connection::{
    ClientConnection, ClientConnectionBuilder, ClientHandshake, ClientSide, WriteEarlyData,
};

mod ech;
pub use ech::{EchConfig, EchGreaseConfig, EchMode, EchStatus};

mod handy;
pub use handy::ClientSessionMemoryCache;

mod hs;
pub(crate) use hs::{ClientHandler, ClientState};

mod tls12;
pub(crate) use tls12::TLS12_HANDLER;

mod tls13;
pub(crate) use tls13::TLS13_HANDLER;

/// Dangerous configuration that should be audited and used with extreme care.
pub mod danger {
    pub use super::config::danger::{DangerousClientConfig, DangerousClientConfigBuilder};
    pub use crate::verify::{
        HandshakeSignatureValid, ServerIdentity, ServerVerifier, SignatureVerificationInput,
    };
}

#[cfg(test)]
mod test;

pub(crate) struct Retrieved<T> {
    pub(crate) value: T,
    retrieved_at: UnixTime,
}

impl<T> Retrieved<T> {
    pub(crate) fn new(value: T, retrieved_at: UnixTime) -> Self {
        Self {
            value,
            retrieved_at,
        }
    }

    pub(crate) fn map<M>(&self, f: impl FnOnce(&T) -> Option<&M>) -> Option<Retrieved<&M>> {
        Some(Retrieved {
            value: f(&self.value)?,
            retrieved_at: self.retrieved_at,
        })
    }
}

impl Retrieved<&Tls13Session> {
    pub(crate) fn obfuscated_ticket_age(&self) -> u32 {
        let age_secs = self
            .retrieved_at
            .as_secs()
            .saturating_sub(self.value.common.epoch);
        // nb. tickets have an upper age limit of ~7 days, well short of the 49 days here
        let age_millis = u32::try_from(age_secs)
            .unwrap_or(u32::MAX)
            .saturating_mul(1000);
        age_millis.wrapping_add(self.value.age_add)
    }
}

impl<T: Deref<Target = ClientSessionCommon>> Retrieved<T> {
    pub(crate) fn has_expired(&self) -> bool {
        let common = &*self.value;
        common.lifetime != Duration::ZERO
            && common
                .epoch
                .saturating_add(common.lifetime.as_secs())
                < self.retrieved_at.as_secs()
    }
}

impl<T> Deref for Retrieved<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.value
    }
}

/// A stored TLS 1.3 client session value.
pub struct Tls13Session {
    suite: Tls13ProtocolSuite,
    secret: Zeroizing<SizedPayload<'static, u8>>,
    pub(crate) age_add: u32,
    max_early_data_size: u32,
    pub(crate) common: ClientSessionCommon,
    quic_params: SizedPayload<'static, u16, MaybeEmpty>,
}

impl Tls13Session {
    /// Decode a ticket from the given bytes.
    #[cfg(test)]
    pub fn from_slice(bytes: &[u8], provider: &CryptoProvider) -> Result<Self, Error> {
        Reader::new(bytes).all("Tls13Session", |reader| {
            let suite = CipherSuite::read(reader)?;
            let suite = provider
                .tls13_cipher_suites
                .iter()
                .find(|s| s.common.suite == suite)
                .ok_or(ApiMisuse::ResumingFromUnknownCipherSuite(suite))?;

            Ok(Self {
                suite: Tls13ProtocolSuite::Tcp(suite),
                secret: Zeroizing::new(SizedPayload::<u8>::read(reader)?.into_owned()),
                age_add: u32::read(reader)?,
                max_early_data_size: u32::read(reader)?,
                common: ClientSessionCommon::read(reader)?,
                quic_params: SizedPayload::<u16, MaybeEmpty>::read(reader)?.into_owned(),
            })
        })
    }

    pub(crate) fn new(
        ticket: &NewSessionTicketPayloadTls13,
        input: Tls13ClientSessionInput,
        secret: &[u8],
        time_now: UnixTime,
    ) -> Self {
        Self {
            suite: input.suite,
            secret: Zeroizing::new(secret.to_vec().into()),
            age_add: ticket.age_add,
            max_early_data_size: ticket
                .extensions
                .max_early_data_size
                .unwrap_or_default(),
            common: ClientSessionCommon::new(
                ticket.ticket.clone(),
                time_now,
                ticket.lifetime,
                input.peer_identity,
            ),
            quic_params: input
                .quic_params
                .unwrap_or_else(|| SizedPayload::from(Payload::new(Vec::new()))),
        }
    }

    /// Encode this ticket into `buf` for persistence.
    pub fn encode(&self, buf: &mut Vec<u8>) {
        self.suite
            .suite()
            .common
            .suite
            .encode(buf);
        self.secret.encode(buf);
        buf.extend_from_slice(&self.age_add.to_be_bytes());
        buf.extend_from_slice(&self.max_early_data_size.to_be_bytes());
        self.common.encode(buf);
        self.quic_params.encode(buf);
    }

    /// Test only: CAS `max_early_data_size` from `expected` to `desired`
    #[doc(hidden)]
    pub fn _reset_max_early_data_size(&mut self, expected: u32, desired: u32) {
        assert_eq!(
            self.max_early_data_size, expected,
            "max_early_data_size was not expected value"
        );
        self.max_early_data_size = desired;
    }

    /// Test only: rewind epoch by `delta` seconds.
    #[doc(hidden)]
    pub fn rewind_epoch(&mut self, delta: u32) {
        self.common.epoch -= delta as u64;
    }
}

impl Deref for Tls13Session {
    type Target = ClientSessionCommon;

    fn deref(&self) -> &Self::Target {
        &self.common
    }
}

impl fmt::Debug for Tls13Session {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self {
            suite,
            secret: _,
            age_add,
            max_early_data_size,
            common,
            quic_params,
        } = self;
        f.debug_struct("Tls13Session")
            .field("suite", suite)
            .field("age_add", age_add)
            .field("max_early_data_size", max_early_data_size)
            .field("common", common)
            .field("quic_params", quic_params)
            .finish_non_exhaustive()
    }
}

/// A "template" for future TLS1.3 client session values.
#[derive(Clone)]
pub(crate) struct Tls13ClientSessionInput {
    pub(crate) suite: Tls13ProtocolSuite,
    pub(crate) peer_identity: VerifiedIdentity<'static>,
    pub(crate) quic_params: Option<SizedPayload<'static, u16, MaybeEmpty>>,
}

/// A stored TLS 1.2 client session value.
#[derive(Clone)]
pub struct Tls12Session {
    suite: &'static Tls12CipherSuite,
    pub(crate) session_id: SessionId,
    master_secret: Zeroizing<[u8; 48]>,
    extended_ms: bool,
    #[doc(hidden)]
    pub(crate) common: ClientSessionCommon,
}

impl Tls12Session {
    /// Decode a ticket from the given bytes.
    pub fn from_slice(bytes: &[u8], provider: &CryptoProvider) -> Result<Self, Error> {
        Reader::new(bytes).all("Tls12Session", |reader| {
            let suite = CipherSuite::read(reader)?;
            let suite = provider
                .tls12_cipher_suites
                .iter()
                .find(|s| s.common.suite == suite)
                .ok_or(ApiMisuse::ResumingFromUnknownCipherSuite(suite))?;

            Ok(Self {
                suite: *suite,
                session_id: SessionId::read(reader)?,
                master_secret: Zeroizing::new(
                    reader
                        .take_array("MasterSecret")
                        .copied()?,
                ),
                extended_ms: matches!(u8::read(reader)?, 1),
                common: ClientSessionCommon::read(reader)?,
            })
        })
    }

    pub(crate) fn new(
        suite: &'static Tls12CipherSuite,
        session_id: SessionId,
        ticket: Arc<SizedPayload<'static, u16, MaybeEmpty>>,
        master_secret: &[u8; 48],
        peer_identity: VerifiedIdentity<'static>,
        time_now: UnixTime,
        lifetime: Duration,
        extended_ms: bool,
    ) -> Self {
        Self {
            suite,
            session_id,
            master_secret: Zeroizing::new(*master_secret),
            extended_ms,
            common: ClientSessionCommon::new(ticket, time_now, lifetime, peer_identity),
        }
    }

    /// Encode this ticket into `buf` for persistence.
    pub fn encode(&self, buf: &mut Vec<u8>) {
        self.suite.common.suite.encode(buf);
        self.session_id.encode(buf);
        buf.extend_from_slice(&*self.master_secret);
        buf.push(self.extended_ms as u8);
        self.common.encode(buf);
    }

    /// Test only: rewind epoch by `delta` seconds.
    #[doc(hidden)]
    pub fn rewind_epoch(&mut self, delta: u32) {
        self.common.epoch -= delta as u64;
    }
}

impl Deref for Tls12Session {
    type Target = ClientSessionCommon;

    fn deref(&self) -> &Self::Target {
        &self.common
    }
}

impl fmt::Debug for Tls12Session {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self {
            suite,
            session_id,
            master_secret: _,
            extended_ms,
            common,
        } = self;
        f.debug_struct("Tls12Session")
            .field("suite", suite)
            .field("session_id", session_id)
            .field("extended_ms", extended_ms)
            .field("common", common)
            .finish_non_exhaustive()
    }
}

/// Common data for stored client sessions.
#[derive(Debug, Clone)]
pub struct ClientSessionCommon {
    pub(crate) ticket: Arc<SizedPayload<'static, u16>>,
    pub(crate) epoch: u64,
    lifetime: Duration,
    peer_identity: Arc<VerifiedIdentity<'static>>,
}

impl ClientSessionCommon {
    pub(crate) fn new(
        ticket: Arc<SizedPayload<'static, u16>>,
        time_now: UnixTime,
        lifetime: Duration,
        peer_identity: VerifiedIdentity<'static>,
    ) -> Self {
        Self {
            ticket,
            epoch: time_now.as_secs(),
            lifetime: Ord::min(lifetime, MAX_TICKET_LIFETIME),
            peer_identity: Arc::new(peer_identity),
        }
    }

    pub(crate) fn peer_identity(&self) -> &Identity<'static> {
        &self.peer_identity
    }

    pub(crate) fn ticket(&self) -> &[u8] {
        (*self.ticket).bytes()
    }
}

impl<'a> Codec<'a> for ClientSessionCommon {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.ticket.encode(bytes);
        bytes.extend_from_slice(&self.epoch.to_be_bytes());
        bytes.extend_from_slice(&self.lifetime.as_secs().to_be_bytes());
        self.peer_identity.encode(bytes);
    }

    fn read(r: &mut Reader<'a>) -> Result<Self, InvalidMessage> {
        Ok(Self {
            ticket: Arc::new(SizedPayload::read(r)?.into_owned()),
            epoch: u64::read(r)?,
            lifetime: Duration::from_secs(u64::read(r)?),
            peer_identity: Arc::new(VerifiedIdentity::assertion(Identity::read(r)?.into_owned())),
        })
    }
}

#[derive(Debug)]
struct ServerCertDetails {
    cert_chain: CertificateChain<'static>,
    ocsp_response: Vec<u8>,
}

impl ServerCertDetails {
    fn new(cert_chain: CertificateChain<'static>, ocsp_response: Vec<u8>) -> Self {
        Self {
            cert_chain,
            ocsp_response,
        }
    }
}

struct ClientHelloDetails {
    alpn_protocols: Vec<ApplicationProtocol<'static>>,
    sent_extensions: Vec<ExtensionType>,
    extension_order_seed: u16,
    offered_cert_compression: bool,
    offered_cipher_suites: Vec<CipherSuite>,
}

impl ClientHelloDetails {
    fn new(alpn_protocols: Vec<ApplicationProtocol<'static>>, extension_order_seed: u16) -> Self {
        Self {
            alpn_protocols,
            sent_extensions: Vec::new(),
            extension_order_seed,
            offered_cert_compression: false,
            offered_cipher_suites: Vec::new(),
        }
    }

    fn server_sent_unsolicited_extensions(
        &self,
        received_exts: impl Iterator<Item = ExtensionType>,
        allowed_unsolicited: &[ExtensionType],
    ) -> bool {
        for ext_type in received_exts {
            if !self.sent_extensions.contains(&ext_type) && !allowed_unsolicited.contains(&ext_type)
            {
                trace!("Unsolicited extension {ext_type:?}");
                return true;
            }
        }

        false
    }
}

enum ClientAuthDetails {
    /// Send an empty `Certificate` and no `CertificateVerify`.
    Empty { auth_context_tls13: Option<Vec<u8>> },
    /// Send a non-empty `Certificate` and a `CertificateVerify`.
    Verify {
        credentials: SelectedCredential,
        auth_context_tls13: Option<Vec<u8>>,
        compressor: Option<&'static dyn compress::CertCompressor>,
    },
}

impl ClientAuthDetails {
    fn resolve(
        negotiated_type: CertificateType,
        resolver: &dyn ClientCredentialResolver,
        root_hint_subjects: Option<&[DistinguishedName]>,
        signature_schemes: &[SignatureScheme],
        auth_context_tls13: Option<Vec<u8>>,
        compressor: Option<&'static dyn compress::CertCompressor>,
    ) -> Self {
        let server_hello = CredentialRequest {
            negotiated_type,
            root_hint_subjects: root_hint_subjects.unwrap_or_default(),
            signature_schemes,
        };

        if let Some(credentials) = resolver.resolve(&server_hello) {
            debug!("Attempting client auth");
            return Self::Verify {
                credentials,
                auth_context_tls13,
                compressor,
            };
        }

        debug!("Client auth requested but no cert/sigscheme available");
        Self::Empty { auth_context_tls13 }
    }
}

static MAX_TICKET_LIFETIME: Duration = Duration::from_secs(7 * 24 * 60 * 60);

#[cfg(test)]
mod tests {
    use alloc::format;

    use pki_types::SubjectPublicKeyInfoDer;

    use super::*;
    use crate::crypto::{TEST_PROVIDER, tls12_suite};

    #[test]
    fn debug_of_session_types() {
        let tls12 = Tls12Session::new(
            tls12_suite(CipherSuite(0xff12), &TEST_PROVIDER),
            SessionId::empty(),
            Arc::new(SizedPayload::empty()),
            &[0xa5; 48],
            VerifiedIdentity::assertion(Identity::RawPublicKey(SubjectPublicKeyInfoDer::from(
                &b"spki"[..],
            ))),
            UnixTime::since_unix_epoch(Duration::from_secs(1)),
            Duration::from_secs(2),
            true,
        );
        assert_eq!(
            format!("{tls12:?}"),
            "Tls12Session { suite: Tls12CipherSuite { suite: 0xff12, .. }, session_id: , extended_ms: true, common: ClientSessionCommon { ticket: , epoch: 1, lifetime: 2s, peer_identity: VerifiedIdentity(RawPublicKey(SubjectPublicKeyInfoDer(0x73706b69))) }, .. }"
        );

        let tls13 = Tls13Session::new(
            &NewSessionTicketPayloadTls13::new(
                Duration::from_secs(2),
                3,
                [4u8; 32],
                Vec::from([5]),
            ),
            Tls13ClientSessionInput {
                suite: Tls13ProtocolSuite::Tcp(TEST_PROVIDER.tls13_cipher_suites[0]),
                peer_identity: VerifiedIdentity::assertion(Identity::RawPublicKey(
                    SubjectPublicKeyInfoDer::from(&b"spki"[..]),
                )),
                quic_params: None,
            },
            &[0xa5; 32],
            UnixTime::since_unix_epoch(Duration::from_secs(1)),
        );
        assert_eq!(
            format!("{tls13:?}"),
            "Tls13Session { suite: Tcp(Tls13CipherSuite { suite: 0xff13, .. }), age_add: 3, max_early_data_size: 0, common: ClientSessionCommon { ticket: 05, epoch: 1, lifetime: 2s, peer_identity: VerifiedIdentity(RawPublicKey(SubjectPublicKeyInfoDer(0x73706b69))) }, quic_params: , .. }"
        );
    }
}
