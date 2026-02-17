use alloc::vec::Vec;
use core::ops::Deref;
use core::time::Duration;

use pki_types::UnixTime;
use zeroize::Zeroizing;

use crate::crypto::cipher::Payload;
use crate::crypto::{CipherSuite, CryptoProvider, Identity, SelectedCredential, SignatureScheme};
use crate::enums::{ApplicationProtocol, CertificateType};
use crate::error::{ApiMisuse, Error, InvalidMessage};
use crate::log::{debug, trace};
use crate::msgs::{
    CertificateChain, Codec, ExtensionType, MaybeEmpty, Reader, ServerExtensions, SessionId,
    SizedPayload,
};
use crate::sync::Arc;
use crate::verify::DistinguishedName;
#[cfg(feature = "webpki")]
pub use crate::webpki::{
    ServerVerifierBuilder, VerifierBuilderError, WebPkiServerVerifier,
    verify_identity_signed_by_trust_anchor, verify_server_name,
};
use crate::{Tls12CipherSuite, Tls13CipherSuite, compress};

mod config;
pub use config::{
    ClientConfig, ClientCredentialResolver, ClientSessionKey, ClientSessionStore,
    CredentialRequest, Resumption, Tls12Resumption, WantsClientCert,
};

mod connection;
pub use connection::{
    ClientConnection, ClientConnectionBuilder, ClientSide, EarlyDataError, WriteEarlyData,
};

mod ech;
pub use ech::{EchConfig, EchGreaseConfig, EchMode, EchStatus};

mod handy;
pub use handy::ClientSessionMemoryCache;

mod hs;
pub(crate) use hs::ClientHandler;

mod tls12;
pub(crate) use tls12::TLS12_HANDLER;

mod tls13;
pub(crate) use tls13::TLS13_HANDLER;

mod state;
pub use state::{AwaitServerFlight, ClientState, ClientTraffic, SendClientFlight, SendEarlyData};

/// Dangerous configuration that should be audited and used with extreme care.
pub mod danger {
    pub use super::config::danger::{DangerousClientConfig, DangerousClientConfigBuilder};
    pub use crate::verify::{
        HandshakeSignatureValid, PeerVerified, ServerIdentity, ServerVerifier,
        SignatureVerificationInput,
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
        let age_millis = age_secs as u32 * 1000;
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
#[derive(Debug)]
pub struct Tls13Session {
    suite: &'static Tls13CipherSuite,
    secret: Zeroizing<SizedPayload<'static, u8>>,
    pub(crate) age_add: u32,
    max_early_data_size: u32,
    pub(crate) common: ClientSessionCommon,
    quic_params: SizedPayload<'static, u16, MaybeEmpty>,
}

impl Tls13Session {
    /// Decode a ticket from the given bytes.
    pub fn from_slice(bytes: &[u8], provider: &CryptoProvider) -> Result<Self, Error> {
        let mut reader = Reader::new(bytes);
        let suite = CipherSuite::read(&mut reader)?;
        let suite = provider
            .tls13_cipher_suites
            .iter()
            .find(|s| s.common.suite == suite)
            .ok_or(ApiMisuse::ResumingFromUnknownCipherSuite(suite))?;

        Ok(Self {
            suite: *suite,
            secret: Zeroizing::new(SizedPayload::<u8>::read(&mut reader)?.into_owned()),
            age_add: u32::read(&mut reader)?,
            max_early_data_size: u32::read(&mut reader)?,
            common: ClientSessionCommon::read(&mut reader)?,
            quic_params: SizedPayload::<u16, MaybeEmpty>::read(&mut reader)?.into_owned(),
        })
    }

    pub(crate) fn new(
        input: Tls13ClientSessionInput,
        ticket: Arc<SizedPayload<'static, u16, MaybeEmpty>>,
        secret: &[u8],
        time_now: UnixTime,
        lifetime: Duration,
        age_add: u32,
        max_early_data_size: u32,
    ) -> Self {
        Self {
            suite: input.suite,
            secret: Zeroizing::new(secret.to_vec().into()),
            age_add,
            max_early_data_size,
            common: ClientSessionCommon::new(ticket, time_now, lifetime, input.peer_identity),
            quic_params: input
                .quic_params
                .unwrap_or_else(|| SizedPayload::from(Payload::new(Vec::new()))),
        }
    }

    /// Encode this ticket into `buf` for persistence.
    pub fn encode(&self, buf: &mut Vec<u8>) {
        self.suite.common.suite.encode(buf);
        self.secret.encode(buf);
        buf.extend_from_slice(&self.age_add.to_be_bytes());
        buf.extend_from_slice(&self.max_early_data_size.to_be_bytes());
        self.common.encode(buf);
        self.quic_params.encode(buf);
    }

    /// Test only: replace `max_early_data_size` with `new`
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

/// A "template" for future TLS1.3 client session values.
#[derive(Clone)]
pub(crate) struct Tls13ClientSessionInput {
    pub(crate) suite: &'static Tls13CipherSuite,
    pub(crate) peer_identity: Identity<'static>,
    pub(crate) quic_params: Option<SizedPayload<'static, u16, MaybeEmpty>>,
}

/// A stored TLS 1.2 client session value.
#[derive(Debug, Clone)]
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
        let mut reader = Reader::new(bytes);
        let suite = CipherSuite::read(&mut reader)?;
        let suite = provider
            .tls12_cipher_suites
            .iter()
            .find(|s| s.common.suite == suite)
            .ok_or(ApiMisuse::ResumingFromUnknownCipherSuite(suite))?;

        Ok(Self {
            suite: *suite,
            session_id: SessionId::read(&mut reader)?,
            master_secret: Zeroizing::new(
                reader
                    .take_array("MasterSecret")
                    .copied()?,
            ),
            extended_ms: matches!(u8::read(&mut reader)?, 1),
            common: ClientSessionCommon::read(&mut reader)?,
        })
    }

    pub(crate) fn new(
        suite: &'static Tls12CipherSuite,
        session_id: SessionId,
        ticket: Arc<SizedPayload<'static, u16, MaybeEmpty>>,
        master_secret: &[u8; 48],
        peer_identity: Identity<'static>,
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

/// Common data for stored client sessions.
#[derive(Debug, Clone)]
pub struct ClientSessionCommon {
    pub(crate) ticket: Arc<SizedPayload<'static, u16>>,
    pub(crate) epoch: u64,
    lifetime: Duration,
    peer_identity: Arc<Identity<'static>>,
}

impl ClientSessionCommon {
    pub(crate) fn new(
        ticket: Arc<SizedPayload<'static, u16>>,
        time_now: UnixTime,
        lifetime: Duration,
        peer_identity: Identity<'static>,
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
            peer_identity: Arc::new(Identity::read(r)?.into_owned()),
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
}

impl ClientHelloDetails {
    fn new(alpn_protocols: Vec<ApplicationProtocol<'static>>, extension_order_seed: u16) -> Self {
        Self {
            alpn_protocols,
            sent_extensions: Vec::new(),
            extension_order_seed,
            offered_cert_compression: false,
        }
    }

    fn server_sent_unsolicited_extensions(
        &self,
        received_exts: &ServerExtensions<'_>,
        allowed_unsolicited: &[ExtensionType],
    ) -> bool {
        let mut extensions = received_exts.collect_used();
        extensions.extend(
            received_exts
                .unknown_extensions
                .iter()
                .map(|ext| ExtensionType::from(*ext)),
        );
        for ext_type in extensions {
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
