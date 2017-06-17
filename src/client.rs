use msgs::enums::CipherSuite;
use msgs::enums::{AlertDescription, HandshakeType, ExtensionType};
use session::{Session, SessionSecrets, SessionRandoms, SessionCommon};
use suites::{SupportedCipherSuite, ALL_CIPHERSUITES};
use msgs::handshake::{CertificatePayload, DigitallySignedStruct, SessionID};
use msgs::enums::SignatureScheme;
use msgs::enums::{ContentType, ProtocolVersion};
use msgs::message::Message;
use msgs::persist;
use client_hs;
use hash_hs;
use verify;
use anchors;
use sign;
use suites;
use error::TLSError;
use key;

use std::collections;
use std::sync::{Arc, Mutex};
use std::io;
use std::fmt;

/// A trait for the ability to store client session data.
/// The keys and values are opaque.
///
/// Both the keys and values should be treated as
/// **highly sensitive data**, containing enough key material
/// to break all security of the corresponding session.
///
/// `put` is a mutating operation; this isn't expressed
/// in the type system to allow implementations freedom in
/// how to achieve interior mutability.  `Mutex` is a common
/// choice.
pub trait StoresClientSessions : Send + Sync {
    /// Stores a new `value` for `key`.  Returns `true`
    /// if the value was stored.
    fn put(&self, key: Vec<u8>, value: Vec<u8>) -> bool;

    /// Returns the latest value for `key`.  Returns `None`
    /// if there's no such value.
    fn get(&self, key: &[u8]) -> Option<Vec<u8>>;
}

/// An implementor of `StoresClientSessions` which does nothing.
struct NoSessionStorage {}

impl StoresClientSessions for NoSessionStorage {
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

impl StoresClientSessions for ClientSessionMemoryCache {
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

/// A trait for the ability to choose a certificate chain and
/// private key for the purposes of client authentication.
pub trait ResolvesClientCert : Send + Sync {
    /// With the server-supplied acceptable issuers in `acceptable_issuers`,
    /// the server's supported signature schemes in `sigschemes`,
    /// return a certificate chain and signing key to authenticate.
    ///
    /// `acceptable_issuers` is undecoded and unverified by the rustls
    /// library, but it should be expected to contain a DER encodings
    /// of X501 NAMEs.
    ///
    /// Return None to continue the handshake without any client
    /// authentication.  The server may reject the handshake later
    /// if it requires authentication.
    fn resolve(&self,
               acceptable_issuers: &[&[u8]],
               sigschemes: &[SignatureScheme])
               -> Option<sign::CertChainAndSigner>;

    /// Return true if any certificates at all are available.
    fn has_certs(&self) -> bool;
}

struct FailResolveClientCert {}

impl ResolvesClientCert for FailResolveClientCert {
    fn resolve(&self,
               _acceptable_issuers: &[&[u8]],
               _sigschemes: &[SignatureScheme])
               -> Option<sign::CertChainAndSigner> {
        None
    }

    fn has_certs(&self) -> bool {
        false
    }
}

struct AlwaysResolvesClientCert {
    chain: Vec<key::Certificate>,
    key: Arc<Box<sign::Signer>>,
}

impl AlwaysResolvesClientCert {
    fn new_rsa(chain: Vec<key::Certificate>,
               priv_key: &key::PrivateKey)
               -> AlwaysResolvesClientCert {
        let key = sign::RSASigner::new(priv_key).expect("Invalid RSA private key");
        AlwaysResolvesClientCert {
            chain: chain,
            key: Arc::new(Box::new(key)),
        }
    }
}

impl ResolvesClientCert for AlwaysResolvesClientCert {
    fn resolve(&self,
               _acceptable_issuers: &[&[u8]],
               _sigschemes: &[SignatureScheme])
               -> Option<sign::CertChainAndSigner> {
        Some((self.chain.clone(), self.key.clone()))
    }

    fn has_certs(&self) -> bool {
        true
    }
}

/// Common configuration for (typically) all connections made by
/// a program.
///
/// Making one of these can be expensive, and should be
/// once per process rather than once per connection.
#[derive(Clone)]
pub struct ClientConfig {
    /// List of ciphersuites, in preference order.
    pub ciphersuites: Vec<&'static SupportedCipherSuite>,

    /// Collection of root certificates.
    pub root_store: anchors::RootCertStore,

    /// Which ALPN protocols we include in our client hello.
    /// If empty, no ALPN extension is sent.
    pub alpn_protocols: Vec<String>,

    /// How we store session data or tickets.
    pub session_persistence: Arc<StoresClientSessions>,

    /// Our MTU.  If None, we don't limit TLS message sizes.
    pub mtu: Option<usize>,

    /// How to decide what client auth certificate/keys to use.
    pub client_auth_cert_resolver: Arc<ResolvesClientCert>,

    /// Whether to support RFC5077 tickets.  You must provide a working
    /// `session_persistence` member for this to have any meaningful
    /// effect.
    ///
    /// The default is true.
    pub enable_tickets: bool,

    /// Supported versions, in no particular order.  The default
    /// is all supported versions.
    pub versions: Vec<ProtocolVersion>,

    /// How to verify the server certificate chain.
    verifier: Arc<verify::ServerCertVerifier>,
}

impl ClientConfig {
    /// Make a `ClientConfig` with a default set of ciphersuites,
    /// no root certificates, no ALPN protocols, no
    /// session persistence, and no client auth.
    pub fn new() -> ClientConfig {
        ClientConfig {
            ciphersuites: ALL_CIPHERSUITES.to_vec(),
            root_store: anchors::RootCertStore::empty(),
            alpn_protocols: Vec::new(),
            session_persistence: Arc::new(NoSessionStorage {}),
            mtu: None,
            client_auth_cert_resolver: Arc::new(FailResolveClientCert {}),
            enable_tickets: true,
            versions: vec![ProtocolVersion::TLSv1_3, ProtocolVersion::TLSv1_2],
            verifier: Arc::new(verify::WebPKIVerifier {})
        }
    }

    #[doc(hidden)]
    pub fn get_verifier(&self) -> &verify::ServerCertVerifier {
        self.verifier.as_ref()
    }

    /// Set the ALPN protocol list to the given protocol names.
    /// Overwrites any existing configured protocols.
    /// The first element in the `protocols` list is the most
    /// preferred, the last is the least preferred.
    pub fn set_protocols(&mut self, protocols: &[String]) {
        self.alpn_protocols.clear();
        self.alpn_protocols.extend_from_slice(protocols);
    }

    /// Sets persistence layer to `persist`.
    pub fn set_persistence(&mut self, persist: Arc<StoresClientSessions>) {
        self.session_persistence = persist;
    }

    /// Sets MTU to `mtu`.  If None, the default is used.
    /// If Some(x) then x must be greater than 5 bytes.
    pub fn set_mtu(&mut self, mtu: &Option<usize>) {
        // Internally our MTU relates to fragment size, and does
        // not include the TLS header overhead.
        //
        // Externally the MTU is the whole packet size.  The difference
        // is PACKET_OVERHEAD.
        if let Some(x) = *mtu {
            use msgs::fragmenter;
            debug_assert!(x > fragmenter::PACKET_OVERHEAD);
            self.mtu = Some(x - fragmenter::PACKET_OVERHEAD);
        } else {
            self.mtu = None;
        }
    }

    /// Sets a single client authentication certificate and private key.
    /// This is blindly used for all servers that ask for client auth.
    ///
    /// `cert_chain` is a vector of DER-encoded certificates,
    /// `key_der` is a DER-encoded RSA private key.
    pub fn set_single_client_cert(&mut self,
                                  cert_chain: Vec<key::Certificate>,
                                  key_der: key::PrivateKey) {
        self.client_auth_cert_resolver = Arc::new(AlwaysResolvesClientCert::new_rsa(cert_chain,
                                                                                    &key_der));
    }

    /// Access configuration options whose use is dangerous and requires
    /// extra care.
    #[cfg(feature = "dangerous_configuration")]
    pub fn dangerous(&mut self) -> danger::DangerousClientConfig {
        danger::DangerousClientConfig { cfg: self }
    }
}

/// Container for unsafe APIs
#[cfg(feature = "dangerous_configuration")]
pub mod danger {
    use std::sync::Arc;

    use super::ClientConfig;
    use super::verify::ServerCertVerifier;

    /// Accessor for dangerous configuration options.
    pub struct DangerousClientConfig<'a> {
        /// The underlying ClientConfig
        pub cfg: &'a mut ClientConfig
    }

    impl<'a> DangerousClientConfig<'a> {
        /// Overrides the default `ServerCertVerifier` with something else.
        pub fn set_certificate_verifier(&mut self,
                                        verifier: Arc<ServerCertVerifier>) {
            self.cfg.verifier = verifier;
        }
    }
}

pub struct ClientHandshakeData {
    pub server_cert_chain: CertificatePayload,
    pub dns_name: String,
    pub session_id: SessionID,
    pub sent_extensions: Vec<ExtensionType>,
    pub server_kx_params: Vec<u8>,
    pub server_kx_sig: Option<DigitallySignedStruct>,
    pub transcript: hash_hs::HandshakeHash,
    pub resuming_session: Option<persist::ClientSessionValue>,
    pub randoms: SessionRandoms,
    pub must_issue_new_ticket: bool,
    pub using_ems: bool,
    pub new_ticket: Vec<u8>,
    pub new_ticket_lifetime: u32,
    pub doing_client_auth: bool,
    pub client_auth_sigscheme: Option<SignatureScheme>,
    pub client_auth_cert: Option<CertificatePayload>,
    pub client_auth_key: Option<Arc<Box<sign::Signer>>>,
    pub client_auth_context: Option<Vec<u8>>,
    pub offered_key_shares: Vec<suites::KeyExchange>,
}

impl ClientHandshakeData {
    fn new(host_name: &str) -> ClientHandshakeData {
        ClientHandshakeData {
            server_cert_chain: Vec::new(),
            dns_name: host_name.to_string(),
            session_id: SessionID::empty(),
            sent_extensions: Vec::new(),
            server_kx_params: Vec::new(),
            server_kx_sig: None,
            transcript: hash_hs::HandshakeHash::new(),
            resuming_session: None,
            randoms: SessionRandoms::for_client(),
            must_issue_new_ticket: false,
            using_ems: false,
            new_ticket: Vec::new(),
            new_ticket_lifetime: 0,
            doing_client_auth: false,
            client_auth_sigscheme: None,
            client_auth_cert: None,
            client_auth_key: None,
            client_auth_context: None,
            offered_key_shares: Vec::new(),
        }
    }
}

pub struct ClientSessionImpl {
    pub config: Arc<ClientConfig>,
    pub handshake_data: ClientHandshakeData,
    pub secrets: Option<SessionSecrets>,
    pub alpn_protocol: Option<String>,
    pub common: SessionCommon,
    pub error: Option<TLSError>,
    pub state: &'static client_hs::State,
}

impl fmt::Debug for ClientSessionImpl {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("ClientSessionImpl").finish()
    }
}

impl ClientSessionImpl {
    pub fn new(config: &Arc<ClientConfig>, hostname: &str) -> ClientSessionImpl {
        let mut cs = ClientSessionImpl {
            config: config.clone(),
            handshake_data: ClientHandshakeData::new(hostname),
            secrets: None,
            alpn_protocol: None,
            common: SessionCommon::new(config.mtu, true),
            error: None,
            state: &client_hs::EXPECT_SERVER_HELLO,
        };

        if cs.config.client_auth_cert_resolver.has_certs() {
            cs.handshake_data.transcript.set_client_auth_enabled();
        }

        cs.state = client_hs::emit_client_hello(&mut cs);
        cs
    }

    pub fn get_cipher_suites(&self) -> Vec<CipherSuite> {
        let mut ret = Vec::new();

        for cs in &self.config.ciphersuites {
            ret.push(cs.suite);
        }

        // We don't do renegotation at all, in fact.
        ret.push(CipherSuite::TLS_EMPTY_RENEGOTIATION_INFO_SCSV);

        ret
    }

    pub fn start_encryption_tls12(&mut self) {
        self.common.start_encryption_tls12(self.secrets.as_ref().unwrap());
    }

    pub fn find_cipher_suite(&self, suite: CipherSuite) -> Option<&'static SupportedCipherSuite> {
        for scs in &self.config.ciphersuites {
            if scs.suite == suite {
                return Some(scs);
            }
        }

        None
    }

    pub fn wants_read(&self) -> bool {
        // We want to read more data all the time, except when we
        // have unprocessed plaintext.  This provides back-pressure
        // to the TCP buffers.
        //
        // This also covers the handshake case, because we don't have
        // readable plaintext before handshake has completed.
        !self.common.has_readable_plaintext()
    }

    pub fn wants_write(&self) -> bool {
        !self.common.sendable_tls.is_empty()
    }

    pub fn is_handshaking(&self) -> bool {
        !self.common.traffic
    }

    pub fn set_buffer_limit(&mut self, len: usize) {
        self.common.set_buffer_limit(len)
    }

    pub fn process_msg(&mut self, mut msg: Message) -> Result<(), TLSError> {
        // Decrypt if demanded by current state.
        if self.common.peer_encrypting {
            let dm = self.common.decrypt_incoming(msg)?;
            msg = dm;
        }

        // For handshake messages, we need to join them before parsing
        // and processing.
        if self.common.handshake_joiner.want_message(&msg) {
            self.common
                .handshake_joiner
                .take_message(msg)
                .ok_or_else(|| {
                            self.common.send_fatal_alert(AlertDescription::DecodeError);
                            TLSError::CorruptMessagePayload(ContentType::Handshake)
                            })?;
            return self.process_new_handshake_messages();
        }

        // Now we can fully parse the message payload.
        if !msg.decode_payload() {
            return Err(TLSError::CorruptMessagePayload(msg.typ));
        }

        // For alerts, we have separate logic.
        if msg.is_content_type(ContentType::Alert) {
            return self.common.process_alert(msg);
        }

        self.process_main_protocol(msg)
    }

    fn process_new_handshake_messages(&mut self) -> Result<(), TLSError> {
        while let Some(msg) = self.common.handshake_joiner.frames.pop_front() {
            self.process_main_protocol(msg)?;
        }

        Ok(())
    }

    fn queue_unexpected_alert(&mut self) {
        self.common.send_fatal_alert(AlertDescription::UnexpectedMessage);
    }

    /// Detect and drop/reject HelloRequests.  This is needed irrespective
    /// of the current protocol state, which should illustrate how badly
    /// TLS renegotiation is designed.
    fn process_hello_req(&mut self) {
        // If we're post handshake, send a refusal alert.
        // Otherwise, drop it silently.
        if !self.is_handshaking() {
            self.common.send_warning_alert(AlertDescription::NoRenegotiation);
        }
    }

    /// Process `msg`.  First, we get the current state.  Then we ask what messages
    /// that state expects, enforced via a `Expectation`.  Finally, we ask the handler
    /// to handle the message.
    fn process_main_protocol(&mut self, msg: Message) -> Result<(), TLSError> {
        if msg.is_handshake_type(HandshakeType::HelloRequest) && !self.common.is_tls13() {
            self.process_hello_req();
            return Ok(());
        }

        self.state.expect
            .check_message(&msg)
            .map_err(|err| {
                self.queue_unexpected_alert();
                err
            })?;
        let new_state = (self.state.handle)(self, msg)?;
        self.state = new_state;

        Ok(())
    }

    pub fn process_new_packets(&mut self) -> Result<(), TLSError> {
        if let Some(ref err) = self.error {
            return Err(err.clone());
        }

        if self.common.message_deframer.desynced {
            return Err(TLSError::CorruptMessage);
        }

        while let Some(msg) = self.common.message_deframer.frames.pop_front() {
            match self.process_msg(msg) {
                Ok(_) => {}
                Err(err) => {
                    self.error = Some(err.clone());
                    return Err(err);
                }
            }
        }

        Ok(())
    }

    pub fn get_peer_certificates(&self) -> Option<Vec<key::Certificate>> {
        if self.handshake_data.server_cert_chain.is_empty() {
            return None;
        }

        let mut r = Vec::new();
        for cert in &self.handshake_data.server_cert_chain {
            r.push(cert.clone());
        }

        Some(r)
    }

    pub fn get_alpn_protocol(&self) -> Option<String> {
        self.alpn_protocol.clone()
    }

    pub fn get_protocol_version(&self) -> Option<ProtocolVersion> {
        self.common.negotiated_version
    }
}

/// This represents a single TLS client session.
#[derive(Debug)]
pub struct ClientSession {
    // We use the pimpl idiom to hide unimportant details.
    imp: ClientSessionImpl,
}

impl ClientSession {
    /// Make a new ClientSession.  `config` controls how
    /// we behave in the TLS protocol, `hostname` is the
    /// hostname of who we want to talk to.
    pub fn new(config: &Arc<ClientConfig>, hostname: &str) -> ClientSession {
        ClientSession { imp: ClientSessionImpl::new(config, hostname) }
    }
}

impl Session for ClientSession {
    fn read_tls(&mut self, rd: &mut io::Read) -> io::Result<usize> {
        self.imp.common.read_tls(rd)
    }

    /// Writes TLS messages to `wr`.
    fn write_tls(&mut self, wr: &mut io::Write) -> io::Result<usize> {
        self.imp.common.write_tls(wr)
    }

    fn process_new_packets(&mut self) -> Result<(), TLSError> {
        self.imp.process_new_packets()
    }

    fn wants_read(&self) -> bool {
        self.imp.wants_read()
    }

    fn wants_write(&self) -> bool {
        self.imp.wants_write()
    }

    fn is_handshaking(&self) -> bool {
        self.imp.is_handshaking()
    }

    fn set_buffer_limit(&mut self, len: usize) {
        self.imp.set_buffer_limit(len)
    }

    fn send_close_notify(&mut self) {
        self.imp.common.send_close_notify()
    }

    fn get_peer_certificates(&self) -> Option<Vec<key::Certificate>> {
        self.imp.get_peer_certificates()
    }

    fn get_alpn_protocol(&self) -> Option<String> {
        self.imp.get_alpn_protocol()
    }

    fn get_protocol_version(&self) -> Option<ProtocolVersion> {
        self.imp.get_protocol_version()
    }
}

impl io::Read for ClientSession {
    /// Obtain plaintext data received from the peer over
    /// this TLS connection.
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.imp.common.read(buf)
    }
}

impl io::Write for ClientSession {
    /// Send the plaintext `buf` to the peer, encrypting
    /// and authenticating it.  Once this function succeeds
    /// you should call `write_tls` which will output the
    /// corresponding TLS records.
    ///
    /// This function buffers plaintext sent before the
    /// TLS handshake completes, and sends it as soon
    /// as it can.  This buffer is of *unlimited size* so
    /// writing much data before it can be sent will
    /// cause excess memory usage.
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.imp.common.send_some_plaintext(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.imp.common.flush_plaintext();
        Ok(())
    }
}
