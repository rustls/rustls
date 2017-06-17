use session::{Session, SessionRandoms, SessionSecrets, SessionCommon};
use suites::{SupportedCipherSuite, ALL_CIPHERSUITES, KeyExchange};
use msgs::enums::{ContentType, SignatureScheme};
use msgs::enums::{AlertDescription, HandshakeType, ProtocolVersion};
use msgs::handshake::{SessionID, CertificatePayload};
use msgs::message::Message;
use msgs::codec::Codec;
use hash_hs;
use server_hs;
use error::TLSError;
use rand;
use sign;
use verify;
use anchors;
use key;

use std::collections;
use std::sync::{Arc, Mutex};
use std::io;
use std::fmt;

/// A trait for the ability to generate Session IDs, and store
/// server session data. The keys and values are opaque.
///
/// Both the keys and values should be treated as
/// **highly sensitive data**, containing enough key material
/// to break all security of the corresponding session.
pub trait StoresServerSessions : Send + Sync {
    /// Generate a session ID.
    fn generate(&self) -> SessionID;

    /// Store session secrets encoded in `value` against key `id`,
    /// overwrites any existing value against `id`.  Returns `true`
    /// if the value was stored.
    fn put(&mut self, id: &SessionID, value: Vec<u8>) -> bool;

    /// Find a session with the given `id`.  Return it, or None
    /// if it doesn't exist.
    fn get(&self, id: &SessionID) -> Option<Vec<u8>>;

    /// Erase a session with the given `id`.  Return true if
    /// `id` existed and was removed.
    fn del(&mut self, id: &SessionID) -> bool;
}

/// A trait for the ability to encrypt and decrypt tickets.
pub trait ProducesTickets : Send + Sync {
    /// Returns true if this implementation will encrypt/decrypt
    /// tickets.  Should return false if this is a dummy
    /// implementation: the server will not send the SessionTicket
    /// extension and will not call the other functions.
    fn enabled(&self) -> bool;

    /// Returns the lifetime in seconds of tickets produced now.
    /// The lifetime is provided as a hint to clients that the
    /// ticket will not be useful after the given time.
    ///
    /// This lifetime must be implemented by key rolling and
    /// erasure, *not* by storing a lifetime in the ticket.
    ///
    /// The objective is to limit damage to forward secrecy caused
    /// by tickets, not just limiting their lifetime.
    fn get_lifetime(&self) -> u32;

    /// Encrypt and authenticate `plain`, returning the resulting
    /// ticket.  Return None if `plain` cannot be encrypted for
    /// some reason: an empty ticket will be sent and the connection
    /// will continue.
    fn encrypt(&self, plain: &[u8]) -> Option<Vec<u8>>;

    /// Decrypt `cipher`, validating its authenticity protection
    /// and recovering the plaintext.  `cipher` is fully attacker
    /// controlled, so this decryption must be side-channel free,
    /// panic-proof, and otherwise bullet-proof.  If the decryption
    /// fails, return None.
    fn decrypt(&self, cipher: &[u8]) -> Option<Vec<u8>>;
}

/// How to choose a certificate chain and signing key for use
/// in server authentication.
pub trait ResolvesServerCert : Send + Sync {
    /// Choose a certificate chain and matching key given any server DNS
    /// name provided via SNI, and signature schemes.
    ///
    /// The certificate chain is returned as a vec of `Certificate`s,
    /// the key is inside a `Signer`.
    fn resolve(&self,
               server_name: Option<&str>,
               sigschemes: &[SignatureScheme])
               -> Option<sign::CertChainAndSigner>;
}

/// Common configuration for a set of server sessions.
///
/// Making one of these can be expensive, and should be
/// once per process rather than once per connection.
pub struct ServerConfig {
    /// List of ciphersuites, in preference order.
    pub ciphersuites: Vec<&'static SupportedCipherSuite>,

    /// Ignore the client's ciphersuite order. Instead,
    /// choose the top ciphersuite in the server list
    /// which is supported by the client.
    pub ignore_client_order: bool,

    /// How to store client sessions.
    pub session_storage: Mutex<Box<StoresServerSessions + Send>>,

    /// How to produce tickets.
    pub ticketer: Box<ProducesTickets>,

    /// How to choose a server cert and key.
    pub cert_resolver: Box<ResolvesServerCert>,

    /// Protocol names we support, most preferred first.
    /// If empty we don't do ALPN at all.
    pub alpn_protocols: Vec<String>,

    /// List of client authentication root certificates.
    pub client_auth_roots: anchors::RootCertStore,

    /// Whether to attempt client auth.
    pub client_auth_offer: bool,

    /// Whether to complete handshakes with clients which
    /// don't do client auth.
    pub client_auth_mandatory: bool,

    /// Supported protocol versions, in no particular order.
    /// The default is all supported versions.
    pub versions: Vec<ProtocolVersion>,

    /// How to verify client certificates.
    verifier: Box<verify::ClientCertVerifier>,
}

/// Something which never stores sessions.
struct NoSessionStorage {}

impl StoresServerSessions for NoSessionStorage {
    fn generate(&self) -> SessionID {
        SessionID::empty()
    }
    fn put(&mut self, _id: &SessionID, _sec: Vec<u8>) -> bool {
        false
    }
    fn get(&self, _id: &SessionID) -> Option<Vec<u8>> {
        None
    }
    fn del(&mut self, _id: &SessionID) -> bool {
        false
    }
}

/// An implementor of `StoresServerSessions` that stores everything
/// in memory.  If enforces a limit on the number of stored sessions
/// to bound memory usage.
pub struct ServerSessionMemoryCache {
    cache: collections::HashMap<Vec<u8>, Vec<u8>>,
    max_entries: usize,
}

impl ServerSessionMemoryCache {
    /// Make a new ServerSessionMemoryCache.  `size` is the maximum
    /// number of stored sessions.
    pub fn new(size: usize) -> Box<ServerSessionMemoryCache> {
        debug_assert!(size > 0);
        Box::new(ServerSessionMemoryCache {
            cache: collections::HashMap::new(),
            max_entries: size,
        })
    }

    fn limit_size(&mut self) {
        while self.cache.len() > self.max_entries {
            let k = self.cache.keys().next().unwrap().clone();
            self.cache.remove(&k);
        }
    }
}

impl StoresServerSessions for ServerSessionMemoryCache {
    fn generate(&self) -> SessionID {
        let mut v = [0u8; 32];
        rand::fill_random(&mut v);
        SessionID::new(&v)
    }

    fn put(&mut self, id: &SessionID, sec: Vec<u8>) -> bool {
        self.cache.insert(id.get_encoding(), sec);
        self.limit_size();
        true
    }

    fn get(&self, id: &SessionID) -> Option<Vec<u8>> {
        self.cache.get(&id.get_encoding()).cloned()
    }

    fn del(&mut self, id: &SessionID) -> bool {
        self.cache.remove(&id.get_encoding()).is_some()
    }
}

/// Something which never produces tickets.
struct NeverProducesTickets {}

impl ProducesTickets for NeverProducesTickets {
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
struct FailResolveChain {}

impl ResolvesServerCert for FailResolveChain {
    fn resolve(&self,
               _server_name: Option<&str>,
               _sigschemes: &[SignatureScheme])
               -> Option<sign::CertChainAndSigner> {
        None
    }
}

/// Something which always resolves to the same cert chain.
struct AlwaysResolvesChain {
    chain: Vec<key::Certificate>,
    key: Arc<Box<sign::Signer>>,
}

impl AlwaysResolvesChain {
    fn new_rsa(chain: Vec<key::Certificate>, priv_key: &key::PrivateKey) -> AlwaysResolvesChain {
        let key = sign::RSASigner::new(priv_key)
            .expect("Invalid RSA private key");
        AlwaysResolvesChain {
            chain: chain,
            key: Arc::new(Box::new(key)),
        }
    }
}

impl ResolvesServerCert for AlwaysResolvesChain {
    fn resolve(&self,
               _server_name: Option<&str>,
               _sigschemes: &[SignatureScheme])
               -> Option<sign::CertChainAndSigner> {
        Some((self.chain.clone(), self.key.clone()))
    }
}

impl ServerConfig {
    /// Make a `ServerConfig` with a default set of ciphersuites,
    /// no keys/certificates, no ALPN protocols, no client auth, and
    /// no session persistence.
    pub fn new() -> ServerConfig {
        ServerConfig {
            ciphersuites: ALL_CIPHERSUITES.to_vec(),
            ignore_client_order: false,
            session_storage: Mutex::new(Box::new(NoSessionStorage {})),
            ticketer: Box::new(NeverProducesTickets {}),
            alpn_protocols: Vec::new(),
            cert_resolver: Box::new(FailResolveChain {}),
            client_auth_roots: anchors::RootCertStore::empty(),
            client_auth_offer: false,
            client_auth_mandatory: false,
            versions: vec![ ProtocolVersion::TLSv1_3, ProtocolVersion::TLSv1_2 ],
            verifier: Box::new(verify::WebPKIVerifier {}),
        }
    }

    #[doc(hidden)]
    pub fn get_verifier(&self) -> &verify::ClientCertVerifier {
        self.verifier.as_ref()
    }

    /// Sets the session persistence layer to `persist`.
    pub fn set_persistence(&mut self, persist: Box<StoresServerSessions + Send>) {
        self.session_storage = Mutex::new(persist);
    }

    /// Sets a single certificate chain and matching private key.  This
    /// certificate and key is used for all subsequent connections,
    /// irrespective of things like SNI hostname.
    ///
    /// `cert_chain` is a vector of DER-encoded certificates.
    /// `key_der` is a DER-encoded RSA private key.
    pub fn set_single_cert(&mut self,
                           cert_chain: Vec<key::Certificate>,
                           key_der: key::PrivateKey) {
        self.cert_resolver = Box::new(AlwaysResolvesChain::new_rsa(cert_chain, &key_der));
    }

    /// Set the ALPN protocol list to the given protocol names.
    /// Overwrites any existing configured protocols.
    ///
    /// The first element in the `protocols` list is the most
    /// preferred, the last is the least preferred.
    pub fn set_protocols(&mut self, protocols: &[String]) {
        self.alpn_protocols.clear();
        self.alpn_protocols.extend_from_slice(protocols);
    }

    /// Enables client authentication.  The server will ask for
    /// and validate certificates to the given list of root
    /// `certs`.  If `mandatory` is true, the server will fail
    /// to handshake with a client if it does not do client auth.
    pub fn set_client_auth_roots(&mut self, certs: Vec<key::Certificate>, mandatory: bool) {
        for cert in certs {
            self.client_auth_roots
                .add(&cert)
                .unwrap()
        }
        self.client_auth_offer = true;
        self.client_auth_mandatory = mandatory;
    }

    /// Access configuration options whose use is dangerous and requires
    /// extra care.
    #[cfg(feature = "dangerous_configuration")]
    pub fn dangerous(&mut self) -> danger::DangerousServerConfig {
        danger::DangerousServerConfig { cfg: self }
    }
}

/// Container for unsafe APIs
#[cfg(feature = "dangerous_configuration")]
pub mod danger {
    use super::ServerConfig;
    use super::verify::ClientCertVerifier;

    /// Accessor for dangerous configuration options.
    pub struct DangerousServerConfig<'a> {
        /// The underlying ServerConfig
        pub cfg: &'a mut ServerConfig
    }

    impl<'a> DangerousServerConfig<'a> {
        /// Overrides the default `ClientCertVerifier` with something else.
        pub fn set_certificate_verifier(&mut self,
                                        verifier: Box<ClientCertVerifier>) {
            self.cfg.verifier = verifier;
        }
    }
}

pub struct ServerHandshakeData {
    pub server_cert_chain: Option<CertificatePayload>,
    pub session_id: SessionID,
    pub randoms: SessionRandoms,
    pub transcript: hash_hs::HandshakeHash,
    pub hash_at_server_fin: Vec<u8>,
    pub kx_data: Option<KeyExchange>,
    pub doing_resume: bool,
    pub send_ticket: bool,
    pub using_ems: bool,
    pub doing_client_auth: bool,
    pub done_retry: bool,
    pub valid_client_cert_chain: Option<Vec<key::Certificate>>,
}

impl ServerHandshakeData {
    fn new() -> ServerHandshakeData {
        ServerHandshakeData {
            server_cert_chain: None,
            session_id: SessionID::empty(),
            randoms: SessionRandoms::for_server(),
            transcript: hash_hs::HandshakeHash::new(),
            hash_at_server_fin: vec![],
            kx_data: None,
            send_ticket: false,
            using_ems: false,
            doing_resume: false,
            doing_client_auth: false,
            done_retry: false,
            valid_client_cert_chain: None,
        }
    }
}

pub struct ServerSessionImpl {
    pub config: Arc<ServerConfig>,
    pub handshake_data: ServerHandshakeData,
    pub secrets: Option<SessionSecrets>,
    pub common: SessionCommon,
    pub alpn_protocol: Option<String>,
    pub error: Option<TLSError>,
    pub state: &'static server_hs::State,
}

impl fmt::Debug for ServerSessionImpl {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("ServerSessionImpl").finish()
    }
}

impl ServerSessionImpl {
    pub fn new(server_config: &Arc<ServerConfig>) -> ServerSessionImpl {
        let mut sess = ServerSessionImpl {
            config: server_config.clone(),
            handshake_data: ServerHandshakeData::new(),
            secrets: None,
            common: SessionCommon::new(None, false),
            alpn_protocol: None,
            error: None,
            state: &server_hs::EXPECT_CLIENT_HELLO,
        };

        if sess.config.client_auth_offer {
            sess.handshake_data.transcript.set_client_auth_enabled();
        }

        sess
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
            self.common.handshake_joiner.take_message(msg)
                .ok_or_else(|| {
                            self.common.send_fatal_alert(AlertDescription::DecodeError);
                            TLSError::CorruptMessagePayload(ContentType::Handshake)
                            })?;
            return self.process_new_handshake_messages();
        }

        // Now we can fully parse the message payload.
        msg.decode_payload();

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

    pub fn process_main_protocol(&mut self, msg: Message) -> Result<(), TLSError> {
        if self.common.traffic && !self.common.is_tls13() &&
           msg.is_handshake_type(HandshakeType::ClientHello) {
            self.common.send_warning_alert(AlertDescription::NoRenegotiation);
            return Ok(());
        }

        self.state.expect.check_message(&msg)
            .map_err(|err| { self.queue_unexpected_alert(); err })?;
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

    pub fn start_encryption_tls12(&mut self) {
        self.common.start_encryption_tls12(self.secrets.as_ref().unwrap());
    }

    pub fn get_peer_certificates(&self) -> Option<Vec<key::Certificate>> {
        if self.handshake_data.valid_client_cert_chain.is_none() {
            return None;
        }

        let mut r = Vec::new();

        for cert in self.handshake_data.valid_client_cert_chain.as_ref().unwrap() {
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

/// This represents a single TLS server session.
///
/// Send TLS-protected data to the peer using the `io::Write` trait implementation.
/// Read data from the peer using the `io::Read` trait implementation.
#[derive(Debug)]
pub struct ServerSession {
    // We use the pimpl idiom to hide unimportant details.
    imp: ServerSessionImpl,
}

impl ServerSession {
    /// Make a new ServerSession.  `config` controls how
    /// we behave in the TLS protocol.
    pub fn new(config: &Arc<ServerConfig>) -> ServerSession {
        ServerSession { imp: ServerSessionImpl::new(config) }
    }
}

impl Session for ServerSession {
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

impl io::Read for ServerSession {
    /// Obtain plaintext data received from the peer over
    /// this TLS connection.
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.imp.common.read(buf)
    }
}

impl io::Write for ServerSession {
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
