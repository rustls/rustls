use crate::builder::{ConfigBuilder, WantsCipherSuites};
use crate::conn::{CommonState, ConnectionCommon, State};
use crate::error::Error;
use crate::keylog::KeyLog;
use crate::kx::SupportedKxGroup;
#[cfg(feature = "logging")]
use crate::log::trace;
use crate::msgs::base::PayloadU8;
#[cfg(feature = "quic")]
use crate::msgs::enums::AlertDescription;
use crate::msgs::enums::ProtocolVersion;
use crate::msgs::enums::SignatureScheme;
use crate::msgs::handshake::{ClientHelloPayload, ServerExtension};
use crate::msgs::message::Message;
use crate::sign;
use crate::suites::SupportedCipherSuite;
use crate::verify;
#[cfg(feature = "quic")]
use crate::{conn::Protocol, quic};

use super::hs;

use std::marker::PhantomData;
use std::ops::{Deref, DerefMut};
use std::sync::Arc;
use std::{fmt, io};

/// A trait for the ability to store server session data.
///
/// The keys and values are opaque.
///
/// Both the keys and values should be treated as
/// **highly sensitive data**, containing enough key material
/// to break all security of the corresponding sessions.
///
/// Implementations can be lossy (in other words, forgetting
/// key/value pairs) without any negative security consequences.
///
/// However, note that `take` **must** reliably delete a returned
/// value.  If it does not, there may be security consequences.
///
/// `put` and `take` are mutating operations; this isn't expressed
/// in the type system to allow implementations freedom in
/// how to achieve interior mutability.  `Mutex` is a common
/// choice.
pub trait StoresServerSessions: Send + Sync {
    /// Store session secrets encoded in `value` against `key`,
    /// overwrites any existing value against `key`.  Returns `true`
    /// if the value was stored.
    fn put(&self, key: Vec<u8>, value: Vec<u8>) -> bool;

    /// Find a value with the given `key`.  Return it, or None
    /// if it doesn't exist.
    fn get(&self, key: &[u8]) -> Option<Vec<u8>>;

    /// Find a value with the given `key`.  Return it and delete it;
    /// or None if it doesn't exist.
    fn take(&self, key: &[u8]) -> Option<Vec<u8>>;

    /// Whether the store can cache another session. This is used to indicate to clients
    /// whether their session can be resumed; the implementation is not required to remember
    /// a session even if it returns `true` here.
    fn can_cache(&self) -> bool;
}

/// A trait for the ability to encrypt and decrypt tickets.
pub trait ProducesTickets: Send + Sync {
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
    fn lifetime(&self) -> u32;

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
pub trait ResolvesServerCert: Send + Sync {
    /// Choose a certificate chain and matching key given simplified
    /// ClientHello information.
    ///
    /// Return `None` to abort the handshake.
    fn resolve(&self, client_hello: ClientHello) -> Option<Arc<sign::CertifiedKey>>;
}

/// A struct representing the received Client Hello
pub struct ClientHello<'a> {
    server_name: &'a Option<webpki::DnsName>,
    signature_schemes: &'a [SignatureScheme],
    alpn: Option<&'a Vec<PayloadU8>>,
}

impl<'a> ClientHello<'a> {
    /// Creates a new ClientHello
    pub(super) fn new(
        server_name: &'a Option<webpki::DnsName>,
        signature_schemes: &'a [SignatureScheme],
        alpn: Option<&'a Vec<PayloadU8>>,
    ) -> Self {
        trace!("sni {:?}", server_name);
        trace!("sig schemes {:?}", signature_schemes);
        trace!("alpn protocols {:?}", alpn);

        ClientHello {
            server_name,
            signature_schemes,
            alpn,
        }
    }

    /// Get the server name indicator.
    ///
    /// Returns `None` if the client did not supply a SNI.
    pub fn server_name(&self) -> Option<&str> {
        self.server_name
            .as_ref()
            .map(|s| <webpki::DnsName as AsRef<str>>::as_ref(s))
    }

    /// Get the compatible signature schemes.
    ///
    /// Returns standard-specified default if the client omitted this extension.
    pub fn signature_schemes(&self) -> &[SignatureScheme] {
        self.signature_schemes
    }

    /// Get the alpn.
    ///
    /// Returns `None` if the client did not include an ALPN extension
    pub fn alpn(&self) -> Option<impl Iterator<Item = &'a [u8]>> {
        self.alpn.map(|protocols| {
            protocols
                .iter()
                .map(|proto| proto.0.as_slice())
        })
    }
}

/// Common configuration for a set of server sessions.
///
/// Making one of these can be expensive, and should be
/// once per process rather than once per connection.
///
/// These must be created via the [`ServerConfig::builder()`] function.
///
/// # Defaults
///
/// * [`ServerConfig::max_fragment_size`]: the default is `None`: TLS packets are not fragmented to a specific size.
/// * [`ServerConfig::session_storage`]: the default stores 256 sessions in memory.
/// * [`ServerConfig::alpn_protocols`]: the default is empty -- no ALPN protocol is negotiated.
/// * [`ServerConfig::key_log`]: key material is not logged.
#[derive(Clone)]
pub struct ServerConfig {
    /// List of ciphersuites, in preference order.
    pub(super) cipher_suites: Vec<SupportedCipherSuite>,

    /// List of supported key exchange groups.
    ///
    /// The first is the highest priority: they will be
    /// offered to the client in this order.
    pub(super) kx_groups: Vec<&'static SupportedKxGroup>,

    /// Ignore the client's ciphersuite order. Instead,
    /// choose the top ciphersuite in the server list
    /// which is supported by the client.
    pub ignore_client_order: bool,

    /// The maximum size of TLS message we'll emit.  If None, we don't limit TLS
    /// message lengths except to the 2**16 limit specified in the standard.
    ///
    /// rustls enforces an arbitrary minimum of 32 bytes for this field.
    /// Out of range values are reported as errors from ServerConnection::new.
    ///
    /// Setting this value to the TCP MSS may improve latency for stream-y workloads.
    pub max_fragment_size: Option<usize>,

    /// How to store client sessions.
    pub session_storage: Arc<dyn StoresServerSessions + Send + Sync>,

    /// How to produce tickets.
    pub ticketer: Arc<dyn ProducesTickets>,

    /// How to choose a server cert and key.
    pub cert_resolver: Arc<dyn ResolvesServerCert>,

    /// Protocol names we support, most preferred first.
    /// If empty we don't do ALPN at all.
    pub alpn_protocols: Vec<Vec<u8>>,

    /// Supported protocol versions, in no particular order.
    /// The default is all supported versions.
    pub(super) versions: crate::versions::EnabledVersions,

    /// How to verify client certificates.
    pub(super) verifier: Arc<dyn verify::ClientCertVerifier>,

    /// How to output key material for debugging.  The default
    /// does nothing.
    pub key_log: Arc<dyn KeyLog>,

    /// Amount of early data to accept; 0 to disable.
    #[cfg(feature = "quic")] // TLS support unimplemented
    #[doc(hidden)]
    pub max_early_data_size: u32,
}

impl ServerConfig {
    /// Create builder to build up the server configuration.
    ///
    /// For more information, see the [`ConfigBuilder`] documentation.
    pub fn builder() -> ConfigBuilder<Self, WantsCipherSuites> {
        ConfigBuilder {
            state: WantsCipherSuites(()),
            side: PhantomData::default(),
        }
    }

    #[doc(hidden)]
    /// We support a given TLS version if it's quoted in the configured
    /// versions *and* at least one ciphersuite for this version is
    /// also configured.
    pub fn supports_version(&self, v: ProtocolVersion) -> bool {
        self.versions.contains(v)
            && self
                .cipher_suites
                .iter()
                .any(|cs| cs.version().version == v)
    }
}

/// This represents a single TLS server connection.
///
/// Send TLS-protected data to the peer using the `io::Write` trait implementation.
/// Read data from the peer using the `io::Read` trait implementation.
pub struct ServerConnection {
    inner: ConnectionCommon<ServerConnectionData>,
}

impl ServerConnection {
    /// Make a new ServerConnection.  `config` controls how
    /// we behave in the TLS protocol.
    pub fn new(config: Arc<ServerConfig>) -> Result<Self, Error> {
        Self::from_config(config, vec![])
    }

    fn from_config(
        config: Arc<ServerConfig>,
        extra_exts: Vec<ServerExtension>,
    ) -> Result<Self, Error> {
        let common = CommonState::new(config.max_fragment_size, false)?;
        Ok(Self {
            inner: ConnectionCommon::new(
                Box::new(hs::ExpectClientHello::new(config, extra_exts)),
                ServerConnectionData::default(),
                common,
            ),
        })
    }

    /// Retrieves the SNI hostname, if any, used to select the certificate and
    /// private key.
    ///
    /// This returns `None` until some time after the client's SNI extension
    /// value is processed during the handshake. It will never be `None` when
    /// the connection is ready to send or process application data, unless the
    /// client does not support SNI.
    ///
    /// This is useful for application protocols that need to enforce that the
    /// SNI hostname matches an application layer protocol hostname. For
    /// example, HTTP/1.1 servers commonly expect the `Host:` header field of
    /// every request on a connection to match the hostname in the SNI extension
    /// when the client provides the SNI extension.
    ///
    /// The SNI hostname is also used to match sessions during session
    /// resumption.
    pub fn sni_hostname(&self) -> Option<&str> {
        self.inner.data.get_sni_str()
    }

    /// Application-controlled portion of the resumption ticket supplied by the client, if any.
    ///
    /// Recovered from the prior session's `set_resumption_data`. Integrity is guaranteed by rustls.
    ///
    /// Returns `Some` iff a valid resumption ticket has been received from the client.
    pub fn received_resumption_data(&self) -> Option<&[u8]> {
        self.inner
            .data
            .received_resumption_data
            .as_ref()
            .map(|x| &x[..])
    }

    /// Set the resumption data to embed in future resumption tickets supplied to the client.
    ///
    /// Defaults to the empty byte string. Must be less than 2^15 bytes to allow room for other
    /// data. Should be called while `is_handshaking` returns true to ensure all transmitted
    /// resumption tickets are affected.
    ///
    /// Integrity will be assured by rustls, but the data will be visible to the client. If secrecy
    /// from the client is desired, encrypt the data separately.
    pub fn set_resumption_data(&mut self, data: &[u8]) {
        assert!(data.len() < 2usize.pow(15));
        self.inner.data.resumption_data = data.into();
    }

    /// Explicitly discard early data, notifying the client
    ///
    /// Useful if invariants encoded in `received_resumption_data()` cannot be respected.
    ///
    /// Must be called while `is_handshaking` is true.
    pub fn reject_early_data(&mut self) {
        assert!(
            self.is_handshaking(),
            "cannot retroactively reject early data"
        );
        self.inner.data.reject_early_data = true;
    }
}

impl fmt::Debug for ServerConnection {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("ServerConnection")
            .finish()
    }
}

impl Deref for ServerConnection {
    type Target = ConnectionCommon<ServerConnectionData>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl DerefMut for ServerConnection {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl From<ServerConnection> for crate::Connection {
    fn from(conn: ServerConnection) -> Self {
        Self::Server(conn)
    }
}

/// Handle on a server-side connection before configuration is available.
///
/// The `Acceptor` allows the caller to provide a [`ServerConfig`] based on the [`ClientHello`] of
/// the incoming connection.
pub struct Acceptor {
    inner: Option<ConnectionCommon<ServerConnectionData>>,
}

impl Acceptor {
    /// Create a new `Acceptor`.
    pub fn new() -> Result<Self, Error> {
        let common = CommonState::new(None, false)?;
        let state = Box::new(Accepting);
        Ok(Self {
            inner: Some(ConnectionCommon::new(state, Default::default(), common)),
        })
    }

    /// Returns true if the caller should call [`Connection::read_tls()`] as soon as possible.
    ///
    /// For more details, refer to [`CommonState::wants_read()`].
    ///
    /// [`Connection::read_tls()`]: crate::Connection::read_tls
    pub fn wants_read(&self) -> bool {
        self.inner
            .as_ref()
            .map(|conn| conn.common_state.wants_read())
            .unwrap_or(false)
    }

    /// Read TLS content from `rd`.
    ///
    /// Returns an error if this `Acceptor` has already yielded an [`Accepted`]. For more details,
    /// refer to [`Connection::read_tls()`].
    ///
    /// [`Connection::read_tls()`]: crate::Connection::read_tls
    pub fn read_tls(&mut self, rd: &mut dyn io::Read) -> Result<usize, io::Error> {
        match &mut self.inner {
            Some(conn) => conn.read_tls(rd),
            None => Err(io::Error::new(
                io::ErrorKind::Other,
                "acceptor cannot read after successful acceptance",
            )),
        }
    }

    /// Check if a `ClientHello` message has been received.
    ///
    /// Returns an error if the `ClientHello` message is invalid or if the acceptor has already
    /// yielded an [`Accepted`]. Returns `Ok(None)` if no complete `ClientHello` has been received
    /// yet.
    pub fn accept(&mut self) -> Result<Option<Accepted>, Error> {
        let mut connection = match self.inner.take() {
            Some(conn) => conn,
            None => {
                return Err(Error::General(
                    "cannot accept after successful acceptance".into(),
                ));
            }
        };

        let message = match connection.first_handshake_message() {
            Ok(Some(msg)) => msg,
            Ok(None) => {
                self.inner = Some(connection);
                return Ok(None);
            }
            Err(e) => {
                self.inner = Some(connection);
                return Err(e);
            }
        };

        let (_, sig_schemes) = hs::process_client_hello(
            &message,
            false,
            &mut connection.common_state,
            &mut connection.data,
        )?;

        Ok(Some(Accepted {
            connection,
            message,
            sig_schemes,
        }))
    }
}

/// Represents a `ClientHello` message received through the [`Acceptor`].
///
/// Contains the state required to resume the connection through [`Accepted::into_connection()`].
pub struct Accepted {
    connection: ConnectionCommon<ServerConnectionData>,
    message: Message,
    sig_schemes: Vec<SignatureScheme>,
}

impl Accepted {
    /// Get the [`ClientHello`] for this connection.
    pub fn client_hello(&self) -> ClientHello<'_> {
        ClientHello::new(
            &self.connection.data.sni,
            &self.sig_schemes,
            Self::client_hello_payload(&self.message).get_alpn_extension(),
        )
    }

    /// Convert the [`Accepted`] into a [`ServerConnection`].
    ///
    /// Takes the state returned from [`Acceptor::accept()`] as well as the [`ServerConfig`] and
    /// [`sign::CertifiedKey`] that should be used for the session. Returns an error if
    /// configuration-dependent validation of the received `ClientHello` message fails.
    pub fn into_connection(mut self, config: Arc<ServerConfig>) -> Result<ServerConnection, Error> {
        self.connection
            .common_state
            .set_max_fragment_size(config.max_fragment_size)?;
        let state = hs::ExpectClientHello::new(config, Vec::new());
        let mut cx = hs::ServerContext {
            common: &mut self.connection.common_state,
            data: &mut self.connection.data,
        };

        let new = state.with_certified_key(
            self.sig_schemes,
            Self::client_hello_payload(&self.message),
            &self.message,
            &mut cx,
        )?;

        self.connection.replace_state(new);
        Ok(ServerConnection {
            inner: self.connection,
        })
    }

    fn client_hello_payload(message: &Message) -> &ClientHelloPayload {
        match &message.payload {
            crate::msgs::message::MessagePayload::Handshake(inner) => match &inner.payload {
                crate::msgs::handshake::HandshakePayload::ClientHello(ch) => ch,
                _ => unreachable!(),
            },
            _ => unreachable!(),
        }
    }
}

struct Accepting;

impl State<ServerConnectionData> for Accepting {
    fn handle(
        self: Box<Self>,
        _cx: &mut hs::ServerContext<'_>,
        _m: Message,
    ) -> Result<Box<dyn State<ServerConnectionData>>, Error> {
        Err(Error::General("unreachable state".into()))
    }
}

/// State associated with a server connection.
#[derive(Default)]
pub struct ServerConnectionData {
    pub(super) sni: Option<webpki::DnsName>,
    pub(super) received_resumption_data: Option<Vec<u8>>,
    pub(super) resumption_data: Vec<u8>,

    #[allow(dead_code)] // only supported for QUIC currently
    /// Whether to reject early data even if it would otherwise be accepted
    pub(super) reject_early_data: bool,
}

impl ServerConnectionData {
    pub(super) fn get_sni_str(&self) -> Option<&str> {
        self.sni.as_ref().map(AsRef::as_ref)
    }
}

impl crate::conn::SideData for ServerConnectionData {}

#[cfg(feature = "quic")]
impl quic::QuicExt for ServerConnection {
    fn quic_transport_parameters(&self) -> Option<&[u8]> {
        self.inner
            .common_state
            .quic
            .params
            .as_ref()
            .map(|v| v.as_ref())
    }

    fn zero_rtt_keys(&self) -> Option<quic::DirectionalKeys> {
        Some(quic::DirectionalKeys::new(
            self.inner
                .common_state
                .suite
                .and_then(|suite| suite.tls13())?,
            self.inner
                .common_state
                .quic
                .early_secret
                .as_ref()?,
        ))
    }

    fn read_hs(&mut self, plaintext: &[u8]) -> Result<(), Error> {
        self.inner.read_quic_hs(plaintext)
    }

    fn write_hs(&mut self, buf: &mut Vec<u8>) -> Option<quic::KeyChange> {
        quic::write_hs(&mut self.inner.common_state, buf)
    }

    fn alert(&self) -> Option<AlertDescription> {
        self.inner.common_state.quic.alert
    }
}

/// Methods specific to QUIC server sessions
#[cfg(feature = "quic")]
pub trait ServerQuicExt {
    /// Make a new QUIC ServerConnection. This differs from `ServerConnection::new()`
    /// in that it takes an extra argument, `params`, which contains the
    /// TLS-encoded transport parameters to send.
    fn new_quic(
        config: Arc<ServerConfig>,
        quic_version: quic::Version,
        params: Vec<u8>,
    ) -> Result<ServerConnection, Error> {
        if !config.supports_version(ProtocolVersion::TLSv1_3) {
            return Err(Error::General(
                "TLS 1.3 support is required for QUIC".into(),
            ));
        }

        if config.max_early_data_size != 0 && config.max_early_data_size != 0xffff_ffff {
            return Err(Error::General(
                "QUIC sessions must set a max early data of 0 or 2^32-1".into(),
            ));
        }

        let ext = match quic_version {
            quic::Version::V1Draft => ServerExtension::TransportParametersDraft(params),
            quic::Version::V1 => ServerExtension::TransportParameters(params),
        };
        let mut new = ServerConnection::from_config(config, vec![ext])?;
        new.inner.common_state.protocol = Protocol::Quic;
        Ok(new)
    }
}

#[cfg(feature = "quic")]
impl ServerQuicExt for ServerConnection {}
