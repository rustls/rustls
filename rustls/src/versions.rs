use crate::enums::ProtocolVersion;
use crate::tls12::Tls12CipherSuite;
use crate::tls13::Tls13CipherSuite;

/// A TLS protocol version supported by rustls.
///
/// All possible values of this enum are provided by the library in
/// the [`ALL_VERSIONS`] array, as well as individually as [`TLS12`]
/// and [`TLS13`].
#[non_exhaustive]
#[derive(Debug)]
pub enum SupportedProtocolVersion {
    /// The TLS1.2 protocol version.
    TLS12(&'static Tls12Version),
    /// The TLS1.3 protocol version.
    TLS13(&'static Tls13Version),
}

impl SupportedProtocolVersion {
    /// The TLS enumeration naming this version.
    pub const fn version(&self) -> ProtocolVersion {
        match self {
            Self::TLS12(_) => ProtocolVersion::TLSv1_2,
            Self::TLS13(_) => ProtocolVersion::TLSv1_3,
        }
    }
}

impl PartialEq for SupportedProtocolVersion {
    fn eq(&self, other: &Self) -> bool {
        matches!(
            (self, other),
            (Self::TLS12(_), Self::TLS12(_)) | (Self::TLS13(_), Self::TLS13(_))
        )
    }
}

impl Eq for SupportedProtocolVersion {}

/// TLS1.2
pub static TLS12: SupportedProtocolVersion = SupportedProtocolVersion::TLS12(TLS12_VERSION);

/// TLS1.3
pub static TLS13: SupportedProtocolVersion = SupportedProtocolVersion::TLS13(TLS13_VERSION);

/// A list of all the protocol versions supported by rustls.
pub static ALL_VERSIONS: &[&SupportedProtocolVersion] = &[&TLS13, &TLS12];

/// The version configuration that an application should use by default.
///
/// This will be [`ALL_VERSIONS`] for now, but gives space in the future
/// to remove a version from here and require users to opt-in to older
/// versions.
pub static DEFAULT_VERSIONS: &[&SupportedProtocolVersion] = ALL_VERSIONS;

/// Internal data for handling the TLS1.2 protocol.
///
/// This value refers to TLS1.2 protocol handling code.  This means
/// that if your program does not refer to this value, all that code
/// can be removed by the linker.
pub static TLS12_VERSION: &Tls12Version = &Tls12Version {
    client: crate::client::TLS12_HANDLER,
    server: crate::server::TLS12_HANDLER,
};

/// Internal data for handling the TLS1.3 protocol.
///
/// This value refers to TLS1.3 protocol handling code.  This means
/// that if your program does not refer to this value, all that code
/// can be removed by the linker.
pub static TLS13_VERSION: &Tls13Version = &Tls13Version {
    client: crate::client::TLS13_HANDLER,
    server: crate::server::TLS13_HANDLER,
};

/// Internal data for handling the TLS1.2 protocol.
///
/// There is one value of this type.  It is `TLS12_VERSION`.
#[non_exhaustive]
#[derive(Debug)]
pub struct Tls12Version {
    pub(crate) client: &'static dyn crate::client::ClientHandler<Tls12CipherSuite>,
    pub(crate) server: &'static dyn crate::server::ServerHandler<Tls12CipherSuite>,
}

/// Internal data for handling the TLS1.3 protocol.
///
/// There is one value of this type.  It is `TLS13_VERSION`.
#[non_exhaustive]
#[derive(Debug)]
pub struct Tls13Version {
    pub(crate) client: &'static dyn crate::client::ClientHandler<Tls13CipherSuite>,
    pub(crate) server: &'static dyn crate::server::ServerHandler<Tls13CipherSuite>,
}
