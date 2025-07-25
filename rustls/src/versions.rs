use core::fmt;

use crate::enums::ProtocolVersion;

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
    pub(crate) client: &'static dyn crate::client::Tls12Handler,
    pub(crate) server: &'static dyn crate::server::Tls12Handler,
}

/// Internal data for handling the TLS1.3 protocol.
///
/// There is one value of this type.  It is `TLS13_VERSION`.
#[non_exhaustive]
#[derive(Debug)]
pub struct Tls13Version {
    pub(crate) client: &'static dyn crate::client::Tls13Handler,
    pub(crate) server: &'static dyn crate::server::Tls13Handler,
}

#[derive(Clone, Copy)]
pub(crate) struct EnabledVersions {
    tls12: Option<&'static SupportedProtocolVersion>,
    tls13: Option<&'static SupportedProtocolVersion>,
}

impl fmt::Debug for EnabledVersions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut list = &mut f.debug_list();
        if let Some(v) = self.tls12 {
            list = list.entry(v);
        }
        if let Some(v) = self.tls13 {
            list = list.entry(v);
        }
        list.finish()
    }
}

impl EnabledVersions {
    pub(crate) fn new(versions: &[&'static SupportedProtocolVersion]) -> Self {
        let mut ev = Self {
            tls12: None,
            tls13: None,
        };

        for v in versions {
            match v.version() {
                ProtocolVersion::TLSv1_2 => ev.tls12 = Some(v),
                ProtocolVersion::TLSv1_3 => ev.tls13 = Some(v),
                _ => {}
            }
        }

        ev
    }

    pub(crate) fn contains(&self, version: ProtocolVersion) -> bool {
        match version {
            ProtocolVersion::TLSv1_2 => self.tls12.is_some(),
            ProtocolVersion::TLSv1_3 => self.tls13.is_some(),
            _ => false,
        }
    }
}
