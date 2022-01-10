use crate::msgs::enums::ProtocolVersion;

/// A TLS protocl version supported by rustls.
///
/// All possible instances of this class are provided by the library in
/// the [`ALL_VERSIONS`] array, as well as individually as [`TLS12`]
/// and [`TLS13`].
#[derive(Debug, PartialEq)]
pub struct SupportedProtocolVersion {
    /// The TLS enumeration naming this version.
    pub version: ProtocolVersion,
    is_private: (),
}

/// TLS1.2
#[cfg(feature = "tls12")]
pub static TLS12: SupportedProtocolVersion = SupportedProtocolVersion {
    version: ProtocolVersion::TLSv1_2,
    is_private: (),
};

/// TLS1.3
pub static TLS13: SupportedProtocolVersion = SupportedProtocolVersion {
    version: ProtocolVersion::TLSv1_3,
    is_private: (),
};

/// A list of all the protocol versions supported by rustls.
///
// This needs to be kept in sync with the `impl Default for EnabledVersions`.
pub static ALL_VERSIONS: &[&SupportedProtocolVersion] = &[
    &TLS13,
    #[cfg(feature = "tls12")]
    &TLS12,
];

/// The version configuration that an application should use by default.
///
/// This will be [`ALL_VERSIONS`] for now, but gives space in the future
/// to remove a version from here and require users to opt-in to older
/// versions.
//
// This needs to be kept in sync with the `impl Default for EnabledVersions`.
pub static DEFAULT_VERSIONS: &[&SupportedProtocolVersion] = ALL_VERSIONS;

#[derive(Debug, Clone, Copy)]
pub(crate) enum EnabledVersions {
    #[cfg(feature = "tls12")]
    All,
    Tls13,
    #[cfg(feature = "tls12")]
    Tls12,
}

impl EnabledVersions {
    pub(crate) fn new(versions: &[&'static SupportedProtocolVersion]) -> Option<Self> {
        let tls13 = versions.iter().any(|v| *v == &TLS13);

        #[cfg(feature = "tls12")]
        {
            let tls12 = versions.iter().any(|v| *v == &TLS12);
            match (tls12, tls13) {
                (true, true) => Some(Self::All),
                (true, false) => Some(Self::Tls12),
                (false, true) => Some(Self::Tls13),
                (false, false) => None,
            }
        }
        #[cfg(not(feature = "tls12"))]
        {
            tls13.then(|| Self::Tls13)
        }
    }

    pub(crate) fn contains(&self, version: ProtocolVersion) -> bool {
        match (version, self) {
            #[cfg(feature = "tls12")]
            (ProtocolVersion::TLSv1_2, Self::All) | (ProtocolVersion::TLSv1_2, Self::Tls12) => true,
            #[cfg(feature = "tls12")]
            (ProtocolVersion::TLSv1_3, Self::All) => true,
            (ProtocolVersion::TLSv1_3, Self::Tls13) => true,
            _ => false,
        }
    }
}

impl Default for EnabledVersions {
    fn default() -> Self {
        #[cfg(feature = "tls12")]
        {
            Self::All
        }
        #[cfg(not(feature = "tls12"))]
        {
            Self::Tls13
        }
    }
}
