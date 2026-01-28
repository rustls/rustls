use alloc::vec::Vec;
use core::fmt;
use core::hash::{Hash, Hasher};

use pki_types::{FipsStatus, SignatureVerificationAlgorithm};

// use super::anchors::RootCertStore;
// use super::pki_error;
use crate::crypto::SignatureScheme;
use crate::error::{Error, PeerMisbehaved};

/// Describes which `webpki` signature verification algorithms are supported and
/// how they map to TLS [`SignatureScheme`]s.
#[expect(clippy::exhaustive_structs)]
#[derive(Clone, Copy)]
pub struct WebPkiSupportedAlgorithms {
    /// A list of all supported signature verification algorithms.
    ///
    /// Used for verifying certificate chains.
    ///
    /// The order of this list is not significant.
    pub all: &'static [&'static dyn SignatureVerificationAlgorithm],

    /// A mapping from TLS `SignatureScheme`s to matching webpki signature verification algorithms.
    ///
    /// This is one (`SignatureScheme`) to many ([`SignatureVerificationAlgorithm`]) because
    /// (depending on the protocol version) there is not necessary a 1-to-1 mapping.
    ///
    /// For TLS1.2, all `SignatureVerificationAlgorithm`s are tried in sequence.
    ///
    /// For TLS1.3, only the first is tried.
    ///
    /// The supported schemes in this mapping is communicated to the peer and the order is significant.
    /// The first mapping is our highest preference.
    pub mapping: &'static [(
        SignatureScheme,
        &'static [&'static dyn SignatureVerificationAlgorithm],
    )],
}

impl WebPkiSupportedAlgorithms {
    /// Return all the `scheme` items in `mapping`, maintaining order.
    pub fn supported_schemes(&self) -> Vec<SignatureScheme> {
        self.mapping
            .iter()
            .map(|item| item.0)
            .collect()
    }

    // XXX TBD KEEP PRIVATE ???
    /// Return the first item in `mapping` that matches `scheme`.
    pub fn convert_scheme(
        &self,
        scheme: SignatureScheme,
    ) -> Result<&[&'static dyn SignatureVerificationAlgorithm], Error> {
        self.mapping
            .iter()
            .filter_map(|item| if item.0 == scheme { Some(item.1) } else { None })
            .next()
            .ok_or_else(|| PeerMisbehaved::SignedHandshakeWithUnadvertisedSigScheme.into())
    }

    /// Return the FIPS validation status of this implementation.
    pub fn fips(&self) -> FipsStatus {
        let algs = self
            .all
            .iter()
            .map(|alg| alg.fips_status())
            .min();
        let mapped = self
            .mapping
            .iter()
            .flat_map(|(_, algs)| algs.iter().map(|alg| alg.fips_status()))
            .min();

        match (algs, mapped) {
            (Some(algs), Some(mapped)) => Ord::min(algs, mapped),
            (Some(status), None) | (None, Some(status)) => status,
            (None, None) => FipsStatus::Unvalidated,
        }
    }
}

impl fmt::Debug for WebPkiSupportedAlgorithms {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "WebPkiSupportedAlgorithms {{ all: [ .. ], mapping: ")?;
        f.debug_list()
            .entries(self.mapping.iter().map(|item| item.0))
            .finish()?;
        write!(f, " }}")
    }
}

impl Hash for WebPkiSupportedAlgorithms {
    fn hash<H: Hasher>(&self, state: &mut H) {
        let Self { all, mapping } = self;

        write_algs(state, all);
        state.write_usize(mapping.len());
        for (scheme, algs) in *mapping {
            state.write_u16(u16::from(*scheme));
            write_algs(state, algs);
        }

        fn write_algs<H: Hasher>(
            state: &mut H,
            algs: &[&'static dyn SignatureVerificationAlgorithm],
        ) {
            state.write_usize(algs.len());
            for alg in algs {
                state.write(alg.public_key_alg_id().as_ref());
                state.write(alg.signature_alg_id().as_ref());
            }
        }
    }
}
