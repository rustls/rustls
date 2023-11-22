use crate::crypto::signer;

use pki_types::CertificateDer;

/// ActiveCertifiedKey wraps [`signer::CertifiedKey`] and tracks OSCP state in a single handshake.
pub(super) struct ActiveCertifiedKey<'a> {
    key: &'a signer::CertifiedKey,
    ocsp: Option<&'a [u8]>,
}

impl<'a> ActiveCertifiedKey<'a> {
    pub(super) fn from_certified_key(key: &signer::CertifiedKey) -> ActiveCertifiedKey {
        ActiveCertifiedKey {
            key,
            ocsp: key.ocsp.as_deref(),
        }
    }

    /// Get the certificate chain
    #[inline]
    pub(super) fn get_cert(&self) -> &[CertificateDer<'static>] {
        &self.key.cert
    }

    /// Get the signing key
    #[inline]
    pub(super) fn get_key(&self) -> &dyn signer::SigningKey {
        &*self.key.key
    }

    #[inline]
    pub(super) fn get_ocsp(&self) -> Option<&[u8]> {
        self.ocsp
    }
}
