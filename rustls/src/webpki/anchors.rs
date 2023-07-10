use pki_types::{CertificateDer, TrustAnchor};
use webpki::extract_trust_anchor;

use super::pki_error;
#[cfg(feature = "logging")]
use crate::log::{debug, trace};
use crate::x509;
use crate::DistinguishedName;
use crate::Error;

/// A trust anchor, commonly known as a "Root Certificate."
#[derive(Debug, Clone)]
pub struct TrustAnchorWithDn {
    subject_dn: DistinguishedName,
    inner: TrustAnchor<'static>,
}

impl TrustAnchorWithDn {
    /// Return the subject field including its outer SEQUENCE encoding.
    ///
    /// This can be decoded using [x509-parser's FromDer trait](https://docs.rs/x509-parser/latest/x509_parser/prelude/trait.FromDer.html).
    ///
    /// ```ignore
    /// use x509_parser::prelude::FromDer;
    /// println!("{}", x509_parser::x509::X509Name::from_der(anchor.subject())?.1);
    /// ```
    pub fn subject(&self) -> &DistinguishedName {
        &self.subject_dn
    }

    /// Get a `TrustAnchor` by borrowing the owned elements.
    pub(crate) fn inner(&self) -> &TrustAnchor<'static> {
        &self.inner
    }
}

impl From<TrustAnchor<'static>> for TrustAnchorWithDn {
    fn from(inner: TrustAnchor<'static>) -> Self {
        let mut subject = inner.subject.as_ref().to_owned();
        x509::wrap_in_sequence(&mut subject);

        Self {
            subject_dn: DistinguishedName::from(subject),
            inner,
        }
    }
}

/// A container for root certificates able to provide a root-of-trust
/// for connection authentication.
#[derive(Debug, Clone)]
pub struct RootCertStore {
    /// The list of roots.
    pub roots: Vec<TrustAnchorWithDn>,
}

impl RootCertStore {
    /// Make a new, empty `RootCertStore`.
    pub fn empty() -> Self {
        Self { roots: Vec::new() }
    }

    /// Return true if there are no certificates.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Say how many certificates are in the container.
    pub fn len(&self) -> usize {
        self.roots.len()
    }

    /// Add a single DER-encoded certificate to the store.
    ///
    /// This is suitable for a small set of root certificates that are expected to parse
    /// successfully. For large collections of roots (for example from a system store) it
    /// is expected that some of them might not be valid according to the rules rustls
    /// implements. As long as a relatively limited number of certificates are affected,
    /// this should not be a cause for concern. Use [`RootCertStore::add_parsable_certificates`]
    /// in order to add as many valid roots as possible and to understand how many certificates
    /// have been diagnosed as malformed.
    pub fn add(&mut self, der: CertificateDer<'_>) -> Result<(), Error> {
        self.roots.push(TrustAnchorWithDn::from(
            extract_trust_anchor(&der)
                .map_err(pki_error)?
                .to_owned(),
        ));
        Ok(())
    }

    /// Adds all the given TrustAnchors `anchors`.  This does not fail.
    pub fn add_trust_anchors(&mut self, trust_anchors: impl Iterator<Item = TrustAnchor<'static>>) {
        self.roots
            .extend(trust_anchors.map(|ta| ta.into()));
    }

    /// Parse the given DER-encoded certificates and add all that can be parsed
    /// in a best-effort fashion.
    ///
    /// This is because large collections of root certificates often
    /// include ancient or syntactically invalid certificates.
    ///
    /// Returns the number of certificates added, and the number that were ignored.
    pub fn add_parsable_certificates<'a>(
        &mut self,
        der_certs: impl IntoIterator<Item = CertificateDer<'a>>,
    ) -> (usize, usize) {
        let mut valid_count = 0;
        let mut invalid_count = 0;

        for der_cert in der_certs {
            #[cfg_attr(not(feature = "logging"), allow(unused_variables))]
            match extract_trust_anchor(&der_cert) {
                Ok(anchor) => {
                    self.roots
                        .push(TrustAnchorWithDn::from(anchor.to_owned()));
                    valid_count += 1;
                }
                Err(err) => {
                    trace!("invalid cert der {:?}", der_cert.as_ref());
                    debug!("certificate parsing failed: {:?}", err);
                    invalid_count += 1;
                }
            };
        }

        debug!(
            "add_parsable_certificates processed {} valid and {} invalid certs",
            valid_count, invalid_count
        );

        (valid_count, invalid_count)
    }
}

#[cfg(test)]
mod tests {
    use super::TrustAnchorWithDn;
    use pki_types::TrustAnchor;

    #[test]
    fn ownedtrustanchor_subject_is_correctly_encoding_dn() {
        let ta = TrustAnchor {
            subject: b"subject"[..].into(),
            subject_public_key_info: [][..].into(),
            name_constraints: None,
        };

        let with_dn = TrustAnchorWithDn::from(ta.clone());
        let expected_prefix = vec![0x30, ta.subject.len() as u8];
        assert_eq!(
            with_dn.subject().as_ref(),
            [expected_prefix, ta.subject.to_vec()].concat()
        );
    }
}
