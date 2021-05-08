use crate::msgs::codec::{self, Codec, Reader};

use std::fmt;

/// This type contains a private key by value.
///
/// The private key must be DER-encoded ASN.1 in either
/// PKCS#8 or PKCS#1 format.
///
/// The `rustls-pemfile` crate can be used to extract
/// private keys from a PEM file in these formats.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct PrivateKey(pub Vec<u8>);

/// This type contains a single certificate by value.
///
/// The certificate must be DER-encoded X.509.
///
/// The `rustls-pemfile` crate can be used to parse a PEM file.
///
/// ## Note
///
/// If you are receiving certificates from an untrusted client or server, the contents
/// must be validated manually.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Certificate(pub Vec<u8>);

impl Codec for Certificate {
    fn encode(&self, bytes: &mut Vec<u8>) {
        codec::u24(self.0.len() as u32).encode(bytes);
        bytes.extend_from_slice(&self.0);
    }

    fn read(r: &mut Reader) -> Option<Self> {
        let len = codec::u24::read(r)?.0 as usize;
        let mut sub = r.sub(len)?;
        let body = sub.rest().to_vec();
        Some(Self(body))
    }
}

impl AsRef<[u8]> for Certificate {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for Certificate {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use super::bs_debug::BsDebug;
        f.debug_tuple("Certificate")
            .field(&BsDebug(&self.0))
            .finish()
    }
}

#[cfg(test)]
mod test {
    use super::Certificate;

    #[test]
    fn certificate_debug() {
        assert_eq!(
            "Certificate(b\"ab\")",
            format!("{:?}", Certificate(b"ab".to_vec()))
        );
    }
}
