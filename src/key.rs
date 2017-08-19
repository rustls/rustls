/// This type contains a private key by value.
///
/// The private key must be DER-encoded ASN.1 in either
/// PKCS#8 or PKCS#1 format.
///
/// `rustls::pemfile::pkcs8_private_keys` or `rustls::pemfile::rsa_private_keys`
/// could be used to extract private keys from a PEM file in these formats.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct PrivateKey(pub Vec<u8>);

/// This type contains a single certificate by value.
///
/// The certificate must be DER-encoded X.509.
///
/// `rustls::pemfile::certs` function can be used to parse a PEM file.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Certificate(pub Vec<u8>);

impl AsRef<[u8]> for Certificate {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}
