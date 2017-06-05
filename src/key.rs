/// This type contains a private key by value.
///
/// Private key must be in either PKCS8 or DER-encoded ASN.1.
///
/// `rustls::pemfile::pkcs8_private_keys` or `rustls::pemfile::pkcs8_private_keys`
/// could be used to extract private keys from PEM file.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct PrivateKey(pub Vec<u8>);

/// This type contains a single certificate by value.
///
/// Certificate must be ASN.1 DER-encoded X.509.
///
/// `rustls::pemfile::certs` function can be used to parse PEM file.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Certificate(pub Vec<u8>);
