use rustls::crypto::aws_lc_rs::default_provider;
use rustls::crypto::CryptoProvider;

/// A `CryptoProvider` which includes `X25519Kyber768Draft00` key exchange.
pub fn provider() -> CryptoProvider {
    default_provider()
}
