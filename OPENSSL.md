# Migrating from OpenSSL
Here are some guidelines and hint how to migrate from the [OpenSSL](https://docs.rs/openssl/latest/openssl/).

**This page is incomplete, and can use some help.**

### Create a builder
```rust
// OpenSSL
use openssl::ssl::{SslConnector, SslMethod};
let mut builder = SslConnector::builder(SslMethod::tls());
```
```rust
// Rustls
let mut builder = rustls::ClientConfig::builder().with_safe_defaults();
```

### Add a root CA file
```rust
// OpenSSL
builder.set_ca_file(ca_root_file)?;
```
```rust
// Rustls
let reader = File::open(ca_root_file)?;
for cert in rustls_pemfile::certs(&mut BufReader::new(reader))? {
    roots.add(&rustls::Certificate(cert))?;
}
```

### Disable certificate validation (dangerous!)
```rust
// OpenSSL
builder.set_verify(SslVerifyMode::NONE);
```
```rust
// Rustls
struct NoCertificateVerification {}
impl rustls::client::ServerCertVerifier for NoCertificateVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::Certificate,
        _intermediates: &[rustls::Certificate],
        _server_name: &rustls::ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp: &[u8],
        _now: std::time::SystemTime,
    ) -> Result<rustls::client::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::ServerCertVerified::assertion())
    }
}

builder.dangerous().set_certificate_verifier(Arc::new(NoCertificateVerification {}));
```

### Finalize builder
```rust
// OpenSSL
let clientConfig = builder.build();
```
```rust
// Rustls
let clientConfig = builder.with_no_client_auth();
```
