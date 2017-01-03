// Engineer a handshake using each suite supported by both
// us and openssl

#[allow(dead_code)]
mod common;
use common::TlsServer;

#[test]
fn ecdhe_rsa_aes_128_gcm_sha256() {
    let mut server = TlsServer::new(7000);

    server.echo_mode()
        .suite("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256")
        .run();

    server.client()
        .expect("Cipher    : ECDHE-RSA-AES128-GCM-SHA256")
        .go();

    server.kill();
}

#[test]
fn ecdhe_rsa_aes_256_gcm_sha384() {
    let mut server = TlsServer::new(7010);

    server.echo_mode()
        .suite("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384")
        .run();

    server.client()
        .expect("Cipher    : ECDHE-RSA-AES256-GCM-SHA384")
        .go();

    server.kill();
}

// cannot do ecdsa tls_ecdhe_ecdsa_* because we don't support ECDSA
// signing yet.
// cannot do chacha20poly1305 because openssl doesn't support it.
