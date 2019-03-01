// Things we don't expect to work.

#[allow(dead_code)]
mod common;
use crate::common::OpenSSLServer;

#[test]
fn no_ecdhe() {
    let test_ca = common::new_test_ca();

    let mut server = OpenSSLServer::new_rsa(test_ca.path(), 8010);
    if common::openssl_server_supports_no_echde() {
        server.arg("-no_ecdhe");
    } else {
        common::skipped("openssl s_server -no_ecdhe");
        return;
    }
    server.run();

    server.client()
        .verbose()
        .fails()
        .expect_log("TLS alert received:")
        .expect(r"TLS error: AlertReceived\(HandshakeFailure\)")
        .go();
}

#[test]
fn tls11_only() {
    let test_ca = common::new_test_ca();

    let mut server = OpenSSLServer::new_rsa(test_ca.path(), 8020);
    server.arg("-tls1_1");
    server.run();

    server.client()
        .verbose()
        .fails()
        .expect_log("TLS alert received:")
        .expect(r"TLS error: AlertReceived\((HandshakeFailure|ProtocolVersion)\)")
        .go();
}
