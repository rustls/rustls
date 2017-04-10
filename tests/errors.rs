// Things we don't expect to work.

#[allow(dead_code)]
mod common;
use common::OpenSSLServer;

#[test]
fn no_tls12() {
    let mut server = OpenSSLServer::new_rsa(8000);
    server.arg("-no_tls1_2");
    server.run();

    server.client()
        .verbose()
        .fails()
        .expect_log("TLS alert received:")
        .expect(r"TLS error: AlertReceived\(HandshakeFailure\)")
        .go();
}

#[test]
fn no_ecdhe() {
    let mut server = OpenSSLServer::new_rsa(8010);
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
    let mut server = OpenSSLServer::new_rsa(8020);
    server.arg("-tls1_1");
    server.run();

    server.client()
        .verbose()
        .fails()
        .expect_log("TLS alert received:")
        .expect(r"TLS error: AlertReceived\(HandshakeFailure\)")
        .go();
}
