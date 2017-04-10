// Engineer a handshake using each curve.

#[allow(dead_code)]
mod common;
use common::OpenSSLServer;

#[test]
fn curve_nistp256() {
    let mut server = OpenSSLServer::new_rsa(4000);
    server.arg("-named_curve").arg("prime256v1");
    server.run();
    server.client()
        .verbose()
        .expect_log(r"ECDHE curve is ECParameters \{ curve_type: NamedCurve, named_group: secp256r1 \}")
        .go();
    server.kill();
}

#[test]
fn curve_nistp384() {
    let mut server = OpenSSLServer::new_rsa(4010);
    server.arg("-named_curve").arg("secp384r1");
    server.run();
    server.client()
        .verbose()
        .expect_log(r"ECDHE curve is ECParameters \{ curve_type: NamedCurve, named_group: secp384r1 \}")
        .go();
    server.kill();
}
