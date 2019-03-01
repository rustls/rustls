// Engineer a handshake using each curve.

#[allow(dead_code)]
mod common;
use crate::common::OpenSSLServer;

#[test]
fn curve_nistp256() {
    let test_ca = common::new_test_ca();

    let mut server = OpenSSLServer::new_rsa(test_ca.path(), 4000);
    server.arg("-named_curve").arg("prime256v1");
    server.run();
    server.client()
        .verbose()
        .expect_log(r"(ECDHE curve is ECParameters \{ curve_type: NamedCurve, named_group: secp256r1 \}|group: secp256r1)")
        .go();
    server.kill();
}

#[test]
fn curve_nistp384() {
    let test_ca = common::new_test_ca();

    let mut server = OpenSSLServer::new_rsa(test_ca.path(), 4010);
    server.arg("-named_curve").arg("secp384r1");
    server.run();
    server.client()
        .verbose()
        .expect_log(r"(ECDHE curve is ECParameters \{ curve_type: NamedCurve, named_group: secp384r1 \}|group: secp384r1)")
        .go();
    server.kill();
}
