/* Engineer a handshake using each curve. */

#[allow(dead_code)]
mod common;
use common::OpenSSLServer;

#[test]
fn curve_nistp256() {
  let mut server = OpenSSLServer::new(8300);
  server.arg("-named_curve").arg("prime256v1");
  server.run();
  server.client()
    .verbose()
    .expect_log("ECDHE curve is ECParameters { curve_type: NamedCurve, named_curve: secp256r1 }")
    .go();
  server.kill();
}

#[test]
fn curve_nistp384() {
  let mut server = OpenSSLServer::new(8400);
  server.arg("-named_curve").arg("secp384r1");
  server.run();
  server.client()
    .verbose()
    .expect_log("ECDHE curve is ECParameters { curve_type: NamedCurve, named_curve: secp384r1 }")
    .go();
  server.kill();
}
