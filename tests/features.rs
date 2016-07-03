#[allow(dead_code)]
mod common;
use common::OpenSSLServer;
use common::TlsServer;

use std::fs;

#[test]
fn alpn_offer() {
  let mut server = OpenSSLServer::new_rsa(8100);
  server.arg("-alpn")
        .arg("ponytown,breakfast,edgware")
        .args_need_openssl_1_0_2();
  server.run();

  if !server.running() {
    println!("skipping test, couldn't start openssl with -alpn");
    return;
  }

  // Basic workingness.
  server.client()
    .verbose()
    .proto("breakfast")
    .expect_log("ALPN protocol is Some(\"breakfast\")")
    .go();

  // Client preference has little effect (we're testing openssl here really)
  server.client()
    .verbose()
    .proto("edgware")
    .proto("ponytown")
    .expect_log("ALPN protocol is Some(\"ponytown\")")
    .go();

  // No overlap should fail with an alert.
  // (Except it doesn't, because openssl rightly ignores this part
  // of the RFC.)
  server.client()
    .verbose()
    .proto("mayfair")
    .expect_log("ALPN protocol is None")
    .go();

  server.kill();
}

#[test]
fn alpn_agree() {
  let mut server = TlsServer::new(7100);
  server.proto("connaught")
        .proto("bonjour")
        .proto("egg")
        .http_mode()
        .run();

  /* Like openssl we don't fail a handshake for no ALPN overlap. */
  server.client()
        .arg("-alpn").arg("coburn")
        .expect("No ALPN negotiated")
        .go();

  server.client()
        .arg("-alpn").arg("bonjour")
        .expect("ALPN protocol: bonjour")
        .go();

  /* client pref ignored */
  server.client()
        .arg("-alpn").arg("bonjour,connaught")
        .expect("ALPN protocol: connaught")
        .go();

  server.kill();
}

#[test]
fn resumption() {
  let mut server = OpenSSLServer::new_rsa(8200);
  server.run();

  // no resumption without client support
  for _ in 0..2 {
    server.client()
      .verbose()
      .expect_log("No cached session for")
      .expect_log("Not resuming any session")
      .go();
  }

  let cache_filename = "target/debug/session.cache";
  let _ = fs::remove_file(cache_filename);

  server.client()
    .verbose()
    .cache(cache_filename)
    .expect_log("No cached session for")
    .expect_log("Not resuming any session")
    .expect("0 session cache hits")
    .expect("3 items in the session cache")
    .go();

  server.client()
    .verbose()
    .cache(cache_filename)
    .expect_log("Resuming session")
    .expect_log("Server agreed to resume")
    .expect("1 session cache hits")
    .go();
}

#[test]
fn recv_low_mtu() {
  let mut server = OpenSSLServer::new_rsa(8300);
  server.arg("-mtu").arg("32");
  server.run();

  server.client()
    .expect("Ciphers common between both SSL end points")
    .go();
}

#[test]
fn send_low_mtu() {
  let mut server = OpenSSLServer::new_rsa(8400);
  server.run();

  server.client()
    .mtu(128)
    .expect("Ciphers common between both SSL end points")
    .go();
}
