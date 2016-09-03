#[allow(dead_code)]
mod common;
use common::OpenSSLServer;
use common::TlsServer;

use std::fs;

#[test]
fn alpn_offer() {
  if !common::openssl_server_supports_alpn() {
    common::skipped("needs openssl s_server with -alpn");
    return;
  }

  let mut server = OpenSSLServer::new_rsa(8100);
  server.arg("-alpn")
        .arg("ponytown,breakfast,edgware")
        .run();

  if !server.running() {
    println!("skipping test, couldn't start openssl with -alpn");
    return;
  }

  // Basic workingness.
  server.client()
    .proto("breakfast")
    .expect_log("ALPN protocol is Some(\"breakfast\")")
    .go();

  // Client preference has little effect (we're testing openssl here really)
  server.client()
    .proto("edgware")
    .proto("ponytown")
    .expect_log("ALPN protocol is Some(\"ponytown\")")
    .go();

  // No overlap should fail with an alert.
  // (Except it doesn't, because openssl rightly ignores this part
  // of the RFC.)
  server.client()
    .proto("mayfair")
    .expect_log("ALPN protocol is None")
    .go();

  server.kill();
}

#[test]
fn alpn_agree() {
  if !common::openssl_client_supports_alpn() {
    common::skipped("needs openssl s_client with -alpn");
    return;
  }

  let mut server = TlsServer::new(9100);
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
fn client_auth_by_client() {
  let mut server = OpenSSLServer::new_rsa(8500);
  server.arg("-verify").arg("0");
  server.run();

  server.client()
    .client_auth("test-ca/rsa/end.fullchain", "test-ca/rsa/end.rsa")
    .expect_log("Got CertificateRequest")
    .expect_log("Attempting client auth")
    .expect("Client certificate\n")
    .expect("Ciphers common between both SSL end points:\n")
    .go();

  server.kill();
}

#[test]
fn client_auth_requested_but_unsupported() {
  let mut server = OpenSSLServer::new_rsa(8600);
  server.arg("-verify").arg("0");
  server.run();

  server.client()
    .expect_log("Got CertificateRequest")
    .expect_log("Client auth requested but no cert/sigalg available")
    .expect("no client certificate available\n")
    .expect("Ciphers common between both SSL end points:\n")
    .go();

  server.kill();
}

#[test]
fn client_auth_required_but_unsupported() {
  let mut server = OpenSSLServer::new_rsa(8700);
  server.arg("-Verify").arg("0");
  server.run();

  server.client()
    .expect_log("Got CertificateRequest")
    .expect_log("Client auth requested but no cert/sigalg available")
    .expect("TLS error: AlertReceived(HandshakeFailure)")
    .fails()
    .go();

  server.kill();
}

#[test]
fn client_auth_by_server_accepted() {
  let mut server = TlsServer::new(9200);
  server.client_auth_roots("test-ca/rsa/client.chain")
        .http_mode()
        .run();

  /* Handshake works without client auth. */
  server.client()
    .expect("Acceptable client certificate CA names")
    .go();

  /* And with */
  server.client()
    .arg("-key").arg("test-ca/rsa/client.key")
    .arg("-cert").arg("test-ca/rsa/client.fullchain")
    .expect("Acceptable client certificate CA names")
    .go();

  server.kill();
}

#[test]
fn client_auth_by_server_required() {
  let mut server = TlsServer::new(9300);
  server.client_auth_roots("test-ca/rsa/client.chain")
        .client_auth_required()
        .http_mode()
        .run();

  /* Handshake *doesn't* work without client auth. */
  server.client()
    .fails()
    .expect_log("ssl handshake failure")
    .go();

  /* ... but does with. */
  server.client()
    .arg("-key").arg("test-ca/rsa/client.key")
    .arg("-cert").arg("test-ca/rsa/client.fullchain")
    .expect("Acceptable client certificate CA names")
    .go();

  server.kill();
}

#[test]
fn client_resumes() {
  let mut server = OpenSSLServer::new_rsa(8200);
  server.run();

  // no resumption without client support
  for _ in 0..2 {
    server.client()
      .expect_log("No cached session for")
      .expect_log("Not resuming any session")
      .go();
  }

  let cache_filename = "target/debug/session.cache";
  let _ = fs::remove_file(cache_filename);

  server.client()
    .cache(cache_filename)
    .expect_log("No cached session for")
    .expect_log("Not resuming any session")
    .expect("0 session cache hits")
    .expect("3 items in the session cache")
    .go();

  server.client()
    .cache(cache_filename)
    .expect_log("Resuming session")
    .expect_log("Server agreed to resume")
    .expect("1 session cache hits")
    .go();
}

#[test]
fn server_resumes() {
  let mut server = TlsServer::new(9600);
  server.resumes()
        .http_mode()
        .run();

  let sess1 = "target/debug/session1.ssl";
  let sess2 = "target/debug/session2.ssl";

  server.client()
    .arg("-sess_out").arg(sess1)
    .expect("New, TLSv1/SSLv3, Cipher is ECDHE-RSA-AES256-GCM-SHA384")
    .go();

  server.client()
    .arg("-sess_in").arg(sess1)
    .expect("Reused, TLSv1/SSLv3, Cipher is ECDHE-RSA-AES256-GCM-SHA384")
    .go();

  server.client()
    .arg("-sess_out").arg(sess2)
    .expect("New, TLSv1/SSLv3, Cipher is ECDHE-RSA-AES256-GCM-SHA384")
    .go();

  for _ in 0..2 {
    server.client()
      .arg("-sess_in").arg(sess1)
      .expect("Reused, TLSv1/SSLv3, Cipher is ECDHE-RSA-AES256-GCM-SHA384")
      .go();

    server.client()
      .arg("-sess_in").arg(sess2)
      .expect("Reused, TLSv1/SSLv3, Cipher is ECDHE-RSA-AES256-GCM-SHA384")
      .go();
  }
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
