#[allow(dead_code)]
mod common;
use crate::common::OpenSSLServer;
use crate::common::TlsServer;

use std::fs;

#[test]
fn alpn_offer() {
    if !common::openssl_server_supports_alpn() {
        common::skipped("needs openssl s_server with -alpn");
        return;
    }

    let test_ca = common::new_test_ca();

    let mut server = OpenSSLServer::new_rsa(test_ca.path(), 9000);
    server
        .arg("-alpn")
        .arg("ponytown,breakfast,edgware")
        .arg("-tls1_2")
        .run();

    if !server.running() {
        println!("skipping test, couldn't start openssl with -alpn");
        return;
    }

    // Basic workingness.
    server
        .client()
        .proto(b"breakfast")
        .expect_log("ALPN protocol is Some\\(b\"breakfast\"\\)")
        .go();

    // Client preference has little effect (we're testing openssl here really)
    server
        .client()
        .proto(b"edgware")
        .proto(b"ponytown")
        .expect_log("ALPN protocol is Some\\(b\"ponytown\"\\)")
        .go();

    server.kill();
}

#[test]
fn alpn_agree() {
    if !common::openssl_client_supports_alpn() {
        common::skipped("needs openssl s_client with -alpn");
        return;
    }

    let test_ca = common::new_test_ca();

    let mut server = TlsServer::new(test_ca.path(), 9010);
    server
        .proto(b"connaught")
        .proto(b"bonjour")
        .proto(b"egg")
        .http_mode()
        .run();

    // Like openssl we don't fail a handshake for no ALPN overlap.
    server
        .client()
        .arg("-alpn")
        .arg("coburn")
        .expect("No ALPN negotiated")
        .go();

    server
        .client()
        .arg("-alpn")
        .arg("bonjour")
        .expect("ALPN protocol: bonjour")
        .go();

    // client pref ignored
    server
        .client()
        .arg("-alpn")
        .arg("bonjour,connaught")
        .expect("ALPN protocol: connaught")
        .go();

    server.kill();
}

#[test]
fn client_auth_by_client() {
    let test_ca = common::new_test_ca();

    let mut server = OpenSSLServer::new_rsa(test_ca.path(), 9020);
    server
        .arg("-verify")
        .arg("0")
        .arg("-tls1_2");
    server.run();

    server
        .client()
        .client_auth(
            &test_ca
                .path()
                .join("rsa")
                .join("end.fullchain"),
            &test_ca
                .path()
                .join("rsa")
                .join("end.rsa"),
        )
        .expect_log("Got CertificateRequest")
        .expect_log("Attempting client auth")
        .expect("Client certificate\n")
        .expect("Ciphers common between both SSL end points:\n")
        .go();

    server.kill();
}

#[test]
fn client_auth_by_client_with_ecdsa_suite() {
    let test_ca = common::new_test_ca();

    let mut server = OpenSSLServer::new_ecdsa(test_ca.path(), 9025);
    server
        .arg("-verify")
        .arg("0")
        .arg("-tls1_2");
    server.run();

    server
        .client()
        .client_auth(
            &test_ca
                .path()
                .join("rsa")
                .join("end.fullchain"),
            &test_ca
                .path()
                .join("rsa")
                .join("end.rsa"),
        )
        .expect_log("Got CertificateRequest")
        .expect_log("Attempting client auth")
        .expect(r"AlertReceived\(UnknownCA\)")
        .fails()
        .go();

    server.kill();
}

#[test]
fn client_auth_by_client_with_eddsa_suite() {
    let test_ca = common::new_test_ca();

    let mut server = OpenSSLServer::new_eddsa(test_ca.path(), 9026);
    server
        .arg("-verify")
        .arg("0")
        .arg("-tls1_3");
    server.run();

    server
        .client()
        .client_auth(
            &test_ca
                .path()
                .join("rsa")
                .join("end.fullchain"),
            &test_ca
                .path()
                .join("rsa")
                .join("end.rsa"),
        )
        .expect_log("Got CertificateRequest")
        .expect_log("Attempting client auth")
        .expect(r"AlertReceived\(UnknownCA\)")
        .fails()
        .go();

    server.kill();
}

#[test]
fn client_auth_requested_but_unsupported() {
    let test_ca = common::new_test_ca();

    let mut server = OpenSSLServer::new_rsa(test_ca.path(), 9030);
    server
        .arg("-verify")
        .arg("0")
        .arg("-tls1_2");
    server.run();

    server
        .client()
        .expect_log("Got CertificateRequest")
        .expect_log("Client auth requested but no cert/sigscheme available")
        .expect("no client certificate available\n")
        .expect("Ciphers common between both SSL end points:\n")
        .go();

    server.kill();
}

#[test]
fn client_auth_required_but_unsupported() {
    let test_ca = common::new_test_ca();

    let mut server = OpenSSLServer::new_rsa(test_ca.path(), 9040);
    server
        .arg("-Verify")
        .arg("0")
        .arg("-tls1_2");
    server.run();

    server
        .client()
        .expect_log("Got CertificateRequest")
        .expect_log("Client auth requested but no cert/sigscheme available")
        .expect(r"TLS error: AlertReceived\(HandshakeFailure\)")
        .fails()
        .go();

    server.kill();
}

#[test]
fn client_auth_by_server_accepted() {
    let test_ca = common::new_test_ca();

    let mut server = TlsServer::new(test_ca.path(), 9050);
    server
        .client_auth_roots(
            &test_ca
                .path()
                .join("rsa")
                .join("client.chain"),
        )
        .http_mode()
        .run();

    // Handshake works without client auth.
    server
        .client()
        .expect("Acceptable client certificate CA names")
        .go();

    // And with
    server
        .client()
        .arg("-key")
        .arg(
            test_ca
                .path()
                .join("rsa")
                .join("client.key")
                .to_str()
                .unwrap(),
        )
        .arg("-cert")
        .arg(
            test_ca
                .path()
                .join("rsa")
                .join("client.fullchain")
                .to_str()
                .unwrap(),
        )
        .expect("Acceptable client certificate CA names")
        .go();

    server.kill();
}

#[test]
fn client_auth_by_server_required() {
    let test_ca = common::new_test_ca();

    let mut server = TlsServer::new(test_ca.path(), 9060);
    server
        .client_auth_roots(
            &test_ca
                .path()
                .join("rsa")
                .join("client.chain"),
        )
        .client_auth_required()
        .http_mode()
        .run();

    // Handshake *doesn't* work without client auth.
    server
        .client()
        .fails()
        .expect_log(r"(ssl handshake failure|verify return:1)")
        .go();

    // ... but does with.
    server
        .client()
        .arg("-key")
        .arg(
            test_ca
                .path()
                .join("rsa")
                .join("client.key")
                .to_str()
                .unwrap(),
        )
        .arg("-cert")
        .arg(
            test_ca
                .path()
                .join("rsa")
                .join("client.fullchain")
                .to_str()
                .unwrap(),
        )
        .expect("Acceptable client certificate CA names")
        .go();

    server.kill();
}

#[test]
fn client_resumes() {
    let test_ca = common::new_test_ca();

    let mut server = OpenSSLServer::new_rsa(test_ca.path(), 9070);
    server.arg("-tls1_2");
    server.run();

    // no resumption without client support
    for _ in 0..2 {
        server
            .client()
            .no_tickets()
            .expect_log("No cached session for")
            .expect_log("Not resuming any session")
            .go();
    }

    let cache_filename = "../target/debug/session.cache";
    let _ = fs::remove_file(cache_filename);

    server
        .client()
        .cache(cache_filename)
        .no_tickets()
        .expect_log("No cached session for")
        .expect_log("Not resuming any session")
        .expect("0 session cache hits")
        .expect("3 items in the session cache")
        .go();

    server
        .client()
        .cache(cache_filename)
        .no_tickets()
        .expect_log("Resuming session")
        .expect_log("Server agreed to resume")
        .expect("1 session cache hits")
        .go();
}

#[test]
fn server_resumes() {
    let test_ca = common::new_test_ca();

    let mut server = TlsServer::new(test_ca.path(), 9080);
    server.resumes().http_mode().run();

    let sess1 = "../target/debug/session1.ssl";
    let sess2 = "../target/debug/session2.ssl";

    server
        .client()
        .arg("-sess_out")
        .arg(sess1)
        .expect(r"New, (TLSv1/SSLv3|TLSv1\.2), Cipher is ECDHE-RSA-AES256-GCM-SHA384")
        .go();

    server
        .client()
        .arg("-sess_in")
        .arg(sess1)
        .expect(r"Reused, (TLSv1/SSLv3|TLSv1\.2), Cipher is ECDHE-RSA-AES256-GCM-SHA384")
        .go();

    server
        .client()
        .arg("-sess_out")
        .arg(sess2)
        .expect(r"New, (TLSv1/SSLv3|TLSv1\.2), Cipher is ECDHE-RSA-AES256-GCM-SHA384")
        .go();

    for _ in 0..2 {
        server
            .client()
            .arg("-sess_in")
            .arg(sess1)
            .expect(r"Reused, (TLSv1/SSLv3|TLSv1\.2), Cipher is ECDHE-RSA-AES256-GCM-SHA384")
            .go();

        server
            .client()
            .arg("-sess_in")
            .arg(sess2)
            .expect(r"Reused, (TLSv1/SSLv3|TLSv1\.2), Cipher is ECDHE-RSA-AES256-GCM-SHA384")
            .go();
    }
}

#[test]
fn server_resumes_with_tickets() {
    let test_ca = common::new_test_ca();

    let mut server = TlsServer::new(test_ca.path(), 9090);
    server.tickets().http_mode().run();

    let sess = "../target/debug/ticket.ssl";

    server
        .client()
        .arg("-sess_out")
        .arg(sess)
        .expect(r"New, (TLSv1/SSLv3|TLSv1\.2), Cipher is ECDHE-RSA-AES256-GCM-SHA384")
        .expect("TLS session ticket:")
        .expect(r"TLS session ticket lifetime hint: 43200 \(seconds\)")
        .go();

    for _ in 0..8 {
        server
            .client()
            .arg("-sess_in")
            .arg(sess)
            .expect(r"Reused, (TLSv1/SSLv3|TLSv1\.2), Cipher is ECDHE-RSA-AES256-GCM-SHA384")
            .expect("TLS session ticket:")
            .expect(r"TLS session ticket lifetime hint: 43200 \(seconds\)")
            .go();
    }
}

#[test]
fn recv_low_mtu() {
    let test_ca = common::new_test_ca();

    let mut server = OpenSSLServer::new_rsa(test_ca.path(), 9100);
    server.arg("-mtu").arg("32");
    server.run();

    server
        .client()
        .expect("Ciphers common between both SSL end points")
        .go();
}

#[test]
fn send_low_mtu() {
    let test_ca = common::new_test_ca();

    let mut server = OpenSSLServer::new_rsa(test_ca.path(), 9110);
    server.run();

    server
        .client()
        .mtu(128)
        .expect("Ciphers common between both SSL end points")
        .go();
}

#[test]
fn send_sni() {
    let test_ca = common::new_test_ca();

    let mut server = OpenSSLServer::new_rsa(test_ca.path(), 9115);
    server
        .arg("-servername_fatal")
        .arg("-servername")
        .arg("not-localhost");
    server.run();

    server
        .client()
        .fails()
        .expect(r"TLS error: AlertReceived\(UnrecognisedName\)")
        .go();
}

#[test]
fn do_not_send_sni() {
    let test_ca = common::new_test_ca();

    let mut server = OpenSSLServer::new_rsa(test_ca.path(), 9116);
    server
        .arg("-servername_fatal")
        .arg("-servername")
        .arg("not-localhost");
    server.run();

    server
        .client()
        .no_sni()
        .expect("Ciphers common between both SSL end points")
        .go();
}
