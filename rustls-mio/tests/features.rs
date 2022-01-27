#[allow(dead_code)]
mod common;
use crate::common::OpenSSLServer;

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
fn send_small_fragments() {
    let test_ca = common::new_test_ca();

    let mut server = OpenSSLServer::new_rsa(test_ca.path(), 9110);
    server.run();

    server
        .client()
        .max_fragment_size(128)
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
