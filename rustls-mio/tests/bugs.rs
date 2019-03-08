#[allow(dead_code)]
mod common;
use crate::common::OpenSSLServer;

// Test where the server gives certificates A -> B where the
// validation path is A -> B -> C where C is a trust root
// but B is not.
#[test]
fn partial_chain() {
    let test_ca = common::new_test_ca();

    let mut server = OpenSSLServer::new_rsa(test_ca.path(), 3000);
    server.partial_chain();
    server.run();
    server.client()
        .verbose()
        .expect("Ciphers common between both SSL end points:")
        .go();
    server.kill();
}
