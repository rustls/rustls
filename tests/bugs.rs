#[allow(dead_code)]
mod common;
use common::OpenSSLServer;

// Test where the server gives certificates A -> B where the
// validation path is A -> B -> C where C is a trust root
// but B is not.
#[test]
fn partial_chain() {
    let mut server = OpenSSLServer::new_rsa(3000);
    server.partial_chain();
    server.run();
    server.client()
        .verbose()
        .expect("Ciphers common between both SSL end points:")
        .go();
    server.kill();
}
