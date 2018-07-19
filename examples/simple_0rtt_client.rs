use std::sync::Arc;

use std::io::{stdout, Read, Write};
use std::net::TcpStream;

extern crate rustls;
extern crate webpki;
extern crate webpki_roots;
extern crate env_logger;

fn start_session(config: &Arc<rustls::ClientConfig>, domain_name: &str) {
    let dns_name = webpki::DNSNameRef::try_from_ascii_str(domain_name).unwrap();
    let mut sess = rustls::ClientSession::new(config, dns_name);
    let mut sock = TcpStream::connect(format!("{}:443", domain_name)).unwrap();
    sock.set_nodelay(true).unwrap();
    let mut stream = rustls::Stream::new(&mut sess, &mut sock);
    let request = format!(
        "GET / HTTP/1.1\r\n\
         Host: {}\r\n\
         Connection: close\r\n\
         Accept-Encoding: identity\r\n\
         \r\n",
        domain_name
    );

    stream.write_all(request.as_bytes()).unwrap();
    let mut plaintext = Vec::new();
    stream.read_to_end(&mut plaintext).unwrap();
    stdout().write_all(&plaintext).unwrap();
}

fn main() {
    env_logger::init();
    let mut config = rustls::ClientConfig::new();
    config.enable_early_data = true;
    config
        .root_store
        .add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);
    let config = Arc::new(config);
    start_session(&config, "mesalink.io");
    start_session(&config, "mesalink.io");
}
