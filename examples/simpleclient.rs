use std::sync::Arc;

use std::net::TcpStream;
use std::io::{Read, Write, stdout};

extern crate rustls;
extern crate webpki_roots;

use rustls::Session;

fn main() {
    let mut config = rustls::ClientConfig::new();
    config.root_store.add_trust_anchors(&webpki_roots::ROOTS);

    let mut tls = rustls::ClientSession::new(&Arc::new(config), "google.com");
    tls.write(concat!("GET / HTTP/1.1\r\n",
                      "Host: google.com\r\n",
                      "Connection: close\r\n",
                      "Accept-Encoding: identity\r\n",
                      "\r\n")
              .as_bytes())
        .unwrap();

    let mut sock = TcpStream::connect("google.com:443").unwrap();
    loop {
        let (rl, wl) = tls.complete_io(&mut sock).unwrap();
        if rl == 0 && wl == 0 {
            println!("EOF");
            break;
        }

        let mut plaintext = Vec::new();
        tls.read_to_end(&mut plaintext).unwrap();
        stdout().write_all(&plaintext).unwrap();
    }
}
