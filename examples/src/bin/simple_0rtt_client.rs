//! This is an example client that uses rustls for TLS, and sends early 0-RTT data.
//!
//! Usage: cargo r --bin simple_0rtt_client --package rustls-examples [domain name] [port] [path/to/ca.cert]
//!
//! You may set the `SSLKEYLOGFILE` env var when using this example to write a
//! log file with key material (insecure) for debugging purposes. See [`rustls::KeyLog`]
//! for more information.
//!
//! Note that `unwrap()` is used to deal with networking errors; this is not something
//! that is sensible outside of example code.

use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;
use std::str::FromStr;
use std::sync::Arc;
use std::{env, fs};

use rustls::pki_types::ServerName;
use rustls::RootCertStore;

fn start_connection(config: &Arc<rustls::ClientConfig>, domain_name: &str, port: u16) {
    let server_name = ServerName::try_from(domain_name)
        .expect("invalid DNS name")
        .to_owned();
    let mut conn = rustls::ClientConnection::new(Arc::clone(config), server_name).unwrap();
    let mut sock = TcpStream::connect(format!("{}:{}", domain_name, port)).unwrap();
    sock.set_nodelay(true).unwrap();
    let request = format!(
        "GET / HTTP/1.1\r\n\
         Host: {}\r\n\
         Connection: close\r\n\
         Accept-Encoding: identity\r\n\
         \r\n",
        domain_name
    );

    // If early data is available with this server, then early_data()
    // will yield Some(WriteEarlyData) and WriteEarlyData implements
    // io::Write.  Use this to send the request.
    if let Some(mut early_data) = conn.early_data() {
        early_data
            .write_all(request.as_bytes())
            .unwrap();
        println!("  * 0-RTT request sent");
    }

    let mut stream = rustls::Stream::new(&mut conn, &mut sock);

    // Complete handshake.
    stream.flush().unwrap();

    // If we didn't send early data, or the server didn't accept it,
    // then send the request as normal.
    if !stream.conn.is_early_data_accepted() {
        stream
            .write_all(request.as_bytes())
            .unwrap();
        println!("  * Normal request sent");
    } else {
        println!("  * 0-RTT data accepted");
    }

    let mut first_response_line = String::new();
    BufReader::new(stream)
        .read_line(&mut first_response_line)
        .unwrap();
    println!("  * Server response: {:?}", first_response_line);
}

fn main() {
    env_logger::init();

    let mut args = env::args();
    args.next();
    let domain_name = args
        .next()
        .unwrap_or("jbp.io".to_owned());
    let port = args
        .next()
        .map(|port| u16::from_str(&port).expect("invalid port"))
        .unwrap_or(443);

    let mut root_store = RootCertStore::empty();
    if let Some(cafile) = args.next() {
        let certfile = fs::File::open(cafile).expect("Cannot open CA file");
        let mut reader = BufReader::new(certfile);
        root_store.add_parsable_certificates(
            rustls_pemfile::certs(&mut reader).map(|result| result.unwrap()),
        );
    } else {
        root_store.extend(
            webpki_roots::TLS_SERVER_ROOTS
                .iter()
                .cloned(),
        )
    }

    let mut config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    // Allow using SSLKEYLOGFILE.
    config.key_log = Arc::new(rustls::KeyLogFile::new());

    // Enable early data.
    config.enable_early_data = true;
    let config = Arc::new(config);

    // Do two connections. The first will be a normal request, the
    // second will use early data if the server supports it.

    println!("* Sending first request:");
    start_connection(&config, &domain_name, port);
    println!("* Sending second request:");
    start_connection(&config, &domain_name, port);
}
