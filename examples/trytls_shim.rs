// A Rustls stub for TryTLS
//
// Author: Joachim Viide
// See: https://github.com/HowNetWorks/trytls-rustls-stub
//

extern crate rustls;
extern crate webpki_roots;

use std::io::{Read, Write, BufReader};
use std::net::TcpStream;
use std::sync::Arc;
use std::fs::File;
use std::error::Error;
use std::process;
use std::env;
use rustls::{ClientConfig, ClientSession, Session, TLSError};

enum Verdict {
    Accept,
    Reject(TLSError),
}

fn parse_args(args: &Vec<String>) -> Result<(String, u16, ClientConfig), Box<Error>> {
    let mut config = ClientConfig::new();
    match args.len() {
        3 => {
            config.root_store.add_trust_anchors(&webpki_roots::ROOTS);
        }
        4 => {
            let f = try!(File::open(&args[3]));
            let mut f = BufReader::new(f);
            if let Err(_) = config.root_store.add_pem_file(&mut f) {
                return Err(From::from("Could not load PEM data"));
            }
        }
        _ => {
            return Err(From::from("Incorrect number of arguments"));
        }
    };
    let port = try!(args[2].parse());
    Ok((args[1].clone(), port, config))
}

fn communicate(host: String, port: u16, config: ClientConfig) -> Result<Verdict, Box<Error>> {
    let rc_config = Arc::new(config);
    let mut client = ClientSession::new(&rc_config, &host);
    let mut stream = try!(TcpStream::connect((&*host, port)));

    try!(client.write(b"GET / HTTP/1.0\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"));
    loop {
        while client.wants_write() {
            try!(client.write_tls(&mut stream));
        }

        if client.wants_read() {
            if try!(client.read_tls(&mut stream)) == 0 {
                return Err(From::from("Connection closed"));
            }

            if let Err(err) = client.process_new_packets() {
                return match err {
                    TLSError::WebPKIError(_) |
                    TLSError::AlertReceived(_) => Ok(Verdict::Reject(err)),
                    _ => Err(From::from(format!("{:?}", err))),
                };
            }

            if try!(client.read(&mut [0])) > 0 {
                return Ok(Verdict::Accept);
            }
        }
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let (host, port, config) = parse_args(&args).unwrap_or_else(|err| {
        println!("Argument error: {}", err);
        process::exit(2);
    });

    match communicate(host, port, config) {
        Ok(Verdict::Accept) => {
            println!("ACCEPT");
            process::exit(0);
        }
        Ok(Verdict::Reject(reason)) => {
            println!("{:?}", reason);
            println!("REJECT");
            process::exit(0);
        }
        Err(err) => {
            println!("{}", err);
            process::exit(1);
        }
    }
}
