#![deny(unsafe_code)]
#![no_main]
#![no_std]

use ministd::{entry, io, net::ToSocketAddrs, println};

entry!(main);

fn main() -> io::Result<()> {
    let server_name = "www.rust-lang.org";
    let port = 443;
    let ip_addrs = (server_name, port).to_socket_addrs()?;

    println!("looking up {}:{}", server_name, port)?;
    for ip_addr in ip_addrs {
        println!("{:?}", ip_addr)?;
    }

    Ok(())
}
