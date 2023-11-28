//! you can test this with
//!
//! ```
//! use std::{
//!     io::{self, Read, Write},
//!     net::TcpListener,
//! };
//!
//! fn main() -> io::Result<()> {
//!     let listener = TcpListener::bind("127.0.0.1:1234")?;
//!     let mut incoming = listener.incoming();
//!
//!     let mut rxbuf = [0; 256];
//!     while let Some(Ok(mut stream)) = incoming.next() {
//!         let read = stream.read(&mut rxbuf)?;
//!         println!("received: {:?}", core::str::from_utf8(&rxbuf[..read]));
//!         stream.write_all(b"response")?;
//!     }
//!
//!     Ok(())
//! }
//! ```

#![deny(unsafe_code)]
#![no_main]
#![no_std]

use ministd::{
    dbg, entry,
    io::{self, Read, Write},
    net::{Ipv4Addr, SocketAddrV4, TcpStream},
    println,
};

const IP: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 1);
const PORT: u16 = 1234;

entry!(main);

fn main() -> io::Result<()> {
    let addr = SocketAddrV4::new(IP, PORT).into();
    let mut stream = TcpStream::connect(&addr)?;
    dbg!(&stream);

    stream.write_all(b"request")?;

    let mut rxbuf = [0; 256];
    let read = stream.read(&mut rxbuf)?;

    println!("received: {:?}", core::str::from_utf8(&rxbuf[..read]))?;

    Ok(())
}
