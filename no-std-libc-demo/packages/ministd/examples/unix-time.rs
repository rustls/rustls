#![deny(unsafe_code)]
#![no_std]
#![no_main]

use ministd::{
    entry, io, println,
    time::{SystemTime, UNIX_EPOCH},
};

entry!(main);

fn main() -> io::Result<()> {
    let now = SystemTime::now();
    let unix_time = now.duration_since(UNIX_EPOCH);
    println!("{:?}", unix_time)?;
    Ok(())
}
