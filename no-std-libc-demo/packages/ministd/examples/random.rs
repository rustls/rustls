#![deny(unsafe_code)]
#![no_std]
#![no_main]

use ministd::{entry, io, println};
use rand_core::{OsRng, RngCore};

entry!(main);

fn main() -> io::Result<()> {
    let random = OsRng.next_u64();
    println!("{}", random)?;
    Ok(())
}
