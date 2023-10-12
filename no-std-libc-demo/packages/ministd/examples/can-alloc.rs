#![deny(unsafe_code)]
#![no_main]
#![no_std]

extern crate alloc;

use alloc::vec;
use ministd::{entry, io, println};

entry!(main);

fn main() -> io::Result<()> {
    let xs = vec![1, 2, 3];
    println!("easy as {:?}", xs)?;
    Ok(())
}
