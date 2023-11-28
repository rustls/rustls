#![deny(unsafe_code)]
#![no_main]
#![no_std]

use core::fmt;

use ministd::{self as _, entry, io};

entry!(main);

fn main() -> io::Result<()> {
    panic!("hello {:?}", Bomb)
}

struct Bomb;

impl fmt::Debug for Bomb {
    fn fmt(&self, _: &mut fmt::Formatter<'_>) -> fmt::Result {
        panic!("boom")
    }
}
