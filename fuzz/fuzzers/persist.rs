#![no_main]
#[macro_use] extern crate libfuzzer_sys;
extern crate rustls;

use rustls::internal::msgs::persist;
use rustls::internal::msgs::codec::{Reader, Codec};

fn try_type<'a, T>(data: &'a [u8]) where T: Codec<'a> {
    let mut rdr = Reader::init(data);
    T::read(&mut rdr);
}

fuzz_target!(|data: &[u8]| {
    try_type::<persist::ClientSessionValue>(data);
    try_type::<persist::ServerSessionValue>(data);
});
