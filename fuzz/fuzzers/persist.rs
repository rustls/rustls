#![no_main]
#[macro_use]
extern crate libfuzzer_sys;
extern crate rustls;

use rustls::internal::msgs::{Codec, Reader, ServerSessionValue};

fn try_type<T>(data: &[u8])
where
    T: for<'a> Codec<'a>,
{
    let mut rdr = Reader::init(data);

    let _ = T::read(&mut rdr);
}

fuzz_target!(|data: &[u8]| {
    try_type::<ServerSessionValue>(data);
});
