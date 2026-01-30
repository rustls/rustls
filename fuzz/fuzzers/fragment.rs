#![no_main]
#[macro_use]
extern crate libfuzzer_sys;
extern crate rustls;

use rustls::internal::fuzzing::fuzz_fragmenter;

fuzz_target!(|data: &[u8]| fuzz_fragmenter(data));
