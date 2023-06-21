#![no_main]
#[macro_use]
extern crate libfuzzer_sys;
extern crate rustls;

use rustls::client::ServerName;

fuzz_target!(|data: &[u8]| {
    let _ = std::str::from_utf8(data)
        .map_err(|_| ())
        .and_then(|s| ServerName::try_from(s).map_err(|_| ()));
});
