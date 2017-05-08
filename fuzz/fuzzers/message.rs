#![no_main]
#[macro_use] extern crate libfuzzer_sys;
extern crate rustls;

use rustls::internal::msgs::message::Message;
use rustls::internal::msgs::codec::{Reader, Codec};

fuzz_target!(|data: &[u8]| {
    let mut rdr = Reader::init(data);
    Message::read(&mut rdr)
        .map(|mut msg| msg.decode_payload());
});
