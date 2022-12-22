#![no_main]
#[macro_use] extern crate libfuzzer_sys;
extern crate rustls;

use std::convert::TryFrom;
use rustls::internal::msgs::codec::Reader;
use rustls::internal::msgs::hsjoiner;
use rustls::internal::msgs::message;

fuzz_target!(|data: &[u8]| {
    let mut rdr = Reader::init(data);
    let msg = match message::OpaqueMessage::read(&mut rdr) {
        Ok(msg) => msg.into_plain_message(),
        Err(_) => return,
    };

    let mut jnr = hsjoiner::HandshakeJoiner::new();
    match jnr.push(msg) {
        Ok(_) => {},
        Err(_) => return,
    }

    while let Ok(Some(msg)) = jnr.pop() {
        message::Message::try_from(msg).unwrap();
    }
});
