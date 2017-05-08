#![no_main]
#[macro_use] extern crate libfuzzer_sys;
extern crate rustls;

use rustls::internal::msgs::hsjoiner;
use rustls::internal::msgs::message;
use rustls::internal::msgs::codec::{Codec, Reader};

fuzz_target!(|data: &[u8]| {
    let mut rdr = Reader::init(data);
    let msg = match message::Message::read(&mut rdr) {
        Some(msg) => msg,
        None => return
    };

    let mut jnr = hsjoiner::HandshakeJoiner::new();
    if jnr.want_message(&msg) {
        jnr.take_message(msg);
    }

    for mut msg in jnr.frames {
        msg.decode_payload();
    }
});
