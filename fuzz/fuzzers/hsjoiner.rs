#![no_main]
#[macro_use] extern crate libfuzzer_sys;
extern crate rustls;

use std::convert::TryFrom;
use rustls::internal::msgs::hsjoiner;
use rustls::internal::msgs::message;

fuzz_target!(|data: &[u8]| {
    let mut buf = data.to_vec();
    let msg = match message::OpaqueMessage::read(&mut buf) {
        Ok((msg, _)) => msg,
        Err(_) => return,
    };

    let plain = msg.to_plain_message();
    let mut jnr = hsjoiner::HandshakeJoiner::new();
    if jnr.want_message(&plain) {
        jnr.take_message(plain);
    }

    let (mut iter, _) = jnr.iter();
    while let Some(msg) = iter.pop() {
        if let Ok(msg) = msg {
            message::Message::try_from(msg).unwrap();
        }
    }
});
