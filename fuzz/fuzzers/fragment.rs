#![no_main]
#[macro_use] extern crate libfuzzer_sys;
extern crate rustls;

use rustls::internal::msgs::fragmenter;
use rustls::internal::msgs::message;
use std::collections::VecDeque;
use std::convert::TryFrom;

fuzz_target!(|data: &[u8]| {
    let mut buf = data.to_vec();
    let msg = match message::OpaqueMessage::read(&mut buf) {
        Ok((msg, _)) => msg,
        Err(_) => return,
    };

    let plain = msg.into_plain_message();
    let msg = match message::Message::try_from(&plain) {
        Ok(msg) => msg,
        Err(_) => return,
    };

    let frg = fragmenter::MessageFragmenter::new(Some(32)).unwrap();
    let mut out = VecDeque::new();
    frg.fragment(message::PlainMessage::from(msg), &mut out);

    for msg in out {
        message::Message::try_from(&msg).ok();
    }
});
