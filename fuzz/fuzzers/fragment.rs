#![no_main]
#[macro_use] extern crate libfuzzer_sys;
extern crate rustls;

use rustls::internal::msgs::fragmenter;
use rustls::internal::msgs::message;
use rustls::internal::msgs::codec::{Codec, Reader};
use std::collections::VecDeque;

fuzz_target!(|data: &[u8]| {
    let mut rdr = Reader::init(data);
    let mut msg = match message::Message::read(&mut rdr) {
        Some(msg) => msg,
        None => return
    };
    msg.decode_payload();

    let frg = fragmenter::MessageFragmenter::new(5);
    let mut out = VecDeque::new();
    frg.fragment(msg, &mut out);

    for mut msg in out {
        msg.decode_payload();
    }
});
