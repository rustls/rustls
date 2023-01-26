#![no_main]
#[macro_use]
extern crate libfuzzer_sys;
extern crate rustls;

use rustls::internal::msgs::base::Payload;
use rustls::internal::msgs::fragmenter::MessageFragmenter;
use rustls::internal::msgs::message::{Message, OpaqueMessageRecv, PlainMessage};

fuzz_target!(|data: &[u8]| {
    let mut buf = data.to_vec();
    let (msg, _) = match OpaqueMessageRecv::read(&mut buf) {
        Ok(msg) => msg,
        Err(_) => return,
    };

    let msg = match Message::try_from(msg.into_plain_message()) {
        Ok(msg) => msg,
        Err(_) => return,
    };

    let mut frg = MessageFragmenter::default();
    frg.set_max_fragment_size(Some(32))
        .unwrap();
    for msg in frg.fragment_message(&PlainMessage::from(msg)) {
        Message::try_from(PlainMessage {
            typ: msg.typ,
            version: msg.version,
            payload: Payload(msg.payload.to_vec()),
        })
        .ok();
    }
});
