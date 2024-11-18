#![no_main]
#[macro_use]
extern crate libfuzzer_sys;
extern crate rustls;

use rustls::internal::msgs::base::Payload;
use rustls::internal::msgs::codec::Reader;
use rustls::internal::msgs::fragmenter::MessageFragmenter;
use rustls::internal::msgs::message::{Message, OutboundOpaqueMessage, PlainMessage};

fuzz_target!(|data: &[u8]| {
    let mut rdr = Reader::init(data);
    let Ok(msg) = OutboundOpaqueMessage::read(&mut rdr) else {
        return;
    };

    let Ok(msg) = Message::try_from(msg.into_plain_message()) else {
        return;
    };

    let mut frg = MessageFragmenter::default();
    frg.set_max_fragment_size(Some(32))
        .unwrap();
    for msg in frg.fragment_message(&PlainMessage::from(msg)) {
        Message::try_from(PlainMessage {
            typ: msg.typ,
            version: msg.version,
            payload: Payload::Owned(msg.payload.to_vec()),
        })
        .ok();
    }
});
