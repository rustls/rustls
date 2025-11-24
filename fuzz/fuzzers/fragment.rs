#![no_main]
#[macro_use]
extern crate libfuzzer_sys;
extern crate rustls;

use rustls::crypto::cipher::{EncodedMessage, Payload};
use rustls::internal::msgs::codec::Reader;
use rustls::internal::msgs::fragmenter::MessageFragmenter;
use rustls::internal::msgs::message::Message;

fuzz_target!(|data: &[u8]| {
    let mut rdr = Reader::init(data);
    let Ok(msg) = EncodedMessage::<Payload>::read(&mut rdr) else {
        return;
    };

    let Ok(msg) = Message::try_from(msg) else {
        return;
    };

    let mut frg = MessageFragmenter::default();
    frg.set_max_fragment_size(Some(32))
        .unwrap();
    for msg in frg.fragment_message(&EncodedMessage::<Payload>::from(msg)) {
        Message::try_from(EncodedMessage {
            typ: msg.typ,
            version: msg.version,
            payload: Payload::Owned(msg.payload.to_vec()),
        })
        .ok();
    }
});
