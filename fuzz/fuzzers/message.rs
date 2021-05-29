#![no_main]
#[macro_use]
extern crate libfuzzer_sys;
extern crate rustls;

use rustls::internal::msgs::codec::Reader;
use rustls::internal::msgs::message::{Message, PlainMessage, OpaqueMessage};
use std::convert::TryFrom;

fuzz_target!(|data: &[u8]| {
    let mut rdr = Reader::init(data);
    if let Ok(m) = OpaqueMessage::read(&mut rdr) {
        let msg = match Message::try_from(m.into_plain_message()) {
            Ok(msg) => msg,
            Err(_) => return,
        };
        //println!("msg = {:#?}", m);
        let enc = PlainMessage::from(msg)
            .into_unencrypted_opaque()
            .encode();
        //println!("data = {:?}", &data[..rdr.used()]);
        assert_eq!(enc, data[..rdr.used()]);
    }
});
