#![no_main]
#[macro_use]
extern crate libfuzzer_sys;
extern crate rustls;

use rustls::internal::msgs::message::{Message, OpaqueMessage, PlainMessage};
use std::convert::TryFrom;

fuzz_target!(|data: &[u8]| {
    let mut buf = data.to_vec();
    if let Ok((m, used)) = OpaqueMessage::read(&mut buf) {
        let plain = m.into_plain_message();
        let msg = match Message::try_from(&plain) {
            Ok(msg) => msg,
            Err(_) => return,
        };
        //println!("msg = {:#?}", m);
        let enc = PlainMessage::from(msg).into_unencrypted_opaque().encode();
        //println!("data = {:?}", &data[..rdr.used()]);
        assert_eq!(enc, data[..used]);
    }
});
