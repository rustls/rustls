#![no_main]
#[macro_use]
extern crate libfuzzer_sys;
extern crate rustls;

use rustls::internal::msgs::codec::Reader;
use rustls::internal::msgs::message::{Message, OutboundOpaqueMessage, PlainMessage};

fuzz_target!(|data: &[u8]| {
    let mut rdr = Reader::init(data);
    if let Ok(m) = OutboundOpaqueMessage::read(&mut rdr) {
        let Ok(msg) = Message::try_from(m.into_plain_message()) else {
            return;
        };
        //println!("msg = {:#?}", m);
        let enc = PlainMessage::from(msg)
            .into_unencrypted_opaque()
            .encode();
        //println!("data = {:?}", &data[..rdr.used()]);
        assert_eq!(enc, data[..rdr.used()]);
    }
});
