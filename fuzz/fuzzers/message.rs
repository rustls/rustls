#![no_main]
#[macro_use] extern crate libfuzzer_sys;
extern crate rustls;

use rustls::internal::msgs::codec::{Codec, Reader};
use rustls::internal::msgs::message::{Message, OpaqueMessage};
use std::convert::TryFrom;

fuzz_target!(|data: &[u8]| {
    let mut rdr = Reader::init(data);
    if let Ok(m) = OpaqueMessage::read(&mut rdr) {
        let msg = match Message::try_from(m) {
            Ok(msg) => msg,
            Err((msg, _)) => msg,
        };
        //println!("msg = {:#?}", m);
        let enc = msg.into_opaque().get_encoding();
        //println!("data = {:?}", &data[..rdr.used()]);
        assert_eq!(enc, data[..rdr.used()]);
    }
});
