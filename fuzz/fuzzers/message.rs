#![no_main]
#[macro_use] extern crate libfuzzer_sys;
extern crate rustls;

use rustls::internal::msgs::message::{Message, OpaqueMessage};
use std::convert::TryFrom;

fuzz_target!(|data: &[u8]| {
    let mut buf = data.to_vec();
    if let Ok((m, used)) = OpaqueMessage::read(&mut buf) {
        let msg = match Message::try_from(&m) {
            Ok(msg) => msg,
            Err(_) => return,
        };
        //println!("msg = {:#?}", m);
        let enc = OpaqueMessage::from(msg).encode();
        //println!("data = {:?}", &data[..rdr.used()]);
        assert_eq!(enc, data[..used]);
    }
});
