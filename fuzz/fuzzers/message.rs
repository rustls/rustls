#![no_main]
#[macro_use]
extern crate libfuzzer_sys;
extern crate rustls;

use rustls::crypto::cipher::{EncodedMessage, Payload};
use rustls::internal::msgs::{Message, Reader};

fuzz_target!(|data: &[u8]| {
    let mut rdr = Reader::init(data);
    if let Ok(m) = EncodedMessage::<Payload>::read(&mut rdr) {
        let Ok(msg) = Message::try_from(&m) else {
            return;
        };
        //println!("msg = {:#?}", m);
        let enc = EncodedMessage::<Payload>::from(msg)
            .into_unencrypted_opaque()
            .encode();
        //println!("data = {:?}", &data[..rdr.used()]);
        assert_eq!(enc, data[..rdr.used()]);
    }
});
