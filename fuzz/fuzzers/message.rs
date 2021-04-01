#![no_main]
#[macro_use] extern crate libfuzzer_sys;
extern crate rustls;

use rustls::internal::msgs::message::Message;
use rustls::internal::msgs::codec::{Reader, Codec};

fuzz_target!(|data: &[u8]| {
    let mut rdr = Reader::init(data);
    if let Some(mut m) = Message::read(&mut rdr) {
        m.decode_payload();
        //println!("msg = {:#?}", m);
        let enc = m.get_encoding();
        //println!("data = {:?}", &data[..rdr.used()]);
        assert_eq!(enc, data[..rdr.used()]);
    }
});
