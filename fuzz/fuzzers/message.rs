#![no_main]
#[macro_use]
extern crate libfuzzer_sys;
extern crate rustls;

use rustls::internal::msgs::message::{Message, OpaqueMessageRecv, PlainMessage};

fuzz_target!(|data: &[u8]| {
    let mut buf = data.to_vec();
    let len = buf.len();

    if let Ok((m, rest)) = OpaqueMessageRecv::read(&mut buf) {
        let msg = match Message::try_from(m.into_plain_message()) {
            Ok(msg) => msg,
            Err(_) => return,
        };
        //println!("msg = {:#?}", m);
        let enc = PlainMessage::from(msg)
            .into_unencrypted_opaque()
            .encode();
        //println!("data = {:?}", &data[..rdr.used()]);
        assert_eq!(enc, data[..len - rest.len()]);
    }
});
