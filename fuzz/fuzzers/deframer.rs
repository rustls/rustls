#![no_main]
#[macro_use]
extern crate libfuzzer_sys;
extern crate rustls;

use rustls::internal::msgs::deframer;
use rustls::internal::msgs::message::Message;
use rustls::internal::record_layer::RecordLayer;
use std::io;

fuzz_target!(|data: &[u8]| {
    let mut dfm = deframer::MessageDeframer::default();
    if dfm
        .read(&mut io::Cursor::new(data))
        .is_err()
    {
        return;
    }
    dfm.has_pending();

    let mut rl = RecordLayer::new();
    while let Ok(Some(decrypted)) = dfm.pop(&mut rl) {
        Message::try_from(decrypted.message).ok();
    }
});
