#![no_main]
#[macro_use]
extern crate libfuzzer_sys;
extern crate rustls;

use rustls::internal::msgs::deframer;
use rustls::internal::msgs::message::Message;
use std::convert::TryFrom;
use std::io;

fuzz_target!(|data: &[u8]| {
    let mut dfm = deframer::MessageDeframer::new();
    if dfm
        .read(&mut io::Cursor::new(data))
        .is_err()
    {
        return;
    }
    dfm.has_pending();

    while !dfm.frames.is_empty() {
        let msg = dfm.frames.pop_front().unwrap();
        Message::try_from(msg.into_plain_message()).ok();
    }
});
