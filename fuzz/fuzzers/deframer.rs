#![no_main]
#[macro_use]
extern crate libfuzzer_sys;
extern crate rustls;

use rustls::internal::msgs::deframer;
use rustls::internal::msgs::message::Message;
use rustls::internal::record_layer::RecordLayer;
use std::io;

fuzz_target!(|data: &[u8]| {
    let mut buf = deframer::DeframerVecBuffer::default();
    let mut dfm = deframer::MessageDeframer::default();
    if dfm
        .read(&mut io::Cursor::new(data), &mut buf)
        .is_err()
    {
        return;
    }
    buf.has_pending();

    let mut rl = RecordLayer::new();
    let mut borrowed_buf = buf.borrow();
    while let Ok(Some(decrypted)) = dfm.pop(&mut rl, None, &mut borrowed_buf) {
        Message::try_from(decrypted.message).ok();
    }
    let discard = borrowed_buf.pending_discard();
    buf.discard(discard);
});
