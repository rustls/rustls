use crate::error::InvalidMessage;
use crate::msgs::codec::{Codec, Reader};

use super::codec::PushBytes;

#[derive(Debug)]
pub struct ChangeCipherSpecPayload;

impl Codec for ChangeCipherSpecPayload {
    fn encode<B: PushBytes>(&self, bytes: &mut B) -> Result<(), B::Error> {
        1u8.encode(bytes)
    }

    fn read(r: &mut Reader) -> Result<Self, InvalidMessage> {
        let typ = u8::read(r)?;
        if typ != 1 {
            return Err(InvalidMessage::InvalidCcs);
        }

        r.expect_empty("ChangeCipherSpecPayload")
            .map(|_| Self {})
    }
}
