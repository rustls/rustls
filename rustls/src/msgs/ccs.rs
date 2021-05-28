use crate::msgs::codec::{Codec, Reader};

#[derive(Debug, Clone)]
pub struct ChangeCipherSpecPayload;

impl Codec for ChangeCipherSpecPayload {
    fn encode(&self, bytes: &mut Vec<u8>) {
        1u8.encode(bytes);
    }

    fn read(r: &mut Reader) -> Option<Self> {
        let typ = u8::read(r)?;

        Some(Self {})
    }
}
