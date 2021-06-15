use crate::msgs::codec::{Codec, Reader};
use crate::msgs::enums::HeartbeatMessageType;
use crate::msgs::base::PayloadU16;

#[derive(Debug, Clone)]
pub struct HeartbeatPayload {
    pub typ: HeartbeatMessageType,
    pub payload: PayloadU16,
    pub fake_length: Option<u16>
}

impl Codec for HeartbeatPayload {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.typ.encode(bytes);
        if let Some(fake_length) = self.fake_length {
            fake_length.encode(bytes);
            bytes.extend_from_slice(self.payload.0.as_slice());
        } else {
            self.payload.encode(bytes);
        }
    }

    fn read(r: &mut Reader) -> Option<HeartbeatPayload> {
        let typ = HeartbeatMessageType::read(r)?;
        let payload = PayloadU16::read(r)?;

        Some(HeartbeatPayload {typ, payload, fake_length: None})
    }
}
