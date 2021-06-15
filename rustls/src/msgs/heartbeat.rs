use crate::msgs::codec::{Codec, Reader};
use crate::msgs::enums::HeartbeatMessageType;
use crate::msgs::base::PayloadU16;

#[derive(Debug, Clone)]
pub struct HeartbeatPayload {
    typ: HeartbeatMessageType,
    payload: PayloadU16,
}

impl Codec for HeartbeatPayload {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.typ.encode(bytes);
        self.payload.encode(bytes);
    }

    fn read(r: &mut Reader) -> Option<HeartbeatPayload> {
        let typ = HeartbeatMessageType::read(r)?;
        let payload = PayloadU16::read(r)?;

        Some(HeartbeatPayload {typ, payload})
    }
}
