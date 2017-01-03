use msgs::codec::{Codec, Reader, encode_u8, read_u8};

#[derive(Debug)]
pub struct ChangeCipherSpecPayload;

impl Codec for ChangeCipherSpecPayload {
    fn encode(&self, bytes: &mut Vec<u8>) {
        encode_u8(1u8, bytes);
    }

    fn read(r: &mut Reader) -> Option<ChangeCipherSpecPayload> {
        let typ = try_ret!(read_u8(r));

        if typ == 1 && !r.any_left() {
            Some(ChangeCipherSpecPayload {})
        } else {
            None
        }
    }
}

impl ChangeCipherSpecPayload {
    pub fn len(&self) -> usize {
        1
    }
}
