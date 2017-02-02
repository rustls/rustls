use msgs::enums::{ContentType, ProtocolVersion};

pub trait MessagePayload: Sized {
    fn encode(&self, bytes: &mut Vec<u8>);

    fn decode_given_type(&self,
                             typ: ContentType,
                             vers: ProtocolVersion)
                             -> Option<Self>;

    fn length(&self) -> usize;

    fn new_opaque(data: Vec<u8>) -> Self;
}
