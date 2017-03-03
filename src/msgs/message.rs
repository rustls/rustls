use msgs::enums::{ContentType, ProtocolVersion};
use msgs::tls_message::{TLSMessage, TLSBorrowMessage};
use msgs::base::Payload;

pub trait BorrowMessage: Sized {
    type Message: Message;

    fn version(&self) -> ProtocolVersion;
    fn typ(&self) -> ContentType;
    fn payload<'a>(&'a self) -> &'a [u8];

    fn to_tls_borrowed<'a>(&'a self) -> TLSBorrowMessage<'a>;
    fn clone_from_tls(&self, msg: TLSMessage) -> Self::Message;
}

pub trait MessagePayload: Sized {
    fn encode(&self, bytes: &mut Vec<u8>);

    fn decode_given_type(&self,
                         typ: ContentType,
                         vers: ProtocolVersion)
                         -> Option<Self>;

    fn length(&self) -> usize;

    fn new_opaque(data: Vec<u8>) -> Self;

    fn encode_for_transcript(&self) -> Vec<u8>;
}

pub trait Message: Sized {
    type Payload: MessagePayload;

    fn version(&self) -> ProtocolVersion;
    fn typ(&self) -> ContentType;
    fn payload<'a>(&'a self) -> &'a Self::Payload;

    fn take_opaque_payload(&mut self) -> Option<Payload>;

    fn to_tls(&mut self) -> TLSMessage;
    fn clone_from_tls(&self, msg: TLSMessage) -> Self;
}

