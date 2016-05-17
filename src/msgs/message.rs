
use msgs::codec::{Codec, Reader, encode_u16};
use msgs::base::PayloadU16;
use msgs::alert::AlertMessagePayload;
use msgs::handshake::HandshakeMessagePayload;
use msgs::enums::{ContentType, ProtocolVersion};

#[derive(Debug)]
pub enum MessagePayload {
  Alert(AlertMessagePayload),
  Handshake(HandshakeMessagePayload),
  Unknown(PayloadU16)
}

impl MessagePayload {
  fn encode(&self, bytes: &mut Vec<u8>) {
    match *self {
      MessagePayload::Alert(ref x) => x.encode(bytes),
      MessagePayload::Handshake(ref x) => x.encode(bytes),
      MessagePayload::Unknown(ref x) => x.encode(bytes)
    }
  }

  pub fn decode_given_type(&self, typ: &ContentType) -> Option<MessagePayload> {
    if let MessagePayload::Unknown(ref payload) = *self {
      let mut r = Reader::init(&payload.body);
      match *typ {
        ContentType::Alert =>
          Some(MessagePayload::Alert(try_ret!(AlertMessagePayload::read(&mut r)))),
        ContentType::Handshake =>
          Some(MessagePayload::Handshake(try_ret!(HandshakeMessagePayload::read(&mut r)))),
        _ =>
          None
      }
    } else {
      None
    }
  }
}

/* aka TLSPlaintext */
#[derive(Debug)]
pub struct Message {
  pub typ: ContentType,
  pub version: ProtocolVersion,
  pub payload: MessagePayload
}

impl Message {
  pub fn read(r: &mut Reader) -> Option<Message> {
    let typ = try_ret!(ContentType::read(r));
    let version = try_ret!(ProtocolVersion::read(r));
    let payload = try_ret!(PayloadU16::read(r));

    Some(Message { typ: typ, version: version, payload: MessagePayload::Unknown(payload) })
  }

  pub fn encode(&self, bytes: &mut Vec<u8>) {
    self.typ.encode(bytes);
    self.version.encode(bytes);

    let mut sub = Vec::new();
    self.payload.encode(&mut sub);
    encode_u16(sub.len() as u16, bytes);
    bytes.extend(sub);
  }

  pub fn is_content_type(&self, typ: ContentType) -> bool {
    self.typ == typ
  }

  pub fn decode_payload(&mut self) {
    if let Some(x) = self.payload.decode_given_type(&self.typ) {
      self.payload = x;
    }
  }
}
