
use msgs::codec::{Codec, Reader, encode_u16, read_u16};
use msgs::base::Payload;
use msgs::alert::AlertMessagePayload;
use msgs::ccs::ChangeCipherSpecPayload;
use msgs::handshake::HandshakeMessagePayload;
use msgs::enums::{ContentType, ProtocolVersion};

#[derive(Debug)]
pub enum MessagePayload {
  Alert(AlertMessagePayload),
  Handshake(HandshakeMessagePayload),
  ChangeCipherSpec(ChangeCipherSpecPayload),
  Unknown(Payload)
}

impl MessagePayload {
  pub fn encode(&self, bytes: &mut Vec<u8>) {
    match *self {
      MessagePayload::Alert(ref x) => x.encode(bytes),
      MessagePayload::Handshake(ref x) => x.encode(bytes),
      MessagePayload::ChangeCipherSpec(ref x) => x.encode(bytes),
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
        ContentType::ChangeCipherSpec =>
          Some(MessagePayload::ChangeCipherSpec(try_ret!(ChangeCipherSpecPayload::read(&mut r)))),
        _ =>
          None
      }
    } else {
      None
    }
  }

  pub fn opaque(data: Vec<u8>) -> MessagePayload {
    MessagePayload::Unknown(Payload { body: data.into_boxed_slice() })
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
    let len = try_ret!(read_u16(r));

    let mut sub = try_ret!(r.sub(len as usize));
    let payload = try_ret!(Payload::read(&mut sub));

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
