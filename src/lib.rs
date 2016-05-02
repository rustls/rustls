use std::fmt::Debug;

mod proto_enums;
use proto_enums::{AlertLevel, AlertDescription, ContentType, ProtocolVersion, HandshakeType};
use proto_enums::{CipherSuite, Compression, ExtensionType};
mod codec;
use codec::{Codec, Reader};

/* An externally length'd payload */
#[derive(Debug)]
struct UnknownPayload {
  body: Box<[u8]>
}

impl Codec for UnknownPayload {
  fn encode(&self, bytes: &mut Vec<u8>) {
    bytes.extend_from_slice(&self.body);
  }
  
  fn decode(r: &mut Reader) -> UnknownPayload {
    UnknownPayload { body: r.rest().to_vec().into_boxed_slice() }
  }
}

/* An arbitrary, unknown-content, u16-length-prefixed payload */
#[derive(Debug)]
struct UnknownPayloadU16 {
  body: Box<[u8]>
}

impl Codec for UnknownPayloadU16 {
  fn encode(&self, bytes: &mut Vec<u8>) {
    codec::encode_u16(self.body.len() as u16, bytes);
    bytes.extend_from_slice(&self.body);
  }
  
  fn decode(r: &mut Reader) -> UnknownPayloadU16 {
    let len = codec::decode_u16(r) as usize;
    UnknownPayloadU16 { body: r.take(len).to_vec().into_boxed_slice() }
  }
}

impl UnknownPayloadU16 {
}

#[derive(Debug)]
struct AlertMessagePayload {
  level: AlertLevel,
  description: AlertDescription
}

impl Codec for AlertMessagePayload {
  fn encode(&self, bytes: &mut Vec<u8>) {
    self.level.encode(bytes);
    self.description.encode(bytes);
  }
  
  fn decode(r: &mut Reader) -> AlertMessagePayload {
    AlertMessagePayload {
      level: AlertLevel::decode(r),
      description: AlertDescription::decode(r)
    }
  }
}

#[derive(Debug)]
struct Random {
  gmt_unix_time: u32,
  opaque: [u8; 28]
}

impl Codec for Random {
  fn encode(&self, bytes: &mut Vec<u8>) {
    codec::encode_u32(self.gmt_unix_time, bytes);
    bytes.extend_from_slice(&self.opaque);
  }
  
  fn decode(r: &mut Reader) -> Random {
    let mut ret = Random {
      gmt_unix_time: codec::decode_u32(r),
      opaque: [0u8; 28]
    };

    ret.opaque.clone_from_slice(r.take(28));
    ret
  }
}

#[derive(Debug)]
struct SessionID {
  bytes: Vec<u8>
}

impl Codec for SessionID {
  fn encode(&self, bytes: &mut Vec<u8>) {
    codec::encode_u8(self.bytes.len() as u8, bytes);
    bytes.extend_from_slice(&self.bytes[..]);
  }
  
  fn decode(r: &mut Reader) -> SessionID {
    let mut ret = SessionID { bytes: Vec::new() };
    let len = codec::decode_u8(r) as usize;
    ret.bytes.extend_from_slice(r.take(len));
    ret
  }
}

#[derive(Debug)]
struct UnknownExtension {
  typ: ExtensionType,
  payload: UnknownPayloadU16
}

impl UnknownExtension {
  fn encode(&self, bytes: &mut Vec<u8>) {
    self.typ.encode(bytes);
    self.payload.encode(bytes);
  }
  
  fn decode(typ: ExtensionType, r: &mut Reader) -> UnknownExtension {
    UnknownExtension {
      typ: typ,
      payload: UnknownPayloadU16::decode(r)
    }
  }
}

#[derive(Debug)]
enum ClientExtension {
  Unknown(UnknownExtension)
}

impl Codec for ClientExtension {
  fn encode(&self, bytes: &mut Vec<u8>) {
    match *self {
      ClientExtension::Unknown(ref r) => r.encode(bytes)
    }
  }
  
  fn decode(r: &mut Reader) -> ClientExtension {
    let typ = ExtensionType::decode(r);

    match typ {
      _ => ClientExtension::Unknown(UnknownExtension::decode(typ, r))
    }
  }
}

#[derive(Debug)]
struct ClientHelloPayload {
  client_version: ProtocolVersion,
  random: Random,
  session_id: SessionID,
  cipher_suites: Vec<CipherSuite>,
  compression_methods: Vec<Compression>,
  extensions: Vec<ClientExtension>
}

impl Codec for ClientHelloPayload {
  fn encode(&self, bytes: &mut Vec<u8>) {
    self.client_version.encode(bytes);
    self.random.encode(bytes);
    self.session_id.encode(bytes);
    codec::encode_vec_u16(bytes, &self.cipher_suites);
    codec::encode_vec_u8(bytes, &self.compression_methods);

    if self.extensions.len() > 0 {
      codec::encode_vec_u16(bytes, &self.extensions);
    }
  }
  
  fn decode(r: &mut Reader) -> ClientHelloPayload {
    let mut ret = ClientHelloPayload {
      client_version: ProtocolVersion::decode(r),
      random: Random::decode(r),
      session_id: SessionID::decode(r),
      cipher_suites: codec::decode_vec_u16::<CipherSuite>(r),
      compression_methods: codec::decode_vec_u8::<Compression>(r),
      extensions: Vec::new()
    };

    if r.any_left() {
      ret.extensions = codec::decode_vec_u16::<ClientExtension>(r);
    }

    ret
  }
}

#[derive(Debug)]
enum HandshakePayload {
  HelloRequest,
  ClientHello(ClientHelloPayload),
  Unknown(UnknownPayload)
}

impl HandshakePayload {
  fn encode(&self, bytes: &mut Vec<u8>) {
    match *self {
      HandshakePayload::HelloRequest => {},
      HandshakePayload::ClientHello(ref x) => x.encode(bytes),
      HandshakePayload::Unknown(ref x) => x.encode(bytes)
    }
  }
}

#[derive(Debug)]
struct HandshakeMessagePayload {
  typ: HandshakeType,
  payload: HandshakePayload
}

impl Codec for HandshakeMessagePayload {
  fn encode(&self, bytes: &mut Vec<u8>) {
    /* encode payload to learn length */
    let mut sub: Vec<u8> = Vec::new();

    match self.payload {
      HandshakePayload::HelloRequest => {},
      HandshakePayload::ClientHello(ref x) => x.encode(&mut sub),
      HandshakePayload::Unknown(ref x) => x.encode(&mut sub)
    }

    /* output type, length, and encoded payload */
    self.typ.encode(bytes);
    codec::encode_u24(sub.len() as u32, bytes);
    bytes.append(&mut sub);
  }

  fn decode(r: &mut Reader) -> HandshakeMessagePayload {
    let typ = HandshakeType::decode(r);
    let len = codec::decode_u24(r) as usize;
    let mut sub = r.sub(len);
    let payload = match typ {
      HandshakeType::HelloRequest => HandshakePayload::HelloRequest,
      HandshakeType::ClientHello => HandshakePayload::ClientHello(ClientHelloPayload::decode(&mut sub)),
      _ => HandshakePayload::Unknown(UnknownPayload::decode(&mut sub))
    };

    HandshakeMessagePayload { typ: typ, payload: payload }
  }
}

#[derive(Debug)]
enum MessagePayload {
  Alert(AlertMessagePayload),
  Handshake(HandshakeMessagePayload),
  Unknown(UnknownPayloadU16)
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
        ContentType::Alert => Some(MessagePayload::Alert(AlertMessagePayload::decode(&mut r))),
        ContentType::Handshake => Some(MessagePayload::Handshake(HandshakeMessagePayload::decode(&mut r))),
        _ => None
      }
    } else {
      None
    }
  }
}

/* aka TLSPlaintext */
#[derive(Debug)]
pub struct Message {
  typ: ContentType,
  version: ProtocolVersion,
  payload: MessagePayload
}

impl Message {
  pub fn decode(r: &mut Reader) -> Message {
    Message {
      typ: ContentType::decode(r),
      version: ProtocolVersion::decode(r),
      payload: MessagePayload::Unknown(UnknownPayloadU16::decode(r))
    }
  }

  pub fn encode(&self, bytes: &mut Vec<u8>) {
    self.typ.encode(bytes);
    self.version.encode(bytes);
    self.payload.encode(bytes);
  }

  pub fn decode_payload(&mut self) {
    if let Some(x) = self.payload.decode_given_type(&self.typ) {
      self.payload = x;
    }
  }
}

#[cfg(test)]
#[test]
fn check() {
  let mut out: Vec<u8> = vec![];
  println!("fart");

  let mut r = Reader::init(b"\x16\x03\x01\x00\xcf\x01\x00\x00\xcb\x03\x03\x51\x49\xcf\x60\x87\xa1\x0a\xe9\x59\x2d\x9d\x3b\x06\x2e\x11\x9b\x31\x93\xb1\xdc\xcc\x2a\xf3\x87\xd7\x93\x9b\x01\x00\xc7\x5f\xa1\x00\x00\x32\xc0\x30\xc0\x2c\xc0\x28\xc0\x24\xc0\x14\xc0\x0a\xc0\x22\xc0\x21\x00\xa3\x00\x9f\x00\x6b\x00\x6a\x00\x39\x00\x38\x00\x88\x00\x87\xc0\x32\xc0\x2e\xc0\x2a\xc0\x26\xc0\x0f\xc0\x05\x00\x9d\x00\x3d\x00\x35\x02\x01\x00\x00\x6f\x00\x0b\x00\x04\x03\x00\x01\x02\x00\x0a\x00\x34\x00\x32\x00\x0e\x00\x0d\x00\x19\x00\x0b\x00\x0c\x00\x18\x00\x09\x00\x0a\x00\x16\x00\x17\x00\x08\x00\x06\x00\x07\x00\x14\x00\x15\x00\x04\x00\x05\x00\x12\x00\x13\x00\x01\x00\x02\x00\x03\x00\x0f\x00\x10\x00\x11\x00\x23\x00\x00\x00\x0d\x00\x22\x00\x20\x06\x01\x06\x02\x06\x03\x05\x01\x05\x02\x05\x03\x04\x01\x04\x02\x04\x03\x03\x01\x03\x02\x03\x03\x02\x01\x02\x02\x02\x03\x01\x01\x00\x0f\x00\x01\x01");
  let mut m = Message::decode(&mut r);
  println!("m = {:?}", m);
  m.encode(&mut out);
  println!("enc = {:?}", out);
  
  m.decode_payload();
  println!("m' = {:?}", m);

}
