
use msgs::codec::{Codec, Reader, encode_u16, read_u16};
use msgs::base::Payload;
use msgs::alert::AlertMessagePayload;
use msgs::ccs::ChangeCipherSpecPayload;
use msgs::handshake::HandshakeMessagePayload;
use msgs::enums::{ContentType, ProtocolVersion};
use msgs::enums::{AlertLevel, AlertDescription};
use msgs::enums::HandshakeType;

use std::mem;

#[derive(Debug)]
pub enum MessagePayload {
    Alert(AlertMessagePayload),
    Handshake(HandshakeMessagePayload),
    ChangeCipherSpec(ChangeCipherSpecPayload),
    Opaque(Payload),
}

impl MessagePayload {
    pub fn encode(&self, bytes: &mut Vec<u8>) {
        match *self {
            MessagePayload::Alert(ref x) => x.encode(bytes),
            MessagePayload::Handshake(ref x) => x.encode(bytes),
            MessagePayload::ChangeCipherSpec(ref x) => x.encode(bytes),
            MessagePayload::Opaque(ref x) => x.encode(bytes),
        }
    }

    pub fn decode_given_type(&self, typ: &ContentType) -> Option<MessagePayload> {
        if let MessagePayload::Opaque(ref payload) = *self {
            let mut r = Reader::init(&payload.0);
            let parsed = match *typ {
                ContentType::Alert => {
                    Some(MessagePayload::Alert(try_ret!(AlertMessagePayload::read(&mut r))))
                }
                ContentType::Handshake => {
                    Some(MessagePayload::Handshake(try_ret!(HandshakeMessagePayload::read(&mut r))))
                }
                ContentType::ChangeCipherSpec =>
          Some(MessagePayload::ChangeCipherSpec(try_ret!(ChangeCipherSpecPayload::read(&mut r)))),
                _ => None,
            };

            if r.any_left() { None } else { parsed }
        } else {
            None
        }
    }

    pub fn len(&self) -> usize {
        match *self {
            MessagePayload::Alert(ref x) => x.len(),
            MessagePayload::Handshake(ref x) => x.len(),
            MessagePayload::ChangeCipherSpec(ref x) => x.len(),
            MessagePayload::Opaque(ref x) => x.len(),
        }
    }

    pub fn opaque(data: &[u8]) -> MessagePayload {
        MessagePayload::Opaque(Payload::from_slice(data))
    }
}

/// A TLS frame, named TLSPlaintext in the standard
#[derive(Debug)]
pub struct Message {
    pub typ: ContentType,
    pub version: ProtocolVersion,
    pub payload: MessagePayload,
}

impl Codec for Message {
    fn read(r: &mut Reader) -> Option<Message> {
        let typ = try_ret!(ContentType::read(r));
        let version = try_ret!(ProtocolVersion::read(r));
        let len = try_ret!(read_u16(r));

        let mut sub = try_ret!(r.sub(len as usize));
        let payload = try_ret!(Payload::read(&mut sub));

        Some(Message {
            typ: typ,
            version: version,
            payload: MessagePayload::Opaque(payload),
        })
    }

    fn encode(&self, bytes: &mut Vec<u8>) {
        self.typ.encode(bytes);
        self.version.encode(bytes);
        encode_u16(self.payload.len() as u16, bytes);
        self.payload.encode(bytes);
    }
}

impl Message {
    /// Do some *very* lax checks on the header, and return
    /// None if it looks really broken.  Otherwise, return
    /// the length field.
    pub fn check_header(bytes: &[u8]) -> Option<usize> {
        let mut rd = Reader::init(bytes);

        let typ = try_ret!(ContentType::read(&mut rd));
        let version = try_ret!(ProtocolVersion::read(&mut rd));
        let len = try_ret!(read_u16(&mut rd));

        // Don't accept any new content-types.
        if let ContentType::Unknown(_) = typ {
            return None;
        }

        // Accept only versions 0x03XX for any XX.
        match version {
            ProtocolVersion::Unknown(ref v) if (v & 0xff00) != 0x0300 => {
                return None;
            }
            _ => (),
        };

        Some(len as usize)
    }

    pub fn is_content_type(&self, typ: ContentType) -> bool {
        self.typ == typ
    }

    pub fn is_handshake_type(&self, hstyp: HandshakeType) -> bool {
        // Bit of a layering violation, but OK.
        if !self.is_content_type(ContentType::Handshake) {
            return false;
        }

        if let MessagePayload::Handshake(ref hsp) = self.payload {
            hsp.typ == hstyp
        } else {
            false
        }
    }

    pub fn decode_payload(&mut self) -> bool {
        // Do we need a decode?
        if self.typ == ContentType::ApplicationData {
            return true;
        }

        if let Some(x) = self.payload.decode_given_type(&self.typ) {
            self.payload = x;
            true
        } else {
            false
        }
    }

    pub fn take_payload(self) -> Vec<u8> {
        self.into_opaque().take_opaque_payload().unwrap().0
    }

    pub fn take_opaque_payload(&mut self) -> Option<Payload> {
        if let MessagePayload::Opaque(ref mut op) = self.payload {
            Some(mem::replace(op, Payload::empty()))
        } else {
            None
        }
    }

    pub fn into_opaque(self) -> Message {
        if let MessagePayload::Opaque(_) = self.payload {
            return self;
        }

        let mut buf = Vec::new();
        self.payload.encode(&mut buf);

        Message {
            typ: self.typ,
            version: self.version,
            payload: MessagePayload::opaque(buf.as_slice()),
        }
    }

    pub fn build_alert(level: AlertLevel, desc: AlertDescription) -> Message {
        Message {
            typ: ContentType::Alert,
            version: ProtocolVersion::TLSv1_2,
            payload: MessagePayload::Alert(AlertMessagePayload {
                level: level,
                description: desc,
            }),
        }
    }
}
