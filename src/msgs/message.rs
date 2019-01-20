
use crate::msgs::codec::{Codec, Reader};
use crate::msgs::base::Payload;
use crate::msgs::alert::AlertMessagePayload;
use crate::msgs::ccs::ChangeCipherSpecPayload;
use crate::msgs::handshake::HandshakeMessagePayload;
use crate::msgs::enums::{ContentType, ProtocolVersion};
use crate::msgs::enums::{AlertLevel, AlertDescription};
use crate::msgs::enums::HandshakeType;

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

    pub fn decode_given_type(&self,
                             typ: ContentType,
                             vers: ProtocolVersion)
                             -> Option<MessagePayload> {
        if let MessagePayload::Opaque(ref payload) = *self {
            let mut r = Reader::init(&payload.0);
            let parsed = match typ {
                ContentType::Alert => {
                    Some(MessagePayload::Alert(AlertMessagePayload::read(&mut r)?))
                }
                ContentType::Handshake => {
                    let p = HandshakeMessagePayload::read_version(&mut r, vers)?;
                    Some(MessagePayload::Handshake(p))
                }
                ContentType::ChangeCipherSpec => {
                    let p = ChangeCipherSpecPayload::read(&mut r)?;
                    Some(MessagePayload::ChangeCipherSpec(p))
                }
                _ => None,
            };

            if r.any_left() { None } else { parsed }
        } else {
            None
        }
    }

    pub fn length(&self) -> usize {
        match *self {
            MessagePayload::Alert(ref x) => x.length(),
            MessagePayload::Handshake(ref x) => x.length(),
            MessagePayload::ChangeCipherSpec(ref x) => x.length(),
            MessagePayload::Opaque(ref x) => x.0.len(),
        }
    }

    pub fn new_opaque(data: Vec<u8>) -> MessagePayload {
        MessagePayload::Opaque(Payload::new(data))
    }
}

/// A TLS frame, named TLSPlaintext in the standard.
/// This type owns all memory for its interior parts.
#[derive(Debug)]
pub struct Message {
    pub typ: ContentType,
    pub version: ProtocolVersion,
    pub payload: MessagePayload,
}

impl Codec for Message {
    fn read(r: &mut Reader) -> Option<Message> {
        let typ = ContentType::read(r)?;
        let version = ProtocolVersion::read(r)?;
        let len = u16::read(r)?;

        let mut sub = r.sub(len as usize)?;
        let payload = Payload::read(&mut sub)?;

        Some(Message {
            typ,
            version,
            payload: MessagePayload::Opaque(payload),
        })
    }

    fn encode(&self, bytes: &mut Vec<u8>) {
        self.typ.encode(bytes);
        self.version.encode(bytes);
        (self.payload.length() as u16).encode(bytes);
        self.payload.encode(bytes);
    }
}

impl Message {
    /// Do some *very* lax checks on the header, and return
    /// None if it looks really broken.  Otherwise, return
    /// the length field.
    pub fn check_header(bytes: &[u8]) -> Option<usize> {
        let mut rd = Reader::init(bytes);

        let typ = ContentType::read(&mut rd)?;
        let version = ProtocolVersion::read(&mut rd)?;
        let len = u16::read(&mut rd)?;

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

        if let Some(x) = self.payload.decode_given_type(self.typ, self.version) {
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
            payload: MessagePayload::new_opaque(buf),
        }
    }

    pub fn build_alert(level: AlertLevel, desc: AlertDescription) -> Message {
        Message {
            typ: ContentType::Alert,
            version: ProtocolVersion::TLSv1_2,
            payload: MessagePayload::Alert(AlertMessagePayload {
                level,
                description: desc,
            }),
        }
    }

    pub fn build_key_update_notify() -> Message {
        Message {
            typ: ContentType::Handshake,
            version: ProtocolVersion::TLSv1_3,
            payload: MessagePayload::Handshake(HandshakeMessagePayload::build_key_update_notify()),
        }
    }
}

impl<'a> Message {
    pub fn to_borrowed(&'a self) -> BorrowMessage<'a> {
        if let MessagePayload::Opaque(ref p) = self.payload {
            BorrowMessage {
                typ: self.typ,
                version: self.version,
                payload: &p.0
            }
        } else {
            unreachable!("to_borrowed must have opaque message");
        }
    }
}


/// A TLS frame, named TLSPlaintext in the standard.
///
/// This type differs from `Message` because it borrows
/// its payload.  You can make a `Message` from an
/// `BorrowMessage`, but this involves a copy.
///
/// This type also cannot decode its internals and
/// is not a `Codec` type, only `Message` can do that.
#[derive(Debug)]
pub struct BorrowMessage<'a> {
    pub typ: ContentType,
    pub version: ProtocolVersion,
    pub payload: &'a [u8],
}
