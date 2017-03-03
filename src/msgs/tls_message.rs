use msgs::codec::{Codec, Reader, encode_u16, read_u16};
use msgs::base::Payload;
use msgs::alert::AlertMessagePayload;
use msgs::ccs::ChangeCipherSpecPayload;
use msgs::handshake::HandshakeMessagePayload;
use msgs::enums::{ContentType, ProtocolVersion};
use msgs::enums::{AlertLevel, AlertDescription};
use msgs::enums::HandshakeType;
use msgs::message::{BorrowMessage, Message, MessagePayload};

use std::mem;

#[derive(Debug)]
pub enum TLSMessagePayload {
    Alert(AlertMessagePayload),
    Handshake(HandshakeMessagePayload),
    ChangeCipherSpec(ChangeCipherSpecPayload),
    Opaque(Payload),
}

impl MessagePayload for TLSMessagePayload {
    fn encode(&self, bytes: &mut Vec<u8>) {
        match *self {
            TLSMessagePayload::Alert(ref x) => x.encode(bytes),
            TLSMessagePayload::Handshake(ref x) => x.encode(bytes),
            TLSMessagePayload::ChangeCipherSpec(ref x) => x.encode(bytes),
            TLSMessagePayload::Opaque(ref x) => x.encode(bytes),
        }
    }

    fn decode_given_type(&self,
                         typ: ContentType,
                         vers: ProtocolVersion)
                         -> Option<TLSMessagePayload> {
        if let TLSMessagePayload::Opaque(ref payload) = *self {
            let mut r = Reader::init(&payload.0);
            let parsed = match typ {
                ContentType::Alert => {
                    Some(TLSMessagePayload::Alert(try_ret!(AlertMessagePayload::read(&mut r))))
                }
                ContentType::Handshake => {
                    let p = try_ret!(HandshakeMessagePayload::read_version(&mut r, vers));
                    Some(TLSMessagePayload::Handshake(p))
                }
                ContentType::ChangeCipherSpec => {
                    let p = try_ret!(ChangeCipherSpecPayload::read(&mut r));
                    Some(TLSMessagePayload::ChangeCipherSpec(p))
                }
                _ => None,
            };

            if r.any_left() { None } else { parsed }
        } else {
            None
        }
    }

    fn length(&self) -> usize {
        match *self {
            TLSMessagePayload::Alert(ref x) => x.length(),
            TLSMessagePayload::Handshake(ref x) => x.length(),
            TLSMessagePayload::ChangeCipherSpec(ref x) => x.length(),
            TLSMessagePayload::Opaque(ref x) => x.len(),
        }
    }

    fn new_opaque(data: Vec<u8>) -> TLSMessagePayload {
        TLSMessagePayload::Opaque(Payload::new(data))
    }

    fn encode_for_transcript(&self) -> Vec<u8> {
        if let &TLSMessagePayload::Handshake(ref hs) = self {
            hs.get_encoding()
        } else {
            unreachable!()
        }
    }
}

/// A TLS frame, named TLSPlaintext in the standard.
/// This type owns all memory for its interior parts.
#[derive(Debug)]
pub struct TLSMessage {
    pub typ: ContentType,
    pub version: ProtocolVersion,
    pub payload: TLSMessagePayload,
}

impl Codec for TLSMessage {
    fn read(r: &mut Reader) -> Option<TLSMessage> {
        let typ = try_ret!(ContentType::read(r));
        let version = try_ret!(ProtocolVersion::read(r));
        let len = try_ret!(read_u16(r));

        let mut sub = try_ret!(r.sub(len as usize));
        let payload = try_ret!(Payload::read(&mut sub));

        Some(TLSMessage {
            typ: typ,
            version: version,
            payload: TLSMessagePayload::Opaque(payload),
        })
    }

    fn encode(&self, bytes: &mut Vec<u8>) {
        self.typ.encode(bytes);
        self.version.encode(bytes);
        encode_u16(self.payload.length() as u16, bytes);
        self.payload.encode(bytes);
    }
}

impl TLSMessage {
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

        if let TLSMessagePayload::Handshake(ref hsp) = self.payload {
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

    pub fn into_opaque(self) -> TLSMessage {
        if let TLSMessagePayload::Opaque(_) = self.payload {
            return self;
        }

        let mut buf = Vec::new();
        self.payload.encode(&mut buf);

        TLSMessage {
            typ: self.typ,
            version: self.version,
            payload: TLSMessagePayload::new_opaque(buf),
        }
    }

    pub fn build_alert(level: AlertLevel, desc: AlertDescription) -> TLSMessage {
        TLSMessage {
            typ: ContentType::Alert,
            version: ProtocolVersion::TLSv1_2,
            payload: TLSMessagePayload::Alert(AlertMessagePayload {
                level: level,
                description: desc,
            }),
        }
    }

    pub fn build_key_update_notify() -> TLSMessage {
        TLSMessage {
            typ: ContentType::Handshake,
            version: ProtocolVersion::TLSv1_3,
            payload: TLSMessagePayload::Handshake(HandshakeMessagePayload::build_key_update_notify()),
        }
    }

    pub fn to_borrowed<'a>(&'a self) -> TLSBorrowMessage {
        if let TLSMessagePayload::Opaque(Payload(ref payload)) = self.payload {
            TLSBorrowMessage {
                typ: self.typ,
                version: self.version,
                payload: &payload[..],
            }
        } else {
            unreachable!()
        }
    }
}

impl Message for TLSMessage {
    type Payload = TLSMessagePayload;

    fn version(&self) -> ProtocolVersion {
        self.version
    }

    fn typ(&self) -> ContentType {
        self.typ
    }

    fn payload<'a>(&'a self) -> &'a Self::Payload {
        &self.payload
    }

    fn take_opaque_payload(&mut self) -> Option<Payload> {
        if let TLSMessagePayload::Opaque(ref mut op) = self.payload {
            Some(mem::replace(op, Payload::empty()))
        } else {
            None
        }
    }

    fn to_tls(&mut self) -> TLSMessage {
        let buf = self.take_opaque_payload().unwrap().0;
        TLSMessage {
            typ: self.typ,
            version: self.version,
            payload: TLSMessagePayload::new_opaque(buf),
        }
    }

    fn clone_from_tls(&self, msg: TLSMessage) -> Self {
        msg
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
pub struct TLSBorrowMessage<'a> {
    pub typ: ContentType,
    pub version: ProtocolVersion,
    pub payload: &'a [u8],
}

impl<'a> BorrowMessage for TLSBorrowMessage<'a> {
    type Message = TLSMessage;

    fn version(&self) -> ProtocolVersion {
        self.version
    }

    fn typ(&self) -> ContentType {
        self.typ
    }

    fn payload<'b>(&'b self) -> &'b [u8] {
        self.payload
    }

    fn to_tls_borrowed(&self) -> TLSBorrowMessage {
        TLSBorrowMessage {
            typ: self.typ,
            version: self.version,
            payload: &self.payload[..],
        }
    }

    fn clone_from_tls(&self, msg: TLSMessage) -> Self::Message {
        TLSMessage {
            typ: self.typ,
            version: self.version,
            payload: TLSMessagePayload::new_opaque(msg.take_payload()),
        }
    }
}

