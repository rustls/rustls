use std::collections::VecDeque;
use msgs::codec;
use msgs::codec::{Codec, Reader};
use msgs::base::Payload;
use msgs::alert::AlertMessagePayload;
use msgs::ccs::ChangeCipherSpecPayload;
use msgs::handshake::HandshakeMessagePayload;
use msgs::enums::{ContentType, ProtocolVersion};
use msgs::enums::{AlertLevel, AlertDescription};
use msgs::enums::HandshakeType;
use msgs::message::MessagePayload;

#[derive(Debug)]
pub enum DTLSHandshakeFragment {
    Fragment {
        typ: HandshakeType,
        message_seq: u16,
        offset: usize,
        total_len: usize,
        payload: Payload,
    },
    Complete {
        message_seq: u16,
        payload: HandshakeMessagePayload,
    },
}

impl DTLSHandshakeFragment {
    pub fn message_seq(&self) -> u16 {
        match *self {
            DTLSHandshakeFragment::Fragment { message_seq, .. } => message_seq,
            DTLSHandshakeFragment::Complete { message_seq, .. } => message_seq,
        }
    }

    pub fn length(&self) -> usize {
        let mut buf = Vec::new();
        self.encode(&mut buf);
        buf.len()
    }

    pub fn fragment(self, max_frag: usize, out: &mut VecDeque<Self>) {
        match self {
            DTLSHandshakeFragment::Complete { message_seq, ref payload } => {
                let mut buf = Vec::new();
                payload.encode(&mut buf);

                let mut offset = 0;
                for chunk in buf.chunks(max_frag) {
                    let frag = DTLSHandshakeFragment::Fragment {
                        typ:         payload.typ,
                        message_seq: message_seq,
                        offset: offset,
                        total_len: buf.len(),
                        payload: Payload::from_slice(chunk),
                    };

                    out.push_back(frag);
                    offset += chunk.len();
                }
            },
            DTLSHandshakeFragment::Fragment {..} =>  out.push_back(self)
        }
    }
}

impl Codec for DTLSHandshakeFragment {
    fn encode(&self, bytes: &mut Vec<u8>) {
        match *self {
            DTLSHandshakeFragment::Complete { message_seq, ref payload } => {
                // We circumvent HandshakeMessagePayload's encode() and
                // deal with its payload here directly.
                let mut sub: Vec<u8> = Vec::new();
                payload.payload.encode(&mut sub);

                let offset = 0;
                let len = sub.len() as u32;

                payload.typ.encode(bytes);
                codec::encode_u24(len, bytes);
                codec::encode_u16(message_seq, bytes);
                codec::encode_u24(offset, bytes);
                codec::encode_u24(len, bytes);
                bytes.append(&mut sub);
            },
            DTLSHandshakeFragment::Fragment { typ, message_seq, offset, total_len, ref payload } => {
                // Encode payload to learn length
                let mut sub: Vec<u8> = Vec::new();
                payload.encode(&mut sub);

                typ.encode(bytes);
                codec::encode_u24(sub.len() as u32, bytes);
                codec::encode_u16(message_seq, bytes);
                codec::encode_u24(offset as u32, bytes);
                codec::encode_u24(total_len as u32, bytes);
                bytes.append(&mut sub);
            },
        }
    }

    fn read(r: &mut Reader) -> Option<DTLSHandshakeFragment> {
        let typ = try_ret!(HandshakeType::read(r));
        let len = try_ret!(codec::read_u24(r)) as usize;
        let message_seq = try_ret!(codec::read_u16(r));
        let offset = try_ret!(codec::read_u24(r)) as usize;
        let total_len = try_ret!(codec::read_u24(r)) as usize;
        let mut sub = try_ret!(r.sub(len as usize));
        let payload = try_ret!(Payload::read(&mut sub));

        Some(DTLSHandshakeFragment::Fragment {
            typ: typ,
            message_seq: message_seq,
            offset: offset,
            total_len: total_len,
            payload: payload,
        })
    }
}

#[derive(Debug)]
pub enum DTLSMessagePayload {
    Alert(AlertMessagePayload),
    Handshake(DTLSHandshakeFragment),
    ChangeCipherSpec(ChangeCipherSpecPayload),
    Opaque(Payload),
}

impl MessagePayload for DTLSMessagePayload {
    fn encode(&self, bytes: &mut Vec<u8>) {
        match *self {
            DTLSMessagePayload::Alert(ref x) => x.encode(bytes),
            DTLSMessagePayload::Handshake(ref x) => x.encode(bytes),
            DTLSMessagePayload::ChangeCipherSpec(ref x) => x.encode(bytes),
            DTLSMessagePayload::Opaque(ref x) => x.encode(bytes),
        }
    }

    fn decode_given_type(&self,
                         typ: ContentType,
                         vers: ProtocolVersion)
                         -> Option<DTLSMessagePayload> {
        if let DTLSMessagePayload::Opaque(ref payload) = *self {
            let mut r = Reader::init(&payload.0);
            let parsed = match typ {
                ContentType::Alert => {
                    Some(DTLSMessagePayload::Alert(try_ret!(AlertMessagePayload::read(&mut r))))
                }
                ContentType::Handshake => {
                    let p = try_ret!(DTLSHandshakeFragment::read(&mut r));
                    Some(DTLSMessagePayload::Handshake(p))
                }
                ContentType::ChangeCipherSpec => {
                    let p = try_ret!(ChangeCipherSpecPayload::read(&mut r));
                    Some(DTLSMessagePayload::ChangeCipherSpec(p))
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
            DTLSMessagePayload::Alert(ref x) => x.length(),
            DTLSMessagePayload::Handshake(ref x) => x.length(),
            DTLSMessagePayload::ChangeCipherSpec(ref x) => x.length(),
            DTLSMessagePayload::Opaque(ref x) => x.len(),
        }
    }

    fn new_opaque(data: Vec<u8>) -> DTLSMessagePayload {
        DTLSMessagePayload::Opaque(Payload::new(data))
    }
}

#[derive(Debug)]
pub struct DTLSMessage {
    pub typ: ContentType,
    pub version: ProtocolVersion,
    pub epoch: u16,
    pub sequence: u64,
    pub payload: DTLSMessagePayload,
}

impl Codec for DTLSMessage {
    fn read(r: &mut Reader) -> Option<DTLSMessage> {
        let typ = try_ret!(ContentType::read(r));
        let version = try_ret!(ProtocolVersion::read(r));
        let epoch = try_ret!(codec::read_u16(r));
        let sequence = try_ret!(codec::read_u48(r));
        let len = try_ret!(codec::read_u16(r));

        let mut sub = try_ret!(r.sub(len as usize));
        let payload = try_ret!(Payload::read(&mut sub));

        Some(DTLSMessage {
            typ: typ,
            version: version,
            epoch: epoch,
            sequence: sequence,
            payload: DTLSMessagePayload::Opaque(payload),
        })
    }

    fn encode(&self, bytes: &mut Vec<u8>) {
        self.typ.encode(bytes);
        self.version.encode(bytes);
        codec::encode_u16(self.epoch as u16, bytes);
        codec::encode_u48(self.sequence, bytes);
        codec::encode_u16(self.payload.length() as u16, bytes);
        self.payload.encode(bytes);
    }
}
