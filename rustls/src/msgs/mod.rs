#![expect(missing_docs)]
//! <https://langsec.org> cat says:
//!
//! ```text
//!  ___ _   _ _    _      ___ ___ ___ ___   ___ _  _ ___ _____ ___ ___  _  _
//! | __| | | | |  | |    | _ \ __/ __/ _ \ / __| \| |_ _|_   _|_ _/ _ \| \| |
//! | _|| |_| | |__| |__  |   / _| (_| (_) | (_ | .` || |  | |  | | (_) | .` |
//! |_|  \___/|____|____| |_|_\___\___\___/ \___|_|\_|___| |_| |___\___/|_|\_|
//!
//!
//!                      .__....._             _.....__,
//!                        .": o :':         ;': o :".
//!                        `. `-' .'.       .'. `-' .'
//!                          `---'             `---'
//!
//!                _...----...      ...   ...      ...----..._
//!             .-'__..-""'----    `.  `"`  .'    ----'""-..__`-.
//!            '.-'   _.--"""'       `-._.-'       '"""--._   `-.`
//!            '  .-"'                  :                  `"-.  `
//!              '   `.              _.'"'._              .'   `
//!                    `.       ,.-'"       "'-.,       .'
//!                      `.                           .'
//!                        `-._                   _.-'
//!                            `"'--...___...--'"`
//!
//!  ___ ___ ___ ___  ___ ___   ___ ___  ___   ___ ___ ___ ___ ___ _  _  ___
//! | _ ) __| __/ _ \| _ \ __| | _ \ _ \/ _ \ / __| __/ __/ __|_ _| \| |/ __|
//! | _ \ _|| _| (_) |   / _|  |  _/   / (_) | (__| _|\__ \__ \| || .` | (_ |
//! |___/___|_| \___/|_|_\___| |_| |_|_\\___/ \___|___|___/___/___|_|\_|\___|
//! ```
//!
//! <https://langsec.org/ForWantOfANail-h2hc2014.pdf>

use core::cmp::min_by_key;

use alloc::boxed::Box;
use alloc::vec::Vec;

use crate::crypto::cipher::{
    EncodableVersion, EncodedMessage, EncodingContext, MessageError, Payload,
};
use crate::enums::{ContentType, ContentTypeName, HandshakeType, ProtocolVersion};
use crate::error::{AlertDescription, InvalidMessage};
use crate::verify::DigitallySignedStruct;

#[macro_use]
mod macros;

mod client_hello;
pub(crate) use client_hello::{
    CertificateStatusRequest, ClientExtensions, ClientHelloPayload, ClientSessionTicket,
    ClientTicketRequest, EncryptedClientHello, EncryptedClientHelloOuter, PresharedKeyBinder,
    PresharedKeyIdentity, PresharedKeyOffer, PskKeyExchangeModes, ServerNamePayload,
};

mod codec;
use codec::U24;
pub(crate) use codec::{
    CERTIFICATE_MAX_SIZE_LIMIT, Codec, LengthPrefixedBuffer, ListLength, MaybeEmpty, NonEmpty,
    Reader, SizedPayload, TlsListElement, U48, hex, put_u16, put_u64,
};

mod deframer;
pub(crate) use deframer::{Deframed, Deframer, Delocator, HandshakeAlignedProof, Locator};

mod enums;
#[cfg(test)]
pub(crate) use enums::ECCurveType;
#[cfg(test)]
pub(crate) use enums::tests::{test_enum8, test_enum8_display, test_enum16};
pub(crate) use enums::{
    AlertLevel, AlertLevelName, ClientCertificateType, Compression, ExtensionType, KeyUpdateRequest,
};

mod fragmenter;
pub(crate) use fragmenter::{Fragmenter, MAX_FRAGMENT_LEN};

#[macro_use]
mod handshake;
use handshake::HELLO_RETRY_REQUEST_RANDOM;
pub(crate) use handshake::{
    ALL_KEY_EXCHANGE_ALGORITHMS, CertificateChain, CertificatePayloadTls13,
    CertificateRequestExtensions, CertificateRequestPayload, CertificateRequestPayloadTls13,
    CertificateStatus, ClientDhParams, ClientEcdhParams, ClientExtensionsInput,
    ClientKeyExchangeParams, CompressedCertificatePayload, Encoding, HelloRetryRequest,
    HelloRetryRequestExtensions, KeyShareEntry, KxDecode, NewSessionTicketPayload,
    NewSessionTicketPayloadTls13, Random, ServerExtensionsInput, ServerKeyExchange,
    ServerKeyExchangeParams, ServerKeyExchangePayload, SessionId, SingleProtocolName,
    SupportedEcPointFormats, SupportedProtocolVersions, TransportParameters,
};
#[cfg(test)]
pub(crate) use handshake::{EcParameters, NewSessionTicketExtensions, ServerEcdhParams};

mod server_hello;
pub(crate) use server_hello::{
    EchConfigContents, EchConfigPayload, EncryptedExtensions, HpkeKeyConfig, ServerExtensions,
    ServerHelloPayload, ServerTicketRequestHint,
};

#[cfg(test)]
mod handshake_test;

pub mod fuzzing {
    pub use super::deframer::fuzz_deframer;
    use super::{Codec, EncodedMessage, Fragmenter, Message, Payload, Reader};
    use crate::common_state::Protocol;
    use crate::crypto::cipher::EncodingContext;
    use crate::server::ServerSessionValue;

    pub fn fuzz_fragmenter(data: &[u8]) {
        let mut rdr = Reader::new(data);
        let Ok(msg) = EncodedMessage::<Payload<'_>>::read(&mut rdr) else {
            return;
        };

        let mut frg = Fragmenter::default();
        frg.set_max_fragment_size(Some(32), Protocol::Tcp)
            .unwrap();
        for msg in frg.fragment(msg.typ, msg.version, msg.payload.bytes().into(), 0) {
            Message::try_from(&EncodedMessage {
                typ: msg.typ,
                version: msg.version,
                payload: Payload::Owned(msg.payload.to_vec()),
            })
            .ok();
        }
    }

    pub fn fuzz_message(data: &[u8]) {
        let mut rdr = Reader::new(data);
        let Ok(m) = EncodedMessage::<Payload<'_>>::read(&mut rdr) else {
            return;
        };

        let Ok(msg) = Message::try_from(&m) else {
            return;
        };

        //println!("msg = {:#?}", m);
        let expected_version = msg.version.encode();
        let enc = EncodedMessage::<Payload<'_>>::from(msg)
            .borrow_outbound()
            .to_unencrypted_bytes(EncodingContext::new());
        //println!("data = {:?}", &data[..rdr.used()]);
        assert_eq!(enc[0], data[0]);
        // The version bytes will have been rewritten by `EncodableVersion`
        assert_eq!([enc[1], enc[2]], expected_version.to_array());
        assert_eq!(&enc[3..], &data[3..data.len() - rdr.left()]);
    }

    pub fn fuzz_server_session_value(data: &[u8]) {
        let mut rdr = Reader::new(data);
        let _ = ServerSessionValue::read(&mut rdr);
    }
}

/// A message with decoded payload
#[derive(Debug)]
pub(crate) struct Message<'a> {
    pub version: EncodableVersion,
    pub payload: MessagePayload<'a>,
}

impl<'a> Message<'a> {
    pub(crate) fn build_alert(
        level: AlertLevel,
        desc: AlertDescription,
        version: ProtocolVersion,
    ) -> Self {
        Self {
            version: EncodableVersion::Legacy(version),
            payload: MessagePayload::Alert(AlertMessagePayload {
                level,
                description: desc,
            }),
        }
    }

    pub(crate) fn build_key_update_notify(
        version: ProtocolVersion,
        seq: HandshakeSequenceNumber,
    ) -> Self {
        Self {
            version: EncodableVersion::Legacy(version),
            payload: MessagePayload::handshake(
                HandshakeMessagePayload(HandshakePayload::KeyUpdate(
                    KeyUpdateRequest::UpdateNotRequested,
                )),
                seq,
            ),
        }
    }

    pub(crate) fn build_key_update_request(
        version: ProtocolVersion,
        seq: HandshakeSequenceNumber,
    ) -> Self {
        Self {
            version: EncodableVersion::Legacy(version),
            payload: MessagePayload::handshake(
                HandshakeMessagePayload(HandshakePayload::KeyUpdate(
                    KeyUpdateRequest::UpdateRequested,
                )),
                seq,
            ),
        }
    }

    pub(crate) fn into_owned(self) -> Message<'static> {
        let Self { version, payload } = self;
        Message {
            version,
            payload: payload.into_owned(),
        }
    }

    #[cfg(test)]
    pub(crate) fn into_wire_bytes(self) -> Vec<u8> {
        EncodedMessage::<Payload<'_>>::from(self)
            .borrow_outbound()
            .to_unencrypted_bytes(EncodingContext::new())
    }

    pub(crate) fn handshake_type(&self) -> Option<HandshakeType> {
        match &self.payload {
            MessagePayload::Handshake { parsed, .. } => Some(parsed.0.handshake_type()),
            _ => None,
        }
    }
}

impl<'a> TryFrom<EncodedMessage<&'a [u8]>> for Message<'a> {
    type Error = InvalidMessage;

    fn try_from(plain: EncodedMessage<&'a [u8]>) -> Result<Self, Self::Error> {
        Ok(Self {
            version: plain.version,
            payload: MessagePayload::new(plain.typ, plain.version.version(), plain.payload)?,
        })
    }
}

impl<'a> TryFrom<&'a EncodedMessage<Payload<'a>>> for Message<'a> {
    type Error = InvalidMessage;

    fn try_from(plain: &'a EncodedMessage<Payload<'a>>) -> Result<Self, Self::Error> {
        Ok(Self {
            version: plain.version,
            payload: MessagePayload::new(
                plain.typ,
                plain.version.version(),
                plain.payload.bytes(),
            )?,
        })
    }
}

pub(crate) struct MessageHeader {
    pub(crate) typ: ContentType,
    pub(crate) version: ProtocolVersion,
    pub(crate) epoch_and_sequence: Option<(Epoch, u64)>,
    pub(crate) len: u16,
}

pub(crate) fn read_opaque_message_header(
    r: &mut Reader<'_>,
) -> Result<MessageHeader, MessageError> {
    let typ = ContentType::read(r).map_err(|_| MessageError::TooShortForHeader)?;
    // Don't accept any new content-types.
    if ContentTypeName::try_from(typ).is_err() {
        return Err(MessageError::InvalidContentType);
    }

    let version = ProtocolVersion::read(r).map_err(|_| MessageError::TooShortForHeader)?;
    // Accept only versions 0x03XX (TLS) or 0xfe (DTLS) for any XX
    let allowed_version_high_bytes = [0x0300, 0xfe00].as_slice();
    if !allowed_version_high_bytes.contains(&(version.0 & 0xff00)) {
        return Err(MessageError::UnknownProtocolVersion);
    }

    let epoch_and_sequence = if version.is_datagram_tls() {
        let epoch = Epoch::read(r, version).map_err(|_| MessageError::TooShortForHeader)?;
        let record_seq = U48::read(r).map_err(|_| MessageError::TooShortForHeader)?;
        Some((epoch, record_seq.0))
    } else {
        None
    };

    let len = u16::read(r).map_err(|_| MessageError::TooShortForHeader)?;

    // Reject undersize messages
    //  implemented per section 5.1 of RFC 9846 (TLSv1.3)
    //              per section 6.2.1 of RFC 5246 (TLSv1.2)
    if typ != ContentType::ApplicationData && len == 0 {
        return Err(MessageError::InvalidEmptyPayload);
    }

    // Reject oversize messages
    if len >= MAX_PAYLOAD {
        return Err(MessageError::MessageTooLarge);
    }

    Ok(MessageHeader {
        typ,
        version,
        epoch_and_sequence,
        len,
    })
}

#[non_exhaustive]
#[derive(Debug)]
pub(crate) enum MessagePayload<'a> {
    Alert(AlertMessagePayload),
    // one handshake message, parsed
    Handshake {
        seq: HandshakeSequenceNumber,
        parsed: HandshakeMessagePayload<'a>,
        encoded: Payload<'a>,
    },
    // (potentially) multiple handshake messages, of various handshake types,
    // encoded
    HandshakeFlight(Vec<(HandshakeType, HandshakeSequenceNumber, Vec<u8>)>),
    ChangeCipherSpec(ChangeCipherSpecPayload),
    ApplicationData(Payload<'a>),
}

impl<'a> MessagePayload<'a> {
    pub(crate) fn encode(&self, bytes: &mut Vec<u8>) {
        match self {
            Self::Alert(x) => x.encode(bytes),
            Self::Handshake { encoded, .. } => bytes.extend(encoded.bytes()),
            Self::HandshakeFlight(encoded) => {
                for (_, _, encoded) in encoded {
                    bytes.extend(encoded)
                }
            }
            Self::ChangeCipherSpec(x) => x.encode(bytes),
            Self::ApplicationData(x) => x.encode(bytes),
        }
    }

    pub(crate) fn handshake(
        parsed: HandshakeMessagePayload<'a>,
        seq: HandshakeSequenceNumber,
    ) -> Self {
        Self::Handshake {
            encoded: Payload::new(parsed.get_encoding()),
            parsed,
            seq,
        }
    }

    pub(crate) fn new(
        typ: ContentType,
        vers: ProtocolVersion,
        payload: &'a [u8],
    ) -> Result<Self, InvalidMessage> {
        let mut r = Reader::new(payload);
        match typ {
            ContentType::ApplicationData => Ok(Self::ApplicationData(Payload::Borrowed(payload))),
            ContentType::Alert => AlertMessagePayload::read(&mut r).map(MessagePayload::Alert),
            ContentType::Handshake => {
                // Strip out handshake fragment fields from DTLS messages, because we don't want
                // them anymore!
                let (payload, seq) = if vers.is_datagram_tls() {
                    let mut payload_without_handshake_fragments =
                        Vec::with_capacity(payload.len() - DTLS_HANDSHAKE_HEADER_EXTRA);

                    // Copy in msg_type (1 byte) + length (3 bytes)
                    payload_without_handshake_fragments.extend(&payload[..1 + 3]);

                    // Skip msg_typ (1 byte) + length (3 bytes) + message_seq (2 bytes) +
                    // fragment_offset (3 bytes) + fragment_length (3 bytes)
                    payload_without_handshake_fragments.extend(&payload[1 + 3 + 2 + 3 + 3..]);

                    (
                        Payload::Owned(payload_without_handshake_fragments),
                        HandshakeSequenceNumber::read_bytes(&payload[1 + 3..1 + 3 + 2])?,
                    )
                } else {
                    (Payload::Borrowed(payload), 0.into())
                };
                HandshakeMessagePayload::read_version(&mut r, vers).map(|parsed| Self::Handshake {
                    parsed,
                    encoded: payload,
                    seq,
                })
            }
            ContentType::ChangeCipherSpec => {
                ChangeCipherSpecPayload::read(&mut r).map(MessagePayload::ChangeCipherSpec)
            }
            _ => Err(InvalidMessage::InvalidContentType),
        }
    }

    pub(crate) fn content_type(&self) -> ContentType {
        match self {
            Self::Alert(_) => ContentType::Alert,
            Self::Handshake { .. } | Self::HandshakeFlight { .. } => ContentType::Handshake,
            Self::ChangeCipherSpec(_) => ContentType::ChangeCipherSpec,
            Self::ApplicationData(_) => ContentType::ApplicationData,
        }
    }

    pub(crate) fn into_owned(self) -> MessagePayload<'static> {
        use MessagePayload::*;
        match self {
            Alert(x) => Alert(x),
            Handshake {
                parsed,
                encoded,
                seq,
            } => Handshake {
                parsed: parsed.into_owned(),
                encoded: encoded.into_owned(),
                seq,
            },
            HandshakeFlight(x) => HandshakeFlight(x),
            ChangeCipherSpec(x) => ChangeCipherSpec(x),
            ApplicationData(x) => ApplicationData(x.into_owned()),
        }
    }
}

impl From<Message<'_>> for EncodedMessage<Payload<'_>> {
    fn from(msg: Message<'_>) -> Self {
        let typ = msg.payload.content_type();
        let payload = match msg.payload {
            MessagePayload::ApplicationData(payload) => payload.into_owned(),
            _ => {
                let mut buf = Vec::new();
                msg.payload.encode(&mut buf);
                Payload::Owned(buf)
            }
        };

        Self {
            typ,
            version: msg.version,
            payload,
        }
    }
}

#[derive(Debug)]
pub(crate) struct HandshakeMessagePayload<'a>(pub(crate) HandshakePayload<'a>);

impl<'a> Codec<'a> for HandshakeMessagePayload<'a> {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.payload_encode(bytes, Encoding::Standard);
    }

    fn read(r: &mut Reader<'a>) -> Result<Self, InvalidMessage> {
        Self::read_version(r, ProtocolVersion::TLSv1_2)
    }
}

impl<'a> HandshakeMessagePayload<'a> {
    pub(crate) fn read_version(
        r: &mut Reader<'a>,
        vers: ProtocolVersion,
    ) -> Result<Self, InvalidMessage> {
        let typ = HandshakeType::read(r)?;
        let len = U24::read(r)?.0 as usize;
        if vers.is_datagram_tls() {
            // Skip the DTLS seq and fragment fields, which are no longer meaningful
            let _ = r.take(DTLS_HANDSHAKE_HEADER_EXTRA);
        }
        r.sub(len)?
            .all("HandshakeMessagePayload", |sub| {
                Ok(Self(match typ {
                    HandshakeType::HelloRequest if sub.left() == 0 => {
                        HandshakePayload::HelloRequest
                    }
                    HandshakeType::ClientHello => {
                        HandshakePayload::ClientHello(ClientHelloPayload::read(sub)?)
                    }
                    HandshakeType::ServerHello => {
                        let version = ProtocolVersion::read(sub)?;
                        let random = Random::read(sub)?;

                        if random == HELLO_RETRY_REQUEST_RANDOM {
                            let mut hrr = HelloRetryRequest::read(sub)?;
                            hrr.legacy_version = version;
                            HandshakePayload::HelloRetryRequest(hrr)
                        } else {
                            let mut shp = ServerHelloPayload::read(sub)?;
                            shp.legacy_version = version;
                            shp.random = random;
                            HandshakePayload::ServerHello(shp)
                        }
                    }
                    HandshakeType::Certificate
                        if vers == ProtocolVersion::TLSv1_3
                            || vers == ProtocolVersion::DTLSv1_3 =>
                    {
                        let p = CertificatePayloadTls13::read(sub)?;
                        HandshakePayload::CertificateTls13(p)
                    }
                    HandshakeType::Certificate => {
                        HandshakePayload::Certificate(CertificateChain::read(sub)?)
                    }
                    HandshakeType::ServerKeyExchange => {
                        let p = ServerKeyExchangePayload::read(sub)?;
                        HandshakePayload::ServerKeyExchange(p)
                    }
                    HandshakeType::ServerHelloDone => HandshakePayload::ServerHelloDone,
                    HandshakeType::ClientKeyExchange => {
                        HandshakePayload::ClientKeyExchange(Payload::read(sub))
                    }
                    HandshakeType::CertificateRequest
                        if vers == ProtocolVersion::TLSv1_3
                            || vers == ProtocolVersion::DTLSv1_3 =>
                    {
                        let p = CertificateRequestPayloadTls13::read(sub)?;
                        HandshakePayload::CertificateRequestTls13(p)
                    }
                    HandshakeType::CertificateRequest => {
                        let p = CertificateRequestPayload::read(sub)?;
                        HandshakePayload::CertificateRequest(p)
                    }
                    HandshakeType::CompressedCertificate => {
                        HandshakePayload::CompressedCertificate(CompressedCertificatePayload::read(
                            sub,
                        )?)
                    }
                    HandshakeType::CertificateVerify => {
                        HandshakePayload::CertificateVerify(DigitallySignedStruct::read(sub)?)
                    }
                    HandshakeType::NewSessionTicket
                        if vers == ProtocolVersion::TLSv1_3
                            || vers == ProtocolVersion::DTLSv1_3 =>
                    {
                        let p = NewSessionTicketPayloadTls13::read(sub)?;
                        HandshakePayload::NewSessionTicketTls13(p)
                    }
                    HandshakeType::NewSessionTicket => {
                        let p = NewSessionTicketPayload::read(sub)?;
                        HandshakePayload::NewSessionTicket(p)
                    }
                    HandshakeType::EncryptedExtensions => HandshakePayload::EncryptedExtensions(
                        Box::new(EncryptedExtensions::read(sub)?),
                    ),
                    HandshakeType::KeyUpdate => {
                        HandshakePayload::KeyUpdate(KeyUpdateRequest::read(sub)?)
                    }
                    HandshakeType::EndOfEarlyData => HandshakePayload::EndOfEarlyData,
                    HandshakeType::Finished => HandshakePayload::Finished(Payload::read(sub)),
                    HandshakeType::CertificateStatus => {
                        HandshakePayload::CertificateStatus(CertificateStatus::read(sub)?)
                    }
                    HandshakeType::MessageHash => {
                        // does not appear on the wire
                        return Err(InvalidMessage::UnexpectedMessage("MessageHash"));
                    }
                    HandshakeType::HelloRetryRequest => {
                        // not legal on wire
                        return Err(InvalidMessage::UnexpectedMessage("HelloRetryRequest"));
                    }
                    _ => HandshakePayload::Unknown((typ, Payload::read(sub))),
                }))
            })
    }

    pub(crate) fn encoding_for_binder_signing(&self) -> Vec<u8> {
        let mut ret = self.get_encoding();
        let ret_len = ret
            .len()
            .saturating_sub(self.total_binder_length());
        ret.truncate(ret_len);
        ret
    }

    pub(crate) fn total_binder_length(&self) -> usize {
        match &self.0 {
            HandshakePayload::ClientHello(ch) => match &ch.preshared_key_offer {
                Some(offer) => {
                    let mut binders_encoding = Vec::new();
                    offer
                        .binders
                        .encode(&mut binders_encoding);
                    binders_encoding.len()
                }
                _ => 0,
            },
            _ => 0,
        }
    }

    pub(crate) fn payload_encode(&self, bytes: &mut Vec<u8>, encoding: Encoding) {
        // output type, length, and encoded payload
        self.0
            .wire_handshake_type()
            .encode(bytes);

        let nested = LengthPrefixedBuffer::new(
            ListLength::U24 {
                max: usize::MAX,
                error: InvalidMessage::MessageTooLarge,
            },
            bytes,
        );

        match &self.0 {
            // for Server Hello and HelloRetryRequest payloads we need to encode the payload
            // differently based on the purpose of the encoding.
            HandshakePayload::ServerHello(payload) => payload.payload_encode(nested.buf, encoding),
            HandshakePayload::HelloRetryRequest(payload) => {
                payload.payload_encode(nested.buf, encoding)
            }

            // All other payload types are encoded the same regardless of purpose.
            _ => self.0.encode(nested.buf),
        }
    }

    pub(crate) fn build_handshake_hash(hash: &[u8]) -> Self {
        Self(HandshakePayload::MessageHash(Payload::new(hash.to_vec())))
    }

    pub(crate) fn into_owned(self) -> HandshakeMessagePayload<'static> {
        HandshakeMessagePayload(self.0.into_owned())
    }
}

#[derive(Debug)]
pub(crate) enum HandshakePayload<'a> {
    HelloRequest,
    ClientHello(ClientHelloPayload),
    ServerHello(ServerHelloPayload),
    HelloRetryRequest(HelloRetryRequest),
    Certificate(CertificateChain<'a>),
    CertificateTls13(CertificatePayloadTls13<'a>),
    CompressedCertificate(CompressedCertificatePayload<'a>),
    ServerKeyExchange(ServerKeyExchangePayload),
    CertificateRequest(CertificateRequestPayload),
    CertificateRequestTls13(CertificateRequestPayloadTls13),
    CertificateVerify(DigitallySignedStruct),
    ServerHelloDone,
    EndOfEarlyData,
    ClientKeyExchange(Payload<'a>),
    NewSessionTicket(NewSessionTicketPayload),
    NewSessionTicketTls13(NewSessionTicketPayloadTls13),
    EncryptedExtensions(Box<EncryptedExtensions<'a>>),
    KeyUpdate(KeyUpdateRequest),
    Finished(Payload<'a>),
    CertificateStatus(CertificateStatus<'a>),
    MessageHash(Payload<'a>),
    Unknown((HandshakeType, Payload<'a>)),
}

impl HandshakePayload<'_> {
    fn encode(&self, bytes: &mut Vec<u8>) {
        use self::HandshakePayload::*;
        match self {
            HelloRequest | ServerHelloDone | EndOfEarlyData => {}
            ClientHello(x) => x.encode(bytes),
            ServerHello(x) => x.encode(bytes),
            HelloRetryRequest(x) => x.encode(bytes),
            Certificate(x) => x.encode(bytes),
            CertificateTls13(x) => x.encode(bytes),
            CompressedCertificate(x) => x.encode(bytes),
            ServerKeyExchange(x) => x.encode(bytes),
            ClientKeyExchange(x) => x.encode(bytes),
            CertificateRequest(x) => x.encode(bytes),
            CertificateRequestTls13(x) => x.encode(bytes),
            CertificateVerify(x) => x.encode(bytes),
            NewSessionTicket(x) => x.encode(bytes),
            NewSessionTicketTls13(x) => x.encode(bytes),
            EncryptedExtensions(x) => x.encode(bytes),
            KeyUpdate(x) => x.encode(bytes),
            Finished(x) => x.encode(bytes),
            CertificateStatus(x) => x.encode(bytes),
            MessageHash(x) => x.encode(bytes),
            Unknown((_, x)) => x.encode(bytes),
        }
    }

    pub(crate) fn handshake_type(&self) -> HandshakeType {
        use self::HandshakePayload::*;
        match self {
            HelloRequest => HandshakeType::HelloRequest,
            ClientHello(_) => HandshakeType::ClientHello,
            ServerHello(_) => HandshakeType::ServerHello,
            HelloRetryRequest(_) => HandshakeType::HelloRetryRequest,
            Certificate(_) | CertificateTls13(_) => HandshakeType::Certificate,
            CompressedCertificate(_) => HandshakeType::CompressedCertificate,
            ServerKeyExchange(_) => HandshakeType::ServerKeyExchange,
            CertificateRequest(_) | CertificateRequestTls13(_) => HandshakeType::CertificateRequest,
            CertificateVerify(_) => HandshakeType::CertificateVerify,
            ServerHelloDone => HandshakeType::ServerHelloDone,
            EndOfEarlyData => HandshakeType::EndOfEarlyData,
            ClientKeyExchange(_) => HandshakeType::ClientKeyExchange,
            NewSessionTicket(_) | NewSessionTicketTls13(_) => HandshakeType::NewSessionTicket,
            EncryptedExtensions(_) => HandshakeType::EncryptedExtensions,
            KeyUpdate(_) => HandshakeType::KeyUpdate,
            Finished(_) => HandshakeType::Finished,
            CertificateStatus(_) => HandshakeType::CertificateStatus,
            MessageHash(_) => HandshakeType::MessageHash,
            Unknown((t, _)) => *t,
        }
    }

    fn wire_handshake_type(&self) -> HandshakeType {
        match self.handshake_type() {
            // A `HelloRetryRequest` appears on the wire as a `ServerHello` with a magic `random` value.
            HandshakeType::HelloRetryRequest => HandshakeType::ServerHello,
            other => other,
        }
    }

    fn into_owned(self) -> HandshakePayload<'static> {
        use HandshakePayload::*;

        match self {
            HelloRequest => HelloRequest,
            ClientHello(x) => ClientHello(x),
            ServerHello(x) => ServerHello(x),
            HelloRetryRequest(x) => HelloRetryRequest(x),
            Certificate(x) => Certificate(x.into_owned()),
            CertificateTls13(x) => CertificateTls13(x.into_owned()),
            CompressedCertificate(x) => CompressedCertificate(x.into_owned()),
            ServerKeyExchange(x) => ServerKeyExchange(x),
            CertificateRequest(x) => CertificateRequest(x),
            CertificateRequestTls13(x) => CertificateRequestTls13(x),
            CertificateVerify(x) => CertificateVerify(x),
            ServerHelloDone => ServerHelloDone,
            EndOfEarlyData => EndOfEarlyData,
            ClientKeyExchange(x) => ClientKeyExchange(x.into_owned()),
            NewSessionTicket(x) => NewSessionTicket(x),
            NewSessionTicketTls13(x) => NewSessionTicketTls13(x),
            EncryptedExtensions(x) => EncryptedExtensions(Box::new(x.into_owned())),
            KeyUpdate(x) => KeyUpdate(x),
            Finished(x) => Finished(x.into_owned()),
            CertificateStatus(x) => CertificateStatus(x.into_owned()),
            MessageHash(x) => MessageHash(x.into_owned()),
            Unknown((t, x)) => Unknown((t, x.into_owned())),
        }
    }
}

#[derive(Debug)]
pub(crate) struct AlertMessagePayload {
    pub level: AlertLevel,
    pub description: AlertDescription,
}

impl Codec<'_> for AlertMessagePayload {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.level.encode(bytes);
        self.description.encode(bytes);
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, InvalidMessage> {
        r.all("AlertMessagePayload", |r| {
            Ok(Self {
                level: AlertLevel::read(r)?,
                description: AlertDescription::read(r)?,
            })
        })
    }
}

#[derive(Debug)]
pub(crate) struct ChangeCipherSpecPayload;

impl Codec<'_> for ChangeCipherSpecPayload {
    fn encode(&self, bytes: &mut Vec<u8>) {
        1u8.encode(bytes);
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, InvalidMessage> {
        r.all("ChangeCipherSpecPayload", |r| {
            let typ = u8::read(r)?;
            if typ != 1 {
                return Err(InvalidMessage::InvalidCcs);
            }
            Ok(Self)
        })
    }
}

/// Cryptographic epoch used in [Datagram TLS 1.2][1] and [1.3][2].
///
/// Epoch 0 is used for early, unencrypted handshake messages.
///
/// In DTLS 1.3, epochs 1 and 2 are
/// reserved for client early data and encrypted handshake messages, respectively ([3]). Epochs 3
/// and above are application data and post-handshake messages ([4]).
///
/// In DTLS 1.2, epoch 1 is used for Finished messages and application data. Epochs 2 and above
/// would be used after re-negotiation (or any other "cipher state change", [1]), but rustls does
/// not support re-negotiation/re-handshaking in TLS 1.2.
///
/// [1]: https://datatracker.ietf.org/doc/html/rfc6347#section-4.1
/// [2]: https://datatracker.ietf.org/doc/html/rfc9147#section-4
/// [3]: https://www.rfc-editor.org/info/rfc9147/#section-6.1
/// [4]: https://www.rfc-editor.org/info/rfc9846/#section-4.7
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub(crate) enum Epoch {
    /// Unencrypted messages.
    ///
    /// Epoch 0, used for messages before any encryption keys are negotiated, meaning all handshake
    /// messages except `Finished` for DTLS 1.2 and `HelloRequest`, `ClientHello`, and `ServerHello`
    /// for DTLS 1.3.
    ///
    /// <https://www.rfc-editor.org/info/rfc9147/#section-6.1>
    Unencrypted,
    /// Early data messages.
    ///
    /// Epoch 1, used when encrypting early data. This epoch is skipped if the client does not offer
    /// early data. Only possible with (D)TLS 1.3.
    ///
    /// <https://www.rfc-editor.org/info/rfc9147/#section-6.1>
    EarlyData,
    /// Encrypted handshake messages.
    ///
    /// Epoch 2, used for encrypting handshake messages once a key has been negotiated, but before
    /// the first handshake completes. This is only used in (D)TLS 1.3.
    ///
    /// <https://www.rfc-editor.org/info/rfc9147/#section-6.1>
    EncryptedHandshakeMessages,
    /// Application data and post-handshake messages.
    ///
    /// In DTLS 1.3, epochs 3 and above are for application data and post-handshake messages ([1]).
    /// The epoch increments again whenever either side sends a KeyUpdate request.
    ///
    /// In DTLS 1.2, epoch 1 is used for Finished handshake messages and then application data.
    /// Epochs 2 and above would be used after re-negotiation (or any other "cipher state change"
    /// [2]), but rustls does not support re-negotiation/re-handshaking in TLS 1.2.
    ///
    /// [1]: https://www.rfc-editor.org/info/rfc9147/#section-6.1
    /// [2]: https://datatracker.ietf.org/doc/html/rfc6347#section-4.1
    ApplicationData(u16),
}

impl Epoch {
    /// Create a new `Epoch`.
    pub(crate) fn new(epoch: u16, version: ProtocolVersion) -> Self {
        match (epoch, version) {
            (0, _) => Self::Unencrypted,
            (1, ProtocolVersion::DTLSv1_3) => Self::EarlyData,
            (2, ProtocolVersion::DTLSv1_3) => Self::EncryptedHandshakeMessages,
            (e, _) => Epoch::ApplicationData(e),
        }
    }

    /// Epoch number.
    pub(crate) fn number(&self) -> u16 {
        match self {
            Epoch::Unencrypted => 0,
            Epoch::EarlyData => 1,
            Epoch::EncryptedHandshakeMessages => 2,
            Epoch::ApplicationData(epoch) => *epoch,
        }
    }

    /// Whether this epoch comes before another.
    pub(crate) fn before(&self, other: Epoch) -> bool {
        match (*self, other) {
            (
                Self::Unencrypted,
                Self::EarlyData | Self::EncryptedHandshakeMessages | Self::ApplicationData(_),
            )
            | (Self::EarlyData, Self::EncryptedHandshakeMessages | Self::ApplicationData(_))
            | (Self::EncryptedHandshakeMessages, Self::ApplicationData(_)) => true,
            (Self::ApplicationData(a), Self::ApplicationData(b)) if a < b => true,
            _ => false,
        }
    }

    /// Whether the provided epoch can be an immediate successor to this one.
    pub(crate) fn successor(&self, other: Epoch) -> bool {
        match (*self, other) {
            (
                Self::Unencrypted,
                Self::EarlyData | Self::EncryptedHandshakeMessages | Self::ApplicationData(_),
            )
            | (Self::EarlyData, Self::EncryptedHandshakeMessages | Self::ApplicationData(_))
            | (Self::EncryptedHandshakeMessages, Self::ApplicationData(_)) => true,
            (Self::ApplicationData(this), Self::ApplicationData(other))
                if other > this && other - this == 1 =>
            {
                true
            }
            _ => false,
        }
    }

    /// Compute additional data for record protection.
    ///
    /// For most protocol versions, this is just the sequence number.
    ///
    /// For DTLS 1.2, this is the 16 bit epoch number concatenated with the 48 bit sequence number
    /// ([1]).
    ///
    /// For DTLS 1.3, this is the sequence number, reconstructed from the unified header ([2]).
    ///
    /// [1]: https://www.rfc-editor.org/info/rfc6347/#section-4.1.2.1
    /// [2]: https://www.rfc-editor.org/info/rfc9147/#section-4.2.2
    pub(crate) fn per_record_additional_data(
        &self,
        sequence: u64,
        version: ProtocolVersion,
    ) -> u64 {
        match version {
            ProtocolVersion::DTLSv1_2 => u64::from(self.number()).unbounded_shl(48) + sequence,
            _ => sequence,
        }
    }

    /// Increment this epoch to one suitable for the provided purpose.
    ///
    /// Panics if the requested epoch increment is impossible.
    pub(crate) fn increment(
        self,
        purpose: EncrypterDecrypterPurpose,
        version: ProtocolVersion,
    ) -> Self {
        match (self, purpose, version) {
            // Can go from unencrypted to early data, regardless of version.
            (Self::Unencrypted, EncrypterDecrypterPurpose::EarlyData, _) => Self::EarlyData,
            // Can go from unencrypted or early data to handshake messages, but only for 1.3
            (
                Self::Unencrypted | Self::EarlyData,
                EncrypterDecrypterPurpose::HandshakeMessages,
                ProtocolVersion::TLSv1_3 | ProtocolVersion::DTLSv1_3,
            ) => Self::EncryptedHandshakeMessages,
            // For 1.3, the first encrypted epoch is 3, and you can only go there from encrypted
            // handshake messages or early data
            (
                Self::EncryptedHandshakeMessages | Self::EarlyData,
                EncrypterDecrypterPurpose::ApplicationData,
                ProtocolVersion::TLSv1_3 | ProtocolVersion::DTLSv1_3,
            ) => Self::ApplicationData(3),
            // For 1.2, the first encrypted epoch is 1 and you can only go there from unencrypted
            (
                Self::Unencrypted,
                EncrypterDecrypterPurpose::ApplicationData,
                ProtocolVersion::TLSv1_2 | ProtocolVersion::DTLSv1_2,
            ) => Self::ApplicationData(1),
            // For 1.3, go to the next application data epoch on re-key
            (
                Self::ApplicationData(e),
                EncrypterDecrypterPurpose::ApplicationData,
                ProtocolVersion::TLSv1_3 | ProtocolVersion::DTLSv1_3,
            ) => Self::ApplicationData(e + 1),
            // Special case for this transition to catch misuse under 1.2
            (
                Self::ApplicationData(_),
                EncrypterDecrypterPurpose::ApplicationData,
                ProtocolVersion::TLSv1_2 | ProtocolVersion::DTLSv1_2,
            ) => panic!("rustls does not support rekey in (D)TLS 1.2"),
            (..) => panic!("illegal epoch transition from {self:?} for {purpose:?}"),
        }
    }

    /// Read an `Epoch` value from a wire message.
    pub(crate) fn read(
        r: &mut Reader<'_>,
        version: ProtocolVersion,
    ) -> Result<Self, InvalidMessage> {
        // This can't be a `Codec` implementation because we need to know the protocol version in use
        // in order to interpret the value. Epoch 1 is Epoch::ApplicationData(1) for DTLS 1.2, but
        // it's EarlyData for 1.3.
        Ok(Self::new(u16::read(r)?, version))
    }
}

/// Purpose of an encrypter or decrypter being set in the record layer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum EncrypterDecrypterPurpose {
    /// (En|De)cryption of early data.
    EarlyData,
    /// (En|De)cryption of handshake messages.
    HandshakeMessages,
    /// (En|De)cryption of application data.
    ApplicationData,
}

/// Fragment of a DTLS handshake message used in [Datagram TLS 1.2][1] and [1.3][2].
///
/// [1]: https://datatracker.ietf.org/doc/html/rfc6347#section-4.2.2
/// [2]: https://datatracker.ietf.org/doc/html/rfc9147#section-5.2
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DtlsHandshakeFragment<'a> {
    pub(crate) msg_type: HandshakeType,
    /// Total length of the message this is a fragment of. The value will be the same in all
    /// fragments of a given message.
    pub(crate) length: U24,
    /// Sequence number of the message this is a fragment of. The value will be the same in all
    /// fragments of a given message.
    pub(crate) message_seq: HandshakeSequenceNumber,
    /// The offset into the original message where this fragment begins. Equivalently, the sum of
    /// the lengths of all previous fragments.
    pub(crate) fragment_offset: U24,
    /// The length of this fragment.
    pub(crate) fragment_length: U24,
    /// The fragment. Its length must be equal to `fragment_length`.
    pub(crate) fragment: Payload<'a>,
}

impl<'a> Codec<'a> for DtlsHandshakeFragment<'a> {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.msg_type.encode(bytes);
        self.length.encode(bytes);
        self.message_seq.encode(bytes);
        self.fragment_offset.encode(bytes);
        self.fragment_length.encode(bytes);
        self.fragment.encode(bytes);
    }

    fn read(r: &mut Reader<'a>) -> Result<Self, InvalidMessage> {
        let msg_type = HandshakeType::read(r)?;
        let length = U24::read(r)?;
        let message_seq = HandshakeSequenceNumber::read(r)?;
        let fragment_offset = U24::read(r)?;
        let fragment_len = U24::read(r)?;
        let fragment = Payload::Borrowed(
            r.take(fragment_len.into())
                .ok_or_else(|| InvalidMessage::MessageTooShort)?,
        );

        Ok(Self {
            msg_type,
            length,
            message_seq,
            fragment_offset,
            fragment_length: fragment_len,
            fragment,
        })
    }
}

/// DTLS 1.3 unified record header, specified in [RFC 9157 section 4][1].
///
/// The first byte of the unified header is a bitfield describing the remainder of the
/// header:
///
///  0 1 2 3 4 5 6 7
/// +-+-+-+-+-+-+-+-+
/// |0|0|1|C|S|L|E E|
/// +-+-+-+-+-+-+-+-+
///
///
/// The first three bits are 001 to distinguish from content type fields of records in other
/// protocols.
/// "C" bit indicates whether the connection ID is present in the header. Its length will have
/// previously been negotiated during the handshake.
/// "S" bit indicates size of the sequence number.
/// "L" bit indicates whether length is present.
/// "EE" bits are low two bits of the epoch of the encrypted message.
///
/// [1]: https://datatracker.ietf.org/doc/html/rfc9147#section-4
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct UnifiedHeader {
    /// An absent connection ID is represented by an empty `Vec`.
    // TODO: implement connection IDs. We assume them to be 0 length/absent for now.
    connection_id: Vec<u8>,
    epoch: Epoch,
    sequence: u64,
    length: Option<u16>,
}

impl UnifiedHeader {
    const FIXED_BITS: u8 = 0b0010_0000;
    const FIXED_BITS_MASK: u8 = 0b1110_0000;
    const C_BIT_MASK: u8 = 0b0001_0000;
    const S_BIT_MASK: u8 = 0b0000_1000;
    const L_BIT_MASK: u8 = 0b0000_0100;
    const EE_BITS_MASK: u8 = 0b0000_0011;

    pub(crate) fn is_unified_header(byte: u8) -> bool {
        byte & Self::FIXED_BITS_MASK == Self::FIXED_BITS
    }

    pub(crate) fn new(len: u16, cx: EncodingContext) -> Self {
        // truncate epoch to 2 bits
        let epoch_low_bits = Epoch::new(cx.epoch.number() & 0b11, ProtocolVersion::DTLSv1_3);
        // truncate sequence number to 16 bits
        let sequence = cx.record_seq & 0xffff;
        Self {
            connection_id: Vec::new(),
            epoch: epoch_low_bits,
            sequence,
            length: Some(len),
        }
    }

    pub(crate) fn encode(&self, bytes: &mut [u8]) {
        bytes[0] = Self::FIXED_BITS;

        if self.connection_id.len() > 0 {
            panic!("connection ID should always be empty for now");
            // bitmask |= Self::C_BIT_MASK;
            // header.extend(self.connection_id);
        }

        // Always encode sequence number as 2 bytes for simplicity
        bytes[0] |= Self::S_BIT_MASK;
        bytes[1..3].copy_from_slice(&(self.sequence as u16).to_be_bytes());
        if let Some(length) = self.encoded_len() {
            bytes[0] |= Self::L_BIT_MASK;
            bytes[3..5].copy_from_slice(&length);
        }

        debug_assert!(self.epoch.number() <= Self::EE_BITS_MASK as u16);
        bytes[0] |= self.epoch.number() as u8;
    }

    /// Read a unified header from `r`.
    ///
    /// `current_epoch` is the epoch messages are expected to be in. `highest_seq` is the highest
    /// observed record sequence number observed in that epoch. These are used to reconstruct the
    /// full sequence number based on [RFC 9147 section 4.2.2][1].
    ///
    /// [1]: https://www.rfc-editor.org/info/rfc9147/#section-4.2.2
    fn read(
        r: &mut Reader<'_>,
        current_epoch: Epoch,
        highest_seq: u64,
    ) -> Result<Self, InvalidMessage> {
        let bitfield = u8::read(r)?;

        if bitfield & Self::FIXED_BITS_MASK != Self::FIXED_BITS {
            return Err(InvalidMessage::InvalidDtls13UnifiedHeader);
        }

        if bitfield & Self::C_BIT_MASK > 0 {
            panic!("connection ID should never be set for now");
            // TODO: handle connection ID properly. How do we figure out how long it should be, and
            // how do we smuggle that information into a call to `Codec::read`?
        }

        let long_seq = bitfield & Self::S_BIT_MASK > 0;
        let truncated_sequence_number = if long_seq {
            // bit set: 2 byte seq
            u16::read(r)?
        } else {
            // bit clear: 1 byte seq
            u8::read(r)? as u16
        };

        // Reconstruct the sequence number based on the truncated sequence number in a DTLS 1.3
        // unified header, per [RFC 9147, section 4.2.2][1]:
        //
        // > [I]mplementations SHOULD reconstruct the sequence number by computing the full
        // > sequence number which is numerically closest to one plus the sequence number of
        // > the highest successfully deprotected record in the current epoch.
        //
        // [1]: https://datatracker.ietf.org/doc/html/rfc9147#section-4.2.2
        // First candidate: clear low bits of highest sequence we've seen and OR in the truncated
        // sequence number
        let reconstructed_seq_0: u64 = highest_seq
            & if long_seq {
                0xffff_ffff_ffff_0000
            } else {
                0xffff_ffff_ffff_ff00
            }
            | truncated_sequence_number as u64;
        // Second candidate: flip the first bit to the left of the truncated portion
        let reconstructed_seq_1 = reconstructed_seq_0 ^ if long_seq { 0x1_ffff } else { 0x0100 };
        // Use whichever is closest to latest_seq+1
        let sequence = min_by_key(reconstructed_seq_0, reconstructed_seq_1, |v| {
            v.abs_diff(highest_seq + 1)
        });

        let length = if bitfield & Self::L_BIT_MASK > 0 {
            Some(u16::read(r)?)
        } else {
            None
        };

        // Infer the 16 bit epoch based on the low bits in the header and most recently seen epoch.
        let epoch_low_bits = bitfield & Self::EE_BITS_MASK;

        Ok(Self {
            connection_id: Vec::new(),
            length,
            epoch: Epoch::new(
                current_epoch.number() | (epoch_low_bits as u16),
                ProtocolVersion::DTLSv1_3,
            ),
            sequence,
        })
    }

    pub(crate) fn encoded_len(&self) -> Option<[u8; 2]> {
        self.length.map(|l| l.to_be_bytes())
    }
}

/// Sequence numbers of TLS handshake messages.
///
/// This is distinct from [`HandshakeSequenceNumber`] to avoid confusing a specific sequence number
/// with the sequence of handshake messages.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct HandshakeSequence(HandshakeSequenceNumber);

impl HandshakeSequence {
    /// Return the current number and increment the position in the sequence.
    pub(crate) fn increment(&mut self) -> HandshakeSequenceNumber {
        let old = self.0;
        self.0 = HandshakeSequenceNumber::from(u16::from(old) + 1);
        old
    }
}

/// Sequence number in an individual TLS handshake message.
///
/// This is distinct from [`HandshakeSequence`] to avoid confusing a handshake's position in the
/// sequence with a particular number encoded into a message.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, PartialOrd, Ord)]
pub(crate) struct HandshakeSequenceNumber(u16);

impl HandshakeSequenceNumber {
    pub(crate) fn to_wire_bytes(&self) -> [u8; 2] {
        self.0.to_be_bytes()
    }
}

impl Codec<'_> for HandshakeSequenceNumber {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.0.encode(bytes);
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, InvalidMessage> {
        Ok(Self(u16::read(r)?))
    }
}

impl From<u16> for HandshakeSequenceNumber {
    fn from(value: u16) -> Self {
        Self(value)
    }
}

impl From<HandshakeSequenceNumber> for u16 {
    fn from(value: HandshakeSequenceNumber) -> Self {
        value.0
    }
}

/// Length of the header on a TLS record.
///
/// Content type (1 byte), version (2 bytes) and size (2 bytes).
pub(crate) const HEADER_SIZE: usize = 1 + 2 + 2;

/// Length of the header on a full DTLS record.
///
/// This header is used for all DTLS 1.2 records and unencrypted DTLS 1.3 records that don't use a
/// unified header.
///
/// TLS header size plus epoch (2 bytes) and sequence number (6 bytes).
pub(crate) const DTLS_12_HEADER_SIZE: usize = HEADER_SIZE + 2 + 6;

/// Length of the unified header on an encrypted DTLS 1.3 record.
pub(crate) const DTLS_13_UNIFIED_HEADER_SIZE: usize = 1 + // bitmask
            0 + // Assume no connection IDs for now
            2 + // Always 2 bytes for seq. TODO(DTLS): truncate to 1 byte if seq is small enough
            2; // 2 bytes for length. TODO(DTLS): can we ever omit length?

/// Length of the header on a handshake message.
///
/// Does not include the record layer header. Handshake type (1 byte) and length (3 bytes).
pub(crate) const HANDSHAKE_HEADER_SIZE: usize = 1 + 3;

/// Length of extra fields in the handshake header for DTLS.
///
/// Message sequence (2 bytes), fragment offset (3 bytes) and fragment length (3 bytes).
pub(crate) const DTLS_HANDSHAKE_HEADER_EXTRA: usize = 2 + 3 + 3;

/// Length of the header on a DTLS handshake message.
///
/// Does not include the record layer header.
pub(crate) const DTLS_HANDSHAKE_HEADER_SIZE: usize =
    HANDSHAKE_HEADER_SIZE + DTLS_HANDSHAKE_HEADER_EXTRA;

/// Maximum message payload size.
/// That's 2^14 payload bytes and a 2KB allowance for ciphertext overheads.
pub(crate) const MAX_PAYLOAD: u16 = 16_384 + 2048;

#[cfg(test)]
mod tests {
    use alloc::vec;
    use std::io::Read;
    use std::path::{Path, PathBuf};
    use std::{format, fs, println};

    use super::*;
    use crate::crypto::cipher::EncodingContext;
    use crate::error::AlertDescription;

    #[test]
    fn test_read_fuzz_corpus() {
        fn corpus_dir() -> PathBuf {
            let from_subcrate = Path::new("../fuzz/corpus/message");
            let from_root = Path::new("fuzz/corpus/message");

            if from_root.is_dir() {
                from_root.to_path_buf()
            } else {
                from_subcrate.to_path_buf()
            }
        }

        for file in fs::read_dir(corpus_dir()).unwrap() {
            let mut f = fs::File::open(file.unwrap().path()).unwrap();
            let mut bytes = Vec::new();
            f.read_to_end(&mut bytes).unwrap();

            let mut rd = Reader::new(&bytes);
            let msg = EncodedMessage::<Payload<'_>>::read(&mut rd).unwrap();
            println!("{msg:?}");

            let Ok(msg) = Message::try_from(&msg) else {
                continue;
            };

            let enc = EncodedMessage::<Payload<'_>>::from(msg)
                .borrow_outbound()
                .to_unencrypted_bytes(EncodingContext::new());
            // Check that round-tripped message matches the input, ignoring the protocol version
            // bytes, which will have been forced to a compatible TLS version.
            assert_eq!(bytes[0], enc[0]);
            assert_eq!(&bytes[3..], &enc[3..]);
            assert_eq!(rd.left(), 0);
        }
    }

    #[test]
    fn can_read_safari_client_hello_with_ip_address_in_sni_extension() {
        let bytes = b"\
        \x16\x03\x01\x00\xeb\x01\x00\x00\xe7\x03\x03\xb6\x1f\xe4\x3a\x55\
        \x90\x3e\xc0\x28\x9c\x12\xe0\x5c\x84\xea\x90\x1b\xfb\x11\xfc\xbd\
        \x25\x55\xda\x9f\x51\x93\x1b\x8d\x92\x66\xfd\x00\x00\x2e\xc0\x2c\
        \xc0\x2b\xc0\x24\xc0\x23\xc0\x0a\xc0\x09\xcc\xa9\xc0\x30\xc0\x2f\
        \xc0\x28\xc0\x27\xc0\x14\xc0\x13\xcc\xa8\x00\x9d\x00\x9c\x00\x3d\
        \x00\x3c\x00\x35\x00\x2f\xc0\x08\xc0\x12\x00\x0a\x01\x00\x00\x90\
        \xff\x01\x00\x01\x00\x00\x00\x00\x0e\x00\x0c\x00\x00\x09\x31\x32\
        \x37\x2e\x30\x2e\x30\x2e\x31\x00\x17\x00\x00\x00\x0d\x00\x18\x00\
        \x16\x04\x03\x08\x04\x04\x01\x05\x03\x02\x03\x08\x05\x08\x05\x05\
        \x01\x08\x06\x06\x01\x02\x01\x00\x05\x00\x05\x01\x00\x00\x00\x00\
        \x33\x74\x00\x00\x00\x12\x00\x00\x00\x10\x00\x30\x00\x2e\x02\x68\
        \x32\x05\x68\x32\x2d\x31\x36\x05\x68\x32\x2d\x31\x35\x05\x68\x32\
        \x2d\x31\x34\x08\x73\x70\x64\x79\x2f\x33\x2e\x31\x06\x73\x70\x64\
        \x79\x2f\x33\x08\x68\x74\x74\x70\x2f\x31\x2e\x31\x00\x0b\x00\x02\
        \x01\x00\x00\x0a\x00\x0a\x00\x08\x00\x1d\x00\x17\x00\x18\x00\x19";
        let mut rd = Reader::new(bytes);
        let m = EncodedMessage::<Payload<'_>>::read(&mut rd).unwrap();
        println!("m = {m:?}");
        Message::try_from(&m).unwrap();
    }

    #[test]
    fn alert_is_not_handshake() {
        let m = Message::build_alert(
            AlertLevel::Fatal,
            AlertDescription::DecodeError,
            ProtocolVersion::TLSv1_2,
        );
        assert_ne!(m.handshake_type(), Some(HandshakeType::ClientHello));
    }

    #[test]
    fn construct_all_types() {
        let samples = [
            &b"\x14\x03\x04\x00\x01\x01"[..],
            &b"\x15\x03\x04\x00\x02\x01\x16"[..],
            &b"\x16\x03\x04\x00\x05\x18\x00\x00\x01\x00"[..],
            &b"\x17\x03\x04\x00\x04\x11\x22\x33\x44"[..],
            &b"\x18\x03\x04\x00\x04\x11\x22\x33\x44"[..],
        ];
        for &bytes in samples.iter() {
            let m = EncodedMessage::<Payload<'_>>::read(&mut Reader::new(bytes)).unwrap();
            println!("m = {m:?}");
            let m = Message::try_from(&m);
            println!("m' = {m:?}");
        }
    }

    #[test]
    fn debug_payload() {
        assert_eq!("01020304", format!("{:?}", Payload::new(vec![1, 2, 3, 4])));
        assert_eq!(
            "01020304",
            format!("{:?}", SizedPayload::<u8, NonEmpty>::from(vec![1, 2, 3, 4]))
        );
        assert_eq!(
            "01020304",
            format!(
                "{:?}",
                SizedPayload::<u16, MaybeEmpty>::from(vec![1, 2, 3, 4])
            )
        );
        assert_eq!(
            "01020304",
            format!(
                "{:?}",
                SizedPayload::<'static, U24, NonEmpty>::from(Payload::new(vec![1, 2, 3, 4]))
            )
        );
    }

    #[test]
    fn into_wire_format() {
        // Message::into_wire_bytes() include both message-level and handshake-level headers
        assert_eq!(
            Message::build_key_update_request(ProtocolVersion::TLSv1_3, 0.into()).into_wire_bytes(),
            &[0x16, 0x3, 0x3, 0x0, 0x5, 0x18, 0x0, 0x0, 0x1, 0x1]
        );
    }

    #[test]
    fn smoketest() {
        let bytes = include_bytes!("../testdata/handshake-test.1.bin");
        let mut r = Reader::new(bytes);

        while r.any_left() {
            let m = EncodedMessage::<Payload<'_>>::read(&mut r).unwrap();

            let out = m
                .borrow_outbound()
                .to_unencrypted_bytes(EncodingContext::new());
            assert!(!out.is_empty());

            Message::try_from(&m).unwrap();
        }
    }
}
