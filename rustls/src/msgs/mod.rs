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

use alloc::vec::Vec;

use crate::crypto::cipher::{EncodedMessage, Payload};
use crate::enums::{ContentType, ProtocolVersion};
use crate::error::{AlertDescription, InvalidMessage};

#[macro_use]
mod macros;

mod base;
pub(crate) use base::{MaybeEmpty, NonEmpty, SizedPayload, hex};

mod client_hello;
pub(crate) use client_hello::{
    CertificateStatusRequest, ClientExtensions, ClientHelloPayload, ClientSessionTicket,
    EncryptedClientHello, EncryptedClientHelloOuter, PresharedKeyBinder, PresharedKeyIdentity,
    PresharedKeyOffer, PskKeyExchangeModes, ServerNamePayload,
};

mod codec;
pub(crate) use codec::{CERTIFICATE_MAX_SIZE_LIMIT, ListLength, TlsListElement, put_u16, put_u64};
pub use codec::{Codec, Reader};

mod deframer;
pub use deframer::fuzz_deframer;
pub(crate) use deframer::{
    BufferProgress, DeframerIter, DeframerSliceBuffer, DeframerVecBuffer, Delocator,
    HandshakeAlignedProof, HandshakeDeframer, Locator,
};

mod enums;
#[cfg(test)]
pub(crate) use enums::ECCurveType;
#[cfg(test)]
pub(crate) use enums::tests::{test_enum8, test_enum8_display, test_enum16};
pub use enums::{AlertLevel, ExtensionType};
pub(crate) use enums::{ClientCertificateType, Compression, KeyUpdateRequest};

mod fragmenter;
pub(crate) use fragmenter::MAX_FRAGMENT_LEN;
pub use fragmenter::MessageFragmenter;

#[macro_use]
mod handshake;
pub(crate) use handshake::{
    ALL_KEY_EXCHANGE_ALGORITHMS, CertificateChain, CertificatePayloadTls13,
    CertificateRequestExtensions, CertificateRequestPayload, CertificateRequestPayloadTls13,
    CertificateStatus, ClientDhParams, ClientEcdhParams, ClientExtensionsInput,
    ClientKeyExchangeParams, CompressedCertificatePayload, Encoding, HandshakeMessagePayload,
    HandshakePayload, HelloRetryRequest, HelloRetryRequestExtensions, KeyShareEntry, KxDecode,
    NewSessionTicketPayload, NewSessionTicketPayloadTls13, Random, ServerExtensionsInput,
    ServerKeyExchange, ServerKeyExchangeParams, ServerKeyExchangePayload, SessionId,
    SingleProtocolName, SupportedEcPointFormats, SupportedProtocolVersions, TransportParameters,
};
#[cfg(test)]
pub(crate) use handshake::{EcParameters, ServerEcdhParams};

mod message;
#[cfg(feature = "std")]
pub(crate) use message::MAX_WIRE_SIZE;
pub use message::Message;
pub(crate) use message::{HEADER_SIZE, read_opaque_message_header};

mod persist;
pub use persist::ServerSessionValue;
pub(crate) use persist::{
    ClientSessionCommon, CommonServerSessionValue, Retrieved, Tls12ServerSessionValue,
    Tls13ServerSessionValue,
};

mod server_hello;
pub(crate) use server_hello::{
    EchConfigContents, EchConfigPayload, HpkeKeyConfig, ServerExtensions, ServerHelloPayload,
};

#[cfg(test)]
mod handshake_test;

#[cfg(test)]
mod message_test;

#[non_exhaustive]
#[derive(Debug)]
pub enum MessagePayload<'a> {
    Alert(AlertMessagePayload),
    // one handshake message, parsed
    Handshake {
        parsed: HandshakeMessagePayload<'a>,
        encoded: Payload<'a>,
    },
    // (potentially) multiple handshake messages, unparsed
    HandshakeFlight(Payload<'a>),
    ChangeCipherSpec(ChangeCipherSpecPayload),
    ApplicationData(Payload<'a>),
}

impl<'a> MessagePayload<'a> {
    pub(crate) fn encode(&self, bytes: &mut Vec<u8>) {
        match self {
            Self::Alert(x) => x.encode(bytes),
            Self::Handshake { encoded, .. } => bytes.extend(encoded.bytes()),
            Self::HandshakeFlight(x) => bytes.extend(x.bytes()),
            Self::ChangeCipherSpec(x) => x.encode(bytes),
            Self::ApplicationData(x) => x.encode(bytes),
        }
    }

    pub(crate) fn handshake(parsed: HandshakeMessagePayload<'a>) -> Self {
        Self::Handshake {
            encoded: Payload::new(parsed.get_encoding()),
            parsed,
        }
    }

    pub(crate) fn new(
        typ: ContentType,
        vers: ProtocolVersion,
        payload: &'a [u8],
    ) -> Result<Self, InvalidMessage> {
        let mut r = Reader::init(payload);
        match typ {
            ContentType::ApplicationData => Ok(Self::ApplicationData(Payload::Borrowed(payload))),
            ContentType::Alert => AlertMessagePayload::read(&mut r).map(MessagePayload::Alert),
            ContentType::Handshake => {
                HandshakeMessagePayload::read_version(&mut r, vers).map(|parsed| Self::Handshake {
                    parsed,
                    encoded: Payload::Borrowed(payload),
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
            Self::Handshake { .. } | Self::HandshakeFlight(_) => ContentType::Handshake,
            Self::ChangeCipherSpec(_) => ContentType::ChangeCipherSpec,
            Self::ApplicationData(_) => ContentType::ApplicationData,
        }
    }

    #[cfg(feature = "std")]
    pub(crate) fn into_owned(self) -> MessagePayload<'static> {
        use MessagePayload::*;
        match self {
            Alert(x) => Alert(x),
            Handshake { parsed, encoded } => Handshake {
                parsed: parsed.into_owned(),
                encoded: encoded.into_owned(),
            },
            HandshakeFlight(x) => HandshakeFlight(x.into_owned()),
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
pub struct AlertMessagePayload {
    pub level: AlertLevel,
    pub description: AlertDescription,
}

impl Codec<'_> for AlertMessagePayload {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.level.encode(bytes);
        self.description.encode(bytes);
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, InvalidMessage> {
        let level = AlertLevel::read(r)?;
        let description = AlertDescription::read(r)?;
        r.expect_empty("AlertMessagePayload")
            .map(|_| Self { level, description })
    }
}

#[derive(Debug)]
pub struct ChangeCipherSpecPayload;

impl Codec<'_> for ChangeCipherSpecPayload {
    fn encode(&self, bytes: &mut Vec<u8>) {
        1u8.encode(bytes);
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, InvalidMessage> {
        let typ = u8::read(r)?;
        if typ != 1 {
            return Err(InvalidMessage::InvalidCcs);
        }

        r.expect_empty("ChangeCipherSpecPayload")
            .map(|_| Self {})
    }
}

#[cfg(test)]
mod tests {
    use super::codec::Reader;
    use super::message::Message;
    use crate::crypto::cipher::{EncodedMessage, OutboundOpaque, Payload};

    #[test]
    fn smoketest() {
        let bytes = include_bytes!("../testdata/handshake-test.1.bin");
        let mut r = Reader::init(bytes);

        while r.any_left() {
            let m = EncodedMessage::<Payload<'_>>::read(&mut r).unwrap();

            let out = EncodedMessage {
                typ: m.typ,
                version: m.version,
                payload: OutboundOpaque::from(m.payload.bytes()),
            }
            .encode();
            assert!(!out.is_empty());

            Message::try_from(&m).unwrap();
        }
    }
}
