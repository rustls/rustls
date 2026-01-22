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
    ClientKeyExchangeParams, CompressedCertificatePayload, EchConfigContents, EchConfigPayload,
    Encoding, HandshakeMessagePayload, HandshakePayload, HelloRetryRequest,
    HelloRetryRequestExtensions, HpkeKeyConfig, KeyShareEntry, KxDecode, NewSessionTicketPayload,
    NewSessionTicketPayloadTls13, Random, ServerExtensions, ServerExtensionsInput,
    ServerHelloPayload, ServerKeyExchange, ServerKeyExchangeParams, ServerKeyExchangePayload,
    SessionId, SingleProtocolName, SupportedEcPointFormats, SupportedProtocolVersions,
    TransportParameters,
};
#[cfg(test)]
pub(crate) use handshake::{EcParameters, ServerEcdhParams};

mod message;
#[cfg(feature = "std")]
pub(crate) use message::MAX_WIRE_SIZE;
pub(crate) use message::{HEADER_SIZE, read_opaque_message_header};
pub use message::{Message, MessagePayload};

pub(crate) mod persist;

#[cfg(test)]
mod handshake_test;

#[cfg(test)]
mod message_test;

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
