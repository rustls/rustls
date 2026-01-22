#![expect(missing_docs)]

use alloc::borrow::Cow;
use alloc::vec::Vec;

use crate::crypto::cipher::Payload;
use crate::error::InvalidMessage;
use crate::msgs::{Codec, ListLength, NonEmpty, Reader, SizedPayload, TlsListElement};

#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApplicationProtocol<'a> {
    AcmeTls1,
    DoT,
    DoQ,
    Ftp,
    Http09,
    Http10,
    Http11,
    Http2,
    Http3,
    Imap,
    Mqtt,
    Pop3,
    Postgresql,
    WebRtc,
    Other(Cow<'a, [u8]>),
}

impl<'a> ApplicationProtocol<'a> {
    fn new(data: Cow<'a, [u8]>) -> Self {
        match data.as_ref() {
            b"acme-tls/1" => Self::AcmeTls1,
            b"dot" => Self::DoT,
            b"doq" => Self::DoQ,
            b"ftp" => Self::Ftp,
            b"http/0.9" => Self::Http09,
            b"http/1.0" => Self::Http10,
            b"http/1.1" => Self::Http11,
            b"h2" => Self::Http2,
            b"h3" => Self::Http3,
            b"imap" => Self::Imap,
            b"mqtt" => Self::Mqtt,
            b"pop3" => Self::Pop3,
            b"postgresql" => Self::Postgresql,
            b"webrtc" => Self::WebRtc,
            _r => Self::Other(data),
        }
    }

    pub fn to_owned(&self) -> ApplicationProtocol<'static> {
        match self {
            Self::AcmeTls1 => ApplicationProtocol::AcmeTls1,
            Self::DoT => ApplicationProtocol::DoT,
            Self::DoQ => ApplicationProtocol::DoQ,
            Self::Ftp => ApplicationProtocol::Ftp,
            Self::Http09 => ApplicationProtocol::Http09,
            Self::Http10 => ApplicationProtocol::Http10,
            Self::Http11 => ApplicationProtocol::Http11,
            Self::Http2 => ApplicationProtocol::Http2,
            Self::Http3 => ApplicationProtocol::Http3,
            Self::Imap => ApplicationProtocol::Imap,
            Self::Mqtt => ApplicationProtocol::Mqtt,
            Self::Pop3 => ApplicationProtocol::Pop3,
            Self::Postgresql => ApplicationProtocol::Postgresql,
            Self::WebRtc => ApplicationProtocol::WebRtc,
            Self::Other(data) => ApplicationProtocol::Other(Cow::Owned(data.to_vec())),
        }
    }
}

impl<'a> Codec<'a> for ApplicationProtocol<'a> {
    fn encode(&self, bytes: &mut Vec<u8>) {
        SizedPayload::<u8, NonEmpty>::from(Payload::Borrowed(self.as_ref())).encode(bytes);
    }

    fn read(r: &mut Reader<'a>) -> Result<Self, InvalidMessage> {
        match SizedPayload::<u8, NonEmpty>::read(r)?.inner {
            Payload::Borrowed(data) => Ok(Self::new(Cow::Borrowed(data))),
            Payload::Owned(data) => Ok(Self::new(Cow::Owned(data))),
        }
    }
}

/// RFC7301: `ProtocolName protocol_name_list<2..2^16-1>`
impl TlsListElement for ApplicationProtocol<'_> {
    const SIZE_LEN: ListLength = ListLength::NonZeroU16 {
        empty_error: InvalidMessage::IllegalEmptyList("ProtocolNames"),
    };
}

impl From<Vec<u8>> for ApplicationProtocol<'static> {
    fn from(data: Vec<u8>) -> Self {
        Self::new(Cow::Owned(data))
    }
}

impl<'a, const N: usize> From<&'a [u8; N]> for ApplicationProtocol<'a> {
    fn from(data: &'a [u8; N]) -> Self {
        ApplicationProtocol::from(&data[..])
    }
}

impl<'a> From<&'a [u8]> for ApplicationProtocol<'a> {
    fn from(data: &'a [u8]) -> Self {
        Self::new(Cow::Borrowed(data))
    }
}

impl AsRef<[u8]> for ApplicationProtocol<'_> {
    fn as_ref(&self) -> &[u8] {
        match self {
            Self::AcmeTls1 => b"acme-tls/1",
            Self::DoT => b"dot",
            Self::DoQ => b"doq",
            Self::Ftp => b"ftp",
            Self::Http09 => b"http/0.9",
            Self::Http10 => b"http/1.0",
            Self::Http11 => b"http/1.1",
            Self::Http2 => b"h2",
            Self::Http3 => b"h3",
            Self::Imap => b"imap",
            Self::Mqtt => b"mqtt",
            Self::Pop3 => b"pop3",
            Self::Postgresql => b"postgresql",
            Self::WebRtc => b"webrtc",
            Self::Other(data) => data.as_ref(),
        }
    }
}

enum_builder! {
    /// The `HandshakeType` TLS protocol enum.  Values in this enum are taken
    /// from the various RFCs covering TLS, and are listed by IANA.
    /// The `Unknown` item is used when processing unrecognized ordinals.
    #[repr(u8)]
    pub enum HandshakeType {
        HelloRequest => 0x00,
        ClientHello => 0x01,
        ServerHello => 0x02,
        HelloVerifyRequest => 0x03,
        NewSessionTicket => 0x04,
        EndOfEarlyData => 0x05,
        HelloRetryRequest => 0x06,
        EncryptedExtensions => 0x08,
        Certificate => 0x0b,
        ServerKeyExchange => 0x0c,
        CertificateRequest => 0x0d,
        ServerHelloDone => 0x0e,
        CertificateVerify => 0x0f,
        ClientKeyExchange => 0x10,
        Finished => 0x14,
        CertificateURL => 0x15,
        CertificateStatus => 0x16,
        KeyUpdate => 0x18,
        CompressedCertificate => 0x19,
        MessageHash => 0xfe,
    }
}

enum_builder! {
    /// The `ContentType` TLS protocol enum.  Values in this enum are taken
    /// from the various RFCs covering TLS, and are listed by IANA.
    /// The `Unknown` item is used when processing unrecognized ordinals.
    #[repr(u8)]
    pub enum ContentType {
        ChangeCipherSpec => 0x14,
        Alert => 0x15,
        Handshake => 0x16,
        ApplicationData => 0x17,
        Heartbeat => 0x18,
    }
}

enum_builder! {
    /// The `ProtocolVersion` TLS protocol enum.  Values in this enum are taken
    /// from the various RFCs covering TLS, and are listed by IANA.
    /// The `Unknown` item is used when processing unrecognized ordinals.
    #[repr(u16)]
    pub enum ProtocolVersion {
        SSLv2 => 0x0002,
        SSLv3 => 0x0300,
        TLSv1_0 => 0x0301,
        TLSv1_1 => 0x0302,
        TLSv1_2 => 0x0303,
        TLSv1_3 => 0x0304,
        DTLSv1_0 => 0xFEFF,
        DTLSv1_2 => 0xFEFD,
        DTLSv1_3 => 0xFEFC,
    }
}

enum_builder! {
    /// The "TLS Certificate Compression Algorithm IDs" TLS protocol enum.
    /// Values in this enum are taken from [RFC8879].
    ///
    /// [RFC8879]: https://www.rfc-editor.org/rfc/rfc8879.html#section-7.3
    #[repr(u16)]
    pub enum CertificateCompressionAlgorithm {
        Zlib => 1,
        Brotli => 2,
        Zstd => 3,
    }
}

enum_builder! {
    /// The `CertificateType` enum sent in the cert_type extensions.
    /// Values in this enum are taken from the various RFCs covering TLS, and are listed by IANA.
    ///
    /// [RFC 6091 Section 5]: <https://datatracker.ietf.org/doc/html/rfc6091#section-5>
    /// [RFC 7250 Section 7]: <https://datatracker.ietf.org/doc/html/rfc7250#section-7>
    #[repr(u8)]
    #[derive(Default)]
    pub enum CertificateType {
        #[default]
        X509 => 0x00,
        RawPublicKey => 0x02,
    }
}

enum_builder! {
    /// The type of Encrypted Client Hello (`EchClientHelloType`).
    ///
    /// Specified in [draft-ietf-tls-esni Section 5].
    ///
    /// [draft-ietf-tls-esni Section 5]: <https://www.ietf.org/archive/id/draft-ietf-tls-esni-18.html#section-5>
    #[repr(u8)]
    pub enum EchClientHelloType {
        ClientHelloOuter => 0,
        ClientHelloInner => 1
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::msgs::enums::tests::{test_enum8, test_enum16};

    #[test]
    fn test_enums() {
        test_enum8::<ContentType>(ContentType::ChangeCipherSpec, ContentType::Heartbeat);
        test_enum8::<HandshakeType>(HandshakeType::HelloRequest, HandshakeType::MessageHash);
        test_enum16::<CertificateCompressionAlgorithm>(
            CertificateCompressionAlgorithm::Zlib,
            CertificateCompressionAlgorithm::Zstd,
        );
        test_enum8::<CertificateType>(CertificateType::X509, CertificateType::RawPublicKey);
    }
}
