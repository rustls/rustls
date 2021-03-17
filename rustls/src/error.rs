use crate::msgs::enums::{AlertDescription, ContentType, HandshakeType};
use crate::rand;
use sct;
use std::error::Error;
use std::fmt;
use webpki;

/// The reason WebPKI operation was performed, used in [`TLSError`].
#[derive(Debug, PartialEq, Clone)]
#[non_exhaustive]
pub enum WebPKIOp {
    /// Validate server certificate.
    ValidateServerCert,
    /// Validate client certificate.
    ValidateClientCert,
    /// Validate certificate for DNS name
    ValidateForDNSName,
    /// Parse end entity certificate.
    ParseEndEntity,
    /// Verify message signature using the certificate.
    VerifySignature,
}

impl fmt::Display for WebPKIOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WebPKIOp::ValidateServerCert => write!(f, "validate server certificate"),
            WebPKIOp::ValidateClientCert => write!(f, "validate client certificate"),
            WebPKIOp::ValidateForDNSName => write!(f, "validate certificate for DNS name"),
            WebPKIOp::ParseEndEntity => write!(f, "parse end entity certificate"),
            WebPKIOp::VerifySignature => write!(f, "verify signature"),
        }
    }
}

/// rustls reports protocol errors using this type.
#[derive(Debug, PartialEq, Clone)]
pub enum TlsError {
    /// We received a TLS message that isn't valid right now.
    /// `expect_types` lists the message types we can expect right now.
    /// `got_type` is the type we found.  This error is typically
    /// caused by a buggy TLS stack (the peer or this one), a broken
    /// network, or an attack.
    InappropriateMessage {
        /// Which types we expected
        expect_types: Vec<ContentType>,
        /// What type we received
        got_type: ContentType,
    },

    /// We received a TLS handshake message that isn't valid right now.
    /// `expect_types` lists the handshake message types we can expect
    /// right now.  `got_type` is the type we found.
    InappropriateHandshakeMessage {
        /// Which handshake type we expected
        expect_types: Vec<HandshakeType>,
        /// What handshake type we received
        got_type: HandshakeType,
    },

    /// The peer sent us a syntactically incorrect TLS message.
    CorruptMessage,

    /// The peer sent us a TLS message with invalid contents.
    CorruptMessagePayload(ContentType),

    /// The peer didn't give us any certificates.
    NoCertificatesPresented,

    /// We couldn't decrypt a message.  This is invariably fatal.
    DecryptError,

    /// The peer doesn't support a protocol version/feature we require.
    /// The parameter gives a hint as to what version/feature it is.
    PeerIncompatibleError(String),

    /// The peer deviated from the standard TLS protocol.
    /// The parameter gives a hint where.
    PeerMisbehavedError(String),

    /// We received a fatal alert.  This means the peer is unhappy.
    AlertReceived(AlertDescription),

    /// The presented certificate chain is invalid.
    WebPKIError(webpki::Error, WebPKIOp),

    /// The presented SCT(s) were invalid.
    InvalidSCT(sct::Error),

    /// A catch-all error for unlikely errors.
    General(String),

    /// We failed to figure out what time it currently is.
    FailedToGetCurrentTime,

    /// We failed to acquire random bytes from the system.
    FailedToGetRandomBytes,

    /// This function doesn't work until the TLS handshake
    /// is complete.
    HandshakeNotComplete,

    /// The peer sent an oversized record/fragment.
    PeerSentOversizedRecord,

    /// An incoming connection did not support any known application protocol.
    NoApplicationProtocol,
}

fn join<T: fmt::Debug>(items: &[T]) -> String {
    items
        .iter()
        .map(|x| format!("{:?}", x))
        .collect::<Vec<String>>()
        .join(" or ")
}

impl fmt::Display for TlsError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            TlsError::InappropriateMessage {
                ref expect_types,
                ref got_type,
            } => write!(
                f,
                "received unexpected message: got {:?} when expecting {}",
                got_type,
                join::<ContentType>(expect_types)
            ),
            TlsError::InappropriateHandshakeMessage {
                ref expect_types,
                ref got_type,
            } => write!(
                f,
                "received unexpected handshake message: got {:?} when expecting {}",
                got_type,
                join::<HandshakeType>(expect_types)
            ),
            TlsError::CorruptMessagePayload(ref typ) => {
                write!(f, "received corrupt message of type {:?}", typ)
            }
            TlsError::PeerIncompatibleError(ref why) => write!(f, "peer is incompatible: {}", why),
            TlsError::PeerMisbehavedError(ref why) => write!(f, "peer misbehaved: {}", why),
            TlsError::AlertReceived(ref alert) => write!(f, "received fatal alert: {:?}", alert),
            TlsError::WebPKIError(ref err, ref reason) => {
                write!(f, "certificate error in operation: {}: {:?}", reason, err)
            }
            TlsError::CorruptMessage => write!(f, "received corrupt message"),
            TlsError::NoCertificatesPresented => write!(f, "peer sent no certificates"),
            TlsError::DecryptError => write!(f, "cannot decrypt peer's message"),
            TlsError::PeerSentOversizedRecord => write!(f, "peer sent excess record size"),
            TlsError::HandshakeNotComplete => write!(f, "handshake not complete"),
            TlsError::NoApplicationProtocol => write!(f, "peer doesn't support any known protocol"),
            TlsError::InvalidSCT(ref err) => write!(f, "invalid certificate timestamp: {:?}", err),
            TlsError::FailedToGetCurrentTime => write!(f, "failed to get current time"),
            TlsError::FailedToGetRandomBytes => write!(f, "failed to get random bytes"),
            TlsError::General(ref err) => write!(f, "unexpected error: {}", err), // (please file a bug)
        }
    }
}

impl Error for TlsError {}

impl From<rand::GetRandomFailed> for TlsError {
    fn from(_: rand::GetRandomFailed) -> Self {
        Self::FailedToGetRandomBytes
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn smoke() {
        use super::TlsError;
        use super::WebPKIOp;
        use crate::msgs::enums::{AlertDescription, ContentType, HandshakeType};
        use sct;
        use webpki;

        let all = vec![
            TlsError::InappropriateMessage {
                expect_types: vec![ContentType::Alert],
                got_type: ContentType::Handshake,
            },
            TlsError::InappropriateHandshakeMessage {
                expect_types: vec![HandshakeType::ClientHello, HandshakeType::Finished],
                got_type: HandshakeType::ServerHello,
            },
            TlsError::CorruptMessage,
            TlsError::CorruptMessagePayload(ContentType::Alert),
            TlsError::NoCertificatesPresented,
            TlsError::DecryptError,
            TlsError::PeerIncompatibleError("no tls1.2".to_string()),
            TlsError::PeerMisbehavedError("inconsistent something".to_string()),
            TlsError::AlertReceived(AlertDescription::ExportRestriction),
            TlsError::WebPKIError(
                webpki::Error::ExtensionValueInvalid,
                WebPKIOp::ParseEndEntity,
            ),
            TlsError::InvalidSCT(sct::Error::MalformedSCT),
            TlsError::General("undocumented error".to_string()),
            TlsError::FailedToGetCurrentTime,
            TlsError::FailedToGetRandomBytes,
            TlsError::HandshakeNotComplete,
            TlsError::PeerSentOversizedRecord,
            TlsError::NoApplicationProtocol,
        ];

        for err in all {
            println!("{:?}:", err);
            println!("  fmt '{}'", err);
        }
    }
}
