//! Error types used throughout rustls.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;
use std::time::SystemTimeError;

use pki_types::{AlgorithmIdentifier, EchConfigListBytes, ServerName, UnixTime};
#[cfg(feature = "webpki")]
use webpki::ExtendedKeyUsage;

use crate::crypto::kx::KeyExchangeAlgorithm;
use crate::crypto::{CipherSuite, GetRandomFailed, InconsistentKeys};
use crate::enums::{ContentType, HandshakeType};
use crate::msgs::{Codec, EchConfigPayload};

#[cfg(test)]
mod tests;

/// rustls reports protocol errors using this type.
#[non_exhaustive]
#[derive(Debug, PartialEq, Clone)]
pub enum Error {
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

    /// An error occurred while handling Encrypted Client Hello (ECH).
    InvalidEncryptedClientHello(EncryptedClientHelloError),

    /// The peer sent us a TLS message with invalid contents.
    InvalidMessage(InvalidMessage),

    /// The certificate verifier doesn't support the given type of name.
    UnsupportedNameType,

    /// We couldn't decrypt a message.  This is invariably fatal.
    DecryptError,

    /// We couldn't encrypt a message because it was larger than the allowed message size.
    /// This should never happen if the application is using valid record sizes.
    EncryptError,

    /// The peer doesn't support a protocol version/feature we require.
    /// The parameter gives a hint as to what version/feature it is.
    PeerIncompatible(PeerIncompatible),

    /// The peer deviated from the standard TLS protocol.
    /// The parameter gives a hint where.
    PeerMisbehaved(PeerMisbehaved),

    /// We received a fatal alert.  This means the peer is unhappy.
    AlertReceived(AlertDescription),

    /// We saw an invalid certificate.
    ///
    /// The contained error is from the certificate validation trait
    /// implementation.
    InvalidCertificate(CertificateError),

    /// A provided certificate revocation list (CRL) was invalid.
    InvalidCertRevocationList(CertRevocationListError),

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

    /// The server certificate resolver didn't find an appropriate certificate.
    NoSuitableCertificate,

    /// The `max_fragment_size` value supplied in configuration was too small,
    /// or too large.
    BadMaxFragmentSize,

    /// Specific failure cases from [`Credentials::new()`] or a
    /// [`crate::crypto::SigningKey`] that cannot produce a corresponding public key.
    ///
    /// If encountered while building a [`Credentials`], consider if
    /// [`Credentials::new_unchecked()`] might be appropriate for your use case.
    ///
    /// [`Credentials::new()`]: crate::crypto::Credentials::new()
    /// [`Credentials`]: crate::crypto::Credentials
    /// [`Credentials::new_unchecked()`]: crate::crypto::Credentials::new_unchecked()
    InconsistentKeys(InconsistentKeys),

    /// The server rejected encrypted client hello (ECH) negotiation
    ///
    /// It may have returned new ECH configurations that could be used to retry negotiation
    /// with a fresh connection.
    ///
    /// See [`RejectedEch::can_retry()`] and [`crate::client::EchConfig::for_retry()`].
    RejectedEch(RejectedEch),

    /// Errors of this variant should never be produced by the library.
    ///
    /// Please file a bug if you see one.
    Unreachable(&'static str),

    /// The caller misused the API
    ///
    /// Generally we try to make error cases like this unnecessary by embedding
    /// the constraints in the type system, so misuses simply do not compile.  But,
    /// for cases where that is not possible or exceptionally costly, we return errors
    /// of this variant.
    ///
    /// This only results from the ordering, dependencies or parameter values of calls,
    /// so (assuming parameter values are fixed) these can be determined and fixed by
    /// reading the code.  They are never caused by the values of untrusted data, or
    /// other non-determinism.
    ApiMisuse(ApiMisuse),

    /// Any other error.
    ///
    /// This variant should only be used when the error is not better described by a more
    /// specific variant. For example, if a custom crypto provider returns a
    /// provider specific error.
    ///
    /// Enums holding this variant will never compare equal to each other.
    Other(OtherError),
}

/// Determine which alert should be sent for a given error.
///
/// If this mapping fails, no alert is sent.
impl TryFrom<&Error> for AlertDescription {
    type Error = ();

    fn try_from(error: &Error) -> Result<Self, Self::Error> {
        Ok(match error {
            Error::DecryptError => Self::BadRecordMac,
            Error::InappropriateMessage { .. } | Error::InappropriateHandshakeMessage { .. } => {
                Self::UnexpectedMessage
            }
            Error::InvalidCertificate(e) => Self::from(e),
            Error::InvalidMessage(e) => Self::from(*e),
            Error::NoApplicationProtocol => Self::NoApplicationProtocol,
            Error::PeerMisbehaved(e) => Self::from(*e),
            Error::PeerIncompatible(e) => Self::from(*e),
            Error::PeerSentOversizedRecord => Self::RecordOverflow,
            Error::RejectedEch(_) => Self::EncryptedClientHelloRequired,

            _ => return Err(()),
        })
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InappropriateMessage {
                expect_types,
                got_type,
            } => write!(
                f,
                "received unexpected message: got {:?} when expecting {}",
                got_type,
                join::<ContentType>(expect_types)
            ),
            Self::InappropriateHandshakeMessage {
                expect_types,
                got_type,
            } => write!(
                f,
                "received unexpected handshake message: got {:?} when expecting {}",
                got_type,
                join::<HandshakeType>(expect_types)
            ),
            Self::InvalidMessage(typ) => {
                write!(f, "received corrupt message of type {typ:?}")
            }
            Self::PeerIncompatible(why) => write!(f, "peer is incompatible: {why:?}"),
            Self::PeerMisbehaved(why) => write!(f, "peer misbehaved: {why:?}"),
            Self::AlertReceived(alert) => write!(f, "received fatal alert: the peer {alert}"),
            Self::InvalidCertificate(err) => {
                write!(f, "invalid peer certificate: {err}")
            }
            Self::InvalidCertRevocationList(err) => {
                write!(f, "invalid certificate revocation list: {err:?}")
            }
            Self::UnsupportedNameType => write!(f, "presented server name type wasn't supported"),
            Self::DecryptError => write!(f, "cannot decrypt peer's message"),
            Self::InvalidEncryptedClientHello(err) => {
                write!(f, "encrypted client hello failure: {err:?}")
            }
            Self::EncryptError => write!(f, "cannot encrypt message"),
            Self::PeerSentOversizedRecord => write!(f, "peer sent excess record size"),
            Self::HandshakeNotComplete => write!(f, "handshake not complete"),
            Self::NoApplicationProtocol => write!(f, "peer doesn't support any known protocol"),
            Self::NoSuitableCertificate => write!(f, "no suitable certificate found"),
            Self::FailedToGetCurrentTime => write!(f, "failed to get current time"),
            Self::FailedToGetRandomBytes => write!(f, "failed to get random bytes"),
            Self::BadMaxFragmentSize => {
                write!(f, "the supplied max_fragment_size was too small or large")
            }
            Self::InconsistentKeys(why) => {
                write!(f, "keys may not be consistent: {why:?}")
            }
            Self::RejectedEch(why) => {
                write!(
                    f,
                    "server rejected encrypted client hello (ECH) {} retry configs",
                    if why.can_retry() { "with" } else { "without" }
                )
            }
            Self::General(err) => write!(f, "unexpected error: {err}"),
            Self::Unreachable(err) => write!(
                f,
                "unreachable condition: {err} (please file a bug in rustls)"
            ),
            Self::ApiMisuse(why) => write!(f, "API misuse: {why:?}"),
            Self::Other(err) => write!(f, "other error: {err}"),
        }
    }
}

impl From<CertificateError> for Error {
    #[inline]
    fn from(e: CertificateError) -> Self {
        Self::InvalidCertificate(e)
    }
}

impl From<InvalidMessage> for Error {
    #[inline]
    fn from(e: InvalidMessage) -> Self {
        Self::InvalidMessage(e)
    }
}

impl From<PeerMisbehaved> for Error {
    #[inline]
    fn from(e: PeerMisbehaved) -> Self {
        Self::PeerMisbehaved(e)
    }
}

impl From<PeerIncompatible> for Error {
    #[inline]
    fn from(e: PeerIncompatible) -> Self {
        Self::PeerIncompatible(e)
    }
}

impl From<CertRevocationListError> for Error {
    #[inline]
    fn from(e: CertRevocationListError) -> Self {
        Self::InvalidCertRevocationList(e)
    }
}

impl From<EncryptedClientHelloError> for Error {
    #[inline]
    fn from(e: EncryptedClientHelloError) -> Self {
        Self::InvalidEncryptedClientHello(e)
    }
}

impl From<RejectedEch> for Error {
    fn from(rejected_error: RejectedEch) -> Self {
        Self::RejectedEch(rejected_error)
    }
}

impl From<ApiMisuse> for Error {
    fn from(e: ApiMisuse) -> Self {
        Self::ApiMisuse(e)
    }
}

impl From<OtherError> for Error {
    fn from(value: OtherError) -> Self {
        Self::Other(value)
    }
}

impl From<InconsistentKeys> for Error {
    #[inline]
    fn from(e: InconsistentKeys) -> Self {
        Self::InconsistentKeys(e)
    }
}

impl From<SystemTimeError> for Error {
    #[inline]
    fn from(_: SystemTimeError) -> Self {
        Self::FailedToGetCurrentTime
    }
}

impl From<GetRandomFailed> for Error {
    fn from(_: GetRandomFailed) -> Self {
        Self::FailedToGetRandomBytes
    }
}

impl core::error::Error for Error {}

/// The ways in which certificate validators can express errors.
///
/// Note that the rustls TLS protocol code interprets specifically these
/// error codes to send specific TLS alerts.  Therefore, if a
/// custom certificate validator uses incorrect errors the library as
/// a whole will send alerts that do not match the standard (this is usually
/// a minor issue, but could be misleading).
#[non_exhaustive]
#[derive(Debug, Clone)]
pub enum CertificateError {
    /// The certificate is not correctly encoded.
    BadEncoding,

    /// The current time is after the `notAfter` time in the certificate.
    Expired,

    /// The current time is after the `notAfter` time in the certificate.
    ///
    /// This variant is semantically the same as `Expired`, but includes
    /// extra data to improve error reports.
    ExpiredContext {
        /// The validation time.
        time: UnixTime,
        /// The `notAfter` time of the certificate.
        not_after: UnixTime,
    },

    /// The current time is before the `notBefore` time in the certificate.
    NotValidYet,

    /// The current time is before the `notBefore` time in the certificate.
    ///
    /// This variant is semantically the same as `NotValidYet`, but includes
    /// extra data to improve error reports.
    NotValidYetContext {
        /// The validation time.
        time: UnixTime,
        /// The `notBefore` time of the certificate.
        not_before: UnixTime,
    },

    /// The certificate has been revoked.
    Revoked,

    /// The certificate contains an extension marked critical, but it was
    /// not processed by the certificate validator.
    UnhandledCriticalExtension,

    /// The certificate chain is not issued by a known root certificate.
    UnknownIssuer,

    /// The certificate's revocation status could not be determined.
    UnknownRevocationStatus,

    /// The certificate's revocation status could not be determined, because the CRL is expired.
    ExpiredRevocationList,

    /// The certificate's revocation status could not be determined, because the CRL is expired.
    ///
    /// This variant is semantically the same as `ExpiredRevocationList`, but includes
    /// extra data to improve error reports.
    ExpiredRevocationListContext {
        /// The validation time.
        time: UnixTime,
        /// The nextUpdate time of the CRL.
        next_update: UnixTime,
    },

    /// A certificate is not correctly signed by the key of its alleged
    /// issuer.
    BadSignature,

    /// A signature inside a certificate or on a handshake was made with an unsupported algorithm.
    UnsupportedSignatureAlgorithm {
        /// The signature algorithm OID that was unsupported.
        signature_algorithm_id: Vec<u8>,
        /// Supported algorithms that were available for signature verification.
        supported_algorithms: Vec<AlgorithmIdentifier>,
    },

    /// A signature was made with an algorithm that doesn't match the relevant public key.
    UnsupportedSignatureAlgorithmForPublicKey {
        /// The signature algorithm OID.
        signature_algorithm_id: Vec<u8>,
        /// The public key algorithm OID.
        public_key_algorithm_id: Vec<u8>,
    },

    /// The subject names in an end-entity certificate do not include
    /// the expected name.
    NotValidForName,

    /// The subject names in an end-entity certificate do not include
    /// the expected name.
    ///
    /// This variant is semantically the same as `NotValidForName`, but includes
    /// extra data to improve error reports.
    NotValidForNameContext {
        /// Expected server name.
        expected: ServerName<'static>,

        /// The names presented in the end entity certificate.
        ///
        /// These are the subject names as present in the leaf certificate and may contain DNS names
        /// with or without a wildcard label as well as IP address names.
        presented: Vec<String>,
    },

    /// The certificate is being used for a different purpose than allowed.
    InvalidPurpose,

    /// The certificate is being used for a different purpose than allowed.
    ///
    /// This variant is semantically the same as `InvalidPurpose`, but includes
    /// extra data to improve error reports.
    InvalidPurposeContext {
        /// Extended key purpose that was required by the application.
        required: ExtendedKeyPurpose,
        /// Extended key purposes that were presented in the peer's certificate.
        presented: Vec<ExtendedKeyPurpose>,
    },

    /// The OCSP response provided to the verifier was invalid.
    ///
    /// This should be returned from [`ServerVerifier::verify_identity()`]
    /// when a verifier checks its `ocsp_response` parameter and finds it invalid.
    ///
    /// This maps to [`AlertDescription::BadCertificateStatusResponse`].
    ///
    /// [`ServerVerifier::verify_identity()`]: crate::client::danger::ServerVerifier::verify_identity
    InvalidOcspResponse,

    /// The certificate is valid, but the handshake is rejected for other
    /// reasons.
    ApplicationVerificationFailure,

    /// Any other error.
    ///
    /// This can be used by custom verifiers to expose the underlying error
    /// (where they are not better described by the more specific errors
    /// above).
    ///
    /// It is also used by the default verifier in case its error is
    /// not covered by the above common cases.
    ///
    /// Enums holding this variant will never compare equal to each other.
    Other(OtherError),
}

impl PartialEq<Self> for CertificateError {
    fn eq(&self, other: &Self) -> bool {
        use CertificateError::*;
        match (self, other) {
            (BadEncoding, BadEncoding) => true,
            (Expired, Expired) => true,
            (
                ExpiredContext {
                    time: left_time,
                    not_after: left_not_after,
                },
                ExpiredContext {
                    time: right_time,
                    not_after: right_not_after,
                },
            ) => (left_time, left_not_after) == (right_time, right_not_after),
            (NotValidYet, NotValidYet) => true,
            (
                NotValidYetContext {
                    time: left_time,
                    not_before: left_not_before,
                },
                NotValidYetContext {
                    time: right_time,
                    not_before: right_not_before,
                },
            ) => (left_time, left_not_before) == (right_time, right_not_before),
            (Revoked, Revoked) => true,
            (UnhandledCriticalExtension, UnhandledCriticalExtension) => true,
            (UnknownIssuer, UnknownIssuer) => true,
            (BadSignature, BadSignature) => true,
            (
                UnsupportedSignatureAlgorithm {
                    signature_algorithm_id: left_signature_algorithm_id,
                    supported_algorithms: left_supported_algorithms,
                },
                UnsupportedSignatureAlgorithm {
                    signature_algorithm_id: right_signature_algorithm_id,
                    supported_algorithms: right_supported_algorithms,
                },
            ) => {
                (left_signature_algorithm_id, left_supported_algorithms)
                    == (right_signature_algorithm_id, right_supported_algorithms)
            }
            (
                UnsupportedSignatureAlgorithmForPublicKey {
                    signature_algorithm_id: left_signature_algorithm_id,
                    public_key_algorithm_id: left_public_key_algorithm_id,
                },
                UnsupportedSignatureAlgorithmForPublicKey {
                    signature_algorithm_id: right_signature_algorithm_id,
                    public_key_algorithm_id: right_public_key_algorithm_id,
                },
            ) => {
                (left_signature_algorithm_id, left_public_key_algorithm_id)
                    == (right_signature_algorithm_id, right_public_key_algorithm_id)
            }
            (NotValidForName, NotValidForName) => true,
            (
                NotValidForNameContext {
                    expected: left_expected,
                    presented: left_presented,
                },
                NotValidForNameContext {
                    expected: right_expected,
                    presented: right_presented,
                },
            ) => (left_expected, left_presented) == (right_expected, right_presented),
            (InvalidPurpose, InvalidPurpose) => true,
            (
                InvalidPurposeContext {
                    required: left_required,
                    presented: left_presented,
                },
                InvalidPurposeContext {
                    required: right_required,
                    presented: right_presented,
                },
            ) => (left_required, left_presented) == (right_required, right_presented),
            (InvalidOcspResponse, InvalidOcspResponse) => true,
            (ApplicationVerificationFailure, ApplicationVerificationFailure) => true,
            (UnknownRevocationStatus, UnknownRevocationStatus) => true,
            (ExpiredRevocationList, ExpiredRevocationList) => true,
            (
                ExpiredRevocationListContext {
                    time: left_time,
                    next_update: left_next_update,
                },
                ExpiredRevocationListContext {
                    time: right_time,
                    next_update: right_next_update,
                },
            ) => (left_time, left_next_update) == (right_time, right_next_update),
            _ => false,
        }
    }
}

// The following mapping are heavily referenced in:
// * [OpenSSL Implementation](https://github.com/openssl/openssl/blob/45bb98bfa223efd3258f445ad443f878011450f0/ssl/statem/statem_lib.c#L1434)
// * [BoringSSL Implementation](https://github.com/google/boringssl/blob/583c60bd4bf76d61b2634a58bcda99a92de106cb/ssl/ssl_x509.cc#L1323)
impl From<&CertificateError> for AlertDescription {
    fn from(e: &CertificateError) -> Self {
        use CertificateError::*;
        match e {
            BadEncoding
            | UnhandledCriticalExtension
            | NotValidForName
            | NotValidForNameContext { .. } => Self::BadCertificate,
            // RFC 5246/RFC 8446
            // certificate_expired
            //  A certificate has expired or **is not currently valid**.
            Expired | ExpiredContext { .. } | NotValidYet | NotValidYetContext { .. } => {
                Self::CertificateExpired
            }
            Revoked => Self::CertificateRevoked,
            // OpenSSL, BoringSSL and AWS-LC all generate an Unknown CA alert for
            // the case where revocation status can not be determined, so we do the same here.
            UnknownIssuer
            | UnknownRevocationStatus
            | ExpiredRevocationList
            | ExpiredRevocationListContext { .. } => Self::UnknownCa,
            InvalidOcspResponse => Self::BadCertificateStatusResponse,
            BadSignature
            | UnsupportedSignatureAlgorithm { .. }
            | UnsupportedSignatureAlgorithmForPublicKey { .. } => Self::DecryptError,
            InvalidPurpose | InvalidPurposeContext { .. } => Self::UnsupportedCertificate,
            ApplicationVerificationFailure => Self::AccessDenied,
            // RFC 5246/RFC 8446
            // certificate_unknown
            //  Some other (unspecified) issue arose in processing the
            //  certificate, rendering it unacceptable.
            Other(..) => Self::CertificateUnknown,
        }
    }
}

impl fmt::Display for CertificateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotValidForNameContext {
                expected,
                presented,
            } => {
                write!(
                    f,
                    "certificate not valid for name {:?}; certificate ",
                    expected.to_str()
                )?;

                match presented.as_slice() {
                    &[] => write!(
                        f,
                        "is not valid for any names (according to its subjectAltName extension)"
                    ),
                    [one] => write!(f, "is only valid for {one}"),
                    many => {
                        write!(f, "is only valid for ")?;

                        let n = many.len();
                        let all_but_last = &many[..n - 1];
                        let last = &many[n - 1];

                        for (i, name) in all_but_last.iter().enumerate() {
                            write!(f, "{name}")?;
                            if i < n - 2 {
                                write!(f, ", ")?;
                            }
                        }
                        write!(f, " or {last}")
                    }
                }
            }

            Self::ExpiredContext { time, not_after } => write!(
                f,
                "certificate expired: verification time {} (UNIX), \
                 but certificate is not valid after {} \
                 ({} seconds ago)",
                time.as_secs(),
                not_after.as_secs(),
                time.as_secs()
                    .saturating_sub(not_after.as_secs())
            ),

            Self::NotValidYetContext { time, not_before } => write!(
                f,
                "certificate not valid yet: verification time {} (UNIX), \
                 but certificate is not valid before {} \
                 ({} seconds in future)",
                time.as_secs(),
                not_before.as_secs(),
                not_before
                    .as_secs()
                    .saturating_sub(time.as_secs())
            ),

            Self::ExpiredRevocationListContext { time, next_update } => write!(
                f,
                "certificate revocation list expired: \
                 verification time {} (UNIX), \
                 but CRL is not valid after {} \
                 ({} seconds ago)",
                time.as_secs(),
                next_update.as_secs(),
                time.as_secs()
                    .saturating_sub(next_update.as_secs())
            ),

            Self::InvalidPurposeContext {
                required,
                presented,
            } => {
                write!(
                    f,
                    "certificate does not allow extended key usage for {required}, allows "
                )?;
                for (i, eku) in presented.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{eku}")?;
                }
                Ok(())
            }

            Self::Other(other) => write!(f, "{other}"),

            other => write!(f, "{other:?}"),
        }
    }
}

enum_builder! {
    /// The `AlertDescription` TLS protocol enum.  Values in this enum are taken
    /// from the various RFCs covering TLS, and are listed by IANA.
    /// The `Unknown` item is used when processing unrecognized ordinals.
    #[repr(u8)]
    pub enum AlertDescription {
        CloseNotify => 0x00,
        UnexpectedMessage => 0x0a,
        BadRecordMac => 0x14,
        DecryptionFailed => 0x15,
        RecordOverflow => 0x16,
        DecompressionFailure => 0x1e,
        HandshakeFailure => 0x28,
        NoCertificate => 0x29,
        BadCertificate => 0x2a,
        UnsupportedCertificate => 0x2b,
        CertificateRevoked => 0x2c,
        CertificateExpired => 0x2d,
        CertificateUnknown => 0x2e,
        IllegalParameter => 0x2f,
        UnknownCa => 0x30,
        AccessDenied => 0x31,
        DecodeError => 0x32,
        DecryptError => 0x33,
        ExportRestriction => 0x3c,
        ProtocolVersion => 0x46,
        InsufficientSecurity => 0x47,
        InternalError => 0x50,
        InappropriateFallback => 0x56,
        UserCanceled => 0x5a,
        NoRenegotiation => 0x64,
        MissingExtension => 0x6d,
        UnsupportedExtension => 0x6e,
        CertificateUnobtainable => 0x6f,
        UnrecognizedName => 0x70,
        BadCertificateStatusResponse => 0x71,
        BadCertificateHashValue => 0x72,
        UnknownPskIdentity => 0x73,
        CertificateRequired => 0x74,
        NoApplicationProtocol => 0x78,
        EncryptedClientHelloRequired => 0x79, // https://datatracker.ietf.org/doc/html/draft-ietf-tls-esni-18#section-11.2
    }
}

impl fmt::Display for AlertDescription {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // these should be:
        // - in past tense
        // - be syntactically correct if prefaced with 'the peer' to describe
        //   received alerts
        match self {
            // this is normal.
            Self::CloseNotify => write!(f, "cleanly closed the connection"),

            // these are abnormal.  they are usually symptomatic of an interop failure.
            // please file a bug report.
            Self::UnexpectedMessage => write!(f, "received an unexpected message"),
            Self::BadRecordMac => write!(f, "failed to verify a message"),
            Self::RecordOverflow => write!(f, "rejected an over-length message"),
            Self::IllegalParameter => write!(
                f,
                "rejected a message because a field was incorrect or inconsistent"
            ),
            Self::DecodeError => write!(f, "failed to decode a message"),
            Self::DecryptError => {
                write!(f, "failed to perform a handshake cryptographic operation")
            }
            Self::InappropriateFallback => {
                write!(f, "detected an attempted version downgrade")
            }
            Self::MissingExtension => {
                write!(f, "required a specific extension that was not provided")
            }
            Self::UnsupportedExtension => write!(f, "rejected an unsolicited extension"),

            // these are deprecated by TLS1.3 and should be very rare (but possible
            // with TLS1.2 or earlier peers)
            Self::DecryptionFailed => write!(f, "failed to decrypt a message"),
            Self::DecompressionFailure => write!(f, "failed to decompress a message"),
            Self::NoCertificate => write!(f, "found no certificate"),
            Self::ExportRestriction => write!(f, "refused due to export restrictions"),
            Self::NoRenegotiation => write!(f, "rejected an attempt at renegotiation"),
            Self::CertificateUnobtainable => {
                write!(f, "failed to retrieve its certificate")
            }
            Self::BadCertificateHashValue => {
                write!(f, "rejected the `certificate_hash` extension")
            }

            // this is fairly normal. it means a server cannot choose compatible parameters
            // given our offer.  please use ssllabs.com or similar to investigate what parameters
            // the server supports.
            Self::HandshakeFailure => write!(
                f,
                "failed to negotiate an acceptable set of security parameters"
            ),
            Self::ProtocolVersion => write!(f, "did not support a suitable TLS version"),
            Self::InsufficientSecurity => {
                write!(f, "required a higher security level than was offered")
            }

            // these usually indicate a local misconfiguration, either in certificate selection
            // or issuance.
            Self::BadCertificate => {
                write!(
                    f,
                    "rejected the certificate as corrupt or incorrectly signed"
                )
            }
            Self::UnsupportedCertificate => {
                write!(f, "did not support the certificate")
            }
            Self::CertificateRevoked => write!(f, "found the certificate to be revoked"),
            Self::CertificateExpired => write!(f, "found the certificate to be expired"),
            Self::CertificateUnknown => {
                write!(f, "rejected the certificate for an unspecified reason")
            }
            Self::UnknownCa => write!(f, "found the certificate was not issued by a trusted CA"),
            Self::BadCertificateStatusResponse => {
                write!(f, "rejected the certificate status response")
            }
            // typically this means client authentication is required, in TLS1.2...
            Self::AccessDenied => write!(f, "denied access"),
            // and in TLS1.3...
            Self::CertificateRequired => write!(f, "required a client certificate"),

            Self::InternalError => write!(f, "encountered an internal error"),
            Self::UserCanceled => write!(f, "canceled the handshake"),

            // rejection of SNI (uncommon; usually servers behave as if it was not sent)
            Self::UnrecognizedName => {
                write!(f, "did not recognize a name in the `server_name` extension")
            }

            // rejection of PSK connections (NYI in this library); indicates a local
            // misconfiguration.
            Self::UnknownPskIdentity => {
                write!(f, "did not recognize any offered PSK identity")
            }

            // rejection of ALPN (varying levels of support, but missing support is
            // often dangerous if the peers fail to agree on the same protocol)
            Self::NoApplicationProtocol => write!(
                f,
                "did not support any of the offered application protocols"
            ),

            // ECH requirement by clients, see
            // <https://datatracker.ietf.org/doc/draft-ietf-tls-esni/25/>
            Self::EncryptedClientHelloRequired => {
                write!(f, "required use of encrypted client hello")
            }

            Self::Unknown(n) => write!(f, "sent an unknown alert (0x{n:02x?})"),
        }
    }
}

/// A corrupt TLS message payload that resulted in an error.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum InvalidMessage {
    /// A certificate payload exceeded rustls's 64KB limit
    CertificatePayloadTooLarge,
    /// An advertised message was larger then expected.
    HandshakePayloadTooLarge,
    /// The peer sent us a syntactically incorrect ChangeCipherSpec payload.
    InvalidCcs,
    /// An unknown content type was encountered during message decoding.
    InvalidContentType,
    /// A peer sent an invalid certificate status type
    InvalidCertificateStatusType,
    /// Context was incorrectly attached to a certificate request during a handshake.
    InvalidCertRequest,
    /// A peer's DH params could not be decoded
    InvalidDhParams,
    /// A message was zero-length when its record kind forbids it.
    InvalidEmptyPayload,
    /// A peer sent an unexpected key update request.
    InvalidKeyUpdate,
    /// A peer's server name could not be decoded
    InvalidServerName,
    /// A TLS message payload was larger then allowed by the specification.
    MessageTooLarge,
    /// Message is shorter than the expected length
    MessageTooShort,
    /// Missing data for the named handshake payload value
    MissingData(&'static str),
    /// A peer did not advertise its supported key exchange groups.
    MissingKeyExchange,
    /// A peer sent an empty list of signature schemes
    NoSignatureSchemes,
    /// Trailing data found for the named handshake payload value
    TrailingData(&'static str),
    /// A peer sent an unexpected message type.
    UnexpectedMessage(&'static str),
    /// An unknown TLS protocol was encountered during message decoding.
    UnknownProtocolVersion,
    /// A peer sent a non-null compression method.
    UnsupportedCompression,
    /// A peer sent an unknown elliptic curve type.
    UnsupportedCurveType,
    /// A peer sent an unsupported key exchange algorithm.
    UnsupportedKeyExchangeAlgorithm(KeyExchangeAlgorithm),
    /// A server sent an empty ticket
    EmptyTicketValue,
    /// A peer sent an empty list of items, but a non-empty list is required.
    ///
    /// The argument names the context.
    IllegalEmptyList(&'static str),
    /// A peer sent a message where a given extension type was repeated
    DuplicateExtension(u16),
    /// A peer sent a message with a PSK offer extension in wrong position
    PreSharedKeyIsNotFinalExtension,
    /// A server sent a HelloRetryRequest with an unknown extension
    UnknownHelloRetryRequestExtension,
    /// The peer sent a TLS1.3 Certificate with an unknown extension
    UnknownCertificateExtension,
}

impl From<InvalidMessage> for AlertDescription {
    fn from(e: InvalidMessage) -> Self {
        match e {
            InvalidMessage::PreSharedKeyIsNotFinalExtension => Self::IllegalParameter,
            InvalidMessage::DuplicateExtension(_) => Self::IllegalParameter,
            InvalidMessage::UnknownHelloRetryRequestExtension => Self::UnsupportedExtension,
            InvalidMessage::CertificatePayloadTooLarge => Self::BadCertificate,
            _ => Self::DecodeError,
        }
    }
}

/// The set of cases where we failed to make a connection because we thought
/// the peer was misbehaving.
///
/// This is `non_exhaustive`: we might add or stop using items here in minor
/// versions.  We also don't document what they mean.  Generally a user of
/// rustls shouldn't vary its behaviour on these error codes, and there is
/// nothing it can do to improve matters.
///
/// Please file a bug against rustls if you see `Error::PeerMisbehaved` in
/// the wild.
#[expect(missing_docs)]
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum PeerMisbehaved {
    AttemptedDowngradeToTls12WhenTls13IsSupported,
    BadCertChainExtensions,
    DisallowedEncryptedExtension,
    DuplicateClientHelloExtensions,
    DuplicateEncryptedExtensions,
    DuplicateHelloRetryRequestExtensions,
    DuplicateNewSessionTicketExtensions,
    DuplicateServerHelloExtensions,
    DuplicateServerNameTypes,
    EarlyDataAttemptedInSecondClientHello,
    EarlyDataExtensionWithoutResumption,
    EarlyDataOfferedWithVariedCipherSuite,
    HandshakeHashVariedAfterRetry,
    /// Received an alert with an undefined level and the given [`AlertDescription`]
    IllegalAlertLevel(u8, AlertDescription),
    IllegalHelloRetryRequestWithEmptyCookie,
    IllegalHelloRetryRequestWithNoChanges,
    IllegalHelloRetryRequestWithOfferedGroup,
    IllegalHelloRetryRequestWithUnofferedCipherSuite,
    IllegalHelloRetryRequestWithUnofferedNamedGroup,
    IllegalHelloRetryRequestWithUnsupportedVersion,
    IllegalHelloRetryRequestWithWrongSessionId,
    IllegalHelloRetryRequestWithInvalidEch,
    IllegalMiddleboxChangeCipherSpec,
    IllegalTlsInnerPlaintext,
    /// Received a warning alert with the given [`AlertDescription`]
    IllegalWarningAlert(AlertDescription),
    IncorrectBinder,
    IncorrectFinished,
    InvalidCertCompression,
    InvalidMaxEarlyDataSize,
    InvalidKeyShare,
    KeyEpochWithPendingFragment,
    KeyUpdateReceivedInQuicConnection,
    MessageInterleavedWithHandshakeMessage,
    MissingBinderInPskExtension,
    MissingKeyShare,
    MissingPskModesExtension,
    MissingQuicTransportParameters,
    NoCertificatesPresented,
    OfferedDuplicateCertificateCompressions,
    OfferedDuplicateKeyShares,
    OfferedEarlyDataWithOldProtocolVersion,
    OfferedEmptyApplicationProtocol,
    OfferedIncorrectCompressions,
    PskExtensionMustBeLast,
    PskExtensionWithMismatchedIdsAndBinders,
    RefusedToFollowHelloRetryRequest,
    RejectedEarlyDataInterleavedWithHandshakeMessage,
    ResumptionAttemptedWithVariedEms,
    ResumptionOfferedWithVariedCipherSuite,
    ResumptionOfferedWithVariedEms,
    ResumptionOfferedWithIncompatibleCipherSuite,
    SelectedDifferentCipherSuiteAfterRetry,
    SelectedInvalidPsk,
    SelectedTls12UsingTls13VersionExtension,
    SelectedUnofferedApplicationProtocol,
    SelectedUnofferedCertCompression,
    SelectedUnofferedCipherSuite,
    SelectedUnofferedCompression,
    SelectedUnofferedKxGroup,
    SelectedUnofferedPsk,
    ServerEchoedCompatibilitySessionId,
    ServerHelloMustOfferUncompressedEcPoints,
    ServerNameDifferedOnRetry,
    ServerNameMustContainOneHostName,
    SignedKxWithWrongAlgorithm,
    SignedHandshakeWithUnadvertisedSigScheme,
    TooManyEmptyFragments,
    TooManyKeyUpdateRequests,
    TooManyRenegotiationRequests,
    TooManyWarningAlertsReceived,
    TooMuchEarlyDataReceived,
    UnexpectedCleartextExtension,
    UnsolicitedCertExtension,
    UnsolicitedEncryptedExtension,
    UnsolicitedSctList,
    UnsolicitedServerHelloExtension,
    WrongGroupForKeyShare,
    UnsolicitedEchExtension,
}

impl From<PeerMisbehaved> for AlertDescription {
    fn from(e: PeerMisbehaved) -> Self {
        match e {
            PeerMisbehaved::DisallowedEncryptedExtension
            | PeerMisbehaved::IllegalHelloRetryRequestWithInvalidEch
            | PeerMisbehaved::UnexpectedCleartextExtension
            | PeerMisbehaved::UnsolicitedEchExtension
            | PeerMisbehaved::UnsolicitedEncryptedExtension
            | PeerMisbehaved::UnsolicitedServerHelloExtension => Self::UnsupportedExtension,

            PeerMisbehaved::IllegalMiddleboxChangeCipherSpec
            | PeerMisbehaved::KeyEpochWithPendingFragment
            | PeerMisbehaved::KeyUpdateReceivedInQuicConnection => Self::UnexpectedMessage,

            PeerMisbehaved::IllegalWarningAlert(_) => Self::DecodeError,

            PeerMisbehaved::IncorrectBinder | PeerMisbehaved::IncorrectFinished => {
                Self::DecryptError
            }

            PeerMisbehaved::InvalidCertCompression
            | PeerMisbehaved::SelectedUnofferedCertCompression => Self::BadCertificate,

            PeerMisbehaved::MissingKeyShare
            | PeerMisbehaved::MissingPskModesExtension
            | PeerMisbehaved::MissingQuicTransportParameters => Self::MissingExtension,

            PeerMisbehaved::NoCertificatesPresented => Self::CertificateRequired,

            _ => Self::IllegalParameter,
        }
    }
}

/// The set of cases where we failed to make a connection because a peer
/// doesn't support a TLS version/feature we require.
///
/// This is `non_exhaustive`: we might add or stop using items here in minor
/// versions.
#[expect(missing_docs)]
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum PeerIncompatible {
    EcPointsExtensionRequired,
    ExtendedMasterSecretExtensionRequired,
    IncorrectCertificateTypeExtension,
    KeyShareExtensionRequired,
    MultipleRawKeys,
    NamedGroupsExtensionRequired,
    NoCertificateRequestSignatureSchemesInCommon,
    NoCipherSuitesInCommon,
    NoEcPointFormatsInCommon,
    NoKxGroupsInCommon,
    NoSignatureSchemesInCommon,
    NoServerNameProvided,
    NullCompressionRequired,
    ServerDoesNotSupportTls12Or13,
    ServerSentHelloRetryRequestWithUnknownExtension,
    ServerTlsVersionIsDisabledByOurConfig,
    SignatureAlgorithmsExtensionRequired,
    SupportedVersionsExtensionRequired,
    Tls12NotOffered,
    Tls12NotOfferedOrEnabled,
    Tls13RequiredForQuic,
    UncompressedEcPointsRequired,
    UnknownCertificateType(u8),
    UnsolicitedCertificateTypeExtension,
}

impl From<PeerIncompatible> for AlertDescription {
    fn from(e: PeerIncompatible) -> Self {
        match e {
            PeerIncompatible::NullCompressionRequired => Self::IllegalParameter,

            PeerIncompatible::ServerTlsVersionIsDisabledByOurConfig
            | PeerIncompatible::SupportedVersionsExtensionRequired
            | PeerIncompatible::Tls12NotOffered
            | PeerIncompatible::Tls12NotOfferedOrEnabled
            | PeerIncompatible::Tls13RequiredForQuic => Self::ProtocolVersion,

            PeerIncompatible::UnknownCertificateType(_) => Self::UnsupportedCertificate,

            _ => Self::HandshakeFailure,
        }
    }
}

/// Extended Key Usage (EKU) purpose values.
///
/// These are usually represented as OID values in the certificate's extension (if present), but
/// we represent the values that are most relevant to rustls as named enum variants.
#[non_exhaustive]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExtendedKeyPurpose {
    /// Client authentication
    ClientAuth,
    /// Server authentication
    ServerAuth,
    /// Other EKU values
    ///
    /// Represented here as a `Vec<usize>` for human readability.
    Other(Vec<usize>),
}

impl ExtendedKeyPurpose {
    #[cfg(feature = "webpki")]
    pub(crate) fn for_values(values: impl Iterator<Item = usize>) -> Self {
        let values = values.collect::<Vec<_>>();
        match &*values {
            ExtendedKeyUsage::CLIENT_AUTH_REPR => Self::ClientAuth,
            ExtendedKeyUsage::SERVER_AUTH_REPR => Self::ServerAuth,
            _ => Self::Other(values),
        }
    }
}

impl fmt::Display for ExtendedKeyPurpose {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ClientAuth => write!(f, "client authentication"),
            Self::ServerAuth => write!(f, "server authentication"),
            Self::Other(values) => {
                for (i, value) in values.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{value}")?;
                }
                Ok(())
            }
        }
    }
}

/// The ways in which a certificate revocation list (CRL) can be invalid.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub enum CertRevocationListError {
    /// The CRL had a bad signature from its issuer.
    BadSignature,

    /// A signature inside a certificate or on a handshake was made with an unsupported algorithm.
    UnsupportedSignatureAlgorithm {
        /// The signature algorithm OID that was unsupported.
        signature_algorithm_id: Vec<u8>,
        /// Supported algorithms that were available for signature verification.
        supported_algorithms: Vec<AlgorithmIdentifier>,
    },

    /// A signature was made with an algorithm that doesn't match the relevant public key.
    UnsupportedSignatureAlgorithmForPublicKey {
        /// The signature algorithm OID.
        signature_algorithm_id: Vec<u8>,
        /// The public key algorithm OID.
        public_key_algorithm_id: Vec<u8>,
    },

    /// The CRL contained an invalid CRL number.
    InvalidCrlNumber,

    /// The CRL contained a revoked certificate with an invalid serial number.
    InvalidRevokedCertSerialNumber,

    /// The CRL issuer does not specify the cRLSign key usage.
    IssuerInvalidForCrl,

    /// The CRL is invalid for some other reason.
    ///
    /// Enums holding this variant will never compare equal to each other.
    Other(OtherError),

    /// The CRL is not correctly encoded.
    ParseError,

    /// The CRL is not a v2 X.509 CRL.
    UnsupportedCrlVersion,

    /// The CRL, or a revoked certificate in the CRL, contained an unsupported critical extension.
    UnsupportedCriticalExtension,

    /// The CRL is an unsupported delta CRL, containing only changes relative to another CRL.
    UnsupportedDeltaCrl,

    /// The CRL is an unsupported indirect CRL, containing revoked certificates issued by a CA
    /// other than the issuer of the CRL.
    UnsupportedIndirectCrl,

    /// The CRL contained a revoked certificate with an unsupported revocation reason.
    /// See RFC 5280 Section 5.3.1[^1] for a list of supported revocation reasons.
    ///
    /// [^1]: <https://www.rfc-editor.org/rfc/rfc5280#section-5.3.1>
    UnsupportedRevocationReason,
}

impl PartialEq<Self> for CertRevocationListError {
    fn eq(&self, other: &Self) -> bool {
        use CertRevocationListError::*;
        match (self, other) {
            (BadSignature, BadSignature) => true,
            (
                UnsupportedSignatureAlgorithm {
                    signature_algorithm_id: left_signature_algorithm_id,
                    supported_algorithms: left_supported_algorithms,
                },
                UnsupportedSignatureAlgorithm {
                    signature_algorithm_id: right_signature_algorithm_id,
                    supported_algorithms: right_supported_algorithms,
                },
            ) => {
                (left_signature_algorithm_id, left_supported_algorithms)
                    == (right_signature_algorithm_id, right_supported_algorithms)
            }
            (
                UnsupportedSignatureAlgorithmForPublicKey {
                    signature_algorithm_id: left_signature_algorithm_id,
                    public_key_algorithm_id: left_public_key_algorithm_id,
                },
                UnsupportedSignatureAlgorithmForPublicKey {
                    signature_algorithm_id: right_signature_algorithm_id,
                    public_key_algorithm_id: right_public_key_algorithm_id,
                },
            ) => {
                (left_signature_algorithm_id, left_public_key_algorithm_id)
                    == (right_signature_algorithm_id, right_public_key_algorithm_id)
            }
            (InvalidCrlNumber, InvalidCrlNumber) => true,
            (InvalidRevokedCertSerialNumber, InvalidRevokedCertSerialNumber) => true,
            (IssuerInvalidForCrl, IssuerInvalidForCrl) => true,
            (ParseError, ParseError) => true,
            (UnsupportedCrlVersion, UnsupportedCrlVersion) => true,
            (UnsupportedCriticalExtension, UnsupportedCriticalExtension) => true,
            (UnsupportedDeltaCrl, UnsupportedDeltaCrl) => true,
            (UnsupportedIndirectCrl, UnsupportedIndirectCrl) => true,
            (UnsupportedRevocationReason, UnsupportedRevocationReason) => true,
            _ => false,
        }
    }
}

/// An error that occurred while handling Encrypted Client Hello (ECH).
#[non_exhaustive]
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum EncryptedClientHelloError {
    /// The provided ECH configuration list was invalid.
    InvalidConfigList,
    /// No compatible ECH configuration.
    NoCompatibleConfig,
    /// The client configuration has server name indication (SNI) disabled.
    SniRequired,
}

/// The server rejected the request to enable Encrypted Client Hello (ECH)
///
/// If [`RejectedEch::can_retry()`] is true, then you may use this with
/// [`crate::client::EchConfig::for_retry()`] to build a new `EchConfig` for a fresh client
/// connection that will use a compatible ECH configuration provided by the server for a retry.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq)]
pub struct RejectedEch {
    pub(crate) retry_configs: Option<Vec<EchConfigPayload>>,
}

impl RejectedEch {
    /// Returns true if the server provided new ECH configurations to use for a fresh retry connection
    ///
    /// The `RejectedEch` error can be provided to [`crate::client::EchConfig::for_retry()`]
    /// to build a new `EchConfig` for a fresh client connection that will use a compatible ECH
    /// configuration provided by the server for a retry.
    pub fn can_retry(&self) -> bool {
        self.retry_configs.is_some()
    }

    /// Returns an `EchConfigListBytes` with the server's provided retry configurations (if any)
    pub fn retry_configs(&self) -> Option<EchConfigListBytes<'static>> {
        let Some(retry_configs) = &self.retry_configs else {
            return None;
        };

        let mut tls_encoded_list = Vec::new();
        retry_configs.encode(&mut tls_encoded_list);

        Some(EchConfigListBytes::from(tls_encoded_list))
    }
}

fn join<T: fmt::Debug>(items: &[T]) -> String {
    items
        .iter()
        .map(|x| format!("{x:?}"))
        .collect::<Vec<String>>()
        .join(" or ")
}

/// Describes cases of API misuse
///
/// Variants here should be sufficiently detailed that the action needed is clear.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq)]
pub enum ApiMisuse {
    /// Trying to resume a session with an unknown cipher suite.
    ResumingFromUnknownCipherSuite(CipherSuite),

    /// The [`KeyingMaterialExporter`][] was already consumed.
    ///
    /// Methods that obtain an exporter (eg, [`Connection::exporter()`][]) can only
    /// be used once.  This error is returned on subsequent calls.
    ///
    /// [`KeyingMaterialExporter`]: crate::KeyingMaterialExporter
    /// [`Connection::exporter()`]: crate::Connection::exporter()
    ExporterAlreadyUsed,

    /// The `context` parameter to [`KeyingMaterialExporter::derive()`][] was too long.
    ///
    /// For TLS1.2 connections (only) this parameter is limited to 64KB.
    ///
    /// [`KeyingMaterialExporter::derive()`]: crate::KeyingMaterialExporter::derive()
    ExporterContextTooLong,

    /// The `output` object for [`KeyingMaterialExporter::derive()`][] was too long.
    ///
    /// For TLS1.3 connections this is limited to 255 times the hash output length.
    ///
    /// [`KeyingMaterialExporter::derive()`]: crate::KeyingMaterialExporter::derive()
    ExporterOutputTooLong,

    /// The `output` object to [`KeyingMaterialExporter::derive()`][] was zero length.
    ///
    /// This doesn't make sense, so we explicitly return an error (rather than simply
    /// producing no output as requested.)
    ///
    /// [`KeyingMaterialExporter::derive()`]: crate::KeyingMaterialExporter::derive()
    ExporterOutputZeroLength,

    /// [`Acceptor::accept()`][] called after it yielded a connection.
    ///
    /// [`Acceptor::accept()`]: crate::server::Acceptor::accept()
    AcceptorPolledAfterCompletion,

    /// Incorrect sample length provided to [`quic::HeaderProtectionKey::encrypt_in_place()`][]
    ///
    /// [`quic::HeaderProtectionKey::encrypt_in_place()`]: crate::quic::HeaderProtectionKey::encrypt_in_place()
    InvalidQuicHeaderProtectionSampleLength,

    /// Incorrect relation between sample length and header number length provided to
    /// [`quic::HeaderProtectionKey::encrypt_in_place()`][]
    ///
    /// [`quic::HeaderProtectionKey::encrypt_in_place()`]: crate::quic::HeaderProtectionKey::encrypt_in_place()
    InvalidQuicHeaderProtectionPacketNumberLength,

    /// Raw keys cannot be used with TLS 1.2.
    InvalidSignerForProtocolVersion,

    /// QUIC attempted with a configuration that does not support TLS1.3.
    QuicRequiresTls13Support,

    /// QUIC attempted with a configuration that does not support a ciphersuite that supports QUIC.
    NoQuicCompatibleCipherSuites,

    /// An empty certificate chain was provided.
    EmptyCertificateChain,

    /// QUIC attempted with unsupported [`ServerConfig::max_early_data_size`][]
    ///
    /// This field must be either zero or [`u32::MAX`] for QUIC.
    ///
    /// [`ServerConfig::max_early_data_size`]: crate::server::ServerConfig::max_early_data_size
    QuicRestrictsMaxEarlyDataSize,

    /// A `CryptoProvider` must have at least one cipher suite.
    NoCipherSuitesConfigured,

    /// A `CryptoProvider` must have at least one key exchange group.
    NoKeyExchangeGroupsConfigured,

    /// An empty list of signature verification algorithms was provided.
    NoSignatureVerificationAlgorithms,

    /// ECH attempted with a configuration that does not support TLS1.3.
    EchRequiresTls13Support,

    /// ECH attempted with a configuration that also supports TLS1.2.
    EchForbidsTls12Support,

    /// The received plaintext buffer is full; read out some plaintext before receiving more.
    ReceivedPlaintextBufferFull,

    /// Secret extraction operation attempted without opting-in to secret extraction.
    ///
    /// This is possible from:
    ///
    /// - [`ClientConnection::dangerous_extract_secrets()`][crate::client::ClientConnection::dangerous_extract_secrets]
    /// - [`ServerConnection::dangerous_extract_secrets()`][crate::server::ServerConnection::dangerous_extract_secrets]
    ///
    /// You must set [`ServerConfig::enable_secret_extraction`][crate::server::ServerConfig::enable_secret_extraction] or
    /// [`ClientConfig::enable_secret_extraction`][crate::client::ClientConfig::enable_secret_extraction] to true before calling
    /// these functions.
    SecretExtractionRequiresPriorOptIn,

    /// Secret extraction operation attempted without first extracting all pending
    /// TLS data.
    ///
    /// See [`Self::SecretExtractionRequiresPriorOptIn`] for a list of the affected
    /// functions.  You must ensure any prior generated TLS records are extracted
    /// from the library before using one of these functions.
    SecretExtractionWithPendingSendableData,

    /// Attempt to verify a certificate with an unsupported type.
    ///
    /// A verifier indicated support for a certificate type but then failed to verify the peer's
    /// identity of that type.
    UnverifiableCertificateType,

    /// A verifier or resolver implementation signalled that it does not support any certificate types.
    NoSupportedCertificateTypes,

    /// [`Nonce::to_array()`][] called with incorrect array size.
    ///
    /// The nonce length does not match the requested array size `N`.
    ///
    /// [`Nonce::to_array()`]: crate::crypto::cipher::Nonce::to_array()
    NonceArraySizeMismatch {
        /// The expected array size (type parameter N)
        expected: usize,
        /// The actual nonce length
        actual: usize,
    },

    /// [`Iv::new()`][] called with a value that exceeds the maximum IV length.
    ///
    /// The IV length must not exceed [`Iv::MAX_LEN`][].
    ///
    /// [`Iv::new()`]: crate::crypto::cipher::Iv::new()
    /// [`Iv::MAX_LEN`]: crate::crypto::cipher::Iv::MAX_LEN
    IvLengthExceedsMaximum {
        /// The actual IV length provided
        actual: usize,
        /// The maximum allowed IV length
        maximum: usize,
    },

    /// Calling [`ServerConnection::set_resumption_data()`] must be done before
    /// any resumption is offered.
    ///
    /// [`ServerConnection::set_resumption_data()`]: crate::server::ServerConnection::set_resumption_data()
    ResumptionDataProvidedTooLate,

    /// [`KernelConnection::update_tx_secret()`] and associated are not available for TLS1.2 connections.
    ///
    /// [`KernelConnection::update_tx_secret()`]: crate::conn::kernel::KernelConnection::update_tx_secret()
    KeyUpdateNotAvailableForTls12,
}

impl fmt::Display for ApiMisuse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl core::error::Error for ApiMisuse {}

mod other_error {
    use core::error::Error as StdError;
    use core::fmt;

    use crate::sync::Arc;

    /// Any other error that cannot be expressed by a more specific [`Error`][super::Error]
    /// variant.
    ///
    /// For example, an `OtherError` could be produced by a custom crypto provider
    /// exposing a provider specific error.
    ///
    /// Enums holding this type will never compare equal to each other.
    #[derive(Debug, Clone)]
    pub struct OtherError(Arc<dyn StdError + Send + Sync>);

    impl OtherError {
        /// Create a new `OtherError` from any error type.
        pub fn new(err: impl StdError + Send + Sync + 'static) -> Self {
            Self(Arc::new(err))
        }
    }

    impl PartialEq<Self> for OtherError {
        fn eq(&self, _other: &Self) -> bool {
            false
        }
    }

    impl fmt::Display for OtherError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "{}", self.0)
        }
    }

    impl StdError for OtherError {
        fn source(&self) -> Option<&(dyn StdError + 'static)> {
            Some(self.0.as_ref())
        }
    }
}

pub use other_error::OtherError;
