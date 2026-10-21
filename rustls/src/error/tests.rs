use alloc::string::ToString;
use core::time::Duration;
use std::{println, vec};

use pki_types::ServerName;

use super::{
    AlertDescription, CertRevocationListError, Error, InconsistentKeys, InvalidMessage, OtherError,
    UnixTime,
};
use crate::crypto::GetRandomFailed;
use crate::msgs::test_enum8_display;

#[test]
fn certificate_error_equality() {
    use super::CertificateError::*;
    assert_eq!(BadEncoding, BadEncoding);
    assert_eq!(Expired, Expired);
    let context = ExpiredContext {
        time: UnixTime::since_unix_epoch(Duration::from_secs(1234)),
        not_after: UnixTime::since_unix_epoch(Duration::from_secs(123)),
    };
    assert_eq!(context, context);
    assert_ne!(
        context,
        ExpiredContext {
            time: UnixTime::since_unix_epoch(Duration::from_secs(12345)),
            not_after: UnixTime::since_unix_epoch(Duration::from_secs(123)),
        }
    );
    assert_ne!(
        context,
        ExpiredContext {
            time: UnixTime::since_unix_epoch(Duration::from_secs(1234)),
            not_after: UnixTime::since_unix_epoch(Duration::from_secs(1234)),
        }
    );
    assert_eq!(NotValidYet, NotValidYet);
    let context = NotValidYetContext {
        time: UnixTime::since_unix_epoch(Duration::from_secs(123)),
        not_before: UnixTime::since_unix_epoch(Duration::from_secs(1234)),
    };
    assert_eq!(context, context);
    assert_ne!(
        context,
        NotValidYetContext {
            time: UnixTime::since_unix_epoch(Duration::from_secs(1234)),
            not_before: UnixTime::since_unix_epoch(Duration::from_secs(1234)),
        }
    );
    assert_ne!(
        context,
        NotValidYetContext {
            time: UnixTime::since_unix_epoch(Duration::from_secs(123)),
            not_before: UnixTime::since_unix_epoch(Duration::from_secs(12345)),
        }
    );
    assert_eq!(Revoked, Revoked);
    assert_eq!(UnhandledCriticalExtension, UnhandledCriticalExtension);
    assert_eq!(UnknownIssuer, UnknownIssuer);
    assert_eq!(IssuerKeyUsageMissingCertSign, IssuerKeyUsageMissingCertSign);
    assert_eq!(ExpiredRevocationList, ExpiredRevocationList);
    assert_eq!(UnknownRevocationStatus, UnknownRevocationStatus);
    let context = ExpiredRevocationListContext {
        time: UnixTime::since_unix_epoch(Duration::from_secs(1234)),
        next_update: UnixTime::since_unix_epoch(Duration::from_secs(123)),
    };
    assert_eq!(context, context);
    assert_ne!(
        context,
        ExpiredRevocationListContext {
            time: UnixTime::since_unix_epoch(Duration::from_secs(12345)),
            next_update: UnixTime::since_unix_epoch(Duration::from_secs(123)),
        }
    );
    assert_ne!(
        context,
        ExpiredRevocationListContext {
            time: UnixTime::since_unix_epoch(Duration::from_secs(1234)),
            next_update: UnixTime::since_unix_epoch(Duration::from_secs(1234)),
        }
    );
    assert_eq!(BadSignature, BadSignature);
    assert_eq!(
        KeyUsageMissingDigitalSignature,
        KeyUsageMissingDigitalSignature
    );
    assert_eq!(
        UnsupportedSignatureAlgorithm {
            signature_algorithm_id: vec![1, 2, 3],
            supported_algorithms: vec![]
        },
        UnsupportedSignatureAlgorithm {
            signature_algorithm_id: vec![1, 2, 3],
            supported_algorithms: vec![]
        }
    );
    assert_eq!(
        UnsupportedSignatureAlgorithmForPublicKey {
            signature_algorithm_id: vec![1, 2, 3],
            public_key_algorithm_id: vec![4, 5, 6]
        },
        UnsupportedSignatureAlgorithmForPublicKey {
            signature_algorithm_id: vec![1, 2, 3],
            public_key_algorithm_id: vec![4, 5, 6]
        }
    );
    assert_eq!(NotValidForName, NotValidForName);
    let context = NotValidForNameContext {
        expected: ServerName::try_from("example.com")
            .unwrap()
            .to_owned(),
        presented: vec!["other.com".into()],
    };
    assert_eq!(context, context);
    assert_ne!(
        context,
        NotValidForNameContext {
            expected: ServerName::try_from("example.com")
                .unwrap()
                .to_owned(),
            presented: vec![]
        }
    );
    assert_ne!(
        context,
        NotValidForNameContext {
            expected: ServerName::try_from("huh.com")
                .unwrap()
                .to_owned(),
            presented: vec!["other.com".into()],
        }
    );
    assert_eq!(InvalidPurpose, InvalidPurpose);
    assert_eq!(
        ApplicationVerificationFailure,
        ApplicationVerificationFailure
    );
    assert_eq!(InvalidOcspResponse, InvalidOcspResponse);
    let other = Other(OtherError::new(TestError));
    assert_ne!(other, other);
    assert_ne!(BadEncoding, Expired);
}

#[test]
fn crl_error_equality() {
    use super::CertRevocationListError::*;
    assert_eq!(BadSignature, BadSignature);
    assert_eq!(
        UnsupportedSignatureAlgorithm {
            signature_algorithm_id: vec![1, 2, 3],
            supported_algorithms: vec![]
        },
        UnsupportedSignatureAlgorithm {
            signature_algorithm_id: vec![1, 2, 3],
            supported_algorithms: vec![]
        }
    );
    assert_eq!(
        UnsupportedSignatureAlgorithmForPublicKey {
            signature_algorithm_id: vec![1, 2, 3],
            public_key_algorithm_id: vec![4, 5, 6]
        },
        UnsupportedSignatureAlgorithmForPublicKey {
            signature_algorithm_id: vec![1, 2, 3],
            public_key_algorithm_id: vec![4, 5, 6]
        }
    );
    assert_eq!(InvalidCrlNumber, InvalidCrlNumber);
    assert_eq!(
        InvalidRevokedCertSerialNumber,
        InvalidRevokedCertSerialNumber
    );
    assert_eq!(IssuerInvalidForCrl, IssuerInvalidForCrl);
    assert_eq!(ParseError, ParseError);
    assert_eq!(UnsupportedCriticalExtension, UnsupportedCriticalExtension);
    assert_eq!(UnsupportedCrlVersion, UnsupportedCrlVersion);
    assert_eq!(UnsupportedDeltaCrl, UnsupportedDeltaCrl);
    assert_eq!(UnsupportedIndirectCrl, UnsupportedIndirectCrl);
    assert_eq!(UnsupportedRevocationReason, UnsupportedRevocationReason);
    let other = Other(OtherError::new(TestError));
    assert_ne!(other, other);
    assert_ne!(BadSignature, InvalidCrlNumber);
}

#[test]
fn other_error_equality() {
    let other_error = OtherError::new(TestError);
    assert_ne!(other_error, other_error);
    let other: Error = other_error.into();
    assert_ne!(other, other);
}

#[test]
fn smoke() {
    use crate::enums::{ContentType, HandshakeType};

    let all = vec![
        Error::InappropriateMessage {
            expect_types: vec![ContentType::Alert],
            got_type: ContentType::Handshake,
        },
        Error::InappropriateHandshakeMessage {
            expect_types: vec![HandshakeType::ClientHello, HandshakeType::Finished],
            got_type: HandshakeType::ServerHello,
        },
        Error::InvalidMessage(InvalidMessage::InvalidCcs),
        Error::DecryptError,
        super::PeerIncompatible::Tls12NotOffered.into(),
        super::PeerMisbehaved::UnsolicitedCertExtension.into(),
        Error::AlertReceived(AlertDescription::ExportRestriction),
        super::CertificateError::Expired.into(),
        super::CertificateError::NotValidForNameContext {
            expected: ServerName::try_from("example.com")
                .unwrap()
                .to_owned(),
            presented: vec![],
        }
        .into(),
        super::CertificateError::NotValidForNameContext {
            expected: ServerName::try_from("example.com")
                .unwrap()
                .to_owned(),
            presented: vec!["DnsName(\"hello.com\")".into()],
        }
        .into(),
        super::CertificateError::NotValidForNameContext {
            expected: ServerName::try_from("example.com")
                .unwrap()
                .to_owned(),
            presented: vec![
                "DnsName(\"hello.com\")".into(),
                "DnsName(\"goodbye.com\")".into(),
            ],
        }
        .into(),
        super::CertificateError::NotValidYetContext {
            time: UnixTime::since_unix_epoch(Duration::from_secs(300)),
            not_before: UnixTime::since_unix_epoch(Duration::from_secs(320)),
        }
        .into(),
        super::CertificateError::ExpiredContext {
            time: UnixTime::since_unix_epoch(Duration::from_secs(320)),
            not_after: UnixTime::since_unix_epoch(Duration::from_secs(300)),
        }
        .into(),
        super::CertificateError::ExpiredRevocationListContext {
            time: UnixTime::since_unix_epoch(Duration::from_secs(320)),
            next_update: UnixTime::since_unix_epoch(Duration::from_secs(300)),
        }
        .into(),
        super::CertificateError::InvalidOcspResponse.into(),
        Error::General("undocumented error".to_string()),
        Error::FailedToGetCurrentTime,
        Error::FailedToGetRandomBytes,
        Error::HandshakeNotComplete,
        Error::PeerSentOversizedRecord,
        Error::NoApplicationProtocol,
        Error::BadMaxFragmentSize,
        Error::InconsistentKeys(InconsistentKeys::KeyMismatch),
        Error::InconsistentKeys(InconsistentKeys::Unknown),
        Error::InvalidCertRevocationList(CertRevocationListError::BadSignature),
        Error::Unreachable("smoke"),
        super::ApiMisuse::ExporterNotAvailable.into(),
        Error::Other(OtherError::new(TestError)),
    ];

    for err in all {
        println!("{err:?}:");
        println!("  fmt '{err}'");
    }
}

#[derive(Debug)]
struct TestError;

impl core::fmt::Display for TestError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "test error")
    }
}

impl core::error::Error for TestError {}

#[test]
fn alert_description_traits() {
    test_enum8_display::<AlertDescription>(
        AlertDescription::CloseNotify,
        AlertDescription::EncryptedClientHelloRequired,
    );
}

#[test]
fn alert_display() {
    println!("Review the following error messages for syntax and grammar errors:");
    for u in 0..=u8::MAX {
        let err = Error::AlertReceived(AlertDescription::from(u));
        println!(" - {err}");
    }

    // pipe the output of this test to `llm` for a quick check of these...
}

#[test]
fn alert_mapping() {
    use super::{
        ApiMisuse, CertificateError, EncryptedClientHelloError, ExtendedKeyPurpose,
        PeerIncompatible, PeerMisbehaved, RejectedEch,
    };
    use crate::enums::{ContentType, HandshakeType};

    let time = UnixTime::since_unix_epoch(Duration::from_secs(1));
    let cases: vec::Vec<(Error, Result<AlertDescription, ()>)> = vec![
        (Error::DecryptError, Ok(AlertDescription::BadRecordMac)),
        (
            Error::InappropriateMessage {
                expect_types: vec![ContentType::Alert],
                got_type: ContentType::Handshake,
            },
            Ok(AlertDescription::UnexpectedMessage),
        ),
        (
            Error::InappropriateHandshakeMessage {
                expect_types: vec![HandshakeType::ClientHello],
                got_type: HandshakeType::ServerHello,
            },
            Ok(AlertDescription::UnexpectedMessage),
        ),
        (
            Error::NoApplicationProtocol,
            Ok(AlertDescription::NoApplicationProtocol),
        ),
        (
            Error::PeerSentOversizedRecord,
            Ok(AlertDescription::RecordOverflow),
        ),
        (
            Error::RejectedEch(RejectedEch {
                retry_configs: None,
            }),
            Ok(AlertDescription::EncryptedClientHelloRequired),
        ),
        (
            Error::General("general".to_string()),
            Ok(AlertDescription::GeneralError),
        ),
        (Error::EncryptError, Err(())),
        (Error::HandshakeNotComplete, Err(())),
        (Error::FailedToGetCurrentTime, Err(())),
        (Error::FailedToGetRandomBytes, Err(())),
        (Error::NoSuitableCertificate, Err(())),
        (Error::UnsupportedNameType, Err(())),
        (Error::BadMaxFragmentSize, Err(())),
        (
            Error::InvalidEncryptedClientHello(EncryptedClientHelloError::SniRequired),
            Err(()),
        ),
        (
            Error::InconsistentKeys(InconsistentKeys::KeyMismatch),
            Err(()),
        ),
        (
            Error::InvalidCertRevocationList(CertRevocationListError::BadSignature),
            Err(()),
        ),
        (Error::AlertReceived(AlertDescription::UnknownCa), Err(())),
        (ApiMisuse::ExporterNotAvailable.into(), Err(())),
        (Error::Unreachable("unreachable"), Err(())),
        (Error::Other(OtherError::new(TestError)), Err(())),
        (
            CertificateError::BadEncoding.into(),
            Ok(AlertDescription::BadCertificate),
        ),
        (
            CertificateError::UnhandledCriticalExtension.into(),
            Ok(AlertDescription::BadCertificate),
        ),
        (
            CertificateError::NotValidForName.into(),
            Ok(AlertDescription::BadCertificate),
        ),
        (
            CertificateError::NotValidForNameContext {
                expected: ServerName::try_from("example.com")
                    .unwrap()
                    .to_owned(),
                presented: vec![],
            }
            .into(),
            Ok(AlertDescription::BadCertificate),
        ),
        (
            CertificateError::Expired.into(),
            Ok(AlertDescription::CertificateExpired),
        ),
        (
            CertificateError::ExpiredContext {
                time,
                not_after: time,
            }
            .into(),
            Ok(AlertDescription::CertificateExpired),
        ),
        (
            CertificateError::NotValidYet.into(),
            Ok(AlertDescription::CertificateExpired),
        ),
        (
            CertificateError::NotValidYetContext {
                time,
                not_before: time,
            }
            .into(),
            Ok(AlertDescription::CertificateExpired),
        ),
        (
            CertificateError::Revoked.into(),
            Ok(AlertDescription::CertificateRevoked),
        ),
        (
            CertificateError::UnknownIssuer.into(),
            Ok(AlertDescription::UnknownCa),
        ),
        (
            CertificateError::IssuerKeyUsageMissingCertSign.into(),
            Ok(AlertDescription::UnknownCa),
        ),
        (
            CertificateError::UnknownRevocationStatus.into(),
            Ok(AlertDescription::UnknownCa),
        ),
        (
            CertificateError::ExpiredRevocationList.into(),
            Ok(AlertDescription::UnknownCa),
        ),
        (
            CertificateError::ExpiredRevocationListContext {
                time,
                next_update: time,
            }
            .into(),
            Ok(AlertDescription::UnknownCa),
        ),
        (
            CertificateError::InvalidOcspResponse.into(),
            Ok(AlertDescription::BadCertificateStatusResponse),
        ),
        (
            CertificateError::BadSignature.into(),
            Ok(AlertDescription::DecryptError),
        ),
        (
            CertificateError::UnsupportedSignatureAlgorithm {
                signature_algorithm_id: vec![],
                supported_algorithms: vec![],
            }
            .into(),
            Ok(AlertDescription::DecryptError),
        ),
        (
            CertificateError::UnsupportedSignatureAlgorithmForPublicKey {
                signature_algorithm_id: vec![],
                public_key_algorithm_id: vec![],
            }
            .into(),
            Ok(AlertDescription::DecryptError),
        ),
        (
            CertificateError::InvalidPurpose.into(),
            Ok(AlertDescription::UnsupportedCertificate),
        ),
        (
            CertificateError::InvalidPurposeContext {
                required: ExtendedKeyPurpose::ServerAuth,
                presented: vec![],
            }
            .into(),
            Ok(AlertDescription::UnsupportedCertificate),
        ),
        (
            CertificateError::KeyUsageMissingDigitalSignature.into(),
            Ok(AlertDescription::UnsupportedCertificate),
        ),
        (
            CertificateError::ApplicationVerificationFailure.into(),
            Ok(AlertDescription::AccessDenied),
        ),
        (
            CertificateError::Other(OtherError::new(TestError)).into(),
            Ok(AlertDescription::CertificateUnknown),
        ),
        (
            InvalidMessage::PreSharedKeyIsNotFinalExtension.into(),
            Ok(AlertDescription::IllegalParameter),
        ),
        (
            InvalidMessage::DuplicateExtension(0).into(),
            Ok(AlertDescription::IllegalParameter),
        ),
        (
            InvalidMessage::MisplacedExtension(0).into(),
            Ok(AlertDescription::IllegalParameter),
        ),
        (
            InvalidMessage::UnsupportedCompression.into(),
            Ok(AlertDescription::IllegalParameter),
        ),
        (
            InvalidMessage::UnknownHelloRetryRequestExtension.into(),
            Ok(AlertDescription::UnsupportedExtension),
        ),
        (
            InvalidMessage::CertificatePayloadTooLarge.into(),
            Ok(AlertDescription::BadCertificate),
        ),
        (
            InvalidMessage::InvalidCcs.into(),
            Ok(AlertDescription::DecodeError),
        ),
        (
            PeerMisbehaved::DisallowedEncryptedExtension.into(),
            Ok(AlertDescription::UnsupportedExtension),
        ),
        (
            PeerMisbehaved::IllegalHelloRetryRequestWithInvalidEch.into(),
            Ok(AlertDescription::UnsupportedExtension),
        ),
        (
            PeerMisbehaved::UnexpectedCleartextExtension.into(),
            Ok(AlertDescription::UnsupportedExtension),
        ),
        (
            PeerMisbehaved::UnsolicitedEchExtension.into(),
            Ok(AlertDescription::UnsupportedExtension),
        ),
        (
            PeerMisbehaved::UnsolicitedEncryptedExtension.into(),
            Ok(AlertDescription::UnsupportedExtension),
        ),
        (
            PeerMisbehaved::UnsolicitedServerHelloExtension.into(),
            Ok(AlertDescription::UnsupportedExtension),
        ),
        (
            PeerMisbehaved::IllegalMiddleboxChangeCipherSpec.into(),
            Ok(AlertDescription::UnexpectedMessage),
        ),
        (
            PeerMisbehaved::KeyEpochWithPendingFragment.into(),
            Ok(AlertDescription::UnexpectedMessage),
        ),
        (
            PeerMisbehaved::KeyUpdateReceivedInQuicConnection.into(),
            Ok(AlertDescription::UnexpectedMessage),
        ),
        (
            PeerMisbehaved::IllegalTls13ContentType.into(),
            Ok(AlertDescription::UnexpectedMessage),
        ),
        (
            PeerMisbehaved::IllegalWarningAlert(AlertDescription::UnknownCa).into(),
            Ok(AlertDescription::DecodeError),
        ),
        (
            PeerMisbehaved::IncorrectBinder.into(),
            Ok(AlertDescription::DecryptError),
        ),
        (
            PeerMisbehaved::IncorrectFinished.into(),
            Ok(AlertDescription::DecryptError),
        ),
        (
            PeerMisbehaved::InvalidCertCompression.into(),
            Ok(AlertDescription::BadCertificate),
        ),
        (
            PeerMisbehaved::SelectedUnofferedCertCompression.into(),
            Ok(AlertDescription::BadCertificate),
        ),
        (
            PeerMisbehaved::MissingKeyShare.into(),
            Ok(AlertDescription::MissingExtension),
        ),
        (
            PeerMisbehaved::MissingPskExtensionInSecondClientHello.into(),
            Ok(AlertDescription::MissingExtension),
        ),
        (
            PeerMisbehaved::MissingPskModesExtension.into(),
            Ok(AlertDescription::MissingExtension),
        ),
        (
            PeerMisbehaved::MissingQuicTransportParameters.into(),
            Ok(AlertDescription::MissingExtension),
        ),
        (
            PeerMisbehaved::NoCertificatesPresented.into(),
            Ok(AlertDescription::CertificateRequired),
        ),
        (
            PeerMisbehaved::NonEmptyRenegotiationInfo.into(),
            Ok(AlertDescription::HandshakeFailure),
        ),
        (
            PeerMisbehaved::EmptyFragment.into(),
            Ok(AlertDescription::IllegalParameter),
        ),
        (
            PeerIncompatible::NullCompressionRequired.into(),
            Ok(AlertDescription::IllegalParameter),
        ),
        (
            PeerIncompatible::ServerTlsVersionIsDisabledByOurConfig.into(),
            Ok(AlertDescription::ProtocolVersion),
        ),
        (
            PeerIncompatible::SupportedVersionsExtensionRequired.into(),
            Ok(AlertDescription::ProtocolVersion),
        ),
        (
            PeerIncompatible::Tls12NotOffered.into(),
            Ok(AlertDescription::ProtocolVersion),
        ),
        (
            PeerIncompatible::Tls12NotOfferedOrEnabled.into(),
            Ok(AlertDescription::ProtocolVersion),
        ),
        (
            PeerIncompatible::Tls13RequiredForQuic.into(),
            Ok(AlertDescription::ProtocolVersion),
        ),
        (
            PeerIncompatible::KeyShareExtensionRequired.into(),
            Ok(AlertDescription::MissingExtension),
        ),
        (
            PeerIncompatible::UnknownCertificateType(0).into(),
            Ok(AlertDescription::UnsupportedCertificate),
        ),
        (
            PeerIncompatible::NoCipherSuitesInCommon.into(),
            Ok(AlertDescription::HandshakeFailure),
        ),
    ];

    for (err, expected) in cases {
        assert_eq!(AlertDescription::try_from(&err), expected, "{err:?}");
    }
}

#[test]
fn rand_error_mapping() {
    let err: Error = GetRandomFailed.into();
    assert_eq!(err, Error::FailedToGetRandomBytes);
}

#[test]
fn time_error_mapping() {
    use std::time::SystemTime;

    let time_error = SystemTime::UNIX_EPOCH
        .duration_since(SystemTime::now())
        .unwrap_err();
    let err: Error = time_error.into();
    assert_eq!(err, Error::FailedToGetCurrentTime);
}
