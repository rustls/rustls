use core::time::Duration;
use std::prelude::v1::*;
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
#[cfg(feature = "std")]
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
        super::ApiMisuse::ExporterAlreadyUsed.into(),
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
fn rand_error_mapping() {
    let err: Error = GetRandomFailed.into();
    assert_eq!(err, Error::FailedToGetRandomBytes);
}

#[cfg(feature = "std")]
#[test]
fn time_error_mapping() {
    use std::time::SystemTime;

    let time_error = SystemTime::UNIX_EPOCH
        .duration_since(SystemTime::now())
        .unwrap_err();
    let err: Error = time_error.into();
    assert_eq!(err, Error::FailedToGetCurrentTime);
}
