use alloc::sync::Arc;
use std::prelude::v1::*;
use std::{format, println, vec};

use pki_types::{CertificateDer, DnsName};

use super::base::{Payload, PayloadU16, PayloadU24, PayloadU8};
use super::codec::{put_u16, Codec, Reader};
use super::enums::{
    CertificateType, ClientCertificateType, Compression, ECCurveType, ECPointFormat, ExtensionType,
    KeyUpdateRequest, NamedGroup, PSKKeyExchangeMode, ServerNameType,
};
use super::handshake::{
    CertReqExtension, CertificateChain, CertificateEntry, CertificateExtension,
    CertificatePayloadTls13, CertificateRequestPayload, CertificateRequestPayloadTls13,
    CertificateStatus, CertificateStatusRequest, ClientExtension, ClientHelloPayload,
    ClientSessionTicket, CompressedCertificatePayload, ConvertProtocolNameList,
    ConvertServerNameList, DistinguishedName, EcParameters, HandshakeMessagePayload,
    HandshakePayload, HasServerExtensions, HelloRetryExtension, HelloRetryRequest, KeyShareEntry,
    NewSessionTicketExtension, NewSessionTicketPayload, NewSessionTicketPayloadTls13,
    PresharedKeyBinder, PresharedKeyIdentity, PresharedKeyOffer, ProtocolName, Random,
    ServerDhParams, ServerEcdhParams, ServerExtension, ServerHelloPayload, ServerKeyExchange,
    ServerKeyExchangeParams, ServerKeyExchangePayload, SessionId, UnknownExtension,
};
use crate::enums::{
    CertificateCompressionAlgorithm, CipherSuite, HandshakeType, ProtocolVersion, SignatureScheme,
};
use crate::error::InvalidMessage;
use crate::verify::DigitallySignedStruct;

#[test]
fn rejects_short_random() {
    let bytes = [0x01; 31];
    let mut rd = Reader::init(&bytes);
    assert!(Random::read(&mut rd).is_err());
}

#[test]
fn reads_random() {
    let bytes = [0x01; 32];
    let mut rd = Reader::init(&bytes);
    let rnd = Random::read(&mut rd).unwrap();
    println!("{:?}", rnd);

    assert!(!rd.any_left());
}

#[test]
fn debug_random() {
    assert_eq!(
        "0101010101010101010101010101010101010101010101010101010101010101",
        format!("{:?}", Random::from([1; 32]))
    );
}

#[test]
fn rejects_truncated_session_id() {
    let bytes = [32; 32];
    let mut rd = Reader::init(&bytes);
    assert!(SessionId::read(&mut rd).is_err());
}

#[test]
fn rejects_session_id_with_bad_length() {
    let bytes = [33; 33];
    let mut rd = Reader::init(&bytes);
    assert!(SessionId::read(&mut rd).is_err());
}

#[test]
fn session_id_with_different_lengths_are_unequal() {
    let a = SessionId::read(&mut Reader::init(&[1u8, 1])).unwrap();
    let b = SessionId::read(&mut Reader::init(&[2u8, 1, 2])).unwrap();
    assert_ne!(a, b);
}

#[test]
fn accepts_short_session_id() {
    let bytes = [1; 2];
    let mut rd = Reader::init(&bytes);
    let sess = SessionId::read(&mut rd).unwrap();
    println!("{:?}", sess);

    #[cfg(feature = "tls12")]
    assert!(!sess.is_empty());
    assert_ne!(sess, SessionId::empty());
    assert!(!rd.any_left());
}

#[test]
fn accepts_empty_session_id() {
    let bytes = [0; 1];
    let mut rd = Reader::init(&bytes);
    let sess = SessionId::read(&mut rd).unwrap();
    println!("{:?}", sess);

    #[cfg(feature = "tls12")]
    assert!(sess.is_empty());
    assert_eq!(sess, SessionId::empty());
    assert!(!rd.any_left());
}

#[test]
fn debug_session_id() {
    let bytes = [
        32, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
        1, 1, 1,
    ];
    let mut rd = Reader::init(&bytes);
    let sess = SessionId::read(&mut rd).unwrap();
    assert_eq!(
        "0101010101010101010101010101010101010101010101010101010101010101",
        format!("{:?}", sess)
    );
}

#[test]
fn can_round_trip_unknown_client_ext() {
    let bytes = [0x12u8, 0x34u8, 0, 3, 1, 2, 3];
    let mut rd = Reader::init(&bytes);
    let ext = ClientExtension::read(&mut rd).unwrap();

    println!("{:?}", ext);
    assert_eq!(ext.ext_type(), ExtensionType::Unknown(0x1234));
    assert_eq!(bytes.to_vec(), ext.get_encoding());
}

#[test]
fn refuses_client_ext_with_unparsed_bytes() {
    let bytes = [0x00u8, 0x0b, 0x00, 0x04, 0x02, 0xf8, 0x01, 0x02];
    let mut rd = Reader::init(&bytes);
    assert!(ClientExtension::read(&mut rd).is_err());
}

#[test]
fn refuses_server_ext_with_unparsed_bytes() {
    let bytes = [0x00u8, 0x0b, 0x00, 0x04, 0x02, 0xf8, 0x01, 0x02];
    let mut rd = Reader::init(&bytes);
    assert!(ServerExtension::read(&mut rd).is_err());
}

#[test]
fn refuses_certificate_ext_with_unparsed_bytes() {
    let bytes = [0x00u8, 0x05, 0x00, 0x03, 0x00, 0x00, 0x01];
    let mut rd = Reader::init(&bytes);
    assert!(CertificateExtension::read(&mut rd).is_err());
}

#[test]
fn refuses_certificate_req_ext_with_unparsed_bytes() {
    let bytes = [0x00u8, 0x0d, 0x00, 0x05, 0x00, 0x02, 0x01, 0x02, 0xff];
    let mut rd = Reader::init(&bytes);
    assert!(CertReqExtension::read(&mut rd).is_err());
}

#[test]
fn refuses_helloreq_ext_with_unparsed_bytes() {
    let bytes = [0x00u8, 0x2b, 0x00, 0x03, 0x00, 0x00, 0x01];
    let mut rd = Reader::init(&bytes);
    assert!(HelloRetryExtension::read(&mut rd).is_err());
}

#[test]
fn refuses_new_session_ticket_ext_with_unparsed_bytes() {
    let bytes = [0x00u8, 0x2a, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x01];
    let mut rd = Reader::init(&bytes);
    assert!(NewSessionTicketExtension::read(&mut rd).is_err());
}

#[test]
fn can_round_trip_single_sni() {
    let bytes = [0, 0, 0, 7, 0, 5, 0, 0, 2, 0x6c, 0x6f];
    let mut rd = Reader::init(&bytes);
    let ext = ClientExtension::read(&mut rd).unwrap();
    println!("{:?}", ext);

    assert_eq!(ext.ext_type(), ExtensionType::ServerName);
    assert_eq!(bytes.to_vec(), ext.get_encoding());
}

#[test]
fn can_round_trip_mixed_case_sni() {
    let bytes = [0, 0, 0, 7, 0, 5, 0, 0, 2, 0x4c, 0x6f];
    let mut rd = Reader::init(&bytes);
    let ext = ClientExtension::read(&mut rd).unwrap();
    println!("{:?}", ext);

    assert_eq!(ext.ext_type(), ExtensionType::ServerName);
    assert_eq!(bytes.to_vec(), ext.get_encoding());
}

#[test]
fn can_round_trip_other_sni_name_types() {
    let bytes = [0, 0, 0, 7, 0, 5, 1, 0, 2, 0x6c, 0x6f];
    let mut rd = Reader::init(&bytes);
    let ext = ClientExtension::read(&mut rd).unwrap();
    println!("{:?}", ext);

    assert_eq!(ext.ext_type(), ExtensionType::ServerName);
    assert_eq!(bytes.to_vec(), ext.get_encoding());
}

#[test]
fn single_hostname_returns_none_for_other_sni_name_types() {
    let bytes = [0, 0, 0, 7, 0, 5, 1, 0, 2, 0x6c, 0x6f];
    let mut rd = Reader::init(&bytes);
    let ext = ClientExtension::read(&mut rd).unwrap();
    println!("{:?}", ext);

    assert_eq!(ext.ext_type(), ExtensionType::ServerName);
    if let ClientExtension::ServerName(snr) = ext {
        assert!(!snr.has_duplicate_names_for_type());
        assert!(snr.single_hostname().is_none());
    } else {
        unreachable!();
    }
}

#[test]
fn can_round_trip_multi_name_sni() {
    let bytes = [0, 0, 0, 12, 0, 10, 0, 0, 2, 0x68, 0x69, 0, 0, 2, 0x6c, 0x6f];
    let mut rd = Reader::init(&bytes);
    let ext = ClientExtension::read(&mut rd).unwrap();
    println!("{:?}", ext);

    assert_eq!(ext.ext_type(), ExtensionType::ServerName);
    assert_eq!(bytes.to_vec(), ext.get_encoding());
    match ext {
        ClientExtension::ServerName(req) => {
            assert_eq!(2, req.len());

            assert!(req.has_duplicate_names_for_type());

            let dns_name = req.single_hostname().unwrap();
            assert_eq!(dns_name.as_ref(), "hi");

            assert_eq!(req[0].typ, ServerNameType::HostName);
            assert_eq!(req[1].typ, ServerNameType::HostName);
        }
        _ => unreachable!(),
    }
}

#[test]
fn rejects_truncated_sni() {
    let bytes = [0, 0, 0, 1, 0];
    assert!(ClientExtension::read(&mut Reader::init(&bytes)).is_err());

    let bytes = [0, 0, 0, 2, 0, 1];
    assert!(ClientExtension::read(&mut Reader::init(&bytes)).is_err());

    let bytes = [0, 0, 0, 3, 0, 1, 0];
    assert!(ClientExtension::read(&mut Reader::init(&bytes)).is_err());

    let bytes = [0, 0, 0, 4, 0, 2, 0, 0];
    assert!(ClientExtension::read(&mut Reader::init(&bytes)).is_err());

    let bytes = [0, 0, 0, 5, 0, 3, 0, 0, 0];
    assert!(ClientExtension::read(&mut Reader::init(&bytes)).is_err());

    let bytes = [0, 0, 0, 5, 0, 3, 0, 0, 1];
    assert!(ClientExtension::read(&mut Reader::init(&bytes)).is_err());

    let bytes = [0, 0, 0, 6, 0, 4, 0, 0, 2, 0x68];
    assert!(ClientExtension::read(&mut Reader::init(&bytes)).is_err());
}

#[test]
fn can_round_trip_psk_identity() {
    let bytes = [0, 0, 0x11, 0x22, 0x33, 0x44];
    let psk_id = PresharedKeyIdentity::read(&mut Reader::init(&bytes)).unwrap();
    println!("{:?}", psk_id);
    assert_eq!(psk_id.obfuscated_ticket_age, 0x11223344);
    assert_eq!(psk_id.get_encoding(), bytes.to_vec());

    let bytes = [0, 5, 0x1, 0x2, 0x3, 0x4, 0x5, 0x11, 0x22, 0x33, 0x44];
    let psk_id = PresharedKeyIdentity::read(&mut Reader::init(&bytes)).unwrap();
    println!("{:?}", psk_id);
    assert_eq!(psk_id.identity.0, vec![0x1, 0x2, 0x3, 0x4, 0x5]);
    assert_eq!(psk_id.obfuscated_ticket_age, 0x11223344);
    assert_eq!(psk_id.get_encoding(), bytes.to_vec());
}

#[test]
fn can_round_trip_psk_offer() {
    let bytes = [
        0, 7, 0, 1, 0x99, 0x11, 0x22, 0x33, 0x44, 0, 4, 3, 0x01, 0x02, 0x3,
    ];
    let psko = PresharedKeyOffer::read(&mut Reader::init(&bytes)).unwrap();
    println!("{:?}", psko);

    assert_eq!(psko.identities.len(), 1);
    assert_eq!(psko.identities[0].identity.0, vec![0x99]);
    assert_eq!(psko.identities[0].obfuscated_ticket_age, 0x11223344);
    assert_eq!(psko.binders.len(), 1);
    assert_eq!(psko.binders[0].as_ref(), &[1, 2, 3]);
    assert_eq!(psko.get_encoding(), bytes.to_vec());
}

#[test]
fn can_round_trip_cert_status_req_for_ocsp() {
    let ext = ClientExtension::CertificateStatusRequest(CertificateStatusRequest::build_ocsp());
    println!("{:?}", ext);

    let bytes = [
        0, 5, // CertificateStatusRequest
        0, 11, 1, // OCSP
        0, 5, 0, 3, 0, 1, 1, 0, 1, 2,
    ];

    let csr = ClientExtension::read(&mut Reader::init(&bytes)).unwrap();
    println!("{:?}", csr);
    assert_eq!(csr.get_encoding(), bytes.to_vec());
}

#[test]
fn can_round_trip_cert_status_req_for_other() {
    let bytes = [
        0, 5, // CertificateStatusRequest
        0, 5, 2, // !OCSP
        1, 2, 3, 4,
    ];

    let csr = ClientExtension::read(&mut Reader::init(&bytes)).unwrap();
    println!("{:?}", csr);
    assert_eq!(csr.get_encoding(), bytes.to_vec());
}

#[test]
fn can_round_trip_multi_proto() {
    let bytes = [0, 16, 0, 8, 0, 6, 2, 0x68, 0x69, 2, 0x6c, 0x6f];
    let mut rd = Reader::init(&bytes);
    let ext = ClientExtension::read(&mut rd).unwrap();
    println!("{:?}", ext);

    assert_eq!(ext.ext_type(), ExtensionType::ALProtocolNegotiation);
    assert_eq!(ext.get_encoding(), bytes.to_vec());
    match ext {
        ClientExtension::Protocols(prot) => {
            assert_eq!(2, prot.len());
            assert_eq!(vec![b"hi", b"lo"], prot.to_slices());
            assert_eq!(prot.as_single_slice(), None);
        }
        _ => unreachable!(),
    }
}

#[test]
fn can_round_trip_single_proto() {
    let bytes = [0, 16, 0, 5, 0, 3, 2, 0x68, 0x69];
    let mut rd = Reader::init(&bytes);
    let ext = ClientExtension::read(&mut rd).unwrap();
    println!("{:?}", ext);

    assert_eq!(ext.ext_type(), ExtensionType::ALProtocolNegotiation);
    assert_eq!(bytes.to_vec(), ext.get_encoding());
    match ext {
        ClientExtension::Protocols(prot) => {
            assert_eq!(1, prot.len());
            assert_eq!(vec![b"hi"], prot.to_slices());
            assert_eq!(prot.as_single_slice(), Some(&b"hi"[..]));
        }
        _ => unreachable!(),
    }
}

#[test]
fn can_print_all_client_extensions() {
    println!("client hello {:?}", sample_client_hello_payload());
}

#[test]
fn can_clone_all_client_extensions() {
    let exts = sample_client_hello_payload().extensions;
    let exts2 = exts.clone();
    println!("{exts:?}, {exts2:?}");
}

#[test]
fn client_has_duplicate_extensions_works() {
    let mut chp = sample_client_hello_payload();
    assert!(chp.has_duplicate_extension()); // due to SessionTicketRequest/SessionTicketOffer

    chp.extensions.drain(1..);
    assert!(!chp.has_duplicate_extension());

    chp.extensions = vec![];
    assert!(!chp.has_duplicate_extension());
}

#[test]
fn test_truncated_psk_offer() {
    let ext = ClientExtension::PresharedKey(PresharedKeyOffer {
        identities: vec![PresharedKeyIdentity::new(vec![3, 4, 5], 123456)],
        binders: vec![PresharedKeyBinder::from(vec![1, 2, 3])],
    });

    let mut enc = ext.get_encoding();
    println!("testing {:?} enc {:?}", ext, enc);
    for l in 0..enc.len() {
        if l == 9 {
            continue;
        }
        put_u16(l as u16, &mut enc[4..]);
        let rc = ClientExtension::read_bytes(&enc);
        assert!(rc.is_err());
    }
}

#[test]
fn test_truncated_client_hello_is_detected() {
    let ch = sample_client_hello_payload();
    let enc = ch.get_encoding();
    println!("testing {:?} enc {:?}", ch, enc);

    for l in 0..enc.len() {
        println!("len {:?} enc {:?}", l, &enc[..l]);
        if l == 41 {
            continue; // where extensions are empty
        }
        assert!(ClientHelloPayload::read_bytes(&enc[..l]).is_err());
    }
}

#[test]
fn test_truncated_client_extension_is_detected() {
    let chp = sample_client_hello_payload();

    for ext in &chp.extensions {
        let mut enc = ext.get_encoding();
        println!("testing {:?} enc {:?}", ext, enc);

        // "outer" truncation, i.e., where the extension-level length is longer than
        // the input
        for l in 0..enc.len() {
            assert!(ClientExtension::read_bytes(&enc[..l]).is_err());
        }

        // these extension types don't have any internal encoding that rustls validates:
        match ext.ext_type() {
            ExtensionType::TransportParameters | ExtensionType::Unknown(_) => {
                continue;
            }
            _ => {}
        };

        // "inner" truncation, where the extension-level length agrees with the input
        // length, but isn't long enough for the type of extension
        for l in 0..(enc.len() - 4) {
            put_u16(l as u16, &mut enc[2..]);
            println!("  encoding {:?} len {:?}", enc, l);
            assert!(ClientExtension::read_bytes(&enc).is_err());
        }
    }
}

#[test]
fn client_sni_extension() {
    test_client_extension_getter(ExtensionType::ServerName, |chp| {
        chp.sni_extension().is_some()
    });
}

#[test]
fn client_sigalgs_extension() {
    test_client_extension_getter(ExtensionType::SignatureAlgorithms, |chp| {
        chp.sigalgs_extension().is_some()
    });
}

#[test]
fn client_namedgroups_extension() {
    test_client_extension_getter(ExtensionType::EllipticCurves, |chp| {
        chp.namedgroups_extension().is_some()
    });
}

#[cfg(feature = "tls12")]
#[test]
fn client_ecpoints_extension() {
    test_client_extension_getter(ExtensionType::ECPointFormats, |chp| {
        chp.ecpoints_extension().is_some()
    });
}

#[test]
fn client_alpn_extension() {
    test_client_extension_getter(ExtensionType::ALProtocolNegotiation, |chp| {
        chp.alpn_extension().is_some()
    });
}

#[test]
fn client_client_certificate_extension() {
    test_client_extension_getter(ExtensionType::ClientCertificateType, |chp| {
        chp.client_certificate_extension()
            .is_some()
    });
}

#[test]
fn client_server_certificate_extension() {
    test_client_extension_getter(ExtensionType::ServerCertificateType, |chp| {
        chp.server_certificate_extension()
            .is_some()
    });
}

#[test]
fn client_quic_params_extension() {
    test_client_extension_getter(ExtensionType::TransportParameters, |chp| {
        chp.quic_params_extension().is_some()
    });
}

#[test]
fn client_versions_extension() {
    test_client_extension_getter(ExtensionType::SupportedVersions, |chp| {
        chp.versions_extension().is_some()
    });
}

#[test]
fn client_keyshare_extension() {
    test_client_extension_getter(ExtensionType::KeyShare, |chp| {
        chp.keyshare_extension().is_some()
    });
}

#[test]
fn client_psk() {
    test_client_extension_getter(ExtensionType::PreSharedKey, |chp| chp.psk().is_some());
}

#[test]
fn client_psk_modes() {
    test_client_extension_getter(ExtensionType::PSKKeyExchangeModes, |chp| {
        chp.psk_modes().is_some()
    });
}

fn test_client_extension_getter(typ: ExtensionType, getter: fn(&ClientHelloPayload) -> bool) {
    let mut chp = sample_client_hello_payload();
    let ext = chp.find_extension(typ).unwrap().clone();

    chp.extensions = vec![];
    assert!(!getter(&chp));

    chp.extensions = vec![ext];
    assert!(getter(&chp));

    chp.extensions = vec![ClientExtension::Unknown(UnknownExtension {
        typ,
        payload: Payload::Borrowed(&[]),
    })];
    assert!(!getter(&chp));
}

#[test]
fn test_truncated_hello_retry_extension_is_detected() {
    let hrr = sample_hello_retry_request();

    for ext in &hrr.extensions {
        let mut enc = ext.get_encoding();
        println!("testing {:?} enc {:?}", ext, enc);

        // "outer" truncation, i.e., where the extension-level length is longer than
        // the input
        for l in 0..enc.len() {
            assert!(HelloRetryExtension::read_bytes(&enc[..l]).is_err());
        }

        // these extension types don't have any internal encoding that rustls validates:
        if let ExtensionType::Unknown(_) = ext.ext_type() {
            continue;
        }

        // "inner" truncation, where the extension-level length agrees with the input
        // length, but isn't long enough for the type of extension
        for l in 0..(enc.len() - 4) {
            put_u16(l as u16, &mut enc[2..]);
            println!("  encoding {:?} len {:?}", enc, l);
            assert!(HelloRetryExtension::read_bytes(&enc).is_err());
        }
    }
}

#[test]
fn hello_retry_requested_key_share_group() {
    test_hello_retry_extension_getter(ExtensionType::KeyShare, |hrr| {
        hrr.requested_key_share_group()
            .is_some()
    });
}

#[test]
fn hello_retry_cookie() {
    test_hello_retry_extension_getter(ExtensionType::Cookie, |hrr| hrr.cookie().is_some());
}

#[test]
fn hello_retry_supported_versions() {
    test_hello_retry_extension_getter(ExtensionType::SupportedVersions, |hrr| {
        hrr.supported_versions().is_some()
    });
}

fn test_hello_retry_extension_getter(typ: ExtensionType, getter: fn(&HelloRetryRequest) -> bool) {
    let mut hrr = sample_hello_retry_request();
    let mut exts = core::mem::take(&mut hrr.extensions);
    exts.retain(|ext| ext.ext_type() == typ);

    assert!(!getter(&hrr));

    hrr.extensions = exts;
    assert!(getter(&hrr));

    hrr.extensions = vec![HelloRetryExtension::Unknown(UnknownExtension {
        typ,
        payload: Payload::Borrowed(&[]),
    })];
    assert!(!getter(&hrr));
}

#[test]
fn test_truncated_server_extension_is_detected() {
    let shp = sample_server_hello_payload();

    for ext in &shp.extensions {
        let mut enc = ext.get_encoding();
        println!("testing {:?} enc {:?}", ext, enc);

        // "outer" truncation, i.e., where the extension-level length is longer than
        // the input
        for l in 0..enc.len() {
            assert!(ServerExtension::read_bytes(&enc[..l]).is_err());
        }

        // these extension types don't have any internal encoding that rustls validates:
        match ext.ext_type() {
            ExtensionType::TransportParameters | ExtensionType::Unknown(_) => {
                continue;
            }
            _ => {}
        };

        // "inner" truncation, where the extension-level length agrees with the input
        // length, but isn't long enough for the type of extension
        for l in 0..(enc.len() - 4) {
            put_u16(l as u16, &mut enc[2..]);
            println!("  encoding {:?} len {:?}", enc, l);
            assert!(ServerExtension::read_bytes(&enc).is_err());
        }
    }
}

fn test_server_extension_getter(typ: ExtensionType, getter: fn(&ServerHelloPayload) -> bool) {
    let mut shp = sample_server_hello_payload();
    let ext = shp.find_extension(typ).unwrap().clone();

    shp.extensions = vec![];
    assert!(!getter(&shp));

    shp.extensions = vec![ext];
    assert!(getter(&shp));

    shp.extensions = vec![ServerExtension::Unknown(UnknownExtension {
        typ,
        payload: Payload::Borrowed(&[]),
    })];
    assert!(!getter(&shp));
}

#[test]
fn server_key_share() {
    test_server_extension_getter(ExtensionType::KeyShare, |shp| shp.key_share().is_some());
}

#[test]
fn server_psk_index() {
    test_server_extension_getter(ExtensionType::PreSharedKey, |shp| shp.psk_index().is_some());
}

#[test]
fn server_ecpoints_extension() {
    test_server_extension_getter(ExtensionType::ECPointFormats, |shp| {
        shp.ecpoints_extension().is_some()
    });
}

#[test]
fn server_supported_versions() {
    test_server_extension_getter(ExtensionType::SupportedVersions, |shp| {
        shp.supported_versions().is_some()
    });
}

#[test]
fn server_client_certificate_type_extension() {
    test_server_extension_getter(ExtensionType::ClientCertificateType, |shp| {
        shp.client_cert_type().is_some()
    });
}

#[test]
fn server_server_certificate_type_extension() {
    test_server_extension_getter(ExtensionType::ServerCertificateType, |shp| {
        shp.server_cert_type().is_some()
    });
}

#[test]
fn cert_entry_ocsp_response() {
    test_cert_extension_getter(ExtensionType::StatusRequest, |ce| {
        ce.ocsp_response().is_some()
    });
}

fn test_cert_extension_getter(typ: ExtensionType, getter: fn(&CertificateEntry<'_>) -> bool) {
    let mut ce = sample_certificate_payload_tls13()
        .entries
        .remove(0);
    let mut exts = core::mem::take(&mut ce.exts);
    exts.retain(|ext| ext.ext_type() == typ);

    assert!(!getter(&ce));

    ce.exts = exts;
    assert!(getter(&ce));

    ce.exts = vec![CertificateExtension::Unknown(UnknownExtension {
        typ,
        payload: Payload::Borrowed(&[]),
    })];
    assert!(!getter(&ce));
}

#[test]
fn can_print_all_server_extensions() {
    println!("server hello {:?}", sample_server_hello_payload());
}

#[test]
fn can_clone_all_server_extensions() {
    let exts = sample_server_hello_payload().extensions;
    let exts2 = exts.clone();
    println!("{exts:?}, {exts2:?}");
}

#[test]
fn can_round_trip_all_tls12_handshake_payloads() {
    for ref hm in all_tls12_handshake_payloads().iter() {
        println!("{:?}", hm.typ);
        let bytes = hm.get_encoding();
        let mut rd = Reader::init(&bytes);
        let other = HandshakeMessagePayload::read(&mut rd).unwrap();
        assert!(!rd.any_left());
        assert_eq!(hm.get_encoding(), other.get_encoding());

        println!("{:?}", hm);
        println!("{:?}", other);
    }
}

#[test]
fn can_into_owned_all_tls12_handshake_payloads() {
    for hm in all_tls12_handshake_payloads().drain(..) {
        let enc = hm.get_encoding();
        let debug = format!("{hm:?}");
        let other = hm.into_owned();
        assert_eq!(enc, other.get_encoding());
        assert_eq!(debug, format!("{other:?}"));
    }
}

#[test]
fn can_detect_truncation_of_all_tls12_handshake_payloads() {
    for hm in all_tls12_handshake_payloads().iter() {
        let mut enc = hm.get_encoding();
        println!("test {:?} enc {:?}", hm, enc);

        // outer truncation
        for l in 0..enc.len() {
            assert!(HandshakeMessagePayload::read_bytes(&enc[..l]).is_err())
        }

        // inner truncation
        for l in 0..enc.len() - 4 {
            put_u24(l as u32, &mut enc[1..]);
            println!("  check len {:?} enc {:?}", l, enc);

            match (hm.typ, l) {
                (HandshakeType::ClientHello, 41)
                | (HandshakeType::ServerHello, 38)
                | (HandshakeType::ServerKeyExchange, _)
                | (HandshakeType::ClientKeyExchange, _)
                | (HandshakeType::Finished, _)
                | (HandshakeType::Unknown(_), _) => continue,
                _ => {}
            };

            assert!(HandshakeMessagePayload::read_version(
                &mut Reader::init(&enc),
                ProtocolVersion::TLSv1_2
            )
            .is_err());
            assert!(HandshakeMessagePayload::read_bytes(&enc).is_err());
        }
    }
}

#[test]
fn can_round_trip_all_tls13_handshake_payloads() {
    for ref hm in all_tls13_handshake_payloads().iter() {
        println!("{:?}", hm.typ);
        let bytes = hm.get_encoding();
        let mut rd = Reader::init(&bytes);

        let other =
            HandshakeMessagePayload::read_version(&mut rd, ProtocolVersion::TLSv1_3).unwrap();
        assert!(!rd.any_left());
        assert_eq!(hm.get_encoding(), other.get_encoding());

        println!("{:?}", hm);
        println!("{:?}", other);
    }
}

#[test]
fn can_into_owned_all_tls13_handshake_payloads() {
    for hm in all_tls13_handshake_payloads().drain(..) {
        let enc = hm.get_encoding();
        let debug = format!("{hm:?}");
        let other = hm.into_owned();
        assert_eq!(enc, other.get_encoding());
        assert_eq!(debug, format!("{other:?}"));
    }
}

#[test]
fn can_detect_truncation_of_all_tls13_handshake_payloads() {
    for hm in all_tls13_handshake_payloads().iter() {
        let mut enc = hm.get_encoding();
        println!("test {:?} enc {:?}", hm, enc);

        // outer truncation
        for l in 0..enc.len() {
            assert!(HandshakeMessagePayload::read_bytes(&enc[..l]).is_err())
        }

        // inner truncation
        for l in 0..enc.len() - 4 {
            put_u24(l as u32, &mut enc[1..]);
            println!("  check len {:?} enc {:?}", l, enc);

            match (hm.typ, l) {
                (HandshakeType::ClientHello, 41)
                | (HandshakeType::ServerHello, 38)
                | (HandshakeType::ServerKeyExchange, _)
                | (HandshakeType::ClientKeyExchange, _)
                | (HandshakeType::Finished, _)
                | (HandshakeType::Unknown(_), _) => continue,
                _ => {}
            };

            assert!(HandshakeMessagePayload::read_version(
                &mut Reader::init(&enc),
                ProtocolVersion::TLSv1_3
            )
            .is_err());
        }
    }
}

fn put_u24(u: u32, b: &mut [u8]) {
    b[0] = (u >> 16) as u8;
    b[1] = (u >> 8) as u8;
    b[2] = u as u8;
}

#[test]
fn cannot_read_message_hash_from_network() {
    let mh = HandshakeMessagePayload {
        typ: HandshakeType::MessageHash,
        payload: HandshakePayload::MessageHash(Payload::new(vec![1, 2, 3])),
    };
    println!("mh {:?}", mh);
    let enc = mh.get_encoding();
    assert!(HandshakeMessagePayload::read_bytes(&enc).is_err());
}

#[test]
fn cannot_decode_huge_certificate() {
    let mut buf = [0u8; 65 * 1024];
    // exactly 64KB decodes fine
    buf[0] = 0x0b;
    buf[1] = 0x01;
    buf[2] = 0x00;
    buf[3] = 0x03;
    buf[4] = 0x01;
    buf[5] = 0x00;
    buf[6] = 0x00;
    buf[7] = 0x00;
    buf[8] = 0xff;
    buf[9] = 0xfd;
    HandshakeMessagePayload::read_bytes(&buf[..0x10000 + 7]).unwrap();

    // however 64KB + 1 byte does not
    buf[1] = 0x01;
    buf[2] = 0x00;
    buf[3] = 0x04;
    buf[4] = 0x01;
    buf[5] = 0x00;
    buf[6] = 0x01;
    assert_eq!(
        HandshakeMessagePayload::read_bytes(&buf[..0x10001 + 7]).unwrap_err(),
        InvalidMessage::CertificatePayloadTooLarge
    );
}

#[test]
fn can_decode_server_hello_from_api_devicecheck_apple_com() {
    let data = include_bytes!("../testdata/hello-api.devicecheck.apple.com.bin");
    let mut r = Reader::init(data);
    let hm = HandshakeMessagePayload::read(&mut r).unwrap();
    println!("msg: {:?}", hm);
}

#[test]
fn wrapped_dn_encoding() {
    let subject = b"subject";
    let dn = DistinguishedName::in_sequence(&subject[..]);
    const DER_SEQUENCE_TAG: u8 = 0x30;
    let expected_prefix = vec![DER_SEQUENCE_TAG, subject.len() as u8];
    assert_eq!(dn.as_ref(), [expected_prefix, subject.to_vec()].concat());
}

fn sample_hello_retry_request() -> HelloRetryRequest {
    HelloRetryRequest {
        legacy_version: ProtocolVersion::TLSv1_2,
        session_id: SessionId::empty(),
        cipher_suite: CipherSuite::TLS_NULL_WITH_NULL_NULL,
        extensions: vec![
            HelloRetryExtension::KeyShare(NamedGroup::X25519),
            HelloRetryExtension::Cookie(PayloadU16(vec![0])),
            HelloRetryExtension::SupportedVersions(ProtocolVersion::TLSv1_2),
            HelloRetryExtension::Unknown(UnknownExtension {
                typ: ExtensionType::Unknown(12345),
                payload: Payload::Borrowed(&[1, 2, 3]),
            }),
        ],
    }
}

fn sample_client_hello_payload() -> ClientHelloPayload {
    ClientHelloPayload {
        client_version: ProtocolVersion::TLSv1_2,
        random: Random::from([0; 32]),
        session_id: SessionId::empty(),
        cipher_suites: vec![CipherSuite::TLS_NULL_WITH_NULL_NULL],
        compression_methods: vec![Compression::Null],
        extensions: vec![
            ClientExtension::EcPointFormats(ECPointFormat::SUPPORTED.to_vec()),
            ClientExtension::NamedGroups(vec![NamedGroup::X25519]),
            ClientExtension::SignatureAlgorithms(vec![SignatureScheme::ECDSA_NISTP256_SHA256]),
            ClientExtension::make_sni(&DnsName::try_from("hello").unwrap()),
            ClientExtension::SessionTicket(ClientSessionTicket::Request),
            ClientExtension::SessionTicket(ClientSessionTicket::Offer(Payload::Borrowed(&[]))),
            ClientExtension::Protocols(vec![ProtocolName::from(vec![0])]),
            ClientExtension::SupportedVersions(vec![ProtocolVersion::TLSv1_3]),
            ClientExtension::KeyShare(vec![KeyShareEntry::new(NamedGroup::X25519, &[1, 2, 3][..])]),
            ClientExtension::PresharedKeyModes(vec![PSKKeyExchangeMode::PSK_DHE_KE]),
            ClientExtension::PresharedKey(PresharedKeyOffer {
                identities: vec![
                    PresharedKeyIdentity::new(vec![3, 4, 5], 123456),
                    PresharedKeyIdentity::new(vec![6, 7, 8], 7891011),
                ],
                binders: vec![
                    PresharedKeyBinder::from(vec![1, 2, 3]),
                    PresharedKeyBinder::from(vec![3, 4, 5]),
                ],
            }),
            ClientExtension::Cookie(PayloadU16(vec![1, 2, 3])),
            ClientExtension::ExtendedMasterSecretRequest,
            ClientExtension::CertificateStatusRequest(CertificateStatusRequest::build_ocsp()),
            ClientExtension::ServerCertTypes(vec![CertificateType::RawPublicKey]),
            ClientExtension::ClientCertTypes(vec![CertificateType::RawPublicKey]),
            ClientExtension::TransportParameters(vec![1, 2, 3]),
            ClientExtension::EarlyData,
            ClientExtension::CertificateCompressionAlgorithms(vec![
                CertificateCompressionAlgorithm::Brotli,
                CertificateCompressionAlgorithm::Zlib,
            ]),
            ClientExtension::Unknown(UnknownExtension {
                typ: ExtensionType::Unknown(12345),
                payload: Payload::Borrowed(&[1, 2, 3]),
            }),
        ],
    }
}

fn sample_server_hello_payload() -> ServerHelloPayload {
    ServerHelloPayload {
        legacy_version: ProtocolVersion::TLSv1_2,
        random: Random::from([0; 32]),
        session_id: SessionId::empty(),
        cipher_suite: CipherSuite::TLS_NULL_WITH_NULL_NULL,
        compression_method: Compression::Null,
        extensions: vec![
            ServerExtension::EcPointFormats(ECPointFormat::SUPPORTED.to_vec()),
            ServerExtension::ServerNameAck,
            ServerExtension::SessionTicketAck,
            ServerExtension::RenegotiationInfo(PayloadU8(vec![0])),
            ServerExtension::Protocols(vec![ProtocolName::from(vec![0])]),
            ServerExtension::KeyShare(KeyShareEntry::new(NamedGroup::X25519, &[1, 2, 3][..])),
            ServerExtension::PresharedKey(3),
            ServerExtension::ExtendedMasterSecretAck,
            ServerExtension::CertificateStatusAck,
            ServerExtension::SupportedVersions(ProtocolVersion::TLSv1_2),
            ServerExtension::TransportParameters(vec![1, 2, 3]),
            ServerExtension::Unknown(UnknownExtension {
                typ: ExtensionType::Unknown(12345),
                payload: Payload::Borrowed(&[1, 2, 3]),
            }),
            ServerExtension::ClientCertType(CertificateType::RawPublicKey),
            ServerExtension::ServerCertType(CertificateType::RawPublicKey),
        ],
    }
}

fn all_tls12_handshake_payloads() -> Vec<HandshakeMessagePayload<'static>> {
    vec![
        HandshakeMessagePayload {
            typ: HandshakeType::HelloRequest,
            payload: HandshakePayload::HelloRequest,
        },
        HandshakeMessagePayload {
            typ: HandshakeType::ClientHello,
            payload: HandshakePayload::ClientHello(sample_client_hello_payload()),
        },
        HandshakeMessagePayload {
            typ: HandshakeType::ServerHello,
            payload: HandshakePayload::ServerHello(sample_server_hello_payload()),
        },
        HandshakeMessagePayload {
            typ: HandshakeType::HelloRetryRequest,
            payload: HandshakePayload::HelloRetryRequest(sample_hello_retry_request()),
        },
        HandshakeMessagePayload {
            typ: HandshakeType::Certificate,
            payload: HandshakePayload::Certificate(CertificateChain(vec![CertificateDer::from(
                vec![1, 2, 3],
            )])),
        },
        HandshakeMessagePayload {
            typ: HandshakeType::ServerKeyExchange,
            payload: HandshakePayload::ServerKeyExchange(sample_ecdhe_server_key_exchange_payload()),
        },
        HandshakeMessagePayload {
            typ: HandshakeType::ServerKeyExchange,
            payload: HandshakePayload::ServerKeyExchange(sample_dhe_server_key_exchange_payload()),
        },
        HandshakeMessagePayload {
            typ: HandshakeType::ServerKeyExchange,
            payload: HandshakePayload::ServerKeyExchange(
                sample_unknown_server_key_exchange_payload(),
            ),
        },
        HandshakeMessagePayload {
            typ: HandshakeType::CertificateRequest,
            payload: HandshakePayload::CertificateRequest(sample_certificate_request_payload()),
        },
        HandshakeMessagePayload {
            typ: HandshakeType::ServerHelloDone,
            payload: HandshakePayload::ServerHelloDone,
        },
        HandshakeMessagePayload {
            typ: HandshakeType::ClientKeyExchange,
            payload: HandshakePayload::ClientKeyExchange(Payload::Borrowed(&[1, 2, 3])),
        },
        HandshakeMessagePayload {
            typ: HandshakeType::NewSessionTicket,
            payload: HandshakePayload::NewSessionTicket(sample_new_session_ticket_payload()),
        },
        HandshakeMessagePayload {
            typ: HandshakeType::EncryptedExtensions,
            payload: HandshakePayload::EncryptedExtensions(sample_encrypted_extensions()),
        },
        HandshakeMessagePayload {
            typ: HandshakeType::KeyUpdate,
            payload: HandshakePayload::KeyUpdate(KeyUpdateRequest::UpdateRequested),
        },
        HandshakeMessagePayload {
            typ: HandshakeType::KeyUpdate,
            payload: HandshakePayload::KeyUpdate(KeyUpdateRequest::UpdateNotRequested),
        },
        HandshakeMessagePayload {
            typ: HandshakeType::Finished,
            payload: HandshakePayload::Finished(Payload::Borrowed(&[1, 2, 3])),
        },
        HandshakeMessagePayload {
            typ: HandshakeType::CertificateStatus,
            payload: HandshakePayload::CertificateStatus(sample_certificate_status()),
        },
        HandshakeMessagePayload {
            typ: HandshakeType::Unknown(99),
            payload: HandshakePayload::Unknown(Payload::Borrowed(&[1, 2, 3])),
        },
    ]
}

fn all_tls13_handshake_payloads() -> Vec<HandshakeMessagePayload<'static>> {
    vec![
        HandshakeMessagePayload {
            typ: HandshakeType::HelloRequest,
            payload: HandshakePayload::HelloRequest,
        },
        HandshakeMessagePayload {
            typ: HandshakeType::ClientHello,
            payload: HandshakePayload::ClientHello(sample_client_hello_payload()),
        },
        HandshakeMessagePayload {
            typ: HandshakeType::ServerHello,
            payload: HandshakePayload::ServerHello(sample_server_hello_payload()),
        },
        HandshakeMessagePayload {
            typ: HandshakeType::HelloRetryRequest,
            payload: HandshakePayload::HelloRetryRequest(sample_hello_retry_request()),
        },
        HandshakeMessagePayload {
            typ: HandshakeType::Certificate,
            payload: HandshakePayload::CertificateTls13(sample_certificate_payload_tls13()),
        },
        HandshakeMessagePayload {
            typ: HandshakeType::CompressedCertificate,
            payload: HandshakePayload::CompressedCertificate(sample_compressed_certificate()),
        },
        HandshakeMessagePayload {
            typ: HandshakeType::ServerKeyExchange,
            payload: HandshakePayload::ServerKeyExchange(sample_ecdhe_server_key_exchange_payload()),
        },
        HandshakeMessagePayload {
            typ: HandshakeType::ServerKeyExchange,
            payload: HandshakePayload::ServerKeyExchange(sample_dhe_server_key_exchange_payload()),
        },
        HandshakeMessagePayload {
            typ: HandshakeType::ServerKeyExchange,
            payload: HandshakePayload::ServerKeyExchange(
                sample_unknown_server_key_exchange_payload(),
            ),
        },
        HandshakeMessagePayload {
            typ: HandshakeType::CertificateRequest,
            payload: HandshakePayload::CertificateRequestTls13(
                sample_certificate_request_payload_tls13(),
            ),
        },
        HandshakeMessagePayload {
            typ: HandshakeType::CertificateVerify,
            payload: HandshakePayload::CertificateVerify(DigitallySignedStruct::new(
                SignatureScheme::ECDSA_NISTP256_SHA256,
                vec![1, 2, 3],
            )),
        },
        HandshakeMessagePayload {
            typ: HandshakeType::ServerHelloDone,
            payload: HandshakePayload::ServerHelloDone,
        },
        HandshakeMessagePayload {
            typ: HandshakeType::ClientKeyExchange,
            payload: HandshakePayload::ClientKeyExchange(Payload::Borrowed(&[1, 2, 3])),
        },
        HandshakeMessagePayload {
            typ: HandshakeType::NewSessionTicket,
            payload: HandshakePayload::NewSessionTicketTls13(
                sample_new_session_ticket_payload_tls13(),
            ),
        },
        HandshakeMessagePayload {
            typ: HandshakeType::EncryptedExtensions,
            payload: HandshakePayload::EncryptedExtensions(sample_encrypted_extensions()),
        },
        HandshakeMessagePayload {
            typ: HandshakeType::KeyUpdate,
            payload: HandshakePayload::KeyUpdate(KeyUpdateRequest::UpdateRequested),
        },
        HandshakeMessagePayload {
            typ: HandshakeType::KeyUpdate,
            payload: HandshakePayload::KeyUpdate(KeyUpdateRequest::UpdateNotRequested),
        },
        HandshakeMessagePayload {
            typ: HandshakeType::Finished,
            payload: HandshakePayload::Finished(Payload::Borrowed(&[1, 2, 3])),
        },
        HandshakeMessagePayload {
            typ: HandshakeType::CertificateStatus,
            payload: HandshakePayload::CertificateStatus(sample_certificate_status()),
        },
        HandshakeMessagePayload {
            typ: HandshakeType::Unknown(99),
            payload: HandshakePayload::Unknown(Payload::Borrowed(&[1, 2, 3])),
        },
    ]
}

fn sample_certificate_payload_tls13() -> CertificatePayloadTls13<'static> {
    CertificatePayloadTls13 {
        context: PayloadU8(vec![1, 2, 3]),
        entries: vec![CertificateEntry {
            cert: CertificateDer::from(vec![3, 4, 5]),
            exts: vec![
                CertificateExtension::CertificateStatus(CertificateStatus {
                    ocsp_response: PayloadU24(Payload::new(vec![1, 2, 3])),
                }),
                CertificateExtension::Unknown(UnknownExtension {
                    typ: ExtensionType::Unknown(12345),
                    payload: Payload::Borrowed(&[1, 2, 3]),
                }),
            ],
        }],
    }
}

fn sample_compressed_certificate() -> CompressedCertificatePayload<'static> {
    CompressedCertificatePayload {
        alg: CertificateCompressionAlgorithm::Brotli,
        uncompressed_len: 123,
        compressed: PayloadU24(Payload::new(vec![1, 2, 3])),
    }
}

fn sample_ecdhe_server_key_exchange_payload() -> ServerKeyExchangePayload {
    ServerKeyExchangePayload::Known(ServerKeyExchange {
        params: ServerKeyExchangeParams::Ecdh(ServerEcdhParams {
            curve_params: EcParameters {
                curve_type: ECCurveType::NamedCurve,
                named_group: NamedGroup::X25519,
            },
            public: PayloadU8(vec![1, 2, 3]),
        }),
        dss: DigitallySignedStruct::new(SignatureScheme::RSA_PSS_SHA256, vec![1, 2, 3]),
    })
}

fn sample_dhe_server_key_exchange_payload() -> ServerKeyExchangePayload {
    ServerKeyExchangePayload::Known(ServerKeyExchange {
        params: ServerKeyExchangeParams::Dh(ServerDhParams {
            dh_p: PayloadU16(vec![1, 2, 3]),
            dh_g: PayloadU16(vec![2]),
            dh_Ys: PayloadU16(vec![1, 2]),
        }),
        dss: DigitallySignedStruct::new(SignatureScheme::RSA_PSS_SHA256, vec![1, 2, 3]),
    })
}

fn sample_unknown_server_key_exchange_payload() -> ServerKeyExchangePayload {
    ServerKeyExchangePayload::Unknown(Payload::Borrowed(&[1, 2, 3]))
}

fn sample_certificate_request_payload() -> CertificateRequestPayload {
    CertificateRequestPayload {
        certtypes: vec![ClientCertificateType::RSASign],
        sigschemes: vec![SignatureScheme::ECDSA_NISTP256_SHA256],
        canames: vec![DistinguishedName::from(vec![1, 2, 3])],
    }
}

fn sample_certificate_request_payload_tls13() -> CertificateRequestPayloadTls13 {
    CertificateRequestPayloadTls13 {
        context: PayloadU8(vec![1, 2, 3]),
        extensions: vec![
            CertReqExtension::SignatureAlgorithms(vec![SignatureScheme::ECDSA_NISTP256_SHA256]),
            CertReqExtension::AuthorityNames(vec![DistinguishedName::from(vec![1, 2, 3])]),
            CertReqExtension::Unknown(UnknownExtension {
                typ: ExtensionType::Unknown(12345),
                payload: Payload::Borrowed(&[1, 2, 3]),
            }),
        ],
    }
}

fn sample_new_session_ticket_payload() -> NewSessionTicketPayload {
    NewSessionTicketPayload {
        lifetime_hint: 1234,
        ticket: Arc::new(PayloadU16(vec![1, 2, 3])),
    }
}

fn sample_new_session_ticket_payload_tls13() -> NewSessionTicketPayloadTls13 {
    NewSessionTicketPayloadTls13 {
        lifetime: 123,
        age_add: 1234,
        nonce: PayloadU8(vec![1, 2, 3]),
        ticket: Arc::new(PayloadU16(vec![4, 5, 6])),
        exts: vec![NewSessionTicketExtension::Unknown(UnknownExtension {
            typ: ExtensionType::Unknown(12345),
            payload: Payload::Borrowed(&[1, 2, 3]),
        })],
    }
}

fn sample_encrypted_extensions() -> Vec<ServerExtension> {
    sample_server_hello_payload().extensions
}

fn sample_certificate_status() -> CertificateStatus<'static> {
    CertificateStatus {
        ocsp_response: PayloadU24(Payload::new(vec![1, 2, 3])),
    }
}
