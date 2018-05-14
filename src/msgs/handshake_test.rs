use super::handshake::*;
use super::enums::*;
use super::base::{Payload, PayloadU8, PayloadU16, PayloadU24};
use super::codec::{Reader, Codec};
use webpki::DNSNameRef;
use key::Certificate;

#[test]
fn rejects_short_random() {
    let bytes = [0x01; 31];
    let mut rd = Reader::init(&bytes);
    assert_eq!(Random::read(&mut rd), None);
}

#[test]
fn reads_random() {
    let bytes = [0x01; 32];
    let mut rd = Reader::init(&bytes);
    let rnd = Random::read(&mut rd)
        .unwrap();
    println!("{:?}", rnd);

    assert_eq!(rd.any_left(), false);
}

#[test]
fn rejects_truncated_sessionid() {
    let bytes = [32; 32];
    let mut rd = Reader::init(&bytes);
    assert_eq!(SessionID::read(&mut rd), None);
}

#[test]
fn rejects_sessionid_with_bad_length() {
    let bytes = [33; 33];
    let mut rd = Reader::init(&bytes);
    assert_eq!(SessionID::read(&mut rd), None);
}

#[test]
fn sessionid_with_different_lengths_are_unequal() {
    let a = SessionID::new(&[1u8]);
    let b = SessionID::new(&[1u8, 2u8]);
    assert_eq!(a, a);
    assert_eq!(b, b);
    assert_ne!(a, b);
}

#[test]
fn accepts_short_sessionid() {
    let bytes = [1; 2];
    let mut rd = Reader::init(&bytes);
    let sess = SessionID::read(&mut rd)
        .unwrap();
    println!("{:?}", sess);

    assert_eq!(sess.is_empty(), false);
    assert_eq!(sess.len(), 1);
    assert_eq!(sess, SessionID::new(&[1u8]));
    assert_eq!(rd.any_left(), false);
}

#[test]
fn accepts_empty_sessionid() {
    let bytes = [0; 1];
    let mut rd = Reader::init(&bytes);
    let sess = SessionID::read(&mut rd)
        .unwrap();
    println!("{:?}", sess);

    assert_eq!(sess.is_empty(), true);
    assert_eq!(sess.len(), 0);
    assert_eq!(sess, SessionID::new(&[]));
    assert_eq!(rd.any_left(), false);
}

#[test]
fn can_roundtrip_unknown_client_ext() {
    let bytes = [0x12u8, 0x34u8, 0, 3, 1, 2, 3];
    let mut rd = Reader::init(&bytes);
    let ext = ClientExtension::read(&mut rd)
        .unwrap();

    println!("{:?}", ext);
    assert_eq!(ext.get_type(), ExtensionType::Unknown(0x1234));
    assert_eq!(bytes.to_vec(), ext.get_encoding());
}

#[test]
fn can_roundtrip_single_sni() {
    let bytes = [
        0, 0,
        0, 7,
        0, 5,
          0, 0, 2, 0x6c, 0x6f
    ];
    let mut rd = Reader::init(&bytes);
    let ext = ClientExtension::read(&mut rd)
        .unwrap();
    println!("{:?}", ext);

    assert_eq!(ext.get_type(), ExtensionType::ServerName);
    assert_eq!(bytes.to_vec(), ext.get_encoding());
}

#[test]
fn can_roundtrip_other_sni_name_types() {
    let bytes = [
        0, 0,
        0, 7,
        0, 5,
          1, 0, 02, 0x6c, 0x6f
    ];
    let mut rd = Reader::init(&bytes);
    let ext = ClientExtension::read(&mut rd)
        .unwrap();
    println!("{:?}", ext);

    assert_eq!(ext.get_type(), ExtensionType::ServerName);
    assert_eq!(bytes.to_vec(), ext.get_encoding());
}

#[test]
fn get_hostname_returns_none_for_other_sni_name_types() {
    let bytes = [
        0, 0,
        0, 7,
        0, 5,
          1, 0, 02, 0x6c, 0x6f
    ];
    let mut rd = Reader::init(&bytes);
    let ext = ClientExtension::read(&mut rd)
        .unwrap();
    println!("{:?}", ext);

    assert_eq!(ext.get_type(), ExtensionType::ServerName);
    if let ClientExtension::ServerName(snr) = ext {
        assert!(snr.get_hostname().is_none());
    } else {
        unreachable!();
    }
}

#[test]
fn can_roundtrip_multiname_sni() {
    let bytes = [
        0, 0,
        0, 12,
        0, 10,
          0, 0, 2, 0x68, 0x69,
          0, 0, 2, 0x6c, 0x6f
    ];
    let mut rd = Reader::init(&bytes);
    let ext = ClientExtension::read(&mut rd)
        .unwrap();
    println!("{:?}", ext);

    assert_eq!(ext.get_type(), ExtensionType::ServerName);
    assert_eq!(bytes.to_vec(), ext.get_encoding());
    match ext {
        ClientExtension::ServerName(req) => {
            assert_eq!(2, req.len());

            let dns_name_str: &str = req.get_hostname().unwrap().into();
            assert_eq!(dns_name_str, "hi");

            assert_eq!(req[0].typ, ServerNameType::HostName);
            assert_eq!(req[1].typ, ServerNameType::HostName);
        }
        _ => unreachable!()
    }
}

#[test]
fn rejects_truncated_sni() {
    let bytes = [ 0, 0, 0, 1, 0 ];
    assert!(ClientExtension::read(&mut Reader::init(&bytes)).is_none());

    let bytes = [ 0, 0, 0, 2, 0, 1 ];
    assert!(ClientExtension::read(&mut Reader::init(&bytes)).is_none());

    let bytes = [ 0, 0, 0, 3, 0, 1, 0 ];
    assert!(ClientExtension::read(&mut Reader::init(&bytes)).is_none());

    let bytes = [ 0, 0, 0, 4, 0, 2, 0, 0 ];
    assert!(ClientExtension::read(&mut Reader::init(&bytes)).is_none());

    let bytes = [ 0, 0, 0, 5, 0, 3, 0, 0, 0 ];
    assert!(ClientExtension::read(&mut Reader::init(&bytes)).is_none());

    let bytes = [ 0, 0, 0, 5, 0, 3, 0, 0, 1 ];
    assert!(ClientExtension::read(&mut Reader::init(&bytes)).is_none());

    let bytes = [ 0, 0, 0, 6, 0, 4, 0, 0, 2, 0x68 ];
    assert!(ClientExtension::read(&mut Reader::init(&bytes)).is_none());
}

#[test]
fn can_roundtrip_psk_identity() {
    let bytes = [ 0, 0, 0x11, 0x22, 0x33, 0x44 ];
    let psk_id = PresharedKeyIdentity::read(&mut Reader::init(&bytes))
        .unwrap();
    println!("{:?}", psk_id);
    assert_eq!(psk_id.identity.len(), 0);
    assert_eq!(psk_id.obfuscated_ticket_age, 0x11223344);
    assert_eq!(psk_id.get_encoding(), bytes.to_vec());

    let bytes = [ 0, 5, 0x1, 0x2, 0x3, 0x4, 0x5, 0x11, 0x22, 0x33, 0x44 ];
    let psk_id = PresharedKeyIdentity::read(&mut Reader::init(&bytes))
        .unwrap();
    println!("{:?}", psk_id);
    assert_eq!(psk_id.identity.len(), 5);
    assert_eq!(psk_id.identity.0, vec![0x1, 0x2, 0x3, 0x4, 0x5]);
    assert_eq!(psk_id.obfuscated_ticket_age, 0x11223344);
    assert_eq!(psk_id.get_encoding(), bytes.to_vec());
}

#[test]
fn can_roundtrip_psk_offer() {
    let bytes = [
        0, 7,
          0, 1,
            0x99,
          0x11, 0x22, 0x33, 0x44,
        0, 4,
          3,
            0x01, 0x02, 0x3
    ];
    let psko = PresharedKeyOffer::read(&mut Reader::init(&bytes))
        .unwrap();
    println!("{:?}", psko);

    assert_eq!(psko.identities.len(), 1);
    assert_eq!(psko.identities[0].identity.0, vec![0x99]);
    assert_eq!(psko.identities[0].obfuscated_ticket_age, 0x11223344);
    assert_eq!(psko.binders.len(), 1);
    assert_eq!(psko.binders[0].0, vec![1, 2, 3]);
    assert_eq!(psko.get_encoding(), bytes.to_vec());
}

#[test]
fn can_roundtrip_certstatusreq_for_ocsp() {
    let ext = ClientExtension::CertificateStatusRequest(
        CertificateStatusRequest::build_ocsp()
    );
    println!("{:?}", ext);

    let bytes = [
        0, 5, // CertificateStatusRequest
        0, 11,
          1, // OCSP
          0, 5,
            0, 3,
              0, 1,
                1,
          0, 1,
            2
    ];

    let csr = ClientExtension::read(&mut Reader::init(&bytes))
        .unwrap();
    println!("{:?}", csr);
    assert_eq!(csr.get_encoding(), bytes.to_vec());
}

#[test]
fn can_roundtrip_certstatusreq_for_other() {
    let bytes = [
        0, 5, // CertificateStatusRequest
        0, 5,
          2, // !OCSP
          1, 2, 3, 4
    ];

    let csr = ClientExtension::read(&mut Reader::init(&bytes))
        .unwrap();
    println!("{:?}", csr);
    assert_eq!(csr.get_encoding(), bytes.to_vec());
}

#[test]
fn can_roundtrip_multi_proto() {
    let bytes = [
        0, 16,
        0, 8,
        0, 6,
          2, 0x68, 0x69,
          2, 0x6c, 0x6f
    ];
    let mut rd = Reader::init(&bytes);
    let ext = ClientExtension::read(&mut rd)
        .unwrap();
    println!("{:?}", ext);

    assert_eq!(ext.get_type(), ExtensionType::ALProtocolNegotiation);
    assert_eq!(ext.get_encoding(), bytes.to_vec());
    match ext {
        ClientExtension::Protocols(prot) => {
            assert_eq!(2, prot.len());
            assert_eq!(vec!["hi".to_string(), "lo".to_string()],
                       prot.to_strings());
            assert_eq!(prot.as_single_string(), None);
        }
        _ => unreachable!()
    }
}

#[test]
fn can_roundtrip_single_proto() {
    let bytes = [
        0, 16,
        0, 5,
        0, 3,
          2, 0x68, 0x69,
    ];
    let mut rd = Reader::init(&bytes);
    let ext = ClientExtension::read(&mut rd)
        .unwrap();
    println!("{:?}", ext);

    assert_eq!(ext.get_type(), ExtensionType::ALProtocolNegotiation);
    assert_eq!(bytes.to_vec(), ext.get_encoding());
    match ext {
        ClientExtension::Protocols(prot) => {
            assert_eq!(1, prot.len());
            assert_eq!(vec!["hi".to_string()], prot.to_strings());
            assert_eq!(prot.as_single_string(), Some("hi"));
        }
        _ => unreachable!()
    }
}

#[test]
fn decomposed_signature_scheme_has_correct_mappings() {
    assert_eq!(SignatureScheme::make(SignatureAlgorithm::RSA, HashAlgorithm::SHA1),
               SignatureScheme::RSA_PKCS1_SHA1);
    assert_eq!(SignatureScheme::make(SignatureAlgorithm::RSA, HashAlgorithm::SHA256),
               SignatureScheme::RSA_PKCS1_SHA256);
    assert_eq!(SignatureScheme::make(SignatureAlgorithm::RSA, HashAlgorithm::SHA384),
               SignatureScheme::RSA_PKCS1_SHA384);
    assert_eq!(SignatureScheme::make(SignatureAlgorithm::RSA, HashAlgorithm::SHA512),
               SignatureScheme::RSA_PKCS1_SHA512);

    assert_eq!(SignatureScheme::make(SignatureAlgorithm::ECDSA, HashAlgorithm::SHA256),
               SignatureScheme::ECDSA_NISTP256_SHA256);
    assert_eq!(SignatureScheme::make(SignatureAlgorithm::ECDSA, HashAlgorithm::SHA384),
               SignatureScheme::ECDSA_NISTP384_SHA384);
    assert_eq!(SignatureScheme::make(SignatureAlgorithm::ECDSA, HashAlgorithm::SHA512),
               SignatureScheme::ECDSA_NISTP521_SHA512);
}

fn get_sample_clienthellopayload() -> ClientHelloPayload {
    ClientHelloPayload {
        client_version: ProtocolVersion::TLSv1_2,
        random: Random::from_slice(&[0; 32]),
        session_id: SessionID::empty(),
        cipher_suites: vec![ CipherSuite::TLS_NULL_WITH_NULL_NULL ],
        compression_methods: vec![ Compression::Null ],
        extensions: vec![
            ClientExtension::ECPointFormats(ECPointFormatList::supported()),
            ClientExtension::NamedGroups(NamedGroups::supported()),
            ClientExtension::SignatureAlgorithms(SupportedSignatureSchemes::supported_verify()),
            ClientExtension::make_sni(DNSNameRef::try_from_ascii_str("hello").unwrap()),
            ClientExtension::SessionTicketRequest,
            ClientExtension::SessionTicketOffer(Payload(vec![])),
            ClientExtension::Protocols(vec![ PayloadU8(vec![ 0 ]) ]),
            ClientExtension::SupportedVersions(vec![ ProtocolVersion::TLSv1_3 ]),
            ClientExtension::KeyShare(vec![ KeyShareEntry::new(NamedGroup::X25519, &[1, 2, 3]) ]),
            ClientExtension::PresharedKeyModes(vec![ PSKKeyExchangeMode::PSK_DHE_KE ]),
            ClientExtension::PresharedKey(
                PresharedKeyOffer::new(PresharedKeyIdentity::new(vec![3, 4, 5], 123456),
                                       vec![1, 2, 3])
                ),
            ClientExtension::Cookie(PayloadU16(vec![1, 2, 3])),
            ClientExtension::ExtendedMasterSecretRequest,
            ClientExtension::CertificateStatusRequest(CertificateStatusRequest::build_ocsp()),
            ClientExtension::SignedCertificateTimestampRequest,
            ClientExtension::TransportParameters(vec![ 1, 2, 3 ]),
            ClientExtension::Unknown(UnknownExtension {
                typ: ExtensionType::Unknown(12345),
                payload: Payload(vec![ 1, 2, 3 ])
            })
        ],
    }
}

#[test]
fn can_print_all_clientextensions() {
    println!("client hello {:?}", get_sample_clienthellopayload());
}

#[test]
fn can_clone_all_clientextensions() {
    let _ = get_sample_serverhellopayload().extensions.clone();
}

fn get_sample_serverhellopayload() -> ServerHelloPayload {
    ServerHelloPayload {
        legacy_version: ProtocolVersion::TLSv1_2,
        random: Random::from_slice(&[0; 32]),
        session_id: SessionID::empty(),
        cipher_suite: CipherSuite::TLS_NULL_WITH_NULL_NULL,
        compression_method: Compression::Null,
        extensions: vec![
            ServerExtension::ECPointFormats(ECPointFormatList::supported()),
            ServerExtension::ServerNameAck,
            ServerExtension::SessionTicketAck,
            ServerExtension::RenegotiationInfo(PayloadU8(vec![ 0 ])),
            ServerExtension::Protocols(vec![ PayloadU8(vec![ 0 ]) ]),
            ServerExtension::KeyShare(KeyShareEntry::new(NamedGroup::X25519, &[1, 2, 3])),
            ServerExtension::PresharedKey(3),
            ServerExtension::ExtendedMasterSecretAck,
            ServerExtension::CertificateStatusAck,
            ServerExtension::SignedCertificateTimestamp(vec![ PayloadU16(vec![0]) ]),
            ServerExtension::SupportedVersions(ProtocolVersion::TLSv1_2),
            ServerExtension::TransportParameters(vec![ 1, 2, 3 ]),
            ServerExtension::Unknown(UnknownExtension {
                typ: ExtensionType::Unknown(12345),
                payload: Payload(vec![ 1, 2, 3 ])
            })
        ]
    }
}

#[test]
fn can_print_all_serverextensions() {
    println!("server hello {:?}", get_sample_serverhellopayload());
}

#[test]
fn can_clone_all_serverextensions() {
    let _ = get_sample_serverhellopayload().extensions.clone();
}

fn get_sample_helloretryrequest() -> HelloRetryRequest {
    HelloRetryRequest {
        legacy_version: ProtocolVersion::TLSv1_2,
        session_id: SessionID::empty(),
        cipher_suite: CipherSuite::TLS_NULL_WITH_NULL_NULL,
        extensions: vec![
            HelloRetryExtension::KeyShare(NamedGroup::X25519),
            HelloRetryExtension::Cookie(PayloadU16(vec![ 0 ])),
            HelloRetryExtension::SupportedVersions(ProtocolVersion::TLSv1_2),
            HelloRetryExtension::Unknown(UnknownExtension {
                typ: ExtensionType::Unknown(12345),
                payload: Payload(vec![ 1, 2, 3 ])
            })
        ]
    }
}

fn get_sample_certificatepayloadtls13() -> CertificatePayloadTLS13 {
    CertificatePayloadTLS13 {
        context: PayloadU8(vec![ 1, 2, 3 ]),
        list: vec![
            CertificateEntry {
                cert: Certificate(vec![ 3, 4, 5]),
                exts: vec![
                    CertificateExtension::CertificateStatus(CertificateStatus {
                        ocsp_response: PayloadU24(vec![ 1, 2, 3 ])
                    }),
                    CertificateExtension::SignedCertificateTimestamp(vec![ PayloadU16(vec![0]) ]),
                    CertificateExtension::Unknown(UnknownExtension {
                        typ: ExtensionType::Unknown(12345),
                        payload: Payload(vec![ 1, 2, 3 ])
                    })
                ]
            }
        ]
    }
}

fn get_sample_serverkeyexchangepayload_ecdhe() -> ServerKeyExchangePayload {
    ServerKeyExchangePayload::ECDHE(ECDHEServerKeyExchange {
        params: ServerECDHParams {
            curve_params: ECParameters {
                curve_type: ECCurveType::NamedCurve,
                named_group: NamedGroup::X25519
            },
            public: PayloadU8(vec![ 1, 2, 3 ])
        },
        dss: DigitallySignedStruct {
            scheme: SignatureScheme::RSA_PSS_SHA256,
            sig: PayloadU16(vec![ 1, 2, 3 ])
        }
    })
}

fn get_sample_serverkeyexchangepayload_unknown() -> ServerKeyExchangePayload {
    ServerKeyExchangePayload::Unknown(Payload(vec![ 1, 2, 3 ]))
}

fn get_sample_certificaterequestpayload() -> CertificateRequestPayload {
    CertificateRequestPayload {
        certtypes: vec![ ClientCertificateType::RSASign ],
        sigschemes: SupportedSignatureSchemes::supported_verify(),
        canames: vec![ PayloadU16(vec![ 1, 2, 3 ]) ]
    }
}

fn get_sample_certificaterequestpayloadtls13() -> CertificateRequestPayloadTLS13 {
    CertificateRequestPayloadTLS13 {
        context: PayloadU8(vec![ 1, 2, 3 ]),
        extensions: vec![
            CertReqExtension::SignatureAlgorithms(SupportedSignatureSchemes::supported_verify()),
            CertReqExtension::AuthorityNames(vec![ PayloadU16(vec![ 1, 2, 3 ]) ]),
            CertReqExtension::Unknown(UnknownExtension {
                typ: ExtensionType::Unknown(12345),
                payload: Payload(vec![ 1, 2, 3 ])
            })
        ]
    }
}

fn get_sample_newsessionticketpayload() -> NewSessionTicketPayload {
    NewSessionTicketPayload {
        lifetime_hint: 1234,
        ticket: PayloadU16(vec![ 1, 2, 3 ]),
    }
}

fn get_sample_newsessionticketpayloadtls13() -> NewSessionTicketPayloadTLS13 {
    NewSessionTicketPayloadTLS13 {
        lifetime: 123,
        age_add: 1234,
        nonce: PayloadU8(vec![ 1, 2, 3 ]),
        ticket: PayloadU16(vec![ 4, 5, 6 ]),
        exts: vec![
            NewSessionTicketExtension::Unknown(UnknownExtension {
                typ: ExtensionType::Unknown(12345),
                payload: Payload(vec![ 1, 2, 3 ])
            })
        ]
    }
}

fn get_sample_encryptedextensions() -> EncryptedExtensions {
    get_sample_serverhellopayload().extensions
}

fn get_sample_certificatestatus() -> CertificateStatus {
    CertificateStatus {
        ocsp_response: PayloadU24(vec![ 1, 2, 3 ])
    }
}

#[test]
fn can_roundtrip_all_tls12_handshake_payloads() {
    let hms = [
        HandshakeMessagePayload {
            typ: HandshakeType::HelloRequest,
            payload: HandshakePayload::HelloRequest,
        },
        HandshakeMessagePayload {
            typ: HandshakeType::ClientHello,
            payload: HandshakePayload::ClientHello(get_sample_clienthellopayload()),
        },
        HandshakeMessagePayload {
            typ: HandshakeType::ServerHello,
            payload: HandshakePayload::ServerHello(get_sample_serverhellopayload()),
        },
        HandshakeMessagePayload {
            typ: HandshakeType::HelloRetryRequest,
            payload: HandshakePayload::HelloRetryRequest(get_sample_helloretryrequest()),
        },
        HandshakeMessagePayload {
            typ: HandshakeType::Certificate,
            payload: HandshakePayload::Certificate(vec![ Certificate(vec![ 1, 2, 3 ]) ]),
        },
        HandshakeMessagePayload {
            typ: HandshakeType::ServerKeyExchange,
            payload: HandshakePayload::ServerKeyExchange(get_sample_serverkeyexchangepayload_ecdhe()),
        },
        HandshakeMessagePayload {
            typ: HandshakeType::ServerKeyExchange,
            payload: HandshakePayload::ServerKeyExchange(get_sample_serverkeyexchangepayload_unknown()),
        },
        HandshakeMessagePayload {
            typ: HandshakeType::CertificateRequest,
            payload: HandshakePayload::CertificateRequest(get_sample_certificaterequestpayload()),
        },
        HandshakeMessagePayload {
            typ: HandshakeType::ServerHelloDone,
            payload: HandshakePayload::ServerHelloDone,
        },
        HandshakeMessagePayload {
            typ: HandshakeType::ClientKeyExchange,
            payload: HandshakePayload::ClientKeyExchange(Payload(vec![ 1, 2, 3 ])),
        },
        HandshakeMessagePayload {
            typ: HandshakeType::NewSessionTicket,
            payload: HandshakePayload::NewSessionTicket(get_sample_newsessionticketpayload()),
        },
        HandshakeMessagePayload {
            typ: HandshakeType::EncryptedExtensions,
            payload: HandshakePayload::EncryptedExtensions(get_sample_encryptedextensions()),
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
            payload: HandshakePayload::Finished(Payload(vec![ 1, 2, 3 ])),
        },
        HandshakeMessagePayload {
            typ: HandshakeType::CertificateStatus,
            payload: HandshakePayload::CertificateStatus(get_sample_certificatestatus()),
        },
        HandshakeMessagePayload {
            typ: HandshakeType::Unknown(99),
            payload: HandshakePayload::Unknown(Payload(vec![ 1, 2, 3 ])),
        },
    ];

    for ref hm in hms.iter() {
        println!("{:?}", hm.typ);
        let bytes = hm.get_encoding();
        let mut rd = Reader::init(&bytes);
        let other = HandshakeMessagePayload::read_version(&mut rd, ProtocolVersion::TLSv1_2)
            .unwrap();
        assert_eq!(rd.any_left(), false);
        assert_eq!(hm.get_encoding(), other.get_encoding());

        println!("{:?}", hm);
        println!("{:?}", other);
    }
}

#[test]
fn can_roundtrip_all_tls13_handshake_payloads() {
    let hms = [
        HandshakeMessagePayload {
            typ: HandshakeType::HelloRequest,
            payload: HandshakePayload::HelloRequest,
        },
        HandshakeMessagePayload {
            typ: HandshakeType::ClientHello,
            payload: HandshakePayload::ClientHello(get_sample_clienthellopayload()),
        },
        HandshakeMessagePayload {
            typ: HandshakeType::ServerHello,
            payload: HandshakePayload::ServerHello(get_sample_serverhellopayload()),
        },
        HandshakeMessagePayload {
            typ: HandshakeType::HelloRetryRequest,
            payload: HandshakePayload::HelloRetryRequest(get_sample_helloretryrequest()),
        },
        HandshakeMessagePayload {
            typ: HandshakeType::Certificate,
            payload: HandshakePayload::CertificateTLS13(get_sample_certificatepayloadtls13()),
        },
        HandshakeMessagePayload {
            typ: HandshakeType::ServerKeyExchange,
            payload: HandshakePayload::ServerKeyExchange(get_sample_serverkeyexchangepayload_ecdhe()),
        },
        HandshakeMessagePayload {
            typ: HandshakeType::ServerKeyExchange,
            payload: HandshakePayload::ServerKeyExchange(get_sample_serverkeyexchangepayload_unknown()),
        },
        HandshakeMessagePayload {
            typ: HandshakeType::CertificateRequest,
            payload: HandshakePayload::CertificateRequestTLS13(get_sample_certificaterequestpayloadtls13()),
        },
        HandshakeMessagePayload {
            typ: HandshakeType::ServerHelloDone,
            payload: HandshakePayload::ServerHelloDone,
        },
        HandshakeMessagePayload {
            typ: HandshakeType::ClientKeyExchange,
            payload: HandshakePayload::ClientKeyExchange(Payload(vec![ 1, 2, 3 ])),
        },
        HandshakeMessagePayload {
            typ: HandshakeType::NewSessionTicket,
            payload: HandshakePayload::NewSessionTicketTLS13(get_sample_newsessionticketpayloadtls13()),
        },
        HandshakeMessagePayload {
            typ: HandshakeType::EncryptedExtensions,
            payload: HandshakePayload::EncryptedExtensions(get_sample_encryptedextensions()),
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
            payload: HandshakePayload::Finished(Payload(vec![ 1, 2, 3 ])),
        },
        HandshakeMessagePayload {
            typ: HandshakeType::CertificateStatus,
            payload: HandshakePayload::CertificateStatus(get_sample_certificatestatus()),
        },
        HandshakeMessagePayload {
            typ: HandshakeType::Unknown(99),
            payload: HandshakePayload::Unknown(Payload(vec![ 1, 2, 3 ])),
        },
    ];

    for ref hm in hms.iter() {
        println!("{:?}", hm.typ);
        let bytes = hm.get_encoding();
        let mut rd = Reader::init(&bytes);

        let other = HandshakeMessagePayload::read_version(&mut rd, ProtocolVersion::TLSv1_3)
            .unwrap();
        assert_eq!(rd.any_left(), false);
        assert_eq!(hm.get_encoding(), other.get_encoding());

        println!("{:?}", hm);
        println!("{:?}", other);
    }
}
