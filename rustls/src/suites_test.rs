use super::suites::*;
use crate::msgs::enums::CipherSuite;
use crate::ProtocolVersion;

#[test]
fn test_client_pref() {
    let client = vec![
        CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    ];
    let server = vec![
        &TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        &TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    ];
    let chosen = choose_ciphersuite_preferring_client(&client, &server);
    assert!(chosen.is_some());
    assert_eq!(chosen.unwrap(), &TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256);
}

#[test]
fn test_server_pref() {
    let client = vec![
        CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    ];
    let server = vec![
        &TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        &TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    ];
    let chosen = choose_ciphersuite_preferring_server(&client, &server);
    assert!(chosen.is_some());
    assert_eq!(chosen.unwrap(), &TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384);
}

#[test]
fn test_pref_fails() {
    assert!(
        choose_ciphersuite_preferring_client(
            &[CipherSuite::TLS_NULL_WITH_NULL_NULL],
            ALL_CIPHERSUITES
        )
        .is_none()
    );
    assert!(
        choose_ciphersuite_preferring_server(
            &[CipherSuite::TLS_NULL_WITH_NULL_NULL],
            ALL_CIPHERSUITES
        )
        .is_none()
    );
}

#[test]
fn test_scs_is_debug() {
    println!("{:?}", ALL_CIPHERSUITES);
}

#[test]
fn test_usable_for_version() {
    fn ok_tls13(scs: &SupportedCipherSuite) {
        assert!(!scs.usable_for_version(ProtocolVersion::TLSv1_0));
        assert!(!scs.usable_for_version(ProtocolVersion::TLSv1_2));
        assert!(scs.usable_for_version(ProtocolVersion::TLSv1_3));
    }

    fn ok_tls12(scs: &SupportedCipherSuite) {
        assert!(!scs.usable_for_version(ProtocolVersion::TLSv1_0));
        assert!(scs.usable_for_version(ProtocolVersion::TLSv1_2));
        assert!(!scs.usable_for_version(ProtocolVersion::TLSv1_3));
    }

    ok_tls13(&TLS13_CHACHA20_POLY1305_SHA256);
    ok_tls13(&TLS13_AES_256_GCM_SHA384);
    ok_tls13(&TLS13_AES_128_GCM_SHA256);

    ok_tls12(&TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256);
    ok_tls12(&TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256);
    ok_tls12(&TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384);
    ok_tls12(&TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256);
    ok_tls12(&TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384);
}

#[test]
fn test_can_resume_to() {
    assert!(TLS13_CHACHA20_POLY1305_SHA256.can_resume_to(&TLS13_AES_128_GCM_SHA256));
    assert!(!TLS13_CHACHA20_POLY1305_SHA256.can_resume_to(&TLS13_AES_256_GCM_SHA384));
    assert!(
        !TLS13_CHACHA20_POLY1305_SHA256
            .can_resume_to(&TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256)
    );
    assert!(
        !TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
            .can_resume_to(&TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256)
    );
    assert!(
        TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
            .can_resume_to(&TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256)
    );
}
