// These tests use the various test servers run by Google
// at badssl.com.

#[allow(dead_code)]
mod common;

mod online {
    use super::common::TlsClient;

    fn connect(hostname: &str) -> TlsClient {
        TlsClient::new(hostname)
    }

    #[test]
    fn no_cbc() {
        connect("cbc.badssl.com")
            .fails()
            .expect(r"TLS error: received fatal alert: HandshakeFailure")
            .go()
            .unwrap();
    }

    #[test]
    fn no_rc4() {
        connect("rc4.badssl.com")
            .fails()
            .expect(r"TLS error: received fatal alert: HandshakeFailure")
            .go()
            .unwrap();
    }

    #[test]
    fn expired() {
        connect("expired.badssl.com")
            .fails()
            .expect(r"TLS error: invalid peer certificate: certificate expired: verification time [0-9]+ \(UNIX\), but certificate is not valid after [0-9]+ \([0-9]+ seconds ago\)")
            .go()
            .unwrap();
    }

    #[test]
    fn wrong_host() {
        connect("wrong.host.badssl.com")
            .fails()
            .expect(r#"TLS error: invalid peer certificate: certificate not valid for name \"wrong.host.badssl.com\"; certificate is only valid for DnsName\(\"\*.badssl.com\"\) or DnsName\(\"badssl.com\"\)"#)
            .go()
            .unwrap();
    }

    #[test]
    fn self_signed() {
        connect("self-signed.badssl.com")
            .fails()
            .expect(r"TLS error: invalid peer certificate: UnknownIssuer")
            .go()
            .unwrap();
    }

    #[test]
    fn no_dh() {
        connect("dh2048.badssl.com")
            .fails()
            .expect(r"TLS error: received fatal alert: HandshakeFailure")
            .go()
            .unwrap();
    }

    #[test]
    fn mozilla_old() {
        connect("mozilla-old.badssl.com")
            .expect("<title>mozilla-old.badssl.com</title>")
            .go()
            .unwrap();
    }

    #[test]
    fn mozilla_inter() {
        connect("mozilla-intermediate.badssl.com")
            .expect("<title>mozilla-intermediate.badssl.com</title>")
            .go()
            .unwrap();
    }

    #[test]
    fn mozilla_modern() {
        connect("mozilla-modern.badssl.com")
            .expect("<title>mozilla-modern.badssl.com</title>")
            .go()
            .unwrap();
    }

    #[test]
    fn sha256() {
        connect("sha256.badssl.com")
            .expect("<title>sha256.badssl.com</title>")
            .go()
            .unwrap();
    }

    #[test]
    fn too_many_sans() {
        connect("10000-sans.badssl.com")
            .fails()
            .expect(r"TLS error: received corrupt message of type HandshakePayloadTooLarge")
            .go()
            .unwrap();
    }

    #[ignore] // https://github.com/chromium/badssl.com/issues/530
    #[test]
    fn rsa8192() {
        connect("rsa8192.badssl.com")
            .expect("<title>rsa8192.badssl.com</title>")
            .go()
            .unwrap();
    }

    #[test]
    fn sha1_2016() {
        connect("sha1-2016.badssl.com")
            .fails()
            .expect(r"TLS error: invalid peer certificate: certificate expired: verification time [0-9]+ \(UNIX\), but certificate is not valid after [0-9]+ \([0-9]+ seconds ago\)")
            .go()
            .unwrap();
    }

    mod danger {
        #[test]
        fn self_signed() {
            super::connect("self-signed.badssl.com")
                .insecure()
                .expect("<title>self-signed.badssl.com</title>")
                .go()
                .unwrap();
        }
    }
}
