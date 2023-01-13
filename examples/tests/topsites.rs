// These tests check we can handshake with a selection of
// common hosts.
//
// Rules: only hosts that can really handle the traffic.

#[allow(dead_code)]
mod common;

mod online {
    use super::common::TlsClient;

    fn check(hostname: &str) {
        TlsClient::new(hostname)
            .expect("HTTP/1.[01] ")
            .go()
            .unwrap()
    }

    #[test]
    fn joe() {
        check("jbp.io")
    }

    #[test]
    fn google() {
        check("google.com")
    }

    #[test]
    fn github() {
        check("github.com")
    }

    #[test]
    fn aws() {
        check("aws.amazon.com")
    }

    #[test]
    fn microsoft() {
        check("www.microsoft.com")
    }

    #[test]
    fn wikipedia() {
        check("www.wikipedia.org")
    }

    #[test]
    fn twitter() {
        check("twitter.com")
    }

    #[test]
    fn facebook() {
        check("www.facebook.com")
    }

    #[test]
    fn baidu() {
        check("www.baidu.com")
    }

    #[test]
    fn netflix() {
        check("www.netflix.com")
    }

    #[test]
    fn stackoverflow() {
        check("stackoverflow.com")
    }

    #[test]
    fn apple() {
        check("www.apple.com")
    }

    #[test]
    fn cloudflare_1_1_1_1_dns() {
        check("1.1.1.1")
    }
}
