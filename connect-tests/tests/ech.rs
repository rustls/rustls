mod ech_config {
    use hickory_resolver::config::{ResolverConfig, ResolverOpts};
    use hickory_resolver::proto::rr::rdata::svcb::{SvcParamKey, SvcParamValue};
    use hickory_resolver::proto::rr::{RData, RecordType};
    use hickory_resolver::Resolver;
    use rustls::internal::msgs::codec::{Codec, Reader};
    use rustls::internal::msgs::enums::EchVersion;
    use rustls::internal::msgs::handshake::EchConfig;

    #[test]
    fn cloudflare() {
        test_deserialize_ech_config("crypto.cloudflare.com");
    }

    #[test]
    fn defo_ie() {
        test_deserialize_ech_config("defo.ie");
    }

    #[test]
    fn tls_ech_dev() {
        test_deserialize_ech_config("tls-ech.dev");
    }

    /// Lookup the ECH config for a domain and deserialize it.
    fn test_deserialize_ech_config(domain: &str) {
        let resolver =
            Resolver::new(ResolverConfig::google_https(), ResolverOpts::default()).unwrap();
        let raw_value = lookup_ech(&resolver, domain);
        let parsed_config = EchConfig::read(&mut Reader::init(&raw_value))
            .expect("failed to deserialize ECH config");
        assert_eq!(parsed_config.version, EchVersion::V14);
    }

    /// Use `resolver` to make an HTTPS record type query for `domain`, returning the
    /// first SvcParam EchConfig value found, panicing if none are returned.
    fn lookup_ech(resolver: &Resolver, domain: &str) -> Vec<u8> {
        resolver
            .lookup(domain, RecordType::HTTPS)
            .expect("failed to lookup HTTPS record type")
            .record_iter()
            .find_map(|r| match r.data() {
                Some(RData::HTTPS(svcb)) => svcb
                    .svc_params()
                    .iter()
                    .find_map(|sp| match sp {
                        (SvcParamKey::EchConfig, SvcParamValue::EchConfig(e)) => Some(e.clone().0),
                        _ => None,
                    }),
                _ => None,
            })
            .expect("missing expected HTTPS SvcParam EchConfig record")
    }
}
