mod ech_config {
    use hickory_resolver::config::{ResolverConfig, ResolverOpts};
    use hickory_resolver::proto::rr::rdata::svcb::{SvcParamKey, SvcParamValue};
    use hickory_resolver::proto::rr::{RData, RecordType};
    use hickory_resolver::{Resolver, TokioResolver};
    use rustls::internal::msgs::codec::{Codec, Reader};
    use rustls::internal::msgs::handshake::EchConfigPayload;
    use rustls::pki_types::EchConfigListBytes;

    #[tokio::test]
    async fn cloudflare() {
        test_deserialize_ech_config_list("research.cloudflare.com").await;
    }

    #[tokio::test]
    async fn defo_ie() {
        test_deserialize_ech_config_list("defo.ie").await;
    }

    #[tokio::test]
    async fn tls_ech_dev() {
        test_deserialize_ech_config_list("tls-ech.dev").await;
    }

    /// Lookup the ECH config list for a domain and deserialize it.
    async fn test_deserialize_ech_config_list(domain: &str) {
        let resolver = Resolver::tokio(ResolverConfig::google_https(), ResolverOpts::default());
        let tls_encoded_list = lookup_ech(&resolver, domain).await;
        let parsed_configs = Vec::<EchConfigPayload>::read(&mut Reader::init(&tls_encoded_list))
            .expect("failed to deserialize ECH config list");
        assert!(!parsed_configs.is_empty());
        assert!(parsed_configs
            .iter()
            .all(|config| matches!(config, EchConfigPayload::V18(_))));
    }

    /// Use `resolver` to make an HTTPS record type query for `domain`, returning the
    /// first SvcParam EchConfig value found, panicking if none are returned.
    async fn lookup_ech(resolver: &TokioResolver, domain: &str) -> EchConfigListBytes<'static> {
        resolver
            .lookup(domain, RecordType::HTTPS)
            .await
            .expect("failed to lookup HTTPS record type")
            .record_iter()
            .find_map(|r| match r.data() {
                RData::HTTPS(svcb) => svcb
                    .svc_params()
                    .iter()
                    .find_map(|sp| match sp {
                        (SvcParamKey::EchConfigList, SvcParamValue::EchConfigList(e)) => {
                            Some(e.clone().0)
                        }
                        _ => None,
                    }),
                _ => None,
            })
            .expect("missing expected HTTPS SvcParam EchConfig record")
            .into()
    }
}
