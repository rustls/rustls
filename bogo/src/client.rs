use core::fmt;
use core::hash::Hasher;
use core::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerIdentity, ServerVerifier};
use rustls::client::{
    self, ClientSessionKey, CredentialRequest, EchConfig, EchGreaseConfig, EchMode, Resumption,
    Tls12Resumption, Tls13Session, WebPkiServerVerifier,
};
use rustls::crypto::hpke::HpkePublicKey;
use rustls::crypto::kx::NamedGroup;
use rustls::crypto::{
    Credentials, CryptoProvider, Identity, SelectedCredential, SignatureScheme, Signer, SigningKey,
    VerifiedIdentity,
};
use rustls::enums::{ApplicationProtocol, CertificateType};
use rustls::error::{ApiMisuse, CertificateError, EncryptedClientHelloError};
use rustls::pki_types::{ServerName, SubjectPublicKeyInfoDer};
use rustls::server::danger::SignatureVerificationInput;
use rustls::{ClientConfig, DistinguishedName, Error};

use super::compress::{CompressionAlgs, ExpandingAlgorithm, RandomAlgorithm, ShrinkingAlgorithm};
use super::opts::Options;
use super::{
    ALL_HPKE_SUITES, Credential, GREASE_25519_PUBKEY, GREASE_HPKE_SUITE, KeyLogMemo,
    load_root_certs, lookup_scheme, quit,
};

pub(crate) fn config(opts: &Options, key_log: &Arc<KeyLogMemo>) -> Arc<ClientConfig> {
    let provider = Arc::new(opts.provider());
    let cfg = ClientConfig::builder(provider.clone());

    let cfg = if opts.selected_provider.supports_ech() {
        let ech_cfg = ClientConfig::builder(
            CryptoProvider {
                tls12_cipher_suites: Default::default(),
                ..opts.provider()
            }
            .into(),
        );

        if let Some(ech_config_list) = &opts.ech_config_list {
            let ech_mode = match EchConfig::new(ech_config_list.clone(), ALL_HPKE_SUITES) {
                Ok(ech_config) => EchMode::from(ech_config),
                Err(Error::InvalidEncryptedClientHello(
                    EncryptedClientHelloError::NoCompatibleConfig,
                )) if opts.reject_unusable_ech_config => quit(":UNUSABLE_ECH_CONFIG_LIST:"),
                Err(_) => quit(":INVALID_ECH_CONFIG_LIST:"),
            };

            ech_cfg.with_ech(ech_mode)
        } else if opts.reject_unusable_ech_config {
            // no ech_config_list is a trivial rejection (boringssl has a more complex API that is tested here)
            quit(":UNUSABLE_ECH_CONFIG_LIST:");
        } else if opts.enable_ech_grease {
            let ech_mode = EchMode::Grease(EchGreaseConfig::new(
                GREASE_HPKE_SUITE,
                HpkePublicKey(GREASE_25519_PUBKEY.to_vec()),
            ));

            ech_cfg.with_ech(ech_mode)
        } else {
            cfg
        }
    } else {
        cfg
    };

    let cfg = cfg
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(DummyServerAuth::new(
            &opts.trusted_cert_file,
            opts.ocsp,
            opts.expected_server_names(),
            &provider,
        )));

    let mut cfg = match opts.credentials.configured() {
        true => {
            let mut resolver = MultipleClientCredentialResolver {
                expect_selected: opts.credentials.expect_selected,
                ..Default::default()
            };

            if opts.credentials.default.configured() {
                let cred = &opts.credentials.default;
                resolver.set_default(cred.load_from_file(&provider), cred)
            }

            for cred in opts.credentials.additional.iter() {
                resolver.add(cred.load_from_file(&provider), cred);
            }

            cfg.with_client_credential_resolver(Arc::new(resolver))
                .unwrap()
        }
        false => match cfg.with_no_client_auth() {
            Ok(cfg) => cfg,
            Err(Error::ApiMisuse(ApiMisuse::NoCipherSuitesConfigured))
                if opts.reject_unusable_ech_config =>
            {
                quit(":UNUSABLE_ECH_CONFIG_LIST:")
            }
            Err(other) => panic!("unexpected error {other:?}"),
        },
    };

    cfg.resumption = Resumption::store(ClientCacheWithSpecificKxHints::new(
        opts.resumption_delay,
        opts.server_supported_group_hint,
    ))
    .tls12_resumption(match opts.tickets {
        true => Tls12Resumption::SessionIdOrTickets,
        false => Tls12Resumption::SessionIdOnly,
    });
    cfg.enable_sni = opts.use_sni;
    cfg.max_fragment_size = opts.max_fragment;
    cfg.require_ems = opts.require_ems;
    if opts.export_traffic_secrets {
        cfg.key_log = key_log.clone();
    }

    if !opts.protocols.is_empty() {
        cfg.alpn_protocols = opts
            .protocols
            .iter()
            .map(|proto| ApplicationProtocol::from(proto.as_bytes()).to_owned())
            .collect();
    }

    if opts.enable_early_data {
        cfg.enable_early_data = true;
    }

    match opts.install_cert_compression_algs {
        CompressionAlgs::All => {
            cfg.cert_decompressors =
                vec![&ExpandingAlgorithm, &ShrinkingAlgorithm, &RandomAlgorithm];
            cfg.cert_compressors = vec![&ExpandingAlgorithm, &ShrinkingAlgorithm, &RandomAlgorithm];
        }
        CompressionAlgs::One(ShrinkingAlgorithm::ALGORITHM) => {
            cfg.cert_decompressors = vec![&ShrinkingAlgorithm];
            cfg.cert_compressors = vec![&ShrinkingAlgorithm];
        }
        CompressionAlgs::None => {}
        _ => unimplemented!(),
    }

    Arc::new(cfg)
}

#[derive(Debug)]
struct DummyServerAuth {
    parent: Arc<dyn ServerVerifier>,
    ocsp: OcspValidation,
    expect_server_names: Vec<ServerName<'static>>,
    server_name_index: AtomicUsize,
}

impl DummyServerAuth {
    fn new(
        trusted_cert_file: &str,
        ocsp: OcspValidation,
        expect_server_names: Vec<ServerName<'static>>,
        provider: &CryptoProvider,
    ) -> Self {
        Self {
            parent: Arc::new(
                WebPkiServerVerifier::builder(load_root_certs(trusted_cert_file), provider)
                    .build()
                    .unwrap(),
            ),
            ocsp,
            expect_server_names,
            server_name_index: AtomicUsize::new(0),
        }
    }
}

impl ServerVerifier for DummyServerAuth {
    fn verify_identity<'a>(
        &self,
        identity: &ServerIdentity<'a, '_>,
    ) -> Result<VerifiedIdentity<'a>, Error> {
        if !self.expect_server_names.is_empty() {
            let expect_server_name = &self.expect_server_names[self
                .server_name_index
                .fetch_add(1, Ordering::SeqCst)];
            assert_eq!(identity.server_name, expect_server_name);
        }
        if let OcspValidation::Reject = self.ocsp {
            return Err(CertificateError::InvalidOcspResponse.into());
        }
        Ok(VerifiedIdentity::assertion(identity.identity.clone()))
    }

    fn verify_tls12_signature(
        &self,
        input: &SignatureVerificationInput<'_>,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.parent
            .verify_tls12_signature(input)
    }

    fn verify_tls13_signature(
        &self,
        input: &SignatureVerificationInput<'_>,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.parent
            .verify_tls13_signature(input)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.parent.supported_verify_schemes()
    }

    fn request_ocsp_response(&self) -> bool {
        true
    }

    fn hash_config(&self, h: &mut dyn Hasher) {
        self.parent.hash_config(h)
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) enum OcspValidation {
    /// Totally ignore `ocsp_response` value
    #[default]
    None,

    /// Return an error (irrespective of `ocsp_response` value)
    Reject,
}

#[derive(Debug, Default)]
struct MultipleClientCredentialResolver {
    additional: Vec<ClientCert>,
    default: Option<ClientCert>,
    expect_selected: Option<isize>,
}

impl MultipleClientCredentialResolver {
    fn add(&mut self, key: Credentials, meta: &Credential) {
        self.additional
            .push(ClientCert::new(key, meta));
    }

    fn set_default(&mut self, key: Credentials, meta: &Credential) {
        self.default = Some(ClientCert::new(key, meta));
    }
}

impl client::ClientCredentialResolver for MultipleClientCredentialResolver {
    fn resolve(&self, request: &CredentialRequest<'_>) -> Option<SelectedCredential> {
        // `sig_schemes` is in server preference order, so respect that.
        let sig_schemes = request.signature_schemes();
        let root_hint_subjects = request.root_hint_subjects();
        for sig_scheme in sig_schemes.iter().copied() {
            for (i, cert) in self.additional.iter().enumerate() {
                // if the server sends any issuer hints, respect them
                if cert.must_match_issuer && !cert.any_issuer_matches_hints(root_hint_subjects) {
                    continue;
                }

                if let Some(signer) = cert.certkey.signer(&[sig_scheme]) {
                    assert!(
                        Some(i as isize) == self.expect_selected || self.expect_selected.is_none()
                    );
                    return Some(signer);
                }
            }
        }

        if let Some(cert) = &self.default
            && let Some(signer) = cert.certkey.signer(sig_schemes)
        {
            assert!(matches!(self.expect_selected, Some(-1) | None));
            return Some(signer);
        }

        assert_eq!(self.expect_selected, None);

        let all_must_match_issuer = self
            .additional
            .iter()
            .chain(self.default.iter())
            .all(|item| item.must_match_issuer);

        quit(match all_must_match_issuer {
            true => ":NO_MATCHING_ISSUER:",
            false => ":NO_COMMON_SIGNATURE_ALGORITHMS:",
        })
    }

    fn supported_certificate_types(&self) -> &'static [CertificateType] {
        match self.default.is_some() || !self.additional.is_empty() {
            true => &[CertificateType::X509],
            false => &[],
        }
    }

    fn hash_config(&self, _: &mut dyn Hasher) {}
}

#[derive(Debug)]
struct ClientCert {
    certkey: Credentials,
    issuer_names: Vec<DistinguishedName>,
    must_match_issuer: bool,
}

impl ClientCert {
    fn new(mut certkey: Credentials, meta: &Credential) -> Self {
        let Identity::X509(id) = &*certkey.identity else {
            panic!("only X.509 client certs supported");
        };

        let mut issuer_names = Vec::new();
        for cert in [&id.end_entity]
            .into_iter()
            .chain(id.intermediates.iter())
        {
            let parsed_cert = webpki::EndEntityCert::try_from(cert).unwrap();
            issuer_names.push(DistinguishedName::in_sequence(parsed_cert.issuer()));
        }

        if let Some(scheme) = meta.use_signing_scheme {
            certkey.key = Box::new(FixedSignatureSchemeSigningKey {
                key: certkey.key,
                scheme: lookup_scheme(scheme),
            });
        }

        Self {
            certkey,
            issuer_names,
            must_match_issuer: meta.must_match_issuer,
        }
    }

    fn any_issuer_matches_hints(&self, hints: &[DistinguishedName]) -> bool {
        hints.iter().any(|dn| {
            self.issuer_names
                .iter()
                .any(|issuer| dn.as_ref() == issuer.as_ref())
        })
    }
}

#[derive(Debug)]
struct FixedSignatureSchemeSigningKey {
    key: Box<dyn SigningKey>,
    scheme: SignatureScheme,
}

impl SigningKey for FixedSignatureSchemeSigningKey {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        if offered.contains(&self.scheme) {
            self.key.choose_scheme(&[self.scheme])
        } else {
            self.key.choose_scheme(&[])
        }
    }

    fn public_key(&self) -> Option<SubjectPublicKeyInfoDer<'_>> {
        self.key.public_key()
    }
}

struct ClientCacheWithSpecificKxHints {
    delay: u32,
    kx_hint: Option<NamedGroup>,
    storage: Arc<client::ClientSessionMemoryCache>,
}

impl ClientCacheWithSpecificKxHints {
    fn new(delay: u32, kx_hint: Option<NamedGroup>) -> Arc<Self> {
        Arc::new(Self {
            delay,
            kx_hint,
            storage: Arc::new(client::ClientSessionMemoryCache::new(32)),
        })
    }
}

impl client::ClientSessionStore for ClientCacheWithSpecificKxHints {
    fn set_kx_hint(&self, _: ClientSessionKey<'static>, _: NamedGroup) {}
    fn kx_hint(&self, _: &ClientSessionKey<'_>) -> Option<NamedGroup> {
        self.kx_hint
    }

    fn set_tls12_session(&self, key: ClientSessionKey<'static>, mut value: client::Tls12Session) {
        value.rewind_epoch(self.delay);
        self.storage
            .set_tls12_session(key, value);
    }

    fn tls12_session(&self, key: &ClientSessionKey<'_>) -> Option<client::Tls12Session> {
        self.storage.tls12_session(key)
    }

    fn remove_tls12_session(&self, key: &ClientSessionKey<'static>) {
        self.storage.remove_tls12_session(key);
    }

    fn insert_tls13_ticket(&self, key: ClientSessionKey<'static>, mut value: Tls13Session) {
        value.rewind_epoch(self.delay);
        self.storage
            .insert_tls13_ticket(key, value)
    }

    fn take_tls13_ticket(&self, key: &ClientSessionKey<'static>) -> Option<Tls13Session> {
        self.storage.take_tls13_ticket(key)
    }
}

impl fmt::Debug for ClientCacheWithSpecificKxHints {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Note: we omit self.storage here as it may contain sensitive data.
        f.debug_struct("ClientCacheWithoutKxHints")
            .field("delay", &self.delay)
            .finish_non_exhaustive()
    }
}
