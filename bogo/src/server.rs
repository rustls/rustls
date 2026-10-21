use std::sync::Arc;

use rustls::client::danger::HandshakeSignatureValid;
use rustls::crypto::{
    Credentials, CryptoProvider, Identity, SelectedCredential, SignatureScheme, SingleCredential,
    VerifiedIdentity,
};
use rustls::enums::ApplicationProtocol;
use rustls::error::PeerIncompatible;
use rustls::server::danger::{ClientIdentity, ClientVerifier, SignatureVerificationInput};
use rustls::server::{
    self, ClientHello, PreferClientOrder, PreferServerOrder, ServerSessionKey, Tls13Tickets,
    TrustAnchorResolver, WebPkiClientVerifier,
};
use rustls::{DistinguishedName, Error, ServerConfig, TrustAnchorId};

use super::opts::Options;
use super::{KeyLogMemo, load_root_certs, quit};
use crate::compress::{CompressionAlgs, ExpandingAlgorithm, RandomAlgorithm, ShrinkingAlgorithm};
use crate::lookup_scheme;

pub(crate) fn config(opts: &Options, key_log: &Arc<KeyLogMemo>) -> Arc<ServerConfig> {
    let provider = opts.provider();
    let client_auth =
        if opts.verify_peer || opts.offer_no_client_cas || opts.require_any_client_cert {
            Arc::new(DummyClientAuth::new(
                &opts.trusted_cert_file,
                opts.require_any_client_cert,
                Arc::from(opts.root_hint_subjects.clone()),
                &provider,
            ))
        } else {
            WebPkiClientVerifier::no_client_auth()
        };

    let cred = &opts.credentials.default;
    let cert_resolver =
        if !opts.credentials.additional.is_empty() || opts.available_trust_anchors.is_some() {
            Arc::new(MultipleServerCredentialResolver::new(opts, &provider))
        } else {
            let mut credentials = cred.load_from_file(&provider);
            credentials.ocsp = Some(opts.server_ocsp_response.clone());

            match cred.use_signing_scheme {
                Some(scheme) => Arc::new(FixedSignatureSchemeServerCertResolver {
                    credentials,
                    scheme: lookup_scheme(scheme),
                }) as Arc<dyn server::ServerCredentialResolver>,
                None => Arc::new(SingleCredential::from(credentials)),
            }
        };

    let mut cfg = ServerConfig::builder(Arc::new(provider))
        .with_client_cert_verifier(client_auth)
        .with_server_credential_resolver(cert_resolver)
        .unwrap();

    cfg.session_storage = ServerCacheWithResumptionDelay::new(opts.resumption_delay);
    cfg.max_fragment_size = opts.max_fragment;
    cfg.send_tls13_tickets = Tls13Tickets { default: 1, max: 1 };
    cfg.require_ems = opts.require_ems;
    cfg.cipher_suite_selector = match opts.server_preference {
        true => &PreferServerOrder,
        false => &PreferClientOrder,
    };

    if opts.export_traffic_secrets {
        cfg.key_log = key_log.clone();
    }

    if opts.tickets {
        cfg.ticketer = Some(
            cfg.provider()
                .ticketer_factory
                .ticketer()
                .unwrap(),
        );
    } else if opts.resumes == 0 {
        cfg.session_storage = Arc::new(server::NoServerSessionStorage {});
    }

    if !opts.protocols.is_empty() {
        cfg.alpn_protocols = opts
            .protocols
            .iter()
            .map(|proto| ApplicationProtocol::from(proto.as_bytes()).to_owned())
            .collect::<Vec<_>>();
    }

    if opts.reject_alpn {
        cfg.alpn_protocols = vec![ApplicationProtocol::from(b"invalid")];
    }

    if opts.enable_early_data {
        // see kMaxEarlyDataAccepted in boringssl, which bogo validates
        cfg.max_early_data_size = 14336;
        cfg.send_half_rtt_data = true;
    }

    match opts.install_cert_compression_algs {
        CompressionAlgs::All => {
            cfg.cert_compressors = vec![&ExpandingAlgorithm, &ShrinkingAlgorithm, &RandomAlgorithm];
            cfg.cert_decompressors =
                vec![&ExpandingAlgorithm, &ShrinkingAlgorithm, &RandomAlgorithm];
        }
        CompressionAlgs::One(ShrinkingAlgorithm::ALGORITHM) => {
            cfg.cert_compressors = vec![&ShrinkingAlgorithm];
            cfg.cert_decompressors = vec![&ShrinkingAlgorithm];
        }
        CompressionAlgs::None => {}
        _ => unimplemented!(),
    }

    Arc::new(cfg)
}

#[derive(Debug)]
pub(crate) struct DummyClientAuth {
    mandatory: bool,
    root_hint_subjects: Arc<[DistinguishedName]>,
    parent: Arc<dyn ClientVerifier>,
}

impl DummyClientAuth {
    fn new(
        trusted_cert_file: &str,
        mandatory: bool,
        root_hint_subjects: Arc<[DistinguishedName]>,
        provider: &CryptoProvider,
    ) -> Self {
        Self {
            mandatory,
            root_hint_subjects,
            parent: Arc::new(
                WebPkiClientVerifier::builder(load_root_certs(trusted_cert_file), provider)
                    .build()
                    .unwrap(),
            ),
        }
    }
}

impl ClientVerifier for DummyClientAuth {
    fn verify_identity<'a>(
        &self,
        identity: &ClientIdentity<'a, '_>,
    ) -> Result<VerifiedIdentity<'a>, Error> {
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

    fn root_hint_subjects(&self) -> Arc<[DistinguishedName]> {
        self.root_hint_subjects.clone()
    }

    fn client_auth_mandatory(&self) -> bool {
        self.mandatory
    }

    fn offer_client_auth(&self) -> bool {
        true
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.parent.supported_verify_schemes()
    }
}

#[derive(Debug)]
struct FixedSignatureSchemeServerCertResolver {
    credentials: Credentials,
    scheme: SignatureScheme,
}

impl server::ServerCredentialResolver for FixedSignatureSchemeServerCertResolver {
    fn resolve(&self, client_hello: &ClientHello<'_>) -> Result<SelectedCredential, Error> {
        if !client_hello
            .signature_schemes()
            .contains(&self.scheme)
        {
            return Err(Error::PeerIncompatible(
                PeerIncompatible::NoSignatureSchemesInCommon,
            ));
        }

        self.credentials
            .signer(&[self.scheme])
            .ok_or(Error::PeerIncompatible(
                PeerIncompatible::NoSignatureSchemesInCommon,
            ))
    }
}

/// Selects among several server credentials, in the order configured.
#[derive(Debug)]
struct MultipleServerCredentialResolver {
    inner: TrustAnchorResolver,
    /// Identities in `inner`'s order, with the default credential (if any) last.
    identities: Vec<Arc<Identity<'static>>>,
    has_default: bool,
    all_must_match_issuer: bool,
    expect_selected: Option<isize>,
    available_trust_anchors: Option<Vec<TrustAnchorId>>,
}

impl MultipleServerCredentialResolver {
    fn new(opts: &Options, provider: &CryptoProvider) -> Self {
        let mut creds = opts.credentials.additional.clone();
        let has_default = opts.credentials.default.configured();
        if has_default {
            creds.push(opts.credentials.default.clone());
        }

        let credentials = creds
            .iter()
            .map(|cred| {
                assert!(
                    cred.use_signing_scheme.is_none(),
                    "TODO: -signing-prefs with multiple server credentials"
                );
                cred.load_from_file(provider)
            })
            .collect::<Vec<_>>();

        Self {
            identities: credentials
                .iter()
                .map(|c| c.identity.clone())
                .collect(),
            has_default,
            all_must_match_issuer: creds
                .iter()
                .all(|cred| cred.must_match_issuer),
            expect_selected: opts.credentials.expect_selected,
            available_trust_anchors: opts.available_trust_anchors.clone(),
            inner: TrustAnchorResolver::new(credentials),
        }
    }
}

impl server::ServerCredentialResolver for MultipleServerCredentialResolver {
    fn resolve(&self, client_hello: &ClientHello<'_>) -> Result<SelectedCredential, Error> {
        let selected = match self.inner.resolve(client_hello) {
            Ok(selected) => selected,
            Err(_) if self.all_must_match_issuer => quit(":NO_MATCHING_ISSUER:"),
            Err(err) => return Err(err),
        };

        if let Some(expected) = self.expect_selected {
            let index = self
                .identities
                .iter()
                .position(|id| Arc::ptr_eq(id, &selected.identity))
                .unwrap();
            let index = match self.has_default && index == self.identities.len() - 1 {
                true => -1,
                false => index as isize,
            };
            assert_eq!(index, expected);
        }

        Ok(selected)
    }

    fn available_trust_anchors(&self, client_hello: &ClientHello<'_>) -> Vec<TrustAnchorId> {
        match &self.available_trust_anchors {
            Some(ids) => ids.clone(),
            None => self
                .inner
                .available_trust_anchors(client_hello),
        }
    }
}

#[derive(Debug)]
struct ServerCacheWithResumptionDelay {
    delay: u32,
    storage: Arc<dyn server::StoresServerSessions>,
}

impl ServerCacheWithResumptionDelay {
    fn new(delay: u32) -> Arc<Self> {
        Arc::new(Self {
            delay,
            storage: server::ServerSessionMemoryCache::new(32),
        })
    }
}

impl server::StoresServerSessions for ServerCacheWithResumptionDelay {
    fn put(&self, key: ServerSessionKey<'_>, mut value: Vec<u8>) -> bool {
        // The creation time should be stored directly after the 2-byte version discriminant.
        let creation_time_sec = &mut value[2..10];
        let original = u64::from_be_bytes(creation_time_sec.try_into().unwrap());
        let delayed = original - self.delay as u64;
        creation_time_sec.copy_from_slice(&delayed.to_be_bytes());
        self.storage.put(key, value)
    }

    fn get(&self, key: ServerSessionKey<'_>) -> Option<Vec<u8>> {
        self.storage.get(key)
    }

    fn take(&self, key: ServerSessionKey<'_>) -> Option<Vec<u8>> {
        self.storage.take(key)
    }

    fn can_cache(&self) -> bool {
        self.storage.can_cache()
    }
}
