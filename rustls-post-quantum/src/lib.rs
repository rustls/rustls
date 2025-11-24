//! This crate provide a [`CryptoProvider`] built on the default aws-lc-rs default provider.
//!
//! Features:
//!
//! - `aws-lc-rs-unstable`: adds support for three variants of the experimental ML-DSA signature
//!   algorithm.
//!
//! Before rustls 0.23.22, this crate additionally provided support for the ML-KEM key exchange
//! (both "pure" and hybrid variants), but these have been moved to the rustls crate itself.
//! In rustls 0.23.22 and later, you can use rustls' `prefer-post-quantum` feature to determine
//! whether the ML-KEM key exchange is preferred over non-post-quantum key exchanges.

#[cfg(feature = "aws-lc-rs-unstable")]
use rustls::SignatureScheme;
use rustls::crypto::CryptoProvider;
#[cfg(feature = "aws-lc-rs-unstable")]
use rustls::crypto::WebPkiSupportedAlgorithms;
pub use rustls::crypto::aws_lc_rs::kx_group::{MLKEM768, X25519MLKEM768};
#[cfg(feature = "aws-lc-rs-unstable")]
use webpki::aws_lc_rs as webpki_algs;

pub fn provider() -> CryptoProvider {
    #[cfg_attr(not(feature = "aws-lc-rs-unstable"), allow(unused_mut))]
    let mut provider = rustls::crypto::aws_lc_rs::default_provider();
    #[cfg(feature = "aws-lc-rs-unstable")]
    {
        provider.signature_verification_algorithms = SUPPORTED_SIG_ALGS;
        provider.key_provider = &key_provider::PqAwsLcRs;
    }
    provider
}

#[cfg(feature = "aws-lc-rs-unstable")]
mod key_provider {
    use core::fmt::{self, Debug, Formatter};
    use std::sync::Arc;

    use aws_lc_rs::signature::KeyPair;
    use aws_lc_rs::unstable::signature::{
        ML_DSA_44_SIGNING, ML_DSA_65_SIGNING, ML_DSA_87_SIGNING, PqdsaKeyPair,
        PqdsaSigningAlgorithm,
    };
    use rustls::crypto::KeyProvider;
    use rustls::crypto::aws_lc_rs::sign;
    use rustls::pki_types::{AlgorithmIdentifier, PrivateKeyDer, SubjectPublicKeyInfoDer, alg_id};
    use rustls::sign::{Signer, SigningKey, public_key_to_spki};
    use rustls::{Error, SignatureAlgorithm, SignatureScheme};

    #[derive(Debug)]
    pub(super) struct PqAwsLcRs;

    impl KeyProvider for PqAwsLcRs {
        fn load_private_key(
            &self,
            key_der: PrivateKeyDer<'static>,
        ) -> Result<Arc<dyn SigningKey>, Error> {
            // TODO: support `PqdsaKeyPair::from_raw_private_key()`?
            if let PrivateKeyDer::Pkcs8(pkcs8) = &key_der {
                for kind in PqdsaKeyKind::iter() {
                    match PqdsaKeyPair::from_pkcs8(kind.to_alg(), pkcs8.secret_pkcs8_der()) {
                        Ok(key_pair) => {
                            return Ok(Arc::new(PqdsaSigningKey {
                                kind,
                                inner: Arc::new(key_pair),
                            }));
                        }
                        Err(_) => continue,
                    }
                }
            }

            match sign::any_supported_type(&key_der) {
                Ok(key) => Ok(key),
                Err(_) => Err(Error::General(
                    "failed to parse private key as ML-DSA, RSA, ECDSA, or EdDSA".into(),
                )),
            }
        }

        fn fips(&self) -> bool {
            false
        }
    }

    struct PqdsaSigningKey {
        kind: PqdsaKeyKind,
        inner: Arc<PqdsaKeyPair>,
    }

    impl SigningKey for PqdsaSigningKey {
        fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
            if !offered.contains(&self.kind.scheme()) {
                return None;
            }

            Some(Box::new(PqdsaSigner {
                key: self.inner.clone(),
                kind: self.kind,
            }))
        }

        fn public_key(&self) -> Option<SubjectPublicKeyInfoDer<'_>> {
            Some(public_key_to_spki(
                &self.kind.alg_id(),
                self.inner.public_key(),
            ))
        }

        // [`SignatureAlgorithm`] is for TLS 1.2, for which ML-DSA is not specified.
        // Pick a "Reserved for Private Use" value.
        fn algorithm(&self) -> SignatureAlgorithm {
            SignatureAlgorithm::Unknown(255)
        }
    }

    impl Debug for PqdsaSigningKey {
        fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
            f.debug_struct("PqdsaSigningKey")
                .field("scheme", &self.kind.scheme())
                .finish_non_exhaustive()
        }
    }

    struct PqdsaSigner {
        key: Arc<PqdsaKeyPair>,
        kind: PqdsaKeyKind,
    }

    impl Signer for PqdsaSigner {
        fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
            let expected_sig_len = self.key.algorithm().signature_len();
            let mut sig = vec![0; expected_sig_len];
            let actual_sig_len = self
                .key
                .sign(message, &mut sig)
                .map_err(|_| Error::General("signing failed".into()))?;

            if actual_sig_len != expected_sig_len {
                return Err(Error::General("unexpected signature length".into()));
            }

            Ok(sig)
        }

        fn scheme(&self) -> SignatureScheme {
            self.kind.scheme()
        }
    }

    impl Debug for PqdsaSigner {
        fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
            f.debug_struct("PqdsaSigner")
                .field("scheme", &self.kind.scheme())
                .finish_non_exhaustive()
        }
    }

    #[derive(Clone, Copy)]
    enum PqdsaKeyKind {
        MlDsa44,
        MlDsa65,
        MlDsa87,
    }

    impl PqdsaKeyKind {
        fn iter() -> impl Iterator<Item = Self> {
            [Self::MlDsa44, Self::MlDsa65, Self::MlDsa87].into_iter()
        }

        fn to_alg(self) -> &'static PqdsaSigningAlgorithm {
            match self {
                Self::MlDsa44 => &ML_DSA_44_SIGNING,
                Self::MlDsa65 => &ML_DSA_65_SIGNING,
                Self::MlDsa87 => &ML_DSA_87_SIGNING,
            }
        }

        fn scheme(&self) -> SignatureScheme {
            match self {
                Self::MlDsa44 => SignatureScheme::ML_DSA_44,
                Self::MlDsa65 => SignatureScheme::ML_DSA_65,
                Self::MlDsa87 => SignatureScheme::ML_DSA_87,
            }
        }

        fn alg_id(&self) -> AlgorithmIdentifier {
            match self {
                Self::MlDsa44 => alg_id::ML_DSA_44,
                Self::MlDsa65 => alg_id::ML_DSA_65,
                Self::MlDsa87 => alg_id::ML_DSA_87,
            }
        }
    }
}

/// Keep in sync with the `SUPPORTED_SIG_ALGS` in `rustls::crypto::aws_lc_rs`.
#[cfg(feature = "aws-lc-rs-unstable")]
static SUPPORTED_SIG_ALGS: WebPkiSupportedAlgorithms = WebPkiSupportedAlgorithms {
    all: &[
        webpki_algs::ECDSA_P256_SHA256,
        webpki_algs::ECDSA_P256_SHA384,
        webpki_algs::ECDSA_P384_SHA256,
        webpki_algs::ECDSA_P384_SHA384,
        webpki_algs::ECDSA_P521_SHA256,
        webpki_algs::ECDSA_P521_SHA384,
        webpki_algs::ECDSA_P521_SHA512,
        webpki_algs::ED25519,
        webpki_algs::RSA_PSS_2048_8192_SHA256_LEGACY_KEY,
        webpki_algs::RSA_PSS_2048_8192_SHA384_LEGACY_KEY,
        webpki_algs::RSA_PSS_2048_8192_SHA512_LEGACY_KEY,
        webpki_algs::RSA_PKCS1_2048_8192_SHA256,
        webpki_algs::RSA_PKCS1_2048_8192_SHA384,
        webpki_algs::RSA_PKCS1_2048_8192_SHA512,
        webpki_algs::RSA_PKCS1_2048_8192_SHA256_ABSENT_PARAMS,
        webpki_algs::RSA_PKCS1_2048_8192_SHA384_ABSENT_PARAMS,
        webpki_algs::RSA_PKCS1_2048_8192_SHA512_ABSENT_PARAMS,
        #[cfg(feature = "aws-lc-rs-unstable")]
        webpki_algs::ML_DSA_44,
        #[cfg(feature = "aws-lc-rs-unstable")]
        webpki_algs::ML_DSA_65,
        #[cfg(feature = "aws-lc-rs-unstable")]
        webpki_algs::ML_DSA_87,
    ],
    mapping: &[
        // Note: for TLS1.2 the curve is not fixed by SignatureScheme. For TLS1.3 it is.
        (
            SignatureScheme::ECDSA_NISTP384_SHA384,
            &[
                webpki_algs::ECDSA_P384_SHA384,
                webpki_algs::ECDSA_P256_SHA384,
                webpki_algs::ECDSA_P521_SHA384,
            ],
        ),
        (
            SignatureScheme::ECDSA_NISTP256_SHA256,
            &[
                webpki_algs::ECDSA_P256_SHA256,
                webpki_algs::ECDSA_P384_SHA256,
                webpki_algs::ECDSA_P521_SHA256,
            ],
        ),
        (
            SignatureScheme::ECDSA_NISTP521_SHA512,
            &[
                webpki_algs::ECDSA_P521_SHA512,
                webpki_algs::ECDSA_P384_SHA512,
                webpki_algs::ECDSA_P256_SHA512,
            ],
        ),
        (SignatureScheme::ED25519, &[webpki_algs::ED25519]),
        (
            SignatureScheme::RSA_PSS_SHA512,
            &[webpki_algs::RSA_PSS_2048_8192_SHA512_LEGACY_KEY],
        ),
        (
            SignatureScheme::RSA_PSS_SHA384,
            &[webpki_algs::RSA_PSS_2048_8192_SHA384_LEGACY_KEY],
        ),
        (
            SignatureScheme::RSA_PSS_SHA256,
            &[webpki_algs::RSA_PSS_2048_8192_SHA256_LEGACY_KEY],
        ),
        (
            SignatureScheme::RSA_PKCS1_SHA512,
            &[webpki_algs::RSA_PKCS1_2048_8192_SHA512],
        ),
        (
            SignatureScheme::RSA_PKCS1_SHA384,
            &[webpki_algs::RSA_PKCS1_2048_8192_SHA384],
        ),
        (
            SignatureScheme::RSA_PKCS1_SHA256,
            &[webpki_algs::RSA_PKCS1_2048_8192_SHA256],
        ),
        #[cfg(feature = "aws-lc-rs-unstable")]
        (SignatureScheme::ML_DSA_44, &[webpki_algs::ML_DSA_44]),
        #[cfg(feature = "aws-lc-rs-unstable")]
        (SignatureScheme::ML_DSA_65, &[webpki_algs::ML_DSA_65]),
        #[cfg(feature = "aws-lc-rs-unstable")]
        (SignatureScheme::ML_DSA_87, &[webpki_algs::ML_DSA_87]),
    ],
};

#[cfg(all(test, feature = "aws-lc-rs-unstable"))]
mod tests {
    use core::ops::DerefMut;
    use std::io;
    use std::sync::Arc;

    use rcgen::{
        CertificateParams, CertifiedIssuer, ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose,
    };
    use rustls::pki_types::PrivateKeyDer;
    use rustls::{
        ClientConfig, ClientConnection, ConnectionCommon, RootCertStore, ServerConfig,
        ServerConnection, SideData,
    };

    #[test]
    fn ml_dsa() {
        let ca_key = KeyPair::generate_for(&rcgen::PKCS_ML_DSA_44).unwrap();
        let mut ca_params = CertificateParams::new(vec!["Test CA".into()]).unwrap();
        ca_params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyCertSign,
        ];
        ca_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let issuer = CertifiedIssuer::self_signed(ca_params, ca_key).unwrap();

        let ee_key = KeyPair::generate_for(&rcgen::PKCS_ML_DSA_87).unwrap();
        let ee_params = CertificateParams::new(vec!["localhost".into()]).unwrap();
        let ee_cert = ee_params
            .signed_by(&ee_key, &issuer)
            .unwrap();

        let provider = Arc::new(super::provider());
        let server_config = ServerConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![ee_cert.der().clone()],
                PrivateKeyDer::try_from(ee_key.serialize_der()).unwrap(),
            )
            .unwrap();

        let mut roots = RootCertStore::empty();
        roots.add(issuer.der().clone()).unwrap();
        let client_config = ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();

        let mut client =
            ClientConnection::new(Arc::new(client_config), "localhost".try_into().unwrap())
                .unwrap();
        let mut server = ServerConnection::new(Arc::new(server_config)).unwrap();
        do_handshake(&mut client, &mut server);
    }

    // Copied from rustls while rustls-post-quantum depends on an older rustls.
    fn do_handshake(
        client: &mut impl DerefMut<Target = ConnectionCommon<impl SideData>>,
        server: &mut impl DerefMut<Target = ConnectionCommon<impl SideData>>,
    ) -> (usize, usize) {
        let (mut to_client, mut to_server) = (0, 0);
        while server.is_handshaking() || client.is_handshaking() {
            to_server += transfer(client, server);
            server.process_new_packets().unwrap();
            to_client += transfer(server, client);
            client.process_new_packets().unwrap();
        }
        (to_server, to_client)
    }

    // Copied from rustls-test while rustls-post-quantum depends on an older rustls.
    fn transfer(
        left: &mut impl DerefMut<Target = ConnectionCommon<impl SideData>>,
        right: &mut impl DerefMut<Target = ConnectionCommon<impl SideData>>,
    ) -> usize {
        let mut buf = [0u8; 262144];
        let mut total = 0;

        while left.wants_write() {
            let sz = {
                let into_buf: &mut dyn io::Write = &mut &mut buf[..];
                left.write_tls(into_buf).unwrap()
            };
            total += sz;
            if sz == 0 {
                return total;
            }

            let mut offs = 0;
            loop {
                let from_buf: &mut dyn io::Read = &mut &buf[offs..sz];
                offs += right.read_tls(from_buf).unwrap();
                if sz == offs {
                    break;
                }
            }
        }

        total
    }
}
