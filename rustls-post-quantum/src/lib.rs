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

use core::fmt::{self, Debug, Formatter};
use std::sync::Arc;

use aws_lc_rs::signature::KeyPair;
use aws_lc_rs::unstable::signature::{
    ML_DSA_44_SIGNING, ML_DSA_65_SIGNING, ML_DSA_87_SIGNING, PqdsaKeyPair, PqdsaSigningAlgorithm,
};
use rustls::Error;
use rustls::crypto::{
    CryptoProvider, KeyProvider, SignatureScheme, Signer, SigningKey, WebPkiSupportedAlgorithms,
    public_key_to_spki,
};
use rustls::pki_types::{
    AlgorithmIdentifier, FipsStatus, PrivateKeyDer, SubjectPublicKeyInfoDer, alg_id,
};
pub use rustls_aws_lc_rs::kx_group::{MLKEM768, X25519MLKEM768};

pub fn provider() -> CryptoProvider {
    let mut provider = rustls_aws_lc_rs::DEFAULT_PROVIDER;
    provider.signature_verification_algorithms = SUPPORTED_SIG_ALGS;
    provider.key_provider = &PqAwsLcRs;
    provider
}

#[derive(Debug)]
pub struct PqAwsLcRs;

impl KeyProvider for PqAwsLcRs {
    fn load_private_key(
        &self,
        key_der: PrivateKeyDer<'static>,
    ) -> Result<Box<dyn SigningKey>, Error> {
        // TODO: support `PqdsaKeyPair::from_raw_private_key()`?
        if let PrivateKeyDer::Pkcs8(pkcs8) = &key_der {
            for kind in PqdsaKeyKind::iter() {
                match PqdsaKeyPair::from_pkcs8(kind.to_alg(), pkcs8.secret_pkcs8_der()) {
                    Ok(key_pair) => {
                        return Ok(Box::new(PqdsaSigningKey {
                            kind,
                            inner: Arc::new(key_pair),
                        }));
                    }
                    Err(_) => continue,
                }
            }
        }

        match rustls_aws_lc_rs::DEFAULT_KEY_PROVIDER.load_private_key(key_der) {
            Ok(key) => Ok(key),
            Err(_) => Err(Error::General(
                "failed to parse private key as ML-DSA, RSA, ECDSA, or EdDSA".into(),
            )),
        }
    }

    fn fips(&self) -> FipsStatus {
        FipsStatus::Unvalidated
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
    fn sign(self: Box<Self>, message: &[u8]) -> Result<Vec<u8>, Error> {
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

/// Keep in sync with the `SUPPORTED_SIG_ALGS` in `rustls_aws_lc_rs`.
static SUPPORTED_SIG_ALGS: WebPkiSupportedAlgorithms = match WebPkiSupportedAlgorithms::new(
    &[
        rustls_aws_lc_rs::ECDSA_P256_SHA256,
        rustls_aws_lc_rs::ECDSA_P256_SHA384,
        rustls_aws_lc_rs::ECDSA_P384_SHA256,
        rustls_aws_lc_rs::ECDSA_P384_SHA384,
        rustls_aws_lc_rs::ECDSA_P521_SHA256,
        rustls_aws_lc_rs::ECDSA_P521_SHA384,
        rustls_aws_lc_rs::ECDSA_P521_SHA512,
        rustls_aws_lc_rs::ED25519,
        rustls_aws_lc_rs::RSA_PSS_2048_8192_SHA256_LEGACY_KEY,
        rustls_aws_lc_rs::RSA_PSS_2048_8192_SHA384_LEGACY_KEY,
        rustls_aws_lc_rs::RSA_PSS_2048_8192_SHA512_LEGACY_KEY,
        rustls_aws_lc_rs::RSA_PKCS1_2048_8192_SHA256,
        rustls_aws_lc_rs::RSA_PKCS1_2048_8192_SHA384,
        rustls_aws_lc_rs::RSA_PKCS1_2048_8192_SHA512,
        rustls_aws_lc_rs::RSA_PKCS1_2048_8192_SHA256_ABSENT_PARAMS,
        rustls_aws_lc_rs::RSA_PKCS1_2048_8192_SHA384_ABSENT_PARAMS,
        rustls_aws_lc_rs::RSA_PKCS1_2048_8192_SHA512_ABSENT_PARAMS,
        rustls_aws_lc_rs::ML_DSA_44,
        rustls_aws_lc_rs::ML_DSA_65,
        rustls_aws_lc_rs::ML_DSA_87,
    ],
    &[
        // Note: for TLS1.2 the curve is not fixed by SignatureScheme. For TLS1.3 it is.
        (
            SignatureScheme::ECDSA_NISTP384_SHA384,
            &[
                rustls_aws_lc_rs::ECDSA_P384_SHA384,
                rustls_aws_lc_rs::ECDSA_P256_SHA384,
                rustls_aws_lc_rs::ECDSA_P521_SHA384,
            ],
        ),
        (
            SignatureScheme::ECDSA_NISTP256_SHA256,
            &[
                rustls_aws_lc_rs::ECDSA_P256_SHA256,
                rustls_aws_lc_rs::ECDSA_P384_SHA256,
                rustls_aws_lc_rs::ECDSA_P521_SHA256,
            ],
        ),
        (
            SignatureScheme::ECDSA_NISTP521_SHA512,
            &[
                rustls_aws_lc_rs::ECDSA_P521_SHA512,
                rustls_aws_lc_rs::ECDSA_P384_SHA512,
                rustls_aws_lc_rs::ECDSA_P256_SHA512,
            ],
        ),
        (SignatureScheme::ED25519, &[rustls_aws_lc_rs::ED25519]),
        (
            SignatureScheme::RSA_PSS_SHA512,
            &[rustls_aws_lc_rs::RSA_PSS_2048_8192_SHA512_LEGACY_KEY],
        ),
        (
            SignatureScheme::RSA_PSS_SHA384,
            &[rustls_aws_lc_rs::RSA_PSS_2048_8192_SHA384_LEGACY_KEY],
        ),
        (
            SignatureScheme::RSA_PSS_SHA256,
            &[rustls_aws_lc_rs::RSA_PSS_2048_8192_SHA256_LEGACY_KEY],
        ),
        (
            SignatureScheme::RSA_PKCS1_SHA512,
            &[rustls_aws_lc_rs::RSA_PKCS1_2048_8192_SHA512],
        ),
        (
            SignatureScheme::RSA_PKCS1_SHA384,
            &[rustls_aws_lc_rs::RSA_PKCS1_2048_8192_SHA384],
        ),
        (
            SignatureScheme::RSA_PKCS1_SHA256,
            &[rustls_aws_lc_rs::RSA_PKCS1_2048_8192_SHA256],
        ),
        (SignatureScheme::ML_DSA_44, &[rustls_aws_lc_rs::ML_DSA_44]),
        (SignatureScheme::ML_DSA_65, &[rustls_aws_lc_rs::ML_DSA_65]),
        (SignatureScheme::ML_DSA_87, &[rustls_aws_lc_rs::ML_DSA_87]),
    ],
) {
    Ok(algs) => algs,
    Err(_) => panic!("bad WebPkiSupportedAlgorithms"),
};

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use rcgen::{
        CertificateParams, CertifiedIssuer, ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose,
    };
    use rustls::crypto::Identity;
    use rustls::pki_types::PrivateKeyDer;
    use rustls::{ClientConfig, RootCertStore, ServerConfig, ServerConnection};
    use rustls_test::do_handshake;

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
        let server_config = ServerConfig::builder(provider.clone())
            .with_no_client_auth()
            .with_single_cert(
                Arc::new(Identity::from_cert_chain(vec![ee_cert.der().clone()]).unwrap()),
                PrivateKeyDer::try_from(ee_key.serialize_der()).unwrap(),
            )
            .unwrap();

        let mut roots = RootCertStore::empty();
        roots.add(issuer.der().clone()).unwrap();
        let mut client = Arc::new(
            ClientConfig::builder(provider)
                .with_root_certificates(roots)
                .with_no_client_auth()
                .unwrap(),
        )
        .connect("localhost".try_into().unwrap())
        .build()
        .unwrap();

        let mut server = ServerConnection::new(Arc::new(server_config)).unwrap();
        do_handshake(&mut client, &mut server);
    }
}
