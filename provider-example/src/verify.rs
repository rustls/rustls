use der::Reader;
use rsa::signature::Verifier;
use rsa::{BigUint, RsaPublicKey, pkcs1v15, pss};
use rustls::crypto::{SignatureScheme, WebPkiSupportedAlgorithms};
use rustls::pki_types::{
    AlgorithmIdentifier, InvalidSignature, SignatureVerificationAlgorithm, alg_id,
};

pub static SUPPORTED_SIG_ALGS: WebPkiSupportedAlgorithms = WebPkiSupportedAlgorithms {
    all: &[RSA_PSS_SHA256, RSA_PKCS1_SHA256],
    mapping: &[
        (SignatureScheme::RSA_PSS_SHA256, &[RSA_PSS_SHA256]),
        (SignatureScheme::RSA_PKCS1_SHA256, &[RSA_PKCS1_SHA256]),
    ],
};

static RSA_PSS_SHA256: &dyn SignatureVerificationAlgorithm = &RsaPssSha256Verify;
static RSA_PKCS1_SHA256: &dyn SignatureVerificationAlgorithm = &RsaPkcs1Sha256Verify;

#[derive(Debug)]
struct RsaPssSha256Verify;

impl SignatureVerificationAlgorithm for RsaPssSha256Verify {
    fn public_key_alg_id(&self) -> AlgorithmIdentifier {
        alg_id::RSA_ENCRYPTION
    }

    fn signature_alg_id(&self) -> AlgorithmIdentifier {
        alg_id::RSA_PSS_SHA256
    }

    fn verify_signature(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), InvalidSignature> {
        let public_key = decode_spki_spk(public_key)?;

        let signature = pss::Signature::try_from(signature).map_err(|_| InvalidSignature)?;

        pss::VerifyingKey::<sha2::Sha256>::new(public_key)
            .verify(message, &signature)
            .map_err(|_| InvalidSignature)
    }
}

#[derive(Debug)]
struct RsaPkcs1Sha256Verify;

impl SignatureVerificationAlgorithm for RsaPkcs1Sha256Verify {
    fn public_key_alg_id(&self) -> AlgorithmIdentifier {
        alg_id::RSA_ENCRYPTION
    }

    fn signature_alg_id(&self) -> AlgorithmIdentifier {
        alg_id::RSA_PKCS1_SHA256
    }

    fn verify_signature(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), InvalidSignature> {
        let public_key = decode_spki_spk(public_key)?;

        let signature = pkcs1v15::Signature::try_from(signature).map_err(|_| InvalidSignature)?;

        pkcs1v15::VerifyingKey::<sha2::Sha256>::new(public_key)
            .verify(message, &signature)
            .map_err(|_| InvalidSignature)
    }
}

fn decode_spki_spk(spki_spk: &[u8]) -> Result<RsaPublicKey, InvalidSignature> {
    // public_key: unfortunately this is not a whole SPKI, but just the key material.
    // decode the two integers manually.
    let mut reader = der::SliceReader::new(spki_spk).map_err(|_| InvalidSignature)?;
    let ne: [der::asn1::UintRef<'_>; 2] = reader
        .decode()
        .map_err(|_| InvalidSignature)?;

    RsaPublicKey::new(
        BigUint::from_bytes_be(ne[0].as_bytes()),
        BigUint::from_bytes_be(ne[1].as_bytes()),
    )
    .map_err(|_| InvalidSignature)
}
