use aws_lc_rs::signature;
use pki_types::{
    AlgorithmIdentifier, FipsStatus, InvalidSignature, SignatureVerificationAlgorithm, alg_id,
};

// nb. aws-lc-rs has an API that is broadly compatible with *ring*,
// so this is very similar to ring_algs.rs.

/// An array of all the verification algorithms exported by this crate.
///
/// This will be empty if the crate is built without the `ring` and `aws-lc-rs` features.
pub static ALL_VERIFICATION_ALGS: &[&dyn SignatureVerificationAlgorithm] = &[
    ECDSA_P256_SHA256,
    ECDSA_P256_SHA384,
    ECDSA_P256_SHA512,
    ECDSA_P384_SHA256,
    ECDSA_P384_SHA384,
    ECDSA_P384_SHA512,
    ECDSA_P521_SHA256,
    ECDSA_P521_SHA384,
    ECDSA_P521_SHA512,
    ED25519,
    RSA_PKCS1_2048_8192_SHA256,
    RSA_PKCS1_2048_8192_SHA384,
    RSA_PKCS1_2048_8192_SHA512,
    RSA_PKCS1_2048_8192_SHA256_ABSENT_PARAMS,
    RSA_PKCS1_2048_8192_SHA384_ABSENT_PARAMS,
    RSA_PKCS1_2048_8192_SHA512_ABSENT_PARAMS,
    RSA_PKCS1_3072_8192_SHA384,
    RSA_PSS_2048_8192_SHA256_LEGACY_KEY,
    RSA_PSS_2048_8192_SHA384_LEGACY_KEY,
    RSA_PSS_2048_8192_SHA512_LEGACY_KEY,
];

/// A `SignatureVerificationAlgorithm` implemented using aws-lc-rs.
#[expect(clippy::exhaustive_structs)]
#[derive(Debug)]
pub struct AwsLcRsVerificationAlgorithm {
    /// The public key algorithm identifier (for example, `id-ecPublicKey`).
    pub public_key_alg_id: AlgorithmIdentifier,
    /// The signature algorithm identifier (for example, `ecdsa-with-SHA256`).
    pub signature_alg_id: AlgorithmIdentifier,
    /// The aws-lc-rs verification algorithm to use for this signature algorithm.
    pub verification_alg: &'static dyn signature::VerificationAlgorithm,
    /// Whether this algorithm is included in the FIPS submission for aws-lc-rs.
    pub in_fips_submission: bool,
}

impl SignatureVerificationAlgorithm for AwsLcRsVerificationAlgorithm {
    fn public_key_alg_id(&self) -> AlgorithmIdentifier {
        self.public_key_alg_id
    }

    fn signature_alg_id(&self) -> AlgorithmIdentifier {
        self.signature_alg_id
    }

    fn verify_signature(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), InvalidSignature> {
        if matches!(
            self.public_key_alg_id,
            alg_id::ECDSA_P256 | alg_id::ECDSA_P384 | alg_id::ECDSA_P521
        ) {
            // Restrict the allowed encodings of EC public keys.
            //
            // "The first octet of the OCTET STRING indicates whether the key is
            //  compressed or uncompressed.  The uncompressed form is indicated
            //  by 0x04 and the compressed form is indicated by either 0x02 or
            //  0x03 (see 2.3.3 in [SEC1]).  The public key MUST be rejected if
            //  any other value is included in the first octet."
            // -- <https://datatracker.ietf.org/doc/html/rfc5480#section-2.2>
            match public_key.first() {
                Some(0x04) | Some(0x02) | Some(0x03) => {}
                _ => return Err(InvalidSignature),
            };
        }
        signature::UnparsedPublicKey::new(self.verification_alg, public_key)
            .verify(message, signature)
            .map_err(|_| InvalidSignature)
    }

    fn fips_status(&self) -> FipsStatus {
        match self.in_fips_submission {
            true => super::fips(),
            false => FipsStatus::Unvalidated,
        }
    }
}

/// ECDSA signatures using the P-256 curve and SHA-256.
pub static ECDSA_P256_SHA256: &dyn SignatureVerificationAlgorithm = &AwsLcRsVerificationAlgorithm {
    public_key_alg_id: alg_id::ECDSA_P256,
    signature_alg_id: alg_id::ECDSA_SHA256,
    verification_alg: &signature::ECDSA_P256_SHA256_ASN1,
    in_fips_submission: true,
};

/// ECDSA signatures using the P-256 curve and SHA-384. Deprecated.
pub static ECDSA_P256_SHA384: &dyn SignatureVerificationAlgorithm = &AwsLcRsVerificationAlgorithm {
    public_key_alg_id: alg_id::ECDSA_P256,
    signature_alg_id: alg_id::ECDSA_SHA384,
    verification_alg: &signature::ECDSA_P256_SHA384_ASN1,
    in_fips_submission: true,
};

/// ECDSA signatures using the P-256 curve and SHA-512. Deprecated.
pub static ECDSA_P256_SHA512: &dyn SignatureVerificationAlgorithm = &AwsLcRsVerificationAlgorithm {
    public_key_alg_id: alg_id::ECDSA_P256,
    signature_alg_id: alg_id::ECDSA_SHA512,
    verification_alg: &signature::ECDSA_P256_SHA512_ASN1,
    in_fips_submission: true,
};

/// ECDSA signatures using the P-384 curve and SHA-256. Deprecated.
pub static ECDSA_P384_SHA256: &dyn SignatureVerificationAlgorithm = &AwsLcRsVerificationAlgorithm {
    public_key_alg_id: alg_id::ECDSA_P384,
    signature_alg_id: alg_id::ECDSA_SHA256,
    verification_alg: &signature::ECDSA_P384_SHA256_ASN1,
    in_fips_submission: true,
};

/// ECDSA signatures using the P-384 curve and SHA-384.
pub static ECDSA_P384_SHA384: &dyn SignatureVerificationAlgorithm = &AwsLcRsVerificationAlgorithm {
    public_key_alg_id: alg_id::ECDSA_P384,
    signature_alg_id: alg_id::ECDSA_SHA384,
    verification_alg: &signature::ECDSA_P384_SHA384_ASN1,
    in_fips_submission: true,
};

/// ECDSA signatures using the P-384 curve and SHA-512. Deprecated.
pub static ECDSA_P384_SHA512: &dyn SignatureVerificationAlgorithm = &AwsLcRsVerificationAlgorithm {
    public_key_alg_id: alg_id::ECDSA_P384,
    signature_alg_id: alg_id::ECDSA_SHA512,
    verification_alg: &signature::ECDSA_P384_SHA512_ASN1,
    in_fips_submission: true,
};

/// ECDSA signatures using the P-521 curve and SHA-256.
pub static ECDSA_P521_SHA256: &dyn SignatureVerificationAlgorithm = &AwsLcRsVerificationAlgorithm {
    public_key_alg_id: alg_id::ECDSA_P521,
    signature_alg_id: alg_id::ECDSA_SHA256,
    verification_alg: &signature::ECDSA_P521_SHA256_ASN1,
    in_fips_submission: true,
};

/// ECDSA signatures using the P-521 curve and SHA-384.
pub static ECDSA_P521_SHA384: &dyn SignatureVerificationAlgorithm = &AwsLcRsVerificationAlgorithm {
    public_key_alg_id: alg_id::ECDSA_P521,
    signature_alg_id: alg_id::ECDSA_SHA384,
    verification_alg: &signature::ECDSA_P521_SHA384_ASN1,
    in_fips_submission: true,
};

/// ECDSA signatures using the P-521 curve and SHA-512.
pub static ECDSA_P521_SHA512: &dyn SignatureVerificationAlgorithm = &AwsLcRsVerificationAlgorithm {
    public_key_alg_id: alg_id::ECDSA_P521,
    signature_alg_id: alg_id::ECDSA_SHA512,
    verification_alg: &signature::ECDSA_P521_SHA512_ASN1,
    in_fips_submission: true,
};

/// RSA PKCS#1 1.5 signatures using SHA-256 for keys of 2048-8192 bits.
pub static RSA_PKCS1_2048_8192_SHA256: &dyn SignatureVerificationAlgorithm =
    &AwsLcRsVerificationAlgorithm {
        public_key_alg_id: alg_id::RSA_ENCRYPTION,
        signature_alg_id: alg_id::RSA_PKCS1_SHA256,
        verification_alg: &signature::RSA_PKCS1_2048_8192_SHA256,
        in_fips_submission: true,
    };

/// RSA PKCS#1 1.5 signatures using SHA-384 for keys of 2048-8192 bits.
pub static RSA_PKCS1_2048_8192_SHA384: &dyn SignatureVerificationAlgorithm =
    &AwsLcRsVerificationAlgorithm {
        public_key_alg_id: alg_id::RSA_ENCRYPTION,
        signature_alg_id: alg_id::RSA_PKCS1_SHA384,
        verification_alg: &signature::RSA_PKCS1_2048_8192_SHA384,
        in_fips_submission: true,
    };

/// RSA PKCS#1 1.5 signatures using SHA-512 for keys of 2048-8192 bits.
pub static RSA_PKCS1_2048_8192_SHA512: &dyn SignatureVerificationAlgorithm =
    &AwsLcRsVerificationAlgorithm {
        public_key_alg_id: alg_id::RSA_ENCRYPTION,
        signature_alg_id: alg_id::RSA_PKCS1_SHA512,
        verification_alg: &signature::RSA_PKCS1_2048_8192_SHA512,
        in_fips_submission: true,
    };

/// RSA PKCS#1 1.5 signatures using SHA-256 for keys of 2048-8192 bits,
/// with illegally absent AlgorithmIdentifier parameters.
///
/// RFC4055 says on sha256WithRSAEncryption and company:
///
/// >   When any of these four object identifiers appears within an
/// >   AlgorithmIdentifier, the parameters MUST be NULL.  Implementations
/// >   MUST accept the parameters being absent as well as present.
///
/// This algorithm covers the absent case, [`RSA_PKCS1_2048_8192_SHA256`] covers
/// the present case.
pub static RSA_PKCS1_2048_8192_SHA256_ABSENT_PARAMS: &dyn SignatureVerificationAlgorithm =
    &AwsLcRsVerificationAlgorithm {
        public_key_alg_id: alg_id::RSA_ENCRYPTION,
        signature_alg_id: AlgorithmIdentifier::from_slice(include_bytes!(
            "data/alg-rsa-pkcs1-sha256-absent-params.der"
        )),
        verification_alg: &signature::RSA_PKCS1_2048_8192_SHA256,
        in_fips_submission: true,
    };

/// RSA PKCS#1 1.5 signatures using SHA-384 for keys of 2048-8192 bits,
/// with illegally absent AlgorithmIdentifier parameters.
///
/// RFC4055 says on sha256WithRSAEncryption and company:
///
/// >   When any of these four object identifiers appears within an
/// >   AlgorithmIdentifier, the parameters MUST be NULL.  Implementations
/// >   MUST accept the parameters being absent as well as present.
///
/// This algorithm covers the absent case, [`RSA_PKCS1_2048_8192_SHA384`] covers
/// the present case.
pub static RSA_PKCS1_2048_8192_SHA384_ABSENT_PARAMS: &dyn SignatureVerificationAlgorithm =
    &AwsLcRsVerificationAlgorithm {
        public_key_alg_id: alg_id::RSA_ENCRYPTION,
        signature_alg_id: AlgorithmIdentifier::from_slice(include_bytes!(
            "data/alg-rsa-pkcs1-sha384-absent-params.der"
        )),
        verification_alg: &signature::RSA_PKCS1_2048_8192_SHA384,
        in_fips_submission: true,
    };

/// RSA PKCS#1 1.5 signatures using SHA-512 for keys of 2048-8192 bits,
/// with illegally absent AlgorithmIdentifier parameters.
///
/// RFC4055 says on sha256WithRSAEncryption and company:
///
/// >   When any of these four object identifiers appears within an
/// >   AlgorithmIdentifier, the parameters MUST be NULL.  Implementations
/// >   MUST accept the parameters being absent as well as present.
///
/// This algorithm covers the absent case, [`RSA_PKCS1_2048_8192_SHA512`] covers
/// the present case.
pub static RSA_PKCS1_2048_8192_SHA512_ABSENT_PARAMS: &dyn SignatureVerificationAlgorithm =
    &AwsLcRsVerificationAlgorithm {
        public_key_alg_id: alg_id::RSA_ENCRYPTION,
        signature_alg_id: AlgorithmIdentifier::from_slice(include_bytes!(
            "data/alg-rsa-pkcs1-sha512-absent-params.der"
        )),
        verification_alg: &signature::RSA_PKCS1_2048_8192_SHA512,
        in_fips_submission: true,
    };

/// RSA PKCS#1 1.5 signatures using SHA-384 for keys of 3072-8192 bits.
pub static RSA_PKCS1_3072_8192_SHA384: &dyn SignatureVerificationAlgorithm =
    &AwsLcRsVerificationAlgorithm {
        public_key_alg_id: alg_id::RSA_ENCRYPTION,
        signature_alg_id: alg_id::RSA_PKCS1_SHA384,
        verification_alg: &signature::RSA_PKCS1_3072_8192_SHA384,
        in_fips_submission: true,
    };

/// RSA PSS signatures using SHA-256 for keys of 2048-8192 bits and of
/// type rsaEncryption; see [RFC 4055 Section 1.2].
///
/// [RFC 4055 Section 1.2]: https://tools.ietf.org/html/rfc4055#section-1.2
pub static RSA_PSS_2048_8192_SHA256_LEGACY_KEY: &dyn SignatureVerificationAlgorithm =
    &AwsLcRsVerificationAlgorithm {
        public_key_alg_id: alg_id::RSA_ENCRYPTION,
        signature_alg_id: alg_id::RSA_PSS_SHA256,
        verification_alg: &signature::RSA_PSS_2048_8192_SHA256,
        in_fips_submission: true,
    };

/// RSA PSS signatures using SHA-384 for keys of 2048-8192 bits and of
/// type rsaEncryption; see [RFC 4055 Section 1.2].
///
/// [RFC 4055 Section 1.2]: https://tools.ietf.org/html/rfc4055#section-1.2
pub static RSA_PSS_2048_8192_SHA384_LEGACY_KEY: &dyn SignatureVerificationAlgorithm =
    &AwsLcRsVerificationAlgorithm {
        public_key_alg_id: alg_id::RSA_ENCRYPTION,
        signature_alg_id: alg_id::RSA_PSS_SHA384,
        verification_alg: &signature::RSA_PSS_2048_8192_SHA384,
        in_fips_submission: true,
    };

/// RSA PSS signatures using SHA-512 for keys of 2048-8192 bits and of
/// type rsaEncryption; see [RFC 4055 Section 1.2].
///
/// [RFC 4055 Section 1.2]: https://tools.ietf.org/html/rfc4055#section-1.2
pub static RSA_PSS_2048_8192_SHA512_LEGACY_KEY: &dyn SignatureVerificationAlgorithm =
    &AwsLcRsVerificationAlgorithm {
        public_key_alg_id: alg_id::RSA_ENCRYPTION,
        signature_alg_id: alg_id::RSA_PSS_SHA512,
        verification_alg: &signature::RSA_PSS_2048_8192_SHA512,
        in_fips_submission: true,
    };

/// ED25519 signatures according to RFC 8410
pub static ED25519: &dyn SignatureVerificationAlgorithm = &AwsLcRsVerificationAlgorithm {
    public_key_alg_id: alg_id::ED25519,
    signature_alg_id: alg_id::ED25519,
    verification_alg: &signature::ED25519,
    in_fips_submission: true,
};
