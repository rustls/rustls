//! Validate signatures against X.509 certificates.
//! The certificate is not validated except for extremely basic syntactic
//! correctness.

#![deny(
    exceeding_bitshifts,
    invalid_type_param_default,
    missing_fragment_specifier,
    mutable_transmutes,
    no_mangle_const_items,
    overflowing_literals,
    patterns_in_fns_without_body,
    pub_use_of_private_extern_crate,
    unknown_crate_types,
    const_err,
    order_dependent_trait_objects,
    illegal_floating_point_literal_pattern,
    improper_ctypes,
    late_bound_lifetime_arguments,
    non_camel_case_types,
    non_shorthand_field_patterns,
    non_snake_case,
    non_upper_case_globals,
    no_mangle_generic_items,
    private_in_public,
    stable_features,
    type_alias_bounds,
    tyvar_behind_raw_pointer,
    unconditional_recursion,
    unused_comparisons,
    unreachable_pub,
    anonymous_parameters,
    missing_copy_implementations,
    missing_debug_implementations,
    missing_docs,
    single_use_lifetimes,
    trivial_casts,
    trivial_numeric_casts,
    unused_import_braces,
    unused_qualifications,
    clippy::all
)]
#![forbid(
    unsafe_code,
    intra_doc_link_resolution_failure,
    safe_packed_borrows,
    while_true,
    elided_lifetimes_in_paths,
    bare_trait_objects
)]

use crate::SignatureScheme;
use ring::{error::Unspecified, io::der, signature};
use webpki::Error;

/// Extracts the algorithm id and public key from a certificate
fn parse_certificate(certificate: &[u8]) -> Result<(&[u8], &[u8]), Unspecified> {
    let (tbs, signature_algorithm) = untrusted::Input::from(certificate)
        .read_all(Unspecified, |mut reader| {
            der::expect_tag_and_get_value(&mut reader, der::Tag::Sequence)
        })?
        .read_all(Unspecified, |mut reader| {
            // tbsCertificate
            let tbs = der::expect_tag_and_get_value(&mut reader, der::Tag::Sequence)?;
            // signatureAlgorithm
            let signature_algorithm =
                der::expect_tag_and_get_value(&mut reader, der::Tag::Sequence)?;
            // signatureValue
            der::bit_string_with_no_unused_bits(&mut reader)?;
            Ok((tbs, signature_algorithm))
        })?;
    let spki = tbs.read_all(Unspecified, |mut reader| {
        // Any reasonable X.509 certificate will have extensions, which means version 3.
        if reader.read_bytes(5)?.as_slice_less_safe() != [160, 3, 2, 1, 2] {
            return Err(Unspecified);
        }
        // we already parsed the version above
        // serialNumber
        der::expect_tag_and_get_value(&mut reader, der::Tag::Integer)?;
        // signature
        if der::expect_tag_and_get_value(&mut reader, der::Tag::Sequence)? != signature_algorithm {
            // signature algorithms don’t match
            return Err(Unspecified);
        }
        // issuer
        der::expect_tag_and_get_value(&mut reader, der::Tag::Sequence)?;
        // validity
        der::expect_tag_and_get_value(&mut reader, der::Tag::Sequence)?;
        // subject
        der::expect_tag_and_get_value(&mut reader, der::Tag::Sequence)?;
        // subjectPublicKeyInfo
        let spki = der::expect_tag_and_get_value(&mut reader, der::Tag::Sequence)?;
        // subjectUniqueId and issuerUniqueId are unsupported
        // We require extensions, as any use case we can think of needs them.
        der::expect_tag_and_get_value(&mut reader, der::Tag::ContextSpecificConstructed3)?;
        Ok(spki)
    })?;
    spki.read_all(Unspecified, |mut reader| {
        let stripped_algid = der::expect_tag_and_get_value(&mut reader, der::Tag::Sequence)?;
        let pkey = der::bit_string_with_no_unused_bits(&mut reader)?;
        Ok((
            stripped_algid.as_slice_less_safe(),
            pkey.as_slice_less_safe(),
        ))
    })
}

/// Verify that `signature` was made by signing `message` with the private key
/// corresponding to the public key for `certificate`, using `scheme`.
///
/// If `reject_ecdsa_curve_hash_mismatch` is true, reject deprecated signatures
/// made with hashes that don’t match the public key. This is required by
/// TLS1.3, but has no security impact.
pub(crate) fn verify_certificate_signature(
    signature: &[u8],
    message: &[u8],
    certificate: &[u8],
    scheme: SignatureScheme,
    reject_ecdsa_curve_hash_mismatch: bool,
) -> Result<(), Error> {
    let (stripped_algid, pkey) =
        parse_certificate(certificate).map_err(|Unspecified| Error::BadDER)?;
    let algorithm: &dyn signature::VerificationAlgorithm = match (scheme, stripped_algid) {
        (SignatureScheme::RSA_PKCS1_SHA256, include_bytes!("data/alg-rsa-encryption.der")) => {
            &signature::RSA_PKCS1_2048_8192_SHA256
        }
        (SignatureScheme::RSA_PKCS1_SHA384, include_bytes!("data/alg-rsa-encryption.der")) => {
            &signature::RSA_PKCS1_2048_8192_SHA384
        }
        (SignatureScheme::RSA_PKCS1_SHA512, include_bytes!("data/alg-rsa-encryption.der")) => {
            &signature::RSA_PKCS1_2048_8192_SHA512
        }
        (SignatureScheme::ECDSA_NISTP256_SHA256, include_bytes!("data/alg-ecdsa-p256.der")) => {
            &signature::ECDSA_P256_SHA256_ASN1
        }
        (SignatureScheme::ECDSA_NISTP384_SHA384, include_bytes!("data/alg-ecdsa-p384.der")) => {
            &signature::ECDSA_P384_SHA384_ASN1
        }
        (SignatureScheme::ECDSA_NISTP384_SHA384, include_bytes!("data/alg-ecdsa-p256.der"))
            if !reject_ecdsa_curve_hash_mismatch =>
        {
            &signature::ECDSA_P256_SHA384_ASN1
        }
        (SignatureScheme::ECDSA_NISTP256_SHA256, include_bytes!("data/alg-ecdsa-p384.der"))
            if !reject_ecdsa_curve_hash_mismatch =>
        {
            &signature::ECDSA_P384_SHA256_ASN1
        }
        (SignatureScheme::ED25519, include_bytes!("data/alg-ed25519.der")) => &signature::ED25519,
        (SignatureScheme::RSA_PSS_SHA256, include_bytes!("data/alg-rsa-encryption.der")) => {
            &signature::RSA_PSS_2048_8192_SHA256
        }
        (SignatureScheme::RSA_PSS_SHA384, include_bytes!("data/alg-rsa-encryption.der")) => {
            &signature::RSA_PSS_2048_8192_SHA384
        }
        (SignatureScheme::RSA_PSS_SHA512, include_bytes!("data/alg-rsa-encryption.der")) => {
            &signature::RSA_PSS_2048_8192_SHA512
        }
        _ => return Err(Error::UnsupportedSignatureAlgorithmForPublicKey),
    };
    signature::UnparsedPublicKey::new(algorithm, pkey)
        .verify(message, signature)
        .map_err(|Unspecified| Error::InvalidSignatureForPublicKey)
}
