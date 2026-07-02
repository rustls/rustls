use rustls::crypto::cipher::{EncodedMessage, InboundOpaque, OutboundPlain, Tls12AeadAlgorithm};
use rustls::crypto::kx::KeyExchangeAlgorithm;
use rustls::crypto::tls12::Prf;
use rustls::crypto::{CipherSuite, HashAlgorithm, SignatureAlgorithm, SignatureScheme};
use rustls::enums::{ContentType, ProtocolVersion};
use rustls::{CipherSuiteCommon, SupportedCipherSuite, Tls12CipherSuite};

use super::{BaselineAead, Error, Report, ReportItem, check_sha256, check_sha384};
use crate::InjectSharedSecret;

pub(crate) fn test_cipher_suite(
    report: &mut Report,
    suite: &'static Tls12CipherSuite,
) -> Result<(), Error> {
    match suite {
        Tls12CipherSuite {
            common:
                CipherSuiteCommon {
                    suite: suite_id,
                    hash_provider,
                    confidentiality_limit,
                },
            protocol_version: _,
            prf_provider,
            kx,
            sign,
            aead_alg,
        } if Decomposition::try_from(*suite_id).is_ok() => {
            let d = Decomposition::try_from(*suite_id)?;

            match d.aead {
                BaselineAead::Aes128Gcm => {
                    Error::assert(
                        *confidentiality_limit <= 0x100_0000,
                        "excess confidentiality_limit for AES_128_GCM",
                    )?;
                }
                BaselineAead::Aes256Gcm => {
                    Error::assert(
                        *confidentiality_limit <= 0x100_0000,
                        "excess confidentiality_limit for AES_128_GCM",
                    )?;
                }
            }
            check_aead(*aead_alg, d.aead)?;

            match d.hash {
                HashAlgorithm::SHA256 => {
                    check_sha256(*hash_provider)?;
                    check_prf_sha256(*prf_provider)?
                }
                HashAlgorithm::SHA384 => {
                    check_sha384(*hash_provider)?;
                    check_prf_sha384(*prf_provider)?
                }
                _ => unimplemented!("unhandled hash/PRF algorithm"),
            }

            Error::assert_eq(*kx, d.kx, "wrong kx")?;

            match d.sign {
                SignatureAlgorithm::ECDSA => check_ecdsa_suite(sign)?,
                SignatureAlgorithm::RSA => check_rsa_suite(sign)?,
                _ => unimplemented!("untested SignatureAlgorithm"),
            }

            report
                .passed
                .push(ReportItem::CipherSuite(SupportedCipherSuite::Tls12(suite)));
        }
        _ => report
            .untested
            .push(ReportItem::CipherSuite(SupportedCipherSuite::Tls12(suite))),
    }

    Ok(())
}

struct Decomposition {
    aead: BaselineAead,
    hash: HashAlgorithm,
    kx: KeyExchangeAlgorithm,
    sign: SignatureAlgorithm,
}

impl TryFrom<CipherSuite> for Decomposition {
    type Error = Error;

    fn try_from(value: CipherSuite) -> Result<Self, Self::Error> {
        Ok(match value {
            CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 => Self {
                aead: BaselineAead::Aes128Gcm,
                hash: HashAlgorithm::SHA256,
                kx: KeyExchangeAlgorithm::ECDHE,
                sign: SignatureAlgorithm::ECDSA,
            },
            CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 => Self {
                aead: BaselineAead::Aes256Gcm,
                hash: HashAlgorithm::SHA384,
                kx: KeyExchangeAlgorithm::ECDHE,
                sign: SignatureAlgorithm::ECDSA,
            },
            CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 => Self {
                aead: BaselineAead::Aes128Gcm,
                hash: HashAlgorithm::SHA256,
                kx: KeyExchangeAlgorithm::ECDHE,
                sign: SignatureAlgorithm::RSA,
            },
            CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 => Self {
                aead: BaselineAead::Aes256Gcm,
                hash: HashAlgorithm::SHA384,
                kx: KeyExchangeAlgorithm::ECDHE,
                sign: SignatureAlgorithm::RSA,
            },
            _ => return Err(Error::from_string(format!("unsupported suite {value:?}"))),
        })
    }
}

fn check_prf_sha256(prf: &dyn Prf) -> Result<(), Error> {
    let mut output = [0u8; 48];

    // known answer test from https://mailarchive.ietf.org/arch/msg/tls/fzVCzk-z3FShgGJ6DOXqM1ydxms/
    // (truncated to fit our API)
    prf.for_key_exchange(
        &mut output,
        Box::new(InjectSharedSecret(
            b"\x9b\xbe\x43\x6b\xa9\x40\xf0\x17\xb1\x76\x52\x84\x9a\x71\xdb\x35",
        )),
        b"unused public key",
        b"test label",
        b"\xa0\xba\x9f\x93\x6c\xda\x31\x18\x27\xa6\xf7\x96\xff\xd5\x19\x8c",
    )
    .expect("TLS1.2 PRF for_key_exchange failed");

    Error::assert_eq(
        &output,
        b"\xe3\xf2\x29\xba\x72\x7b\xe1\x7b\x8d\x12\x26\x20\x55\x7c\xd4\x53\xc2\xaa\xb2\x1d\x07\xc3\xd4\x95\
          \x32\x9b\x52\xd4\xe6\x1e\xdb\x5a\x6b\x30\x17\x91\xe9\x0d\x35\xc9\xc9\xa4\x6b\x4e\x14\xba\xf9\xaf",
        "wrong TLS1.2 PRF-SHA256 output")?;

    prf.new_secret(&[0u8; 48])
        .prf(&mut output, b"label", b"seed");
    Error::assert_eq(output[0], 0x2c, "wrong TLS1.2 PRF-SHA256 output")?;

    Ok(())
}

fn check_prf_sha384(prf: &dyn Prf) -> Result<(), Error> {
    let mut output = [0u8; 48];

    // known answer test from https://mailarchive.ietf.org/arch/msg/tls/fzVCzk-z3FShgGJ6DOXqM1ydxms/
    // (truncated to fit our API)
    prf.for_key_exchange(
        &mut output,
        Box::new(InjectSharedSecret(
            b"\xb8\x0b\x73\x3d\x6c\xee\xfc\xdc\x71\x56\x6e\xa4\x8e\x55\x67\xdf",
        )),
        b"unused public key",
        b"test label",
        b"\xcd\x66\x5c\xf6\xa8\x44\x7d\xd6\xff\x8b\x27\x55\x5e\xdb\x74\x65",
    )
    .expect("TLS1.2 PRF for_key_exchange failed");

    Error::assert_eq(
        &output,
        b"\x7b\x0c\x18\xe9\xce\xd4\x10\xed\x18\x04\xf2\xcf\xa3\x4a\x33\x6a\x1c\x14\xdf\xfb\x49\x00\xbb\x5f\
          \xd7\x94\x21\x07\xe8\x1c\x83\xcd\xe9\xca\x0f\xaa\x60\xbe\x9f\xe3\x4f\x82\xb1\x23\x3c\x91\x46\xa0",
        "wrong TLS1.2 PRF-SHA384 output")?;

    prf.new_secret(&[0u8; 48])
        .prf(&mut output, b"label", b"seed");
    Error::assert_eq(output[0], 0xad, "wrong TLS1.2 PRF-SHA384 output")?;

    Ok(())
}

fn check_ecdsa_suite(schemes: &[SignatureScheme]) -> Result<(), Error> {
    // these are generally required to be useful.
    Error::assert(
        schemes.contains(&SignatureScheme::ECDSA_NISTP256_SHA256),
        "TLS1.2 sign field should contain ECDSA-SHA256",
    )?;
    Error::assert(
        schemes.contains(&SignatureScheme::ECDSA_NISTP384_SHA384),
        "TLS1.2 sign field should contain ECDSA-SHA384",
    )?;
    // P521 and ED25519 allowed but not required
    let p521 = schemes.contains(&SignatureScheme::ECDSA_NISTP521_SHA512);
    let ed25519 = schemes.contains(&SignatureScheme::ED25519);
    Error::assert_eq(
        schemes.len(),
        2 + (p521 as usize) + (ed25519 as usize),
        "unexpected items in TLS1.2 sign field",
    )?;
    Ok(())
}

fn check_rsa_suite(schemes: &[SignatureScheme]) -> Result<(), Error> {
    // these are generally required to be useful.
    for required in [
        SignatureScheme::RSA_PKCS1_SHA256,
        SignatureScheme::RSA_PKCS1_SHA384,
        SignatureScheme::RSA_PKCS1_SHA512,
        SignatureScheme::RSA_PSS_SHA256,
        SignatureScheme::RSA_PSS_SHA384,
        SignatureScheme::RSA_PSS_SHA512,
    ] {
        Error::assert(
            schemes.contains(&required),
            &format!("TLS1.2 sign field should contain {required:?}"),
        )?;
    }
    Ok(())
}

fn check_aead(alg: &dyn Tls12AeadAlgorithm, baseline: BaselineAead) -> Result<(), Error> {
    let shape = alg.key_block_shape();
    baseline.check_key_block_shape(&shape)?;

    // `fips()` reports a provider-specific status; just confirm it is callable.
    let _ = alg.fips();

    // The fixed IV and explicit nonce, of the lengths announced by `key_block_shape()`.
    let write_iv = vec![0x5cu8; shape.fixed_iv_len];
    let explicit = vec![0xa3u8; shape.explicit_nonce_len];
    let expected_iv = [&write_iv[..], &explicit[..]].concat();

    // `extract_keys()` should repackage the inputs as the baseline's variant.
    let secrets = alg
        .extract_keys(baseline.aead_key(), &write_iv, &explicit)
        .map_err(|err| Error::from_rustls(err.into(), "extract_keys failed"))?;
    baseline.check_extracted_secrets(secrets, &expected_iv)?;

    let mut encrypter = alg.encrypter(baseline.aead_key(), &write_iv, &explicit);
    let mut decrypter = alg.decrypter(baseline.aead_key(), &write_iv);

    // A record sealed by `encrypter()` must decrypt back to the same plaintext under
    // `decrypter()`, leaving the type and version intact.  Sequence numbers are presented
    // in strictly increasing order, since a sealing implementation may be stateful and
    // reject reuse or rewind.
    let plaintext = EncodedMessage::new(
        ContentType::ApplicationData,
        ProtocolVersion::TLSv1_2,
        OutboundPlain::Single(b"the quick brown fox jumps over the lazy dog"),
    );
    for seq in 0..4 {
        let sealed = encrypter
            .encrypt(plaintext.clone(), seq)
            .map_err(|err| Error::from_rustls(err, "encrypt failed"))?;

        Error::assert_eq(
            encrypter.encrypted_payload_len(plaintext.payload.len()),
            sealed.payload.as_ref().len(),
            "encrypted_payload_len disagrees with encrypt output",
        )?;

        let mut buffer = sealed.payload.as_ref().to_vec();
        let opened = decrypter
            .decrypt(
                EncodedMessage::new(sealed.typ, sealed.version, InboundOpaque(&mut buffer)),
                seq,
            )
            .map_err(|err| Error::from_rustls(err, "decrypt of own ciphertext failed"))?;
        Error::assert_eq(
            opened.payload,
            plaintext.payload.to_vec().as_slice(),
            "decrypt did not round-trip plaintext",
        )?;
        Error::assert_eq(
            opened.typ,
            ContentType::ApplicationData,
            "decrypt altered the content type",
        )?;
        Error::assert_eq(
            opened.version,
            ProtocolVersion::TLSv1_2,
            "decrypt altered the version",
        )?;
    }

    // The negative cases use fresh keys so that each is exercised at its natural sequence
    // number, and seal a single seq-0 record to corrupt.
    let ciphertext = alg
        .encrypter(baseline.aead_key(), &write_iv, &explicit)
        .encrypt(plaintext, 0)
        .map_err(|err| Error::from_rustls(err, "encrypt failed"))?
        .payload
        .as_ref()
        .to_vec();

    // Authentication must reject a flipped tag byte.
    let mut tampered = ciphertext.clone();
    *tampered
        .last_mut()
        .expect("ciphertext is never empty") ^= 0xff;
    Error::assert(
        alg.decrypter(baseline.aead_key(), &write_iv)
            .decrypt(
                EncodedMessage::new(
                    ContentType::ApplicationData,
                    ProtocolVersion::TLSv1_2,
                    InboundOpaque(&mut tampered),
                ),
                0,
            )
            .is_err(),
        "decrypt accepted a tampered authentication tag",
    )?;

    // The sequence number is authenticated: a seq-0 record must not decrypt as seq 1.
    let mut wrong_seq = ciphertext;
    Error::assert(
        alg.decrypter(baseline.aead_key(), &write_iv)
            .decrypt(
                EncodedMessage::new(
                    ContentType::ApplicationData,
                    ProtocolVersion::TLSv1_2,
                    InboundOpaque(&mut wrong_seq),
                ),
                1,
            )
            .is_err(),
        "decrypt accepted a record under the wrong sequence number",
    )?;

    Ok(())
}
