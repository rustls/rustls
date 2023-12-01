#![allow(clippy::duplicate_mod)]

use crate::enums::{SignatureAlgorithm, SignatureScheme};
use crate::error::Error;
use crate::sign::{Signer, SigningKey};
use crate::x509::{asn1_wrap, wrap_in_sequence};

use super::ring_like::io::der;
use super::ring_like::rand::{SecureRandom, SystemRandom};
use super::ring_like::signature::{self, EcdsaKeyPair, Ed25519KeyPair, RsaKeyPair};
use pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};

use alloc::boxed::Box;
use alloc::format;
use alloc::string::ToString;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::fmt::{self, Debug, Formatter};

/// Parse `der` as any supported key encoding/type, returning
/// the first which works.
pub fn any_supported_type(der: &PrivateKeyDer<'_>) -> Result<Arc<dyn SigningKey>, Error> {
    if let Ok(rsa) = RsaSigningKey::new(der) {
        return Ok(Arc::new(rsa));
    }

    if let Ok(ecdsa) = any_ecdsa_type(der) {
        return Ok(ecdsa);
    }

    if let PrivateKeyDer::Pkcs8(pkcs8) = der {
        if let Ok(eddsa) = any_eddsa_type(pkcs8) {
            return Ok(eddsa);
        }
    }

    Err(Error::General(
        "failed to parse private key as RSA, ECDSA, or EdDSA".into(),
    ))
}

/// Parse `der` as any ECDSA key type, returning the first which works.
///
/// Both SEC1 (PEM section starting with 'BEGIN EC PRIVATE KEY') and PKCS8
/// (PEM section starting with 'BEGIN PRIVATE KEY') encodings are supported.
pub fn any_ecdsa_type(der: &PrivateKeyDer<'_>) -> Result<Arc<dyn SigningKey>, Error> {
    if let Ok(ecdsa_p256) = EcdsaSigningKey::new(
        der,
        SignatureScheme::ECDSA_NISTP256_SHA256,
        &signature::ECDSA_P256_SHA256_ASN1_SIGNING,
    ) {
        return Ok(Arc::new(ecdsa_p256));
    }

    if let Ok(ecdsa_p384) = EcdsaSigningKey::new(
        der,
        SignatureScheme::ECDSA_NISTP384_SHA384,
        &signature::ECDSA_P384_SHA384_ASN1_SIGNING,
    ) {
        return Ok(Arc::new(ecdsa_p384));
    }

    Err(Error::General(
        "failed to parse ECDSA private key as PKCS#8 or SEC1".into(),
    ))
}

/// Parse `der` as any EdDSA key type, returning the first which works.
pub fn any_eddsa_type(der: &PrivatePkcs8KeyDer<'_>) -> Result<Arc<dyn SigningKey>, Error> {
    // TODO: Add support for Ed448
    Ok(Arc::new(Ed25519SigningKey::new(
        der,
        SignatureScheme::ED25519,
    )?))
}

/// A `SigningKey` for RSA-PKCS1 or RSA-PSS.
///
/// This is used by the test suite, so it must be `pub`, but it isn't part of
/// the public, stable, API.
#[doc(hidden)]
pub struct RsaSigningKey {
    key: Arc<RsaKeyPair>,
}

static ALL_RSA_SCHEMES: &[SignatureScheme] = &[
    SignatureScheme::RSA_PSS_SHA512,
    SignatureScheme::RSA_PSS_SHA384,
    SignatureScheme::RSA_PSS_SHA256,
    SignatureScheme::RSA_PKCS1_SHA512,
    SignatureScheme::RSA_PKCS1_SHA384,
    SignatureScheme::RSA_PKCS1_SHA256,
];

impl RsaSigningKey {
    /// Make a new `RsaSigningKey` from a DER encoding, in either
    /// PKCS#1 or PKCS#8 format.
    pub fn new(der: &PrivateKeyDer<'_>) -> Result<Self, Error> {
        let key_pair = match der {
            PrivateKeyDer::Pkcs1(pkcs1) => RsaKeyPair::from_der(pkcs1.secret_pkcs1_der()),
            PrivateKeyDer::Pkcs8(pkcs8) => RsaKeyPair::from_pkcs8(pkcs8.secret_pkcs8_der()),
            _ => {
                return Err(Error::General(
                    "failed to parse RSA private key as either PKCS#1 or PKCS#8".into(),
                ));
            }
        }
        .map_err(|key_rejected| {
            Error::General(format!("failed to parse RSA private key: {}", key_rejected))
        })?;

        Ok(Self {
            key: Arc::new(key_pair),
        })
    }
}

impl SigningKey for RsaSigningKey {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        ALL_RSA_SCHEMES
            .iter()
            .find(|scheme| offered.contains(scheme))
            .map(|scheme| RsaSigner::new(Arc::clone(&self.key), *scheme))
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::RSA
    }
}

impl Debug for RsaSigningKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("RsaSigningKey")
            .field("algorithm", &self.algorithm())
            .finish()
    }
}

struct RsaSigner {
    key: Arc<RsaKeyPair>,
    scheme: SignatureScheme,
    encoding: &'static dyn signature::RsaEncoding,
}

impl RsaSigner {
    fn new(key: Arc<RsaKeyPair>, scheme: SignatureScheme) -> Box<dyn Signer> {
        let encoding: &dyn signature::RsaEncoding = match scheme {
            SignatureScheme::RSA_PKCS1_SHA256 => &signature::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384 => &signature::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512 => &signature::RSA_PKCS1_SHA512,
            SignatureScheme::RSA_PSS_SHA256 => &signature::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384 => &signature::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512 => &signature::RSA_PSS_SHA512,
            _ => unreachable!(),
        };

        Box::new(Self {
            key,
            scheme,
            encoding,
        })
    }
}

impl Signer for RsaSigner {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        let mut sig = vec![0; super::ring_shim::rsa_key_pair_public_modulus_len(&self.key)];

        let rng = SystemRandom::new();
        self.key
            .sign(self.encoding, &rng, message, &mut sig)
            .map(|_| sig)
            .map_err(|_| Error::General("signing failed".to_string()))
    }

    fn scheme(&self) -> SignatureScheme {
        self.scheme
    }
}

impl Debug for RsaSigner {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("RsaSigner")
            .field("scheme", &self.scheme)
            .finish()
    }
}

/// A SigningKey that uses exactly one TLS-level SignatureScheme
/// and one ring-level signature::SigningAlgorithm.
///
/// Compare this to RsaSigningKey, which for a particular key is
/// willing to sign with several algorithms.  This is quite poor
/// cryptography practice, but is necessary because a given RSA key
/// is expected to work in TLS1.2 (PKCS#1 signatures) and TLS1.3
/// (PSS signatures) -- nobody is willing to obtain certificates for
/// different protocol versions.
///
/// Currently this is only implemented for ECDSA keys.
struct EcdsaSigningKey {
    key: Arc<EcdsaKeyPair>,
    scheme: SignatureScheme,
}

impl EcdsaSigningKey {
    /// Make a new `ECDSASigningKey` from a DER encoding in PKCS#8 or SEC1
    /// format, expecting a key usable with precisely the given signature
    /// scheme.
    fn new(
        der: &PrivateKeyDer<'_>,
        scheme: SignatureScheme,
        sigalg: &'static signature::EcdsaSigningAlgorithm,
    ) -> Result<Self, ()> {
        let rng = SystemRandom::new();
        let key_pair = match der {
            PrivateKeyDer::Sec1(sec1) => {
                Self::convert_sec1_to_pkcs8(scheme, sigalg, sec1.secret_sec1_der(), &rng)?
            }
            PrivateKeyDer::Pkcs8(pkcs8) => {
                super::ring_shim::ecdsa_key_pair_from_pkcs8(sigalg, pkcs8.secret_pkcs8_der(), &rng)?
            }
            _ => return Err(()),
        };

        Ok(Self {
            key: Arc::new(key_pair),
            scheme,
        })
    }

    /// Convert a SEC1 encoding to PKCS8, and ask ring to parse it.  This
    /// can be removed once <https://github.com/briansmith/ring/pull/1456>
    /// (or equivalent) is landed.
    fn convert_sec1_to_pkcs8(
        scheme: SignatureScheme,
        sigalg: &'static signature::EcdsaSigningAlgorithm,
        maybe_sec1_der: &[u8],
        rng: &dyn SecureRandom,
    ) -> Result<EcdsaKeyPair, ()> {
        let pkcs8_prefix = match scheme {
            SignatureScheme::ECDSA_NISTP256_SHA256 => &PKCS8_PREFIX_ECDSA_NISTP256,
            SignatureScheme::ECDSA_NISTP384_SHA384 => &PKCS8_PREFIX_ECDSA_NISTP384,
            _ => unreachable!(), // all callers are in this file
        };

        let sec1_wrap = asn1_wrap(der::Tag::OctetString as u8, maybe_sec1_der);

        let mut pkcs8_inner = Vec::with_capacity(pkcs8_prefix.len() + sec1_wrap.len());
        pkcs8_inner.extend_from_slice(pkcs8_prefix);
        pkcs8_inner.extend_from_slice(&sec1_wrap);

        super::ring_shim::ecdsa_key_pair_from_pkcs8(sigalg, &wrap_in_sequence(&pkcs8_inner), rng)
    }
}

// This is (line-by-line):
// - INTEGER Version = 0
// - SEQUENCE (privateKeyAlgorithm)
//   - id-ecPublicKey OID
//   - prime256v1 OID
const PKCS8_PREFIX_ECDSA_NISTP256: &[u8] = b"\x02\x01\x00\
      \x30\x13\
      \x06\x07\x2a\x86\x48\xce\x3d\x02\x01\
      \x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07";

// This is (line-by-line):
// - INTEGER Version = 0
// - SEQUENCE (privateKeyAlgorithm)
//   - id-ecPublicKey OID
//   - secp384r1 OID
const PKCS8_PREFIX_ECDSA_NISTP384: &[u8] = b"\x02\x01\x00\
     \x30\x10\
     \x06\x07\x2a\x86\x48\xce\x3d\x02\x01\
     \x06\x05\x2b\x81\x04\x00\x22";

impl SigningKey for EcdsaSigningKey {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        if offered.contains(&self.scheme) {
            Some(Box::new(EcdsaSigner {
                key: Arc::clone(&self.key),
                scheme: self.scheme,
            }))
        } else {
            None
        }
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        self.scheme.sign()
    }
}

impl Debug for EcdsaSigningKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("EcdsaSigningKey")
            .field("algorithm", &self.algorithm())
            .finish()
    }
}

struct EcdsaSigner {
    key: Arc<EcdsaKeyPair>,
    scheme: SignatureScheme,
}

impl Signer for EcdsaSigner {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        let rng = super::ring_like::rand::SystemRandom::new();
        self.key
            .sign(&rng, message)
            .map_err(|_| Error::General("signing failed".into()))
            .map(|sig| sig.as_ref().into())
    }

    fn scheme(&self) -> SignatureScheme {
        self.scheme
    }
}

impl Debug for EcdsaSigner {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("EcdsaSigner")
            .field("scheme", &self.scheme)
            .finish()
    }
}

/// A SigningKey that uses exactly one TLS-level SignatureScheme
/// and one ring-level signature::SigningAlgorithm.
///
/// Compare this to RsaSigningKey, which for a particular key is
/// willing to sign with several algorithms.  This is quite poor
/// cryptography practice, but is necessary because a given RSA key
/// is expected to work in TLS1.2 (PKCS#1 signatures) and TLS1.3
/// (PSS signatures) -- nobody is willing to obtain certificates for
/// different protocol versions.
///
/// Currently this is only implemented for Ed25519 keys.
struct Ed25519SigningKey {
    key: Arc<Ed25519KeyPair>,
    scheme: SignatureScheme,
}

impl Ed25519SigningKey {
    /// Make a new `Ed25519SigningKey` from a DER encoding in PKCS#8 format,
    /// expecting a key usable with precisely the given signature scheme.
    fn new(der: &PrivatePkcs8KeyDer<'_>, scheme: SignatureScheme) -> Result<Self, Error> {
        match Ed25519KeyPair::from_pkcs8_maybe_unchecked(der.secret_pkcs8_der()) {
            Ok(key_pair) => Ok(Self {
                key: Arc::new(key_pair),
                scheme,
            }),
            Err(e) => Err(Error::General(format!(
                "failed to parse Ed25519 private key: {e}"
            ))),
        }
    }
}

impl SigningKey for Ed25519SigningKey {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        if offered.contains(&self.scheme) {
            Some(Box::new(Ed25519Signer {
                key: Arc::clone(&self.key),
                scheme: self.scheme,
            }))
        } else {
            None
        }
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        self.scheme.sign()
    }
}

impl Debug for Ed25519SigningKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ed25519SigningKey")
            .field("algorithm", &self.algorithm())
            .finish()
    }
}

struct Ed25519Signer {
    key: Arc<Ed25519KeyPair>,
    scheme: SignatureScheme,
}

impl Signer for Ed25519Signer {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        Ok(self.key.sign(message).as_ref().into())
    }

    fn scheme(&self) -> SignatureScheme {
        self.scheme
    }
}

impl Debug for Ed25519Signer {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ed25519Signer")
            .field("scheme", &self.scheme)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pki_types::{PrivatePkcs1KeyDer, PrivateSec1KeyDer};

    #[test]
    fn can_load_ecdsa_nistp256_pkcs8() {
        let key =
            PrivatePkcs8KeyDer::from(&include_bytes!("../../testdata/nistp256key.pkcs8.der")[..]);
        assert!(any_eddsa_type(&key).is_err());
        let key = PrivateKeyDer::Pkcs8(key);
        assert!(any_supported_type(&key).is_ok());
        assert!(any_ecdsa_type(&key).is_ok());
    }

    #[test]
    fn can_load_ecdsa_nistp256_sec1() {
        let key = PrivateKeyDer::Sec1(PrivateSec1KeyDer::from(
            &include_bytes!("../../testdata/nistp256key.der")[..],
        ));
        assert!(any_supported_type(&key).is_ok());
        assert!(any_ecdsa_type(&key).is_ok());
    }

    #[test]
    fn can_load_ecdsa_nistp384_pkcs8() {
        let key =
            PrivatePkcs8KeyDer::from(&include_bytes!("../../testdata/nistp384key.pkcs8.der")[..]);
        assert!(any_eddsa_type(&key).is_err());
        let key = PrivateKeyDer::Pkcs8(key);
        assert!(any_supported_type(&key).is_ok());
        assert!(any_ecdsa_type(&key).is_ok());
    }

    #[test]
    fn can_load_ecdsa_nistp384_sec1() {
        let key = PrivateKeyDer::Sec1(PrivateSec1KeyDer::from(
            &include_bytes!("../../testdata/nistp384key.der")[..],
        ));
        assert!(any_supported_type(&key).is_ok());
        assert!(any_ecdsa_type(&key).is_ok());
    }

    #[test]
    fn can_load_eddsa_pkcs8() {
        let key = PrivatePkcs8KeyDer::from(&include_bytes!("../../testdata/eddsakey.der")[..]);
        assert!(any_eddsa_type(&key).is_ok());
        let key = PrivateKeyDer::Pkcs8(key);
        assert!(any_supported_type(&key).is_ok());
        assert!(any_ecdsa_type(&key).is_err());
    }

    #[test]
    fn can_load_rsa2048_pkcs8() {
        let key =
            PrivatePkcs8KeyDer::from(&include_bytes!("../../testdata/rsa2048key.pkcs8.der")[..]);
        assert!(any_eddsa_type(&key).is_err());
        let key = PrivateKeyDer::Pkcs8(key);
        assert!(any_supported_type(&key).is_ok());
        assert!(any_ecdsa_type(&key).is_err());
    }

    #[test]
    fn can_load_rsa2048_pkcs1() {
        let key = PrivateKeyDer::Pkcs1(PrivatePkcs1KeyDer::from(
            &include_bytes!("../../testdata/rsa2048key.pkcs1.der")[..],
        ));
        assert!(any_supported_type(&key).is_ok());
        assert!(any_ecdsa_type(&key).is_err());
    }

    #[test]
    fn cannot_load_invalid_pkcs8_encoding() {
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(&b"invalid"[..]));
        assert_eq!(
            any_supported_type(&key).err(),
            Some(Error::General(
                "failed to parse private key as RSA, ECDSA, or EdDSA".into()
            ))
        );
        assert_eq!(
            any_ecdsa_type(&key).err(),
            Some(Error::General(
                "failed to parse ECDSA private key as PKCS#8 or SEC1".into()
            ))
        );
        assert_eq!(
            RsaSigningKey::new(&key).err(),
            Some(Error::General(
                "failed to parse RSA private key: InvalidEncoding".into()
            ))
        );
    }
}

#[cfg(bench)]
mod benchmarks {
    use super::{PrivateKeyDer, PrivatePkcs8KeyDer, SignatureScheme};

    #[bench]
    fn bench_rsa2048_pkcs1_sha256(b: &mut test::Bencher) {
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
            &include_bytes!("../../testdata/rsa2048key.pkcs8.der")[..],
        ));
        let sk = super::any_supported_type(&key).unwrap();
        let signer = sk
            .choose_scheme(&[SignatureScheme::RSA_PKCS1_SHA256])
            .unwrap();

        b.iter(|| {
            test::black_box(
                signer
                    .sign(SAMPLE_TLS13_MESSAGE)
                    .unwrap(),
            );
        });
    }

    #[bench]
    fn bench_rsa2048_pss_sha256(b: &mut test::Bencher) {
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
            &include_bytes!("../../testdata/rsa2048key.pkcs8.der")[..],
        ));
        let sk = super::any_supported_type(&key).unwrap();
        let signer = sk
            .choose_scheme(&[SignatureScheme::RSA_PSS_SHA256])
            .unwrap();

        b.iter(|| {
            test::black_box(
                signer
                    .sign(SAMPLE_TLS13_MESSAGE)
                    .unwrap(),
            );
        });
    }

    #[bench]
    fn bench_eddsa(b: &mut test::Bencher) {
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
            &include_bytes!("../../testdata/eddsakey.der")[..],
        ));
        let sk = super::any_supported_type(&key).unwrap();
        let signer = sk
            .choose_scheme(&[SignatureScheme::ED25519])
            .unwrap();

        b.iter(|| {
            test::black_box(
                signer
                    .sign(SAMPLE_TLS13_MESSAGE)
                    .unwrap(),
            );
        });
    }

    #[bench]
    fn bench_ecdsa_p256_sha256(b: &mut test::Bencher) {
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
            &include_bytes!("../../testdata/nistp256key.pkcs8.der")[..],
        ));
        let sk = super::any_supported_type(&key).unwrap();
        let signer = sk
            .choose_scheme(&[SignatureScheme::ECDSA_NISTP256_SHA256])
            .unwrap();

        b.iter(|| {
            test::black_box(
                signer
                    .sign(SAMPLE_TLS13_MESSAGE)
                    .unwrap(),
            );
        });
    }

    #[bench]
    fn bench_ecdsa_p384_sha384(b: &mut test::Bencher) {
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
            &include_bytes!("../../testdata/nistp384key.pkcs8.der")[..],
        ));
        let sk = super::any_supported_type(&key).unwrap();
        let signer = sk
            .choose_scheme(&[SignatureScheme::ECDSA_NISTP384_SHA384])
            .unwrap();

        b.iter(|| {
            test::black_box(
                signer
                    .sign(SAMPLE_TLS13_MESSAGE)
                    .unwrap(),
            );
        });
    }

    #[bench]
    fn bench_load_and_validate_rsa2048(b: &mut test::Bencher) {
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
            &include_bytes!("../../testdata/rsa2048key.pkcs8.der")[..],
        ));

        b.iter(|| {
            test::black_box(super::any_supported_type(&key).unwrap());
        });
    }

    #[bench]
    fn bench_load_and_validate_rsa4096(b: &mut test::Bencher) {
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
            &include_bytes!("../../testdata/rsa4096key.pkcs8.der")[..],
        ));

        b.iter(|| {
            test::black_box(super::any_supported_type(&key).unwrap());
        });
    }

    #[bench]
    fn bench_load_and_validate_p256(b: &mut test::Bencher) {
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
            &include_bytes!("../../testdata/nistp256key.pkcs8.der")[..],
        ));

        b.iter(|| {
            test::black_box(super::any_ecdsa_type(&key).unwrap());
        });
    }

    #[bench]
    fn bench_load_and_validate_p384(b: &mut test::Bencher) {
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
            &include_bytes!("../../testdata/nistp384key.pkcs8.der")[..],
        ));

        b.iter(|| {
            test::black_box(super::any_ecdsa_type(&key).unwrap());
        });
    }

    #[bench]
    fn bench_load_and_validate_eddsa(b: &mut test::Bencher) {
        let key = PrivatePkcs8KeyDer::from(&include_bytes!("../../testdata/eddsakey.der")[..]);

        b.iter(|| {
            test::black_box(super::any_eddsa_type(&key).unwrap());
        });
    }

    const SAMPLE_TLS13_MESSAGE: &[u8] = &[
        0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
        0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
        0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
        0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
        0x20, 0x20, 0x20, 0x20, 0x54, 0x4c, 0x53, 0x20, 0x31, 0x2e, 0x33, 0x2c, 0x20, 0x73, 0x65,
        0x72, 0x76, 0x65, 0x72, 0x20, 0x43, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74,
        0x65, 0x56, 0x65, 0x72, 0x69, 0x66, 0x79, 0x00, 0x04, 0xca, 0xc4, 0x48, 0x0e, 0x70, 0xf2,
        0x1b, 0xa9, 0x1c, 0x16, 0xca, 0x90, 0x48, 0xbe, 0x28, 0x2f, 0xc7, 0xf8, 0x9b, 0x87, 0x72,
        0x93, 0xda, 0x4d, 0x2f, 0x80, 0x80, 0x60, 0x1a, 0xd3, 0x08, 0xe2, 0xb7, 0x86, 0x14, 0x1b,
        0x54, 0xda, 0x9a, 0xc9, 0x6d, 0xe9, 0x66, 0xb4, 0x9f, 0xe2, 0x2c,
    ];
}
