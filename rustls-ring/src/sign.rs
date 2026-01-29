use alloc::boxed::Box;
use alloc::string::ToString;
use alloc::sync::Arc;
use alloc::vec::Vec;
use alloc::{format, vec};
use core::fmt::{self, Debug, Formatter};

use pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer, SubjectPublicKeyInfoDer, alg_id};
use ring::rand::{SecureRandom, SystemRandom};
use ring::signature::{self, EcdsaKeyPair, Ed25519KeyPair, KeyPair, RsaKeyPair};
#[cfg(any(test, bench))]
use rustls::crypto::CryptoProvider;
use rustls::crypto::{SignatureScheme, Signer, SigningKey, public_key_to_spki};
use rustls::error::Error;

/// A `SigningKey` for RSA-PKCS1 or RSA-PSS.
pub(super) struct RsaSigningKey {
    key: Arc<RsaKeyPair>,
}

impl RsaSigningKey {
    fn to_signer(&self, scheme: SignatureScheme) -> RsaSigner {
        let encoding: &dyn signature::RsaEncoding = match scheme {
            SignatureScheme::RSA_PKCS1_SHA256 => &signature::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384 => &signature::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512 => &signature::RSA_PKCS1_SHA512,
            SignatureScheme::RSA_PSS_SHA256 => &signature::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384 => &signature::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512 => &signature::RSA_PSS_SHA512,
            _ => unreachable!(),
        };

        RsaSigner {
            key: self.key.clone(),
            scheme,
            encoding,
        }
    }

    const SCHEMES: &[SignatureScheme] = &[
        SignatureScheme::RSA_PSS_SHA512,
        SignatureScheme::RSA_PSS_SHA384,
        SignatureScheme::RSA_PSS_SHA256,
        SignatureScheme::RSA_PKCS1_SHA512,
        SignatureScheme::RSA_PKCS1_SHA384,
        SignatureScheme::RSA_PKCS1_SHA256,
    ];
}

impl SigningKey for RsaSigningKey {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        Self::SCHEMES
            .iter()
            .find(|scheme| offered.contains(scheme))
            .map(|&scheme| Box::new(self.to_signer(scheme)) as Box<dyn Signer>)
    }

    fn public_key(&self) -> Option<SubjectPublicKeyInfoDer<'_>> {
        Some(public_key_to_spki(
            &alg_id::RSA_ENCRYPTION,
            self.key.public_key(),
        ))
    }
}

impl TryFrom<&PrivateKeyDer<'_>> for RsaSigningKey {
    type Error = Error;

    /// Make a new `RsaSigningKey` from a DER encoding, in either
    /// PKCS#1 or PKCS#8 format.
    fn try_from(der: &PrivateKeyDer<'_>) -> Result<Self, Self::Error> {
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
            Error::General(format!("failed to parse RSA private key: {key_rejected}"))
        })?;

        Ok(Self {
            key: Arc::new(key_pair),
        })
    }
}

impl Debug for RsaSigningKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("RsaSigningKey")
            .finish_non_exhaustive()
    }
}

struct RsaSigner {
    key: Arc<RsaKeyPair>,
    scheme: SignatureScheme,
    encoding: &'static dyn signature::RsaEncoding,
}

impl RsaSigner {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        let mut sig = vec![0; self.key.public().modulus_len()];

        let rng = SystemRandom::new();
        self.key
            .sign(self.encoding, &rng, message, &mut sig)
            .map(|_| sig)
            .map_err(|_| Error::General("signing failed".to_string()))
    }
}

impl Signer for RsaSigner {
    fn sign(self: Box<Self>, message: &[u8]) -> Result<Vec<u8>, Error> {
        (*self).sign(message)
    }

    fn scheme(&self) -> SignatureScheme {
        self.scheme
    }
}

impl Debug for RsaSigner {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("RsaSigner")
            .field("scheme", &self.scheme)
            .finish_non_exhaustive()
    }
}

/// A [`SigningKey`] and [`Signer`] implementation for ECDSA.
///
/// Unlike [`RsaSigningKey`]/[`RsaSigner`], where we have one key that supports
/// multiple signature schemes, we can use the same type for both traits here.
#[derive(Clone)]
pub(super) struct EcdsaSigner {
    key: Arc<EcdsaKeyPair>,
    scheme: SignatureScheme,
}

impl EcdsaSigner {
    /// Make a new [`EcdsaSigner`] from a DER encoding in PKCS#8 or SEC1
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
                EcdsaKeyPair::from_pkcs8(sigalg, pkcs8.secret_pkcs8_der(), &rng).map_err(|_| ())?
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
            SignatureScheme::ECDSA_NISTP256_SHA256 => &Self::PKCS8_PREFIX_ECDSA_NISTP256,
            SignatureScheme::ECDSA_NISTP384_SHA384 => &Self::PKCS8_PREFIX_ECDSA_NISTP384,
            _ => unreachable!(), // all callers are in this file
        };

        let sec1_wrap = wrap_in_octet_string(maybe_sec1_der);
        let pkcs8 = wrap_concat_in_sequence(pkcs8_prefix, &sec1_wrap);

        EcdsaKeyPair::from_pkcs8(sigalg, &pkcs8, rng).map_err(|_| ())
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        let rng = SystemRandom::new();
        self.key
            .sign(&rng, message)
            .map_err(|_| Error::General("signing failed".into()))
            .map(|sig| sig.as_ref().into())
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
}

impl SigningKey for EcdsaSigner {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        if offered.contains(&self.scheme) {
            Some(Box::new(self.clone()))
        } else {
            None
        }
    }

    fn public_key(&self) -> Option<SubjectPublicKeyInfoDer<'_>> {
        let id = match self.scheme {
            SignatureScheme::ECDSA_NISTP256_SHA256 => alg_id::ECDSA_P256,
            SignatureScheme::ECDSA_NISTP384_SHA384 => alg_id::ECDSA_P384,
            _ => unreachable!(),
        };

        Some(public_key_to_spki(&id, self.key.public_key()))
    }
}

impl Signer for EcdsaSigner {
    fn sign(self: Box<Self>, message: &[u8]) -> Result<Vec<u8>, Error> {
        (*self).sign(message)
    }

    fn scheme(&self) -> SignatureScheme {
        self.scheme
    }
}

impl TryFrom<&PrivateKeyDer<'_>> for EcdsaSigner {
    type Error = Error;

    /// Parse `der` as any ECDSA key type, returning the first which works.
    ///
    /// Both SEC1 (PEM section starting with 'BEGIN EC PRIVATE KEY') and PKCS8
    /// (PEM section starting with 'BEGIN PRIVATE KEY') encodings are supported.
    fn try_from(der: &PrivateKeyDer<'_>) -> Result<Self, Self::Error> {
        if let Ok(ecdsa_p256) = Self::new(
            der,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            &signature::ECDSA_P256_SHA256_ASN1_SIGNING,
        ) {
            return Ok(ecdsa_p256);
        }

        if let Ok(ecdsa_p384) = Self::new(
            der,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            &signature::ECDSA_P384_SHA384_ASN1_SIGNING,
        ) {
            return Ok(ecdsa_p384);
        }

        Err(Error::General(
            "failed to parse ECDSA private key as PKCS#8 or SEC1".into(),
        ))
    }
}

impl Debug for EcdsaSigner {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("EcdsaSigner")
            .field("scheme", &self.scheme)
            .finish_non_exhaustive()
    }
}

/// A [`SigningKey`] and [`Signer`] implementation for ED25519.
///
/// Unlike [`RsaSigningKey`]/[`RsaSigner`], where we have one key that supports
/// multiple signature schemes, we can use the same type for both traits here.
#[derive(Clone)]
pub(super) struct Ed25519Signer {
    key: Arc<Ed25519KeyPair>,
    scheme: SignatureScheme,
}

impl Ed25519Signer {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        Ok(self.key.sign(message).as_ref().into())
    }
}

impl SigningKey for Ed25519Signer {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        if offered.contains(&self.scheme) {
            Some(Box::new(self.clone()))
        } else {
            None
        }
    }

    fn public_key(&self) -> Option<SubjectPublicKeyInfoDer<'_>> {
        Some(public_key_to_spki(&alg_id::ED25519, self.key.public_key()))
    }
}

impl Signer for Ed25519Signer {
    fn sign(self: Box<Self>, message: &[u8]) -> Result<Vec<u8>, Error> {
        (*self).sign(message)
    }

    fn scheme(&self) -> SignatureScheme {
        self.scheme
    }
}

impl TryFrom<&PrivatePkcs8KeyDer<'_>> for Ed25519Signer {
    type Error = Error;

    /// Parse `der` as an Ed25519 key.
    ///
    /// Note that, at the time of writing, Ed25519 does not have wide support
    /// in browsers.  It is also not supported by the WebPKI, because the
    /// CA/Browser Forum Baseline Requirements do not support it for publicly
    /// trusted certificates.
    fn try_from(der: &PrivatePkcs8KeyDer<'_>) -> Result<Self, Self::Error> {
        match Ed25519KeyPair::from_pkcs8_maybe_unchecked(der.secret_pkcs8_der()) {
            Ok(key_pair) => Ok(Self {
                key: Arc::new(key_pair),
                scheme: SignatureScheme::ED25519,
            }),
            Err(e) => Err(Error::General(format!(
                "failed to parse Ed25519 private key: {e}"
            ))),
        }
    }
}

impl Debug for Ed25519Signer {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ed25519Signer")
            .field("scheme", &self.scheme)
            .finish_non_exhaustive()
    }
}

#[cfg(any(test, bench))]
fn load_key(
    provider: &CryptoProvider,
    der: PrivateKeyDer<'static>,
) -> Result<Box<dyn SigningKey>, Error> {
    provider
        .key_provider
        .load_private_key(der)
}

/// Prepend stuff to `bytes_a` + `bytes_b` to put it in a DER SEQUENCE.
pub(crate) fn wrap_concat_in_sequence(bytes_a: &[u8], bytes_b: &[u8]) -> Vec<u8> {
    asn1_wrap(DER_SEQUENCE_TAG, bytes_a, bytes_b)
}

/// Prepend stuff to `bytes` to put it in a DER OCTET STRING.
pub(crate) fn wrap_in_octet_string(bytes: &[u8]) -> Vec<u8> {
    asn1_wrap(DER_OCTET_STRING_TAG, bytes, &[])
}

fn asn1_wrap(tag: u8, bytes_a: &[u8], bytes_b: &[u8]) -> Vec<u8> {
    let len = bytes_a.len() + bytes_b.len();

    if len <= 0x7f {
        // Short form
        let mut ret = Vec::with_capacity(2 + len);
        ret.push(tag);
        ret.push(len as u8);
        ret.extend_from_slice(bytes_a);
        ret.extend_from_slice(bytes_b);
        ret
    } else {
        // Long form
        let size = len.to_be_bytes();
        let leading_zero_bytes = size
            .iter()
            .position(|&x| x != 0)
            .unwrap_or(size.len());
        assert!(leading_zero_bytes < size.len());
        let encoded_bytes = size.len() - leading_zero_bytes;

        let mut ret = Vec::with_capacity(2 + encoded_bytes + len);
        ret.push(tag);

        ret.push(0x80 + encoded_bytes as u8);
        ret.extend_from_slice(&size[leading_zero_bytes..]);

        ret.extend_from_slice(bytes_a);
        ret.extend_from_slice(bytes_b);
        ret
    }
}

const DER_SEQUENCE_TAG: u8 = 0x30;
const DER_OCTET_STRING_TAG: u8 = 0x04;

#[cfg(test)]
mod tests {
    use alloc::format;

    use pki_types::{PrivatePkcs1KeyDer, PrivateSec1KeyDer};

    use super::*;
    use crate::DEFAULT_PROVIDER;

    #[test]
    fn can_load_ecdsa_nistp256_pkcs8() {
        let key = PrivatePkcs8KeyDer::from(
            &include_bytes!("../../rustls/src/testdata/nistp256key.pkcs8.der")[..],
        );
        assert!(Ed25519Signer::try_from(&key).is_err());
        let key = PrivateKeyDer::Pkcs8(key);
        assert!(load_key(&DEFAULT_PROVIDER, key.clone_key()).is_ok());
        assert!(EcdsaSigner::try_from(&key).is_ok());
    }

    #[test]
    fn can_load_ecdsa_nistp256_sec1() {
        let key = PrivateKeyDer::Sec1(PrivateSec1KeyDer::from(
            &include_bytes!("../../rustls/src/testdata/nistp256key.der")[..],
        ));
        assert!(load_key(&DEFAULT_PROVIDER, key.clone_key()).is_ok());
        assert!(EcdsaSigner::try_from(&key).is_ok());
    }

    #[test]
    fn can_sign_ecdsa_nistp256() {
        let key = PrivateKeyDer::Sec1(PrivateSec1KeyDer::from(
            &include_bytes!("../../rustls/src/testdata/nistp256key.der")[..],
        ));

        let k = load_key(&DEFAULT_PROVIDER, key.clone_key()).unwrap();
        assert_eq!(
            format!("{k:?}"),
            "EcdsaSigner { scheme: ECDSA_NISTP256_SHA256, .. }"
        );

        assert!(
            k.choose_scheme(&[SignatureScheme::RSA_PKCS1_SHA256])
                .is_none()
        );
        assert!(
            k.choose_scheme(&[SignatureScheme::ECDSA_NISTP384_SHA384])
                .is_none()
        );
        let s = k
            .choose_scheme(&[SignatureScheme::ECDSA_NISTP256_SHA256])
            .unwrap();
        assert_eq!(
            format!("{s:?}"),
            "EcdsaSigner { scheme: ECDSA_NISTP256_SHA256, .. }"
        );
        assert_eq!(s.scheme(), SignatureScheme::ECDSA_NISTP256_SHA256);
        // nb. signature is variable length and asn.1-encoded
        assert!(
            s.sign(b"hello")
                .unwrap()
                .starts_with(&[0x30])
        );
    }

    #[test]
    fn can_load_ecdsa_nistp384_pkcs8() {
        let key = PrivatePkcs8KeyDer::from(
            &include_bytes!("../../rustls/src/testdata/nistp384key.pkcs8.der")[..],
        );
        assert!(Ed25519Signer::try_from(&key).is_err());
        let key = PrivateKeyDer::Pkcs8(key);
        assert!(load_key(&DEFAULT_PROVIDER, key.clone_key()).is_ok());
        assert!(EcdsaSigner::try_from(&key).is_ok());
    }

    #[test]
    fn can_load_ecdsa_nistp384_sec1() {
        let key = PrivateKeyDer::Sec1(PrivateSec1KeyDer::from(
            &include_bytes!("../../rustls/src/testdata/nistp384key.der")[..],
        ));
        assert!(load_key(&DEFAULT_PROVIDER, key.clone_key()).is_ok());
        assert!(EcdsaSigner::try_from(&key).is_ok());
    }

    #[test]
    fn can_sign_ecdsa_nistp384() {
        let key = PrivateKeyDer::Sec1(PrivateSec1KeyDer::from(
            &include_bytes!("../../rustls/src/testdata/nistp384key.der")[..],
        ));

        let k = load_key(&DEFAULT_PROVIDER, key.clone_key()).unwrap();
        assert_eq!(
            format!("{k:?}"),
            "EcdsaSigner { scheme: ECDSA_NISTP384_SHA384, .. }"
        );

        assert!(
            k.choose_scheme(&[SignatureScheme::RSA_PKCS1_SHA256])
                .is_none()
        );
        assert!(
            k.choose_scheme(&[SignatureScheme::ECDSA_NISTP256_SHA256])
                .is_none()
        );
        let s = k
            .choose_scheme(&[SignatureScheme::ECDSA_NISTP384_SHA384])
            .unwrap();
        assert_eq!(
            format!("{s:?}"),
            "EcdsaSigner { scheme: ECDSA_NISTP384_SHA384, .. }"
        );
        assert_eq!(s.scheme(), SignatureScheme::ECDSA_NISTP384_SHA384);
        // nb. signature is variable length and asn.1-encoded
        assert!(
            s.sign(b"hello")
                .unwrap()
                .starts_with(&[0x30])
        );
    }

    #[test]
    fn can_load_eddsa_pkcs8() {
        let key =
            PrivatePkcs8KeyDer::from(&include_bytes!("../../rustls/src/testdata/eddsakey.der")[..]);
        assert!(Ed25519Signer::try_from(&key).is_ok());
        let key = PrivateKeyDer::Pkcs8(key);
        assert!(load_key(&DEFAULT_PROVIDER, key.clone_key()).is_ok());
        assert!(EcdsaSigner::try_from(&key).is_err());
    }

    #[test]
    fn can_sign_eddsa() {
        let key =
            PrivatePkcs8KeyDer::from(&include_bytes!("../../rustls/src/testdata/eddsakey.der")[..]);

        let k = Ed25519Signer::try_from(&key).unwrap();
        assert_eq!(format!("{k:?}"), "Ed25519Signer { scheme: ED25519, .. }");

        assert!(
            k.choose_scheme(&[SignatureScheme::RSA_PKCS1_SHA256])
                .is_none()
        );
        assert!(
            k.choose_scheme(&[SignatureScheme::ECDSA_NISTP256_SHA256])
                .is_none()
        );
        let s = k
            .choose_scheme(&[SignatureScheme::ED25519])
            .unwrap();
        assert_eq!(format!("{s:?}"), "Ed25519Signer { scheme: ED25519, .. }");
        assert_eq!(s.scheme(), SignatureScheme::ED25519);
        assert_eq!(s.sign(b"hello").unwrap().len(), 64);
    }

    #[test]
    fn can_load_rsa2048_pkcs8() {
        let key = PrivatePkcs8KeyDer::from(
            &include_bytes!("../../rustls/src/testdata/rsa2048key.pkcs8.der")[..],
        );
        assert!(Ed25519Signer::try_from(&key).is_err());
        let key = PrivateKeyDer::Pkcs8(key);
        assert!(load_key(&DEFAULT_PROVIDER, key.clone_key()).is_ok());
        assert!(EcdsaSigner::try_from(&key).is_err());
    }

    #[test]
    fn can_load_rsa2048_pkcs1() {
        let key = PrivateKeyDer::Pkcs1(PrivatePkcs1KeyDer::from(
            &include_bytes!("../../rustls/src/testdata/rsa2048key.pkcs1.der")[..],
        ));
        assert!(load_key(&DEFAULT_PROVIDER, key.clone_key()).is_ok());
        assert!(EcdsaSigner::try_from(&key).is_err());
    }

    #[test]
    fn can_sign_rsa2048() {
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
            &include_bytes!("../../rustls/src/testdata/rsa2048key.pkcs8.der")[..],
        ));

        let k = load_key(&DEFAULT_PROVIDER, key.clone_key()).unwrap();
        assert_eq!(format!("{k:?}"), "RsaSigningKey { .. }");

        assert!(
            k.choose_scheme(&[SignatureScheme::ECDSA_NISTP256_SHA256])
                .is_none()
        );
        assert!(
            k.choose_scheme(&[SignatureScheme::ED25519])
                .is_none()
        );

        let s = k
            .choose_scheme(&[SignatureScheme::RSA_PSS_SHA256])
            .unwrap();
        assert_eq!(format!("{s:?}"), "RsaSigner { scheme: RSA_PSS_SHA256, .. }");
        assert_eq!(s.scheme(), SignatureScheme::RSA_PSS_SHA256);
        assert_eq!(s.sign(b"hello").unwrap().len(), 256);

        for scheme in &[
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
        ] {
            k.choose_scheme(&[*scheme]).unwrap();
        }
    }

    #[test]
    fn cannot_load_invalid_pkcs8_encoding() {
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(&b"invalid"[..]));
        assert_eq!(
            load_key(&DEFAULT_PROVIDER, key.clone_key()).err(),
            Some(Error::General(
                "failed to parse private key as RSA, ECDSA, or EdDSA".into()
            ))
        );
        assert_eq!(
            EcdsaSigner::try_from(&key).err(),
            Some(Error::General(
                "failed to parse ECDSA private key as PKCS#8 or SEC1".into()
            ))
        );
        assert_eq!(
            RsaSigningKey::try_from(&key).err(),
            Some(Error::General(
                "failed to parse RSA private key: InvalidEncoding".into()
            ))
        );
    }
}

#[cfg(bench)]
mod benchmarks {
    use super::*;
    use crate::DEFAULT_PROVIDER;

    #[bench]
    fn bench_rsa2048_pkcs1_sha256(b: &mut test::Bencher) {
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
            &include_bytes!("../../rustls/src/testdata/rsa2048key.pkcs8.der")[..],
        ));

        let signer = RsaSigningKey::try_from(&key)
            .unwrap()
            .to_signer(SignatureScheme::RSA_PKCS1_SHA256);

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
            &include_bytes!("../../rustls/src/testdata/rsa2048key.pkcs8.der")[..],
        ));

        let signer = RsaSigningKey::try_from(&key)
            .unwrap()
            .to_signer(SignatureScheme::RSA_PSS_SHA256);

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
        let key =
            PrivatePkcs8KeyDer::from(&include_bytes!("../../rustls/src/testdata/eddsakey.der")[..]);
        let signer = Ed25519Signer::try_from(&key).unwrap();

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
            &include_bytes!("../../rustls/src/testdata/nistp256key.pkcs8.der")[..],
        ));

        let signer = EcdsaSigner::try_from(&key).unwrap();
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
            &include_bytes!("../../rustls/src/testdata/nistp384key.pkcs8.der")[..],
        ));

        let signer = EcdsaSigner::try_from(&key).unwrap();
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
            &include_bytes!("../../rustls/src/testdata/rsa2048key.pkcs8.der")[..],
        ));

        b.iter(|| {
            test::black_box(load_key(&DEFAULT_PROVIDER, key.clone_key()).unwrap());
        });
    }

    #[bench]
    fn bench_load_and_validate_rsa4096(b: &mut test::Bencher) {
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
            &include_bytes!("../../rustls/src/testdata/rsa4096key.pkcs8.der")[..],
        ));

        b.iter(|| {
            test::black_box(load_key(&DEFAULT_PROVIDER, key.clone_key()).unwrap());
        });
    }

    #[bench]
    fn bench_load_and_validate_p256(b: &mut test::Bencher) {
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
            &include_bytes!("../../rustls/src/testdata/nistp256key.pkcs8.der")[..],
        ));

        b.iter(|| {
            test::black_box(EcdsaSigner::try_from(&key).unwrap());
        });
    }

    #[bench]
    fn bench_load_and_validate_p384(b: &mut test::Bencher) {
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
            &include_bytes!("../../rustls/src/testdata/nistp384key.pkcs8.der")[..],
        ));

        b.iter(|| {
            test::black_box(EcdsaSigner::try_from(&key).unwrap());
        });
    }

    #[bench]
    fn bench_load_and_validate_eddsa(b: &mut test::Bencher) {
        let key =
            PrivatePkcs8KeyDer::from(&include_bytes!("../../rustls/src/testdata/eddsakey.der")[..]);

        b.iter(|| {
            test::black_box(Ed25519Signer::try_from(&key).unwrap());
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
