use core::fmt;
use core::panic::Location;
use std::sync::Arc;

use rustls::crypto::cipher::{KeyBlockShape, Tls12AeadAlgorithm};
use rustls::crypto::hash::{Hash, Output};
use rustls::crypto::kx::{
    ActiveKeyExchange, KeyExchangeAlgorithm, NamedGroup, SharedSecret, SupportedKxGroup,
};
use rustls::crypto::tls12::Prf;
use rustls::crypto::{
    CipherSuite, CryptoProvider, HashAlgorithm, KeyProvider, SecureRandom, SignatureScheme,
    SigningKey, TicketProducer, TicketerFactory, WebPkiSupportedAlgorithms,
};
use rustls::pki_types::{PrivateKeyDer, SignatureVerificationAlgorithm};
use rustls::{CipherSuiteCommon, SupportedCipherSuite, Tls12CipherSuite, Tls13CipherSuite};

/// Tests the given `CryptoProvider`.
///
/// Returns `Ok(_)` if all attempted tests pass.
///
/// Returns `Err(_)` if any attempted test fails.  This means not all
/// tests will have run.
///
/// The returned report will detail any untested items in the provider
/// (and why).
pub fn test(provider: CryptoProvider) -> Result<Report, Error> {
    Report::for_provider(provider)
}

#[derive(Debug, Default)]
pub struct Report {
    /// Items that were present in the provider, but this library cannot test.
    untested: Vec<ReportItem>,

    /// Tested items that passed.
    passed: Vec<ReportItem>,

    /// Attempted tests that weren't supported by the provider.
    unsupported: Vec<UnsupportedItem>,
}

impl Report {
    /// Returns true if no items were left untested.
    ///
    /// If this library tests everything your provider offers, then
    /// you can assert this.
    pub fn everything_was_tested(&self) -> bool {
        self.untested.is_empty()
    }

    fn for_provider(provider: CryptoProvider) -> Result<Self, Error> {
        let CryptoProvider {
            tls12_cipher_suites,
            tls13_cipher_suites,
            kx_groups,
            signature_verification_algorithms,
            secure_random,
            key_provider,
            ticketer_factory,
        } = provider;

        let mut r = Self::default();

        for cs in tls12_cipher_suites.as_ref() {
            r.test_tls12_cipher_suite(cs)?;
        }

        for cs in tls13_cipher_suites.as_ref() {
            r.test_tls13_cipher_suite(cs)?;
        }

        for kxg in kx_groups.as_ref() {
            r.test_kx_group(*kxg)?;
        }

        r.test_sigver(signature_verification_algorithms)?;
        r.test_key_provider(key_provider)?;
        r.test_ticketer_factory(ticketer_factory)?;
        check_random(secure_random)?;
        Ok(r)
    }

    fn test_tls12_cipher_suite(&mut self, suite: &'static Tls12CipherSuite) -> Result<(), Error> {
        match suite {
            Tls12CipherSuite {
                common:
                    CipherSuiteCommon {
                        suite: CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                        ..
                    },
                ..
            } => {
                check_sha256(suite.common.hash_provider)?;
                Error::assert(
                    suite.common.confidentiality_limit <= 0x100_0000,
                    "excess confidentiality_limit for AES_128_GCM",
                )?;
                check_tls12_prf_sha256(suite.prf_provider)?;
                Error::assert_eq(suite.kx, KeyExchangeAlgorithm::ECDHE, "wrong kx")?;
                check_tls12_ecdsa_suite(suite.sign)?;
                check_tls12_aead(suite.aead_alg, BaselineAead::Aes128Gcm)?;

                self.passed
                    .push(ReportItem::CipherSuite(SupportedCipherSuite::Tls12(suite)));
            }
            _ => self
                .untested
                .push(ReportItem::CipherSuite(SupportedCipherSuite::Tls12(suite))),
        }

        Ok(())
    }

    fn test_tls13_cipher_suite(&mut self, suite: &'static Tls13CipherSuite) -> Result<(), Error> {
        self.untested
            .push(ReportItem::CipherSuite(SupportedCipherSuite::Tls13(suite)));
        Ok(())
    }

    fn test_kx_group(&mut self, kxg: &'static dyn SupportedKxGroup) -> Result<(), Error> {
        self.untested
            .push(ReportItem::KeyExchangeGroup(kxg));
        Ok(())
    }

    fn test_sigver(&mut self, sigver: WebPkiSupportedAlgorithms) -> Result<(), Error> {
        for a in sigver.chain_validation_algorithms() {
            self.untested
                .push(ReportItem::SignatureVerification(*a));
        }
        for (_scheme, algs) in sigver.mapping() {
            for a in *algs {
                self.untested
                    .push(ReportItem::SignatureVerification(*a));
            }
        }
        Ok(())
    }

    fn test_key_provider(&mut self, key_provider: &'static dyn KeyProvider) -> Result<(), Error> {
        for (format, expected, data) in [
            (
                "ecdsa-nistp256-sec1",
                SigningKeyType::EcdsaP256,
                PrivateKeyDer::Sec1(
                    include_bytes!("testdata/nistp256key.der")
                        .as_slice()
                        .into(),
                ),
            ),
            (
                "ecdsa-nistp256-pkcs8",
                SigningKeyType::EcdsaP256,
                PrivateKeyDer::Pkcs8(
                    include_bytes!("testdata/nistp256key.pkcs8.der")
                        .as_slice()
                        .into(),
                ),
            ),
            (
                "ecdsa-nistp384-sec1",
                SigningKeyType::EcdsaP384,
                PrivateKeyDer::Sec1(
                    include_bytes!("testdata/nistp384key.der")
                        .as_slice()
                        .into(),
                ),
            ),
            (
                "ecdsa-nistp384-pkcs8",
                SigningKeyType::EcdsaP384,
                PrivateKeyDer::Pkcs8(
                    include_bytes!("testdata/nistp384key.pkcs8.der")
                        .as_slice()
                        .into(),
                ),
            ),
            (
                "ecdsa-nistp521-sec1",
                SigningKeyType::EcdsaP521,
                PrivateKeyDer::Sec1(
                    include_bytes!("testdata/nistp521key.der")
                        .as_slice()
                        .into(),
                ),
            ),
            (
                "ecdsa-nistp521-pkcs8",
                SigningKeyType::EcdsaP521,
                PrivateKeyDer::Pkcs8(
                    include_bytes!("testdata/nistp521key.pkcs8.der")
                        .as_slice()
                        .into(),
                ),
            ),
            (
                "ed25519-pkcs8v2",
                SigningKeyType::Ed25519,
                PrivateKeyDer::Pkcs8(
                    include_bytes!("testdata/eddsakey.der")
                        .as_slice()
                        .into(),
                ),
            ),
        ] {
            match key_provider.load_private_key(data) {
                Ok(k) => {
                    self.test_signing_key(format, k.as_ref(), expected)?;
                }
                Err(error) => {
                    self.unsupported
                        .push(UnsupportedItem::PrivateKeyFormat {
                            format: format.to_string(),
                            error: Error::from_rustls(
                                error,
                                "KeyProvider::load_private_key failed",
                            ),
                        });
                }
            }
        }
        Ok(())
    }

    fn test_signing_key(
        &mut self,
        format: &str,
        signing_key: &dyn SigningKey,
        expect: SigningKeyType,
    ) -> Result<(), Error> {
        match signing_key.public_key() {
            Some(_) => self
                .passed
                .push(ReportItem::PrivateKeyCanComputePublicKey(
                    format.to_string(),
                )),
            None => self
                .unsupported
                .push(UnsupportedItem::PrivateKeyCanComputePublicKey(
                    format.to_string(),
                )),
        };

        Error::assert(
            signing_key
                .choose_scheme(&expect.unsuitable_schemes())
                .is_none(),
            &format!(
                "signing key {signing_key:?} for {format} responded for unsuitable schemes {:?}",
                expect.unsuitable_schemes()
            ),
        )?;

        let Some(signer) = signing_key.choose_scheme(expect.possible_schemes()) else {
            return Ok(());
        };
        Error::assert(
            expect
                .possible_schemes()
                .contains(&signer.scheme()),
            &format!(
                "signing key for {format} was for {:?}, expected one of {expect:?}",
                signer.scheme()
            ),
        )?;
        match signer.sign(b"unused") {
            Ok(sig) => expect.correct_signature_structure(sig)?,
            Err(e) => return Err(Error::from_rustls(e, "sign() for {format:?} failed")),
        };

        self.passed
            .push(ReportItem::PrivateKeyFormat(format.to_string()));
        Ok(())
    }

    fn test_ticketer_factory(
        &mut self,
        ticketer_factory: &'static dyn TicketerFactory,
    ) -> Result<(), Error> {
        match ticketer_factory.ticketer() {
            Ok(ticketer) => self.test_ticketer(ticketer)?,
            Err(error) => self
                .unsupported
                .push(UnsupportedItem::TicketerProvider {
                    error: Error::from_rustls(error, "TicketerFactory::ticketer failed"),
                }),
        };
        Ok(())
    }

    fn test_ticketer(&mut self, ticketer: Arc<dyn TicketProducer + 'static>) -> Result<(), Error> {
        // basic pairwise
        let message = b"hello world";
        let cipher = ticketer.encrypt(message).unwrap();
        let decrypted = ticketer.decrypt(&cipher).unwrap();
        Error::assert_eq(
            decrypted.as_slice(),
            &message[..],
            "ticketer not pair-wise consistent",
        )?;
        self.passed.push(ReportItem::Ticketer);
        Ok(())
    }
}

impl fmt::Display for Report {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "PASSED:")?;
        if self.passed.is_empty() {
            writeln!(f, "  (nothing)")?;
        } else {
            for u in &self.passed {
                writeln!(f, " - {u:?}")?;
            }
        }
        writeln!(f)?;

        if !self.untested.is_empty() {
            writeln!(f, "NOT tested:")?;

            for u in &self.untested {
                writeln!(f, " - {u:?}")?;
            }
        }

        if !self.unsupported.is_empty() {
            writeln!(f, "Attempted but NOT supported:")?;

            for u in &self.unsupported {
                writeln!(f, " - {u:?}")?;
            }
        }

        Ok(())
    }
}

#[derive(Debug)]
pub enum ReportItem {
    CipherSuite(SupportedCipherSuite),
    KeyExchangeGroup(&'static dyn SupportedKxGroup),
    PrivateKeyCanComputePublicKey(String),
    PrivateKeyCanSignWith {
        format: String,
        scheme: SignatureScheme,
    },
    PrivateKeyFormat(String),
    SignatureVerification(&'static dyn SignatureVerificationAlgorithm),
    Ticketer,
}

#[derive(Debug)]
pub enum UnsupportedItem {
    PrivateKeyCanComputePublicKey(String),
    PrivateKeyCanSignWith {
        format: String,
        scheme: SignatureScheme,
    },
    PrivateKeyFormat {
        format: String,
        error: Error,
    },
    TicketerProvider {
        error: Error,
    },
}

#[derive(Debug)]
enum SigningKeyType {
    EcdsaP256,
    EcdsaP384,
    EcdsaP521,
    Ed25519,
}

impl SigningKeyType {
    fn possible_schemes(&self) -> &[SignatureScheme] {
        match self {
            Self::EcdsaP256 => &[SignatureScheme::ECDSA_NISTP256_SHA256],
            Self::EcdsaP384 => &[SignatureScheme::ECDSA_NISTP384_SHA384],
            Self::EcdsaP521 => &[SignatureScheme::ECDSA_NISTP521_SHA512],
            Self::Ed25519 => &[SignatureScheme::ED25519],
        }
    }

    fn unsuitable_schemes(&self) -> Vec<SignatureScheme> {
        let mut all_schemes = vec![
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::RSA_PKCS1_SHA1,
            SignatureScheme::ECDSA_SHA1_Legacy,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::SM2_SM3,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
            SignatureScheme::ED448,
            SignatureScheme::ML_DSA_44,
            SignatureScheme::ML_DSA_65,
            SignatureScheme::ML_DSA_87,
        ];
        let desired = self.possible_schemes();
        all_schemes.retain(|s| !desired.contains(s));
        all_schemes
    }

    fn correct_signature_structure(&self, signature: Vec<u8>) -> Result<(), Error> {
        match self {
            Self::EcdsaP256 | Self::EcdsaP384 | Self::EcdsaP521 => Error::assert_eq(
                signature.first(),
                Some(&0x30),
                "ECDSA signatures must be ASN.1-encoded",
            ),
            Self::Ed25519 => Error::assert_eq(
                signature.len(),
                64,
                "Ed25519 signatures must be exactly 64 bytes",
            ),
        }
    }
}

enum BaselineAead {
    Aes128Gcm,
}

impl BaselineAead {
    fn check_key_block_shape(&self, kb: KeyBlockShape) -> Result<(), Error> {
        match self {
            Self::Aes128Gcm => {
                Error::assert_eq(
                    (kb.enc_key_len, kb.fixed_iv_len, kb.explicit_nonce_len),
                    (16, 4, 8),
                    "wrong KeyBlockShape",
                )?;
            }
        }
        Ok(())
    }
}

fn check_sha256(hash: &dyn Hash) -> Result<(), Error> {
    Error::assert_eq(
        hash.algorithm(),
        HashAlgorithm::SHA256,
        "sha256 misidentified",
    )?;
    Error::assert_eq(hash.output_len(), 32, "sha256 wrong output_len")?;
    Error::assert_eq(
        hash.start().finish().as_ref(),
        Output::new(
            b"\xe3\xb0\xc4\x42\x98\xfc\x1c\x14\x9a\xfb\xf4\xc8\x99\x6f\xb9\x24\
              \x27\xae\x41\xe4\x64\x9b\x93\x4c\xa4\x95\x99\x1b\x78\x52\xb8\x55",
        )
        .as_ref(),
        "sha256 wrong output for ''",
    )?;
    Error::assert_eq(
        hash.start().finish().as_ref(),
        hash.hash(b"").as_ref(),
        "inconsistent hash output for ''",
    )?;
    // TODO: verify operation of fork(), fork_finish(), update()
    Ok(())
}

fn check_tls12_ecdsa_suite(schemes: &[SignatureScheme]) -> Result<(), Error> {
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

fn check_tls12_aead(alg: &dyn Tls12AeadAlgorithm, baseline: BaselineAead) -> Result<(), Error> {
    baseline.check_key_block_shape(alg.key_block_shape())?;
    // TODO: check remaining members
    Ok(())
}

fn check_tls12_prf_sha256(prf: &dyn Prf) -> Result<(), Error> {
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
    .unwrap();

    Error::assert_eq(
        &output,
        b"\xe3\xf2\x29\xba\x72\x7b\xe1\x7b\x8d\x12\x26\x20\x55\x7c\xd4\x53\xc2\xaa\xb2\x1d\x07\xc3\xd4\x95\
          \x32\x9b\x52\xd4\xe6\x1e\xdb\x5a\x6b\x30\x17\x91\xe9\x0d\x35\xc9\xc9\xa4\x6b\x4e\x14\xba\xf9\xaf",
        "wrong TLS1.2 PRF-SHA256 output")?;

    prf.new_secret(&[0u8; 48])
        .prf(&mut output, b"label", b"seed");
    Error::assert_eq(output[0], b',', "yo")?;

    Ok(())
}

struct InjectSharedSecret(&'static [u8]);

impl ActiveKeyExchange for InjectSharedSecret {
    fn complete(self: Box<Self>, _peer_pub_key: &[u8]) -> Result<SharedSecret, rustls::Error> {
        Ok(SharedSecret::from(self.0))
    }

    fn pub_key(&self) -> &[u8] {
        todo!()
    }

    fn group(&self) -> NamedGroup {
        NamedGroup(0)
    }
}

fn check_random(rand: &dyn SecureRandom) -> Result<(), Error> {
    let mut buffer = [0u8; 256];
    rand.fill(&mut buffer)
        .map_err(|err| Error::from_rustls(err.into(), "SecureRandom::fill reported error"))?;

    Ok(())
}

#[derive(Debug)]
pub struct Error {
    rustls_error: Option<rustls::Error>,
    message: String,
}

impl Error {
    fn from_rustls(err: rustls::Error, why: &str) -> Self {
        Self {
            rustls_error: Some(err),
            message: why.to_owned(),
        }
    }

    fn from_string(message: String) -> Self {
        Self {
            rustls_error: None,
            message,
        }
    }

    #[track_caller]
    fn assert(pass: bool, why: &str) -> Result<(), Self> {
        match pass {
            true => Ok(()),
            false => Err(Self::from_string(format!(
                "{why}: assertion failed at {}",
                Location::caller()
            ))),
        }
    }

    #[track_caller]
    fn assert_eq<T: PartialEq + fmt::Debug>(a: T, b: T, why: &str) -> Result<(), Self> {
        match a == b {
            true => Ok(()),
            false => Err(Self::from_string(format!(
                "{why}: {a:?} != {b:?} at {}",
                Location::caller()
            ))),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Error: {}", self.message)?;
        if let Some(cause) = &self.rustls_error {
            write!(f, "\n  caused by {cause}")?;
        }
        Ok(())
    }
}
