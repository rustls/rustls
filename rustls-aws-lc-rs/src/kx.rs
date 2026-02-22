use alloc::boxed::Box;
use alloc::vec::Vec;
use core::fmt;

use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::{agreement, kem};
use pki_types::FipsStatus;
use rustls::crypto::GetRandomFailed;
use rustls::crypto::kx::{
    ActiveKeyExchange, CompletedKeyExchange, Hybrid, HybridLayout, NamedGroup, SharedSecret,
    StartedKeyExchange, SupportedKxGroup,
};
use rustls::error::{Error, PeerMisbehaved};

/// This is the [X25519MLKEM768] key exchange.
///
/// [X25519MLKEM768]: <https://datatracker.ietf.org/doc/draft-ietf-tls-ecdhe-mlkem/>
pub static X25519MLKEM768: &dyn SupportedKxGroup = &Hybrid {
    classical: X25519,
    post_quantum: MLKEM768,
    name: NamedGroup::X25519MLKEM768,
    layout: HybridLayout {
        classical_share_len: X25519_LEN,
        post_quantum_client_share_len: MLKEM768_ENCAP_LEN,
        post_quantum_server_share_len: MLKEM768_CIPHERTEXT_LEN,
        post_quantum_first: true,
    },
};

/// This is the [SECP256R1MLKEM768] key exchange.
///
/// [SECP256R1MLKEM768]: <https://datatracker.ietf.org/doc/draft-ietf-tls-ecdhe-mlkem/>
pub static SECP256R1MLKEM768: &dyn SupportedKxGroup = &Hybrid {
    classical: SECP256R1,
    post_quantum: MLKEM768,
    name: NamedGroup::secp256r1MLKEM768,
    layout: HybridLayout {
        classical_share_len: SECP256R1_LEN,
        post_quantum_client_share_len: MLKEM768_ENCAP_LEN,
        post_quantum_server_share_len: MLKEM768_CIPHERTEXT_LEN,
        post_quantum_first: false,
    },
};

/// This is the [MLKEM] key encapsulation mechanism in NIST with security category 3.
///
/// [MLKEM]: https://datatracker.ietf.org/doc/draft-ietf-tls-mlkem
pub static MLKEM768: &dyn SupportedKxGroup = &MlKem {
    alg: &kem::ML_KEM_768,
    group: NamedGroup::MLKEM768,
};

/// This is the [MLKEM] key encapsulation mechanism in NIST with security category 5.
///
/// [MLKEM]: https://datatracker.ietf.org/doc/draft-ietf-tls-mlkem
pub static MLKEM1024: &dyn SupportedKxGroup = &MlKem {
    alg: &kem::ML_KEM_1024,
    group: NamedGroup::MLKEM1024,
};

#[derive(Debug)]
pub(crate) struct MlKem {
    alg: &'static kem::Algorithm<kem::AlgorithmId>,
    group: NamedGroup,
}

impl SupportedKxGroup for MlKem {
    fn start(&self) -> Result<StartedKeyExchange, Error> {
        let decaps_key = kem::DecapsulationKey::generate(self.alg)
            .map_err(|_| Error::General("key generation failed".into()))?;

        let pub_key_bytes = decaps_key
            .encapsulation_key()
            .and_then(|encaps_key| encaps_key.key_bytes())
            .map_err(|_| Error::General("encaps failed".into()))?;

        Ok(StartedKeyExchange::Single(Box::new(Active {
            group: self.group,
            decaps_key: Box::new(decaps_key),
            encaps_key_bytes: Vec::from(pub_key_bytes.as_ref()),
        })))
    }

    fn start_and_complete(&self, client_share: &[u8]) -> Result<CompletedKeyExchange, Error> {
        let encaps_key = kem::EncapsulationKey::new(self.alg, client_share)
            .map_err(|_| PeerMisbehaved::InvalidKeyShare)?;

        let (ciphertext, shared_secret) = encaps_key
            .encapsulate()
            .map_err(|_| PeerMisbehaved::InvalidKeyShare)?;

        Ok(CompletedKeyExchange {
            group: self.name(),
            pub_key: Vec::from(ciphertext.as_ref()),
            secret: SharedSecret::from(shared_secret.as_ref()),
        })
    }

    fn name(&self) -> NamedGroup {
        self.group
    }

    fn fips(&self) -> FipsStatus {
        // AUDITORS:
        // At the time of writing, the ML-KEM implementation in AWS-LC-FIPS module 3.0
        // is FIPS-pending.  Some regulatory regimes (eg, FedRAMP rev 5 SC-13) allow
        // use of implementations in this state, as if they are already approved.
        //
        // We follow this liberal interpretation, and say MlKem768 is FIPS-compliant
        // if the underlying library is in FIPS mode.
        //
        // TODO: adjust the `fips()` function return type to allow more policies to
        // be expressed, perhaps following something like
        // <https://github.com/golang/go/issues/70200#issuecomment-2490017956> --
        // see <https://github.com/rustls/rustls/issues/2309>
        super::fips()
    }
}

struct Active {
    group: NamedGroup,
    decaps_key: Box<kem::DecapsulationKey<kem::AlgorithmId>>,
    encaps_key_bytes: Vec<u8>,
}

impl ActiveKeyExchange for Active {
    // The received 'peer_pub_key' is actually the ML-KEM ciphertext,
    // which when decapsulated with our `decaps_key` produces the shared
    // secret.
    fn complete(self: Box<Self>, peer_pub_key: &[u8]) -> Result<SharedSecret, Error> {
        let shared_secret = self
            .decaps_key
            .decapsulate(peer_pub_key.into())
            .map_err(|_| PeerMisbehaved::InvalidKeyShare)?;

        Ok(SharedSecret::from(shared_secret.as_ref()))
    }

    fn pub_key(&self) -> &[u8] {
        &self.encaps_key_bytes
    }

    fn group(&self) -> NamedGroup {
        self.group
    }
}

const X25519_LEN: usize = 32;
const SECP256R1_LEN: usize = 65;
const MLKEM768_CIPHERTEXT_LEN: usize = 1088;
const MLKEM768_ENCAP_LEN: usize = 1184;

/// A key-exchange group supported by *ring*.
struct KxGroup {
    /// The IANA "TLS Supported Groups" name of the group
    name: NamedGroup,

    /// The corresponding ring agreement::Algorithm
    agreement_algorithm: &'static agreement::Algorithm,

    /// Whether the algorithm is allowed by FIPS
    ///
    /// `SupportedKxGroup::fips()` is true if and only if the algorithm is allowed,
    /// _and_ the implementation is FIPS-validated.
    fips_allowed: bool,

    /// aws-lc-rs 1.9 and later accepts more formats of public keys than
    /// just uncompressed.
    ///
    /// That is not compatible with TLS:
    /// - TLS1.3 outlaws other encodings,
    /// - TLS1.2 negotiates other encodings (we only offer uncompressed), and
    ///   defaults to uncompressed if negotiation is not done.
    ///
    /// This function should return `true` if the basic shape of its argument
    /// is consistent with an uncompressed point encoding.  It does not need
    /// to verify that the point is on the curve (if the curve requires that
    /// for security); aws-lc-rs/ring must do that.
    pub_key_validator: fn(&[u8]) -> bool,
}

impl SupportedKxGroup for KxGroup {
    fn start(&self) -> Result<StartedKeyExchange, Error> {
        let rng = SystemRandom::new();
        let priv_key = agreement::EphemeralPrivateKey::generate(self.agreement_algorithm, &rng)
            .map_err(|_| GetRandomFailed)?;

        let pub_key = priv_key
            .compute_public_key()
            .map_err(|_| GetRandomFailed)?;

        Ok(StartedKeyExchange::Single(Box::new(KeyExchange {
            name: self.name,
            agreement_algorithm: self.agreement_algorithm,
            priv_key,
            pub_key,
            pub_key_validator: self.pub_key_validator,
        })))
    }

    fn name(&self) -> NamedGroup {
        self.name
    }

    fn fips(&self) -> FipsStatus {
        match self.fips_allowed {
            true => super::fips(),
            false => FipsStatus::Unvalidated,
        }
    }
}

impl fmt::Debug for KxGroup {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.name.fmt(f)
    }
}

/// Ephemeral ECDH on curve25519 (see RFC7748)
pub static X25519: &dyn SupportedKxGroup = &KxGroup {
    name: NamedGroup::X25519,
    agreement_algorithm: &agreement::X25519,

    // "Curves that are included in SP 800-186 but not included in SP 800-56Arev3 are
    //  not approved for key agreement. E.g., the ECDH X25519 and X448 key agreement
    //  schemes (defined in RFC 7748) that use Curve25519 and Curve448, respectively,
    //  are not compliant to SP 800-56Arev3."
    // -- <https://csrc.nist.gov/csrc/media/Projects/cryptographic-module-validation-program/documents/fips%20140-3/FIPS%20140-3%20IG.pdf>
    fips_allowed: false,

    pub_key_validator: |point: &[u8]| point.len() == 32,
};

/// Ephemeral ECDH on secp256r1 (aka NIST-P256)
pub static SECP256R1: &dyn SupportedKxGroup = &KxGroup {
    name: NamedGroup::secp256r1,
    agreement_algorithm: &agreement::ECDH_P256,
    fips_allowed: true,
    pub_key_validator: uncompressed_point,
};

/// Ephemeral ECDH on secp384r1 (aka NIST-P384)
pub static SECP384R1: &dyn SupportedKxGroup = &KxGroup {
    name: NamedGroup::secp384r1,
    agreement_algorithm: &agreement::ECDH_P384,
    fips_allowed: true,
    pub_key_validator: uncompressed_point,
};

fn uncompressed_point(point: &[u8]) -> bool {
    // See `UncompressedPointRepresentation`, which is a retelling of
    // SEC1 section 2.3.3 "Elliptic-Curve-Point-to-Octet-String Conversion"
    // <https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.8.2>
    matches!(point.first(), Some(0x04))
}

/// An in-progress key exchange.  This has the algorithm,
/// our private key, and our public key.
struct KeyExchange {
    name: NamedGroup,
    agreement_algorithm: &'static agreement::Algorithm,
    priv_key: agreement::EphemeralPrivateKey,
    pub_key: agreement::PublicKey,
    pub_key_validator: fn(&[u8]) -> bool,
}

impl ActiveKeyExchange for KeyExchange {
    /// Completes the key exchange, given the peer's public key.
    fn complete(self: Box<Self>, peer: &[u8]) -> Result<SharedSecret, Error> {
        if !(self.pub_key_validator)(peer) {
            return Err(PeerMisbehaved::InvalidKeyShare.into());
        }
        let peer_key = agreement::UnparsedPublicKey::new(self.agreement_algorithm, peer);
        super::ring_shim::agree_ephemeral(self.priv_key, &peer_key)
            .map_err(|_| PeerMisbehaved::InvalidKeyShare.into())
    }

    /// Return the group being used.
    fn group(&self) -> NamedGroup {
        self.name
    }

    /// Return the public key being used.
    fn pub_key(&self) -> &[u8] {
        self.pub_key.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use std::format;

    #[test]
    fn kxgroup_fmt_yields_name() {
        assert_eq!("X25519", format!("{:?}", super::X25519));
    }
}

#[cfg(all(test, bench))]
mod benchmarks {
    #[bench]
    fn bench_x25519(b: &mut test::Bencher) {
        bench_any(b, super::X25519);
    }

    #[bench]
    fn bench_ecdh_p256(b: &mut test::Bencher) {
        bench_any(b, super::SECP256R1);
    }

    #[bench]
    fn bench_ecdh_p384(b: &mut test::Bencher) {
        bench_any(b, super::SECP384R1);
    }

    fn bench_any(b: &mut test::Bencher, kxg: &dyn super::SupportedKxGroup) {
        b.iter(|| {
            let akx = kxg.start().unwrap().into_single();
            let pub_key = akx.pub_key().to_vec();
            test::black_box(akx.complete(&pub_key).unwrap());
        });
    }
}
