use alloc::boxed::Box;
use alloc::vec::Vec;

use aws_lc_rs::kem;

use super::kx_group;
use crate::crypto::kx::{
    ActiveKeyExchange, CompletedKeyExchange, Hybrid, HybridLayout, NamedGroup, SharedSecret,
    StartedKeyExchange, SupportedKxGroup,
};
use crate::error::{Error, PeerMisbehaved};

/// This is the [X25519MLKEM768] key exchange.
///
/// [X25519MLKEM768]: <https://datatracker.ietf.org/doc/draft-ietf-tls-ecdhe-mlkem/>
pub static X25519MLKEM768: &dyn SupportedKxGroup = &Hybrid {
    classical: kx_group::X25519,
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
    classical: kx_group::SECP256R1,
    post_quantum: MLKEM768,
    name: NamedGroup::secp256r1MLKEM768,
    layout: HybridLayout {
        classical_share_len: SECP256R1_LEN,
        post_quantum_client_share_len: MLKEM768_ENCAP_LEN,
        post_quantum_server_share_len: MLKEM768_CIPHERTEXT_LEN,
        post_quantum_first: false,
    },
};

/// This is the [MLKEM] key exchange.
///
/// [MLKEM]: https://datatracker.ietf.org/doc/draft-connolly-tls-mlkem-key-agreement
pub static MLKEM768: &dyn SupportedKxGroup = &MlKem768;

#[derive(Debug)]
pub(crate) struct MlKem768;

impl SupportedKxGroup for MlKem768 {
    fn start(&self) -> Result<StartedKeyExchange, Error> {
        let decaps_key = kem::DecapsulationKey::generate(&kem::ML_KEM_768)
            .map_err(|_| Error::General("key generation failed".into()))?;

        let pub_key_bytes = decaps_key
            .encapsulation_key()
            .and_then(|encaps_key| encaps_key.key_bytes())
            .map_err(|_| Error::General("encaps failed".into()))?;

        Ok(StartedKeyExchange::Single(Box::new(Active {
            decaps_key: Box::new(decaps_key),
            encaps_key_bytes: Vec::from(pub_key_bytes.as_ref()),
        })))
    }

    fn start_and_complete(&self, client_share: &[u8]) -> Result<CompletedKeyExchange, Error> {
        let encaps_key = kem::EncapsulationKey::new(&kem::ML_KEM_768, client_share)
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
        NamedGroup::MLKEM768
    }

    fn fips(&self) -> bool {
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
        NamedGroup::MLKEM768
    }
}

const X25519_LEN: usize = 32;
const SECP256R1_LEN: usize = 65;
const MLKEM768_CIPHERTEXT_LEN: usize = 1088;
const MLKEM768_ENCAP_LEN: usize = 1184;
