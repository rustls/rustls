use aws_lc_rs::kem;
use aws_lc_rs::unstable::kem::ML_KEM_768;
use rustls::crypto::{ActiveKeyExchange, CompletedKeyExchange, SharedSecret, SupportedKxGroup};
use rustls::ffdhe_groups::FfdheGroup;
use rustls::{Error, NamedGroup, ProtocolVersion};

use crate::INVALID_KEY_SHARE;

#[derive(Debug)]
pub(crate) struct MlKem768;

impl SupportedKxGroup for MlKem768 {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, Error> {
        let decaps_key = kem::DecapsulationKey::generate(&ML_KEM_768)
            .map_err(|_| Error::General("key generation failed".into()))?;

        let pub_key_bytes = decaps_key
            .encapsulation_key()
            .and_then(|encaps_key| encaps_key.key_bytes())
            .map_err(|_| Error::General("encaps failed".into()))?;

        Ok(Box::new(Active {
            decaps_key: Box::new(decaps_key),
            encaps_key_bytes: Vec::from(pub_key_bytes.as_ref()),
        }))
    }

    fn start_and_complete(&self, client_share: &[u8]) -> Result<CompletedKeyExchange, Error> {
        let encaps_key =
            kem::EncapsulationKey::new(&ML_KEM_768, client_share).map_err(|_| INVALID_KEY_SHARE)?;

        let (ciphertext, shared_secret) = encaps_key
            .encapsulate()
            .map_err(|_| INVALID_KEY_SHARE)?;

        Ok(CompletedKeyExchange {
            group: self.name(),
            pub_key: Vec::from(ciphertext.as_ref()),
            secret: SharedSecret::from(shared_secret.as_ref()),
        })
    }

    fn ffdhe_group(&self) -> Option<FfdheGroup<'static>> {
        None
    }

    fn name(&self) -> NamedGroup {
        NamedGroup::MLKEM768
    }

    fn usable_for_version(&self, version: ProtocolVersion) -> bool {
        version == ProtocolVersion::TLSv1_3
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
            .map_err(|_| INVALID_KEY_SHARE)?;

        Ok(SharedSecret::from(shared_secret.as_ref()))
    }

    fn pub_key(&self) -> &[u8] {
        &self.encaps_key_bytes
    }

    fn ffdhe_group(&self) -> Option<FfdheGroup<'static>> {
        None
    }

    fn group(&self) -> NamedGroup {
        NamedGroup::MLKEM768
    }
}
