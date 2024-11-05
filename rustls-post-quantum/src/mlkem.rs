use aws_lc_rs::kem;
use aws_lc_rs::unstable::kem::{
    // ML_KEM_1024, ML_KEM_512,
    ML_KEM_768,
};
use rustls::crypto::aws_lc_rs::{default_provider, kx_group};
use rustls::crypto::{ActiveKeyExchange, CompletedKeyExchange, SharedSecret, SupportedKxGroup};
use rustls::ffdhe_groups::FfdheGroup;
use rustls::{Error, NamedGroup, PeerMisbehaved, ProtocolVersion};

/// This is the [MLKEM] key exchange.
///
/// [MLKEM]: https://datatracker.ietf.org/doc/draft-connolly-tls-mlkem-key-agreement
#[derive(Debug)]
pub struct MLKEM768;

impl SupportedKxGroup for MLKEM768 {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, Error> {
        let decaps_key = kem::DecapsulationKey::generate(&ML_KEM_768)
            .map_err(|_| Error::FailedToGetRandomBytes)?;

        let encaps_key = decaps_key
            .encapsulation_key()
            .map_err(|_| Error::FailedToGetRandomBytes)?;

        let pub_key_bytes = encaps_key.key_bytes().unwrap();

        Ok(Box::new(Active {
            decaps_key: Box::new(decaps_key),
            encaps_key_bytes: Vec::from(pub_key_bytes.as_ref()),
        }))
    }

    fn start_and_complete(&self, client_share: &[u8]) -> Result<CompletedKeyExchange, Error> {
        let (ciphertext, shared_secret) = kem::EncapsulationKey::new(&ML_KEM_768, client_share)
            .map_err(|_| INVALID_KEY_SHARE)
            .and_then(|encaps_key| {
                encaps_key
                    .encapsulate()
                    .map_err(|_| INVALID_KEY_SHARE)
            })?;

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
        NAMED_GROUP
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
        NAMED_GROUP
    }
}

// IANA TLS Supported Group value 513, 0x0201
//
// https://www.iana.org/assignments/tls-para≈1meters/tls-parameters.xhtml#tls-parameters-8
const NAMED_GROUP: NamedGroup = NamedGroup::Unknown(0x0201);

const INVALID_KEY_SHARE: Error = Error::PeerMisbehaved(PeerMisbehaved::InvalidKeyShare);

const MLKEM768_CIPHERTEXT_LEN: usize = 1088;
const MLKEM768_ENCAPS_KEY_LEN: usize = 1184;
const MLKEM768_SHARED_SECRET_LEN: usize = 32;
