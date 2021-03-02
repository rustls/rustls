use crate::msgs::enums::{ECHVersion, KEM};
use crate::msgs::handshake::{ECHConfigContents, ECHConfig};
use hpke::{kem, Kem};
use hpke::kex::Serializable;

use crate::msgs::codec::{Codec, Reader};

// TODO: delegate to ring?
use rand::{rngs::StdRng, SeedableRng};
use crate::msgs::base::PayloadU16;

pub type HPKEPrivateKey = Vec<u8>;
pub type HPKEPublicKey = Vec<u8>;

#[derive(Clone, Debug)]
pub struct HPKEKeyPair {
    pub kem_id: KEM,
    pub private_key: HPKEPrivateKey,
    pub public_key: HPKEPublicKey,
}

impl HPKEKeyPair {
    pub fn new(kem_id: KEM) -> HPKEKeyPair {
        let mut csprng = StdRng::from_entropy();
        let (private_key, public_key) = match kem_id {
            KEM::DHKEM_P256_HKDF_SHA256 => {
                let (private, public) = kem::DhP256HkdfSha256::gen_keypair(&mut csprng);
                (private.to_bytes().as_slice().to_vec(), public.to_bytes().as_slice().to_vec())
            },
            KEM::DHKEM_P384_HKDF_SHA384 => unimplemented!(),
            KEM::DHKEM_P521_HKDF_SHA512 => unimplemented!(),
            KEM::DHKEM_X25519_HKDF_SHA256 => {
                let (private, public) = kem::X25519HkdfSha256::gen_keypair(&mut csprng);
                (private.to_bytes().as_slice().to_vec(), public.to_bytes().as_slice().to_vec())
            }
            KEM::DHKEM_X448_HKDF_SHA512 => unimplemented!(),
            _ => unreachable!(),
        };
        HPKEKeyPair {
            kem_id,
            private_key,
            public_key,
        }
    }
}

/// A private key paired with an ECHConfig, which contains the corresponding public key.
#[derive(Clone, Debug)]
pub struct ECHKey {
    pub private_key: HPKEPrivateKey,
    pub config: ECHConfig,
}

impl ECHKey {
    pub fn new(key_pair: HPKEKeyPair, domain: webpki::DNSNameRef) -> ECHKey {
        ECHKey {
            private_key: key_pair.private_key,
            config: ECHConfig {
                version: ECHVersion::V9,
                contents: ECHConfigContents::new(key_pair.public_key, key_pair.kem_id, domain)
            }
        }
    }
}

impl Codec for ECHKey {
    fn encode(&self, bytes: &mut Vec<u8>) {
        PayloadU16(self.private_key.clone()).encode(bytes);
        self.config.encode(bytes);
    }

    fn read(r: &mut Reader) -> Option<ECHKey> {
        let private_key = PayloadU16::read(r)?;
        let config_payload = PayloadU16::read(r)?;
        let config = ECHConfig::read(&mut Reader::init(&config_payload.into_inner()))?;
        Some(ECHKey {
            private_key: private_key.into_inner(),
            config,
        })
    }
}