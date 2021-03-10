use crate::msgs::enums::*;
use crate::msgs::handshake::*;
use hpke::{kem, Kem};
use hpke::kex::Serializable;
use crate::msgs::codec::{Codec, Reader};

// TODO: delegate to ring?
use rand::{rngs::StdRng, SeedableRng};
use crate::msgs::base::{PayloadU16, PayloadU8, Payload};
use crate::ProtocolVersion;
use webpki::DNSNameRef;

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
    pub fn new(key_pair: HPKEKeyPair, domain: DNSNameRef) -> ECHKey {
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

// ---
/*
Create a ClientHelloInner (just a ClientHelloPayload with some restrictions)
Create an “EncodedClientHelloInner” that can be a no-op for now, since we won’t deduplicate anything in the ClientHelloOuter initially.
Create a ClientHelloOuter for the EncodedClientHelloInner.
The ClientHelloOuterAAD is computed to created “Additional authenticated data” for HPKE by serializing the entire ClientHelloOuter less the last extension (which is ECH)
The encrypted_client_hello extension (ECH) is computed using choices from ECHConfig (done for -09) and the ClientHelloOuterAAD.
*/

// Enforce these in hs.rs:
// It MUST NOT offer to negotiate TLS 1.2 or below
// It MUST NOT offer to resume any session for TLS 1.2 and below.
#[allow(dead_code)]
pub fn encrypt_client_hello_payload(_ech_config: &ECHConfig,
                                    _payload: ClientHelloPayload,
                                    _outer_exts: Vec<ClientExtension>) -> Option<ClientHelloPayload> {
    None
}

#[allow(dead_code)]
fn get_sample_clienthellopayload() -> ClientHelloPayload {
    ClientHelloPayload {
        client_version: ProtocolVersion::TLSv1_2,
        random: Random::from_slice(&[0; 32]),
        session_id: SessionID::empty(),
        cipher_suites: vec![CipherSuite::TLS_NULL_WITH_NULL_NULL],
        compression_methods: vec![Compression::Null],
        extensions: vec![
            ClientExtension::ECPointFormats(ECPointFormatList::supported()),
            ClientExtension::NamedGroups(vec![NamedGroup::X25519]),
            ClientExtension::SignatureAlgorithms(vec![SignatureScheme::ECDSA_NISTP256_SHA256]),
            ClientExtension::make_sni(DNSNameRef::try_from_ascii_str("inner-sni.example.com").unwrap()),
            ClientExtension::SessionTicketRequest,
            ClientExtension::SessionTicketOffer(Payload(vec![])),
            ClientExtension::Protocols(vec![PayloadU8(vec![0])]),
            ClientExtension::SupportedVersions(vec![ProtocolVersion::TLSv1_3]),
            ClientExtension::KeyShare(vec![KeyShareEntry::new(NamedGroup::X25519, &[1, 2, 3])]),
            ClientExtension::PresharedKeyModes(vec![PSKKeyExchangeMode::PSK_DHE_KE]),
            ClientExtension::PresharedKey(PresharedKeyOffer {
                identities: vec![
                    PresharedKeyIdentity::new(vec![3, 4, 5], 123456),
                    PresharedKeyIdentity::new(vec![6, 7, 8], 7891011),
                ],
                binders: vec![
                    PresharedKeyBinder::new(vec![1, 2, 3]),
                    PresharedKeyBinder::new(vec![3, 4, 5]),
                ],
            }),
            ClientExtension::Cookie(PayloadU16(vec![1, 2, 3])),
            ClientExtension::ExtendedMasterSecretRequest,
            ClientExtension::CertificateStatusRequest(CertificateStatusRequest::build_ocsp()),
            ClientExtension::SignedCertificateTimestampRequest,
            ClientExtension::TransportParameters(vec![1, 2, 3]),
            ClientExtension::Unknown(UnknownExtension {
                typ: ExtensionType::Unknown(12345),
                payload: Payload(vec![1, 2, 3]),
            }),
        ],
    }
}
