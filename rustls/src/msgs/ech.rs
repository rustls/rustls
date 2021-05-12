use crate::msgs::enums::ExtensionType;
use crate::msgs::handshake::{HpkeKeyConfig, ClientHelloPayload, ClientExtension, SessionID};
use crate::msgs::codec::*;
use crate::rand;
use crate::Error;
use hpke_rs::prelude::*;
use hpke_rs::{Hpke, Mode};
use webpki::DnsName;
use std::cmp::Ordering;
use crate::msgs::handshake::ClientExtension::EchOuterExtensions;

#[allow(dead_code)]
/// ECH data that's reused across HRR.
pub struct EchHrrContext {
    pub hpke: Hpke,
    pub name: DnsName,
    pub config_id: u8,
    pub inner_random: [u8; 32],
}

impl EchHrrContext {
    #[allow(dead_code)]
    pub(crate) fn new(
        name: DnsName,
        hpke_key_config: &HpkeKeyConfig,
    ) -> Result<EchHrrContext, Error> {
        let hpke = hpke_key_config
            .hpke_symmetric_cipher_suites
            .iter()
            .find_map(|suite| {
                Some(hpke_rs::Hpke::new(
                    Mode::Base,
                    HpkeKemMode::try_from(hpke_key_config.hpke_kem_id.get_u16()).ok()?,
                    HpkeKdfMode::try_from(suite.hpke_kdf_id.get_u16()).ok()?,
                    HpkeAeadMode::try_from(suite.hpke_aead_id.get_u16()).ok()?,
                ))
            })
            .ok_or(Error::NoHpkeConfig)?;

        let mut inner_random = [0u8; 32];
        rand::fill_random(&mut inner_random)?;

        Ok(EchHrrContext {
            hpke,
            name,
            config_id: hpke_key_config.config_id,
            inner_random,
        })
    }
}

#[allow(dead_code)]
fn encode_inner_hello(mut hello: ClientHelloPayload, outer_exts: &Vec<ExtensionType>) -> (ClientHelloPayload, Vec<u8>) {

    hello.extensions.sort_by(|a, b| {
        if outer_exts.contains(&a.get_type()) {
            Ordering::Greater
        } else if outer_exts.contains(&b.get_type())  {
            Ordering::Less
        } else {
            Ordering::Equal
        }
    });

    let range = hello.extensions.iter().rev().take_while(|el| outer_exts.contains(&el.get_type())).collect::<Vec<&ClientExtension>>().len();
    let outer: Vec<ClientExtension> = hello.extensions.drain(hello.extensions.len() - range..).collect();
    let outer_extensions = EchOuterExtensions(outer.iter().map(|ext| {
        ext.get_type()
    }).collect());

    let legacy_session_id = hello.session_id;
    hello.session_id = SessionID::empty();
    hello.extensions.push(outer_extensions);

    let mut encoded_hello = Vec::new();
    hello.encode(&mut encoded_hello);

    hello.extensions.pop();
    hello.session_id = legacy_session_id;

    (hello, encoded_hello)
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::msgs::base::{PayloadU16, PayloadU8, Payload};
    use crate::msgs::codec::{Codec, Reader};
    use crate::msgs::enums::*;
    use crate::msgs::handshake::*;
    use base64;
    use crate::ProtocolVersion;
    use crate::msgs::enums::ExtensionType::{KeyShare, EllipticCurves};
    use crate::internal::msgs::enums::ExtensionType::ECPointFormats;
    use webpki::DnsNameRef;

    #[test]
    fn test_echconfig_serialization() {
        // An ECHConfigList record from Cloudflare for "crypto.cloudflare.com", draft-10
        let base64_echconfigs = "AEj+CgBEuwAgACCYKvleXJQ16RUURAsG1qTRN70ob5ewCDH6NuzE97K8MAAEAAEAAQAAABNjbG91ZGZsYXJlLWVzbmkuY29tAAA=";
        let bytes = base64::decode(&base64_echconfigs).unwrap();
        let configs = ECHConfigList::read(&mut Reader::init(&bytes)).unwrap();
        assert_eq!(configs.len(), 1);
        let config: &ECHConfig = &configs[0];
        assert_eq!(config.version, ECHVersion::V10);
        let name = String::from_utf8(
            config
                .contents
                .public_name
                .clone()
                .into_inner(),
        )
            .unwrap();
        assert_eq!("cloudflare-esni.com", name.as_str());
        assert_eq!(
            config
                .contents
                .hpke_key_config
                .hpke_kem_id,
            KEM::DHKEM_X25519_HKDF_SHA256
        );
        assert_eq!(
            config
                .contents
                .hpke_key_config
                .hpke_symmetric_cipher_suites
                .len(),
            1
        );
        assert_eq!(
            config
                .contents
                .hpke_key_config
                .hpke_symmetric_cipher_suites[0]
                .hpke_kdf_id,
            KDF::HKDF_SHA256
        );
        assert_eq!(
            config
                .contents
                .hpke_key_config
                .hpke_symmetric_cipher_suites[0]
                .hpke_aead_id,
            AEAD::AES_128_GCM
        );
        let mut output = Vec::new();
        configs.encode(&mut output);
        assert_eq!(base64_echconfigs, base64::encode(&output));
    }

    fn get_sample_clienthellopayload() -> ClientHelloPayload {
        let mut random = [0; 32];
        rand::fill_random(&mut random).unwrap();
        ClientHelloPayload {
            client_version: ProtocolVersion::TLSv1_2,
            random: Random::from(random),
            session_id: SessionID::random().unwrap(),
            cipher_suites: vec![CipherSuite::TLS_NULL_WITH_NULL_NULL],
            compression_methods: vec![Compression::Null],
            extensions: vec![
                ClientExtension::ECPointFormats(ECPointFormatList::supported()),
                ClientExtension::NamedGroups(vec![NamedGroup::X25519]),
                ClientExtension::SignatureAlgorithms(vec![SignatureScheme::ECDSA_NISTP256_SHA256]),
                ClientExtension::make_sni(DnsNameRef::try_from_ascii_str("inner-sni.example.com").unwrap()),
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

    #[test]
    fn test_encode_client_hello_inner() {
        let original_hello = get_sample_clienthellopayload();
        let original_ext_length = original_hello.extensions.len();
        let original_session_id = original_hello.session_id;
        let outer_exts = vec![KeyShare, ECPointFormats, EllipticCurves];
        let (hello, encoded_inner) = encode_inner_hello(original_hello, &outer_exts);
        assert_eq!(hello.session_id, original_session_id);

        let mut reader = Reader::init(&encoded_inner);
        let decoded = ClientHelloPayload::read(&mut reader).unwrap();
        assert_eq!(decoded.session_id, SessionID::empty());
        assert_ne!(decoded.session_id, original_session_id);

        // The compressed extensions, plus one for the outer_extensions field.
        let expected_length = original_ext_length - outer_exts.len() + 1;
        assert_eq!(decoded.extensions.len(), expected_length);
        let decoded_outer = decoded.find_extension(ExtensionType::EchOuterExtensions).unwrap();
        let outers = match decoded_outer {
            EchOuterExtensions(outer_exts) => Some(outer_exts),
            _ => None,
        }.unwrap();
        assert_eq!(outers.len(), 3);
        for ext_type in outers.iter() {
            assert!(outer_exts.contains(ext_type));
        }
    }
}