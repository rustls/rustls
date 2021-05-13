use crate::msgs::codec::*;
use crate::msgs::enums::ExtensionType;
use crate::msgs::handshake::ClientExtension::EchOuterExtensions;
use crate::msgs::handshake::{
    ClientExtension, ClientHelloPayload, HpkeKeyConfig, Random, SessionID,
};
use crate::rand;
use crate::Error;
use hpke_rs::prelude::*;
use hpke_rs::{Hpke, Mode};
use std::cmp::Ordering;
use webpki::DnsName;

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
fn encode_inner_hello(
    mut hello: ClientHelloPayload,
    context: &EchHrrContext,
    outer_exts: &Vec<ExtensionType>,
) -> (ClientHelloPayload, Vec<u8>) {
    // nightly's drain_filter would be nice here.
    let mut indices = Vec::with_capacity(outer_exts.len());
    for (i, ext) in hello.extensions.iter().enumerate() {
        if outer_exts.contains(&ext.get_type()) {
            indices.push(i);
        }
    }
    let mut outers = Vec::with_capacity(indices.len());
    for index in indices.iter().rev() {
        outers.push(hello.extensions.swap_remove(*index));
    }
    let outer_extensions = EchOuterExtensions(
        outers
            .iter()
            .map(|ext| ext.get_type())
            .collect(),
    );
    hello
        .extensions
        .push(ClientExtension::ClientHelloInnerIndication);
    hello.extensions.push(outer_extensions);

    let original_session_id = hello.session_id;
    let original_random = hello.random;

    hello.session_id = SessionID::empty();
    hello.random = Random::from(context.inner_random);
    let mut encoded_hello = Vec::new();
    hello.encode(&mut encoded_hello);

    hello.extensions.pop();
    hello.extensions.pop();

    hello.session_id = original_session_id;
    hello.random = original_random;
    let index = hello
        .extensions
        .iter()
        .position(|ext| ext.get_type() == ExtensionType::PreSharedKey);
    if let Some(i) = index {
        hello.extensions.remove(i);
    }
    hello.extensions.append(&mut outers);

    (hello, encoded_hello)
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::internal::msgs::enums::ExtensionType::ECPointFormats;
    use crate::msgs::base::{Payload, PayloadU8, PayloadU16};
    use crate::msgs::codec::{Codec, Reader};
    use crate::msgs::enums::ExtensionType::{Cookie, EllipticCurves, KeyShare};
    use crate::msgs::enums::*;
    use crate::msgs::handshake::*;
    use crate::ProtocolVersion;
    use base64;
    use webpki::DnsNameRef;

    const BASE64_ECHCONFIGS: &str = "AEj+CgBEuwAgACCYKvleXJQ16RUURAsG1qTRN70ob5ewCDH6NuzE97K8MAAEAAEAAQAAABNjbG91ZGZsYXJlLWVzbmkuY29tAAA=";

    fn get_ech_config() -> ECHConfigList {
        // An ECHConfigList record from Cloudflare for "crypto.cloudflare.com", draft-10
        let bytes = base64::decode(&BASE64_ECHCONFIGS).unwrap();
        let configs = ECHConfigList::read(&mut Reader::init(&bytes)).unwrap();
        assert_eq!(configs.len(), 1);
        configs
    }

    #[test]
    fn test_echconfig_serialization() {
        let configs = get_ech_config();
        let config = &configs[0];
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
        assert_eq!(BASE64_ECHCONFIGS, base64::encode(&output));
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
                ClientExtension::make_sni(
                    DnsNameRef::try_from_ascii_str("inner-sni.example.com").unwrap(),
                ),
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
        let original_random = original_hello.random.clone();
        let outer_exts = vec![Cookie, KeyShare, ECPointFormats, EllipticCurves];
        let config = &get_ech_config()[0];
        let dns_name = DnsNameRef::try_from_ascii(b"test.example.com").unwrap();
        let ech_context =
            EchHrrContext::new(dns_name.to_owned(), &config.contents.hpke_key_config).unwrap();
        let (hello, encoded_inner) = encode_inner_hello(original_hello, &ech_context, &outer_exts);
        assert_eq!(hello.session_id, original_session_id);
        assert_eq!(hello.random, original_random);
        // Return hello should not have a PSK
        assert!(
            hello
                .find_extension(ExtensionType::PreSharedKey)
                .is_none()
        );

        let mut reader = Reader::init(&encoded_inner);
        let decoded = ClientHelloPayload::read(&mut reader).unwrap();
        assert_eq!(decoded.session_id, SessionID::empty());
        assert_ne!(decoded.session_id, original_session_id);
        assert_ne!(decoded.random, original_random);

        // The compressed extensions, plus two for the outer_extensions and ech_is_inner.
        let expected_length = original_ext_length - outer_exts.len() + 2;
        assert_eq!(decoded.extensions.len(), expected_length);
        let decoded_outer = decoded
            .find_extension(ExtensionType::EchOuterExtensions)
            .unwrap();
        let outers = match decoded_outer {
            EchOuterExtensions(outer_exts) => Some(outer_exts),
            _ => None,
        }
        .unwrap();
        assert_eq!(outers.len(), outer_exts.len());
        for ext_type in outers.iter() {
            assert!(outer_exts.contains(ext_type));
        }

        // All of the old extensions except for PSK
        let old_len = original_ext_length - 1;
        assert_eq!(hello.extensions.len(), old_len);
        assert!(
            decoded
                .find_extension(ExtensionType::PreSharedKey)
                .is_some()
        );
        assert!(
            decoded
                .find_extension(ExtensionType::EchIsInner)
                .is_some()
        );
    }
}
