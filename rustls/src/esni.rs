use crate::client::ClientConfig;
use crate::msgs::handshake::{ESNIRecord, KeyShareEntry, ServerNamePayload, ServerName, ClientEncryptedSNI, ESNIContents, Random, PaddedServerNameList, ClientESNIInner};
use crate::msgs::enums::ServerNameType;
use crate::msgs::enums::ProtocolVersion;
use crate::suites::{KeyExchange, TLS13_CIPHERSUITES, choose_ciphersuite_preferring_server};
use crate::msgs::codec::{Codec, Reader};
use crate::rand;

use std::time::{SystemTime, UNIX_EPOCH};

use ring::{digest, hkdf};
use webpki;
use crate::SupportedCipherSuite;
use crate::key_schedule::hkdf_expand;
use crate::msgs::base::PayloadU16;
use ring::hkdf::KeyType;
use crate::cipher::{Iv, IvLen};

/// Data calculated for a client session from a DNS ESNI record.
#[derive(Clone, Debug)]
pub struct ESNIHandshakeData {
    /// The selected Key Share from the DNS record
    pub peer_share: KeyShareEntry,

    /// The selected CipherSuite from the DNS record
    pub cipher_suite: &'static SupportedCipherSuite,

    /// The length to pad the ESNI to
    pub padded_length: u16,

    /// A digest of the DNS record
    pub record_digest: Vec<u8>,
}

/// Create a TLS 1.3 Config for ESNI
pub fn create_esni_config() -> ClientConfig {
    let mut config = ClientConfig::new();
    config.versions = vec![ProtocolVersion::TLSv1_3];
    config.ciphersuites = TLS13_CIPHERSUITES.to_vec();
    config.encrypt_sni = true;
    config
}

/// Creates a `ClientConfig` with defaults suitable for ESNI extension support.
/// This creates a config that supports TLS 1.3 only.
pub fn create_esni_handshake(record_bytes: &Vec<u8>) -> Option<ESNIHandshakeData> {
    let record = ESNIRecord::read(&mut Reader::init(&record_bytes))?;

    println!("record {:?}", record);

    // Check whether the record is still valid
    let now = now()?;

    if now < record.not_before || now > record.not_after {
        return None
    }

    let peer_share = match KeyExchange::supported_groups()
        .iter()
        .flat_map(|group| {
          record.keys.iter().find(|key| { key.group == *group })
        }).nth(0)
        .cloned() {
        Some(entry) => entry,
        None => return None,
    };

    let cipher_suite= match
        choose_ciphersuite_preferring_server(record.cipher_suites.as_slice(),
                                             &TLS13_CIPHERSUITES) {
        Some(entry) => entry,
        None => return None,
    };

    let digest = digest::digest(cipher_suite.get_hash(), &record.bytes.as_slice()[2..]);
    let bytes: Vec<u8> = Vec::from(digest.as_ref());

    Some(ESNIHandshakeData {
        peer_share,
        cipher_suite,
        padded_length: record.padded_length,
        record_digest: bytes,
    })
}

/// Compute the encrypted SNI
// TODO: this is big and messy, fix it up
pub fn compute_esni(dns_name: webpki::DNSNameRef,
                    hs_data: &ESNIHandshakeData,
                    key_share_bytes: Vec<u8>) -> Option<ClientEncryptedSNI> {
    let mut nonce = [0u8; 16];
    rand::fill_random(&mut nonce);
    let name = ServerName {
        typ: ServerNameType::HostName,
        payload: ServerNamePayload::HostName(dns_name.into()),
    };
    let psnl = PaddedServerNameList::new(name, hs_data.padded_length);
    let client_esni_inner = ClientESNIInner {
        nonce,
        real_sni: psnl,
    };
    let mut sni_bytes = Vec::new();
    client_esni_inner.encode(&mut sni_bytes);


    let key_exchange = match KeyExchange::start_ecdhe(hs_data.peer_share.group) {
        Some(ke) => ke,
        None => return None,
    };
    let exchange_result = key_exchange.complete(&hs_data.peer_share.payload.0)?;

    let mut random = [0u8; 32];
    rand::fill_random(&mut random);
    let contents = ESNIContents {
        record_digest: PayloadU16::new(hs_data.record_digest.clone()),
        esni_key_share: KeyShareEntry::new(hs_data.peer_share.group, exchange_result.pubkey.as_ref()),
        client_hello_random: Random::from_slice(&random),
    };

    let mut contents_bytes = Vec::new();
    contents.encode(&mut contents_bytes);
    let digest = digest::digest(hs_data.cipher_suite.get_hash(), &contents_bytes);

    let algorithm = hs_data.cipher_suite.hkdf_algorithm;
    let zeroes = [0u8; digest::MAX_OUTPUT_LEN];
    let zeroes = &zeroes[..algorithm.len()];
    let salt = hkdf::Salt::new(algorithm, &zeroes);
    let zx = salt.extract(&exchange_result.premaster_secret);
    let key = hkdf_expand(&zx, hs_data.cipher_suite.get_aead_alg(), b"esni key", digest.as_ref());
    let iv: Iv = hkdf_expand(&zx, IvLen, b"esni iv", digest.as_ref());
    let lsk = ring::aead::LessSafeKey::new(key);
    match lsk.seal_in_place_append_tag(ring::aead::Nonce::assume_unique_for_key(*iv.value()),
                                 ring::aead::Aad::from(key_share_bytes),
                                 &mut sni_bytes) {
        Ok(_) => {
            println!("What's the suite? {:?}", hs_data.cipher_suite.suite);
            println!("What's record digest? {:?}", hs_data.record_digest);
            println!("what the group? {:?}", hs_data.peer_share.group);
            Some (ClientEncryptedSNI {
                suite: hs_data.cipher_suite.suite,
                key_share_entry: KeyShareEntry::new(hs_data.peer_share.group, exchange_result.pubkey.as_ref()),
                record_digest: PayloadU16(hs_data.record_digest.clone()),
                encrypted_sni: PayloadU16(Vec::from(sni_bytes)),
            })
        },
        _ => None
    }
}

fn now() -> Option<u64> {
    let start = SystemTime::now();
    match start.duration_since(UNIX_EPOCH)  {
        Err(_e) => None,
        Ok(since_the_epoch) => Some(since_the_epoch.as_secs())
    }
}