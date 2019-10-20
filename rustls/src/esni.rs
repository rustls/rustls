use crate::client::ClientConfig;
use crate::msgs::handshake::{ESNIRecord, KeyShareEntry, ServerNamePayload, ServerName};
use crate::msgs::enums::{HashAlgorithm, SignatureAlgorithm, ServerNameType};
use crate::msgs::enums::{CipherSuite, ProtocolVersion};
use crate::suites::{KeyExchange, TLS13_CIPHERSUITES, choose_ciphersuite_preferring_server};
use crate::msgs::codec::Codec;
use crate::rand;

use std::time::{SystemTime, UNIX_EPOCH};

use ring::digest;
use webpki;
use crate::SupportedCipherSuite;

#[derive(Clone, Debug)]
pub struct ESNIHandshakeData {
    pub peer_share: KeyShareEntry,
    pub cipher_suite: &'static SupportedCipherSuite,
    pub padded_length: u16,
    pub record_digest: digest::Digest,
}

/// Creates a `ClientConfig` with defaults suitable for ESNI extension support.
/// This creates a config that supports TLS 1.3 only.
pub fn create_esniclient_config(record: ESNIRecord) -> Option<ClientConfig> {
    // Check whether the record is still valid
    let now = now()?;
    if now < record.not_before || now > record.not_after {
        return None
    }

    let mut config = ClientConfig::new();
    config.versions = vec![ProtocolVersion::TLSv1_3];
    config.ciphersuites = TLS13_CIPHERSUITES.to_vec();

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

    config.encrypt_sni = Some(ESNIHandshakeData {
        peer_share,
        cipher_suite,
        padded_length: record.padded_length,
        record_digest: digest::digest(cipher_suite.get_hash(), &record.bytes.as_slice()[2..]),
    });

    Some(config)
}

fn compute_esni_extension_data(dns_name: webpki::DNSNameRef, hs_data: &ESNIHandshakeData) {
    let mut nonce = [0u8; 16];
    rand::fill_random(&mut random_id);

    let name = ServerName {
        typ: ServerNameType::HostName,
        payload: ServerNamePayload::HostName(dns_name.into()),
    };

    let key_exchange = match KeyExchange::start_ecdhe(hs_data.peer_share.group) {
        Some(entry) => entry,
        None => return None,
    };
}

fn now() -> Option<u64> {
    let start = SystemTime::now();
    match start.duration_since(UNIX_EPOCH)  {
        Err(_e) => None,
        Ok(since_the_epoch) => Some(since_the_epoch.as_secs() * 1000)
    }
}