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
use ring::hkdf::{KeyType, Prk};
use crate::cipher::{Iv, IvLen};
use ring::aead::{UnboundKey, Algorithm};

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

    let digest = digest::digest(cipher_suite.get_hash(), record_bytes);
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

    let mut padded_bytes = Vec::new();
    psnl.encode(&mut padded_bytes);
    println!("padded length: {}", padded_bytes.len());


    let client_esni_inner = ClientESNIInner {
        nonce,
        real_sni: psnl,
    };
    let mut sni_bytes = Vec::new();
    client_esni_inner.encode(&mut sni_bytes);
    println!("sni_bytes: {:02x?}, {}", sni_bytes, sni_bytes.len());

    println!("Client key share: {:?}", hs_data.peer_share);
    let mut peer_bytes = Vec::new();
    hs_data.peer_share.clone().encode(&mut peer_bytes);
    println!("peer_bytes: {:02x?}, {}", peer_bytes, peer_bytes.len());

    let key_exchange = match KeyExchange::start_ecdhe(hs_data.peer_share.group) {
        Some(ke) => ke,
        None => return None,
    };

    println!("group: {:?}", key_exchange.group);


    let keyex_Bytes =  key_exchange.pubkey.as_ref();
    println!("     key_exchange: {:02x?}, {}", keyex_Bytes, keyex_Bytes.len());
    let exchange_result = key_exchange.complete(&hs_data.peer_share.payload.0)?;
    let mut result_bytes = exchange_result.pubkey.as_ref();
    println!("   Z result_bytes: {:02x?}, {}", result_bytes, result_bytes.len());

    let premaster_bytes = exchange_result.premaster_secret.as_slice();
    println!("Z premaster_bytes: {:02x?}, {}", premaster_bytes, premaster_bytes.len());


    let mut random = [0u8; 32];
    rand::fill_random(&mut random);
    let contents = ESNIContents {
        record_digest: PayloadU16::new(hs_data.record_digest.clone()),
        esni_key_share: KeyShareEntry {
            group: hs_data.peer_share.group,
            payload: PayloadU16(exchange_result.pubkey.clone().as_ref().to_vec())
        },
        client_hello_random: Random::from_slice(&random),
    };

    let mut contents_bytes = Vec::new();
    contents.encode(&mut contents_bytes);
    println!("ESNIContents encoded, {:02x?}, {}", contents_bytes, contents_bytes.len());
    let digest = digest::digest(hs_data.cipher_suite.get_hash(), &contents_bytes);
    let digest_bytes = digest.as_ref();
    println!("   ESNIContents hash, {:02x?}, {}", digest_bytes, digest_bytes.len());


    let zx = zx(hs_data.cipher_suite.hkdf_algorithm, &exchange_result.premaster_secret);

    let key = hkdf_expand(&zx, hs_data.cipher_suite.get_aead_alg(), b"esni key", digest.as_ref());
    println!("Key {:?}", key);
    let iv: Iv = hkdf_expand(&zx, IvLen, b"esni iv", digest.as_ref());
    println!("Iv {:02x?}", iv.value());


    println!("key_share_bytes: {:02x?}, {}", key_share_bytes, key_share_bytes.len());
    let aad = ring::aead::Aad::from(key_share_bytes.to_vec());
    let aad_bytes = aad.as_ref();
    println!("AAD: {:02x?}, {}", aad_bytes, aad_bytes.len());

    match encrypt(key, iv, aad, &mut sni_bytes) {
        Some(bytes) => {
            println!("cipher: {:02x?}, {}", bytes, bytes.len());
            Some (ClientEncryptedSNI {
                suite: hs_data.cipher_suite.suite,
                key_share_entry: KeyShareEntry::new(hs_data.peer_share.group, exchange_result.pubkey.as_ref()),
                record_digest: PayloadU16(hs_data.record_digest.clone()),
                encrypted_sni: PayloadU16(bytes),
            })
        },
        _ => None
    }
}

fn zx(algorithm: ring::hkdf::Algorithm, secret: &Vec<u8>) -> Prk {
    let zeroes = [0u8; digest::MAX_OUTPUT_LEN];
    let zeroes = &zeroes[..algorithm.len()];
    let salt = hkdf::Salt::new(algorithm, &zeroes);
    salt.extract(secret)
}

fn encrypt(unbound: UnboundKey, iv: Iv, aad: ring::aead::Aad<Vec<u8>>, sni_bytes: &mut Vec<u8>) -> Option<Vec<u8>> {
    let lsk = ring::aead::LessSafeKey::new(unbound);
    match lsk.seal_in_place_append_tag(ring::aead::Nonce::assume_unique_for_key(*iv.value()),
                                       aad,
                                       sni_bytes) {
        Ok(_) => Some(sni_bytes.clone()),
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

#[cfg(test)]
mod tests {
    use crate::SupportedCipherSuite;

    #[test]
    fn test_zx() {
        let z_bytes = hex!("
            97 1a 40 1c cb 08 be 7f 7b de f3 10 c7 9c 1d 36
            45 bd 27 f6 34 ee 73 e6 5d 1b a0 ff 60 f8 3e 5e");

        let zx_bytes = hex!("
            51 98 ef 6a 9d bb af f8 44 42 ac 57 28 69 e6 63
            60 ce 27 2d c4 30 82 5f 4e 2c eb a4 4e 42 05 0a
        ");

        let zx = super::zx(crate::suites::TLS13_AES_128_GCM_SHA256.hkdf_algorithm, &z_bytes.to_vec());
    }

    #[test]
    fn test_encrypt() {
        let key_bytes = hex!("9b 9f f2 2c dd 39 4c f6 20 ac f8 d6 f6 90 99 ab");

        let iv_bytes = hex!("d0 c2 2c 42 3c 03 a7 1d 3d 36 36 51");

        let aad_bytes = hex!("
    00 69 00 1d 00 20 e7 41
    94 4b 78 8d 6f cd 6b 5b 64 f6 69 35 83 d1 df c7
    e8 21 55 c6 f7 8d a5 c3 25 b9 7a 69 58 7d 00 17
    00 41 04 d8 75 ac 7c 46 38 c6 eb 35 a9 90 60 6b
    1b be b1 70 dd 18 0c 80 82 8d 83 95 b1 aa a5 2e
    24 2e fb ed 9f 2a bd 7f 86 f0 8c 8b 6b ca db a6
    28 69 88 1d fb 76 5f 34 d9 da 0b 07 02 64 80 d2
    d3 84 15 ");

        let mut plain_text = hex!("
    ad 1b f4 b3 d3 14 59 48 59 9e be c8 56 42 4f 66
    00 15 00 00 12 63 61 6e 62 65 2e 65 73 6e 69 2e
    64 65 66 6f 2e 69 65 00 00 00 00 00 00 00 00 00
    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    00 00 00 00 ");

        let expected = hex!("
    6f f6 5d 1e bd 9c 35 2d 2c 1c ca 92 5d 3e 1a 65
    f6 30 fe 97 3b a0 24 9d 92 b8 cb 67 f0 1d 17 a4
    bc 11 9b ac 39 c4 48 f7 bb 86 04 b5 58 ad 76 15
    10 c3 21 d0 3b 86 ac c9 d6 7e 9f 89 6e b0 73 cb
    69 97 f4 1b f5 17 e9 81 29 86 6f 3e df 49 99 3c
    59 00 24 6c 2d d6 3e 7b d2 b7 bd 3a c0 90 8f b6
    dc 2b 11 08 15 00 41 ca fb 79 ef 57 5b 17 18 00
    bf c2 0c 1b 2b cf 1e 9b f0 0f 9d 67 32 37 e1 06
    22 f8 cb a8 a3 40 26 6e 50 85 32 29 d7 20 41 a5
    0f 47 87 d0 af 01 ba 83 62 ad a0 b6 ac 8e d5 dd
    24 42 3d f8 a8 f9 9e 16 40 cf 85 b9 16 39 f8 94
    4b bd cb a5 59 a8 a9 65 7a 83 95 b2 38 c7 3b d5
    d4 9b 6f f0 e3 18 d0 cb 65 65 c9 0c 8a 07 a1 ce
    5f 39 ed 6a 1b 6f e7 59 11 7d b3 81 e4 4b 51 d4
    db 28 f3 95 eb 16 62 de de 29 c7 dc 79 54 67 24
    d7 4d d1 3f 34 ca 64 6e 6c 12 9a e4 0c 1c ea 33
    c3 81 15 48 04 14 a4 ed ab 44 90 e9 0d c2 56 8a
    df 4e 92 eb 3b 93 f5 5c 59 15 0e 7d 85 66 2d b4
    62 ee 41 8a");

        let key = ring::aead::UnboundKey::new(crate::suites::TLS13_AES_128_GCM_SHA256.get_aead_alg(), &key_bytes).unwrap();
        let iv = crate::cipher::Iv::new(iv_bytes);
        let aad = ring::aead::Aad::from(aad_bytes.to_vec());
        let mut sni_bytes = Vec::from(plain_text.to_vec());
        let encrypted = super::encrypt(key, iv, aad, &mut sni_bytes).unwrap();
        println!("{}, {:02x?}", encrypted.len(), encrypted);
        assert_eq!(expected.len(), encrypted.len());
        assert!(crate::msgs::handshake::slice_eq(&expected, encrypted.as_slice()));
    }
}