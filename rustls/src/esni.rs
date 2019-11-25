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
use crate::msgs::base::PayloadU16;
use ring::hkdf::Prk;
use crate::cipher::{Iv, IvLen};
use ring::aead::UnboundKey;
use crate::session::SessionRandoms;
use crate::key_schedule::hkdf_expand;

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
    // Check whether the record is still valid
    let now = now()?;

    if now < record.not_before || now > record.not_after {
        return None
    }

    record_to_handshake_data(&record, record_bytes)
}

fn record_to_handshake_data(record: &ESNIRecord, record_bytes: &Vec<u8>) -> Option<ESNIHandshakeData> {
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

    Some(ESNIHandshakeData {
        peer_share,
        cipher_suite,
        padded_length: record.padded_length,
        record_digest: record_digest(cipher_suite.get_hash(), record_bytes),
    })
}

fn now() -> Option<u64> {
    let start = SystemTime::now();
    match start.duration_since(UNIX_EPOCH)  {
        Err(_e) => None,
        Ok(since_the_epoch) => Some(since_the_epoch.as_secs())
    }
}

fn record_digest(algorithm: &'static ring::digest::Algorithm, bytes: &[u8]) -> Vec<u8> {
    digest::digest(algorithm, bytes).as_ref().to_vec()
}

/// Compute the encrypted SNI
pub fn compute_esni(dns_name: webpki::DNSNameRef,
                    hs_data: &ESNIHandshakeData,
                    key_share_bytes: Vec<u8>,
                    randoms: &SessionRandoms) -> Option<ClientEncryptedSNI> {
    let mut nonce = [0u8; 16];
    rand::fill_random(&mut nonce);
    let mut sni_bytes = compute_client_esni_inner(dns_name, hs_data.padded_length, nonce);
    let mut peer_bytes = Vec::new();
    hs_data.peer_share.clone().encode(&mut peer_bytes);

    let key_exchange = match KeyExchange::start_ecdhe(hs_data.peer_share.group) {
        Some(ke) => ke,
        None => return None,
    };
    let exchange_result = key_exchange.complete(&hs_data.peer_share.payload.0)?;
    let contents_bytes = compute_esni_content(&hs_data, &exchange_result.pubkey.clone().as_ref().to_vec(), randoms.client);
    let hash = esni_hash(&contents_bytes, hs_data.cipher_suite.get_hash());

    let zx = zx(hs_data.cipher_suite.hkdf_algorithm, &exchange_result.premaster_secret);
    let key = hkdf_expand(&zx, hs_data.cipher_suite.get_aead_alg(), b"esni key", &hash);
    let iv: Iv = hkdf_expand(&zx, IvLen, b"esni iv", &hash);
    let aad = ring::aead::Aad::from(key_share_bytes.to_vec());

    match encrypt(key, iv, aad, &mut sni_bytes) {
        Some(bytes) => {
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

fn compute_esni_content(hs_data: &ESNIHandshakeData, pubkey: &Vec<u8>, random: [u8; 32]) -> Vec<u8> {
    let contents = ESNIContents {
        record_digest: PayloadU16::new(hs_data.record_digest.clone()),
        esni_key_share: KeyShareEntry {
            group: hs_data.peer_share.group,
            payload: PayloadU16(pubkey.to_vec())
        },
        client_hello_random: Random::from_slice(&random),
    };

    let mut contents_bytes = Vec::new();
    contents.encode(&mut contents_bytes);
    contents_bytes
}

fn compute_client_esni_inner(dns_name: webpki::DNSNameRef, length: u16, nonce: [u8; 16]) -> Vec<u8> {
    let name = ServerName {
        typ: ServerNameType::HostName,
        payload: ServerNamePayload::HostName(dns_name.into()),
    };
    let psnl = PaddedServerNameList::new(vec![name], length);

    let mut padded_bytes = Vec::new();
    psnl.encode(&mut padded_bytes);

    let client_esni_inner = ClientESNIInner {
        nonce,
        real_sni: psnl,
    };
    let mut sni_bytes = Vec::new();
    client_esni_inner.encode(&mut sni_bytes);
    sni_bytes
}

fn esni_hash(encoded_esni_contents: &Vec<u8>, algorithm: &'static ring::digest::Algorithm) -> Vec<u8> {
    let digest = digest::digest(algorithm, &encoded_esni_contents);
    digest.as_ref().to_vec()
}

fn zx(algorithm: ring::hkdf::Algorithm, secret: &Vec<u8>) -> Prk {
    let salt = hkdf::Salt::new(algorithm, &[]);
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

#[cfg(test)]
mod tests {
    use crate::key_schedule::hkdf_expand;
    use crate::cipher::{Iv, IvLen};
    use crate::msgs::handshake::ESNIRecord;
    use crate::msgs::codec::{Codec, Reader};
    use webpki::DNSNameRef;

    #[test]
    fn test_compute_esni_content() {
        let esni_keys = hex!("
            ff 01 a0 1f 3e 02 00 24 00 1d 00 20 f6 27 6f e9
            c5 63 14 c3 d7 0c 12 ce ab ea 55 97 28 9e f3 75
            ee 5a ae 04 41 af 5b ff d4 fa 78 5f 00 02 13 01
            01 04 00 00 00 00 5d da 02 98 00 00 00 00 5d da
            17 b0 00 00
        ");

        let random = hex!("
            8a 96 02 a9 3c 80 de 46 01 22 c8 0a 65 48 fb c2
            b7 f6 be 87 07 8d 2d d8 e8 68 25 aa c3 44 1d 7f
        ");

        let pubkey = hex!("
            b3 cf b7 0e eb e5 d4 40 c7 00 af 31
            ba 1e 32 a4 8a ce 7d 6d 24 ce ed 33 4b 82 b4 c9
            4e 90 78 17
        ");

        let expected = hex!("
            00 20 20 4f 08 28 be 7f 73 0e 92 bb 2b 1d 0e 3c
            35 05 86 1d 83 5a a8 7b ad fa 83 3b 17 9a f9 70
            42 c9 00 1d 00 20 b3 cf b7 0e eb e5 d4 40 c7 00
            af 31 ba 1e 32 a4 8a ce 7d 6d 24 ce ed 33 4b 82
            b4 c9 4e 90 78 17 8a 96 02 a9 3c 80 de 46 01 22
            c8 0a 65 48 fb c2 b7 f6 be 87 07 8d 2d d8 e8 68
            25 aa c3 44 1d 7f
        ");

        let record = ESNIRecord::read(&mut Reader::init(&esni_keys)).unwrap();
        let hs_data = super::record_to_handshake_data(&record, &esni_keys.to_vec()).unwrap();
        let esni_contents = super::compute_esni_content(&hs_data, &pubkey.to_vec(), random);
        assert!(crate::msgs::handshake::slice_eq(&expected, &esni_contents));
    }

    #[test]
    fn test_record_digest() {
        let esni_keys = hex!("
            ff 01 f3 92 e6 e7 00 24 00 1d 00 20 10 9f e6 de
            ac e8 f6 2f 94 61 9c 1d 61 c9 a2 b9 2f 45 92 3d
            aa 93 87 e4 e5 51 39 e7 da 26 2b 65 00 02 13 01
            01 04 00 00 00 00 5d d9 f4 88 00 00 00 00 5d da
            09 a0 00 00
        ");

        let expected = hex!("
            3b d7 25 90 a7 58 68 16 46 c5 22 93 2a 1e b0 8d
            0c e3 8c 2c 67 21 8e bf ab 88 90 04 49 cc 23 92
        ");

        let result = super::record_digest(&ring::digest::SHA256, &esni_keys);
        assert!(crate::msgs::handshake::slice_eq(&expected, &result));
    }

    #[test]
    fn test_compute_client_esni_inner() {
        let nonce = hex!("c0 2b f3 39 f8 95 58 ac c4 7c d1 c6 b1 ff a7 28");

        let dns_name = DNSNameRef::try_from_ascii(b"canbe.esni.defo.ie").unwrap();

        let expected = hex!("
            c0 2b f3 39 f8 95 58 ac c4 7c d1 c6 b1 ff a7 28
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
            00 00 00 00
        ");

        let result = super::compute_client_esni_inner(dns_name, 260u16, nonce);
        assert_eq!(expected.len(), result.len());
        assert!(crate::msgs::handshake::slice_eq(&expected, &result));
    }

    #[test]
    fn test_hash() {
        let esni_bytes = hex!("
            00 20 3e 06 06 98 4c 3b a9 70 3a fb a7 a1 2d 75
            29 5b 05 81 7d 75 8f 40 9b 51 00 c8 37 8e 9d 08
            7e f1 00 1d 00 20 72 d8 3a 31 da 1c cd c7 e5 89
            c1 c6 24 bd 7a 14 2d 90 de 7f 01 82 73 9d 25 14
            c2 66 e1 97 23 5b 64 c0 c4 7c 5b c8 14 a0 a4 2b
            0c 2f f4 23 51 00 10 f4 1d f4 c1 f4 3c 3e 89 c8
            fe 87 25 d1 9f 00
        ");

        let expected = hex!("
            21 5b ba fe a8 9e da 35 7b 7b 55 e4 6d 01 ac c8
            94 94 b2 6e e6 55 08 0e 47 21 6a b2 3b 7d 25 f7
        ");

        let result = super::esni_hash(&esni_bytes.to_vec(), &ring::digest::SHA256);
        assert!(crate::msgs::handshake::slice_eq(&expected, &result));
    }

    #[test]
    fn test_zx() {
        let z_bytes = hex!("
            de cf 6a 8c 23 49 e1 8c db d8 48 49 7c 10 16 9a
            77 66 fb 3f f4 8b 54 f7 bd 1f 15 14 74 e1 88 1c");

        let hash = hex!("
            a5 33 9b 1b a6 ae d2 7f 43 b9 91 5e 5e bc 8e 5a
            af d9 fb 1d e2 b4 df 36 13 70 97 14 27 a1 61 25
        ");

        let expected_iv = hex!("
            07 d7 77 4c 69 be bd ad 1b 75 49 c7
        ");

        let aad_bytes = hex!("
            00 69 00 1d 00 20 70 cb
            7e ce 36 ab c1 b6 e1 92 6a 9a f2 08 d9 91 70 f1
            98 7a aa 0f e3 9b f0 b3 c5 4d 79 00 a8 07 00 17
            00 41 04 03 1d 6c 6c e6 f3 28 1f 6f f2 78 d5 5c
            0f 5e f7 be 52 71 9f 7e c0 0e 6e 26 db 85 7b f9
            e0 73 91 e6 b5 3e 06 7b ef c8 f8 b5 f0 46 16 c2
            9f 0d 52 c3 6a 9e 41 2f 68 ce 7e ee d0 27 99 e5
            28 aa 9e
        ");

        let plain_text = hex!("
            4f b0 25 11 6b f7 4d f8 ce f3 0f 59 ce d9 d6 df
            00 17 00 00 14 63 64 6e 6a 73 2e 63 6c 6f 75 64
            66 6c 61 72 65 2e 63 6f 6d 00 00 00 00 00 00 00
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
            00 00 00 00
        ");

        let expected = hex!("
            28 0a 3d 56 cd 30 9d 68 ac 98 1b 41 bb fb 85 26
            48 ef 1a 83 c8 aa bd 12 15 80 44 10 50 2f c0 3d
            68 15 99 e0 47 6a 80 c2 e9 a0 df 86 16 7e a8 a4
            37 8c 27 62 89 7e f8 60 4f 04 cf b5 ea 60 ed 99
            51 59 70 a1 a5 ac b9 32 7d 35 86 e9 e2 01 d6 60
            9d 8d de 81 03 69 13 dd 66 09 e9 18 76 f9 25 65
            3d b7 ea 22 50 da 50 4d d8 74 31 5a 35 a2 29 7a
            09 31 0a 45 4e b2 29 fd 72 40 04 93 3a e3 a6 7d
            09 46 bb b5 8d e0 0f b5 12 e4 36 7d 38 32 3b b5
            ee 99 6f ad 2c ea af 39 9f a1 dc c9 70 dc 2f ad
            46 de 2a d6 8c 4e 3c e6 31 01 8a 97 f0 1f c9 3c
            b8 c8 f1 45 02 c4 d7 3d ee b9 88 6f 53 cc 85 0b
            69 ce 61 dc 30 c8 85 2d e1 d0 d3 d6 10 c2 32 04
            0d 96 2d d5 4a a4 1f e2 bc a3 77 15 72 61 20 75
            aa 9b 4a ee f7 25 cf 22 95 b9 77 88 48 f3 30 8e
            a4 ab 3d b4 bd b4 e4 24 98 b7 ca 7e bf 26 ee 82
            b5 b4 fd f2 f0 65 04 ea 4c 7c 75 25 24 b0 be 92
            9a a2 b7 e4 82 5a 37 cf 08 3f 0e 9b 6c 89 27 b4
            33 15 75 24
        ");

        let hkdf_alg = crate::suites::TLS13_AES_128_GCM_SHA256.hkdf_algorithm;
        let zx = super::zx(hkdf_alg, &z_bytes.to_vec());
        let aead_alg = crate::suites::TLS13_AES_128_GCM_SHA256.get_aead_alg();
        let key = hkdf_expand(&zx, aead_alg, b"esni key", hash.as_ref());

        let iv: Iv = hkdf_expand(&zx, IvLen, b"esni iv", hash.as_ref());
        assert!(crate::msgs::handshake::slice_eq(&expected_iv, iv.value()));

        let aad = ring::aead::Aad::from(aad_bytes.to_vec());
        let mut sni_bytes = Vec::from(plain_text.to_vec());
        let encrypted = super::encrypt(key, iv, aad, &mut sni_bytes).unwrap();

        assert!(crate::msgs::handshake::slice_eq(&expected, &encrypted));
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
            d3 84 15
         ");

        let plain_text = hex!("
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
            00 00 00 00
        ");

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
            62 ee 41 8a
         ");

        let alg= crate::suites::TLS13_AES_128_GCM_SHA256.get_aead_alg();
        let key = ring::aead::UnboundKey::new(alg, &key_bytes).unwrap();
        let iv = crate::cipher::Iv::new(iv_bytes);
        let aad = ring::aead::Aad::from(aad_bytes.to_vec());
        let mut sni_bytes = Vec::from(plain_text.to_vec());
        let encrypted = super::encrypt(key, iv, aad, &mut sni_bytes).unwrap();
        assert_eq!(expected.len(), encrypted.len());
        assert!(crate::msgs::handshake::slice_eq(&expected, encrypted.as_slice()));
    }
}
