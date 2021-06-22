/// This module contains optional APIs for implementing QUIC TLS.
use crate::cipher::{Iv, IvLen};
pub use crate::client::ClientQuicExt;
use crate::conn::ConnectionCommon;
use crate::error::Error;
use crate::msgs::base::Payload;
use crate::msgs::enums::{AlertDescription, ContentType, ProtocolVersion};
use crate::msgs::message::PlainMessage;
pub use crate::server::ServerQuicExt;
use crate::suites::BulkAlgorithm;
use crate::tls13::key_schedule::hkdf_expand;
use crate::tls13::{Tls13CipherSuite, TLS13_AES_128_GCM_SHA256_INTERNAL};

use ring::{aead, hkdf};

/// Secrets used to encrypt/decrypt traffic
#[derive(Clone, Debug)]
pub struct Secrets {
    /// Secret used to encrypt packets transmitted by the client
    client: hkdf::Prk,
    /// Secret used to encrypt packets transmitted by the server
    server: hkdf::Prk,
    /// Cipher suite used with these secrets
    suite: &'static Tls13CipherSuite,
    is_client: bool,
}

impl Secrets {
    pub(crate) fn new(
        client: hkdf::Prk,
        server: hkdf::Prk,
        suite: &'static Tls13CipherSuite,
        is_client: bool,
    ) -> Self {
        Self {
            client,
            server,
            suite,
            is_client,
        }
    }

    /// Derive the next set of packet keys
    pub fn next_packet_keys(&mut self) -> PacketKeySet {
        let keys = PacketKeySet::new(self);
        self.update();
        keys
    }

    fn update(&mut self) {
        let hkdf_alg = self.suite.hkdf_algorithm;
        self.client = hkdf_expand(&self.client, hkdf_alg, b"quic ku", &[]);
        self.server = hkdf_expand(&self.server, hkdf_alg, b"quic ku", &[]);
    }

    fn local_remote(&self) -> (&hkdf::Prk, &hkdf::Prk) {
        if self.is_client {
            (&self.client, &self.server)
        } else {
            (&self.server, &self.client)
        }
    }
}

/// Generic methods for QUIC sessions
pub trait QuicExt {
    /// Return the TLS-encoded transport parameters for the session's peer.
    ///
    /// While the transport parameters are technically available prior to the
    /// completion of the handshake, they cannot be fully trusted until the
    /// handshake completes, and reliance on them should be minimized.
    /// However, any tampering with the parameters will cause the handshake
    /// to fail.
    fn quic_transport_parameters(&self) -> Option<&[u8]>;

    /// Compute the keys for encrypting/decrypting 0-RTT packets, if available
    fn zero_rtt_keys(&self) -> Option<DirectionalKeys>;

    /// Consume unencrypted TLS handshake data.
    ///
    /// Handshake data obtained from separate encryption levels should be supplied in separate calls.
    fn read_hs(&mut self, plaintext: &[u8]) -> Result<(), Error>;

    /// Emit unencrypted TLS handshake data.
    ///
    /// When this returns `Some(_)`, the new keys must be used for future handshake data.
    fn write_hs(&mut self, buf: &mut Vec<u8>) -> Option<KeyChange>;

    /// Emit the TLS description code of a fatal alert, if one has arisen.
    ///
    /// Check after `read_hs` returns `Err(_)`.
    fn alert(&self) -> Option<AlertDescription>;
}

/// Keys used to communicate in a single direction
pub struct DirectionalKeys {
    /// Encrypts or decrypts a packet's headers
    pub header: aead::quic::HeaderProtectionKey,
    /// Encrypts or decrypts the payload of a packet
    pub packet: PacketKey,
}

impl DirectionalKeys {
    pub(crate) fn new(suite: &'static Tls13CipherSuite, secret: &hkdf::Prk) -> Self {
        let hp_alg = match suite.common.bulk {
            BulkAlgorithm::Aes128Gcm => &aead::quic::AES_128,
            BulkAlgorithm::Aes256Gcm => &aead::quic::AES_256,
            BulkAlgorithm::Chacha20Poly1305 => &aead::quic::CHACHA20,
        };

        Self {
            header: hkdf_expand(secret, hp_alg, b"quic hp", &[]),
            packet: PacketKey::new(suite, secret),
        }
    }
}

/// Keys to encrypt or decrypt the payload of a packet
pub struct PacketKey {
    /// Encrypts or decrypts a packet's payload
    key: aead::LessSafeKey,
    /// Computes unique nonces for each packet
    iv: Iv,
    /// The cipher suite used for this packet key
    suite: &'static Tls13CipherSuite,
}

impl PacketKey {
    fn new(suite: &'static Tls13CipherSuite, secret: &hkdf::Prk) -> Self {
        Self {
            key: aead::LessSafeKey::new(hkdf_expand(
                secret,
                suite.common.aead_algorithm,
                b"quic key",
                &[],
            )),
            iv: hkdf_expand(secret, IvLen, b"quic iv", &[]),
            suite,
        }
    }

    /// Encrypt a QUIC packet
    ///
    /// Takes a `packet_number`, used to derive the nonce; the packet `header`, which is used as
    /// the additional authenticated data; and the `payload`. The authentication tag is returned if
    /// encryption succeeds.
    ///
    /// Fails iff the payload is longer than allowed by the cipher suite's AEAD algorithm.
    pub fn encrypt_in_place(
        &self,
        packet_number: u64,
        header: &[u8],
        payload: &mut [u8],
    ) -> Result<Tag, Error> {
        let aad = aead::Aad::from(header);
        let nonce = nonce_for(packet_number, &self.iv);
        let tag = self
            .key
            .seal_in_place_separate_tag(nonce, aad, payload)
            .map_err(|_| Error::EncryptError)?;
        Ok(Tag(tag))
    }

    /// Decrypt a QUIC packet
    ///
    /// Takes the packet `header`, which is used as the additional authenticated data, and the
    /// `payload`, which includes the authentication tag.
    ///
    /// If the return value is `Ok`, the decrypted payload can be found in `payload`, up to the
    /// length found in the return value.
    pub fn decrypt_in_place<'a>(
        &self,
        packet_number: u64,
        header: &[u8],
        payload: &'a mut [u8],
    ) -> Result<&'a [u8], Error> {
        let payload_len = payload.len();
        let aad = aead::Aad::from(header);
        let nonce = nonce_for(packet_number, &self.iv);
        self.key
            .open_in_place(nonce, aad, payload)
            .map_err(|_| Error::DecryptError)?;

        let plain_len = payload_len - self.key.algorithm().tag_len();
        Ok(&payload[..plain_len])
    }

    /// Number of times the packet key can be used without sacrificing confidentiality
    ///
    /// See <https://www.rfc-editor.org/rfc/rfc9001.html#name-confidentiality-limit>.
    #[inline]
    pub fn confidentiality_limit(&self) -> u64 {
        self.suite.confidentiality_limit
    }

    /// Number of times the packet key can be used without sacrificing integrity
    ///
    /// See <https://www.rfc-editor.org/rfc/rfc9001.html#name-integrity-limit>.
    #[inline]
    pub fn integrity_limit(&self) -> u64 {
        self.suite.integrity_limit
    }

    /// Tag length for the underlying AEAD algorithm
    #[inline]
    pub fn tag_len(&self) -> usize {
        self.key.algorithm().tag_len()
    }
}

/// AEAD tag, must be appended to encrypted cipher text
pub struct Tag(aead::Tag);

impl AsRef<[u8]> for Tag {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

/// Packet protection keys for bidirectional 1-RTT communication
pub struct PacketKeySet {
    /// Encrypts outgoing packets
    pub local: PacketKey,
    /// Decrypts incoming packets
    pub remote: PacketKey,
}

impl PacketKeySet {
    fn new(secrets: &Secrets) -> Self {
        let (local, remote) = secrets.local_remote();
        Self {
            local: PacketKey::new(secrets.suite, local),
            remote: PacketKey::new(secrets.suite, remote),
        }
    }
}

/// Complete set of keys used to communicate with the peer
pub struct Keys {
    /// Encrypts outgoing packets
    pub local: DirectionalKeys,
    /// Decrypts incoming packets
    pub remote: DirectionalKeys,
}

impl Keys {
    /// Construct keys for use with initial packets
    pub fn initial(
        initial_salt: &hkdf::Salt,
        client_dst_connection_id: &[u8],
        is_client: bool,
    ) -> Self {
        const CLIENT_LABEL: &[u8] = b"client in";
        const SERVER_LABEL: &[u8] = b"server in";
        let hs_secret = initial_salt.extract(client_dst_connection_id);

        let secrets = Secrets {
            client: hkdf_expand(&hs_secret, hkdf::HKDF_SHA256, CLIENT_LABEL, &[]),
            server: hkdf_expand(&hs_secret, hkdf::HKDF_SHA256, SERVER_LABEL, &[]),
            suite: TLS13_AES_128_GCM_SHA256_INTERNAL,
            is_client,
        };
        Self::new(&secrets)
    }

    fn new(secrets: &Secrets) -> Self {
        let (local, remote) = secrets.local_remote();
        Self {
            local: DirectionalKeys::new(secrets.suite, local),
            remote: DirectionalKeys::new(secrets.suite, remote),
        }
    }
}

pub(crate) fn read_hs(this: &mut ConnectionCommon, plaintext: &[u8]) -> Result<(), Error> {
    if this
        .handshake_joiner
        .take_message(PlainMessage {
            typ: ContentType::Handshake,
            version: ProtocolVersion::TLSv1_3,
            payload: Payload::new(plaintext.to_vec()),
        })
        .is_none()
    {
        this.quic.alert = Some(AlertDescription::DecodeError);
        return Err(Error::CorruptMessage);
    }
    Ok(())
}

pub(crate) fn write_hs(this: &mut ConnectionCommon, buf: &mut Vec<u8>) -> Option<KeyChange> {
    while let Some((_, msg)) = this.quic.hs_queue.pop_front() {
        buf.extend_from_slice(&msg);
        if let Some(&(true, _)) = this.quic.hs_queue.front() {
            if this.quic.hs_secrets.is_some() {
                // Allow the caller to switch keys before proceeding.
                break;
            }
        }
    }

    if let Some(secrets) = this.quic.hs_secrets.take() {
        return Some(KeyChange::Handshake {
            keys: Keys::new(&secrets),
        });
    }

    if let Some(mut secrets) = this.quic.traffic_secrets.take() {
        if !this.quic.returned_traffic_keys {
            this.quic.returned_traffic_keys = true;
            let keys = Keys::new(&secrets);
            secrets.update();
            return Some(KeyChange::OneRtt {
                keys,
                next: secrets,
            });
        }
    }

    None
}

/// Key material for use in QUIC packet spaces
///
/// QUIC uses 4 different sets of keys (and progressive key updates for long-running connections):
///
/// * Initial: these can be created from [`Keys::initial()`]
/// * 0-RTT keys: can be retrieved from [`QuicExt::zero_rtt_keys()`]
/// * Handshake: these are returned from [`QuicExt::write_hs()`] after `ClientHello` and
///   `ServerHello` messages have been exchanged
/// * 1-RTT keys: these are returned from [`QuicExt::write_hs()`] after the handshake is done
///
/// Once the 1-RTT keys have been exchanged, either side may initiate a key update. Progressive
/// update keys can be obtained from the [`Secrets`] returned in [`KeyChange::OneRtt`]. Note that
/// only packet keys are updated by key updates; header protection keys remain the same.
#[allow(clippy::large_enum_variant)]
pub enum KeyChange {
    /// Keys for the handshake space
    Handshake {
        /// Header and packet keys for the handshake space
        keys: Keys,
    },
    /// Keys for 1-RTT data
    OneRtt {
        /// Header and packet keys for 1-RTT data
        keys: Keys,
        /// Secrets to derive updated keys from
        next: Secrets,
    },
}

/// Compute the nonce to use for encrypting or decrypting `packet_number`
fn nonce_for(packet_number: u64, iv: &Iv) -> ring::aead::Nonce {
    let mut out = [0; aead::NONCE_LEN];
    out[4..].copy_from_slice(&packet_number.to_be_bytes());
    for (out, inp) in out.iter_mut().zip(iv.0.iter()) {
        *out ^= inp;
    }
    aead::Nonce::assume_unique_for_key(out)
}

/// QUIC protocol version
///
/// Governs version-specific behavior in the TLS layer
#[non_exhaustive]
pub enum Version {
    /// Draft versions prior to V1
    V1Draft,
    /// First stable RFC
    V1,
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn initial_keys_test_vectors() {
        // Test vectors based on draft 27
        const INITIAL_SALT: [u8; 20] = [
            0xc3, 0xee, 0xf7, 0x12, 0xc7, 0x2e, 0xbb, 0x5a, 0x11, 0xa7, 0xd2, 0x43, 0x2b, 0xb4,
            0x63, 0x65, 0xbe, 0xf9, 0xf5, 0x02,
        ];

        const CONNECTION_ID: &[u8] = &[0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];
        const PACKET_NUMBER: u64 = 42;

        let initial_salt = hkdf::Salt::new(hkdf::HKDF_SHA256, &INITIAL_SALT);
        let server_keys = Keys::initial(&initial_salt, &CONNECTION_ID, false);
        let client_keys = Keys::initial(&initial_salt, &CONNECTION_ID, true);

        // Nonces
        const SERVER_NONCE: [u8; 12] = [
            0x5e, 0x5a, 0xe6, 0x51, 0xfd, 0x1e, 0x84, 0x95, 0xaf, 0x13, 0x50, 0xa1,
        ];
        assert_eq!(
            nonce_for(PACKET_NUMBER, &server_keys.local.packet.iv).as_ref(),
            &SERVER_NONCE
        );
        assert_eq!(
            nonce_for(PACKET_NUMBER, &client_keys.remote.packet.iv).as_ref(),
            &SERVER_NONCE
        );
        const CLIENT_NONCE: [u8; 12] = [
            0x86, 0x81, 0x35, 0x94, 0x10, 0xa7, 0x0b, 0xb9, 0xc9, 0x2f, 0x04, 0x0a,
        ];
        assert_eq!(
            nonce_for(PACKET_NUMBER, &server_keys.remote.packet.iv).as_ref(),
            &CLIENT_NONCE
        );
        assert_eq!(
            nonce_for(PACKET_NUMBER, &client_keys.local.packet.iv).as_ref(),
            &CLIENT_NONCE
        );

        // Header encryption mask
        const SAMPLE: &[u8] = &[
            0x70, 0x02, 0x59, 0x6f, 0x99, 0xae, 0x67, 0xab, 0xf6, 0x5a, 0x58, 0x52, 0xf5, 0x4f,
            0x58, 0xc3,
        ];

        const SERVER_MASK: [u8; 5] = [0x38, 0x16, 0x8a, 0x0c, 0x25];
        assert_eq!(
            server_keys
                .local
                .header
                .new_mask(SAMPLE)
                .unwrap(),
            SERVER_MASK
        );
        assert_eq!(
            client_keys
                .remote
                .header
                .new_mask(SAMPLE)
                .unwrap(),
            SERVER_MASK
        );
        const CLIENT_MASK: [u8; 5] = [0xae, 0x96, 0x2e, 0x67, 0xec];
        assert_eq!(
            server_keys
                .remote
                .header
                .new_mask(SAMPLE)
                .unwrap(),
            CLIENT_MASK
        );
        assert_eq!(
            client_keys
                .local
                .header
                .new_mask(SAMPLE)
                .unwrap(),
            CLIENT_MASK
        );

        const AAD: &[u8] = &[
            0xc9, 0xff, 0x00, 0x00, 0x1b, 0x00, 0x08, 0xf0, 0x67, 0xa5, 0x50, 0x2a, 0x42, 0x62,
            0xb5, 0x00, 0x40, 0x74, 0x16, 0x8b,
        ];
        let aad = aead::Aad::from(AAD);
        const PLAINTEXT: [u8; 12] = [
            0x0d, 0x00, 0x00, 0x00, 0x00, 0x18, 0x41, 0x0a, 0x02, 0x00, 0x00, 0x56,
        ];
        let mut payload = PLAINTEXT;
        let server_nonce = nonce_for(PACKET_NUMBER, &server_keys.local.packet.iv);
        let tag = server_keys
            .local
            .packet
            .key
            .seal_in_place_separate_tag(server_nonce, aad, &mut payload)
            .unwrap();
        assert_eq!(
            payload,
            [
                0x0d, 0x91, 0x96, 0x31, 0xc0, 0xeb, 0x84, 0xf2, 0x88, 0x59, 0xfe, 0xc0
            ]
        );
        assert_eq!(
            tag.as_ref(),
            &[
                0xdf, 0xee, 0x06, 0x81, 0x9e, 0x7a, 0x08, 0x34, 0xe4, 0x94, 0x19, 0x79, 0x5f, 0xe0,
                0xd7, 0x3f
            ]
        );

        let aad = aead::Aad::from(AAD);
        let mut payload = PLAINTEXT;
        let client_nonce = nonce_for(PACKET_NUMBER, &client_keys.local.packet.iv);
        let tag = client_keys
            .local
            .packet
            .key
            .seal_in_place_separate_tag(client_nonce, aad, &mut payload)
            .unwrap();
        assert_eq!(
            payload,
            [
                0x89, 0x6c, 0x66, 0x91, 0xe0, 0x9f, 0x47, 0x7a, 0x91, 0x42, 0xa4, 0x46
            ]
        );
        assert_eq!(
            tag.as_ref(),
            &[
                0xb6, 0xff, 0xef, 0x89, 0xd5, 0xcb, 0x53, 0xd0, 0x98, 0xf7, 0x40, 0xa, 0x8d, 0x97,
                0x72, 0x6e
            ]
        );
    }

    #[test]
    fn key_update_test_vector() {
        fn equal_prk(x: &hkdf::Prk, y: &hkdf::Prk) -> bool {
            let mut x_data = [0; 16];
            let mut y_data = [0; 16];
            let x_okm = x
                .expand(&[b"info"], &aead::quic::AES_128)
                .unwrap();
            x_okm.fill(&mut x_data[..]).unwrap();
            let y_okm = y
                .expand(&[b"info"], &aead::quic::AES_128)
                .unwrap();
            y_okm.fill(&mut y_data[..]).unwrap();
            x_data == y_data
        }

        let mut secrets = Secrets {
            // Constant dummy values for reproducibility
            client: hkdf::Prk::new_less_safe(
                hkdf::HKDF_SHA256,
                &[
                    0xb8, 0x76, 0x77, 0x08, 0xf8, 0x77, 0x23, 0x58, 0xa6, 0xea, 0x9f, 0xc4, 0x3e,
                    0x4a, 0xdd, 0x2c, 0x96, 0x1b, 0x3f, 0x52, 0x87, 0xa6, 0xd1, 0x46, 0x7e, 0xe0,
                    0xae, 0xab, 0x33, 0x72, 0x4d, 0xbf,
                ],
            ),
            server: hkdf::Prk::new_less_safe(
                hkdf::HKDF_SHA256,
                &[
                    0x42, 0xdc, 0x97, 0x21, 0x40, 0xe0, 0xf2, 0xe3, 0x98, 0x45, 0xb7, 0x67, 0x61,
                    0x34, 0x39, 0xdc, 0x67, 0x58, 0xca, 0x43, 0x25, 0x9b, 0x87, 0x85, 0x06, 0x82,
                    0x4e, 0xb1, 0xe4, 0x38, 0xd8, 0x55,
                ],
            ),
            suite: TLS13_AES_128_GCM_SHA256_INTERNAL,
            is_client: true,
        };
        secrets.update();

        assert!(equal_prk(
            &secrets.client,
            &hkdf::Prk::new_less_safe(
                hkdf::HKDF_SHA256,
                &[
                    0x42, 0xca, 0xc8, 0xc9, 0x1c, 0xd5, 0xeb, 0x40, 0x68, 0x2e, 0x43, 0x2e, 0xdf,
                    0x2d, 0x2b, 0xe9, 0xf4, 0x1a, 0x52, 0xca, 0x6b, 0x22, 0xd8, 0xe6, 0xcd, 0xb1,
                    0xe8, 0xac, 0xa9, 0x6, 0x1f, 0xce
                ]
            )
        ));
        assert!(equal_prk(
            &secrets.server,
            &hkdf::Prk::new_less_safe(
                hkdf::HKDF_SHA256,
                &[
                    0xeb, 0x7f, 0x5e, 0x2a, 0x12, 0x3f, 0x40, 0x7d, 0xb4, 0x99, 0xe3, 0x61, 0xca,
                    0xe5, 0x90, 0xd4, 0xd9, 0x92, 0xe1, 0x4b, 0x7a, 0xce, 0x3, 0xc2, 0x44, 0xe0,
                    0x42, 0x21, 0x15, 0xb6, 0xd3, 0x8a
                ]
            )
        ));
    }
}
