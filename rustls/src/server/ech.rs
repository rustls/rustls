use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;

use pki_types::{DnsName, EchConfigListBytes};

use crate::crypto::hpke::{EncapsulatedSecret, Hpke, HpkeOpener, HpkePrivateKey, HpkeSuite};
use crate::enums::ProtocolVersion;
use crate::error::{EncryptedClientHelloError, Error};
use crate::log::{debug, trace, warn};
use crate::msgs::{
    ClientHelloPayload, Codec, EchConfigContents, EchConfigPayload, EncryptedClientHello,
    EncryptedClientHelloOuter, HandshakeMessagePayload, HandshakePayload, Message, MessagePayload,
    Reader,
};
use crate::sync::Arc;

/// Server-side ECH key configuration.
///
/// Holds an ECH configuration (containing the public key, config ID, and
/// cipher suites) together with the corresponding HPKE private key and a
/// matched HPKE suite.  The server uses this to decrypt ECH-offering
/// ClientHellos.
///
/// Construct with [`ServerEchConfig::new`].
#[derive(Clone)]
pub struct ServerEchConfig {
    pub(crate) config: EchConfigPayload,
    pub(crate) suite: &'static dyn Hpke,
    pub(crate) private_key: Arc<HpkePrivateKey>,
}

impl core::fmt::Debug for ServerEchConfig {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ServerEchConfig")
            .field("config", &self.config)
            .field("suite", &self.suite)
            .field("private_key", &"[redacted]")
            .finish()
    }
}

impl ServerEchConfig {
    /// Build a server ECH key from an ECH config list, a matching private key,
    /// and the available HPKE suites.
    ///
    /// The `ech_config_list` should contain one or more ECH configurations.
    /// The first configuration that is compatible with one of the provided
    /// `hpke_suites` is selected.  The `private_key` must correspond to the
    /// public key in the selected configuration.
    ///
    /// Returns an error if the config list is malformed or no compatible
    /// configuration is found.
    pub fn new(
        ech_config_list: EchConfigListBytes<'_>,
        private_key: HpkePrivateKey,
        hpke_suites: &[&'static dyn Hpke],
    ) -> Result<Self, Error> {
        let ech_configs = Vec::<EchConfigPayload>::read(&mut Reader::new(&ech_config_list))
            .map_err(|_| {
                Error::InvalidEncryptedClientHello(EncryptedClientHelloError::InvalidConfigList)
            })?;

        for (i, config) in ech_configs.iter().enumerate() {
            let contents = match config {
                EchConfigPayload::V18(contents) => contents,
                EchConfigPayload::Unknown { version, .. } => {
                    warn!("ECH config {} has unsupported version {:?}", i + 1, version);
                    continue;
                }
            };

            if contents.has_unknown_mandatory_extension() || contents.has_duplicate_extension() {
                warn!(
                    "ECH config has duplicate, or unknown mandatory extensions: {contents:?}",
                );
                continue;
            }

            let key_config = &contents.key_config;
            for cipher_suite in &key_config.symmetric_cipher_suites {
                if cipher_suite.aead_id.tag_len().is_none() {
                    continue;
                }

                let suite = HpkeSuite {
                    kem: key_config.kem_id,
                    sym: *cipher_suite,
                };
                if let Some(hpke) = hpke_suites
                    .iter()
                    .find(|hpke| hpke.suite() == suite)
                {
                    debug!(
                        "selected server ECH config ID {:?} suite {:?} public_name {:?}",
                        key_config.config_id, suite, contents.public_name
                    );
                    return Ok(Self {
                        config: config.clone(),
                        suite: *hpke,
                        private_key: Arc::new(private_key),
                    });
                }
            }
        }

        Err(EncryptedClientHelloError::NoCompatibleConfig.into())
    }

    /// Generate a fresh ECH key pair and configuration for the given HPKE suite.
    ///
    /// This creates a new key pair, builds an `EchConfigPayload` with the given
    /// `config_id` and `public_name`, and returns both the `ServerEchConfig` (for
    /// the server) and the encoded `EchConfigListBytes` (for distribution to
    /// clients, e.g. via DNS HTTPS records).
    pub fn generate(
        suite: &'static dyn Hpke,
        config_id: u8,
        public_name: DnsName<'static>,
        maximum_name_length: u8,
    ) -> Result<(Self, EchConfigListBytes<'static>), Error> {
        use crate::msgs::{EchConfigContents, EchConfigPayload, HpkeKeyConfig, SizedPayload};

        let (public_key, private_key) = suite.generate_key_pair()?;
        let hpke_suite = suite.suite();

        let config = EchConfigPayload::V18(EchConfigContents {
            key_config: HpkeKeyConfig {
                config_id,
                kem_id: hpke_suite.kem,
                public_key: SizedPayload::from(crate::crypto::cipher::Payload::new(
                    public_key.0,
                )),
                symmetric_cipher_suites: vec![hpke_suite.sym],
            },
            maximum_name_length,
            public_name,
            extensions: Vec::new(),
        });

        // Encode as an ECH config list (length-prefixed list of EchConfigPayload).
        let mut config_list_bytes = Vec::new();
        vec![config.clone()].encode(&mut config_list_bytes);
        let config_list = EchConfigListBytes::from(config_list_bytes);

        Ok((
            Self {
                config,
                suite,
                private_key: Arc::new(private_key),
            },
            config_list,
        ))
    }

    /// Compute the HPKE `SetupBaseS` `info` parameter for this ECH configuration.
    ///
    /// See <https://datatracker.ietf.org/doc/html/rfc9849#section-6.1>.
    pub(crate) fn hpke_info(&self) -> Vec<u8> {
        let mut info = Vec::with_capacity(128);
        info.extend_from_slice(b"tls ech\0");
        self.config.encode(&mut info);
        info
    }

    /// Return the config ID from this ECH configuration, if V18.
    pub(crate) fn config_id(&self) -> Option<u8> {
        match &self.config {
            EchConfigPayload::V18(contents) => Some(contents.key_config.config_id),
            EchConfigPayload::Unknown { .. } => None,
        }
    }

    /// Return the V18 contents of this ECH configuration.
    pub(crate) fn v18_contents(&self) -> Option<&EchConfigContents> {
        match &self.config {
            EchConfigPayload::V18(contents) => Some(contents),
            EchConfigPayload::Unknown { .. } => None,
        }
    }
}

/// Per-connection ECH state when the server has accepted an ECH offer.
pub(crate) struct ServerEchState {
    /// The inner ClientHello's random, needed for ECH confirmation derivation.
    pub(crate) inner_random: [u8; 32],
    /// The HPKE opener context, retained across HRR for the second ClientHello.
    pub(crate) opener: Box<dyn HpkeOpener>,
}

/// Result of attempting ECH decryption on a received ClientHello.
pub(crate) enum EchDecryptResult {
    /// ECH was offered and decryption succeeded.
    Accepted {
        /// The reconstructed inner ClientHello wrapped as a Message for transcript.
        inner_message: Message<'static>,
        /// Per-connection state to carry through the handshake.
        state: ServerEchState,
    },
    /// ECH was offered but decryption or inner hello reconstruction failed.
    /// The handshake should continue with the outer ClientHello.
    Rejected,
    /// No ECH extension was present in the ClientHello.
    NotOffered,
}

/// Attempt to decrypt an ECH-offering ClientHello.
///
/// Per RFC 9849 Section 7.1, if decryption fails the server MUST ignore the
/// ECH extension and proceed with the outer ClientHello.
/// Attempt to decrypt an ECH-offering ClientHello.
///
/// `outer_encoded` is the raw `HandshakeMessagePayload` encoding of the
/// ClientHello as received on the wire.  It is used to compute the HPKE AAD
/// (the ClientHello payload with the ECH extension's encrypted payload
/// replaced by zeros), which must match the encoding the client used when
/// sealing.
pub(crate) fn try_decrypt_ech(
    outer_hello: &ClientHelloPayload,
    outer_encoded: &[u8],
    ech_keys: &[ServerEchConfig],
    is_retry: bool,
) -> EchDecryptResult {
    let ech_outer = match &outer_hello.encrypted_client_hello {
        Some(EncryptedClientHello::Outer(outer)) => outer,
        Some(EncryptedClientHello::Inner) | None => return EchDecryptResult::NotOffered,
    };

    for key in ech_keys {
        // These use `continue` on None/Err to try the next key, which
        // does not lend itself to combinators.
        let Some(config_id) = key.config_id() else {
            continue;
        };

        if config_id != ech_outer.config_id {
            continue;
        }

        let Some(contents) = key.v18_contents() else {
            continue;
        };

        let suite_matches = contents
            .key_config
            .symmetric_cipher_suites
            .iter()
            .any(|s| *s == ech_outer.cipher_suite);
        if !suite_matches {
            continue;
        }

        let enc = EncapsulatedSecret(ech_outer.enc.bytes().to_vec());
        let info = key.hpke_info();
        let Ok(mut opener) = key.suite.setup_opener(&enc, &info, &key.private_key) else {
            continue;
        };

        let aad = compute_ech_aad_from_encoding(outer_encoded, ech_outer);

        let Ok(plaintext) = opener.open(&aad, ech_outer.payload.bytes()) else {
            continue;
        };

        return decode_inner_hello(&plaintext, outer_hello, is_retry).map_or_else(
            || {
                trace!("ECH inner hello reconstruction failed for config_id {config_id}");
                EchDecryptResult::Rejected
            },
            |inner_message| {
                let inner_random = extract_random(&inner_message);
                trace!("ECH decryption succeeded for config_id {config_id}");
                EchDecryptResult::Accepted {
                    inner_message,
                    state: ServerEchState {
                        inner_random,
                        opener,
                    },
                }
            },
        );
    }

    // No matching config found, or all decryption attempts failed.
    outer_hello
        .encrypted_client_hello
        .as_ref()
        .map_or(EchDecryptResult::NotOffered, |_| EchDecryptResult::Rejected)
}

/// Attempt ECH decryption for a retry (second ClientHello after HRR),
/// reusing the opener from the first successful decryption.
pub(crate) fn try_decrypt_ech_retry(
    outer_hello: &ClientHelloPayload,
    outer_encoded: &[u8],
    state: &mut ServerEchState,
) -> Option<Message<'static>> {
    let ech_outer = match &outer_hello.encrypted_client_hello {
        Some(EncryptedClientHello::Outer(outer)) => outer,
        Some(EncryptedClientHello::Inner) | None => return None,
    };

    let aad = compute_ech_aad_from_encoding(outer_encoded, ech_outer);

    state
        .opener
        .open(&aad, ech_outer.payload.bytes())
        .ok()
        .and_then(|plaintext| decode_inner_hello(&plaintext, outer_hello, true))
        .map(|inner_message| {
            state.inner_random = extract_random(&inner_message);
            inner_message
        })
}

/// Compute the AAD for ECH decryption from the raw handshake encoding.
///
/// The AAD is the ClientHello payload encoding (without the 4-byte handshake
/// header) with the ECH extension's encrypted payload replaced by zeros.
/// We operate on the raw wire bytes to preserve the original extension
/// ordering (which uses a randomized seed not recoverable from parsing).
fn compute_ech_aad_from_encoding(
    outer_encoded: &[u8],
    ech_outer: &EncryptedClientHelloOuter,
) -> Vec<u8> {
    // The handshake encoding is: type (1) + length (3) + ClientHello payload.
    // The AAD is just the ClientHello payload portion.
    let ch_payload = &outer_encoded[4..];
    let mut aad = ch_payload.to_vec();

    // Find and zero the ECH extension's payload within the AAD.
    // The ECH extension payload is the `payload` field of
    // EncryptedClientHelloOuter: a u16-length-prefixed ciphertext that we
    // need to zero.  We search for the ECH extension by its encoded form.
    let payload_bytes = ech_outer.payload.bytes();
    zero_ech_payload_in_encoding(&mut aad, payload_bytes.len());

    aad
}

/// Find the ECH extension in the encoded ClientHello payload and zero its
/// encrypted payload field.
///
/// The ECH extension (type 0xfe0d) encoding within the extensions list is:
///   extension_type (2) + extension_length (2) + ECH_type (1=outer) +
///   cipher_suite (4) + config_id (1) + enc_len (2) + enc + payload_len (2) + payload
///
/// We scan the extensions to find type 0xfe0d, then zero the last
/// `payload_len` bytes of the extension data.
fn zero_ech_payload_in_encoding(ch_payload: &mut [u8], payload_len: usize) {
    // Skip: client_version (2) + random (32) + session_id (1+len) +
    // cipher_suites (2+len) + compression (1+len).
    let mut pos = 2 + 32; // version + random

    // session_id: 1-byte length + data
    let sid_len = *ch_payload.get(pos).unwrap_or(&0) as usize;
    pos += 1 + sid_len;

    // cipher_suites: 2-byte length + data
    let cs_len = ch_payload
        .get(pos..pos + 2)
        .map(|b| u16::from_be_bytes([b[0], b[1]]) as usize)
        .unwrap_or(0);
    pos += 2 + cs_len;

    // compression_methods: 1-byte length + data
    let comp_len = *ch_payload.get(pos).unwrap_or(&0) as usize;
    pos += 1 + comp_len;

    // extensions: 2-byte length + extension data
    let _ext_total_len = ch_payload
        .get(pos..pos + 2)
        .map(|b| u16::from_be_bytes([b[0], b[1]]) as usize)
        .unwrap_or(0);
    pos += 2;

    // Scan extensions looking for type 0xfe0d.
    while pos + 4 <= ch_payload.len() {
        let ext_type = u16::from_be_bytes([ch_payload[pos], ch_payload[pos + 1]]);
        let ext_len =
            u16::from_be_bytes([ch_payload[pos + 2], ch_payload[pos + 3]]) as usize;
        let ext_data_start = pos + 4;

        if ext_type == 0xfe0d {
            // Found the ECH extension.  The payload field is at the end:
            // the last (2 + payload_len) bytes of ext_data are the
            // u16 length prefix + payload.
            let payload_start = ext_data_start + ext_len - payload_len;
            ch_payload[payload_start..payload_start + payload_len].fill(0x00);
            return;
        }

        pos = ext_data_start + ext_len;
    }
}

/// Decode an ECH-encoded inner ClientHello.
///
/// This is the inverse of `ClientHelloPayload::ech_inner_encoding`.
/// Per RFC 9849 Section 5.1:
/// - The encoded inner hello has an empty session_id (restored from outer).
/// - Compressed extensions are indicated by `EncryptedClientHelloOuterExtensions`.
/// - Trailing zero padding follows the extensions.
fn decode_inner_hello(
    encoded: &[u8],
    outer_hello: &ClientHelloPayload,
    is_retry: bool,
) -> Option<Message<'static>> {
    // Parse the inner ClientHello payload fields individually.
    // We cannot use ClientHelloPayload::read directly because the encoded
    // inner hello has zero-padding after the extensions that would cause the
    // trailing-data check to fail.
    let mut reader = Reader::new(encoded);
    let mut inner_hello = parse_inner_hello_tolerant(&mut reader).or_else(|| {
        trace!("Failed to parse ECH inner ClientHello");
        None
    })?;

    // Restore session_id from outer hello (inner encoding uses empty session_id).
    inner_hello.session_id = outer_hello.session_id;

    // Validate that the inner hello has the ECH Inner marker.
    match &inner_hello.encrypted_client_hello {
        Some(EncryptedClientHello::Inner) => {}
        Some(EncryptedClientHello::Outer(..)) | None => {
            trace!("ECH inner hello missing Inner marker");
            return None;
        }
    }

    // Expand compressed extensions: copy listed extension values from the
    // outer hello for each type in the OuterExtensions marker.
    if let Some(compressed_types) = inner_hello.encrypted_client_hello_outer.take() {
        for ext_type in &compressed_types {
            inner_hello
                .extensions
                .clone_one(&outer_hello.extensions, *ext_type);
        }
    }

    let version = if is_retry {
        ProtocolVersion::TLSv1_2
    } else {
        ProtocolVersion::TLSv1_0
    };

    Some(Message {
        version,
        payload: MessagePayload::handshake(HandshakeMessagePayload(
            HandshakePayload::ClientHello(inner_hello),
        )),
    })
}

/// Parse a ClientHelloPayload without rejecting trailing data.
///
/// The standard `ClientHelloPayload::read` returns `Err` if any bytes remain
/// after parsing.  The ECH inner encoding appends zero-padding that sits
/// outside the extensions length prefix, so we parse the fields ourselves
/// and simply ignore leftover bytes.
fn parse_inner_hello_tolerant(r: &mut Reader<'_>) -> Option<ClientHelloPayload> {
    use crate::crypto::CipherSuite;
    use crate::msgs::{ClientExtensions, Compression, SessionId};

    Some(ClientHelloPayload {
        client_version: ProtocolVersion::read(r).ok()?,
        random: crate::msgs::Random::read(r).ok()?,
        session_id: SessionId::read(r).ok()?,
        cipher_suites: Vec::<CipherSuite>::read(r).ok()?,
        compression_methods: Vec::<Compression>::read(r).ok()?,
        extensions: Box::new(ClientExtensions::read(r).ok()?.into_owned()),
    })
}

/// Extract the 32-byte random from a ClientHello message.
///
/// Panics if `msg` is not a ClientHello handshake message.  Callers
/// must ensure this precondition (it is always satisfied in this module
/// because we only call it on messages we just constructed).
fn extract_random(msg: &Message<'_>) -> [u8; 32] {
    match &msg.payload {
        MessagePayload::Handshake { parsed, .. } => match &parsed.0 {
            HandshakePayload::ClientHello(ch) => ch.random.0,
            HandshakePayload::HelloRequest
            | HandshakePayload::ServerHello(..)
            | HandshakePayload::HelloRetryRequest(..)
            | HandshakePayload::Certificate(..)
            | HandshakePayload::CertificateTls13(..)
            | HandshakePayload::CompressedCertificate(..)
            | HandshakePayload::ServerKeyExchange(..)
            | HandshakePayload::CertificateRequest(..)
            | HandshakePayload::CertificateRequestTls13(..)
            | HandshakePayload::CertificateVerify(..)
            | HandshakePayload::ServerHelloDone
            | HandshakePayload::ClientKeyExchange(..)
            | HandshakePayload::NewSessionTicket(..)
            | HandshakePayload::NewSessionTicketTls13(..)
            | HandshakePayload::EncryptedExtensions(..)
            | HandshakePayload::KeyUpdate(..)
            | HandshakePayload::EndOfEarlyData
            | HandshakePayload::Finished(..)
            | HandshakePayload::CertificateStatus(..)
            | HandshakePayload::MessageHash(..)
            | HandshakePayload::Unknown(..) => {
                panic!("extract_random called on non-ClientHello message")
            }
        },
        MessagePayload::Alert(..)
        | MessagePayload::HandshakeFlight(..)
        | MessagePayload::ChangeCipherSpec(..)
        | MessagePayload::ApplicationData(..) => {
            panic!("extract_random called on non-Handshake message")
        }
    }
}
