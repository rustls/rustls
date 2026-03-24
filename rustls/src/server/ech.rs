use alloc::boxed::Box;
use alloc::vec::Vec;
use core::fmt::Debug;

use crate::conn::Input;
use crate::crypto::cipher::Payload;
use crate::crypto::hpke::{
    EncapsulatedSecret, Hpke, HpkeOpener, HpkePrivateKey, HpkeSuite, HpkeSymmetricCipherSuite,
};
use crate::enums::HandshakeType;
use crate::error::{Error, PeerMisbehaved};
use crate::log::debug;
use crate::msgs::{
    ClientHelloPayload, Codec, EchConfigPayload, EncryptedClientHello, EncryptedClientHelloOuter,
    ExtensionType, HandshakeMessagePayload, HandshakePayload, Message, MessagePayload, Random,
    RawClientHello, Reader,
};
use crate::sync::Arc;

// --- Public API ---

/// A resolver for ECH server keys.
///
/// This trait allows ECH keys to be hot-swapped at runtime (e.g. for key
/// rotation) rather than requiring an immutable list at configuration time.
///
/// Called once per incoming ClientHello.
pub trait EchKeyResolver: Debug + Send + Sync {
    /// Return the current set of ECH keys.
    fn resolve(&self) -> EchKeys;
}

/// A pre-built, immutable set of ECH server keys.
///
/// Wraps the internal key index in an `Arc` for cheap cloning.
/// Construct via [`EchKeys::new`].
#[derive(Clone, Debug)]
pub struct EchKeys(Arc<EchKeyIndex>);

impl EchKeys {
    /// Build a key set from a list of ECH server keys.
    pub fn new(keys: Vec<EchServerKey>) -> Self {
        Self(Arc::new(EchKeyIndex::new(keys)))
    }

    /// An empty key set (no ECH support).
    pub fn empty() -> Self {
        Self(Arc::new(EchKeyIndex::new(Vec::new())))
    }

    pub(crate) fn index(&self) -> &EchKeyIndex {
        &self.0
    }
}

/// A fixed set of ECH server keys.
///
/// This is the simplest implementation of [`EchKeyResolver`], wrapping an
/// immutable [`EchKeys`].
#[derive(Debug)]
pub struct FixedEchKeys(EchKeys);

impl FixedEchKeys {
    /// Create a new `FixedEchKeys` from a list of keys.
    pub fn new(keys: Vec<EchServerKey>) -> Self {
        Self(EchKeys::new(keys))
    }

    /// Create an empty resolver (no ECH support).
    pub fn empty() -> Self {
        Self(EchKeys::empty())
    }
}

impl From<Vec<EchServerKey>> for FixedEchKeys {
    fn from(keys: Vec<EchServerKey>) -> Self {
        Self::new(keys)
    }
}

impl EchKeyResolver for FixedEchKeys {
    fn resolve(&self) -> EchKeys {
        self.0.clone()
    }
}

/// A server-side ECH key, pairing a published ECH config with the corresponding
/// HPKE private key.
///
/// Multiple keys can be configured on a server to support key rotation: publish
/// new configs in DNS while still accepting connections encrypted to old configs
/// during the DNS TTL transition period.
///
/// **Note:** `from_raw` does not validate that the private key matches the
/// config's public key. A mismatched key will cause ECH decryption to fail
/// at connection time rather than at construction time.
///
/// See <https://datatracker.ietf.org/doc/html/rfc9849#section-7.1> for the
/// server-side ECH decryption procedure.
pub struct EchServerKey {
    /// The full ECH config (needed for `encode()` in retry_configs and hpke_info).
    pub(crate) config: EchConfigPayload,

    /// The parsed V18 config contents (guaranteed V18 by construction).
    pub(crate) contents: crate::msgs::EchConfigContents,

    /// The HPKE private key corresponding to the config's public key.
    pub(crate) private_key: HpkePrivateKey,

    /// Available HPKE implementations.
    pub(crate) hpke_suites: Vec<&'static dyn Hpke>,

    /// Whether this config should be included in retry_configs on ECH rejection.
    pub(crate) is_retry_config: bool,

    /// Cached HPKE info parameter: `"tls ech" || 0x00 || ECHConfig`.
    pub(crate) hpke_info: Vec<u8>,
}

impl EchServerKey {
    /// Create an ECH server key from a raw ECHConfig and private key bytes.
    ///
    /// `config_bytes` should be a single serialized ECHConfig (not an ECHConfigList).
    /// All suites from `hpke_suites` matching the config's KEM and cipher suites
    /// are retained.
    ///
    /// Returns an error if the config cannot be parsed, is not a V18 config,
    /// has trailing data, or no matching HPKE suite is found.
    pub fn from_raw(
        config_bytes: &[u8],
        private_key_bytes: Vec<u8>,
        hpke_suites: &[&'static dyn Hpke],
    ) -> Result<Self, Error> {
        let mut reader = Reader::new(config_bytes);
        let config = EchConfigPayload::read(&mut reader)
            .map_err(|_| Error::General("invalid ECH config".into()))?;

        if reader.any_left() {
            return Err(Error::General("trailing data after ECH config".into()));
        }

        let EchConfigPayload::V18(contents) = &config else {
            return Err(Error::General("unsupported ECH config version".into()));
        };
        let contents = contents.clone();

        let matching_suites: Vec<&'static dyn Hpke> = hpke_suites
            .iter()
            .filter(|s| {
                let suite = s.suite();
                suite.kem == contents.key_config.kem_id
                    && contents
                        .key_config
                        .symmetric_cipher_suites
                        .contains(&suite.sym)
            })
            .copied()
            .collect();

        if matching_suites.is_empty() {
            return Err(Error::General(
                "no matching HPKE suite for ECH config".into(),
            ));
        }

        // Cache the HPKE info parameter: "tls ech" || 0x00 || ECHConfig.
        let mut hpke_info = Vec::with_capacity(128);
        hpke_info.extend_from_slice(b"tls ech\0");
        config.encode(&mut hpke_info);

        Ok(Self {
            config,
            contents,
            private_key: HpkePrivateKey::from(private_key_bytes),
            hpke_suites: matching_suites,
            is_retry_config: true,
            hpke_info,
        })
    }

    /// Set whether this config should be included in retry_configs on ECH rejection.
    ///
    /// Non-retry configs are still used for decryption but not sent to clients
    /// on rejection (useful for old keys being rotated out).
    pub fn with_retry(mut self, is_retry: bool) -> Self {
        self.is_retry_config = is_retry;
        self
    }

    pub(crate) fn config_id(&self) -> u8 {
        self.contents.key_config.config_id
    }
}

impl Debug for EchServerKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("EchServerKey")
            .field("config", &self.config)
            .field("private_key", &"[redacted]")
            .finish()
    }
}

// --- Decryption internals ---

/// A parsed outer ClientHello bundled with its raw wire encoding.
///
/// ECH decryption requires both the parsed structure and the raw bytes
/// (for AAD computation and inner hello reconstruction).
struct OuterClientHello<'a> {
    hello: &'a ClientHelloPayload,
    encoded: &'a [u8],
}

impl<'a> OuterClientHello<'a> {
    fn from_input(input: &'a Input<'a>) -> Result<Self, Error> {
        let hello = require_handshake_msg!(
            input.message,
            HandshakeType::ClientHello,
            HandshakePayload::ClientHello
        )?;

        // Invariant: we already matched a Handshake variant above.
        let encoded = match &input.message.payload {
            MessagePayload::Handshake { encoded, .. } => encoded.bytes(),
            _ => unreachable!("from_input called on non-Handshake message"),
        };

        Ok(Self { hello, encoded })
    }

    /// Attempt to decrypt ECH from this ClientHello using the key index.
    ///
    /// See <https://datatracker.ietf.org/doc/html/rfc9849#section-7.1>.
    fn decrypt_ech(&self, index: &EchKeyIndex) -> EchDecryptResult {
        let ech_ext = match &self.hello.encrypted_client_hello {
            Some(EncryptedClientHello::Outer(outer)) => outer,
            Some(EncryptedClientHello::Inner) => return EchDecryptResult::NotOffered,
            None => return EchDecryptResult::NotOffered,
        };

        if index.is_empty() {
            return EchDecryptResult::Rejected;
        }

        debug!(
            "ECH offer: config_id={}, cipher_suite={:?}",
            ech_ext.config_id, ech_ext.cipher_suite
        );

        let mut candidates = index
            .candidates(ech_ext.config_id, ech_ext.cipher_suite)
            .peekable();
        if candidates.peek().is_none() {
            return EchDecryptResult::Rejected;
        }

        let enc = EncapsulatedSecret(ech_ext.enc.bytes().to_vec());
        let aad = match self.compute_aad(ech_ext) {
            Ok(aad) => aad,
            Err(e) => return EchDecryptResult::Fatal(e),
        };

        for entry in candidates {
            let Ok(mut opener) =
                entry
                    .hpke_suite
                    .setup_opener(&enc, &entry.hpke_info, &entry.private_key)
            else {
                continue;
            };

            let Ok(encoded_inner) = opener.open(&aad, ech_ext.payload.bytes()) else {
                continue;
            };

            match self.decode_inner_hello(encoded_inner) {
                Ok(decrypted) => return EchDecryptResult::Accepted(decrypted, opener),
                Err(e) => return EchDecryptResult::Fatal(e),
            }
        }

        EchDecryptResult::Rejected
    }

    /// Decode an encoded inner hello and reconstruct the full inner
    /// ClientHello from this outer hello's wire encoding.
    ///
    /// Mirrors the client's `encode_inner_hello()`.
    ///
    /// See <https://datatracker.ietf.org/doc/html/rfc9849#section-5.1>.
    fn decode_inner_hello(&self, encoded_inner: Vec<u8>) -> Result<DecryptedEch, Error> {
        if encoded_inner.is_empty() {
            return Err(PeerMisbehaved::InvalidEchClientHelloInner.into());
        }

        let inner_hello_encoded = self.reconstruct_inner_bytes(&encoded_inner)?;

        // Parse the body after the 4-byte handshake header.
        let mut reader = Reader::new(&inner_hello_encoded[4..]);
        let inner_hello = ClientHelloPayload::read(&mut reader)
            .map_err(|_| -> Error { PeerMisbehaved::InvalidEchClientHelloInner.into() })?;

        // Per RFC 9849 section 7.1, the inner hello must include a well-formed
        // "encrypted_client_hello" extension of type inner.
        if !matches!(
            inner_hello.encrypted_client_hello,
            Some(EncryptedClientHello::Inner)
        ) {
            return Err(PeerMisbehaved::InvalidEchClientHelloInner.into());
        }

        // Per RFC 9849 section 7.1, the inner hello must not offer TLS 1.2 or below.
        // <https://datatracker.ietf.org/doc/html/rfc9849#section-7.1>
        match &inner_hello
            .extensions
            .supported_versions
        {
            Some(versions) if !versions.tls12 => {}
            _ => return Err(PeerMisbehaved::InvalidEchClientHelloInner.into()),
        }

        Ok(DecryptedEch {
            inner_hello,
            inner_hello_encoded,
        })
    }

    /// Construct the ClientHelloOuterAAD: the ClientHello body with the ECH
    /// payload replaced by zeros.
    ///
    /// See <https://datatracker.ietf.org/doc/html/rfc9849#section-5.2>.
    fn compute_aad(&self, ech_ext: &EncryptedClientHelloOuter) -> Result<Vec<u8>, Error> {
        // Skip the 4-byte handshake header to get the ClientHello body.
        let mut aad = self
            .encoded
            .get(4..)
            .ok_or(PeerMisbehaved::InvalidEchClientHelloInner)?
            .to_vec();
        let payload_len = ech_ext.payload.bytes().len();

        // Find the ECH extension payload and zero it.
        let fields =
            RawClientHello::parse(&aad).ok_or(PeerMisbehaved::InvalidEchClientHelloInner)?;
        let ech = fields
            .iter_extensions()
            .advance_to(u16::from(ExtensionType::EncryptedClientHello))
            .map_err(|_| PeerMisbehaved::MissingEchExtension)?;
        let data_end = fields.extensions_offset + ech.data_end;
        aad[data_end - payload_len..data_end].fill(0);

        Ok(aad)
    }

    /// Reconstruct the inner ClientHello as raw bytes by splicing extensions
    /// from this outer hello directly into the output buffer.
    ///
    /// Walks the inner extensions and expands any `ech_outer_extensions`
    /// references inline, copying the referenced extensions from the outer
    /// hello via a forward-only cursor.
    ///
    /// Duplicate extension detection is *not* done here -- it is handled by
    /// `ClientHelloPayload::read`'s `DuplicateExtensionChecker` when the
    /// reconstructed bytes are parsed. We only explicitly reject references
    /// to `encrypted_client_hello` (0xfe0d) and `ech_outer_extensions`
    /// (0xfd00), which the parser would not catch.
    ///
    /// See <https://datatracker.ietf.org/doc/html/rfc9849#section-5.1>.
    fn reconstruct_inner_bytes(&self, content: &[u8]) -> Result<Vec<u8>, Error> {
        let err = || -> Error { PeerMisbehaved::InvalidEchClientHelloInner.into() };
        let inner = RawClientHello::parse(content).ok_or_else(err)?;

        if !inner.session_id.is_empty() {
            return Err(err());
        }
        if !inner.trailing.iter().all(|&b| b == 0) {
            return Err(PeerMisbehaved::InvalidEchPadding.into());
        }

        // Include the handshake header: type(1) || length(3) || body.
        // The length is patched at the end.
        let mut out = Vec::with_capacity(self.encoded.len());
        out.extend_from_slice(&[u8::from(HandshakeType::ClientHello), 0, 0, 0]);
        out.extend_from_slice(inner.version_and_random);
        self.hello.session_id.encode(&mut out);
        out.extend_from_slice(&(inner.cipher_suites.len() as u16).to_be_bytes());
        out.extend_from_slice(inner.cipher_suites);
        out.push(inner.compression.len() as u8);
        out.extend_from_slice(inner.compression);

        // Walk inner extensions, expanding ech_outer_extensions references inline.
        let ext_len_pos = out.len();
        out.extend_from_slice(&[0, 0]); // placeholder

        let mut expanded_outer = false;
        for ext in inner.iter_extensions() {
            let ext = ext.map_err(|_| err())?;
            if ext.ext_type == u16::from(ExtensionType::EncryptedClientHelloOuterExtensions) {
                if expanded_outer {
                    return Err(err());
                }
                expanded_outer = true;
                self.expand_outer_extensions(ext.data, &mut out)?;
            } else {
                ext.write_to(&mut out);
            }
        }

        let ext_total_len = (out.len() - ext_len_pos - 2) as u16;
        out[ext_len_pos..ext_len_pos + 2].copy_from_slice(&ext_total_len.to_be_bytes());

        // Patch the handshake length (bytes 1..4).
        let body_len = (out.len() - 4) as u32;
        out[1..4].copy_from_slice(&body_len.to_be_bytes()[1..4]);
        Ok(out)
    }

    /// Expand an `ech_outer_extensions` reference list by copying the
    /// referenced extensions from this outer hello into `out`.
    ///
    /// We only explicitly reject references to `encrypted_client_hello`
    /// (0xfe0d) and `ech_outer_extensions` (0xfd00), which the parser
    /// would not catch.
    fn expand_outer_extensions(&self, ext_data: &[u8], out: &mut Vec<u8>) -> Result<(), Error> {
        let err = || -> Error { PeerMisbehaved::InvalidEchOuterExtension.into() };

        let outer_body = self.encoded.get(4..).ok_or_else(err)?;
        let outer_fields = RawClientHello::parse(outer_body).ok_or_else(err)?;
        let mut outer_iter = outer_fields.iter_extensions();

        let mut list_reader = Reader::new(ext_data);
        let list_len = u8::read(&mut list_reader).map_err(|_| err())? as usize;
        let list_data = list_reader
            .take(list_len)
            .ok_or_else(err)?;

        if list_len == 0 || list_reader.any_left() {
            return Err(err());
        }

        let mut type_reader = Reader::new(list_data);

        while type_reader.any_left() {
            let want = u16::read(&mut type_reader).map_err(|_| err())?;

            // Must not reference encrypted_client_hello or
            // ech_outer_extensions itself -- the parser wouldn't
            // catch these since they're valid extension types.
            if want == u16::from(ExtensionType::EncryptedClientHello)
                || want == u16::from(ExtensionType::EncryptedClientHelloOuterExtensions)
            {
                return Err(err());
            }

            outer_iter
                .advance_to(want)
                .map_err(|_| err())?
                .write_to(out);
        }

        Ok(())
    }
}

/// Result of attempting to decrypt an ECH offer.
enum EchDecryptResult {
    /// ECH was successfully decrypted.
    Accepted(DecryptedEch, Box<dyn HpkeOpener>),
    /// HPKE decryption succeeded but the inner ClientHello is malformed.
    /// This is fatal per RFC 9849 section 7.1.
    Fatal(Error),
    /// No ECH extension was present.
    NotOffered,
    /// ECH was offered but decryption failed.
    Rejected,
}

/// A successfully decrypted ECH inner ClientHello.
#[derive(Debug)]

struct DecryptedEch {
    inner_hello: ClientHelloPayload,
    inner_hello_encoded: Vec<u8>,
}

impl DecryptedEch {
    /// Consume `self` and build an [`Input`] wrapping the decrypted inner
    /// ClientHello, returning the inner random alongside it.
    fn into_input<'a>(self, outer_input: &Input<'a>) -> (Input<'a>, Random) {
        let random = self.inner_hello.random;
        let input = Input {
            message: Message {
                version: outer_input.message.version,
                payload: MessagePayload::Handshake {
                    encoded: Payload::Owned(self.inner_hello_encoded),
                    parsed: HandshakeMessagePayload(HandshakePayload::ClientHello(
                        self.inner_hello,
                    )),
                },
            },
            aligned_handshake: outer_input.aligned_handshake,
        };
        (input, random)
    }
}
// --- Key index ---

/// Pre-indexed ECH server keys for efficient lookup.
///
/// Built from a list of [`EchServerKey`]s, flattens the key x suite
/// combinations into a lookup table so that ECH decryption can jump
/// directly to matching candidates without scanning all keys.
///
/// Also pre-materializes retry configs for the rejection path.
pub(crate) struct EchKeyIndex {
    /// Whether any keys were provided.
    has_keys: bool,
    /// Entries grouped by config_id. Indexed by config_id, so
    /// `by_config_id[id]` gives the candidates for that id.
    /// Length is `max(config_id) + 1` (empty if no keys).
    by_config_id: Vec<Vec<EchKeyEntry>>,
    /// Pre-materialized retry configs for the rejection path.
    retry_configs: Vec<EchConfigPayload>,
}

impl EchKeyIndex {
    /// Build an index from a list of ECH server keys.
    pub(crate) fn new(keys: Vec<EchServerKey>) -> Self {
        let max_id = keys
            .iter()
            .map(|k| k.config_id() as usize)
            .max();
        let mut by_config_id: Vec<Vec<EchKeyEntry>> = (0..max_id.map_or(0, |m| m + 1))
            .map(|_| Vec::new())
            .collect();
        let retry_configs = keys
            .iter()
            .filter(|k| k.is_retry_config)
            .map(|k| k.config.clone())
            .collect();
        let has_keys = !keys.is_empty();
        for key in keys {
            let config_id = key.config_id() as usize;
            let private_key = Arc::new(key.private_key);
            for &cipher_suite in &key
                .contents
                .key_config
                .symmetric_cipher_suites
            {
                let expected = HpkeSuite {
                    kem: key.contents.key_config.kem_id,
                    sym: cipher_suite,
                };
                for &hpke_suite in &key.hpke_suites {
                    if hpke_suite.suite() == expected {
                        by_config_id[config_id].push(EchKeyEntry {
                            cipher_suite,
                            hpke_suite,
                            private_key: Arc::clone(&private_key),
                            hpke_info: key.hpke_info.clone(),
                        });
                    }
                }
            }
        }
        Self {
            has_keys,
            by_config_id,
            retry_configs,
        }
    }

    /// Whether this index has any keys.
    pub(crate) fn is_empty(&self) -> bool {
        !self.has_keys
    }

    /// Iterate over candidates matching the given config_id and cipher_suite.
    fn candidates(
        &self,
        config_id: u8,
        cipher_suite: HpkeSymmetricCipherSuite,
    ) -> impl Iterator<Item = &EchKeyEntry> {
        self.by_config_id
            .get(config_id as usize)
            .map(|v| v.as_slice())
            .unwrap_or_default()
            .iter()
            .filter(move |e| e.cipher_suite == cipher_suite)
    }

    /// The pre-materialized retry configs.
    pub(crate) fn retry_configs(&self) -> &[EchConfigPayload] {
        &self.retry_configs
    }
}

impl Debug for EchKeyIndex {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("EchKeyIndex")
            .field("has_keys", &self.has_keys)
            .field("num_config_ids", &self.by_config_id.len())
            .finish()
    }
}
struct EchKeyEntry {
    cipher_suite: HpkeSymmetricCipherSuite,
    hpke_suite: &'static dyn Hpke,
    private_key: Arc<HpkePrivateKey>,
    hpke_info: Vec<u8>,
}
#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;
    use crate::crypto::cipher::Payload;
    use crate::crypto::hpke::*;
    use crate::msgs::{SessionId, SizedPayload};

    #[test]
    fn hpke_info_starts_with_prefix() {
        let key = make_test_key(1);
        assert!(key.hpke_info.starts_with(b"tls ech\0"));
    }

    fn make_v18_contents(config_id: u8) -> crate::msgs::EchConfigContents {
        use pki_types::DnsName;

        crate::msgs::EchConfigContents {
            key_config: crate::msgs::HpkeKeyConfig {
                config_id,
                kem_id: HpkeKem::DHKEM_X25519_HKDF_SHA256,
                public_key: SizedPayload::from(Payload::new(vec![0u8; 32])),
                symmetric_cipher_suites: vec![HpkeSymmetricCipherSuite::default()],
            },
            maximum_name_length: 128,
            // Invariant: "example.com" is always a valid DNS name.
            public_name: DnsName::try_from("example.com")
                .unwrap()
                .to_owned(),
            extensions: Vec::new(),
        }
    }

    fn make_v18_config(config_id: u8) -> EchConfigPayload {
        EchConfigPayload::V18(make_v18_contents(config_id))
    }

    fn make_test_key(config_id: u8) -> EchServerKey {
        let contents = make_v18_contents(config_id);
        let config = EchConfigPayload::V18(contents.clone());
        let mut hpke_info = Vec::new();
        hpke_info.extend_from_slice(b"tls ech\0");
        config.encode(&mut hpke_info);
        EchServerKey {
            config,
            contents,
            private_key: HpkePrivateKey::from(vec![0u8; 32]),
            hpke_suites: vec![],
            is_retry_config: true,
            hpke_info,
        }
    }

    #[test]
    fn config_id_returns_id_for_v18() {
        assert_eq!(make_test_key(42).config_id(), 42);
    }

    #[test]
    fn with_retry_toggles_flag() {
        let key = make_test_key(1);
        assert!(key.is_retry_config);
        let key = key.with_retry(false);
        assert!(!key.is_retry_config);
    }

    #[test]
    fn from_raw_rejects_invalid_bytes() {
        let result = EchServerKey::from_raw(&[0xFF, 0x01], vec![0u8; 32], &[]);
        assert!(result.is_err());
    }

    #[test]
    fn from_raw_rejects_no_matching_suite() {
        let config = make_v18_config(1);
        let mut config_bytes = Vec::new();
        config.encode(&mut config_bytes);

        let result = EchServerKey::from_raw(&config_bytes, vec![0u8; 32], &[]);
        assert!(
            matches!(result, Err(Error::General(msg)) if msg.contains("no matching HPKE suite"))
        );
    }

    #[test]
    fn from_raw_rejects_trailing_data() {
        let config = make_v18_config(1);
        let mut config_bytes = Vec::new();
        config.encode(&mut config_bytes);
        config_bytes.push(0xFF); // trailing garbage

        let result = EchServerKey::from_raw(&config_bytes, vec![0u8; 32], &[]);
        assert!(matches!(result, Err(Error::General(msg)) if msg.contains("trailing data")));
    }

    #[test]
    fn key_index_precomputes_retry_configs() {
        let key1 = make_test_key(1);
        let key2 = make_test_key(2).with_retry(false);
        let key3 = make_test_key(3);
        let index = EchKeyIndex::new(vec![key1, key2, key3]);

        // Only keys 1 and 3 have is_retry_config=true
        assert_eq!(index.retry_configs().len(), 2);
    }

    fn make_hello(random: [u8; 32]) -> ClientHelloPayload {
        use alloc::boxed::Box;

        use crate::crypto::CipherSuite;
        use crate::enums::ProtocolVersion;
        use crate::msgs::{
            ClientExtensions, Compression, Random, SessionId, SupportedProtocolVersions,
        };

        ClientHelloPayload {
            client_version: ProtocolVersion::TLSv1_2,
            random: Random(random),
            session_id: SessionId::empty(),
            cipher_suites: vec![CipherSuite::TLS13_AES_128_GCM_SHA256],
            compression_methods: vec![Compression::Null],
            extensions: Box::new(ClientExtensions {
                supported_versions: Some(SupportedProtocolVersions {
                    tls13: true,
                    tls12: false,
                }),
                ..Default::default()
            }),
        }
    }

    fn make_outer<'a>(hello: &'a ClientHelloPayload, encoded: &'a [u8]) -> OuterClientHello<'a> {
        OuterClientHello { hello, encoded }
    }

    /// Build a minimal valid encoded handshake message with the given raw
    /// extensions, for use in tests that exercise `extensions_raw()`.
    fn make_encoded(extensions_raw: &[u8]) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.push(0x01); // HandshakeType::ClientHello
        let body_len = 2 + 32 + 1 + 4 + 2 + 2 + extensions_raw.len();
        buf.push(((body_len >> 16) & 0xff) as u8);
        buf.push(((body_len >> 8) & 0xff) as u8);
        buf.push((body_len & 0xff) as u8);
        buf.extend_from_slice(&[0x03, 0x03]); // version
        buf.extend_from_slice(&[0u8; 32]); // random
        buf.push(0); // session_id len
        buf.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]); // cipher suites
        buf.extend_from_slice(&[0x01, 0x00]); // compression
        buf.extend_from_slice(&(extensions_raw.len() as u16).to_be_bytes());
        buf.extend_from_slice(extensions_raw);
        buf
    }

    #[test]
    fn inner_hello_strips_padding() {
        let mut inner = make_hello([0x42u8; 32]);
        inner.encrypted_client_hello = Some(EncryptedClientHello::Inner);

        let mut encoded = inner.get_encoding();
        encoded.extend_from_slice(&[0u8; 31]);

        let mut outer = make_hello([0x11u8; 32]);
        let sid_bytes = {
            let mut b = vec![32u8];
            b.extend_from_slice(&[0xAB; 32]);
            b
        };
        // Invariant: a 32-byte session ID is always valid.
        outer.session_id = SessionId::read(&mut Reader::new(&sid_bytes)).unwrap();

        let outer_wrapper = make_outer(&outer, &[]);
        let decrypted = outer_wrapper
            .decode_inner_hello(encoded)
            .unwrap();

        assert_eq!(decrypted.inner_hello.session_id, outer.session_id);
        assert_eq!(decrypted.inner_hello.random.0, [0x42u8; 32]);
        assert!(matches!(
            decrypted
                .inner_hello
                .encrypted_client_hello,
            Some(EncryptedClientHello::Inner)
        ));
    }

    #[test]
    fn inner_hello_rejects_truly_empty() {
        let outer = make_hello([0x11u8; 32]);
        assert!(
            make_outer(&outer, &[])
                .decode_inner_hello(vec![])
                .is_err()
        );
    }

    #[test]
    fn inner_hello_rejects_garbage() {
        let outer = make_hello([0x11u8; 32]);
        assert!(
            make_outer(&outer, &[])
                .decode_inner_hello(vec![0u8; 32])
                .is_err()
        );
    }

    #[test]
    fn inner_hello_rejects_missing_marker() {
        let inner = make_hello([0x42u8; 32]);
        let encoded = inner.get_encoding();
        let outer = make_hello([0x11u8; 32]);
        assert!(
            make_outer(&outer, &[])
                .decode_inner_hello(encoded)
                .is_err()
        );
    }

    #[test]
    fn inner_hello_rejects_nonzero_padding() {
        let mut inner = make_hello([0x42u8; 32]);
        inner.encrypted_client_hello = Some(EncryptedClientHello::Inner);
        let mut encoded = inner.get_encoding();
        encoded.extend_from_slice(&[0x01; 4]);

        let outer = make_hello([0x11u8; 32]);
        let err = make_outer(&outer, &[])
            .decode_inner_hello(encoded)
            .unwrap_err();
        assert!(matches!(
            err,
            Error::PeerMisbehaved(PeerMisbehaved::InvalidEchPadding)
        ));
    }

    /// Build a raw extension: type(2) || length(2) || data
    fn raw_ext(ext_type: u16, data: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&ext_type.to_be_bytes());
        out.extend_from_slice(&(data.len() as u16).to_be_bytes());
        out.extend_from_slice(data);
        out
    }

    /// Build an ech_outer_extensions extension referencing the given types.
    fn outer_ext_ref(types: &[u16]) -> Vec<u8> {
        let list_len = (types.len() * 2) as u8;
        let mut data = vec![list_len];
        for &t in types {
            data.extend_from_slice(&t.to_be_bytes());
        }
        raw_ext(0xfd00, &data)
    }

    /// Build an encoded inner hello with extra raw extensions appended.
    /// Uses `make_hello` + `get_encoding()` to produce a valid base, then
    /// appends extra extensions and fixes the extensions length.
    fn make_inner_encoded(extra_extensions: &[u8]) -> Vec<u8> {
        let mut inner = make_hello([0x42u8; 32]);
        inner.encrypted_client_hello = Some(EncryptedClientHello::Inner);
        let mut encoded = inner.get_encoding();

        if !extra_extensions.is_empty() {
            let fields = RawClientHello::parse(&encoded).unwrap();
            let ext_len_pos = fields.extensions_offset - 2;
            let old_ext_len =
                u16::from_be_bytes([encoded[ext_len_pos], encoded[ext_len_pos + 1]]) as usize;
            let new_ext_len = old_ext_len + extra_extensions.len();
            encoded[ext_len_pos..ext_len_pos + 2]
                .copy_from_slice(&(new_ext_len as u16).to_be_bytes());
            encoded.extend_from_slice(extra_extensions);
        }

        encoded
    }

    /// Helper: attempt decode with given inner extensions and outer extensions.
    fn try_decode_with_extensions(
        inner_extra_exts: &[u8],
        outer_exts: &[u8],
    ) -> Result<DecryptedEch, Error> {
        let outer = make_hello([0; 32]);
        let encoded = make_encoded(outer_exts);
        let inner = make_inner_encoded(inner_extra_exts);
        make_outer(&outer, &encoded).decode_inner_hello(inner)
    }

    #[test]
    fn reconstruct_copies_outer_extension() {
        let result = try_decode_with_extensions(
            &outer_ext_ref(&[0xaaaa]),
            &raw_ext(0xaaaa, &[0xAA, 0xBB, 0xCC]),
        );
        assert!(result.is_ok(), "expected Ok, got {:?}", result.unwrap_err());
    }

    #[test]
    fn reconstruct_preserves_non_referenced() {
        let mut inner_exts = raw_ext(0xcccc, &[0x11]);
        inner_exts.extend_from_slice(&outer_ext_ref(&[0xaaaa]));

        let result = try_decode_with_extensions(&inner_exts, &raw_ext(0xaaaa, &[0xAA]));
        assert!(result.is_ok());
    }

    #[test]
    fn reconstruct_rejects_out_of_order() {
        let mut outer_exts = raw_ext(0xbbbb, &[0x01]);
        outer_exts.extend_from_slice(&raw_ext(0xaaaa, &[0x02]));

        // References 0xaaaa then 0xbbbb, but outer has them in reverse order
        assert!(
            try_decode_with_extensions(&outer_ext_ref(&[0xaaaa, 0xbbbb]), &outer_exts,).is_err()
        );
    }

    #[test]
    fn reconstruct_rejects_ech_reference() {
        assert!(
            try_decode_with_extensions(&outer_ext_ref(&[0xfe0d]), &raw_ext(0xfe0d, &[0x01]),)
                .is_err()
        );
    }

    #[test]
    fn reconstruct_rejects_self_reference() {
        assert!(
            try_decode_with_extensions(&outer_ext_ref(&[0xfd00]), &raw_ext(0xfd00, &[0x01]),)
                .is_err()
        );
    }

    #[test]
    fn reconstruct_rejects_duplicate_reference() {
        // Reference 0xaaaa twice; outer has two copies (itself invalid, but
        // the forward-only cursor catches the second seek failing).
        let mut outer_exts = raw_ext(0xaaaa, &[0xAA]);
        outer_exts.extend_from_slice(&raw_ext(0xaaaa, &[0xBB]));

        assert!(
            try_decode_with_extensions(&outer_ext_ref(&[0xaaaa, 0xaaaa]), &outer_exts,).is_err()
        );
    }

    #[test]
    fn reconstruct_rejects_inline_outer_overlap() {
        // Extension 0xaaaa appears both inline and via ech_outer_extensions.
        // The parser's DuplicateExtensionChecker catches this.
        let mut inner_exts = raw_ext(0xaaaa, &[0x11]);
        inner_exts.extend_from_slice(&outer_ext_ref(&[0xaaaa]));

        assert!(try_decode_with_extensions(&inner_exts, &raw_ext(0xaaaa, &[0xAA]),).is_err());
    }

    #[test]
    fn reconstruct_rejects_missing_outer() {
        assert!(
            try_decode_with_extensions(
                &outer_ext_ref(&[0xaaaa]),
                &[], // no outer extensions
            )
            .is_err()
        );
    }

    #[test]
    fn aad_zeros_ech_payload() {
        let ech_outer = EncryptedClientHelloOuter {
            cipher_suite: HpkeSymmetricCipherSuite::default(),
            config_id: 42,
            enc: SizedPayload::from(Payload::new(vec![1, 2, 3])),
            payload: SizedPayload::from(Payload::new(vec![0xAA; 32])),
        };

        let mut outer_hello = make_hello([0u8; 32]);
        outer_hello.encrypted_client_hello = Some(EncryptedClientHello::Outer(ech_outer.clone()));

        let hmp = HandshakeMessagePayload(HandshakePayload::ClientHello(outer_hello.clone()));
        let encoded = hmp.get_encoding();

        let aad = make_outer(&outer_hello, &encoded)
            .compute_aad(&ech_outer)
            .expect("compute_aad failed on valid ClientHello");

        assert!(!aad.is_empty());
        let has_aa_run = aad
            .windows(32)
            .any(|w| w.iter().all(|&b| b == 0xAA));
        assert!(!has_aa_run, "AAD should have zeroed ECH payload");

        let has_zero_run = aad
            .windows(32)
            .any(|w| w.iter().all(|&b| b == 0x00));
        assert!(has_zero_run, "AAD should contain zeroed payload");
    }

    #[test]
    fn not_offered() {
        let hello = make_hello([0u8; 32]);
        let index = EchKeyIndex::new(Vec::new());
        assert!(matches!(
            make_outer(&hello, &[]).decrypt_ech(&index),
            EchDecryptResult::NotOffered
        ));
    }

    #[test]
    fn rejected_no_keys() {
        let mut hello = make_hello([0u8; 32]);
        hello.encrypted_client_hello =
            Some(EncryptedClientHello::Outer(EncryptedClientHelloOuter {
                cipher_suite: HpkeSymmetricCipherSuite::default(),
                config_id: 1,
                enc: SizedPayload::from(Payload::new(vec![0u8; 32])),
                payload: SizedPayload::from(Payload::new(vec![0u8; 64])),
            }));

        let index = EchKeyIndex::new(Vec::new());
        assert!(matches!(
            make_outer(&hello, &[]).decrypt_ech(&index),
            EchDecryptResult::Rejected
        ));
    }

    #[test]
    fn rejected_config_id_mismatch() {
        let mut hello = make_hello([0u8; 32]);
        hello.encrypted_client_hello =
            Some(EncryptedClientHello::Outer(EncryptedClientHelloOuter {
                cipher_suite: HpkeSymmetricCipherSuite::default(),
                config_id: 99,
                enc: SizedPayload::from(Payload::new(vec![0u8; 32])),
                payload: SizedPayload::from(Payload::new(vec![0u8; 64])),
            }));

        let index = EchKeyIndex::new(vec![make_test_key(1)]);
        assert!(matches!(
            make_outer(&hello, &[]).decrypt_ech(&index),
            EchDecryptResult::Rejected
        ));
    }
}
