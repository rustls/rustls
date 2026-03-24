use alloc::vec::Vec;
use core::fmt::Debug;

use crate::crypto::hpke::{Hpke, HpkePrivateKey, HpkeSuite, HpkeSymmetricCipherSuite};
use crate::error::Error;
use crate::msgs::{Codec, EchConfigPayload, Reader};
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
    use crate::msgs::SizedPayload;

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
}
