use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;
use core::fmt;

use zeroize::Zeroizing;

use crate::common_state::{CommonState, Protocol, Side};
use crate::conn::ConnectionRandoms;
use crate::crypto::cipher::{AeadKey, MessageDecrypter, MessageEncrypter, Tls12AeadAlgorithm};
use crate::crypto::hash;
use crate::enums::{AlertDescription, SignatureScheme};
use crate::error::{Error, InvalidMessage};
use crate::msgs::codec::{Codec, Reader};
use crate::msgs::handshake::{KeyExchangeAlgorithm, KxDecode};
use crate::suites::{CipherSuiteCommon, PartiallyExtractedSecrets, SupportedCipherSuite};
use crate::version::Tls12Version;
use crate::{SignatureAlgorithm, crypto};

/// A TLS 1.2 cipher suite supported by rustls.
#[allow(clippy::exhaustive_structs)]
pub struct Tls12CipherSuite {
    /// Common cipher suite fields.
    pub common: CipherSuiteCommon,

    /// The associated protocol version.
    ///
    /// This field should have the value [`rustls::version::TLS12_VERSION`].
    ///
    /// This value contains references to the TLS1.2 protocol handling code.
    /// This means that a program that does not contain any `Tls12CipherSuite`
    /// values also does not contain any reference to the TLS1.2 protocol handling
    /// code, and the linker can remove it.
    ///
    /// [`rustls::version::TLS12_VERSION`]: crate::version::TLS12_VERSION
    pub protocol_version: &'static Tls12Version,

    /// How to compute the TLS1.2 PRF for the suite's hash function.
    ///
    /// If you have a TLS1.2 PRF implementation, you should directly implement the [`crypto::tls12::Prf`] trait.
    ///
    /// If not, you can implement the [`crypto::hmac::Hmac`] trait (and associated), and then use
    /// [`crypto::tls12::PrfUsingHmac`].
    pub prf_provider: &'static dyn crypto::tls12::Prf,

    /// How to exchange/agree keys.
    ///
    /// In TLS1.2, the key exchange method (eg, Elliptic Curve Diffie-Hellman with Ephemeral keys -- ECDHE)
    /// is baked into the cipher suite, but the details to achieve it are negotiated separately.
    ///
    /// This controls how protocol messages (like the `ClientKeyExchange` message) are interpreted
    /// once this cipher suite has been negotiated.
    pub kx: KeyExchangeAlgorithm,

    /// How to sign messages for authentication.
    ///
    /// This is a set of [`SignatureScheme`]s that are usable once this cipher suite has been
    /// negotiated.
    ///
    /// The precise scheme used is then chosen from this set by the selected authentication key.
    pub sign: &'static [SignatureScheme],

    /// How to produce a [`MessageDecrypter`] or [`MessageEncrypter`]
    /// from raw key material.
    pub aead_alg: &'static dyn Tls12AeadAlgorithm,
}

impl Tls12CipherSuite {
    /// Resolve the set of supported [`SignatureScheme`]s from the
    /// offered signature schemes.  If we return an empty
    /// set, the handshake terminates.
    pub fn resolve_sig_schemes(&self, offered: &[SignatureScheme]) -> Vec<SignatureScheme> {
        self.sign
            .iter()
            .filter(|pref| offered.contains(pref))
            .copied()
            .collect()
    }

    /// Return `true` if this is backed by a FIPS-approved implementation.
    ///
    /// This means all the constituent parts that do cryptography return `true` for `fips()`.
    pub fn fips(&self) -> bool {
        self.common.fips() && self.prf_provider.fips() && self.aead_alg.fips()
    }

    /// Does this suite support the `proto` protocol?
    ///
    /// All TLS1.2 suites support TCP-TLS. No TLS1.2 suites support QUIC.
    pub(crate) fn usable_for_protocol(&self, proto: Protocol) -> bool {
        matches!(proto, Protocol::Tcp)
    }

    /// Return true if this suite is usable for a key only offering `sig_alg`
    /// signatures.
    pub(crate) fn usable_for_signature_algorithm(&self, sig_alg: SignatureAlgorithm) -> bool {
        self.sign
            .iter()
            .any(|scheme| scheme.algorithm() == sig_alg)
    }

    /// Say if the given `KeyExchangeAlgorithm` is supported by this cipher suite.
    pub(crate) fn usable_for_kx_algorithm(&self, kxa: KeyExchangeAlgorithm) -> bool {
        self.kx == kxa
    }
}

impl From<&'static Tls12CipherSuite> for SupportedCipherSuite {
    fn from(s: &'static Tls12CipherSuite) -> Self {
        Self::Tls12(s)
    }
}

impl PartialEq for Tls12CipherSuite {
    fn eq(&self, other: &Self) -> bool {
        self.common.suite == other.common.suite
    }
}

impl fmt::Debug for Tls12CipherSuite {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Tls12CipherSuite")
            .field("suite", &self.common.suite)
            .finish()
    }
}

/// TLS1.2 per-connection keying material
pub(crate) struct ConnectionSecrets {
    pub(crate) randoms: ConnectionRandoms,
    suite: &'static Tls12CipherSuite,
    master_secret: Zeroizing<[u8; 48]>,

    /// `master_secret` ready to be used as a TLS1.2 PRF secret.
    ///
    /// Zeroizing this on drop is left to the implementer of the trait.
    master_secret_prf: Box<dyn crypto::tls12::PrfSecret>,
}

impl ConnectionSecrets {
    pub(crate) fn from_key_exchange(
        kx: Box<dyn crypto::ActiveKeyExchange>,
        peer_pub_key: &[u8],
        ems_seed: Option<hash::Output>,
        randoms: ConnectionRandoms,
        suite: &'static Tls12CipherSuite,
    ) -> Result<Self, Error> {
        let (label, seed) = match ems_seed {
            Some(seed) => ("extended master secret", Seed::Ems(seed)),
            None => (
                "master secret",
                Seed::Randoms(join_randoms(&randoms.client, &randoms.server)),
            ),
        };

        // The API contract for for_key_exchange is that the caller guarantees `label` and `seed`
        // slice parameters are non-empty.
        // `label` is guaranteed non-empty because it's assigned from a `&str` above.
        // `seed.as_ref()` is guaranteed non-empty by documentation on the AsRef impl.
        let mut master_secret = [0u8; 48];
        suite.prf_provider.for_key_exchange(
            &mut master_secret,
            kx,
            peer_pub_key,
            label.as_bytes(),
            seed.as_ref(),
        )?;
        let master_secret = Zeroizing::new(master_secret);

        let master_secret_prf = suite
            .prf_provider
            .new_secret(&master_secret);

        Ok(Self {
            randoms,
            suite,
            master_secret,
            master_secret_prf,
        })
    }

    pub(crate) fn new_resume(
        randoms: ConnectionRandoms,
        suite: &'static Tls12CipherSuite,
        master_secret: &[u8; 48],
    ) -> Self {
        Self {
            randoms,
            suite,
            master_secret: Zeroizing::new(*master_secret),
            master_secret_prf: suite
                .prf_provider
                .new_secret(master_secret),
        }
    }

    /// Make a `MessageCipherPair` based on the given supported ciphersuite `self.suite`,
    /// and the session's `secrets`.
    pub(crate) fn make_cipher_pair(&self, side: Side) -> MessageCipherPair {
        // Make a key block, and chop it up.
        // Note: we don't implement any ciphersuites with nonzero mac_key_len.
        let key_block = self.make_key_block();
        let shape = self.suite.aead_alg.key_block_shape();

        let (client_write_key, key_block) = key_block.split_at(shape.enc_key_len);
        let (server_write_key, key_block) = key_block.split_at(shape.enc_key_len);
        let (client_write_iv, key_block) = key_block.split_at(shape.fixed_iv_len);
        let (server_write_iv, extra) = key_block.split_at(shape.fixed_iv_len);

        let (write_key, write_iv, read_key, read_iv) = match side {
            Side::Client => (
                client_write_key,
                client_write_iv,
                server_write_key,
                server_write_iv,
            ),
            Side::Server => (
                server_write_key,
                server_write_iv,
                client_write_key,
                client_write_iv,
            ),
        };

        (
            self.suite
                .aead_alg
                .decrypter(AeadKey::new(read_key), read_iv),
            self.suite
                .aead_alg
                .encrypter(AeadKey::new(write_key), write_iv, extra),
        )
    }

    fn make_key_block(&self) -> Zeroizing<Vec<u8>> {
        let shape = self.suite.aead_alg.key_block_shape();

        let len = (shape.enc_key_len + shape.fixed_iv_len) * 2 + shape.explicit_nonce_len;

        let mut out = vec![0u8; len];

        // NOTE: opposite order to above for no good reason.
        // Don't design security protocols on drugs, kids.
        let randoms = join_randoms(&self.randoms.server, &self.randoms.client);
        self.master_secret_prf
            .prf(&mut out, b"key expansion", &randoms);

        Zeroizing::new(out)
    }

    pub(crate) fn suite(&self) -> &'static Tls12CipherSuite {
        self.suite
    }

    pub(crate) fn master_secret(&self) -> &[u8; 48] {
        &self.master_secret
    }

    fn make_verify_data(&self, handshake_hash: &hash::Output, label: &[u8]) -> [u8; 12] {
        let mut out = [0u8; 12];
        self.master_secret_prf
            .prf(&mut out, label, handshake_hash.as_ref());
        out
    }

    pub(crate) fn client_verify_data(&self, handshake_hash: &hash::Output) -> [u8; 12] {
        self.make_verify_data(handshake_hash, b"client finished")
    }

    pub(crate) fn server_verify_data(&self, handshake_hash: &hash::Output) -> [u8; 12] {
        self.make_verify_data(handshake_hash, b"server finished")
    }

    pub(crate) fn export_keying_material(
        &self,
        output: &mut [u8],
        label: &[u8],
        context: Option<&[u8]>,
    ) {
        let mut randoms = Vec::new();
        randoms.extend_from_slice(&self.randoms.client);
        randoms.extend_from_slice(&self.randoms.server);
        if let Some(context) = context {
            assert!(context.len() <= 0xffff);
            (context.len() as u16).encode(&mut randoms);
            randoms.extend_from_slice(context);
        }

        self.master_secret_prf
            .prf(output, label, &randoms);
    }

    pub(crate) fn extract_secrets(&self, side: Side) -> Result<PartiallyExtractedSecrets, Error> {
        // Make a key block, and chop it up
        let key_block = self.make_key_block();
        let shape = self.suite.aead_alg.key_block_shape();

        let (client_key, key_block) = key_block.split_at(shape.enc_key_len);
        let (server_key, key_block) = key_block.split_at(shape.enc_key_len);
        let (client_iv, key_block) = key_block.split_at(shape.fixed_iv_len);
        let (server_iv, explicit_nonce) = key_block.split_at(shape.fixed_iv_len);

        let client_secrets = self.suite.aead_alg.extract_keys(
            AeadKey::new(client_key),
            client_iv,
            explicit_nonce,
        )?;
        let server_secrets = self.suite.aead_alg.extract_keys(
            AeadKey::new(server_key),
            server_iv,
            explicit_nonce,
        )?;

        let (tx, rx) = match side {
            Side::Client => (client_secrets, server_secrets),
            Side::Server => (server_secrets, client_secrets),
        };
        Ok(PartiallyExtractedSecrets { tx, rx })
    }
}

enum Seed {
    Ems(hash::Output),
    Randoms([u8; 64]),
}

impl AsRef<[u8]> for Seed {
    /// This is guaranteed to return a non-empty slice.
    fn as_ref(&self) -> &[u8] {
        match self {
            // seed is a hash::Output, which is a fixed, non-zero length array.
            Self::Ems(seed) => seed.as_ref(),
            // randoms is a fixed, non-zero length array.
            Self::Randoms(randoms) => randoms.as_ref(),
        }
    }
}

fn join_randoms(first: &[u8; 32], second: &[u8; 32]) -> [u8; 64] {
    let mut randoms = [0u8; 64];
    randoms[..32].copy_from_slice(first);
    randoms[32..].copy_from_slice(second);
    randoms
}

type MessageCipherPair = (Box<dyn MessageDecrypter>, Box<dyn MessageEncrypter>);

pub(crate) fn decode_kx_params<'a, T: KxDecode<'a>>(
    kx_algorithm: KeyExchangeAlgorithm,
    common: &mut CommonState,
    kx_params: &'a [u8],
) -> Result<T, Error> {
    let mut rd = Reader::init(kx_params);
    let kx_params = T::decode(&mut rd, kx_algorithm)?;
    match rd.any_left() {
        false => Ok(kx_params),
        true => Err(common.send_fatal_alert(
            AlertDescription::DecodeError,
            InvalidMessage::InvalidDhParams,
        )),
    }
}

pub(crate) const DOWNGRADE_SENTINEL: [u8; 8] = [0x44, 0x4f, 0x57, 0x4e, 0x47, 0x52, 0x44, 0x01];

#[cfg(test)]
#[macro_rules_attribute::apply(test_for_each_provider)]
mod tests {
    use super::provider::kx_group::X25519;
    use super::*;
    use crate::common_state::{CommonState, Side};
    use crate::msgs::handshake::{ServerEcdhParams, ServerKeyExchangeParams};

    #[test]
    fn server_ecdhe_remaining_bytes() {
        let key = X25519.start().unwrap();
        let server_params = ServerEcdhParams::new(&*key);
        let mut server_buf = Vec::new();
        server_params.encode(&mut server_buf);
        server_buf.push(34);

        let mut common = CommonState::new(Side::Client);
        assert!(
            decode_kx_params::<ServerKeyExchangeParams>(
                KeyExchangeAlgorithm::ECDHE,
                &mut common,
                &server_buf
            )
            .is_err()
        );
    }

    #[test]
    fn client_ecdhe_invalid() {
        let mut common = CommonState::new(Side::Server);
        assert!(
            decode_kx_params::<ServerKeyExchangeParams>(
                KeyExchangeAlgorithm::ECDHE,
                &mut common,
                &[34],
            )
            .is_err()
        );
    }
}
