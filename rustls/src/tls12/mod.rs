use crate::common_state::{CommonState2, Side};
use crate::conn::ConnectionRandoms;
use crate::crypto;
use crate::crypto::cipher::{AeadKey, MessageDecrypter, MessageEncrypter, Tls12AeadAlgorithm};
use crate::crypto::hash;
use crate::enums::{AlertDescription, SignatureScheme};
use crate::error::{Error, InvalidMessage};
use crate::msgs::codec::{Codec, Reader};
use crate::msgs::handshake::KeyExchangeAlgorithm;
use crate::suites::{CipherSuiteCommon, PartiallyExtractedSecrets, SupportedCipherSuite};

use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;
use core::fmt;

use zeroize::Zeroize;

/// A TLS 1.2 cipher suite supported by rustls.
pub struct Tls12CipherSuite {
    /// Common cipher suite fields.
    pub common: CipherSuiteCommon,

    /// How to compute the TLS1.2 PRF for the suite's hash function.
    pub prf_provider: &'static dyn crypto::tls12::Prf,

    /// How to exchange/agree keys.
    pub kx: KeyExchangeAlgorithm,

    /// How to sign messages for authentication.
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
            .cloned()
            .collect()
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
    pub(crate) master_secret: [u8; 48],
}

impl ConnectionSecrets {
    pub(crate) fn from_key_exchange(
        kx: Box<dyn crypto::ActiveKeyExchange>,
        peer_pub_key: &[u8],
        ems_seed: Option<hash::Output>,
        randoms: ConnectionRandoms,
        suite: &'static Tls12CipherSuite,
    ) -> Result<Self, Error> {
        let mut ret = Self {
            randoms,
            suite,
            master_secret: [0u8; 48],
        };

        let (label, seed) = match ems_seed {
            Some(seed) => ("extended master secret", Seed::Ems(seed)),
            None => (
                "master secret",
                Seed::Randoms(join_randoms(&ret.randoms.client, &ret.randoms.server)),
            ),
        };

        ret.suite
            .prf_provider
            .for_key_exchange(
                &mut ret.master_secret,
                kx,
                peer_pub_key,
                label.as_bytes(),
                seed.as_ref(),
            )?;

        Ok(ret)
    }

    pub(crate) fn new_resume(
        randoms: ConnectionRandoms,
        suite: &'static Tls12CipherSuite,
        master_secret: &[u8],
    ) -> Self {
        let mut ret = Self {
            randoms,
            suite,
            master_secret: [0u8; 48],
        };
        ret.master_secret
            .copy_from_slice(master_secret);
        ret
    }

    /// Make a `MessageCipherPair` based on the given supported ciphersuite `self.suite`,
    /// and the session's `secrets`.
    pub(crate) fn make_cipher_pair(&self, side: Side) -> MessageCipherPair {
        // Make a key block, and chop it up.
        // nb. we don't implement any ciphersuites with nonzero mac_key_len.
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

    fn make_key_block(&self) -> Vec<u8> {
        let shape = self.suite.aead_alg.key_block_shape();

        let len = (shape.enc_key_len + shape.fixed_iv_len) * 2 + shape.explicit_nonce_len;

        let mut out = vec![0u8; len];

        // NOTE: opposite order to above for no good reason.
        // Don't design security protocols on drugs, kids.
        let randoms = join_randoms(&self.randoms.server, &self.randoms.client);
        self.suite.prf_provider.for_secret(
            &mut out,
            &self.master_secret,
            b"key expansion",
            &randoms,
        );

        out
    }

    pub(crate) fn suite(&self) -> &'static Tls12CipherSuite {
        self.suite
    }

    pub(crate) fn master_secret(&self) -> &[u8] {
        &self.master_secret[..]
    }

    fn make_verify_data(&self, handshake_hash: &hash::Output, label: &[u8]) -> Vec<u8> {
        let mut out = vec![0u8; 12];

        self.suite.prf_provider.for_secret(
            &mut out,
            &self.master_secret,
            label,
            handshake_hash.as_ref(),
        );

        out
    }

    pub(crate) fn client_verify_data(&self, handshake_hash: &hash::Output) -> Vec<u8> {
        self.make_verify_data(handshake_hash, b"client finished")
    }

    pub(crate) fn server_verify_data(&self, handshake_hash: &hash::Output) -> Vec<u8> {
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

        self.suite
            .prf_provider
            .for_secret(output, &self.master_secret, label, &randoms);
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

impl Drop for ConnectionSecrets {
    fn drop(&mut self) {
        self.master_secret.zeroize();
    }
}

enum Seed {
    Ems(hash::Output),
    Randoms([u8; 64]),
}

impl AsRef<[u8]> for Seed {
    fn as_ref(&self) -> &[u8] {
        match self {
            Self::Ems(seed) => seed.as_ref(),
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

pub(crate) fn decode_ecdh_params<T: Codec>(
    common: &mut CommonState2,
    kx_params: &[u8],
) -> Result<T, Error> {
    let mut rd = Reader::init(kx_params);
    let ecdh_params = T::read(&mut rd)?;
    match rd.any_left() {
        false => Ok(ecdh_params),
        true => Err(common.send_fatal_alert(
            AlertDescription::DecodeError,
            InvalidMessage::InvalidDhParams,
        )),
    }
}

pub(crate) const DOWNGRADE_SENTINEL: [u8; 8] = [0x44, 0x4f, 0x57, 0x4e, 0x47, 0x52, 0x44, 0x01];

#[cfg(all(test, feature = "ring"))]
mod tests {
    use super::*;
    use crate::common_state::{CommonState, Side};
    use crate::crypto::ring::kx_group::X25519;
    use crate::msgs::handshake::{ClientEcdhParams, ServerEcdhParams};

    #[test]
    fn server_ecdhe_remaining_bytes() {
        let key = X25519.start().unwrap();
        let server_params = ServerEcdhParams::new(&*key);
        let mut server_buf = Vec::new();
        server_params.encode(&mut server_buf);
        server_buf.push(34);

        let mut common = CommonState::new(Side::Client);
        let mut common2 = CommonState2::Eager {
            common_state: &mut common,
        };
        assert!(decode_ecdh_params::<ServerEcdhParams>(&mut common2, &server_buf).is_err());
    }

    #[test]
    fn client_ecdhe_invalid() {
        let mut common = CommonState::new(Side::Server);
        let mut common2 = CommonState2::Eager {
            common_state: &mut common,
        };
        assert!(decode_ecdh_params::<ClientEcdhParams>(&mut common2, &[34]).is_err());
    }
}
