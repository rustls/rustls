use crate::cipher::{MessageDecrypter, MessageEncrypter};
use crate::conn::ConnectionCommon;
use crate::conn::ConnectionRandoms;
use crate::kx;
use crate::msgs::codec::{Codec, Reader};
use crate::msgs::enums::{AlertDescription, ContentType};
use crate::suites::Tls12CipherSuite;
use crate::Error;

use ring::aead;
use ring::digest::Digest;

mod prf;

/// TLS1.2 per-connection keying material
pub(crate) struct ConnectionSecrets {
    pub(crate) randoms: ConnectionRandoms,
    suite: &'static Tls12CipherSuite,
    pub(crate) master_secret: [u8; 48],
}

impl ConnectionSecrets {
    pub(crate) fn new(
        randoms: &ConnectionRandoms,
        suite: &'static Tls12CipherSuite,
        pms: &[u8],
    ) -> Self {
        let mut ret = Self {
            randoms: randoms.clone(),
            suite,
            master_secret: [0u8; 48],
        };

        let randoms = join_randoms(&ret.randoms.client, &ret.randoms.server);
        prf::prf(
            &mut ret.master_secret,
            suite.hmac_algorithm,
            pms,
            b"master secret",
            &randoms,
        );
        ret
    }

    pub(crate) fn new_ems(
        randoms: &ConnectionRandoms,
        hs_hash: &Digest,
        suite: &'static Tls12CipherSuite,
        pms: &[u8],
    ) -> Self {
        let mut ret = Self {
            randoms: randoms.clone(),
            master_secret: [0u8; 48],
            suite,
        };

        prf::prf(
            &mut ret.master_secret,
            suite.hmac_algorithm,
            pms,
            b"extended master secret",
            hs_hash.as_ref(),
        );
        ret
    }

    pub(crate) fn new_resume(
        randoms: &ConnectionRandoms,
        suite: &'static Tls12CipherSuite,
        master_secret: &[u8],
    ) -> Self {
        let mut ret = Self {
            randoms: randoms.clone(),
            suite,
            master_secret: [0u8; 48],
        };
        ret.master_secret
            .copy_from_slice(master_secret);
        ret
    }


    /// Make a `MessageCipherPair` based on the given supported ciphersuite `scs`,
    /// and the session's `secrets`.
    pub(crate) fn make_cipher_pair(&self) -> MessageCipherPair {
        fn split_key<'a>(
            key_block: &'a [u8],
            alg: &'static aead::Algorithm,
        ) -> (aead::LessSafeKey, &'a [u8]) {
            // Might panic if the key block is too small.
            let (key, rest) = key_block.split_at(alg.key_len());
            // Won't panic because its only prerequisite is that `key` is `alg.key_len()` bytes long.
            let key = aead::UnboundKey::new(alg, key).unwrap();
            (aead::LessSafeKey::new(key), rest)
        }

        // Make a key block, and chop it up.
        // nb. we don't implement any ciphersuites with nonzero mac_key_len.
        let key_block = self.make_key_block();

        let suite = self.suite;
        let scs = &suite.common;

        let (client_write_key, key_block) = split_key(&key_block, scs.aead_algorithm);
        let (server_write_key, key_block) = split_key(key_block, scs.aead_algorithm);
        let (client_write_iv, key_block) = key_block.split_at(suite.fixed_iv_len);
        let (server_write_iv, extra) = key_block.split_at(suite.fixed_iv_len);

        let (write_key, write_iv, read_key, read_iv) = if self.randoms.we_are_client {
            (
                client_write_key,
                client_write_iv,
                server_write_key,
                server_write_iv,
            )
        } else {
            (
                server_write_key,
                server_write_iv,
                client_write_key,
                client_write_iv,
            )
        };

        (
            suite
                .aead_alg
                .decrypter(read_key, read_iv),
            suite
                .aead_alg
                .encrypter(write_key, write_iv, extra),
        )
    }

    fn make_key_block(&self) -> Vec<u8> {
        let suite = &self.suite;
        let common = &self.suite.common;

        let len =
            (common.aead_algorithm.key_len() + suite.fixed_iv_len) * 2 + suite.explicit_nonce_len;

        let mut out = Vec::new();
        out.resize(len, 0u8);

        // NOTE: opposite order to above for no good reason.
        // Don't design security protocols on drugs, kids.
        let randoms = join_randoms(&self.randoms.server, &self.randoms.client);
        prf::prf(
            &mut out,
            self.suite.hmac_algorithm,
            &self.master_secret,
            b"key expansion",
            &randoms,
        );

        out
    }

    pub(crate) fn suite(&self) -> &'static Tls12CipherSuite {
        self.suite
    }

    pub(crate) fn get_master_secret(&self) -> Vec<u8> {
        let mut ret = Vec::new();
        ret.extend_from_slice(&self.master_secret);
        ret
    }

    fn make_verify_data(&self, handshake_hash: &Digest, label: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.resize(12, 0u8);

        prf::prf(
            &mut out,
            self.suite.hmac_algorithm,
            &self.master_secret,
            label,
            handshake_hash.as_ref(),
        );
        out
    }

    pub(crate) fn client_verify_data(&self, handshake_hash: &Digest) -> Vec<u8> {
        self.make_verify_data(handshake_hash, b"client finished")
    }

    pub(crate) fn server_verify_data(&self, handshake_hash: &Digest) -> Vec<u8> {
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

        prf::prf(
            output,
            self.suite.hmac_algorithm,
            &self.master_secret,
            label,
            &randoms,
        )
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
    conn: &mut ConnectionCommon,
    kx_params: &[u8],
) -> Result<T, Error> {
    decode_ecdh_params_::<T>(kx_params).ok_or_else(|| {
        conn.send_fatal_alert(AlertDescription::DecodeError);
        Error::CorruptMessagePayload(ContentType::Handshake)
    })
}

fn decode_ecdh_params_<T: Codec>(kx_params: &[u8]) -> Option<T> {
    let mut rd = Reader::init(kx_params);
    let ecdh_params = T::read(&mut rd)?;
    match rd.any_left() {
        false => Some(ecdh_params),
        true => None,
    }
}

pub(crate) fn complete_ecdh(
    mine: kx::KeyExchange,
    peer_pub_key: &[u8],
) -> Result<kx::KeyExchangeResult, Error> {
    mine.complete(peer_pub_key)
        .ok_or_else(|| Error::PeerMisbehavedError("key agreement failed".to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::msgs::handshake::{ClientECDHParams, ServerECDHParams};

    #[test]
    fn server_ecdhe_remaining_bytes() {
        let key = kx::KeyExchange::start(&kx::X25519).unwrap();
        let server_params = ServerECDHParams::new(key.group(), key.pubkey.as_ref());
        let mut server_buf = Vec::new();
        server_params.encode(&mut server_buf);
        server_buf.push(34);
        assert!(decode_ecdh_params_::<ServerECDHParams>(&server_buf).is_none());
    }

    #[test]
    fn client_ecdhe_invalid() {
        assert!(decode_ecdh_params_::<ClientECDHParams>(&[34]).is_none());
    }
}
