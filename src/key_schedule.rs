/// Key schedule mainteance for TLS1.3

use ring::{hmac, digest, hkdf};
use msgs::codec;

/// The kinds of secret we can extract from KeySchedule.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SecretKind {
    ResumptionPSKBinderKey,
    ClientHandshakeTrafficSecret,
    ServerHandshakeTrafficSecret,
    ClientApplicationTrafficSecret,
    ServerApplicationTrafficSecret,
    ResumptionMasterSecret,
}

impl SecretKind {
    fn to_bytes(&self) -> &'static [u8] {
        match *self {
            SecretKind::ResumptionPSKBinderKey => b"resumption psk binder key",
            SecretKind::ClientHandshakeTrafficSecret => b"client handshake traffic secret",
            SecretKind::ServerHandshakeTrafficSecret => b"server handshake traffic secret",
            SecretKind::ClientApplicationTrafficSecret => b"client application traffic secret",
            SecretKind::ServerApplicationTrafficSecret => b"server application traffic secret",
            SecretKind::ResumptionMasterSecret => b"resumption master secret",
        }
    }
}

/// This is the TLS1.3 key schedule.  It stores the current secret,
/// the type of hash, plus the two current traffic keys which form their
/// own lineage of keys over successive key updates.
pub struct KeySchedule {
    current: hmac::SigningKey,
    hash: &'static digest::Algorithm,
    pub current_client_traffic_secret: Vec<u8>,
    pub current_server_traffic_secret: Vec<u8>,
}

impl KeySchedule {
    pub fn new(hash: &'static digest::Algorithm) -> KeySchedule {
        let zeroes = [0u8; digest::MAX_OUTPUT_LEN];
        KeySchedule {
            current: hmac::SigningKey::new(hash, &zeroes[..hash.output_len]),
            hash: hash,
            current_server_traffic_secret: Vec::new(),
            current_client_traffic_secret: Vec::new(),
        }
    }

    /// Input the empty secret.
    pub fn input_empty(&mut self) {
        let zeroes = [0u8; digest::MAX_OUTPUT_LEN];
        let hash_len = self.hash.output_len;
        self.input_secret(&zeroes[..hash_len]);
    }

    /// Input the given secret.
    pub fn input_secret(&mut self, secret: &[u8]) {
        let new = hkdf::extract(&self.current, secret);
        self.current = new
    }

    /// Derive a secret of given `kind`, using current handshake hash `hs_hash`.
    pub fn derive(&self, kind: SecretKind, hs_hash: &[u8]) -> Vec<u8> {
        debug_assert!(hs_hash.len() == self.hash.output_len);

        _hkdf_expand_label(&self.current,
                           kind.to_bytes(),
                           hs_hash,
                           self.hash.output_len as u16)
    }

    /// Return the current traffic secret, of given `kind`.
    fn current_traffic_secret(&self, kind: SecretKind) -> &[u8] {
        match kind {
            SecretKind::ServerHandshakeTrafficSecret |
            SecretKind::ServerApplicationTrafficSecret => &self.current_server_traffic_secret,
            SecretKind::ClientHandshakeTrafficSecret |
            SecretKind::ClientApplicationTrafficSecret => &self.current_client_traffic_secret,
            _ => unreachable!(),
        }
    }

    /// Sign the finished message consisting of `hs_hash` using the current
    /// traffic secret.
    pub fn sign_finish(&self, kind: SecretKind, hs_hash: &[u8]) -> Vec<u8> {
        let base_key = self.current_traffic_secret(kind);
        self.sign_verify_data(&base_key, hs_hash)
    }

    /// Sign the finished message consisting of `hs_hash` using the key material
    /// `base_key`.
    pub fn sign_verify_data(&self, base_key: &[u8], hs_hash: &[u8]) -> Vec<u8> {
        debug_assert!(hs_hash.len() == self.hash.output_len);

        let hmac_key = hkdf_expand_label(self.hash,
                                         &base_key,
                                         b"finished",
                                         &[],
                                         self.hash.output_len as u16);

        hmac::sign(&hmac::SigningKey::new(self.hash, &hmac_key), hs_hash)
            .as_ref()
            .to_vec()
    }

    /// Derive the next application traffic secret of given `kind`, returning
    /// it.
    pub fn derive_next(&self, kind: SecretKind) -> Vec<u8> {
        let base_key = self.current_traffic_secret(kind);
        hkdf_expand_label(self.hash,
                          &base_key,
                          b"application traffic secret",
                          &[],
                          self.hash.output_len as u16)
    }
}

fn _hkdf_expand_label(secret: &hmac::SigningKey,
                      label: &[u8],
                      context: &[u8],
                      len: u16)
                      -> Vec<u8> {
    let mut out = Vec::new();
    out.resize(len as usize, 0u8);

    let label_prefix = b"TLS 1.3, ";

    let mut hkdflabel = Vec::new();
    codec::encode_u16(out.len() as u16, &mut hkdflabel);
    codec::encode_u8((label.len() + label_prefix.len()) as u8, &mut hkdflabel);
    hkdflabel.extend_from_slice(label_prefix);
    hkdflabel.extend_from_slice(label);
    codec::encode_u8(context.len() as u8, &mut hkdflabel);
    hkdflabel.extend_from_slice(&context);

    hkdf::expand(secret, &hkdflabel, &mut out);
    out
}

pub fn hkdf_expand_label(hash: &'static digest::Algorithm,
                         secret: &[u8],
                         label: &[u8],
                         context: &[u8],
                         len: u16)
                         -> Vec<u8> {
    _hkdf_expand_label(&hmac::SigningKey::new(hash, secret), label, context, len)
}

#[cfg(test)]
mod test {
    use super::{KeySchedule, SecretKind};
    use ring::digest;

    #[test]
    fn smoke_test() {
        let fake_handshake_hash = [0u8; 32];

        let mut ks = KeySchedule::new(&digest::SHA256);
        ks.input_empty(); // no PSK
        ks.derive(SecretKind::ResumptionPSKBinderKey, &fake_handshake_hash);
        ks.input_secret(&[1u8, 2u8, 3u8, 4u8]);
        ks.derive(SecretKind::ClientHandshakeTrafficSecret,
                  &fake_handshake_hash);
        ks.derive(SecretKind::ServerHandshakeTrafficSecret,
                  &fake_handshake_hash);
        ks.input_empty();
        ks.derive(SecretKind::ClientApplicationTrafficSecret,
                  &fake_handshake_hash);
        ks.derive(SecretKind::ServerApplicationTrafficSecret,
                  &fake_handshake_hash);
        ks.derive(SecretKind::ResumptionMasterSecret, &fake_handshake_hash);
    }
}
