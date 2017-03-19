/// Key schedule mainteance for TLS1.3

use ring::{hmac, digest, hkdf};
use msgs::codec;

/// The kinds of secret we can extract from `KeySchedule`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SecretKind {
    ResumptionPSKBinderKey,
    ClientHandshakeTrafficSecret,
    ServerHandshakeTrafficSecret,
    ClientApplicationTrafficSecret,
    ServerApplicationTrafficSecret,
    ResumptionMasterSecret,
    DerivedSecret,
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
            SecretKind::DerivedSecret => b"derived secret",
        }
    }
}

/// This is the TLS1.3 key schedule.  It stores the current secret,
/// the type of hash, plus the two current traffic keys which form their
/// own lineage of keys over successive key updates.
pub struct KeySchedule {
    current: hmac::SigningKey,
    need_derive_for_extract: bool,
    hash: &'static digest::Algorithm,
    hash_of_empty_message: [u8; digest::MAX_OUTPUT_LEN],
    pub current_client_traffic_secret: Vec<u8>,
    pub current_server_traffic_secret: Vec<u8>,
}

impl KeySchedule {
    pub fn new(hash: &'static digest::Algorithm) -> KeySchedule {
        let zeroes = [0u8; digest::MAX_OUTPUT_LEN];

        let mut empty_hash = [0u8; digest::MAX_OUTPUT_LEN];
        empty_hash[..hash.output_len]
            .clone_from_slice(digest::digest(hash, &[]).as_ref());

        KeySchedule {
            current: hmac::SigningKey::new(hash, &zeroes[..hash.output_len]),
            need_derive_for_extract: false,
            hash: hash,
            hash_of_empty_message: empty_hash,
            current_server_traffic_secret: Vec::new(),
            current_client_traffic_secret: Vec::new(),
        }
    }

    pub fn get_hash_of_empty_message(&self) -> &[u8] {
        &self.hash_of_empty_message[..self.hash.output_len]
    }

    /// Input the empty secret.
    pub fn input_empty(&mut self) {
        let zeroes = [0u8; digest::MAX_OUTPUT_LEN];
        let hash_len = self.hash.output_len;
        self.input_secret(&zeroes[..hash_len]);
    }

    /// Input the given secret.
    pub fn input_secret(&mut self, secret: &[u8]) {
        if self.need_derive_for_extract {
            let derived = self.derive(SecretKind::DerivedSecret,
                                      self.get_hash_of_empty_message());
            self.current = hmac::SigningKey::new(self.hash, &derived);
        }
        self.need_derive_for_extract = true;
        let new = hkdf::extract(&self.current, secret);
        self.current = new
    }

    /// Derive a secret of given `kind`, using current handshake hash `hs_hash`.
    pub fn derive(&self, kind: SecretKind, hs_hash: &[u8]) -> Vec<u8> {
        debug_assert_eq!(hs_hash.len(), self.hash.output_len);

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
        self.sign_verify_data(base_key, hs_hash)
    }

    /// Sign the finished message consisting of `hs_hash` using the key material
    /// `base_key`.
    pub fn sign_verify_data(&self, base_key: &[u8], hs_hash: &[u8]) -> Vec<u8> {
        debug_assert_eq!(hs_hash.len(), self.hash.output_len);

        let hmac_key = _hkdf_expand_label(&hmac::SigningKey::new(self.hash, base_key),
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
        _hkdf_expand_label(&hmac::SigningKey::new(self.hash, base_key),
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
    hkdflabel.extend_from_slice(context);

    hkdf::expand(secret, &hkdflabel, &mut out);
    out
}

pub fn derive_traffic_key(hash: &'static digest::Algorithm, secret: &[u8], len: usize) -> Vec<u8> {
    _hkdf_expand_label(&hmac::SigningKey::new(hash, secret), b"key", &[], len as u16)
}

pub fn derive_traffic_iv(hash: &'static digest::Algorithm, secret: &[u8], len: usize) -> Vec<u8> {
    _hkdf_expand_label(&hmac::SigningKey::new(hash, secret), b"iv", &[], len as u16)
}

#[cfg(test)]
mod test {
    use super::{KeySchedule, SecretKind, derive_traffic_key, derive_traffic_iv};
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

    #[test]
    fn test_vectors() {
        /* These test vectors generated with OpenSSL. */
        let hs_start_hash = [
            0xec, 0x14, 0x7a, 0x06, 0xde, 0xa3, 0xc8, 0x84, 0x6c, 0x02, 0xb2, 0x23, 0x8e,
            0x41, 0xbd, 0xdc, 0x9d, 0x89, 0xf9, 0xae, 0xa1, 0x7b, 0x5e, 0xfd, 0x4d, 0x74,
            0x82, 0xaf, 0x75, 0x88, 0x1c, 0x0a
        ];

        let hs_full_hash = [
            0x75, 0x1a, 0x3d, 0x4a, 0x14, 0xdf, 0xab, 0xeb, 0x68, 0xe9, 0x2c, 0xa5, 0x91,
            0x8e, 0x24, 0x08, 0xb9, 0xbc, 0xb0, 0x74, 0x89, 0x82, 0xec, 0x9c, 0x32, 0x30,
            0xac, 0x30, 0xbb, 0xeb, 0x23, 0xe2
        ];

        let ecdhe_secret = [
            0xe7, 0xb8, 0xfe, 0xf8, 0x90, 0x3b, 0x52, 0x0c, 0xb9, 0xa1, 0x89, 0x71, 0xb6,
            0x9d, 0xd4, 0x5d, 0xca, 0x53, 0xce, 0x2f, 0x12, 0xbf, 0x3b, 0xef, 0x93, 0x15,
            0xe3, 0x12, 0x71, 0xdf, 0x4b, 0x40
        ];

        let client_hts = [
            0xd7, 0x58, 0x9f, 0x10, 0xa8, 0x30, 0xf3, 0x85, 0x63, 0x6f, 0xd9, 0xb0, 0x61,
            0xd5, 0x20, 0x19, 0xb1, 0x45, 0x96, 0x82, 0x24, 0x8e, 0x36, 0x45, 0xf7, 0x5a,
            0xd7, 0x2f, 0x31, 0xec, 0x57, 0xf7
        ];

        let client_hts_key = [
            0xcc, 0x8b, 0xda, 0xbf, 0x83, 0x74, 0x2d, 0xf4, 0x53, 0x44, 0xff, 0xbc, 0xa4,
            0x43, 0xc8, 0x2a
        ];

        let client_hts_iv = [
            0xa4, 0x83, 0x46, 0x11, 0xc2, 0x78, 0xea, 0x0f, 0x94, 0x52, 0x1d, 0xca
        ];

        let server_hts = [
            0xba, 0x7c, 0x3b, 0x74, 0x0d, 0x1e, 0x84, 0x82, 0xd6, 0x6f, 0x3e, 0x5e, 0x1d,
            0x6e, 0x25, 0xdc, 0x87, 0x1f, 0x48, 0x74, 0x2f, 0x65, 0xa4, 0x40, 0x39, 0xda,
            0xdc, 0x02, 0x2a, 0x16, 0x19, 0x5c
        ];

        let server_hts_key = [
            0x7d, 0x22, 0x2a, 0x3f, 0x72, 0x37, 0x92, 0xd9, 0x95, 0x9a, 0xe1, 0x66, 0x32,
            0x6f, 0x0d, 0xc9
        ];

        let server_hts_iv = [
            0xa2, 0x73, 0xcd, 0x4e, 0x20, 0xe7, 0xe1, 0xe3, 0xcb, 0x0e, 0x18, 0x9e
        ];

        let client_ats = [
            0xc3, 0x60, 0x5f, 0xb3, 0xc4, 0x4b, 0xc2, 0x25, 0xd2, 0xaf, 0x36, 0xad, 0x99,
            0xa1, 0xcd, 0xcf, 0x71, 0xc4, 0xb9, 0xa2, 0x3d, 0xd2, 0x3e, 0xe6, 0xff, 0xca,
            0x2c, 0x71, 0x86, 0x3d, 0x1f, 0x85
        ];

        let client_ats_key = [
            0x3a, 0x25, 0x23, 0x12, 0xde, 0x0f, 0x53, 0xc7, 0xa0, 0xb2, 0xcf, 0x71, 0xb7,
            0x1a, 0x0d, 0xc7
        ];

        let client_ats_iv = [
            0xbd, 0x0d, 0x3c, 0x26, 0x9d, 0x2d, 0xa6, 0x52, 0x1b, 0x8d, 0x45, 0xef
        ];

        let server_ats = [
            0x27, 0x8d, 0x96, 0x76, 0x95, 0x9e, 0x3e, 0x39, 0xa4, 0xa9, 0xfc, 0x46, 0x9c,
            0x32, 0x9f, 0xe0, 0x29, 0x50, 0x22, 0x45, 0x39, 0x82, 0xdd, 0x1c, 0xc5, 0xfb,
            0xa9, 0x0a, 0x68, 0x29, 0x4e, 0x80
        ];

        let server_ats_key = [
            0x78, 0xbd, 0xd7, 0xc6, 0xb0, 0xf1, 0x50, 0x5e, 0xae, 0x54, 0xff, 0xa5, 0xf2,
            0xed, 0x0b, 0x77
        ];

        let server_ats_iv = [
            0xb1, 0x7b, 0x1c, 0xa2, 0xca, 0xbe, 0xe4, 0xac, 0xb5, 0xf3, 0x91, 0x7e
        ];

        let hash = &digest::SHA256;
        let mut ks = KeySchedule::new(hash);
        ks.input_empty();
        ks.input_secret(&ecdhe_secret);

        let got_client_hts = ks.derive(SecretKind::ClientHandshakeTrafficSecret,
                                       &hs_start_hash);
        assert_eq!(got_client_hts,
                   client_hts.to_vec());
        assert_eq!(derive_traffic_key(hash, &got_client_hts, client_hts_key.len()),
                   client_hts_key.to_vec());
        assert_eq!(derive_traffic_iv(hash, &got_client_hts, client_hts_iv.len()),
                   client_hts_iv.to_vec());

        let got_server_hts = ks.derive(SecretKind::ServerHandshakeTrafficSecret,
                                       &hs_start_hash);
        assert_eq!(got_server_hts,
                   server_hts.to_vec());
        assert_eq!(derive_traffic_key(hash, &got_server_hts, server_hts_key.len()),
                   server_hts_key.to_vec());
        assert_eq!(derive_traffic_iv(hash, &got_server_hts, server_hts_iv.len()),
                   server_hts_iv.to_vec());

        ks.input_empty();

        let got_client_ats = ks.derive(SecretKind::ClientApplicationTrafficSecret,
                                       &hs_full_hash);
        assert_eq!(got_client_ats,
                   client_ats.to_vec());
        assert_eq!(derive_traffic_key(hash, &got_client_ats, client_ats_key.len()),
                   client_ats_key.to_vec());
        assert_eq!(derive_traffic_iv(hash, &got_client_ats, client_ats_iv.len()),
                   client_ats_iv.to_vec());

        let got_server_ats = ks.derive(SecretKind::ServerApplicationTrafficSecret,
                                       &hs_full_hash);
        assert_eq!(got_server_ats,
                   server_ats.to_vec());
        assert_eq!(derive_traffic_key(hash, &got_server_ats, server_ats_key.len()),
                   server_ats_key.to_vec());
        assert_eq!(derive_traffic_iv(hash, &got_server_ats, server_ats_iv.len()),
                   server_ats_iv.to_vec());

    }
}
