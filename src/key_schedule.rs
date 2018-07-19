/// Key schedule maintenance for TLS1.3

use ring::{hmac, digest, hkdf};
use msgs::codec::Codec;
use error::TLSError;

/// The kinds of secret we can extract from `KeySchedule`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SecretKind {
    ResumptionPSKBinderKey,
    ClientEarlyTrafficSecret,
    ClientHandshakeTrafficSecret,
    ServerHandshakeTrafficSecret,
    ClientApplicationTrafficSecret,
    ServerApplicationTrafficSecret,
    ExporterMasterSecret,
    ResumptionMasterSecret,
    DerivedSecret,
}

impl SecretKind {
    fn to_bytes(&self) -> &'static [u8] {
        match *self {
            SecretKind::ResumptionPSKBinderKey => b"res binder",
            SecretKind::ClientEarlyTrafficSecret => b"c e traffic",
            SecretKind::ClientHandshakeTrafficSecret => b"c hs traffic",
            SecretKind::ServerHandshakeTrafficSecret => b"s hs traffic",
            SecretKind::ClientApplicationTrafficSecret => b"c ap traffic",
            SecretKind::ServerApplicationTrafficSecret => b"s ap traffic",
            SecretKind::ExporterMasterSecret => b"exp master",
            SecretKind::ResumptionMasterSecret => b"res master",
            SecretKind::DerivedSecret => b"derived",
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
    pub current_exporter_secret: Vec<u8>,
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
            hash,
            hash_of_empty_message: empty_hash,
            current_server_traffic_secret: Vec::new(),
            current_client_traffic_secret: Vec::new(),
            current_exporter_secret: Vec::new(),
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

        _hkdf_expand_label_vec(&self.current,
                               kind.to_bytes(),
                               hs_hash,
                               self.hash.output_len)
    }

    /// Return the current traffic secret, of given `kind`.
    fn current_traffic_secret(&self, kind: SecretKind) -> &[u8] {
        match kind {
            SecretKind::ServerHandshakeTrafficSecret |
            SecretKind::ServerApplicationTrafficSecret => &self.current_server_traffic_secret,
            SecretKind::ClientEarlyTrafficSecret |
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

        let hmac_key = _hkdf_expand_label_vec(&hmac::SigningKey::new(self.hash, base_key),
                                              b"finished",
                                              &[],
                                              self.hash.output_len);

        hmac::sign(&hmac::SigningKey::new(self.hash, &hmac_key), hs_hash)
            .as_ref()
            .to_vec()
    }

    /// Derive the next application traffic secret of given `kind`, returning
    /// it.
    pub fn derive_next(&self, kind: SecretKind) -> Vec<u8> {
        let base_key = self.current_traffic_secret(kind);
        _hkdf_expand_label_vec(&hmac::SigningKey::new(self.hash, base_key),
                               b"traffic upd",
                               &[],
                               self.hash.output_len)
    }

    /// Derive the PSK to use given a resumption_master_secret and
    /// ticket_nonce.
    pub fn derive_ticket_psk(&self, rms: &[u8], nonce: &[u8]) -> Vec<u8> {
        _hkdf_expand_label_vec(&hmac::SigningKey::new(self.hash, rms),
                               b"resumption",
                               nonce,
                               self.hash.output_len)
    }

    pub fn export_keying_material(&self, out: &mut [u8],
                                  label: &[u8],
                                  context: Option<&[u8]>) -> Result<(), TLSError> {
        if self.current_exporter_secret.is_empty() {
            return Err(TLSError::HandshakeNotComplete);
        }

        let h_empty = digest::digest(self.hash, &[]);
        let mut secret = [0u8; digest::MAX_OUTPUT_LEN];
        _hkdf_expand_label(&mut secret[..self.hash.output_len],
                           &hmac::SigningKey::new(self.hash,
                                                  &self.current_exporter_secret),
                           label,
                           h_empty.as_ref());

        let mut h_context = [0u8; digest::MAX_OUTPUT_LEN];
        h_context[..self.hash.output_len]
            .clone_from_slice(digest::digest(self.hash,
                                             context.unwrap_or(&[]))
                              .as_ref());

        _hkdf_expand_label(out,
                           &hmac::SigningKey::new(self.hash, &secret[..self.hash.output_len]),
                           b"exporter",
                           &h_context[..self.hash.output_len]);
        Ok(())
    }
}

fn _hkdf_expand_label_vec(secret: &hmac::SigningKey,
                          label: &[u8],
                          context: &[u8],
                          len: usize) -> Vec<u8> {
    let mut v = Vec::new();
    v.resize(len, 0u8);
    _hkdf_expand_label(&mut v,
                       secret,
                       label,
                       context);
    v
}

fn _hkdf_expand_label(output: &mut [u8],
                      secret: &hmac::SigningKey,
                      label: &[u8],
                      context: &[u8]) {
    let label_prefix = b"tls13 ";

    let mut hkdflabel = Vec::new();
    (output.len() as u16).encode(&mut hkdflabel);
    ((label.len() + label_prefix.len()) as u8).encode(&mut hkdflabel);
    hkdflabel.extend_from_slice(label_prefix);
    hkdflabel.extend_from_slice(label);
    (context.len() as u8).encode(&mut hkdflabel);
    hkdflabel.extend_from_slice(context);

    hkdf::expand(secret, &hkdflabel, output)
}

pub fn derive_traffic_key(hash: &'static digest::Algorithm, secret: &[u8], len: usize) -> Vec<u8> {
    _hkdf_expand_label_vec(&hmac::SigningKey::new(hash, secret), b"key", &[], len)
}

pub fn derive_traffic_iv(hash: &'static digest::Algorithm, secret: &[u8], len: usize) -> Vec<u8> {
    _hkdf_expand_label_vec(&hmac::SigningKey::new(hash, secret), b"iv", &[], len)
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
            0x61, 0x7b, 0x35, 0x07, 0x6b, 0x9d, 0x0e, 0x08, 0xcf, 0x73, 0x1d, 0x94, 0xa8,
            0x66, 0x14, 0x78, 0x41, 0x09, 0xef, 0x25, 0x55, 0x51, 0x92, 0x1d, 0xd4, 0x6e,
            0x04, 0x01, 0x35, 0xcf, 0x46, 0xab
        ];

        let client_hts_key = [
            0x62, 0xd0, 0xdd, 0x00, 0xf6, 0x96, 0x19, 0xd3, 0xb8, 0x19, 0x3a, 0xb4, 0xa0,
            0x95, 0x85, 0xa7
        ];

        let client_hts_iv = [
            0xff, 0xf7, 0x5d, 0xf5, 0xad, 0x35, 0xd5, 0xcb, 0x3c, 0x53, 0xf3, 0xa9
        ];

        let server_hts = [
            0xfc, 0xf7, 0xdf, 0xe6, 0x4f, 0xa2, 0xc0, 0x4f, 0x62, 0x35, 0x38, 0x7f, 0x43,
            0x4e, 0x01, 0x42, 0x23, 0x36, 0xd9, 0xc0, 0x39, 0xde, 0x68, 0x47, 0xa0, 0xb9,
            0xdd, 0xcf, 0x29, 0xa8, 0x87, 0x59
        ];

        let server_hts_key = [
            0x04, 0x67, 0xf3, 0x16, 0xa8, 0x05, 0xb8, 0xc4, 0x97, 0xee, 0x67, 0x04, 0x7b,
            0xbc, 0xbc, 0x54
        ];

        let server_hts_iv = [
            0xde, 0x83, 0xa7, 0x3e, 0x9d, 0x81, 0x4b, 0x04, 0xc4, 0x8b, 0x78, 0x09
        ];

        let client_ats = [
            0xc1, 0x4a, 0x6d, 0x79, 0x76, 0xd8, 0x10, 0x2b, 0x5a, 0x0c, 0x99, 0x51, 0x49,
            0x3f, 0xee, 0x87, 0xdc, 0xaf, 0xf8, 0x2c, 0x24, 0xca, 0xb2, 0x14, 0xe8, 0xbe,
            0x71, 0xa8, 0x20, 0x6d, 0xbd, 0xa5
        ];

        let client_ats_key = [
            0xcc, 0x9f, 0x5f, 0x98, 0x0b, 0x5f, 0x10, 0x30, 0x6c, 0xba, 0xd7, 0xbe, 0x98,
            0xd7, 0x57, 0x2e
        ];

        let client_ats_iv = [
            0xb8, 0x09, 0x29, 0xe8, 0xd0, 0x2c, 0x70, 0xf6, 0x11, 0x62, 0xed, 0x6b
        ];

        let server_ats = [
            0x2c, 0x90, 0x77, 0x38, 0xd3, 0xf8, 0x37, 0x02, 0xd1, 0xe4, 0x59, 0x8f, 0x48,
            0x48, 0x53, 0x1d, 0x9f, 0x93, 0x65, 0x49, 0x1b, 0x9f, 0x7f, 0x52, 0xc8, 0x22,
            0x29, 0x0d, 0x4c, 0x23, 0x21, 0x92
        ];

        let server_ats_key = [
            0x0c, 0xb2, 0x95, 0x62, 0xd8, 0xd8, 0x8f, 0x48, 0xb0, 0x2c, 0xbf, 0xbe, 0xd7,
            0xe6, 0x2b, 0xb3
        ];

        let server_ats_iv = [
            0x0d, 0xb2, 0x8f, 0x98, 0x85, 0x86, 0xa1, 0xb7, 0xe4, 0xd5, 0xc6, 0x9c
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
