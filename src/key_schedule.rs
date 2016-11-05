/// Key schedule mainteance for TLS1.3

use ring::{hmac, digest, hkdf};
use msgs::codec;

#[derive(Debug, Clone, Copy)]
pub enum SecretKind {
    ExternalPSKBinderKey,
    ResumptionPSKBinderKey,
    ClientEarlyTrafficSecret,
    EarlyExporterMasterSecret,
    ClientHandshakeTrafficSecret,
    ServerHandshakeTrafficSecret,
    ClientApplicationTrafficSecret,
    ServerApplicationTrafficSecret,
    ExporterMasterSecret,
    ResumptionMasterSecret,
}

impl SecretKind {
    fn to_bytes(&self) -> &'static [u8] {
        match *self {
            SecretKind::ExternalPSKBinderKey => b"external psk binder key",
            SecretKind::ResumptionPSKBinderKey => b"reusmption psk binder key",
            SecretKind::ClientEarlyTrafficSecret => b"client early traffic secret",
            SecretKind::EarlyExporterMasterSecret => b"early exporter master secret",
            SecretKind::ClientHandshakeTrafficSecret => b"client handshake traffic secret",
            SecretKind::ServerHandshakeTrafficSecret => b"server handshake traffic secret",
            SecretKind::ClientApplicationTrafficSecret => b"client application traffic secret",
            SecretKind::ServerApplicationTrafficSecret => b"server application traffic secret",
            SecretKind::ExporterMasterSecret => b"exporter master secret",
            SecretKind::ResumptionMasterSecret => b"resumption master secret",
        }
    }
}


pub struct KeySchedule {
    current: hmac::SigningKey,
    hash: &'static digest::Algorithm,
    pub current_client_traffic_secret: Vec<u8>,
    pub current_server_traffic_secret: Vec<u8>,
}

fn dumphex(why: &str, bytes: &[u8]) {
    print!("{}: ", why);
    for b in bytes {
        print!("{:02x}", b);
    }
    println!("");
}

impl KeySchedule {
    pub fn new(hash: &'static digest::Algorithm) -> KeySchedule {
        let zeroes = [0u8; digest::MAX_OUTPUT_LEN];
        println!("start-zeroes");
        KeySchedule {
            current: hmac::SigningKey::new(hash, &zeroes[..hash.output_len]),
            hash: hash,
            current_server_traffic_secret: Vec::new(),
            current_client_traffic_secret: Vec::new(),
        }
    }

    pub fn input_empty(&mut self) {
        let zeroes = [0u8; digest::MAX_OUTPUT_LEN];
        let hash_len = self.hash.output_len;
        self.input_secret(&zeroes[..hash_len]);
    }

    pub fn input_secret(&mut self, secret: &[u8]) {
        dumphex("extract-secret", secret);
        let res = hmac::sign(&self.current, secret);
        dumphex("extract-result", res.as_ref());
        let new = hkdf::extract(&self.current, secret);
        self.current = new
    }

    pub fn derive(&self, kind: SecretKind, hs_hash: &[u8]) -> Vec<u8> {
        debug_assert!(hs_hash.len() == self.hash.output_len);

        println!("derive({:?})", kind);
        _hkdf_expand_label(&self.current,
                           kind.to_bytes(),
                           hs_hash,
                           self.hash.output_len as u16)
    }

    pub fn sign_verify_data(&self, kind: SecretKind, hs_hash: &[u8]) -> Vec<u8> {
        debug_assert!(hs_hash.len() == self.hash.output_len);

        let base_key = match kind {
            SecretKind::ServerHandshakeTrafficSecret => &self.current_server_traffic_secret,
            SecretKind::ClientHandshakeTrafficSecret => &self.current_client_traffic_secret,
            _ => unreachable!(),
        };

        dumphex("verify_data base", &base_key);
        dumphex("verify_data hash", &hs_hash);
        let hmac_key = hkdf_expand_label(self.hash,
                                         &base_key,
                                         b"finished",
                                         &[],
                                         self.hash.output_len as u16);
        dumphex("verify_data signkey", &hmac_key);

        hmac::sign(&hmac::SigningKey::new(self.hash, &hmac_key), hs_hash)
            .as_ref()
            .to_vec()
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
    dumphex("  label", &hkdflabel);

    hkdf::expand(secret, &hkdflabel, &mut out);
    dumphex("  output", &out);
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
        ks.derive(SecretKind::ExternalPSKBinderKey, &fake_handshake_hash);
        ks.derive(SecretKind::ResumptionPSKBinderKey, &fake_handshake_hash);
        ks.derive(SecretKind::ClientEarlyTrafficSecret, &fake_handshake_hash);
        ks.derive(SecretKind::EarlyExporterMasterSecret, &fake_handshake_hash);
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
        ks.derive(SecretKind::ExporterMasterSecret, &fake_handshake_hash);
        ks.derive(SecretKind::ResumptionMasterSecret, &fake_handshake_hash);
    }
}
