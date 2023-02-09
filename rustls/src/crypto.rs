use crate::rand::GetRandomFailed;
use crate::server::ProducesTickets;

use ring::aead;
use ring::constant_time;
use ring::rand::{SecureRandom, SystemRandom};

/// Pluggable crypto galore.
pub trait CryptoProvider: Send + Sync + 'static {
    /// Build a ticket generator.
    fn ticket_generator() -> Result<Box<dyn ProducesTickets>, GetRandomFailed>;

    /// Fill the given buffer with random bytes.
    fn fill_random(buf: &mut [u8]) -> Result<(), GetRandomFailed>;

    /// Verify that the two input slices are equal, in constant time.
    fn verify_equal_ct(a: &[u8], b: &[u8]) -> bool;
}

/// Default crypto provider.
pub struct Ring;

impl CryptoProvider for Ring {
    fn ticket_generator() -> Result<Box<dyn ProducesTickets>, GetRandomFailed> {
        let mut key = [0u8; 32];
        Self::fill_random(&mut key)?;

        let alg = &aead::CHACHA20_POLY1305;
        let key = aead::UnboundKey::new(alg, &key).unwrap();

        Ok(Box::new(AeadTicketer {
            alg,
            key: aead::LessSafeKey::new(key),
            lifetime: 60 * 60 * 12,
        }))
    }

    fn fill_random(buf: &mut [u8]) -> Result<(), GetRandomFailed> {
        SystemRandom::new()
            .fill(buf)
            .map_err(|_| GetRandomFailed)
    }

    fn verify_equal_ct(a: &[u8], b: &[u8]) -> bool {
        constant_time::verify_slices_are_equal(a, b).is_ok()
    }
}

/// This is a `ProducesTickets` implementation which uses
/// any *ring* `aead::Algorithm` to encrypt and authentication
/// the ticket payload.  It does not enforce any lifetime
/// constraint.
struct AeadTicketer {
    alg: &'static aead::Algorithm,
    key: aead::LessSafeKey,
    lifetime: u32,
}

impl ProducesTickets for AeadTicketer {
    fn enabled(&self) -> bool {
        true
    }
    fn lifetime(&self) -> u32 {
        self.lifetime
    }

    /// Encrypt `message` and return the ciphertext.
    fn encrypt(&self, message: &[u8]) -> Option<Vec<u8>> {
        // Random nonce, because a counter is a privacy leak.
        let mut nonce_buf = [0u8; 12];
        Ring::fill_random(&mut nonce_buf).ok()?;
        let nonce = ring::aead::Nonce::assume_unique_for_key(nonce_buf);
        let aad = ring::aead::Aad::empty();

        let mut ciphertext =
            Vec::with_capacity(nonce_buf.len() + message.len() + self.key.algorithm().tag_len());
        ciphertext.extend(nonce_buf);
        ciphertext.extend(message);
        self.key
            .seal_in_place_separate_tag(nonce, aad, &mut ciphertext[nonce_buf.len()..])
            .map(|tag| {
                ciphertext.extend(tag.as_ref());
                ciphertext
            })
            .ok()
    }

    /// Decrypt `ciphertext` and recover the original message.
    fn decrypt(&self, ciphertext: &[u8]) -> Option<Vec<u8>> {
        // Non-panicking `let (nonce, ciphertext) = ciphertext.split_at(...)`.
        let nonce = ciphertext.get(..self.alg.nonce_len())?;
        let ciphertext = ciphertext.get(nonce.len()..)?;

        // This won't fail since `nonce` has the required length.
        let nonce = ring::aead::Nonce::try_assume_unique_for_key(nonce).ok()?;

        let mut out = Vec::from(ciphertext);

        let plain_len = self
            .key
            .open_in_place(nonce, aead::Aad::empty(), &mut out)
            .ok()?
            .len();
        out.truncate(plain_len);

        Some(out)
    }
}
