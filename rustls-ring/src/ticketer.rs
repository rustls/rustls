use alloc::boxed::Box;
use alloc::vec::Vec;
use core::fmt;
use core::fmt::{Debug, Formatter};
use core::sync::atomic::{AtomicUsize, Ordering};
use core::time::Duration;

use ring::aead;
use ring::rand::{SecureRandom, SystemRandom};
use rustls::crypto::TicketProducer;
use rustls::error::Error;
use subtle::ConstantTimeEq;

/// A [`TicketProducer`] implementation which can use any *ring* `aead::Algorithm`.
///
/// It does not enforce any lifetime constraint.
pub(super) struct AeadTicketer {
    alg: &'static aead::Algorithm,
    key: aead::LessSafeKey,
    key_name: [u8; 16],

    /// Tracks the largest ciphertext produced by `encrypt`, and
    /// uses it to early-reject `decrypt` queries that are too long.
    ///
    /// Accepting excessively long ciphertexts means a "Partitioning
    /// Oracle Attack" (see <https://eprint.iacr.org/2020/1491.pdf>)
    /// can be more efficient, though also note that these are thought
    /// to be cryptographically hard if the key is full-entropy (as it
    /// is here).
    maximum_ciphertext_len: AtomicUsize,
}

impl AeadTicketer {
    #[expect(clippy::new_ret_no_self)]
    pub(super) fn new() -> Result<Box<dyn TicketProducer>, Error> {
        let mut key = [0u8; 32];
        SystemRandom::new()
            .fill(&mut key)
            .map_err(|_| Error::FailedToGetRandomBytes)?;

        let key = aead::UnboundKey::new(TICKETER_AEAD, &key).unwrap();

        let mut key_name = [0u8; 16];
        SystemRandom::new()
            .fill(&mut key_name)
            .map_err(|_| Error::FailedToGetRandomBytes)?;

        Ok(Box::new(Self {
            alg: TICKETER_AEAD,
            key: aead::LessSafeKey::new(key),
            key_name,
            maximum_ciphertext_len: AtomicUsize::new(0),
        }))
    }
}

impl TicketProducer for AeadTicketer {
    /// Encrypt `message` and return the ciphertext.
    fn encrypt(&self, message: &[u8]) -> Option<Vec<u8>> {
        // Random nonce, because a counter is a privacy leak.
        let mut nonce_buf = [0u8; 12];
        SystemRandom::new()
            .fill(&mut nonce_buf)
            .ok()?;
        let nonce = aead::Nonce::assume_unique_for_key(nonce_buf);
        let aad = aead::Aad::from(self.key_name);

        // ciphertext structure is:
        // key_name: [u8; 16]
        // nonce: [u8; 12]
        // message: [u8, _]
        // tag: [u8; 16]

        let mut ciphertext = Vec::with_capacity(
            self.key_name.len() + nonce_buf.len() + message.len() + self.key.algorithm().tag_len(),
        );
        ciphertext.extend(self.key_name);
        ciphertext.extend(nonce_buf);
        ciphertext.extend(message);
        let ciphertext = self
            .key
            .seal_in_place_separate_tag(
                nonce,
                aad,
                &mut ciphertext[self.key_name.len() + nonce_buf.len()..],
            )
            .map(|tag| {
                ciphertext.extend(tag.as_ref());
                ciphertext
            })
            .ok()?;

        self.maximum_ciphertext_len
            .fetch_max(ciphertext.len(), Ordering::SeqCst);
        Some(ciphertext)
    }

    /// Decrypt `ciphertext` and recover the original message.
    fn decrypt(&self, ciphertext: &[u8]) -> Option<Vec<u8>> {
        if ciphertext.len()
            > self
                .maximum_ciphertext_len
                .load(Ordering::SeqCst)
        {
            return None;
        }

        let (alleged_key_name, ciphertext) = ciphertext.split_at_checked(self.key_name.len())?;

        let (nonce, ciphertext) = ciphertext.split_at_checked(self.alg.nonce_len())?;

        // checking the key_name is the expected one, *and* then putting it into the
        // additionally authenticated data is duplicative.  this check quickly rejects
        // tickets for a different ticketer (see `TicketRotator`), while including it
        // in the AAD ensures it is authenticated independent of that check and that
        // any attempted attack on the integrity such as [^1] must happen for each
        // `key_label`, not over a population of potential keys.  this approach
        // is overall similar to [^2].
        //
        // [^1]: https://eprint.iacr.org/2020/1491.pdf
        // [^2]: "Authenticated Encryption with Key Identification", fig 6
        //       <https://eprint.iacr.org/2022/1680.pdf>
        if ConstantTimeEq::ct_ne(&self.key_name[..], alleged_key_name).into() {
            return None;
        }

        // This won't fail since `nonce` has the required length.
        let nonce = aead::Nonce::try_assume_unique_for_key(nonce).ok()?;

        let mut out = Vec::from(ciphertext);

        let plain_len = self
            .key
            .open_in_place(nonce, aead::Aad::from(alleged_key_name), &mut out)
            .ok()?
            .len();
        out.truncate(plain_len);

        Some(out)
    }

    fn lifetime(&self) -> Duration {
        // this is not used, as this ticketer is only used via a `TicketRotator`
        // that is responsible for defining and managing the lifetime of tickets.
        Duration::ZERO
    }
}

impl Debug for AeadTicketer {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        // Note: we deliberately omit the key from the debug output.
        f.debug_struct("AeadTicketer")
            .field("alg", &self.alg)
            .finish()
    }
}

static TICKETER_AEAD: &aead::Algorithm = &aead::CHACHA20_POLY1305;

#[cfg(all(test, feature = "std"))]
mod tests {
    use rustls::crypto::TicketerFactory;

    use crate::Ring;

    #[test]
    fn basic_pairwise_test() {
        let t = Ring.ticketer().unwrap();
        let cipher = t.encrypt(b"hello world").unwrap();
        let plain = t.decrypt(&cipher).unwrap();
        assert_eq!(plain, b"hello world");
    }

    #[test]
    fn refuses_decrypt_before_encrypt() {
        let t = Ring.ticketer().unwrap();
        assert_eq!(t.decrypt(b"hello"), None);
    }

    #[test]
    fn refuses_decrypt_larger_than_largest_encryption() {
        let t = Ring.ticketer().unwrap();
        let mut cipher = t.encrypt(b"hello world").unwrap();
        assert_eq!(t.decrypt(&cipher), Some(b"hello world".to_vec()));

        // obviously this would never work anyway, but this
        // and `cannot_decrypt_before_encrypt` exercise the
        // first branch in `decrypt()`
        cipher.push(0);
        assert_eq!(t.decrypt(&cipher), None);
    }

    #[test]
    fn aeadticketer_is_debug_and_producestickets() {
        use alloc::format;

        use super::*;

        let t = AeadTicketer::new().unwrap();

        let expect = format!("AeadTicketer {{ alg: {TICKETER_AEAD:?} }}");
        assert_eq!(format!("{t:?}"), expect);
        assert_eq!(t.lifetime(), Duration::ZERO);
    }
}
