use alloc::boxed::Box;
use alloc::vec::Vec;
use core::fmt;
use core::fmt::{Debug, Formatter};
use core::sync::atomic::{AtomicUsize, Ordering};
use core::time::Duration;

use chacha20poly1305::aead::AeadCore;
use chacha20poly1305::aead::generic_array::typenum::Unsigned;
use chacha20poly1305::{AeadInPlace, ChaCha20Poly1305, Key, KeyInit, Nonce};
use rand_core::{OsRng, RngCore};
use rustls::crypto::TicketProducer;
use rustls::error::Error;
use subtle::ConstantTimeEq;

/// A [`TicketProducer`] implementation based on random ChaCha20Poly1305 keys.
///
/// This implementation does not enforce any lifetime constraint.
pub(super) struct AeadTicketer {
    key: ChaCha20Poly1305,
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
        // Generate a random key
        let mut key = Key::default();
        OsRng.fill_bytes(key.as_mut_slice());

        // Generate a random key name.
        let mut key_name = [0u8; 16];
        OsRng.fill_bytes(&mut key_name);

        Ok(Box::new(Self {
            key: ChaCha20Poly1305::new(&key),
            key_name,
            maximum_ciphertext_len: AtomicUsize::new(0),
        }))
    }
}

impl TicketProducer for AeadTicketer {
    /// Encrypt `message` and return the ciphertext.
    fn encrypt(&self, message: &[u8]) -> Option<Vec<u8>> {
        let mut nonce = Nonce::default();
        OsRng.fill_bytes(nonce.as_mut_slice());

        // ciphertext structure is:
        // key_name: [u8; 16]
        // nonce: [u8; 12]
        // message: [u8, _]
        // tag: [u8; 16]

        let mut ciphertext = Vec::with_capacity(
            self.key_name.len()
                + nonce.len()
                + message.len()
                + <ChaCha20Poly1305 as AeadCore>::TagSize::to_usize(),
        );
        ciphertext.extend(self.key_name);
        ciphertext.extend(nonce);
        ciphertext.extend(message);

        let tag = self
            .key
            .encrypt_in_place_detached(
                &nonce,
                &self.key_name,
                &mut ciphertext[self.key_name.len() + nonce.len()..],
            )
            .ok()?;
        ciphertext.extend(tag.as_slice());

        self.maximum_ciphertext_len
            .fetch_max(ciphertext.len(), Ordering::SeqCst);
        Some(ciphertext)
    }

    fn decrypt(&self, ciphertext: &[u8]) -> Option<Vec<u8>> {
        if ciphertext.len()
            > self
                .maximum_ciphertext_len
                .load(Ordering::SeqCst)
        {
            return None;
        }

        let (alleged_key_name, ciphertext) = ciphertext.split_at_checked(self.key_name.len())?;

        let (nonce, ciphertext) =
            ciphertext.split_at_checked(<ChaCha20Poly1305 as AeadCore>::NonceSize::to_usize())?;

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

        let nonce = Nonce::from_slice(nonce);
        let mut out = Vec::from(ciphertext);
        self.key
            .decrypt_in_place(nonce, alleged_key_name, &mut out)
            .ok()?;

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
        // Note: we deliberately omit keys from the debug output.
        f.debug_struct("AeadTicketer")
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use rustls::crypto::TicketerFactory;

    use crate::Provider;

    #[test]
    fn basic_pairwise_test() {
        let t = Provider.ticketer().unwrap();
        let cipher = t.encrypt(b"hello world").unwrap();
        let plain = t.decrypt(&cipher).unwrap();
        assert_eq!(plain, b"hello world");
    }

    #[test]
    fn refuses_decrypt_before_encrypt() {
        let t = Provider.ticketer().unwrap();
        assert_eq!(t.decrypt(b"hello"), None);
    }

    #[test]
    fn refuses_decrypt_larger_than_largest_encryption() {
        let t = Provider.ticketer().unwrap();
        let mut cipher = t.encrypt(b"hello world").unwrap();
        assert_eq!(t.decrypt(&cipher), Some(b"hello world".to_vec()));

        // obviously this would never work anyway, but this
        // and `cannot_decrypt_before_encrypt` exercise the
        // first branch in `decrypt()`
        cipher.push(0);
        assert_eq!(t.decrypt(&cipher), None);
    }

    #[test]
    fn aead_ticketer_is_debug_and_producestickets() {
        use alloc::format;

        use super::*;

        let t = AeadTicketer::new().unwrap();

        assert_eq!(format!("{t:?}"), "AeadTicketer { .. }");
        assert_eq!(t.lifetime(), Duration::ZERO);
    }
}
