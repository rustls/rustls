use alloc::boxed::Box;

use pki_types::FipsStatus;

use super::hmac;
use super::kx::ActiveKeyExchange;
use crate::enums::ProtocolVersion;
use crate::error::Error;

/// Implements [`Prf`] using a [`hmac::Hmac`].
#[expect(clippy::exhaustive_structs)]
pub struct PrfUsingHmac<'a>(pub &'a dyn hmac::Hmac);

impl Prf for PrfUsingHmac<'_> {
    fn for_key_exchange(
        &self,
        output: &mut [u8; 48],
        kx: Box<dyn ActiveKeyExchange>,
        peer_pub_key: &[u8],
        label: &[u8],
        seed: &[u8],
    ) -> Result<(), Error> {
        prf(
            output,
            self.0
                .with_key(
                    kx.complete_for_tls_version(peer_pub_key, ProtocolVersion::TLSv1_2)?
                        .secret_bytes(),
                )
                .as_ref(),
            label,
            seed,
        );
        Ok(())
    }

    fn new_secret(&self, secret: &[u8; 48]) -> Box<dyn PrfSecret> {
        Box::new(PrfSecretUsingHmac(self.0.with_key(secret)))
    }
}

struct PrfSecretUsingHmac(Box<dyn hmac::Key>);

impl PrfSecret for PrfSecretUsingHmac {
    fn prf(&self, output: &mut [u8], label: &[u8], seed: &[u8]) {
        prf(output, &*self.0, label, seed)
    }
}

/// An instantiation of the TLS1.2 PRF with a specific, implicit hash function.
///
/// See the definition in [RFC5246 section 5](https://www.rfc-editor.org/rfc/rfc5246#section-5).
///
/// See [`PrfUsingHmac`] as a route to implementing this trait with just
/// an implementation of [`hmac::Hmac`].
pub trait Prf: Send + Sync {
    /// Computes `PRF(secret, label, seed)` using the secret from a completed key exchange.
    ///
    /// Completes the given key exchange, and then uses the resulting shared secret
    /// to compute the PRF, writing the result into `output`.
    ///
    /// The caller guarantees that `label`, `seed` are non-empty. The caller makes no
    /// guarantees about the contents of `peer_pub_key`. It must be validated by
    /// [`ActiveKeyExchange::complete`].
    fn for_key_exchange(
        &self,
        output: &mut [u8; 48],
        kx: Box<dyn ActiveKeyExchange>,
        peer_pub_key: &[u8],
        label: &[u8],
        seed: &[u8],
    ) -> Result<(), Error>;

    /// Returns an object that can compute `PRF(secret, label, seed)` with
    /// the same `master_secret`.
    ///
    /// This object can amortize any preprocessing needed on `master_secret` over
    /// several `PRF(...)` calls.
    fn new_secret(&self, master_secret: &[u8; 48]) -> Box<dyn PrfSecret>;

    /// Return the FIPS validation status of this implementation.
    fn fips(&self) -> FipsStatus {
        FipsStatus::Unvalidated
    }
}

/// An instantiation of the TLS1.2 PRF with a fixed hash function and master secret.
pub trait PrfSecret: Send + Sync {
    /// Computes `PRF(secret, label, seed)`, writing the result into `output`.
    ///
    /// `secret` is implicit in this object; see [`Prf::new_secret`].
    ///
    /// The caller guarantees that `label` and `seed` are non-empty.
    fn prf(&self, output: &mut [u8], label: &[u8], seed: &[u8]);
}

#[doc(hidden)]
pub fn prf(out: &mut [u8], hmac_key: &dyn hmac::Key, label: &[u8], seed: &[u8]) {
    let mut previous_a: Option<hmac::Tag> = None;

    let chunk_size = hmac_key.tag_len();
    for chunk in out.chunks_mut(chunk_size) {
        let a_i = match previous_a {
            // A(0) = HMAC_hash(secret, label + seed)
            None => hmac_key.sign(&[label, seed]),
            // A(i) = HMAC_hash(secret, A(i - 1))
            Some(previous_a) => hmac_key.sign(&[previous_a.as_ref()]),
        };

        // P_hash[i] = HMAC_hash(secret, A(i) + label + seed)
        let p_term = hmac_key.sign(&[a_i.as_ref(), label, seed]);
        chunk.copy_from_slice(&p_term.as_ref()[..chunk.len()]);

        previous_a = Some(a_i);
    }
}
