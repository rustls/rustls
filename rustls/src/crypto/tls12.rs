use alloc::boxed::Box;

use super::{ActiveKeyExchange, hmac};
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

    /// Return `true` if this is backed by a FIPS-approved implementation.
    fn fips(&self) -> bool {
        false
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

pub(crate) fn prf(out: &mut [u8], hmac_key: &dyn hmac::Key, label: &[u8], seed: &[u8]) {
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

#[cfg(all(test, any(feature = "aws-lc-rs", feature = "ring")))]
pub(crate) struct FakePrf;

#[cfg(all(test, any(feature = "aws-lc-rs", feature = "ring")))]
impl Prf for FakePrf {
    fn for_key_exchange(
        &self,
        _: &mut [u8; 48],
        _: Box<dyn ActiveKeyExchange>,
        _: &[u8],
        _: &[u8],
        _: &[u8],
    ) -> Result<(), Error> {
        todo!()
    }

    fn new_secret(&self, _: &[u8; 48]) -> Box<dyn PrfSecret> {
        todo!()
    }

    fn fips(&self) -> bool {
        false
    }
}

#[cfg(all(test, feature = "ring"))]
mod tests {
    use crate::crypto::hmac::Hmac;
    // nb: crypto::aws_lc_rs provider doesn't provide (or need) hmac,
    // so cannot be used for this test.
    use crate::crypto::ring::hmac;

    // Below known answer tests come from https://mailarchive.ietf.org/arch/msg/tls/fzVCzk-z3FShgGJ6DOXqM1ydxms/

    #[test]
    fn check_sha256() {
        let secret = b"\x9b\xbe\x43\x6b\xa9\x40\xf0\x17\xb1\x76\x52\x84\x9a\x71\xdb\x35";
        let seed = b"\xa0\xba\x9f\x93\x6c\xda\x31\x18\x27\xa6\xf7\x96\xff\xd5\x19\x8c";
        let label = b"test label";
        let expect = include_bytes!("../testdata/prf-result.1.bin");
        let mut output = [0u8; 100];

        super::prf(
            &mut output,
            &*hmac::HMAC_SHA256.with_key(secret),
            label,
            seed,
        );
        assert_eq!(expect.len(), output.len());
        assert_eq!(expect.to_vec(), output.to_vec());
    }

    #[test]
    fn check_sha512() {
        let secret = b"\xb0\x32\x35\x23\xc1\x85\x35\x99\x58\x4d\x88\x56\x8b\xbb\x05\xeb";
        let seed = b"\xd4\x64\x0e\x12\xe4\xbc\xdb\xfb\x43\x7f\x03\xe6\xae\x41\x8e\xe5";
        let label = b"test label";
        let expect = include_bytes!("../testdata/prf-result.2.bin");
        let mut output = [0u8; 196];

        super::prf(
            &mut output,
            &*hmac::HMAC_SHA512.with_key(secret),
            label,
            seed,
        );
        assert_eq!(expect.len(), output.len());
        assert_eq!(expect.to_vec(), output.to_vec());
    }

    #[test]
    fn check_sha384() {
        let secret = b"\xb8\x0b\x73\x3d\x6c\xee\xfc\xdc\x71\x56\x6e\xa4\x8e\x55\x67\xdf";
        let seed = b"\xcd\x66\x5c\xf6\xa8\x44\x7d\xd6\xff\x8b\x27\x55\x5e\xdb\x74\x65";
        let label = b"test label";
        let expect = include_bytes!("../testdata/prf-result.3.bin");
        let mut output = [0u8; 148];

        super::prf(
            &mut output,
            &*hmac::HMAC_SHA384.with_key(secret),
            label,
            seed,
        );
        assert_eq!(expect.len(), output.len());
        assert_eq!(expect.to_vec(), output.to_vec());
    }
}

#[cfg(all(bench, feature = "ring"))]
mod benchmarks {
    #[bench]
    fn bench_sha256(b: &mut test::Bencher) {
        use crate::crypto::hmac::Hmac;
        use crate::crypto::ring::hmac;

        let label = &b"extended master secret"[..];
        let seed = [0u8; 32];
        let key = &b"secret"[..];

        b.iter(|| {
            let mut out = [0u8; 48];
            super::prf(&mut out, &*hmac::HMAC_SHA256.with_key(key), &label, &seed);
            test::black_box(out);
        });
    }
}
