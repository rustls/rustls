#![allow(clippy::duplicate_mod)]

use super::ring_like;
use crate::crypto;

use alloc::boxed::Box;

#[cfg(feature = "tls12")]
pub(crate) static HMAC_SHA256: Hmac = Hmac(&ring_like::hmac::HMAC_SHA256);
#[cfg(feature = "tls12")]
pub(crate) static HMAC_SHA384: Hmac = Hmac(&ring_like::hmac::HMAC_SHA384);
#[cfg(test)]
#[allow(dead_code)] // only for TLS1.2 prf test
pub(crate) static HMAC_SHA512: Hmac = Hmac(&ring_like::hmac::HMAC_SHA512);

pub(crate) struct Hmac(&'static ring_like::hmac::Algorithm);

impl crypto::hmac::Hmac for Hmac {
    fn with_key(&self, key: &[u8]) -> Box<dyn crypto::hmac::Key> {
        Box::new(Key(ring_like::hmac::Key::new(*self.0, key)))
    }

    fn hash_output_len(&self) -> usize {
        self.0.digest_algorithm().output_len()
    }
}

struct Key(ring_like::hmac::Key);

impl crypto::hmac::Key for Key {
    fn sign_concat(&self, first: &[u8], middle: &[&[u8]], last: &[u8]) -> crypto::hmac::Tag {
        let mut ctx = ring_like::hmac::Context::with_key(&self.0);
        ctx.update(first);
        for d in middle {
            ctx.update(d);
        }
        ctx.update(last);
        crypto::hmac::Tag::new(ctx.sign().as_ref())
    }

    fn tag_len(&self) -> usize {
        self.0
            .algorithm()
            .digest_algorithm()
            .output_len()
    }
}
