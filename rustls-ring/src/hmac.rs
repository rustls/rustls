use alloc::boxed::Box;

use ring::hmac;
use rustls::crypto;

pub(crate) static HMAC_SHA256: Hmac = Hmac(&hmac::HMAC_SHA256);
pub(crate) static HMAC_SHA384: Hmac = Hmac(&hmac::HMAC_SHA384);
#[allow(dead_code)] // Only used for TLS 1.2 prf test, and aws-lc-rs HPKE suites.
pub(crate) static HMAC_SHA512: Hmac = Hmac(&hmac::HMAC_SHA512);

pub(crate) struct Hmac(&'static hmac::Algorithm);

impl crypto::hmac::Hmac for Hmac {
    fn with_key(&self, key: &[u8]) -> Box<dyn crypto::hmac::Key> {
        Box::new(Key(hmac::Key::new(*self.0, key)))
    }

    fn hash_output_len(&self) -> usize {
        self.0.digest_algorithm().output_len()
    }

    fn fips(&self) -> bool {
        super::fips()
    }
}

struct Key(hmac::Key);

impl crypto::hmac::Key for Key {
    fn sign_concat(&self, first: &[u8], middle: &[&[u8]], last: &[u8]) -> crypto::hmac::Tag {
        let mut ctx = hmac::Context::with_key(&self.0);
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
