use crate::crypto;
use ring;

pub(crate) struct Hmac(&'static ring::hmac::Algorithm);

pub(crate) static HMAC_SHA256: Hmac = Hmac(&ring::hmac::HMAC_SHA256);
pub(crate) static HMAC_SHA384: Hmac = Hmac(&ring::hmac::HMAC_SHA384);
#[cfg(test)]
pub(crate) static HMAC_SHA512: Hmac = Hmac(&ring::hmac::HMAC_SHA512);

impl From<ring::hmac::Tag> for crypto::hmac::Tag {
    fn from(val: ring::hmac::Tag) -> Self {
        Self::new(val.as_ref())
    }
}

impl crypto::hmac::Hmac for Hmac {
    fn open_key(&self, key: &[u8]) -> Box<dyn crypto::hmac::Key> {
        Box::new(Key(ring::hmac::Key::new(*self.0, key)))
    }

    fn hash_output_len(&self) -> usize {
        self.0.digest_algorithm().output_len
    }
}

struct Key(ring::hmac::Key);

impl crypto::hmac::Key for Key {
    fn sign_concat(&self, first: &[u8], middle: &[&[u8]], last: &[u8]) -> crypto::hmac::Tag {
        let mut ctx = ring::hmac::Context::with_key(&self.0);
        ctx.update(first);
        for d in middle {
            ctx.update(d);
        }
        ctx.update(last);
        ctx.sign().into()
    }

    fn tag_len(&self) -> usize {
        self.0
            .algorithm()
            .digest_algorithm()
            .output_len
    }
}
