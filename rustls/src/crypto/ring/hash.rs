use crate::crypto;
use crate::msgs::enums::HashAlgorithm;
use ring;

pub(crate) struct Hash(&'static ring::digest::Algorithm, HashAlgorithm);

pub(crate) static SHA256: Hash = Hash(&ring::digest::SHA256, HashAlgorithm::SHA256);
pub(crate) static SHA384: Hash = Hash(&ring::digest::SHA384, HashAlgorithm::SHA384);

impl From<ring::digest::Digest> for crypto::hash::Output {
    fn from(val: ring::digest::Digest) -> Self {
        Self::new(val.as_ref())
    }
}

impl crypto::hash::Hash for Hash {
    fn algorithm(&self) -> HashAlgorithm {
        self.1
    }

    fn output_len(&self) -> usize {
        self.0.output_len
    }

    fn start(&self) -> Box<dyn crypto::hash::Context> {
        Box::new(Context(ring::digest::Context::new(self.0)))
    }

    fn compute(&self, bytes: &[u8]) -> crypto::hash::Output {
        let mut ctx = ring::digest::Context::new(self.0);
        ctx.update(bytes);
        ctx.finish().into()
    }
}

struct Context(ring::digest::Context);

impl crypto::hash::Context for Context {
    fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    fn fork(&self) -> Box<dyn crypto::hash::Context> {
        Box::new(Self(self.0.clone()))
    }

    fn fork_finish(&self) -> crypto::hash::Output {
        self.0.clone().finish().into()
    }

    fn finish(self: Box<Self>) -> crypto::hash::Output {
        self.0.finish().into()
    }
}
