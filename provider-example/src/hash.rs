use rustls::crypto::hash;
use sha2::Digest;

pub struct SHA256;
struct SHA256Context(sha2::Sha256);

impl hash::Hash for SHA256 {
    fn algorithm(&self) -> hash::HashAlgorithm {
        hash::HashAlgorithm::SHA256
    }

    fn output_len(&self) -> usize {
        32
    }

    fn start(&self) -> Box<dyn hash::Context> {
        Box::new(SHA256Context(sha2::Sha256::new()))
    }

    fn compute(&self, data: &[u8]) -> hash::Output {
        hash::Output::new(&sha2::Sha256::digest(data)[..])
    }
}

impl hash::Context for SHA256Context {
    fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    fn fork(&self) -> Box<dyn hash::Context> {
        Box::new(SHA256Context(self.0.clone()))
    }

    fn fork_finish(&self) -> hash::Output {
        hash::Output::new(&self.0.clone().finalize()[..])
    }

    fn finish(self: Box<Self>) -> hash::Output {
        hash::Output::new(&self.0.finalize()[..])
    }
}
