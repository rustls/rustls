use num_bigint::BigUint;
use rustls::Tls12CipherSuite;
use rustls::crypto::kx::ffdhe::{FFDHE2048, FfdheGroup};
use rustls::crypto::kx::{
    ActiveKeyExchange, KeyExchangeAlgorithm, NamedGroup, SharedSecret, StartedKeyExchange,
    SupportedKxGroup,
};
use rustls::crypto::{CipherSuite, CipherSuiteCommon, aws_lc_rs as provider};

pub(crate) const FFDHE2048_GROUP: &dyn SupportedKxGroup =
    &FfdheKxGroup(NamedGroup::FFDHE2048, FFDHE2048);

#[derive(Debug)]
pub(crate) struct FfdheKxGroup(pub NamedGroup, pub FfdheGroup<'static>);

impl SupportedKxGroup for FfdheKxGroup {
    fn start(&self) -> Result<StartedKeyExchange, rustls::Error> {
        let mut x = vec![0; 64];
        provider::DEFAULT_PROVIDER
            .secure_random
            .fill(&mut x)?;
        let x = BigUint::from_bytes_be(&x);

        let group = self.1;
        let p = BigUint::from_bytes_be(group.p);
        let g = BigUint::from_bytes_be(group.g);

        let x_pub = g.modpow(&x, &p);
        let x_pub = to_bytes_be_with_len(x_pub, group.p.len());

        Ok(StartedKeyExchange::Single(Box::new(ActiveFfdheKx {
            x_pub,
            x,
            p,
            group,
            named_group: self.0,
        })))
    }

    fn ffdhe_group(&self) -> Option<FfdheGroup<'static>> {
        Some(self.1)
    }

    fn name(&self) -> NamedGroup {
        self.0
    }
}

pub(crate) static TLS_DHE_RSA_WITH_AES_128_GCM_SHA256: Tls12CipherSuite = Tls12CipherSuite {
    common: CipherSuiteCommon {
        suite: CipherSuite::TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
        ..provider::cipher_suite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256.common
    },
    kx: KeyExchangeAlgorithm::DHE,
    ..*provider::cipher_suite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
};

struct ActiveFfdheKx {
    x_pub: Vec<u8>,
    x: BigUint,
    p: BigUint,
    group: FfdheGroup<'static>,
    named_group: NamedGroup,
}

impl ActiveKeyExchange for ActiveFfdheKx {
    fn complete(self: Box<Self>, peer_pub_key: &[u8]) -> Result<SharedSecret, rustls::Error> {
        let peer_pub = BigUint::from_bytes_be(peer_pub_key);
        let secret = peer_pub.modpow(&self.x, &self.p);
        let secret = to_bytes_be_with_len(secret, self.group.p.len());

        Ok(SharedSecret::from(&secret[..]))
    }

    fn pub_key(&self) -> &[u8] {
        &self.x_pub
    }

    fn ffdhe_group(&self) -> Option<FfdheGroup<'static>> {
        Some(self.group)
    }

    fn group(&self) -> NamedGroup {
        self.named_group
    }
}

fn to_bytes_be_with_len(n: BigUint, len_bytes: usize) -> Vec<u8> {
    let mut bytes = n.to_bytes_le();
    bytes.resize(len_bytes, 0);
    bytes.reverse();
    bytes
}
