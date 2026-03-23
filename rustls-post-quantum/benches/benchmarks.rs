use core::hint::black_box;
use std::borrow::Cow;
use std::sync::Arc;

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use rustls::crypto::CryptoProvider;
use rustls::crypto::kx::{
    ActiveKeyExchange, HybridKeyExchange, NamedGroup, SharedSecret, StartedKeyExchange,
    SupportedKxGroup,
};
use rustls::{ClientConfig, Connection, Error, RootCertStore};
use rustls_aws_lc_rs::kx_group::{MLKEM768, X25519, X25519MLKEM768};

fn bench_client(c: &mut Criterion) {
    let mut group = c.benchmark_group("client");
    group.throughput(Throughput::Elements(1));

    group.bench_function("MLKEM768", |b| {
        b.iter(|| black_box(MLKEM768.start().unwrap()))
    });
    group.bench_function("X25519MLKEM768", |b| {
        b.iter(|| black_box(X25519MLKEM768.start().unwrap()))
    });
    group.bench_function("X25519", |b| b.iter(|| black_box(X25519.start().unwrap())));
    group.bench_function("X25519MLKEM768+X25519", |b| {
        b.iter(|| {
            black_box(X25519.start().unwrap());
            black_box(X25519MLKEM768.start().unwrap());
        })
    });
}

fn bench_server(c: &mut Criterion) {
    let client_x25519mlkem768 = X25519MLKEM768.start().unwrap();
    let client_x25519 = X25519.start().unwrap();
    let client_mlkem768 = MLKEM768.start().unwrap();

    let mut group = c.benchmark_group("server");
    group.throughput(Throughput::Elements(1));

    group.bench_function("MLKEM768", |b| {
        b.iter(|| {
            black_box(
                MLKEM768
                    .start_and_complete(client_mlkem768.pub_key())
                    .unwrap(),
            )
        })
    });
    group.bench_function("X25519MLKEM768", |b| {
        b.iter(|| {
            black_box(
                X25519MLKEM768
                    .start_and_complete(client_x25519mlkem768.pub_key())
                    .unwrap(),
            )
        })
    });
    group.bench_function("X25519", |b| {
        b.iter(|| {
            black_box(
                X25519
                    .start_and_complete(client_x25519.pub_key())
                    .unwrap(),
            )
        })
    });
}

fn bench_clienthello(c: &mut Criterion) {
    let mut group = c.benchmark_group("clienthello");
    group.throughput(Throughput::Elements(1));

    let anchors = Arc::new(RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.into(),
    });

    let config_x25519 = Arc::new(
        ClientConfig::builder(rustls_aws_lc_rs::DEFAULT_PROVIDER.into())
            .with_root_certificates(anchors.clone())
            .with_no_client_auth()
            .unwrap(),
    );

    let config_x25519mlkem768 = Arc::new(
        ClientConfig::builder(rustls_post_quantum::provider().into())
            .with_root_certificates(anchors.clone())
            .with_no_client_auth()
            .unwrap(),
    );

    let config_x25519mlkem768_x25519 = Arc::new(
        ClientConfig::builder(separate_provider().into())
            .with_root_certificates(anchors)
            .with_no_client_auth()
            .unwrap(),
    );

    println!("Clienthello lengths:");
    println!("  X25519 alone = {:?}", do_client_hello(&config_x25519));
    println!(
        "  X25519MLKEM768 joint = {:?}",
        do_client_hello(&config_x25519mlkem768)
    );
    println!(
        "  X25519MLKEM768 sep = {:?}",
        do_client_hello(&config_x25519mlkem768_x25519)
    );

    group.bench_function("X25519", |b| b.iter(|| do_client_hello(&config_x25519)));

    group.bench_function("X25519MLKEM768", |b| {
        b.iter(|| do_client_hello(&config_x25519mlkem768))
    });

    group.bench_function("X25519MLKEM768+X25519", |b| {
        b.iter(|| do_client_hello(&config_x25519mlkem768_x25519))
    });
}

fn do_client_hello(config: &Arc<ClientConfig>) -> usize {
    let mut conn = config
        .connect("localhost".try_into().unwrap())
        .build()
        .unwrap();
    let mut buf = vec![];
    let len = conn.write_tls(&mut &mut buf).unwrap();
    black_box(buf);
    len
}

fn separate_provider() -> CryptoProvider {
    const KX_GROUPS: &[&'static dyn SupportedKxGroup] = &[
        &SeparateX25519Mlkem768,
        MLKEM768,
        X25519,
        rustls_aws_lc_rs::kx_group::SECP256R1,
        rustls_aws_lc_rs::kx_group::SECP384R1,
    ];
    CryptoProvider {
        kx_groups: Cow::Borrowed(KX_GROUPS),
        ..rustls_aws_lc_rs::DEFAULT_PROVIDER
    }
}

// nb. this cannot actually complete a handshake; limited to ClientHellos
#[derive(Debug)]
struct SeparateX25519Mlkem768;

impl SupportedKxGroup for SeparateX25519Mlkem768 {
    fn start(&self) -> Result<StartedKeyExchange, Error> {
        let StartedKeyExchange::Hybrid(hybrid) = X25519MLKEM768.start()? else {
            unreachable!();
        };
        let StartedKeyExchange::Single(separate) = X25519.start()? else {
            unreachable!();
        };

        Ok(StartedKeyExchange::Hybrid(Box::new(Active {
            hybrid,
            separate,
        })))
    }

    fn name(&self) -> NamedGroup {
        X25519MLKEM768.name()
    }
}

struct Active {
    hybrid: Box<dyn HybridKeyExchange>,
    separate: Box<dyn ActiveKeyExchange>,
}

impl ActiveKeyExchange for Active {
    fn complete(self: Box<Self>, _peer: &[u8]) -> Result<SharedSecret, Error> {
        todo!()
    }

    fn group(&self) -> NamedGroup {
        self.hybrid.group()
    }

    fn pub_key(&self) -> &[u8] {
        self.hybrid.pub_key()
    }
}

impl HybridKeyExchange for Active {
    fn component(&self) -> (NamedGroup, &[u8]) {
        (self.separate.group(), self.separate.pub_key())
    }

    fn complete_component(self: Box<Self>, peer_pub_key: &[u8]) -> Result<SharedSecret, Error> {
        self.separate.complete(peer_pub_key)
    }

    fn as_key_exchange(&self) -> &(dyn ActiveKeyExchange + 'static) {
        self
    }

    fn into_key_exchange(self: Box<Self>) -> Box<dyn ActiveKeyExchange> {
        self.separate
    }
}

criterion_group!(benches, bench_client, bench_server, bench_clienthello);
criterion_main!(benches);
