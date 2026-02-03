//! This program does benchmarking of the functions in verify.rs,
//! that do certificate chain validation and signature verification.
//!
//! This uses captured certificate chains for a selection of websites,
//! saved in `data/cert-{SITE}.{I}.der`.
//!
//! To update that data:
//!
//! - delete all `data/cert-*.der`.
//! - run the `admin/capture-certdata` script.
//! - update the verification timestamp near the bottom of this file
//!   to the current time.
//! - where a website's chain length changed, reflect that in the list
//!   of certificate files below.
//!
//! This does not need to be done regularly; because the verification
//! time is fixed, it only needs doing if a root certificate is
//! distrusted.

#![cfg(bench)]
#![cfg_attr(bench, feature(test))]

extern crate test;

use core::time::Duration;
use std::sync::Arc;

use pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::RootCertStore;
use rustls::client::WebPkiServerVerifier;
use rustls::client::danger::{ServerIdentity, ServerVerifier};
use rustls::crypto::{CertificateIdentity, CryptoProvider, Identity};

/// Instantiate the given benchmark functions once for each built-in provider.
///
/// The selected provider module is bound as `provider`; you can rely on this
/// having the union of the items common to the `crypto::ring` and
/// `crypto::aws_lc_rs` modules.
#[cfg(bench)]
macro_rules! bench_for_each_provider {
    ($($tt:tt)+) => {
        #[cfg(feature = "ring")]
        mod bench_with_ring {
            use rustls_ring as provider;
            #[allow(unused_imports)]
            use super::*;
            $($tt)+
        }

        #[cfg(feature = "aws-lc-rs")]
        mod bench_with_aws_lc_rs {
            use rustls_aws_lc_rs as provider;
            #[allow(unused_imports)]
            use super::*;
            $($tt)+
        }
    };
}

/*
#[cfg(all(test, bench))]
#[macro_rules_attribute::apply(bench_for_each_provider)]
mod benchmarks {
    #[bench]
    fn bench_each_provider(b: &mut test::Bencher) {
        b.iter(|| super::provider::DEFAULT_PROVIDER);
    }
}*/

#[macro_rules_attribute::apply(bench_for_each_provider)]
mod benchmarks {
    use super::{Context, provider};

    #[bench]
    fn reddit_cert(b: &mut test::Bencher) {
        let ctx = Context::new(
            &provider::DEFAULT_PROVIDER,
            "reddit.com",
            &[
                include_bytes!("data/cert-reddit.0.der"),
                include_bytes!("data/cert-reddit.1.der"),
            ],
        );
        b.iter(|| ctx.verify_once());
    }

    #[bench]
    fn github_cert(b: &mut test::Bencher) {
        let ctx = Context::new(
            &provider::DEFAULT_PROVIDER,
            "github.com",
            &[
                include_bytes!("data/cert-github.0.der"),
                include_bytes!("data/cert-github.1.der"),
                include_bytes!("data/cert-github.2.der"),
            ],
        );
        b.iter(|| ctx.verify_once());
    }

    #[bench]
    fn arstechnica_cert(b: &mut test::Bencher) {
        let ctx = Context::new(
            &provider::DEFAULT_PROVIDER,
            "arstechnica.com",
            &[
                include_bytes!("data/cert-arstechnica.0.der"),
                include_bytes!("data/cert-arstechnica.1.der"),
                include_bytes!("data/cert-arstechnica.2.der"),
            ],
        );
        b.iter(|| ctx.verify_once());
    }

    #[bench]
    fn servo_cert(b: &mut test::Bencher) {
        let ctx = Context::new(
            &provider::DEFAULT_PROVIDER,
            "servo.org",
            &[
                include_bytes!("data/cert-servo.0.der"),
                include_bytes!("data/cert-servo.1.der"),
                include_bytes!("data/cert-servo.2.der"),
            ],
        );
        b.iter(|| ctx.verify_once());
    }

    #[bench]
    fn twitter_cert(b: &mut test::Bencher) {
        let ctx = Context::new(
            &provider::DEFAULT_PROVIDER,
            "twitter.com",
            &[
                include_bytes!("data/cert-twitter.0.der"),
                include_bytes!("data/cert-twitter.1.der"),
            ],
        );
        b.iter(|| ctx.verify_once());
    }

    #[bench]
    fn wikipedia_cert(b: &mut test::Bencher) {
        let ctx = Context::new(
            &provider::DEFAULT_PROVIDER,
            "wikipedia.org",
            &[
                include_bytes!("data/cert-wikipedia.0.der"),
                include_bytes!("data/cert-wikipedia.1.der"),
            ],
        );
        b.iter(|| ctx.verify_once());
    }

    #[bench]
    fn google_cert(b: &mut test::Bencher) {
        let ctx = Context::new(
            &provider::DEFAULT_PROVIDER,
            "www.google.com",
            &[
                include_bytes!("data/cert-google.0.der"),
                include_bytes!("data/cert-google.1.der"),
                include_bytes!("data/cert-google.2.der"),
            ],
        );
        b.iter(|| ctx.verify_once());
    }

    #[bench]
    fn hn_cert(b: &mut test::Bencher) {
        let ctx = Context::new(
            &provider::DEFAULT_PROVIDER,
            "news.ycombinator.com",
            &[
                include_bytes!("data/cert-hn.0.der"),
                include_bytes!("data/cert-hn.1.der"),
            ],
        );
        b.iter(|| ctx.verify_once());
    }

    #[bench]
    fn stackoverflow_cert(b: &mut test::Bencher) {
        let ctx = Context::new(
            &provider::DEFAULT_PROVIDER,
            "stackoverflow.com",
            &[
                include_bytes!("data/cert-stackoverflow.0.der"),
                include_bytes!("data/cert-stackoverflow.1.der"),
            ],
        );
        b.iter(|| ctx.verify_once());
    }

    #[bench]
    fn duckduckgo_cert(b: &mut test::Bencher) {
        let ctx = Context::new(
            &provider::DEFAULT_PROVIDER,
            "duckduckgo.com",
            &[
                include_bytes!("data/cert-duckduckgo.0.der"),
                include_bytes!("data/cert-duckduckgo.1.der"),
                include_bytes!("data/cert-duckduckgo.2.der"),
            ],
        );
        b.iter(|| ctx.verify_once());
    }

    #[bench]
    fn rustlang_cert(b: &mut test::Bencher) {
        let ctx = Context::new(
            &provider::DEFAULT_PROVIDER,
            "www.rust-lang.org",
            &[
                include_bytes!("data/cert-rustlang.0.der"),
                include_bytes!("data/cert-rustlang.1.der"),
                include_bytes!("data/cert-rustlang.2.der"),
                include_bytes!("data/cert-rustlang.3.der"),
            ],
        );
        b.iter(|| ctx.verify_once());
    }

    #[bench]
    fn wapo_cert(b: &mut test::Bencher) {
        let ctx = Context::new(
            &provider::DEFAULT_PROVIDER,
            "www.washingtonpost.com",
            &[
                include_bytes!("data/cert-wapo.0.der"),
                include_bytes!("data/cert-wapo.1.der"),
            ],
        );
        b.iter(|| ctx.verify_once());
    }
}

struct Context {
    server_name: ServerName<'static>,
    chain: Vec<CertificateDer<'static>>,
    now: UnixTime,
    verifier: WebPkiServerVerifier,
}

impl Context {
    fn new(provider: &CryptoProvider, domain: &'static str, certs: &[&'static [u8]]) -> Self {
        let mut roots = RootCertStore::empty();
        roots.extend(
            webpki_roots::TLS_SERVER_ROOTS
                .iter()
                .cloned(),
        );
        Self {
            server_name: domain.try_into().unwrap(),
            chain: certs
                .iter()
                .copied()
                .map(|bytes| CertificateDer::from(bytes.to_vec()))
                .collect(),
            now: UnixTime::since_unix_epoch(Duration::from_secs(1_746_605_469)),
            verifier: WebPkiServerVerifier::builder(Arc::new(roots), provider)
                .build()
                .unwrap(),
        }
    }

    fn verify_once(&self) {
        self.verifier
            .verify_identity(&ServerIdentity::new(
                &Identity::X509(CertificateIdentity::new(
                    self.chain[0].clone(),
                    self.chain[1..].to_vec(),
                )),
                &self.server_name,
                self.now,
            ))
            .unwrap();
    }
}
