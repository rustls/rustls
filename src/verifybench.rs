// This program does benchmarking of the functions in verify.rs,
// that do certificate chain validation and signature verification.
//
// Note: we don't use any of the standard 'cargo bench', 'test::Bencher',
// etc. because it's unstable at the time of writing.

use std::time::{Duration, Instant};

use anchors;
use verify;
use verify::ServerCertVerifier;
use key;

extern crate webpki_roots;

fn duration_nanos(d: Duration) -> u64 {
    ((d.as_secs() as f64) * 1e9 + (d.subsec_nanos() as f64)) as u64
}

fn bench<Fsetup, Ftest, S>(count: usize, name: &'static str, f_setup: Fsetup, f_test: Ftest)
    where Fsetup: Fn() -> S,
          Ftest: Fn(S)
{
    let mut times = Vec::new();

    for _ in 0..count {
        let state = f_setup();
        let start = Instant::now();
        f_test(state);
        times.push(duration_nanos(Instant::now().duration_since(start)));
    }

    println!("{}: min {:?}us",
             name,
             times.iter().min().unwrap() / 1000);
}

static V: &'static verify::WebPKIVerifier = &verify::WebPKIVerifier {};

#[test]
fn test_reddit_cert() {
    let cert0 = key::Certificate(include_bytes!("testdata/cert-reddit.0.der").to_vec());
    let cert1 = key::Certificate(include_bytes!("testdata/cert-reddit.1.der").to_vec());
    let chain = [ cert0, cert1 ];
    let mut anchors = anchors::RootCertStore::empty();
    anchors.add_trust_anchors(&webpki_roots::ROOTS);
    bench(100, "verify_server_cert(reddit)", 
          || (),
          |_| V.verify_server_cert(&anchors, &chain[..], "reddit.com", &[]).unwrap());
}

#[test]
fn test_github_cert() {
    let cert0 = key::Certificate(include_bytes!("testdata/cert-github.0.der").to_vec());
    let cert1 = key::Certificate(include_bytes!("testdata/cert-github.1.der").to_vec());
    let chain = [ cert0, cert1 ];
    let mut anchors = anchors::RootCertStore::empty();
    anchors.add_trust_anchors(&webpki_roots::ROOTS);
    bench(100, "verify_server_cert(github)", 
          || (),
          |_| V.verify_server_cert(&anchors, &chain[..], "github.com", &[]).unwrap());
}

#[test]
fn test_arstechnica_cert() {
    let cert0 = key::Certificate(include_bytes!("testdata/cert-arstechnica.0.der").to_vec());
    let cert1 = key::Certificate(include_bytes!("testdata/cert-arstechnica.1.der").to_vec());
    let cert2 = key::Certificate(include_bytes!("testdata/cert-arstechnica.2.der").to_vec());
    let chain = [ cert0, cert1, cert2 ];
    let mut anchors = anchors::RootCertStore::empty();
    anchors.add_trust_anchors(&webpki_roots::ROOTS);
    bench(100, "verify_server_cert(arstechnica)", 
          || (),
          |_| V.verify_server_cert(&anchors, &chain[..], "arstechnica.com", &[]).unwrap());
}

#[test]
fn test_servo_cert() {
    let cert0 = key::Certificate(include_bytes!("testdata/cert-servo.0.der").to_vec());
    let cert1 = key::Certificate(include_bytes!("testdata/cert-servo.1.der").to_vec());
    let cert2 = key::Certificate(include_bytes!("testdata/cert-servo.2.der").to_vec());
    let chain = [ cert0, cert1, cert2 ];
    let mut anchors = anchors::RootCertStore::empty();
    anchors.add_trust_anchors(&webpki_roots::ROOTS);
    bench(100, "verify_server_cert(servo)", 
          || (),
          |_| V.verify_server_cert(&anchors, &chain[..], "servo.org", &[]).unwrap());
}

#[test]
fn test_twitter_cert() {
    let cert0 = key::Certificate(include_bytes!("testdata/cert-twitter.0.der").to_vec());
    let cert1 = key::Certificate(include_bytes!("testdata/cert-twitter.1.der").to_vec());
    let chain = [ cert0, cert1 ];
    let mut anchors = anchors::RootCertStore::empty();
    anchors.add_trust_anchors(&webpki_roots::ROOTS);
    bench(100, "verify_server_cert(twitter)", 
          || (),
          |_| V.verify_server_cert(&anchors, &chain[..], "twitter.com", &[]).unwrap());
}

#[test]
fn test_wikipedia_cert() {
    let cert0 = key::Certificate(include_bytes!("testdata/cert-wikipedia.0.der").to_vec());
    let cert1 = key::Certificate(include_bytes!("testdata/cert-wikipedia.1.der").to_vec());
    let chain = [ cert0, cert1 ];
    let mut anchors = anchors::RootCertStore::empty();
    anchors.add_trust_anchors(&webpki_roots::ROOTS);
    bench(100, "verify_server_cert(wikipedia)", 
          || (),
          |_| V.verify_server_cert(&anchors, &chain[..], "wikipedia.org", &[]).unwrap());
}

#[test]
fn test_google_cert() {
    let cert0 = key::Certificate(include_bytes!("testdata/cert-google.0.der").to_vec());
    let cert1 = key::Certificate(include_bytes!("testdata/cert-google.1.der").to_vec());
    let cert2 = key::Certificate(include_bytes!("testdata/cert-google.2.der").to_vec());
    let chain = [ cert0, cert1, cert2 ];
    let mut anchors = anchors::RootCertStore::empty();
    anchors.add_trust_anchors(&webpki_roots::ROOTS);
    bench(100, "verify_server_cert(google)", 
          || (),
          |_| V.verify_server_cert(&anchors, &chain[..], "www.google.com", &[]).unwrap());
}

#[test]
fn test_hn_cert() {
    let cert0 = key::Certificate(include_bytes!("testdata/cert-hn.0.der").to_vec());
    let cert1 = key::Certificate(include_bytes!("testdata/cert-hn.1.der").to_vec());
    let cert2 = key::Certificate(include_bytes!("testdata/cert-hn.2.der").to_vec());
    let chain = [ cert0, cert1, cert2 ];
    let mut anchors = anchors::RootCertStore::empty();
    anchors.add_trust_anchors(&webpki_roots::ROOTS);
    bench(100, "verify_server_cert(hn)", 
          || (),
          |_| V.verify_server_cert(&anchors, &chain[..], "news.ycombinator.com", &[]).unwrap());
}

#[test]
fn test_stackoverflow_cert() {
    let cert0 = key::Certificate(include_bytes!("testdata/cert-stackoverflow.0.der").to_vec());
    let cert1 = key::Certificate(include_bytes!("testdata/cert-stackoverflow.1.der").to_vec());
    let chain = [ cert0, cert1 ];
    let mut anchors = anchors::RootCertStore::empty();
    anchors.add_trust_anchors(&webpki_roots::ROOTS);
    bench(100, "verify_server_cert(stackoverflow)", 
          || (),
          |_| V.verify_server_cert(&anchors, &chain[..], "stackoverflow.com", &[]).unwrap());
}

#[test]
fn test_duckduckgo_cert() {
    let cert0 = key::Certificate(include_bytes!("testdata/cert-duckduckgo.0.der").to_vec());
    let cert1 = key::Certificate(include_bytes!("testdata/cert-duckduckgo.1.der").to_vec());
    let chain = [ cert0, cert1 ];
    let mut anchors = anchors::RootCertStore::empty();
    anchors.add_trust_anchors(&webpki_roots::ROOTS);
    bench(100, "verify_server_cert(duckduckgo)", 
          || (),
          |_| V.verify_server_cert(&anchors, &chain[..], "duckduckgo.com", &[]).unwrap());
}

#[test]
fn test_rustlang_cert() {
    let cert0 = key::Certificate(include_bytes!("testdata/cert-rustlang.0.der").to_vec());
    let cert1 = key::Certificate(include_bytes!("testdata/cert-rustlang.1.der").to_vec());
    let cert2 = key::Certificate(include_bytes!("testdata/cert-rustlang.2.der").to_vec());
    let chain = [ cert0, cert1, cert2 ];
    let mut anchors = anchors::RootCertStore::empty();
    anchors.add_trust_anchors(&webpki_roots::ROOTS);
    bench(100, "verify_server_cert(rustlang)", 
          || (),
          |_| V.verify_server_cert(&anchors, &chain[..], "www.rust-lang.org", &[]).unwrap());
}

#[test]
fn test_wapo_cert() {
    let cert0 = key::Certificate(include_bytes!("testdata/cert-wapo.0.der").to_vec());
    let cert1 = key::Certificate(include_bytes!("testdata/cert-wapo.1.der").to_vec());
    let cert2 = key::Certificate(include_bytes!("testdata/cert-wapo.2.der").to_vec());
    let chain = [ cert0, cert1, cert2 ];
    let mut anchors = anchors::RootCertStore::empty();
    anchors.add_trust_anchors(&webpki_roots::ROOTS);
    bench(100, "verify_server_cert(wapo)", 
          || (),
          |_| V.verify_server_cert(&anchors, &chain[..], "www.washingtonpost.com", &[]).unwrap());
}

