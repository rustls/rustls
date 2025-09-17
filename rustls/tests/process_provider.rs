#![cfg(any(feature = "ring", feature = "aws-lc-rs"))]
#![allow(clippy::disallowed_types)]

//! Note that the default test runner builds each test file into a separate
//! executable, and runs tests in an indeterminate order.  That restricts us
//! to doing all the desired tests, in series, in one function.

use rustls::ClientConfig;
use rustls::crypto::DefaultCryptoProvider;
#[cfg(all(feature = "aws-lc-rs", not(feature = "ring")))]
use rustls::crypto::aws_lc_rs as provider;
#[cfg(all(feature = "ring", not(feature = "aws-lc-rs")))]
use rustls::crypto::ring as provider;
#[cfg(all(feature = "ring", feature = "aws-lc-rs"))]
use rustls::crypto::ring as provider;

mod common;
use crate::common::*;

#[test]
fn test_process_provider() {
    if dbg!(cfg!(all(feature = "ring", feature = "aws-lc-rs"))) {
        test_explicit_choice_required();
    } else if dbg!(cfg!(all(feature = "ring", not(feature = "aws-lc-rs")))) {
        test_ring_used_as_implicit_provider();
    } else if dbg!(cfg!(all(feature = "aws-lc-rs", not(feature = "ring")))) {
        test_aws_lc_rs_used_as_implicit_provider();
    } else {
        panic!("fix feature combinations");
    }
}

fn test_explicit_choice_required() {
    assert!(DefaultCryptoProvider::get().is_none());
    DefaultCryptoProvider::install(Arc::new(provider::default_provider())).expect("cannot install");
    DefaultCryptoProvider::get().expect("provider missing");
    DefaultCryptoProvider::install(Arc::new(provider::default_provider()))
        .expect_err("install succeeded a second time");
    DefaultCryptoProvider::get().expect("provider missing");

    // does not panic
    ClientConfig::builder().finish(KeyType::Rsa2048);
}

fn test_ring_used_as_implicit_provider() {
    assert!(DefaultCryptoProvider::get().is_none());

    // implicitly installs ring provider
    ClientConfig::builder().finish(KeyType::Rsa2048);

    let default = DefaultCryptoProvider::get().expect("provider missing");
    let debug = format!("{default:?}");
    assert!(debug.contains("secure_random: Ring"));

    let builder = ClientConfig::builder();
    assert_eq!(format!("{:?}", builder.crypto_provider()), debug);
}

fn test_aws_lc_rs_used_as_implicit_provider() {
    assert!(DefaultCryptoProvider::get().is_none());

    // implicitly installs aws-lc-rs provider
    ClientConfig::builder().finish(KeyType::Rsa2048);

    let default = DefaultCryptoProvider::get().expect("provider missing");
    let debug = format!("{default:?}");
    assert!(debug.contains("secure_random: AwsLcRs"));

    let builder = ClientConfig::builder();
    assert_eq!(format!("{:?}", builder.crypto_provider()), debug);
}
