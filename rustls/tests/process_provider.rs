#![cfg(any(feature = "ring", feature = "aws_lc_rs"))]

//! Note that the default test runner builds each test file into a separate
//! executable, and runs tests in an indeterminate order.  That restricts us
//! to doing all the desired tests, in series, in one function.

#[cfg(all(feature = "aws_lc_rs", not(feature = "ring")))]
use rustls::crypto::aws_lc_rs as provider;
#[cfg(all(feature = "ring", not(feature = "aws_lc_rs")))]
use rustls::crypto::ring as provider;
#[cfg(all(feature = "ring", feature = "aws_lc_rs"))]
use rustls::crypto::ring as provider;
use rustls::crypto::CryptoProvider;
use rustls::ClientConfig;

mod common;
use crate::common::*;

#[test]
fn test_process_provider() {
    if dbg!(cfg!(all(feature = "ring", feature = "aws_lc_rs"))) {
        test_explicit_choice_required();
    } else if dbg!(cfg!(all(feature = "ring", not(feature = "aws_lc_rs")))) {
        test_ring_used_as_implicit_provider();
    } else if dbg!(cfg!(all(feature = "aws_lc_rs", not(feature = "ring")))) {
        test_aws_lc_rs_used_as_implicit_provider();
    } else {
        panic!("fix feature combinations");
    }
}

fn test_explicit_choice_required() {
    assert!(CryptoProvider::get_default().is_none());
    provider::default_provider()
        .install_default()
        .expect("cannot install");
    CryptoProvider::get_default().expect("provider missing");
    provider::default_provider()
        .install_default()
        .expect_err("install succeeded a second time");
    CryptoProvider::get_default().expect("provider missing");

    // does not panic
    finish_client_config(KeyType::Rsa2048, ClientConfig::builder());
}

fn test_ring_used_as_implicit_provider() {
    assert!(CryptoProvider::get_default().is_none());

    // implicitly installs ring provider
    finish_client_config(KeyType::Rsa2048, ClientConfig::builder());

    assert!(format!(
        "{:?}",
        CryptoProvider::get_default().expect("provider missing")
    )
    .contains("secure_random: Ring"));
}

fn test_aws_lc_rs_used_as_implicit_provider() {
    assert!(CryptoProvider::get_default().is_none());

    // implicitly installs aws-lc-rs provider
    finish_client_config(KeyType::Rsa2048, ClientConfig::builder());

    assert!(format!(
        "{:?}",
        CryptoProvider::get_default().expect("provider missing")
    )
    .contains("secure_random: AwsLcRs"));
}
