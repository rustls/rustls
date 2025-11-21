//! Check that `limitedclient` is successful in its goal of not linking in any
//! AES code.
//!
//! We also check `simpleclient` (which includes everything) as a baseline to
//! detect errors in the test code.

// Don't assume binutils are available everywhere, or that `nm` has a
// portable interface.
#![cfg(target_os = "linux")]

use std::process::Command;

#[test]
fn simpleclient_contains_aes_symbols() {
    assert!(count_aes_symbols_in_executable(env!("CARGO_BIN_EXE_simpleclient")) > 0);
}

#[test]
fn simpleclient_contains_tls12_code() {
    assert!(count_tls12_client_symbols_in_executable(env!("CARGO_BIN_EXE_simpleclient")) > 0);
}

#[test]
fn limitedclient_does_not_contain_aes_symbols() {
    let limitedclient = env!("CARGO_BIN_EXE_limitedclient");
    if fips_mode(limitedclient) {
        println!("FIPS mode includes the entirety of the fipsmodule due to dynamic linking");
        return;
    }
    assert_eq!(count_aes_symbols_in_executable(limitedclient), 0);
}

#[test]
fn limitedclient_does_not_contain_tls12_code() {
    assert_eq!(
        count_tls12_client_symbols_in_executable(env!("CARGO_BIN_EXE_limitedclient")),
        0
    );
}

fn fips_mode(exe: &str) -> bool {
    symbols_in_executable(exe)
        .lines()
        .any(|sym| sym.starts_with("aws_lc_fips_"))
}

fn count_aes_symbols_in_executable(exe: &str) -> usize {
    let mut count = 0;

    for sym in symbols_in_executable(exe).lines() {
        //println!("candidate symbol {sym:?}");

        if sym.starts_with("aws_lc_") && sym.ends_with("_EVP_aead_aes_128_gcm_tls13") {
            println!("found aes symbol {sym:?}");
            count += 1;
        }
    }

    count
}

fn count_tls12_client_symbols_in_executable(exe: &str) -> usize {
    let mut count = 0;

    for sym in symbols_in_executable(exe).lines() {
        //println!("candidate symbol {sym:?}");

        if sym.contains("rustls::client::tls12") && !sym.contains("core::fmt::Debug") {
            println!("found tls12 symbol {sym:?}");
            count += 1;
        }
    }

    count
}

fn symbols_in_executable(exe: &str) -> String {
    let nm_output = dbg!(
        Command::new("nm")
            .arg("--defined-only")
            .arg("--demangle")
            .arg("--format=just-symbols")
            .arg(exe)
    )
    .output()
    .expect("nm failed");

    String::from_utf8(nm_output.stdout).expect("nm output not valid utf8")
}
