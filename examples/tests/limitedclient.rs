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
    assert!(
        !find_symbols_in_executable(
            |sym| sym.starts_with("aws_lc_") && sym.ends_with("_EVP_aead_aes_128_gcm_tls13"),
            env!("CARGO_BIN_EXE_simpleclient")
        )
        .is_empty()
    );
}

#[test]
fn simpleclient_contains_tls12_code() {
    assert!(
        !find_symbols_in_executable(
            |sym| sym.contains("rustls::client::tls12") && !sym.contains("core::fmt::Debug"),
            env!("CARGO_BIN_EXE_simpleclient")
        )
        .is_empty()
    );
}

#[test]
fn limitedclient_does_not_contain_aes_symbols() {
    let limitedclient = env!("CARGO_BIN_EXE_limitedclient");
    if fips_mode(limitedclient) {
        println!("FIPS mode includes the entirety of the fipsmodule due to dynamic linking");
        return;
    }

    assert_no_symbols_in_executable(
        |sym| sym.starts_with("aws_lc_") && sym.ends_with("_EVP_aead_aes_128_gcm_tls13"),
        limitedclient,
    );
}

#[test]
fn limitedclient_does_not_contain_tls12_code() {
    assert_no_symbols_in_executable(
        |sym| sym.contains("rustls::client::tls12") && !sym.contains("core::fmt::Debug"),
        env!("CARGO_BIN_EXE_limitedclient"),
    );
}

fn fips_mode(exe: &str) -> bool {
    symbols_in_executable(exe)
        .lines()
        .any(|sym| sym.starts_with("aws_lc_fips_"))
}

fn assert_no_symbols_in_executable(f: impl Fn(&str) -> bool, exe: &str) {
    let offending = find_symbols_in_executable(f, exe);
    assert!(
        offending.is_empty(),
        "found unexpected symbols in {exe}: {offending:#?}",
    );
}

fn find_symbols_in_executable(f: impl Fn(&str) -> bool, exe: &str) -> Vec<String> {
    let mut matching = Vec::new();

    for sym in symbols_in_executable(exe).lines() {
        //println!("candidate symbol {sym:?}");
        if f(sym) {
            matching.push(sym.trim().to_owned());
        }
    }

    matching
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
