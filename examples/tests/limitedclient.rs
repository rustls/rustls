//! Check that `limitedclient` is successful in its goal of not linking in any
//! AES code.
//!
//! We also check `simpleclient` (which includes everything) as a baseline to
//! detect errors in the test code.

// Don't assume binutils are available everywhere, or that `nm` has a
// portable interface.
#![cfg(any(target_os = "linux", target_os = "macos"))]

use std::process::Command;

#[test]
fn limited_no_aes_symbols() {
    let aws_aes = |sym: &str| {
        (sym.starts_with("aws_lc_") || sym.starts_with("_aws_lc_"))
            && sym.ends_with("_EVP_aead_aes_128_gcm_tls13")
    };
    let expected = find_symbols_in_executable(aws_aes, env!("CARGO_BIN_EXE_simpleclient"));
    assert!(!expected.is_empty());

    let limited = env!("CARGO_BIN_EXE_limitedclient");
    let mut unexpected = find_symbols_in_executable(aws_aes, limited);
    unexpected.retain(|sym| !sym.starts_with("aws_lc_fips_") && !sym.starts_with("_aws_lc_fips_"));
    assert!(
        unexpected.is_empty(),
        "found unexpected symbols in {limited}: {unexpected:#?}",
    );
}

#[test]
fn limited_no_tls12_symbols() {
    let tls12 =
        |sym: &str| sym.contains("rustls::client::tls12") && !sym.contains("core::fmt::Debug");
    let expected = find_symbols_in_executable(tls12, env!("CARGO_BIN_EXE_simpleclient"));
    assert!(!expected.is_empty());

    let limited = env!("CARGO_BIN_EXE_limitedclient");
    let unexpected = find_symbols_in_executable(tls12, limited);
    assert!(
        unexpected.is_empty(),
        "found unexpected symbols in {limited}: {unexpected:#?}",
    );
}

fn find_symbols_in_executable(f: impl Fn(&str) -> bool, exe: &str) -> Vec<String> {
    let nm_output = dbg!(
        Command::new("nm")
            .arg("--defined-only")
            .arg("--demangle")
            .arg("--format=just-symbols")
            .arg(exe)
    )
    .output()
    .expect("nm failed");

    let mut matching = Vec::new();
    let symbols = String::from_utf8(nm_output.stdout).expect("nm output not valid utf8");
    for sym in symbols.lines() {
        //println!("candidate symbol {sym:?}");
        if f(sym) {
            matching.push(sym.trim().to_owned());
        }
    }

    matching
}
