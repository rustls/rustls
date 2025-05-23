//! Tests of [`rustls::KeyLogFile`] that require us to set environment variables.
//!
//!                                 vvvv
//! Every test you add to this file MUST execute through `serialized()`.
//!                                 ^^^^
//!
//! See https://github.com/rust-lang/rust/issues/90308; despite not being marked
//! `unsafe`, `env::var::set_var` is an unsafe function. These tests are separated
//! from the rest of the tests so that their use of `set_ver` is less likely to
//! affect them; as of the time these tests were moved to this file, Cargo will
//! compile each test suite file to a separate executable, so these will be run
//! in a completely separate process. This way, executing every test through
//! `serialized()` will cause them to be run one at a time.
//!
//! Note: If/when we add new constructors to `KeyLogFile` to allow constructing
//! one from a path directly (without using an environment variable), then those
//! tests SHOULD NOT go in this file.
//!
//! XXX: These tests don't actually test the functionality; they just ensure
//! the code coverage doesn't complain it isn't covered. TODO: Verify that the
//! file was created successfully, with the right permissions, etc., and that it
//! contains something like what we expect.

#![allow(clippy::duplicate_mod)]

use std::env;
use std::io::Write;

use super::*;

mod common;
use common::{
    Arc, KeyType, do_handshake, make_client_config_with_versions, make_pair_for_arc_configs,
    make_server_config, transfer,
};

#[test]
fn exercise_key_log_file_for_client() {
    serialized(|| {
        let provider = provider::default_provider();
        let server_config = Arc::new(make_server_config(KeyType::Rsa2048, &provider));
        unsafe { env::set_var("SSLKEYLOGFILE", "./sslkeylogfile.txt") };

        for version in rustls::ALL_VERSIONS {
            let mut client_config =
                make_client_config_with_versions(KeyType::Rsa2048, &[version], &provider);
            client_config.key_log = Arc::new(rustls::KeyLogFile::new());

            let (mut client, mut server) =
                make_pair_for_arc_configs(&Arc::new(client_config), &server_config);

            assert_eq!(5, client.writer().write(b"hello").unwrap());

            do_handshake(&mut client, &mut server);
            transfer(&mut client, &mut server);
            server.process_new_packets().unwrap();
        }
    })
}

#[test]
fn exercise_key_log_file_for_server() {
    serialized(|| {
        let provider = provider::default_provider();
        let mut server_config = make_server_config(KeyType::Rsa2048, &provider);

        unsafe { env::set_var("SSLKEYLOGFILE", "./sslkeylogfile.txt") };
        server_config.key_log = Arc::new(rustls::KeyLogFile::new());

        let server_config = Arc::new(server_config);

        for version in rustls::ALL_VERSIONS {
            let client_config =
                make_client_config_with_versions(KeyType::Rsa2048, &[version], &provider);
            let (mut client, mut server) =
                make_pair_for_arc_configs(&Arc::new(client_config), &server_config);

            assert_eq!(5, client.writer().write(b"hello").unwrap());

            do_handshake(&mut client, &mut server);
            transfer(&mut client, &mut server);
            server.process_new_packets().unwrap();
        }
    })
}
