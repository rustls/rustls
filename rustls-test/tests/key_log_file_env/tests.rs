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
use std::sync::Arc;

use rustls::{Connection, TlsInputBuffer};
use rustls_test::{
    KeyType, do_handshake, make_client_config, make_pair_for_arc_configs, make_server_config,
    transfer,
};
use rustls_util::KeyLogFile;

use super::{ALL_VERSIONS, provider, serialized};

#[test]
fn exercise_key_log_file_for_client() {
    serialized(|| {
        let provider = provider::DEFAULT_PROVIDER;
        let server_config = Arc::new(make_server_config(KeyType::Rsa2048, &provider));
        unsafe { env::set_var("SSLKEYLOGFILE", "./sslkeylogfile.txt") };

        for version_provider in ALL_VERSIONS {
            let mut client_config = make_client_config(KeyType::Rsa2048, &version_provider);
            client_config.key_log = Arc::new(KeyLogFile::new());

            let (mut client, mut server) =
                make_pair_for_arc_configs(&Arc::new(client_config), &server_config);
            let mut client_buf = TlsInputBuffer::default();
            let mut server_buf = TlsInputBuffer::default();

            assert_eq!(5, client.writer().write(b"hello").unwrap());

            do_handshake(&mut client_buf, &mut client, &mut server_buf, &mut server);
            transfer(&mut client, &mut server_buf, &mut server);
            server
                .process_new_packets(&mut server_buf)
                .unwrap();
        }
    })
}

#[test]
fn exercise_key_log_file_for_server() {
    serialized(|| {
        let mut server_config = make_server_config(KeyType::Rsa2048, &provider::DEFAULT_PROVIDER);

        unsafe { env::set_var("SSLKEYLOGFILE", "./sslkeylogfile.txt") };
        server_config.key_log = Arc::new(KeyLogFile::new());

        let server_config = Arc::new(server_config);

        for version_provider in ALL_VERSIONS {
            let client_config = make_client_config(KeyType::Rsa2048, &version_provider);
            let (mut client, mut server) =
                make_pair_for_arc_configs(&Arc::new(client_config), &server_config);
            let mut client_buf = TlsInputBuffer::default();
            let mut server_buf = TlsInputBuffer::default();

            assert_eq!(5, client.writer().write(b"hello").unwrap());

            do_handshake(&mut client_buf, &mut client, &mut server_buf, &mut server);
            transfer(&mut client, &mut server_buf, &mut server);
            server
                .process_new_packets(&mut server_buf)
                .unwrap();
        }
    })
}
