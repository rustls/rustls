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

use rustls::{Connection, VecInput};
use rustls_test::{MultiTest, do_handshake, make_pair_for_arc_configs, transfer};
use rustls_util::KeyLogFile;

use super::{provider, serialized};

#[test]
fn exercise_key_log_file_for_client() {
    serialized(|| {
        unsafe { env::set_var("SSLKEYLOGFILE", "./sslkeylogfile.txt") };

        for (client_config, server_config, _) in MultiTest::new(provider::DEFAULT_PROVIDER) {
            let mut client_config = Arc::unwrap_or_clone(client_config);
            client_config.key_log = Arc::new(KeyLogFile::new());
            let client_config = Arc::new(client_config);

            let (mut client, mut server) =
                make_pair_for_arc_configs(&client_config, &server_config);
            let mut client_input = VecInput::default();
            let mut server_input = VecInput::default();

            assert_eq!(5, client.writer().write(b"hello").unwrap());

            do_handshake(
                &mut client_input,
                &mut client,
                &mut server_input,
                &mut server,
            );
            transfer(&mut client, &mut server_input);
            server
                .process_new_packets(&mut server_input)
                .unwrap();
        }
    })
}

#[test]
fn exercise_key_log_file_for_server() {
    serialized(|| {
        unsafe { env::set_var("SSLKEYLOGFILE", "./sslkeylogfile.txt") };

        for (client_config, server_config, _) in MultiTest::new(provider::DEFAULT_PROVIDER) {
            let mut server_config = Arc::unwrap_or_clone(server_config);
            server_config.key_log = Arc::new(KeyLogFile::new());
            let server_config = Arc::new(server_config);

            let (mut client, mut server) =
                make_pair_for_arc_configs(&client_config, &server_config);
            let mut client_input = VecInput::default();
            let mut server_input = VecInput::default();

            assert_eq!(5, client.writer().write(b"hello").unwrap());

            do_handshake(
                &mut client_input,
                &mut client,
                &mut server_input,
                &mut server,
            );
            transfer(&mut client, &mut server_input);
            server
                .process_new_packets(&mut server_input)
                .unwrap();
        }
    })
}
