//! Tests for the kernel connection API.
//!
//! See [`rustls::kernel`] for what this API is for.

#![allow(clippy::disallowed_types, clippy::duplicate_mod)]

use std::sync::Arc;

use rustls::client::ClientSide;
use rustls::enums::ProtocolVersion;
use rustls::error::ApiMisuse;
use rustls::kernel::KernelConnection;
use rustls::server::ServerSide;
use rustls::{ClientConfig, ConnectionTrafficSecrets, ExtractedSecrets, ServerConfig, VecInput};
use rustls_test::{MultiTest, do_handshake, make_pair_for_configs};

use super::provider;

#[test]
fn kernel_connection() {
    for (client_config, server_config, expect) in MultiTest::new(provider::DEFAULT_PROVIDER) {
        let ((client_secrets, mut client_kernel), (server_secrets, mut server_kernel)) =
            kernel_pair(client_config, server_config);

        // the negotiated facts survive the transition
        assert_eq!(client_kernel.protocol_version(), expect.version);
        assert_eq!(server_kernel.protocol_version(), expect.version);
        assert_eq!(
            client_kernel
                .negotiated_cipher_suite()
                .suite(),
            server_kernel
                .negotiated_cipher_suite()
                .suite()
        );

        // the extracted secrets agree, in both directions
        let client_tx = Secrets::new(client_secrets.tx);
        let client_rx = Secrets::new(client_secrets.rx);
        assert_eq!(client_tx, Secrets::new(server_secrets.rx));
        assert_eq!(client_rx, Secrets::new(server_secrets.tx));

        // Key update tests below are TLS1.3-only
        let ProtocolVersion::TLSv1_3 = expect.version else {
            assert_eq!(
                client_kernel.update_tx_secret().err(),
                Some(ApiMisuse::KeyUpdateNotAvailableForTls12.into())
            );
            assert_eq!(
                server_kernel.update_tx_secret().err(),
                Some(ApiMisuse::KeyUpdateNotAvailableForTls12.into())
            );

            assert_eq!(
                client_kernel.update_rx_secret().err(),
                Some(ApiMisuse::KeyUpdateNotAvailableForTls12.into())
            );
            assert_eq!(
                server_kernel.update_rx_secret().err(),
                Some(ApiMisuse::KeyUpdateNotAvailableForTls12.into())
            );
            continue;
        };

        // and so do the secrets each end derives for a key update
        let client_tx_next = Secrets::new(
            client_kernel
                .update_tx_secret()
                .unwrap(),
        );
        assert_eq!(
            client_tx_next,
            Secrets::new(
                server_kernel
                    .update_rx_secret()
                    .unwrap()
            )
        );

        let client_rx_next = Secrets::new(
            client_kernel
                .update_rx_secret()
                .unwrap(),
        );
        assert_eq!(
            client_rx_next,
            Secrets::new(
                server_kernel
                    .update_tx_secret()
                    .unwrap()
            )
        );

        // the key update really rolled the keys, and restarted the sequence
        assert_ne!(client_tx_next.key, client_tx.key);
        assert_ne!(client_tx_next.iv, client_tx.iv);
        assert_ne!(client_rx_next.key, client_rx.key);
        assert_ne!(client_rx_next.iv, client_rx.iv);
        assert_eq!(client_tx_next.seq, 0);
        assert_eq!(client_rx_next.seq, 0);
    }
}

fn kernel_pair(
    client_config: Arc<ClientConfig>,
    server_config: Arc<ServerConfig>,
) -> (
    (ExtractedSecrets, KernelConnection<ClientSide>),
    (ExtractedSecrets, KernelConnection<ServerSide>),
) {
    // secret extraction must be opted into by both ends
    let mut client_config = Arc::unwrap_or_clone(client_config);
    client_config.enable_secret_extraction = true;
    let mut server_config = Arc::unwrap_or_clone(server_config);
    server_config.enable_secret_extraction = true;

    let (mut client, mut server) = make_pair_for_configs(client_config, server_config);
    do_handshake(
        &mut VecInput::default(),
        &mut client,
        &mut VecInput::default(),
        &mut server,
    );

    (
        client
            .split()
            .unwrap()
            .dangerous_into_kernel_connection()
            .unwrap(),
        server
            .split()
            .unwrap()
            .dangerous_into_kernel_connection()
            .unwrap(),
    )
}

/// `ConnectionTrafficSecrets` counterpart that does `Debug` and `PartialEq`
#[derive(Debug, PartialEq)]
struct Secrets {
    seq: u64,
    key: Vec<u8>,
    iv: Vec<u8>,
}

impl Secrets {
    fn new((seq, secrets): (u64, ConnectionTrafficSecrets)) -> Self {
        match secrets {
            ConnectionTrafficSecrets::Aes128Gcm { key, iv } => Self {
                seq,
                key: key.as_ref().to_vec(),
                iv: iv.as_ref().to_vec(),
            },
            _ => panic!("unexpected secret type"),
        }
    }
}
