//! Tests for QUIC

#![allow(clippy::disallowed_types, clippy::duplicate_mod)]

use std::sync::Arc;

use rustls::client::Resumption;
use rustls::error::{AlertDescription, ApiMisuse, Error, PeerIncompatible, PeerMisbehaved};
use rustls::quic::{self, ConnectionCommon};
use rustls::{HandshakeKind, Side, SideData};
use rustls_test::{
    ClientStorage, KeyType, encoding, make_client_config, make_server_config, server_name,
};

use super::provider;

// Returns the sender's next secrets to use, or the receiver's error.
fn step<L: SideData, R: SideData>(
    send: &mut ConnectionCommon<L>,
    recv: &mut ConnectionCommon<R>,
) -> Result<Option<quic::KeyChange>, Error> {
    let mut buf = Vec::new();
    let change = loop {
        let prev = buf.len();
        if let Some(x) = send.write_hs(&mut buf) {
            break Some(x);
        }
        if prev == buf.len() {
            break None;
        }
    };

    recv.read_hs(&buf)?;
    assert_eq!(recv.alert(), None);
    Ok(change)
}

#[test]
fn test_quic_handshake() {
    fn equal_packet_keys(x: &dyn quic::PacketKey, y: &dyn quic::PacketKey) -> bool {
        // Check that these two sets of keys are equal.
        let mut buf = [0; 32];
        let (header, payload_tag) = buf.split_at_mut(8);
        let (payload, tag_buf) = payload_tag.split_at_mut(8);
        let tag = x
            .encrypt_in_place(42, header, payload, None)
            .unwrap();
        tag_buf.copy_from_slice(tag.as_ref());

        let result = y.decrypt_in_place(42, header, payload_tag, None);
        match result {
            Ok(payload) => payload == [0; 8],
            Err(_) => false,
        }
    }

    fn compatible_keys(x: &quic::KeyChange, y: &quic::KeyChange) -> bool {
        fn keys(kc: &quic::KeyChange) -> &quic::Keys {
            match kc {
                quic::KeyChange::Handshake { keys } => keys,
                quic::KeyChange::OneRtt { keys, .. } => keys,
            }
        }

        let (x, y) = (keys(x), keys(y));
        equal_packet_keys(x.local.packet.as_ref(), y.remote.packet.as_ref())
            && equal_packet_keys(x.remote.packet.as_ref(), y.local.packet.as_ref())
    }

    let kt = KeyType::Rsa2048;
    let provider = provider::DEFAULT_TLS13_PROVIDER;
    let mut client_config = make_client_config(kt, &provider);
    client_config.enable_early_data = true;
    let client_config = Arc::new(client_config);
    let mut server_config = make_server_config(kt, &provider);
    server_config.max_early_data_size = 0xffffffff;
    let server_config = Arc::new(server_config);
    let client_params = &b"client params"[..];
    let server_params = &b"server params"[..];

    // full handshake
    let mut client = quic::ClientConnection::new(
        client_config.clone(),
        quic::Version::V1,
        server_name("localhost"),
        client_params.into(),
    )
    .unwrap();

    let mut server = quic::ServerConnection::new(
        server_config.clone(),
        quic::Version::V1,
        server_params.into(),
    )
    .unwrap();

    let client_initial = step(&mut client, &mut server).unwrap();
    assert!(client_initial.is_none());
    assert!(client.zero_rtt_keys().is_none());
    assert_eq!(server.quic_transport_parameters(), Some(client_params));
    let server_hs = step(&mut server, &mut client)
        .unwrap()
        .unwrap();
    assert!(server.zero_rtt_keys().is_none());
    let client_hs = step(&mut client, &mut server)
        .unwrap()
        .unwrap();
    assert!(compatible_keys(&server_hs, &client_hs));
    assert!(client.is_handshaking());
    let server_1rtt = step(&mut server, &mut client)
        .unwrap()
        .unwrap();
    assert!(!client.is_handshaking());
    assert_eq!(client.quic_transport_parameters(), Some(server_params));
    assert!(server.is_handshaking());
    let client_1rtt = step(&mut client, &mut server)
        .unwrap()
        .unwrap();
    assert!(!server.is_handshaking());
    assert!(compatible_keys(&server_1rtt, &client_1rtt));
    assert!(!compatible_keys(&server_hs, &server_1rtt));

    assert!(
        step(&mut client, &mut server)
            .unwrap()
            .is_none()
    );
    assert!(
        step(&mut server, &mut client)
            .unwrap()
            .is_none()
    );
    assert_eq!(client.tls13_tickets_received(), 2);

    // 0-RTT handshake
    let mut client = quic::ClientConnection::new(
        client_config.clone(),
        quic::Version::V1,
        server_name("localhost"),
        client_params.into(),
    )
    .unwrap();
    assert!(
        client
            .negotiated_cipher_suite()
            .is_some()
    );

    let mut server = quic::ServerConnection::new(
        server_config.clone(),
        quic::Version::V1,
        server_params.into(),
    )
    .unwrap();

    step(&mut client, &mut server).unwrap();
    assert_eq!(client.quic_transport_parameters(), Some(server_params));
    {
        let client_early = client.zero_rtt_keys().unwrap();
        let server_early = server.zero_rtt_keys().unwrap();
        assert!(equal_packet_keys(
            client_early.packet.as_ref(),
            server_early.packet.as_ref()
        ));
    }
    step(&mut server, &mut client)
        .unwrap()
        .unwrap();
    step(&mut client, &mut server)
        .unwrap()
        .unwrap();
    step(&mut server, &mut client)
        .unwrap()
        .unwrap();
    assert!(client.is_early_data_accepted());
    // 0-RTT rejection
    {
        let client_config = (*client_config).clone();
        let mut client = quic::ClientConnection::new(
            Arc::new(client_config),
            quic::Version::V1,
            server_name("localhost"),
            client_params.into(),
        )
        .unwrap();

        let mut server = quic::ServerConnection::new(
            server_config.clone(),
            quic::Version::V1,
            server_params.into(),
        )
        .unwrap();
        server.reject_early_data();

        step(&mut client, &mut server).unwrap();
        assert_eq!(client.quic_transport_parameters(), Some(server_params));
        assert!(client.zero_rtt_keys().is_some());
        assert!(server.zero_rtt_keys().is_none());
        step(&mut server, &mut client)
            .unwrap()
            .unwrap();
        step(&mut client, &mut server)
            .unwrap()
            .unwrap();
        step(&mut server, &mut client)
            .unwrap()
            .unwrap();
        assert!(!client.is_early_data_accepted());
    }

    // failed handshake
    let mut client = quic::ClientConnection::new(
        client_config,
        quic::Version::V1,
        server_name("example.com"),
        client_params.into(),
    )
    .unwrap();

    let mut server =
        quic::ServerConnection::new(server_config, quic::Version::V1, server_params.into())
            .unwrap();

    step(&mut client, &mut server).unwrap();
    step(&mut server, &mut client)
        .unwrap()
        .unwrap();
    assert!(step(&mut server, &mut client).is_err());
    assert_eq!(client.alert(), Some(AlertDescription::BadCertificate));

    // Key updates

    let (
        quic::KeyChange::OneRtt {
            next: mut client_secrets,
            ..
        },
        quic::KeyChange::OneRtt {
            next: mut server_secrets,
            ..
        },
    ) = (client_1rtt, server_1rtt)
    else {
        unreachable!();
    };

    let mut client_next = client_secrets.next_packet_keys();
    let mut server_next = server_secrets.next_packet_keys();
    assert!(equal_packet_keys(
        client_next.local.as_ref(),
        server_next.remote.as_ref()
    ));
    assert!(equal_packet_keys(
        server_next.local.as_ref(),
        client_next.remote.as_ref()
    ));

    client_next = client_secrets.next_packet_keys();
    server_next = server_secrets.next_packet_keys();
    assert!(equal_packet_keys(
        client_next.local.as_ref(),
        server_next.remote.as_ref()
    ));
    assert!(equal_packet_keys(
        server_next.local.as_ref(),
        client_next.remote.as_ref()
    ));
}

#[test]
fn test_quic_rejects_missing_alpn() {
    let client_params = &b"client params"[..];
    let server_params = &b"server params"[..];
    let provider = provider::DEFAULT_TLS13_PROVIDER;

    for &kt in KeyType::all_for_provider(&provider) {
        let client_config = make_client_config(kt, &provider);
        let client_config = Arc::new(client_config);

        let mut server_config = make_server_config(kt, &provider);
        server_config.alpn_protocols = vec!["foo".into()];
        let server_config = Arc::new(server_config);

        let mut client = quic::ClientConnection::new(
            client_config,
            quic::Version::V1,
            server_name("localhost"),
            client_params.into(),
        )
        .unwrap();
        let mut server =
            quic::ServerConnection::new(server_config, quic::Version::V1, server_params.into())
                .unwrap();

        assert_eq!(
            step(&mut client, &mut server)
                .err()
                .unwrap(),
            Error::NoApplicationProtocol
        );

        assert_eq!(
            server.alert(),
            Some(AlertDescription::NoApplicationProtocol)
        );
    }
}

#[test]
fn test_quic_no_tls13_error() {
    let provider = provider::DEFAULT_TLS12_PROVIDER;
    let mut client_config = make_client_config(KeyType::Ed25519, &provider);
    client_config.alpn_protocols = vec!["foo".into()];
    let client_config = Arc::new(client_config);

    assert!(
        quic::ClientConnection::new(
            client_config,
            quic::Version::V1,
            server_name("localhost"),
            b"client params".to_vec(),
        )
        .is_err()
    );

    let mut server_config = make_server_config(KeyType::Ed25519, &provider);
    server_config.alpn_protocols = vec!["foo".into()];
    let server_config = Arc::new(server_config);

    assert!(
        quic::ServerConnection::new(server_config, quic::Version::V1, b"server params".to_vec(),)
            .is_err()
    );
}

#[test]
fn test_quic_invalid_early_data_size() {
    let provider = provider::DEFAULT_TLS13_PROVIDER;
    let mut server_config = make_server_config(KeyType::Ed25519, &provider);
    server_config.alpn_protocols = vec!["foo".into()];

    let cases = [
        (None, true),
        (Some(0u32), true),
        (Some(5), false),
        (Some(0xffff_ffff), true),
    ];

    for &(size, ok) in cases.iter() {
        println!("early data size case: {size:?}");
        if let Some(new) = size {
            server_config.max_early_data_size = new;
        }

        let wrapped = Arc::new(server_config.clone());
        assert_eq!(
            quic::ServerConnection::new(wrapped, quic::Version::V1, b"server params".to_vec(),)
                .is_ok(),
            ok
        );
    }
}

#[test]
fn test_quic_server_no_params_received() {
    let provider = provider::DEFAULT_TLS13_PROVIDER;
    let server_config = make_server_config(KeyType::EcdsaP256, &provider);
    let server_config = Arc::new(server_config);

    let mut server =
        quic::ServerConnection::new(server_config, quic::Version::V1, b"server params".to_vec())
            .unwrap();

    let buf = encoding::basic_client_hello(vec![]);
    assert_eq!(
        server.read_hs(buf.as_slice()).err(),
        Some(Error::PeerMisbehaved(
            PeerMisbehaved::MissingQuicTransportParameters
        ))
    );
}

#[test]
fn test_quic_server_no_tls12() {
    let provider = provider::DEFAULT_TLS13_PROVIDER;
    let mut server_config = make_server_config(KeyType::Ed25519, &provider);
    server_config.alpn_protocols = vec!["foo".into()];
    let server_config = Arc::new(server_config);

    let mut server =
        quic::ServerConnection::new(server_config, quic::Version::V1, b"server params".to_vec())
            .unwrap();

    let buf = encoding::client_hello_with_extensions(vec![
        encoding::Extension::new_sig_algs(),
        encoding::Extension::new_dummy_key_share(),
        encoding::Extension::new_kx_groups(),
    ]);
    assert_eq!(
        server.read_hs(buf.as_slice()).err(),
        Some(Error::PeerIncompatible(
            PeerIncompatible::SupportedVersionsExtensionRequired
        )),
    );
}

fn do_quic_handshake<L: SideData, R: SideData>(
    client: &mut ConnectionCommon<L>,
    server: &mut ConnectionCommon<R>,
) {
    while client.is_handshaking() || server.is_handshaking() {
        quic_transfer(client, server);
        quic_transfer(server, client);
    }
}

fn quic_transfer<L: SideData, R: SideData>(
    sender: &mut ConnectionCommon<L>,
    receiver: &mut ConnectionCommon<R>,
) {
    let mut buf = Vec::new();
    while let Some(_change) = sender.write_hs(&mut buf) {
        // In a real QUIC implementation, we would handle key changes here
        // For testing, we just continue
    }

    if !buf.is_empty() {
        receiver.read_hs(&buf).unwrap();
        assert_eq!(receiver.alert(), None);
    }
}

#[test]
fn test_quic_resumption_data_basic() {
    let server_params = b"server params";
    let kt = KeyType::Rsa2048;
    let provider = provider::DEFAULT_TLS13_PROVIDER;

    let mut server_config = make_server_config(kt, &provider);
    server_config.alpn_protocols = vec!["foo".into()];
    server_config.max_early_data_size = 0xffff_ffff;
    server_config.ticketer = Some(
        provider
            .ticketer_factory
            .ticketer()
            .unwrap(),
    );
    server_config.send_tls13_tickets = 2;
    let server_config = Arc::new(server_config);

    let mut server =
        quic::ServerConnection::new(server_config, quic::Version::V1, server_params.to_vec())
            .unwrap();

    // Initially, no resumption data should be received
    assert_eq!(server.received_resumption_data(), None);

    // Set resumption data
    let test_data1 = b"test resumption data 1";
    server.set_resumption_data(test_data1);
    // Still no received data (server has set data, but hasn't received any from client)
    assert_eq!(server.received_resumption_data(), None);

    // Update resumption data with different content
    let test_data2 = b"test resumption data 2";
    server.set_resumption_data(test_data2);
    // Still no received data
    assert_eq!(server.received_resumption_data(), None);

    // Test empty resumption data
    server.set_resumption_data(b"");
    assert_eq!(server.received_resumption_data(), None);
}

#[test]
fn test_quic_resumption_data_0rtt() {
    let client_params = b"client params";
    let server_params = b"server params";
    let kt = KeyType::Rsa2048;
    let provider = provider::DEFAULT_TLS13_PROVIDER;

    let mut client_config = make_client_config(kt, &provider);
    client_config.alpn_protocols = vec!["foo".into()];
    client_config.enable_early_data = true;
    client_config.resumption = Resumption::store(Arc::new(ClientStorage::new()));
    let client_config = Arc::new(client_config);

    let mut server_config = make_server_config(kt, &provider);
    server_config.alpn_protocols = vec!["foo".into()];
    server_config.max_early_data_size = 0xffff_ffff;
    server_config.ticketer = Some(
        provider
            .ticketer_factory
            .ticketer()
            .unwrap(),
    );
    server_config.send_tls13_tickets = 2;
    let server_config = Arc::new(server_config);

    // QUIC 0-RTT parameters to store in resumption data
    let quic_0rtt_params = b"active_connection_id_limit=2,initial_max_data=1048576,initial_max_stream_data_bidi_local=262144,initial_max_stream_data_bidi_remote=262144,initial_max_stream_data_uni=262144,initial_max_streams_bidi=100,initial_max_streams_uni=100,max_datagram_frame_size=1500";

    // First connection: establish session with 0-RTT parameters
    let mut server1 = quic::ServerConnection::new(
        server_config.clone(),
        quic::Version::V1,
        server_params.to_vec(),
    )
    .unwrap();

    server1.set_resumption_data(quic_0rtt_params);
    assert_eq!(server1.received_resumption_data(), None);

    let mut client1 = quic::ClientConnection::new(
        client_config.clone(),
        quic::Version::V1,
        server_name("localhost"),
        client_params.to_vec(),
    )
    .unwrap();

    do_quic_handshake(&mut client1, &mut server1);

    // Verify initial connection
    assert_eq!(client1.handshake_kind(), Some(HandshakeKind::Full));
    assert_eq!(server1.handshake_kind(), Some(HandshakeKind::Full));
    assert_eq!(server1.received_resumption_data(), None);

    // Second connection: attempt 0-RTT resumption
    let mut server2 =
        quic::ServerConnection::new(server_config, quic::Version::V1, server_params.to_vec())
            .unwrap();

    let mut client2 = quic::ClientConnection::new(
        client_config,
        quic::Version::V1,
        server_name("localhost"),
        client_params.to_vec(),
    )
    .unwrap();

    // Check negotiated cipher suite for potential 0-RTT
    assert!(
        client2
            .negotiated_cipher_suite()
            .is_some()
    );

    // Start handshake and check transport parameters early
    quic_transfer(&mut client2, &mut server2);
    assert_eq!(
        client2.quic_transport_parameters(),
        Some(server_params.as_slice())
    );

    // Complete the handshake (whether 0-RTT or regular resumption)
    do_quic_handshake(&mut client2, &mut server2);

    // Verify resumption worked and parameters were received
    assert_eq!(client2.handshake_kind(), Some(HandshakeKind::Resumed));
    assert_eq!(server2.handshake_kind(), Some(HandshakeKind::Resumed));
    assert_eq!(
        server2.received_resumption_data(),
        Some(quic_0rtt_params.as_slice()),
        "Server should receive QUIC 0-RTT parameters from resumption data"
    );

    // Verify server can parse and use the received 0-RTT parameters
    if let Some(received_params) = server2.received_resumption_data() {
        let params_str = core::str::from_utf8(received_params).unwrap();
        assert!(params_str.contains("active_connection_id_limit=2"));
        assert!(params_str.contains("initial_max_data=1048576"));
        assert!(params_str.contains("initial_max_stream_data_bidi_local=262144"));
        assert!(params_str.contains("initial_max_stream_data_bidi_remote=262144"));
        assert!(params_str.contains("initial_max_stream_data_uni=262144"));
        assert!(params_str.contains("initial_max_streams_bidi=100"));
        assert!(params_str.contains("initial_max_streams_uni=100"));
        assert!(params_str.contains("max_datagram_frame_size=1500"));
    }
}

#[test]
fn packet_key_api() {
    use provider::cipher_suite::TLS13_AES_128_GCM_SHA256;
    use rustls::quic::{Keys, Version};

    // Test vectors: https://www.rfc-editor.org/rfc/rfc9001.html#name-client-initial
    const CONNECTION_ID: &[u8] = &[0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];
    const PACKET_NUMBER: u64 = 2;
    const PLAIN_HEADER: &[u8] = &[
        0xc3, 0x00, 0x00, 0x00, 0x01, 0x08, 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08, 0x00,
        0x00, 0x44, 0x9e, 0x00, 0x00, 0x00, 0x02,
    ];

    const PAYLOAD: &[u8] = &[
        0x06, 0x00, 0x40, 0xf1, 0x01, 0x00, 0x00, 0xed, 0x03, 0x03, 0xeb, 0xf8, 0xfa, 0x56, 0xf1,
        0x29, 0x39, 0xb9, 0x58, 0x4a, 0x38, 0x96, 0x47, 0x2e, 0xc4, 0x0b, 0xb8, 0x63, 0xcf, 0xd3,
        0xe8, 0x68, 0x04, 0xfe, 0x3a, 0x47, 0xf0, 0x6a, 0x2b, 0x69, 0x48, 0x4c, 0x00, 0x00, 0x04,
        0x13, 0x01, 0x13, 0x02, 0x01, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00, 0x10, 0x00, 0x0e, 0x00,
        0x00, 0x0b, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d, 0xff, 0x01,
        0x00, 0x01, 0x00, 0x00, 0x0a, 0x00, 0x08, 0x00, 0x06, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x18,
        0x00, 0x10, 0x00, 0x07, 0x00, 0x05, 0x04, 0x61, 0x6c, 0x70, 0x6e, 0x00, 0x05, 0x00, 0x05,
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x33, 0x00, 0x26, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20,
        0x93, 0x70, 0xb2, 0xc9, 0xca, 0xa4, 0x7f, 0xba, 0xba, 0xf4, 0x55, 0x9f, 0xed, 0xba, 0x75,
        0x3d, 0xe1, 0x71, 0xfa, 0x71, 0xf5, 0x0f, 0x1c, 0xe1, 0x5d, 0x43, 0xe9, 0x94, 0xec, 0x74,
        0xd7, 0x48, 0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04, 0x00, 0x0d, 0x00, 0x10, 0x00, 0x0e,
        0x04, 0x03, 0x05, 0x03, 0x06, 0x03, 0x02, 0x03, 0x08, 0x04, 0x08, 0x05, 0x08, 0x06, 0x00,
        0x2d, 0x00, 0x02, 0x01, 0x01, 0x00, 0x1c, 0x00, 0x02, 0x40, 0x01, 0x00, 0x39, 0x00, 0x32,
        0x04, 0x08, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x05, 0x04, 0x80, 0x00, 0xff,
        0xff, 0x07, 0x04, 0x80, 0x00, 0xff, 0xff, 0x08, 0x01, 0x10, 0x01, 0x04, 0x80, 0x00, 0x75,
        0x30, 0x09, 0x01, 0x10, 0x0f, 0x08, 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08, 0x06,
        0x04, 0x80, 0x00, 0xff, 0xff,
    ];

    let client_keys = Keys::initial(
        Version::V1,
        TLS13_AES_128_GCM_SHA256,
        TLS13_AES_128_GCM_SHA256.quic.unwrap(),
        CONNECTION_ID,
        Side::Client,
    );
    assert_eq!(client_keys.local.packet.tag_len(), 16);

    let mut buf = Vec::new();
    buf.extend(PLAIN_HEADER);
    buf.extend(PAYLOAD);
    let header_len = PLAIN_HEADER.len();
    let tag_len = client_keys.local.packet.tag_len();
    let padding_len = 1200 - header_len - PAYLOAD.len() - tag_len;
    buf.extend(core::iter::repeat_n(0, padding_len));
    let (header, payload) = buf.split_at_mut(header_len);
    let tag = client_keys
        .local
        .packet
        .encrypt_in_place(PACKET_NUMBER, header, payload, None)
        .unwrap();

    let sample_len = client_keys.local.header.sample_len();
    let sample = &payload[..sample_len];
    let (first, rest) = header.split_at_mut(1);
    client_keys
        .local
        .header
        .encrypt_in_place(sample, &mut first[0], &mut rest[17..21])
        .unwrap();
    buf.extend_from_slice(tag.as_ref());

    const PROTECTED: &[u8] = &[
        0xc0, 0x00, 0x00, 0x00, 0x01, 0x08, 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08, 0x00,
        0x00, 0x44, 0x9e, 0x7b, 0x9a, 0xec, 0x34, 0xd1, 0xb1, 0xc9, 0x8d, 0xd7, 0x68, 0x9f, 0xb8,
        0xec, 0x11, 0xd2, 0x42, 0xb1, 0x23, 0xdc, 0x9b, 0xd8, 0xba, 0xb9, 0x36, 0xb4, 0x7d, 0x92,
        0xec, 0x35, 0x6c, 0x0b, 0xab, 0x7d, 0xf5, 0x97, 0x6d, 0x27, 0xcd, 0x44, 0x9f, 0x63, 0x30,
        0x00, 0x99, 0xf3, 0x99, 0x1c, 0x26, 0x0e, 0xc4, 0xc6, 0x0d, 0x17, 0xb3, 0x1f, 0x84, 0x29,
        0x15, 0x7b, 0xb3, 0x5a, 0x12, 0x82, 0xa6, 0x43, 0xa8, 0xd2, 0x26, 0x2c, 0xad, 0x67, 0x50,
        0x0c, 0xad, 0xb8, 0xe7, 0x37, 0x8c, 0x8e, 0xb7, 0x53, 0x9e, 0xc4, 0xd4, 0x90, 0x5f, 0xed,
        0x1b, 0xee, 0x1f, 0xc8, 0xaa, 0xfb, 0xa1, 0x7c, 0x75, 0x0e, 0x2c, 0x7a, 0xce, 0x01, 0xe6,
        0x00, 0x5f, 0x80, 0xfc, 0xb7, 0xdf, 0x62, 0x12, 0x30, 0xc8, 0x37, 0x11, 0xb3, 0x93, 0x43,
        0xfa, 0x02, 0x8c, 0xea, 0x7f, 0x7f, 0xb5, 0xff, 0x89, 0xea, 0xc2, 0x30, 0x82, 0x49, 0xa0,
        0x22, 0x52, 0x15, 0x5e, 0x23, 0x47, 0xb6, 0x3d, 0x58, 0xc5, 0x45, 0x7a, 0xfd, 0x84, 0xd0,
        0x5d, 0xff, 0xfd, 0xb2, 0x03, 0x92, 0x84, 0x4a, 0xe8, 0x12, 0x15, 0x46, 0x82, 0xe9, 0xcf,
        0x01, 0x2f, 0x90, 0x21, 0xa6, 0xf0, 0xbe, 0x17, 0xdd, 0xd0, 0xc2, 0x08, 0x4d, 0xce, 0x25,
        0xff, 0x9b, 0x06, 0xcd, 0xe5, 0x35, 0xd0, 0xf9, 0x20, 0xa2, 0xdb, 0x1b, 0xf3, 0x62, 0xc2,
        0x3e, 0x59, 0x6d, 0x11, 0xa4, 0xf5, 0xa6, 0xcf, 0x39, 0x48, 0x83, 0x8a, 0x3a, 0xec, 0x4e,
        0x15, 0xda, 0xf8, 0x50, 0x0a, 0x6e, 0xf6, 0x9e, 0xc4, 0xe3, 0xfe, 0xb6, 0xb1, 0xd9, 0x8e,
        0x61, 0x0a, 0xc8, 0xb7, 0xec, 0x3f, 0xaf, 0x6a, 0xd7, 0x60, 0xb7, 0xba, 0xd1, 0xdb, 0x4b,
        0xa3, 0x48, 0x5e, 0x8a, 0x94, 0xdc, 0x25, 0x0a, 0xe3, 0xfd, 0xb4, 0x1e, 0xd1, 0x5f, 0xb6,
        0xa8, 0xe5, 0xeb, 0xa0, 0xfc, 0x3d, 0xd6, 0x0b, 0xc8, 0xe3, 0x0c, 0x5c, 0x42, 0x87, 0xe5,
        0x38, 0x05, 0xdb, 0x05, 0x9a, 0xe0, 0x64, 0x8d, 0xb2, 0xf6, 0x42, 0x64, 0xed, 0x5e, 0x39,
        0xbe, 0x2e, 0x20, 0xd8, 0x2d, 0xf5, 0x66, 0xda, 0x8d, 0xd5, 0x99, 0x8c, 0xca, 0xbd, 0xae,
        0x05, 0x30, 0x60, 0xae, 0x6c, 0x7b, 0x43, 0x78, 0xe8, 0x46, 0xd2, 0x9f, 0x37, 0xed, 0x7b,
        0x4e, 0xa9, 0xec, 0x5d, 0x82, 0xe7, 0x96, 0x1b, 0x7f, 0x25, 0xa9, 0x32, 0x38, 0x51, 0xf6,
        0x81, 0xd5, 0x82, 0x36, 0x3a, 0xa5, 0xf8, 0x99, 0x37, 0xf5, 0xa6, 0x72, 0x58, 0xbf, 0x63,
        0xad, 0x6f, 0x1a, 0x0b, 0x1d, 0x96, 0xdb, 0xd4, 0xfa, 0xdd, 0xfc, 0xef, 0xc5, 0x26, 0x6b,
        0xa6, 0x61, 0x17, 0x22, 0x39, 0x5c, 0x90, 0x65, 0x56, 0xbe, 0x52, 0xaf, 0xe3, 0xf5, 0x65,
        0x63, 0x6a, 0xd1, 0xb1, 0x7d, 0x50, 0x8b, 0x73, 0xd8, 0x74, 0x3e, 0xeb, 0x52, 0x4b, 0xe2,
        0x2b, 0x3d, 0xcb, 0xc2, 0xc7, 0x46, 0x8d, 0x54, 0x11, 0x9c, 0x74, 0x68, 0x44, 0x9a, 0x13,
        0xd8, 0xe3, 0xb9, 0x58, 0x11, 0xa1, 0x98, 0xf3, 0x49, 0x1d, 0xe3, 0xe7, 0xfe, 0x94, 0x2b,
        0x33, 0x04, 0x07, 0xab, 0xf8, 0x2a, 0x4e, 0xd7, 0xc1, 0xb3, 0x11, 0x66, 0x3a, 0xc6, 0x98,
        0x90, 0xf4, 0x15, 0x70, 0x15, 0x85, 0x3d, 0x91, 0xe9, 0x23, 0x03, 0x7c, 0x22, 0x7a, 0x33,
        0xcd, 0xd5, 0xec, 0x28, 0x1c, 0xa3, 0xf7, 0x9c, 0x44, 0x54, 0x6b, 0x9d, 0x90, 0xca, 0x00,
        0xf0, 0x64, 0xc9, 0x9e, 0x3d, 0xd9, 0x79, 0x11, 0xd3, 0x9f, 0xe9, 0xc5, 0xd0, 0xb2, 0x3a,
        0x22, 0x9a, 0x23, 0x4c, 0xb3, 0x61, 0x86, 0xc4, 0x81, 0x9e, 0x8b, 0x9c, 0x59, 0x27, 0x72,
        0x66, 0x32, 0x29, 0x1d, 0x6a, 0x41, 0x82, 0x11, 0xcc, 0x29, 0x62, 0xe2, 0x0f, 0xe4, 0x7f,
        0xeb, 0x3e, 0xdf, 0x33, 0x0f, 0x2c, 0x60, 0x3a, 0x9d, 0x48, 0xc0, 0xfc, 0xb5, 0x69, 0x9d,
        0xbf, 0xe5, 0x89, 0x64, 0x25, 0xc5, 0xba, 0xc4, 0xae, 0xe8, 0x2e, 0x57, 0xa8, 0x5a, 0xaf,
        0x4e, 0x25, 0x13, 0xe4, 0xf0, 0x57, 0x96, 0xb0, 0x7b, 0xa2, 0xee, 0x47, 0xd8, 0x05, 0x06,
        0xf8, 0xd2, 0xc2, 0x5e, 0x50, 0xfd, 0x14, 0xde, 0x71, 0xe6, 0xc4, 0x18, 0x55, 0x93, 0x02,
        0xf9, 0x39, 0xb0, 0xe1, 0xab, 0xd5, 0x76, 0xf2, 0x79, 0xc4, 0xb2, 0xe0, 0xfe, 0xb8, 0x5c,
        0x1f, 0x28, 0xff, 0x18, 0xf5, 0x88, 0x91, 0xff, 0xef, 0x13, 0x2e, 0xef, 0x2f, 0xa0, 0x93,
        0x46, 0xae, 0xe3, 0x3c, 0x28, 0xeb, 0x13, 0x0f, 0xf2, 0x8f, 0x5b, 0x76, 0x69, 0x53, 0x33,
        0x41, 0x13, 0x21, 0x19, 0x96, 0xd2, 0x00, 0x11, 0xa1, 0x98, 0xe3, 0xfc, 0x43, 0x3f, 0x9f,
        0x25, 0x41, 0x01, 0x0a, 0xe1, 0x7c, 0x1b, 0xf2, 0x02, 0x58, 0x0f, 0x60, 0x47, 0x47, 0x2f,
        0xb3, 0x68, 0x57, 0xfe, 0x84, 0x3b, 0x19, 0xf5, 0x98, 0x40, 0x09, 0xdd, 0xc3, 0x24, 0x04,
        0x4e, 0x84, 0x7a, 0x4f, 0x4a, 0x0a, 0xb3, 0x4f, 0x71, 0x95, 0x95, 0xde, 0x37, 0x25, 0x2d,
        0x62, 0x35, 0x36, 0x5e, 0x9b, 0x84, 0x39, 0x2b, 0x06, 0x10, 0x85, 0x34, 0x9d, 0x73, 0x20,
        0x3a, 0x4a, 0x13, 0xe9, 0x6f, 0x54, 0x32, 0xec, 0x0f, 0xd4, 0xa1, 0xee, 0x65, 0xac, 0xcd,
        0xd5, 0xe3, 0x90, 0x4d, 0xf5, 0x4c, 0x1d, 0xa5, 0x10, 0xb0, 0xff, 0x20, 0xdc, 0xc0, 0xc7,
        0x7f, 0xcb, 0x2c, 0x0e, 0x0e, 0xb6, 0x05, 0xcb, 0x05, 0x04, 0xdb, 0x87, 0x63, 0x2c, 0xf3,
        0xd8, 0xb4, 0xda, 0xe6, 0xe7, 0x05, 0x76, 0x9d, 0x1d, 0xe3, 0x54, 0x27, 0x01, 0x23, 0xcb,
        0x11, 0x45, 0x0e, 0xfc, 0x60, 0xac, 0x47, 0x68, 0x3d, 0x7b, 0x8d, 0x0f, 0x81, 0x13, 0x65,
        0x56, 0x5f, 0xd9, 0x8c, 0x4c, 0x8e, 0xb9, 0x36, 0xbc, 0xab, 0x8d, 0x06, 0x9f, 0xc3, 0x3b,
        0xd8, 0x01, 0xb0, 0x3a, 0xde, 0xa2, 0xe1, 0xfb, 0xc5, 0xaa, 0x46, 0x3d, 0x08, 0xca, 0x19,
        0x89, 0x6d, 0x2b, 0xf5, 0x9a, 0x07, 0x1b, 0x85, 0x1e, 0x6c, 0x23, 0x90, 0x52, 0x17, 0x2f,
        0x29, 0x6b, 0xfb, 0x5e, 0x72, 0x40, 0x47, 0x90, 0xa2, 0x18, 0x10, 0x14, 0xf3, 0xb9, 0x4a,
        0x4e, 0x97, 0xd1, 0x17, 0xb4, 0x38, 0x13, 0x03, 0x68, 0xcc, 0x39, 0xdb, 0xb2, 0xd1, 0x98,
        0x06, 0x5a, 0xe3, 0x98, 0x65, 0x47, 0x92, 0x6c, 0xd2, 0x16, 0x2f, 0x40, 0xa2, 0x9f, 0x0c,
        0x3c, 0x87, 0x45, 0xc0, 0xf5, 0x0f, 0xba, 0x38, 0x52, 0xe5, 0x66, 0xd4, 0x45, 0x75, 0xc2,
        0x9d, 0x39, 0xa0, 0x3f, 0x0c, 0xda, 0x72, 0x19, 0x84, 0xb6, 0xf4, 0x40, 0x59, 0x1f, 0x35,
        0x5e, 0x12, 0xd4, 0x39, 0xff, 0x15, 0x0a, 0xab, 0x76, 0x13, 0x49, 0x9d, 0xbd, 0x49, 0xad,
        0xab, 0xc8, 0x67, 0x6e, 0xef, 0x02, 0x3b, 0x15, 0xb6, 0x5b, 0xfc, 0x5c, 0xa0, 0x69, 0x48,
        0x10, 0x9f, 0x23, 0xf3, 0x50, 0xdb, 0x82, 0x12, 0x35, 0x35, 0xeb, 0x8a, 0x74, 0x33, 0xbd,
        0xab, 0xcb, 0x90, 0x92, 0x71, 0xa6, 0xec, 0xbc, 0xb5, 0x8b, 0x93, 0x6a, 0x88, 0xcd, 0x4e,
        0x8f, 0x2e, 0x6f, 0xf5, 0x80, 0x01, 0x75, 0xf1, 0x13, 0x25, 0x3d, 0x8f, 0xa9, 0xca, 0x88,
        0x85, 0xc2, 0xf5, 0x52, 0xe6, 0x57, 0xdc, 0x60, 0x3f, 0x25, 0x2e, 0x1a, 0x8e, 0x30, 0x8f,
        0x76, 0xf0, 0xbe, 0x79, 0xe2, 0xfb, 0x8f, 0x5d, 0x5f, 0xbb, 0xe2, 0xe3, 0x0e, 0xca, 0xdd,
        0x22, 0x07, 0x23, 0xc8, 0xc0, 0xae, 0xa8, 0x07, 0x8c, 0xdf, 0xcb, 0x38, 0x68, 0x26, 0x3f,
        0xf8, 0xf0, 0x94, 0x00, 0x54, 0xda, 0x48, 0x78, 0x18, 0x93, 0xa7, 0xe4, 0x9a, 0xd5, 0xaf,
        0xf4, 0xaf, 0x30, 0x0c, 0xd8, 0x04, 0xa6, 0xb6, 0x27, 0x9a, 0xb3, 0xff, 0x3a, 0xfb, 0x64,
        0x49, 0x1c, 0x85, 0x19, 0x4a, 0xab, 0x76, 0x0d, 0x58, 0xa6, 0x06, 0x65, 0x4f, 0x9f, 0x44,
        0x00, 0xe8, 0xb3, 0x85, 0x91, 0x35, 0x6f, 0xbf, 0x64, 0x25, 0xac, 0xa2, 0x6d, 0xc8, 0x52,
        0x44, 0x25, 0x9f, 0xf2, 0xb1, 0x9c, 0x41, 0xb9, 0xf9, 0x6f, 0x3c, 0xa9, 0xec, 0x1d, 0xde,
        0x43, 0x4d, 0xa7, 0xd2, 0xd3, 0x92, 0xb9, 0x05, 0xdd, 0xf3, 0xd1, 0xf9, 0xaf, 0x93, 0xd1,
        0xaf, 0x59, 0x50, 0xbd, 0x49, 0x3f, 0x5a, 0xa7, 0x31, 0xb4, 0x05, 0x6d, 0xf3, 0x1b, 0xd2,
        0x67, 0xb6, 0xb9, 0x0a, 0x07, 0x98, 0x31, 0xaa, 0xf5, 0x79, 0xbe, 0x0a, 0x39, 0x01, 0x31,
        0x37, 0xaa, 0xc6, 0xd4, 0x04, 0xf5, 0x18, 0xcf, 0xd4, 0x68, 0x40, 0x64, 0x7e, 0x78, 0xbf,
        0xe7, 0x06, 0xca, 0x4c, 0xf5, 0xe9, 0xc5, 0x45, 0x3e, 0x9f, 0x7c, 0xfd, 0x2b, 0x8b, 0x4c,
        0x8d, 0x16, 0x9a, 0x44, 0xe5, 0x5c, 0x88, 0xd4, 0xa9, 0xa7, 0xf9, 0x47, 0x42, 0x41, 0xe2,
        0x21, 0xaf, 0x44, 0x86, 0x00, 0x18, 0xab, 0x08, 0x56, 0x97, 0x2e, 0x19, 0x4c, 0xd9, 0x34,
    ];

    assert_eq!(&buf, PROTECTED);

    let (header, payload) = buf.split_at_mut(header_len);
    let (first, rest) = header.split_at_mut(1);
    let sample = &payload[..sample_len];

    let server_keys = Keys::initial(
        Version::V1,
        TLS13_AES_128_GCM_SHA256,
        TLS13_AES_128_GCM_SHA256.quic.unwrap(),
        CONNECTION_ID,
        Side::Server,
    );
    server_keys
        .remote
        .header
        .decrypt_in_place(sample, &mut first[0], &mut rest[17..21])
        .unwrap();
    let payload = server_keys
        .remote
        .packet
        .decrypt_in_place(PACKET_NUMBER, header, payload, None)
        .unwrap();

    assert_eq!(&payload[..PAYLOAD.len()], PAYLOAD);
    assert_eq!(payload.len(), buf.len() - header_len - tag_len);
}

#[test]
fn test_quic_exporter() {
    let provider = provider::DEFAULT_TLS13_PROVIDER;
    for &kt in KeyType::all_for_provider(&provider) {
        let client_config = make_client_config(kt, &provider);
        let server_config = make_server_config(kt, &provider);

        let mut server =
            quic::ServerConnection::new(server_config.into(), quic::Version::V2, vec![]).unwrap();
        let mut client = quic::ClientConnection::new(
            client_config.into(),
            quic::Version::V2,
            server_name("localhost"),
            vec![],
        )
        .unwrap();

        assert_eq!(Some(Error::HandshakeNotComplete), client.exporter().err());
        assert_eq!(Some(Error::HandshakeNotComplete), server.exporter().err());

        do_quic_handshake(&mut client, &mut server);

        let client_exporter = client.exporter().unwrap();
        let server_exporter = server.exporter().unwrap();

        assert_eq!(
            client.exporter().err(),
            Some(Error::ApiMisuse(ApiMisuse::ExporterAlreadyUsed)),
        );
        assert_eq!(
            server.exporter().err(),
            Some(Error::ApiMisuse(ApiMisuse::ExporterAlreadyUsed)),
        );

        let mut client_secret = [0u8; 64];
        let mut server_secret = [0u8; 64];
        assert!(
            client_exporter
                .derive(b"label", Some(b"context"), &mut client_secret)
                .is_ok()
        );
        assert!(
            server_exporter
                .derive(b"label", Some(b"context"), &mut server_secret)
                .is_ok()
        );
        assert_eq!(client_secret, server_secret);
    }
}

#[test]
fn test_fragmented_append() {
    // Create a QUIC client connection.
    let client_config = make_client_config(KeyType::Rsa2048, &provider::DEFAULT_TLS13_PROVIDER);
    let client_config = Arc::new(client_config);
    let mut client = quic::ClientConnection::new(
        client_config.clone(),
        quic::Version::V1,
        server_name("localhost"),
        b"client params"[..].into(),
    )
    .unwrap();

    // Construct a message that is too large to fit in a single QUIC packet.
    // We want the partial pieces to be large enough to overflow the deframer's
    // 4096 byte buffer if mishandled.
    let mut out = vec![0; 4096];
    let len_bytes = u32::to_be_bytes(9266_u32);
    out[1..4].copy_from_slice(&len_bytes[1..]);

    // Read the message - this will put us into a joining handshake message state, buffering
    // 4096 bytes into the deframer buffer.
    client.read_hs(&out).unwrap();

    // Read the message again - once more it isn't a complete message, so we'll try to
    // append another 4096 bytes into the deframer buffer.
    //
    // If the deframer mishandles writing into the used buffer space this will panic with
    // an index out of range error:
    //   range end index 8192 out of range for slice of length 4096
    client.read_hs(&out).unwrap();
}

#[test]
fn server_rejects_client_hello_with_trailing_fragment() {
    let mut server = quic::ServerConnection::new(
        Arc::new(make_server_config(
            KeyType::EcdsaP256,
            &provider::DEFAULT_TLS13_PROVIDER,
        )),
        quic::Version::V2,
        b"server params".to_vec(),
    )
    .unwrap();

    // this is a trivial ClientHello, followed by a fragment of a ClientHello
    let mut hello =
        encoding::basic_client_hello(vec![encoding::Extension::new_quic_transport_params(
            b"client params",
        )]);
    hello.extend(&hello[..10].to_vec());

    assert_eq!(
        server.read_hs(&hello).unwrap_err(),
        PeerMisbehaved::KeyEpochWithPendingFragment.into()
    );
}
