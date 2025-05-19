use std::prelude::v1::*;
use std::vec;

use super::ServerConnectionData;
use crate::common_state::Context;
use crate::msgs::codec::{Codec, LengthPrefixedBuffer, ListLength};
use crate::msgs::enums::{Compression, ExtensionType};
use crate::msgs::handshake::{
    ClientExtension, ClientHelloPayload, HandshakeMessagePayload, HandshakePayload, Random,
    SessionId,
};
use crate::msgs::message::{Message, MessagePayload};
use crate::{CommonState, Error, HandshakeType, PeerIncompatible, ProtocolVersion, Side};

#[test]
fn null_compression_required() {
    assert_eq!(
        test_process_client_hello(ClientHelloPayload {
            compression_methods: vec![],
            ..minimal_client_hello()
        }),
        Err(PeerIncompatible::NullCompressionRequired.into()),
    );
}

#[test]
fn server_ignores_sni_with_ip_address() {
    let mut ch = minimal_client_hello();
    ch.extensions
        .push(ClientExtension::read_bytes(&sni_extension(&[b"1.1.1.1"])).unwrap());
    std::println!("{:?}", ch.extensions);
    assert_eq!(test_process_client_hello(ch), Ok(()));
}

fn test_process_client_hello(hello: ClientHelloPayload) -> Result<(), Error> {
    let m = Message {
        version: ProtocolVersion::TLSv1_2,
        payload: MessagePayload::handshake(HandshakeMessagePayload {
            typ: HandshakeType::ClientHello,
            payload: HandshakePayload::ClientHello(hello),
        }),
    };
    super::hs::process_client_hello(
        &m,
        false,
        &mut Context {
            common: &mut CommonState::new(Side::Server),
            data: &mut ServerConnectionData::default(),
            sendable_plaintext: None,
        },
    )
    .map(|_| ())
}

fn minimal_client_hello() -> ClientHelloPayload {
    ClientHelloPayload {
        client_version: ProtocolVersion::TLSv1_3,
        random: Random::from([0u8; 32]),
        session_id: SessionId::empty(),
        cipher_suites: vec![],
        compression_methods: vec![Compression::Null],
        extensions: vec![ClientExtension::SignatureAlgorithms(vec![])],
    }
}

fn sni_extension(names: &[&[u8]]) -> Vec<u8> {
    let mut r = Vec::new();
    ExtensionType::ServerName.encode(&mut r);
    let outer = LengthPrefixedBuffer::new(ListLength::U16, &mut r);
    let name_items = LengthPrefixedBuffer::new(ListLength::U16, outer.buf);
    for name in names {
        name_items.buf.push(0);
        let host_name = LengthPrefixedBuffer::new(ListLength::U16, name_items.buf);
        host_name.buf.extend_from_slice(name);
        drop(host_name);
    }
    drop(name_items);
    drop(outer);
    r
}
