use std::prelude::v1::*;
use std::vec;

use super::ServerConnectionData;
use crate::common_state::Context;
use crate::msgs::enums::Compression;
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
