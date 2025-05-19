#![cfg(any(feature = "ring", feature = "aws_lc_rs"))]
use std::prelude::v1::*;

use pki_types::{CertificateDer, ServerName};

use crate::client::{ClientConfig, ClientConnection, Resumption, Tls12Resumption};
use crate::msgs::codec::Reader;
use crate::msgs::handshake::{ClientHelloPayload, HandshakeMessagePayload, HandshakePayload};
use crate::msgs::message::{Message, MessagePayload, OutboundOpaqueMessage};
use crate::{Error, RootCertStore};

#[macro_rules_attribute::apply(test_for_each_provider)]
mod tests {
    use super::super::*;
    use crate::version;

    /// Tests that session_ticket(35) extension
    /// is not sent if the client does not support TLS 1.2.
    #[test]
    fn test_no_session_ticket_request_on_tls_1_3() {
        let mut config =
            ClientConfig::builder_with_provider(super::provider::default_provider().into())
                .with_protocol_versions(&[&version::TLS13])
                .unwrap()
                .with_root_certificates(roots())
                .with_no_client_auth();
        config.resumption = Resumption::in_memory_sessions(128)
            .tls12_resumption(Tls12Resumption::SessionIdOrTickets);
        let ch = client_hello_sent_for_config(config).unwrap();
        assert!(ch.ticket_extension().is_none());
    }
}

fn client_hello_sent_for_config(config: ClientConfig) -> Result<ClientHelloPayload, Error> {
    let mut conn =
        ClientConnection::new(config.into(), ServerName::try_from("localhost").unwrap())?;
    let mut bytes = Vec::new();
    conn.write_tls(&mut bytes).unwrap();

    let message = OutboundOpaqueMessage::read(&mut Reader::init(&bytes))
        .unwrap()
        .into_plain_message();

    match Message::try_from(message).unwrap() {
        Message {
            payload:
                MessagePayload::Handshake {
                    parsed:
                        HandshakeMessagePayload {
                            payload: HandshakePayload::ClientHello(ch),
                            ..
                        },
                    ..
                },
            ..
        } => Ok(ch),
        other => panic!("unexpected message {other:?}"),
    }
}

fn roots() -> RootCertStore {
    let mut r = RootCertStore::empty();
    r.add(CertificateDer::from_slice(include_bytes!(
        "../../../test-ca/rsa-2048/ca.der"
    )))
    .unwrap();
    r
}
