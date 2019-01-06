/// This module contains optional APIs for implementing QUIC TLS.
use client::{ClientConfig, ClientSession, ClientSessionImpl};
use msgs::enums::{ContentType, ProtocolVersion, AlertDescription};
use msgs::handshake::{ClientExtension, ServerExtension};
use msgs::message::{Message, MessagePayload};
use server::{ServerConfig, ServerSession, ServerSessionImpl};
use error::TLSError;
use key_schedule::{KeySchedule, SecretKind};
use session::{SessionCommon, Protocol};

use std::sync::Arc;
use webpki;

/// Secrets used to encrypt/decrypt traffic
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Secrets {
    /// Secret used to encrypt packets transmitted by the client
    pub client: Vec<u8>,
    /// Secret used to encrypt packets transmitted by the server
    pub server: Vec<u8>,
}

/// Generic methods for QUIC sessions
pub trait QuicExt {
    /// Return the TLS-encoded transport parameters for the session's peer.
    fn get_quic_transport_parameters(&self) -> Option<&[u8]>;

    /// Return the early traffic secret, used to encrypt 0-RTT data.
    fn get_early_secret(&self) -> Option<&[u8]>;

    /// Consume unencrypted TLS handshake data.
    ///
    /// Handshake data obtained from separate encryption levels should be supplied in separate calls.
    fn read_hs(&mut self, plaintext: &[u8]) -> Result<(), TLSError>;

    /// Emit unencrypted TLS handshake data.
    ///
    /// When this returns `Some(_)`, the keys used for future handshake data must be derived from
    /// the new secrets.
    fn write_hs(&mut self, buf: &mut Vec<u8>) -> Option<Secrets>;

    /// Emit the TLS description code of a fatal alert, if one has arisen.
    ///
    /// Check after `read_hs` returns `Err(_)`.
    fn get_alert(&self) -> Option<AlertDescription>;

    /// Compute the secrets to use following a 1-RTT key update from their previous values.
    fn update_secrets(&self, client: &[u8], server: &[u8]) -> Secrets;
}

impl QuicExt for ClientSession {
    fn get_quic_transport_parameters(&self) -> Option<&[u8]> {
        self.imp.common.quic.params.as_ref().map(|v| v.as_ref())
    }

    fn get_early_secret(&self) -> Option<&[u8]> {
        self.imp.common.quic.early_secret.as_ref().map(|x| &x[..])
    }

    fn read_hs(&mut self, plaintext: &[u8]) -> Result<(), TLSError> {
        self.imp.common
            .handshake_joiner
            .take_message(Message {
                typ: ContentType::Handshake,
                version: ProtocolVersion::TLSv1_3,
                payload: MessagePayload::new_opaque(plaintext.into()),
            });
        self.imp.process_new_handshake_messages()?;
        Ok(())
    }

    fn write_hs(&mut self, buf: &mut Vec<u8>) -> Option<Secrets> { write_hs(&mut self.imp.common, buf) }

    fn get_alert(&self) -> Option<AlertDescription> { self.imp.common.quic.alert }

    fn update_secrets(&self, client: &[u8], server: &[u8]) -> Secrets { update_secrets(&self.imp.common, client, server) }
}

impl QuicExt for ServerSession {
    fn get_quic_transport_parameters(&self) -> Option<&[u8]> {
        self.imp.common.quic.params.as_ref().map(|v| v.as_ref())
    }

    fn get_early_secret(&self) -> Option<&[u8]> {
        self.imp.common.quic.early_secret.as_ref().map(|x| &x[..])
    }

    fn read_hs(&mut self, plaintext: &[u8]) -> Result<(), TLSError> {
        self.imp.common
            .handshake_joiner
            .take_message(Message {
                typ: ContentType::Handshake,
                version: ProtocolVersion::TLSv1_3,
                payload: MessagePayload::new_opaque(plaintext.into()),
            });
        self.imp.process_new_handshake_messages()?;
        Ok(())
    }
    
    fn write_hs(&mut self, buf: &mut Vec<u8>) -> Option<Secrets> { write_hs(&mut self.imp.common, buf) }

    fn get_alert(&self) -> Option<AlertDescription> { self.imp.common.quic.alert }

    fn update_secrets(&self, client: &[u8], server: &[u8]) -> Secrets { update_secrets(&self.imp.common, client, server) }
}

fn write_hs(this: &mut SessionCommon, buf: &mut Vec<u8>) -> Option<Secrets> {
    while let Some((_, msg)) = this.quic.hs_queue.pop_front() {
        buf.extend_from_slice(&msg);
        if let Some(&(true, _)) = this.quic.hs_queue.front() {
            if this.quic.hs_secrets.is_some() {
                // Allow the caller to switch keys before proceeding.
                break;
            }
        }
    }
    if let Some(secrets) = this.quic.hs_secrets.take() {
        return Some(secrets);
    }
    if let Some(secrets) = this.quic.traffic_secrets.take() {
        return Some(secrets);
    }
    None
}

fn update_secrets(this: &SessionCommon, client: &[u8], server: &[u8]) -> Secrets {
    let suite = this.get_suite_assert();
    // TODO: Don't clone
    let mut key_schedule = KeySchedule::new(suite.get_hash());
    key_schedule.current_client_traffic_secret = client.into();
    key_schedule.current_server_traffic_secret = server.into();
    Secrets {
        client: key_schedule.derive_next(SecretKind::ClientApplicationTrafficSecret),
        server: key_schedule.derive_next(SecretKind::ServerApplicationTrafficSecret),
    }
}

/// Methods specific to QUIC client sessions
pub trait ClientQuicExt {
    /// Make a new QUIC ClientSession. This differs from `ClientSession::new()`
    /// in that it takes an extra argument, `params`, which contains the
    /// TLS-encoded transport parameters to send.
    fn new_quic(config: &Arc<ClientConfig>, hostname: webpki::DNSNameRef, params: Vec<u8>)
                -> ClientSession {
        assert!(config.versions.iter().all(|x| x.get_u16() >= ProtocolVersion::TLSv1_3.get_u16()), "QUIC requires TLS version >= 1.3");
        let mut imp = ClientSessionImpl::new(config);
        imp.common.protocol = Protocol::Quic;
        imp.start_handshake(hostname.into(), vec![
            ClientExtension::TransportParameters(params),
        ]);
        ClientSession { imp }
    }
}

impl ClientQuicExt for ClientSession {}

/// Methods specific to QUIC server sessions
pub trait ServerQuicExt {
    /// Make a new QUIC ServerSession. This differs from `ServerSession::new()`
    /// in that it takes an extra argument, `params`, which contains the
    /// TLS-encoded transport parameters to send.
    fn new_quic(config: &Arc<ServerConfig>, params: Vec<u8>) -> ServerSession {
        assert!(config.versions.iter().all(|x| x.get_u16() >= ProtocolVersion::TLSv1_3.get_u16()), "QUIC requires TLS version >= 1.3");
        let mut imp = ServerSessionImpl::new(config, vec![
            ServerExtension::TransportParameters(params),
        ]);
        imp.common.protocol = Protocol::Quic;
        ServerSession { imp }
    }
}

impl ServerQuicExt for ServerSession {}
