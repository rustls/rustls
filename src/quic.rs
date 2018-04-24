/// This module contains optional APIs for implementing QUIC TLS.
use client::{ClientConfig, ClientSession, ClientSessionImpl};
use msgs::base::Payload;
use msgs::enums::ExtensionType;
use msgs::handshake::{ClientExtension, ServerExtension, UnknownExtension};
use server::{ServerConfig, ServerSession, ServerSessionImpl};

use std::sync::Arc;
use webpki;

/// Generic methods for QUIC sessions
pub trait QuicExt {
    /// Return the TLS-encoded transport parameters for the session's peer.
    fn get_quic_transport_parameters(&self) -> Option<&[u8]>;
}

impl QuicExt for ClientSession {
    fn get_quic_transport_parameters(&self) -> Option<&[u8]> {
        self.imp.quic_params.as_ref().map(|v| v.as_ref())
    }
}

impl QuicExt for ServerSession {
    fn get_quic_transport_parameters(&self) -> Option<&[u8]> {
        self.imp.quic_params.as_ref().map(|v| v.as_ref())
    }
}

/// Methods specific to QUIC client sessions
pub trait ClientQuicExt {
    /// Make a new QUIC ClientSession. This differs from `ClientSession::new()`
    /// in that it takes an extra argument, `params`, which contains the
    /// TLS-encoded transport parameters to send.
    fn new_quic(config: &Arc<ClientConfig>, hostname: webpki::DNSNameRef, params: Vec<u8>)
                -> ClientSession {
        let mut imp = ClientSessionImpl::new(config);
        imp.start_handshake(hostname.into(), vec![
            ClientExtension::Unknown(UnknownExtension {
                typ: ExtensionType::TransportParameters,
                payload: Payload::new(params),
            })
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
        ServerSession {
            imp: ServerSessionImpl::new(config, vec![
                ServerExtension::Unknown(UnknownExtension {
                    typ: ExtensionType::TransportParameters,
                    payload: Payload::new(params),
                }),
            ]),
        }
    }
}

impl ServerQuicExt for ServerSession {}
