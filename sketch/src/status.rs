use alloc::vec::Vec;

use crate::{CertificateEntry, DigitallySignedStruct, ProtocolVersion};

#[derive(Debug)]
pub enum State {
    /// TLS records related to the handshake have been placed in the `outgoing_tls` buffer and must
    /// be transmitted to continue with the handshake process
    MustTransmitTlsData,

    /// More TLS data needs to be added to the `incoming_tls` buffer to continue with the handshake
    NeedsMoreTlsData,

    /// The supported verify schemes must be provided using `add_supported_verify_schemes` to continue with the handshake
    NeedsSupportedVerifySchemes,

    /// `incoming_tls` has application data that `decrypt_incoming` can decrypt
    ReceivedAppData,

    /// `incoming_tls` has early ("0-RTT") data that `decrypt_early_data` can decrypt
    ReceivedEarlyData,

    /// Handshake is complete. `decrypt_incoming` and `decrypt_outgoing` may now be freely used
    TrafficTransit,

    /// Received a `Certificate` message
    ReceivedCertificate(Vec<CertificateEntry>),

    /// Received a `ServerKeyExchange` (TLS 1.2) / `CertificateVerify` (TLS 1.3) message
    ReceivedSignature(DigitallySignedStruct),

    /// Needs to send back the `message` signed. provide it with the either `handshake_signature`
    NeedsSignature {
        // XXX rustls passes this around as plain bytes but in public API this should be an opaque structure
        message: Vec<u8>,
        version: ProtocolVersion,
    },
}

#[derive(Default, Clone, Copy)]
pub struct Capabilities {
    pub may_encrypt_app_data: bool,
    pub may_encrypt_early_data: bool,
}

#[must_use]
pub struct Status {
    pub caps: Capabilities,
    pub state: State,
}
