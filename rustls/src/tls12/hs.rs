//! Shared logic for TLS 1.2 client and server handshakes.
//!
use crate::check::inappropriate_handshake_message;
use crate::msgs::enums::{ContentType, HandshakeType};
use crate::msgs::handshake::{HandshakeMessagePayload, HandshakePayload};
use crate::msgs::message::{Message, MessagePayload};
use crate::{CommonState, Error};

pub(crate) fn handle_traffic(
    common_state: &mut CommonState,
    m: Message,
    is_valid_renegotiation_request: fn(&HandshakePayload) -> bool,
) -> Result<(), Error> {
    match m.payload {
        MessagePayload::ApplicationData(payload) => {
            common_state.take_received_plaintext(payload);
            Ok(())
        }
        MessagePayload::Handshake(HandshakeMessagePayload { payload, .. })
            if is_valid_renegotiation_request(&payload) =>
        {
            // XXX(https://github.com/rustls/rustls/issues/952): DoS potential.
            common_state.send_no_renegotiation_warning_alert();
            Ok(())
        }
        payload => Err(inappropriate_handshake_message(
            &payload,
            &[ContentType::ApplicationData, ContentType::Handshake],
            &[HandshakeType::HelloRequest],
        )),
    }
}
