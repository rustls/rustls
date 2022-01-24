//! Shared logic for TLS 1.2 client and server handshakes.
//!
use crate::check::inappropriate_handshake_message;
use crate::hash_hs::HandshakeHash;
use crate::msgs::base::Payload;
use crate::msgs::enums::{AlertDescription, ContentType, HandshakeType};
use crate::msgs::handshake::{HandshakeMessagePayload, HandshakePayload};
use crate::msgs::message::{Message, MessagePayload};
use crate::tls12::{ConnectionSecrets, FinishedLabel};
use crate::{verify, Certificate, CommonState, Error, ProtocolVersion};
use ring::constant_time;

pub(crate) fn emit_certificate(
    transcript: &mut HandshakeHash,
    common: &mut CommonState,
    cert_chain: &[Certificate],
) {
    let cert = Message {
        version: ProtocolVersion::TLSv1_2,
        payload: MessagePayload::Handshake(HandshakeMessagePayload {
            typ: HandshakeType::Certificate,
            payload: HandshakePayload::Certificate(cert_chain.to_owned()),
        }),
    };

    transcript.add_message(&cert);
    common.send_msg(cert, false);
}

pub(crate) fn emit_finished(
    secrets: &ConnectionSecrets,
    transcript: &mut HandshakeHash,
    common: &mut CommonState,
    finished_label: FinishedLabel,
) {
    let vh = transcript.get_current_hash();
    let verify_data = secrets.make_verify_data(&vh, finished_label);
    let verify_data_payload = Payload::new(verify_data);

    let f = Message {
        version: ProtocolVersion::TLSv1_2,
        payload: MessagePayload::Handshake(HandshakeMessagePayload {
            typ: HandshakeType::Finished,
            payload: HandshakePayload::Finished(verify_data_payload),
        }),
    };

    transcript.add_message(&f);
    common.send_msg(f, true);
}

pub(crate) fn handle_finished(
    secrets: &ConnectionSecrets,
    transcript: &HandshakeHash,
    common: &mut CommonState,
    finished_label: FinishedLabel,
    m: &Message,
) -> Result<verify::FinishedMessageVerified, Error> {
    let finished = require_handshake_msg!(m, HandshakeType::Finished, HandshakePayload::Finished)?;
    common.check_aligned_handshake()?;

    let vh = transcript.get_current_hash();
    let expect_verify_data = secrets.make_verify_data(&vh, finished_label);

    // Constant-time verification of this is relatively unimportant: they only
    // get one chance.  But it can't hurt.
    let fin_verified = constant_time::verify_slices_are_equal(&expect_verify_data, &finished.0)
        .map_err(|_| {
            common.send_fatal_alert(AlertDescription::DecryptError);
            Error::DecryptError
        })
        .map(|_| verify::FinishedMessageVerified::assertion())?;

    Ok(fin_verified)
}

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
