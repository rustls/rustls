//! Shared logic for TLS 1.3 client and server handshakes.

use crate::hash_hs::HandshakeHash;
#[cfg(feature = "logging")]
use crate::log::trace;
use crate::msgs::base::Payload;
use crate::msgs::enums::HandshakeType;
use crate::msgs::handshake::{
    CertificateEntry, CertificateExtension, CertificatePayloadTLS13, CertificateStatus,
    DigitallySignedStruct, HandshakeMessagePayload, HandshakePayload,
};
use crate::msgs::message::{Message, MessagePayload};
use crate::sign::Signer;
use crate::{verify, Certificate, CommonState, Error, ProtocolVersion};

pub(crate) fn emit_certificate(
    transcript: &mut HandshakeHash,
    common: &mut CommonState,
    context: Option<Vec<u8>>,
    cert_chain: Vec<Certificate>,
    ocsp_response: Option<&[u8]>,
    sct_list: Option<&[u8]>,
) {
    let mut cert_entries = cert_chain
        .into_iter()
        .map(|cert| CertificateEntry {
            cert,
            exts: Vec::new(),
        })
        .collect::<Vec<_>>();

    if let Some(end_entity_cert) = cert_entries.first_mut() {
        // Apply OCSP response to first certificate (we don't support OCSP
        // except for leaf certs).
        if let Some(ocsp) = ocsp_response {
            let cst = CertificateStatus::new(ocsp.to_owned());
            end_entity_cert
                .exts
                .push(CertificateExtension::CertificateStatus(cst));
        }

        // Likewise, SCT
        if let Some(sct_list) = sct_list {
            end_entity_cert
                .exts
                .push(CertificateExtension::make_sct(sct_list.to_owned()));
        }
    }

    let cert_body = CertificatePayloadTLS13::new(context, cert_entries);
    let c = Message {
        version: ProtocolVersion::TLSv1_3,
        payload: MessagePayload::Handshake(HandshakeMessagePayload {
            typ: HandshakeType::Certificate,
            payload: HandshakePayload::CertificateTLS13(cert_body),
        }),
    };

    trace!("sending certificate {:?}", c);
    transcript.add_message(&c);
    common.send_msg(c, true);
}

pub(crate) fn emit_certificate_verify(
    transcript: &mut HandshakeHash,
    common: &mut CommonState,
    signer: &dyn Signer,
    context_string_with_0: verify::ContextString,
) -> Result<(), Error> {
    let message = verify::construct_tls13_verify_message(
        &transcript.get_current_hash(),
        context_string_with_0,
    );

    let scheme = signer.scheme();
    let sig = signer.sign(&message)?;
    let dss = DigitallySignedStruct::new(scheme, sig);

    let m = Message {
        version: ProtocolVersion::TLSv1_3,
        payload: MessagePayload::Handshake(HandshakeMessagePayload {
            typ: HandshakeType::CertificateVerify,
            payload: HandshakePayload::CertificateVerify(dss),
        }),
    };

    transcript.add_message(&m);
    common.send_msg(m, true);
    Ok(())
}

pub(crate) fn emit_finished(
    transcript: &mut HandshakeHash,
    common: &mut CommonState,
    verify_data: ring::hmac::Tag,
) {
    let verify_data_payload = Payload::new(verify_data.as_ref());

    let m = Message {
        version: ProtocolVersion::TLSv1_3,
        payload: MessagePayload::Handshake(HandshakeMessagePayload {
            typ: HandshakeType::Finished,
            payload: HandshakePayload::Finished(verify_data_payload),
        }),
    };

    transcript.add_message(&m);
    common.send_msg(m, true);
}
