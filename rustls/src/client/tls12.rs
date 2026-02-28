use alloc::borrow::ToOwned;
use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;
use core::time::Duration;

pub(crate) use server_hello::TLS12_HANDLER;
use subtle::ConstantTimeEq;

use super::config::{ClientConfig, ClientSessionKey};
use super::{ClientAuthDetails, ServerCertDetails, Tls12Session};
use crate::ConnectionTrafficSecrets;
use crate::check::{inappropriate_handshake_message, inappropriate_message};
use crate::common_state::{Event, HandshakeKind, Input, Output, Side, State};
use crate::conn::ConnectionRandoms;
use crate::conn::kernel::KernelState;
use crate::crypto::cipher::{MessageDecrypter, MessageEncrypter, Payload};
use crate::crypto::kx::KeyExchangeAlgorithm;
use crate::crypto::{Identity, Signer};
use crate::enums::{CertificateType, ContentType, HandshakeType, ProtocolVersion};
use crate::error::{ApiMisuse, Error, InvalidMessage, PeerIncompatible, PeerMisbehaved};
use crate::hash_hs::HandshakeHash;
use crate::log::{debug, trace, warn};
use crate::msgs::{
    CertificateChain, ChangeCipherSpecPayload, ClientDhParams, ClientEcdhParams,
    ClientKeyExchangeParams, HandshakeAlignedProof, HandshakeMessagePayload, HandshakePayload,
    Message, MessagePayload, NewSessionTicketPayload, NewSessionTicketPayloadTls13,
    ServerKeyExchangeParams, SessionId, SizedPayload,
};
use crate::suites::{PartiallyExtractedSecrets, Suite};
use crate::sync::Arc;
use crate::tls12::{self, ConnectionSecrets, Tls12CipherSuite};
use crate::tls13::key_schedule::KeyScheduleTrafficSend;
use crate::verify::{self, DigitallySignedStruct, ServerIdentity, SignatureVerificationInput};

mod server_hello {
    use super::*;
    use crate::client::hs::{
        ClientHandler, ClientHelloInput, ClientSessionValue, ExpectServerHello,
    };
    use crate::msgs::ServerHelloPayload;
    use crate::sealed::Sealed;

    pub(crate) static TLS12_HANDLER: &dyn ClientHandler<Tls12CipherSuite> = &Handler;

    #[derive(Debug)]
    struct Handler;

    impl ClientHandler<Tls12CipherSuite> for Handler {
        fn handle_server_hello(
            &self,
            suite: &'static Tls12CipherSuite,
            server_hello: &ServerHelloPayload,
            Input { message, .. }: &Input<'_>,
            st: ExpectServerHello,
            output: &mut dyn Output,
        ) -> Result<Box<dyn State>, Error> {
            // Start our handshake hash, and input the server-hello.
            let mut transcript = st
                .transcript_buffer
                .start_hash(suite.common.hash_provider);
            transcript.add_message(message);

            let mut randoms = ConnectionRandoms::new(st.input.random, server_hello.random);
            randoms
                .server
                .clone_from_slice(&server_hello.random.0[..]);

            // Look for TLS1.3 downgrade signal in server random
            // both the server random and TLS12_DOWNGRADE_SENTINEL are
            // public values and don't require constant time comparison
            let has_downgrade_marker = randoms.server[24..] == tls12::DOWNGRADE_SENTINEL;
            if st
                .input
                .config
                .supports_version(ProtocolVersion::TLSv1_3)
                && has_downgrade_marker
            {
                return Err(PeerMisbehaved::AttemptedDowngradeToTls12WhenTls13IsSupported.into());
            }

            // If we didn't have an input session to resume, and we sent a session ID,
            // that implies we sent a TLS 1.3 legacy_session_id for compatibility purposes.
            // In this instance since we're now continuing a TLS 1.2 handshake the server
            // should not have echoed it back: it's a randomly generated session ID it couldn't
            // have known.
            if st.input.resuming.is_none()
                && !st.input.session_id.is_empty()
                && st.input.session_id == server_hello.session_id
            {
                return Err(PeerMisbehaved::ServerEchoedCompatibilitySessionId.into());
            }

            let ClientHelloInput {
                config,
                session_key,
                ..
            } = st.input;

            let resuming_session = st
                .input
                .resuming
                .and_then(|resuming| match resuming.value {
                    ClientSessionValue::Tls12(inner) => Some(inner),
                    ClientSessionValue::Tls13(_) => None,
                });

            // Doing EMS?
            let using_ems = server_hello
                .extended_master_secret_ack
                .is_some();
            if config.require_ems && !using_ems {
                return Err(PeerIncompatible::ExtendedMasterSecretExtensionRequired.into());
            }

            // Might the server send a ticket?
            let must_issue_new_ticket = if server_hello
                .session_ticket_ack
                .is_some()
            {
                debug!("Server supports tickets");
                true
            } else {
                false
            };

            // Might the server send a CertificateStatus between Certificate and
            // ServerKeyExchange?
            let may_send_cert_status = server_hello
                .certificate_status_request_ack
                .is_some();
            if may_send_cert_status {
                debug!("Server may staple OCSP response");
            }

            // See if we're successfully resuming.
            if let Some(resuming) = resuming_session {
                if resuming.session_id == server_hello.session_id {
                    debug!("Server agreed to resume");

                    // Is the server telling lies about the ciphersuite?
                    if resuming.suite != suite {
                        return Err(PeerMisbehaved::ResumptionOfferedWithVariedCipherSuite.into());
                    }

                    // And about EMS support?
                    if resuming.extended_ms != using_ems {
                        return Err(PeerMisbehaved::ResumptionOfferedWithVariedEms.into());
                    }

                    let secrets =
                        ConnectionSecrets::new_resume(randoms, suite, &resuming.master_secret);
                    config.key_log.log(
                        "CLIENT_RANDOM",
                        &secrets.randoms.client,
                        secrets.master_secret(),
                    );

                    let (dec, enc) = secrets.make_cipher_pair(Side::Client);
                    output.emit(Event::HandshakeKind(HandshakeKind::Resumed));
                    let cert_verified = verify::PeerVerified::assertion();
                    let sig_verified = verify::HandshakeSignatureValid::assertion();

                    let hs = HandshakeState {
                        config,
                        session_id: server_hello.session_id,
                        session_key,
                        using_ems,
                        transcript,
                    };
                    return if must_issue_new_ticket {
                        Ok(Box::new(ExpectNewTicket {
                            hs,
                            secrets,
                            // Since we're resuming, we verified the certificate and
                            // proof of possession in the prior session.
                            peer_identity: resuming.peer_identity().clone(),
                            resuming: Some((resuming, enc)),
                            pending_decrypter: dec,
                            cert_verified,
                            sig_verified,
                        }))
                    } else {
                        Ok(Box::new(ExpectCcs {
                            hs,
                            secrets,
                            peer_identity: resuming.peer_identity().clone(),
                            resuming: Some((resuming, enc)),
                            pending_decrypter: dec,
                            ticket: None,
                            cert_verified,
                            sig_verified,
                        }))
                    };
                }
            }

            output.emit(Event::HandshakeKind(HandshakeKind::Full));
            Ok(Box::new(ExpectCertificate {
                hs: HandshakeState {
                    config,
                    session_id: server_hello.session_id,
                    session_key,
                    using_ems,
                    transcript,
                },
                randoms,
                suite,
                may_send_cert_status,
                must_issue_new_ticket,
                negotiated_client_type: server_hello.client_certificate_type,
            }))
        }
    }

    impl Sealed for Handler {}
}

struct ExpectCertificate {
    hs: HandshakeState,
    randoms: ConnectionRandoms,
    suite: &'static Tls12CipherSuite,
    may_send_cert_status: bool,
    must_issue_new_ticket: bool,
    negotiated_client_type: Option<CertificateType>,
}

impl State for ExpectCertificate {
    fn handle(
        mut self: Box<Self>,
        Input { message, .. }: Input<'_>,
        _output: &mut dyn Output,
    ) -> Result<Box<dyn State>, Error> {
        self.hs.transcript.add_message(&message);
        let server_cert_chain = require_handshake_msg_move!(
            message,
            HandshakeType::Certificate,
            HandshakePayload::Certificate
        )?;

        if self.may_send_cert_status {
            Ok(Box::new(ExpectCertificateStatusOrServerKx {
                hs: self.hs,
                randoms: self.randoms,
                suite: self.suite,
                server_cert_chain: server_cert_chain.into_owned(),
                must_issue_new_ticket: self.must_issue_new_ticket,
                negotiated_client_type: self.negotiated_client_type,
            }))
        } else {
            Ok(Box::new(ExpectServerKx {
                hs: self.hs,
                randoms: self.randoms,
                suite: self.suite,
                server_cert: ServerCertDetails::new(server_cert_chain.into_owned(), vec![]),
                must_issue_new_ticket: self.must_issue_new_ticket,
                negotiated_client_type: self.negotiated_client_type,
            }))
        }
    }
}

struct ExpectCertificateStatusOrServerKx {
    hs: HandshakeState,
    randoms: ConnectionRandoms,
    suite: &'static Tls12CipherSuite,
    server_cert_chain: CertificateChain<'static>,
    must_issue_new_ticket: bool,
    negotiated_client_type: Option<CertificateType>,
}

impl State for ExpectCertificateStatusOrServerKx {
    fn handle(
        self: Box<Self>,
        input: Input<'_>,
        _output: &mut dyn Output,
    ) -> Result<Box<dyn State>, Error> {
        match input.message.payload {
            MessagePayload::Handshake {
                parsed: HandshakeMessagePayload(HandshakePayload::ServerKeyExchange(..)),
                ..
            } => ExpectServerKx {
                hs: self.hs,
                randoms: self.randoms,
                suite: self.suite,
                server_cert: ServerCertDetails::new(self.server_cert_chain, vec![]),
                must_issue_new_ticket: self.must_issue_new_ticket,
                negotiated_client_type: self.negotiated_client_type,
            }
            .handle_input(input),

            MessagePayload::Handshake {
                parsed: HandshakeMessagePayload(HandshakePayload::CertificateStatus(..)),
                ..
            } => ExpectCertificateStatus {
                hs: self.hs,
                randoms: self.randoms,
                suite: self.suite,
                server_cert_chain: self.server_cert_chain,
                must_issue_new_ticket: self.must_issue_new_ticket,
                negotiated_client_type: self.negotiated_client_type,
            }
            .handle_input(input),

            payload => Err(inappropriate_handshake_message(
                &payload,
                &[ContentType::Handshake],
                &[
                    HandshakeType::ServerKeyExchange,
                    HandshakeType::CertificateStatus,
                ],
            )),
        }
    }
}

struct ExpectCertificateStatus {
    hs: HandshakeState,
    randoms: ConnectionRandoms,
    suite: &'static Tls12CipherSuite,
    server_cert_chain: CertificateChain<'static>,
    must_issue_new_ticket: bool,
    negotiated_client_type: Option<CertificateType>,
}

impl ExpectCertificateStatus {
    fn handle_input(mut self, Input { message, .. }: Input<'_>) -> Result<Box<dyn State>, Error> {
        self.hs.transcript.add_message(&message);
        let server_cert_ocsp_response = require_handshake_msg_move!(
            message,
            HandshakeType::CertificateStatus,
            HandshakePayload::CertificateStatus
        )?
        .into_inner();

        trace!(
            "Server stapled OCSP response is {:?}",
            &server_cert_ocsp_response
        );

        let server_cert = ServerCertDetails::new(self.server_cert_chain, server_cert_ocsp_response);

        Ok(Box::new(ExpectServerKx {
            hs: self.hs,
            randoms: self.randoms,
            suite: self.suite,
            server_cert,
            must_issue_new_ticket: self.must_issue_new_ticket,
            negotiated_client_type: self.negotiated_client_type,
        }))
    }
}

struct ExpectServerKx {
    hs: HandshakeState,
    randoms: ConnectionRandoms,
    suite: &'static Tls12CipherSuite,
    server_cert: ServerCertDetails,
    must_issue_new_ticket: bool,
    negotiated_client_type: Option<CertificateType>,
}

impl ExpectServerKx {
    fn handle_input(mut self, Input { message, .. }: Input<'_>) -> Result<Box<dyn State>, Error> {
        let opaque_kx = require_handshake_msg!(
            message,
            HandshakeType::ServerKeyExchange,
            HandshakePayload::ServerKeyExchange
        )?;
        self.hs.transcript.add_message(&message);

        let kx = opaque_kx
            .unwrap_given_kxa(self.suite.kx)
            .ok_or(InvalidMessage::MissingKeyExchange)?;

        // Save the signature and signed parameters for later verification.
        let mut kx_params = Vec::new();
        kx.params.encode(&mut kx_params);
        let server_kx = ServerKxDetails::new(kx_params, kx.dss);

        match &kx.params {
            ServerKeyExchangeParams::Ecdh(ecdhe) => {
                debug!("ECDHE curve is {:?}", ecdhe.curve_params)
            }
            ServerKeyExchangeParams::Dh(dhe) => {
                debug!("DHE params are p = {:?}, g = {:?}", dhe.dh_p, dhe.dh_g)
            }
        }

        Ok(Box::new(ExpectServerDoneOrCertReq {
            hs: self.hs,
            randoms: self.randoms,
            suite: self.suite,
            server_cert: self.server_cert,
            server_kx,
            must_issue_new_ticket: self.must_issue_new_ticket,
            negotiated_client_type: self.negotiated_client_type,
        }))
    }
}

impl State for ExpectServerKx {
    fn handle(
        self: Box<Self>,
        input: Input<'_>,
        _output: &mut dyn Output,
    ) -> Result<Box<dyn State>, Error> {
        self.handle_input(input)
    }
}

fn emit_certificate(
    transcript: &mut HandshakeHash,
    cert_chain: CertificateChain<'_>,
    output: &mut dyn Output,
) {
    let cert = Message {
        version: ProtocolVersion::TLSv1_2,
        payload: MessagePayload::handshake(HandshakeMessagePayload(HandshakePayload::Certificate(
            cert_chain,
        ))),
    };

    transcript.add_message(&cert);
    output.send_msg(cert, false);
}

fn emit_client_kx(
    transcript: &mut HandshakeHash,
    kxa: KeyExchangeAlgorithm,
    output: &mut dyn Output,
    pub_key: &[u8],
) {
    let mut buf = Vec::new();
    match kxa {
        KeyExchangeAlgorithm::ECDHE => ClientKeyExchangeParams::Ecdh(ClientEcdhParams {
            public: pub_key.to_vec().into(),
        }),
        KeyExchangeAlgorithm::DHE => ClientKeyExchangeParams::Dh(ClientDhParams {
            public: SizedPayload::from(Payload::new(pub_key.to_vec())),
        }),
    }
    .encode(&mut buf);
    let pubkey = Payload::new(buf);

    let ckx = Message {
        version: ProtocolVersion::TLSv1_2,
        payload: MessagePayload::handshake(HandshakeMessagePayload(
            HandshakePayload::ClientKeyExchange(pubkey),
        )),
    };

    transcript.add_message(&ckx);
    output.send_msg(ckx, false);
}

fn emit_certverify(
    transcript: &mut HandshakeHash,
    signer: Box<dyn Signer>,
    output: &mut dyn Output,
) -> Result<(), Error> {
    let message = transcript
        .take_handshake_buf()
        .ok_or_else(|| Error::General("Expected transcript".to_owned()))?;

    let scheme = signer.scheme();
    let sig = signer.sign(&message)?;
    let body = DigitallySignedStruct::new(scheme, sig);

    let m = Message {
        version: ProtocolVersion::TLSv1_2,
        payload: MessagePayload::handshake(HandshakeMessagePayload(
            HandshakePayload::CertificateVerify(body),
        )),
    };

    transcript.add_message(&m);
    output.send_msg(m, false);
    Ok(())
}

fn emit_ccs(output: &mut dyn Output) {
    output.send_msg(
        Message {
            version: ProtocolVersion::TLSv1_2,
            payload: MessagePayload::ChangeCipherSpec(ChangeCipherSpecPayload {}),
        },
        false,
    );
}

fn emit_finished(
    secrets: &ConnectionSecrets,
    transcript: &mut HandshakeHash,
    output: &mut dyn Output,
    proof: &HandshakeAlignedProof,
) {
    let vh = transcript.current_hash();
    let verify_data = secrets.client_verify_data(&vh, proof);
    let verify_data_payload = Payload::Borrowed(&verify_data);

    let f = Message {
        version: ProtocolVersion::TLSv1_2,
        payload: MessagePayload::handshake(HandshakeMessagePayload(HandshakePayload::Finished(
            verify_data_payload,
        ))),
    };

    transcript.add_message(&f);
    output.send_msg(f, true);
}

struct ServerKxDetails {
    kx_params: Vec<u8>,
    kx_sig: DigitallySignedStruct,
}

impl ServerKxDetails {
    fn new(params: Vec<u8>, sig: DigitallySignedStruct) -> Self {
        Self {
            kx_params: params,
            kx_sig: sig,
        }
    }
}

// --- Either a CertificateRequest, or a ServerHelloDone. ---
// Existence of the CertificateRequest tells us the server is asking for
// client auth.  Otherwise we go straight to ServerHelloDone.
struct ExpectServerDoneOrCertReq {
    hs: HandshakeState,
    randoms: ConnectionRandoms,
    suite: &'static Tls12CipherSuite,
    server_cert: ServerCertDetails,
    server_kx: ServerKxDetails,
    must_issue_new_ticket: bool,
    negotiated_client_type: Option<CertificateType>,
}

impl State for ExpectServerDoneOrCertReq {
    fn handle(
        mut self: Box<Self>,
        input: Input<'_>,
        output: &mut dyn Output,
    ) -> Result<Box<dyn State>, Error> {
        if matches!(
            input.message.payload,
            MessagePayload::Handshake {
                parsed: HandshakeMessagePayload(HandshakePayload::CertificateRequest(_)),
                ..
            }
        ) {
            ExpectCertificateRequest {
                hs: self.hs,
                randoms: self.randoms,
                suite: self.suite,
                server_cert: self.server_cert,
                server_kx: self.server_kx,
                must_issue_new_ticket: self.must_issue_new_ticket,
                negotiated_client_type: self.negotiated_client_type,
            }
            .handle_input(input)
        } else {
            self.hs.transcript.abandon_client_auth();

            ExpectServerDone {
                hs: self.hs,
                randoms: self.randoms,
                suite: self.suite,
                server_cert: self.server_cert,
                server_kx: self.server_kx,
                client_auth: None,
                must_issue_new_ticket: self.must_issue_new_ticket,
            }
            .handle_input(input, output)
        }
    }
}

struct ExpectCertificateRequest {
    hs: HandshakeState,
    randoms: ConnectionRandoms,
    suite: &'static Tls12CipherSuite,
    server_cert: ServerCertDetails,
    server_kx: ServerKxDetails,
    must_issue_new_ticket: bool,
    negotiated_client_type: Option<CertificateType>,
}

impl ExpectCertificateRequest {
    fn handle_input(mut self, Input { message, .. }: Input<'_>) -> Result<Box<dyn State>, Error> {
        let certreq = require_handshake_msg!(
            message,
            HandshakeType::CertificateRequest,
            HandshakePayload::CertificateRequest
        )?;
        self.hs.transcript.add_message(&message);
        debug!("Got CertificateRequest {certreq:?}");

        // The RFC jovially describes the design here as 'somewhat complicated'
        // and 'somewhat underspecified'.  So thanks for that.
        //
        // We ignore certreq.certtypes as a result, since the information it contains
        // is entirely duplicated in certreq.sigschemes.

        const NO_CONTEXT: Option<Vec<u8>> = None; // TLS 1.2 doesn't use a context.
        let no_compression = None; // or compression
        let client_auth = ClientAuthDetails::resolve(
            self.negotiated_client_type
                .unwrap_or(CertificateType::X509),
            self.hs.config.resolver().as_ref(),
            Some(&certreq.canames),
            &certreq.sigschemes,
            NO_CONTEXT,
            no_compression,
        );

        Ok(Box::new(ExpectServerDone {
            hs: self.hs,
            randoms: self.randoms,
            suite: self.suite,
            server_cert: self.server_cert,
            server_kx: self.server_kx,
            client_auth: Some(client_auth),
            must_issue_new_ticket: self.must_issue_new_ticket,
        }))
    }
}

struct ExpectServerDone {
    hs: HandshakeState,
    randoms: ConnectionRandoms,
    suite: &'static Tls12CipherSuite,
    server_cert: ServerCertDetails,
    server_kx: ServerKxDetails,
    client_auth: Option<ClientAuthDetails>,
    must_issue_new_ticket: bool,
}

impl ExpectServerDone {
    fn handle_input(
        mut self,
        input: Input<'_>,
        output: &mut dyn Output,
    ) -> Result<Box<dyn State>, Error> {
        match input.message.payload {
            MessagePayload::Handshake {
                parsed: HandshakeMessagePayload(HandshakePayload::ServerHelloDone),
                ..
            } => {}
            payload => {
                return Err(inappropriate_handshake_message(
                    &payload,
                    &[ContentType::Handshake],
                    &[HandshakeType::ServerHelloDone],
                ));
            }
        }

        self.hs
            .transcript
            .add_message(&input.message);

        let proof = input.check_aligned_handshake()?;

        trace!("Server cert is {:?}", self.server_cert.cert_chain);
        debug!("Server DNS name is {:?}", self.hs.session_key.server_name);

        let suite = self.suite;

        // 1. Verify the cert chain.
        // 2. Verify that the top certificate signed their kx.
        // 3. If doing client auth, send our Certificate.
        // 4. Complete the key exchange:
        //    a) generate our kx pair
        //    b) emit a ClientKeyExchange containing it
        //    c) if doing client auth, emit a CertificateVerify
        //    d) derive the shared keys
        //    e) emit a CCS
        //    f) use the derived keys to start encryption
        // 5. emit a Finished, our first encrypted message under the new keys.

        // 1.
        let identity = Identity::from_peer(self.server_cert.cert_chain.0, CertificateType::X509)?
            .ok_or(PeerMisbehaved::NoCertificatesPresented)?;

        let cert_verified = self
            .hs
            .config
            .verifier()
            .verify_identity(&ServerIdentity {
                identity: &identity,
                server_name: &self.hs.session_key.server_name,
                ocsp_response: &self.server_cert.ocsp_response,
                now: self.hs.config.current_time()?,
            })?;

        // 2.
        // Build up the contents of the signed message.
        // It's ClientHello.random || ServerHello.random || ServerKeyExchange.params
        let sig_verified = {
            let mut message = Vec::new();
            message.extend_from_slice(&self.randoms.client);
            message.extend_from_slice(&self.randoms.server);
            message.extend_from_slice(&self.server_kx.kx_params);

            // Check the signature is compatible with the ciphersuite.
            let signature = &self.server_kx.kx_sig;
            if !suite.usable_for_signature_scheme(signature.scheme) {
                warn!(
                    "peer signed kx with wrong algorithm (got {:?} expect {:?})",
                    signature.scheme.algorithm(),
                    suite.sign
                );
                return Err(PeerMisbehaved::SignedKxWithWrongAlgorithm.into());
            }

            self.hs
                .config
                .verifier()
                .verify_tls12_signature(&SignatureVerificationInput {
                    message: &message,
                    signer: &identity.as_signer(),
                    signature,
                })?
        };

        // 3.
        if let Some(client_auth) = &self.client_auth {
            let certs = match client_auth {
                ClientAuthDetails::Empty { .. } => CertificateChain::default(),
                ClientAuthDetails::Verify { credentials, .. } => {
                    CertificateChain::from_signer(credentials)
                }
            };
            emit_certificate(&mut self.hs.transcript, certs, output);
        }

        // 4a.
        let kx_params = tls12::decode_kx_params::<ServerKeyExchangeParams>(
            self.suite.kx,
            &self.server_kx.kx_params,
        )?;
        let maybe_skxg = match &kx_params {
            ServerKeyExchangeParams::Ecdh(ecdh) => self
                .hs
                .config
                .provider()
                .find_kx_group(ecdh.curve_params.named_group, ProtocolVersion::TLSv1_2),
            ServerKeyExchangeParams::Dh(dh) => {
                let ffdhe_group = dh.as_ffdhe_group();

                self.hs
                    .config
                    .provider()
                    .kx_groups
                    .iter()
                    .find(|kxg| kxg.ffdhe_group() == Some(ffdhe_group))
                    .copied()
            }
        };
        let Some(skxg) = maybe_skxg else {
            return Err(PeerMisbehaved::SelectedUnofferedKxGroup.into());
        };
        let kx = skxg.start()?.into_single();

        // 4b.
        emit_client_kx(&mut self.hs.transcript, self.suite.kx, output, kx.pub_key());
        // Note: EMS handshake hash only runs up to ClientKeyExchange.
        let ems_seed = self
            .hs
            .using_ems
            .then(|| self.hs.transcript.current_hash());

        // 4c.
        if let Some(ClientAuthDetails::Verify { credentials, .. }) = self.client_auth {
            emit_certverify(&mut self.hs.transcript, credentials.signer, output)?;
        }

        // 4d. Derive secrets.
        // An alert at this point will be sent in plaintext.  That must happen
        // prior to the CCS, or else the peer will try to decrypt it.
        let secrets = ConnectionSecrets::from_key_exchange(
            kx,
            kx_params.pub_key(),
            ems_seed,
            self.randoms,
            suite,
        )?;
        output.emit(Event::KeyExchangeGroup(skxg));

        // 4e. CCS. We are definitely going to switch on encryption.
        emit_ccs(output);

        // 4f. Now commit secrets.
        self.hs.config.key_log.log(
            "CLIENT_RANDOM",
            &secrets.randoms.client,
            secrets.master_secret(),
        );

        let (dec, encrypter) = secrets.make_cipher_pair(Side::Client);
        output.emit(Event::MessageEncrypter {
            encrypter,
            limit: secrets
                .suite()
                .common
                .confidentiality_limit,
        });

        // 5.
        emit_finished(&secrets, &mut self.hs.transcript, output, &proof);

        if self.must_issue_new_ticket {
            Ok(Box::new(ExpectNewTicket {
                hs: self.hs,
                secrets,
                peer_identity: identity,
                resuming: None,
                pending_decrypter: dec,
                cert_verified,
                sig_verified,
            }))
        } else {
            Ok(Box::new(ExpectCcs {
                hs: self.hs,
                secrets,
                peer_identity: identity,
                resuming: None,
                pending_decrypter: dec,
                ticket: None,
                cert_verified,
                sig_verified,
            }))
        }
    }
}

impl State for ExpectServerDone {
    fn handle(
        self: Box<Self>,
        input: Input<'_>,
        output: &mut dyn Output,
    ) -> Result<Box<dyn State>, Error> {
        self.handle_input(input, output)
    }
}

struct ExpectNewTicket {
    hs: HandshakeState,
    secrets: ConnectionSecrets,
    peer_identity: Identity<'static>,
    resuming: Option<(Tls12Session, Box<dyn MessageEncrypter>)>,
    pending_decrypter: Box<dyn MessageDecrypter>,
    cert_verified: verify::PeerVerified,
    sig_verified: verify::HandshakeSignatureValid,
}

impl State for ExpectNewTicket {
    fn handle(
        mut self: Box<Self>,
        Input { message, .. }: Input<'_>,
        _output: &mut dyn Output,
    ) -> Result<Box<dyn State>, Error> {
        self.hs.transcript.add_message(&message);

        let nst = require_handshake_msg_move!(
            message,
            HandshakeType::NewSessionTicket,
            HandshakePayload::NewSessionTicket
        )?;

        Ok(Box::new(ExpectCcs {
            hs: self.hs,
            secrets: self.secrets,
            resuming: self.resuming,
            peer_identity: self.peer_identity,
            pending_decrypter: self.pending_decrypter,
            ticket: Some(nst),
            cert_verified: self.cert_verified,
            sig_verified: self.sig_verified,
        }))
    }
}

// -- Waiting for their CCS --
struct ExpectCcs {
    hs: HandshakeState,
    secrets: ConnectionSecrets,
    peer_identity: Identity<'static>,
    resuming: Option<(Tls12Session, Box<dyn MessageEncrypter>)>,
    pending_decrypter: Box<dyn MessageDecrypter>,
    ticket: Option<NewSessionTicketPayload>,
    cert_verified: verify::PeerVerified,
    sig_verified: verify::HandshakeSignatureValid,
}

impl State for ExpectCcs {
    fn handle(
        self: Box<Self>,
        input: Input<'_>,
        output: &mut dyn Output,
    ) -> Result<Box<dyn State>, Error> {
        match input.message.payload {
            MessagePayload::ChangeCipherSpec(..) => {}
            payload => {
                return Err(inappropriate_message(
                    &payload,
                    &[ContentType::ChangeCipherSpec],
                ));
            }
        }
        // CCS should not be received interleaved with fragmented handshake-level
        // message.
        let proof = input.check_aligned_handshake()?;

        // Note: msgs layer validates trivial contents of CCS.
        output.emit(Event::MessageDecrypter {
            decrypter: self.pending_decrypter,
            proof,
        });

        Ok(Box::new(ExpectFinished {
            hs: self.hs,
            peer_identity: self.peer_identity,
            resuming: self.resuming,
            ticket: self.ticket,
            secrets: self.secrets,
            cert_verified: self.cert_verified,
            sig_verified: self.sig_verified,
        }))
    }
}

struct ExpectFinished {
    hs: HandshakeState,
    peer_identity: Identity<'static>,
    resuming: Option<(Tls12Session, Box<dyn MessageEncrypter>)>,
    ticket: Option<NewSessionTicketPayload>,
    secrets: ConnectionSecrets,
    cert_verified: verify::PeerVerified,
    sig_verified: verify::HandshakeSignatureValid,
}

impl ExpectFinished {
    // -- Waiting for their finished --
    fn save_session(&mut self) {
        // Save a ticket.  If we got a new ticket, save that.  Otherwise, save the
        // original ticket again.
        let (mut ticket, lifetime) = match self.ticket.take() {
            Some(nst) => (nst.ticket, nst.lifetime_hint),
            None => (
                Arc::new(SizedPayload::from(Payload::new(Vec::new()))),
                Duration::ZERO,
            ),
        };

        if ticket.is_empty() {
            if let Some((resuming_session, _)) = &mut self.resuming {
                ticket = resuming_session.ticket.clone();
            }
        }

        if self.hs.session_id.is_empty() && ticket.is_empty() {
            debug!("Session not saved: server didn't allocate id or ticket");
            return;
        }

        let Ok(now) = self.hs.config.current_time() else {
            debug!("Could not get current time");
            return;
        };

        let session_value = Tls12Session::new(
            self.secrets.suite(),
            self.hs.session_id,
            ticket,
            self.secrets.master_secret(),
            self.peer_identity.clone(),
            now,
            lifetime,
            self.hs.using_ems,
        );

        self.hs
            .config
            .resumption
            .store
            .set_tls12_session(self.hs.session_key.clone(), session_value);
    }
}

impl State for ExpectFinished {
    fn handle(
        self: Box<Self>,
        input: Input<'_>,
        output: &mut dyn Output,
    ) -> Result<Box<dyn State>, Error> {
        let mut st = *self;
        let finished = require_handshake_msg!(
            input.message,
            HandshakeType::Finished,
            HandshakePayload::Finished
        )?;

        let proof = input.check_aligned_handshake()?;

        // Work out what verify_data we expect.
        let vh = st.hs.transcript.current_hash();
        let expect_verify_data = st
            .secrets
            .server_verify_data(&vh, &proof);

        // Constant-time verification of this is relatively unimportant: they only
        // get one chance.  But it can't hurt.
        let fin_verified =
            match ConstantTimeEq::ct_eq(&expect_verify_data[..], finished.bytes()).into() {
                true => verify::FinishedMessageVerified::assertion(),
                false => {
                    return Err(PeerMisbehaved::IncorrectFinished.into());
                }
            };

        // Hash this message too.
        st.hs
            .transcript
            .add_message(&input.message);

        st.save_session();

        if let Some((_, encrypter)) = st.resuming.take() {
            emit_ccs(output);
            output.emit(Event::MessageEncrypter {
                encrypter,
                limit: st
                    .secrets
                    .suite()
                    .common
                    .confidentiality_limit,
            });
            emit_finished(&st.secrets, &mut st.hs.transcript, output, &proof);
        }

        let extracted_secrets = st
            .hs
            .config
            .enable_secret_extraction
            .then(|| st.secrets.extract_secrets(Side::Client));

        output.emit(Event::PeerIdentity(st.peer_identity));
        output.emit(Event::Exporter(st.secrets.into_exporter()));
        output.emit(Event::StartTraffic);

        Ok(Box::new(ExpectTraffic {
            extracted_secrets,
            _cert_verified: st.cert_verified,
            _sig_verified: st.sig_verified,
            _fin_verified: fin_verified,
        }))
    }

    // we could not decrypt the encrypted handshake message with session resumption
    // this might mean that the ticket was invalid for some reason, so we remove it
    // from the store to restart a session from scratch
    fn handle_decrypt_error(&self) {
        if self.resuming.is_some() {
            self.hs
                .config
                .resumption
                .store
                .remove_tls12_session(&self.hs.session_key);
        }
    }
}

struct HandshakeState {
    config: Arc<ClientConfig>,
    session_id: SessionId,
    session_key: ClientSessionKey<'static>,
    using_ems: bool,
    transcript: HandshakeHash,
}

// -- Traffic transit state --
struct ExpectTraffic {
    // only `Some` if `config.enable_secret_extraction` is true
    extracted_secrets: Option<Result<PartiallyExtractedSecrets, Error>>,
    _cert_verified: verify::PeerVerified,
    _sig_verified: verify::HandshakeSignatureValid,
    _fin_verified: verify::FinishedMessageVerified,
}

impl State for ExpectTraffic {
    fn handle(
        self: Box<Self>,
        Input { message, .. }: Input<'_>,
        output: &mut dyn Output,
    ) -> Result<Box<dyn State>, Error> {
        match message.payload {
            MessagePayload::ApplicationData(payload) => output.received_plaintext(payload),
            payload => {
                return Err(inappropriate_message(
                    &payload,
                    &[ContentType::ApplicationData],
                ));
            }
        }
        Ok(self)
    }

    fn into_external_state(
        mut self: Box<Self>,
        _send_keys: &Option<Box<KeyScheduleTrafficSend>>,
    ) -> Result<(PartiallyExtractedSecrets, Box<dyn KernelState + 'static>), Error> {
        match self.extracted_secrets.take() {
            Some(extracted_secrets) => Ok((extracted_secrets?, self)),
            None => Err(ApiMisuse::SecretExtractionRequiresPriorOptIn.into()),
        }
    }
}

impl KernelState for ExpectTraffic {
    fn update_rx_secret(&mut self) -> Result<ConnectionTrafficSecrets, Error> {
        Err(ApiMisuse::KeyUpdateNotAvailableForTls12.into())
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn handle_new_session_ticket(
        &self,
        _message: &NewSessionTicketPayloadTls13,
    ) -> Result<(), Error> {
        Err(Error::Unreachable(
            "TLS 1.2 session tickets may not be sent once the handshake has completed",
        ))
    }
}
