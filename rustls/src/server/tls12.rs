use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;

pub(crate) use client_hello::TLS12_HANDLER;
use pki_types::UnixTime;
use subtle::ConstantTimeEq;

use super::config::ServerConfig;
use super::connection::ServerConnectionData;
use super::hs::{self, ServerContext};
use crate::check::inappropriate_message;
use crate::common_state::{CommonState, HandshakeFlightTls12, HandshakeKind, Side, State};
use crate::conn::ConnectionRandoms;
use crate::conn::kernel::{Direction, KernelContext, KernelState};
use crate::crypto::cipher::Payload;
use crate::crypto::kx::ActiveKeyExchange;
use crate::crypto::{Identity, TicketProducer};
use crate::enums::{CertificateType, ContentType, HandshakeType, ProtocolVersion};
use crate::error::{Error, PeerIncompatible, PeerMisbehaved};
use crate::hash_hs::HandshakeHash;
use crate::log::{debug, trace};
use crate::msgs::ccs::ChangeCipherSpecPayload;
use crate::msgs::codec::Codec;
use crate::msgs::deframer::HandshakeAlignedProof;
use crate::msgs::handshake::{
    CertificateChain, ClientKeyExchangeParams, HandshakeMessagePayload, HandshakePayload,
    NewSessionTicketPayload, NewSessionTicketPayloadTls13, SessionId,
};
use crate::msgs::message::{Message, MessagePayload};
use crate::msgs::persist;
use crate::suites::PartiallyExtractedSecrets;
use crate::sync::Arc;
use crate::tls12::{self, ConnectionSecrets, Tls12CipherSuite};
use crate::verify::{ClientIdentity, SignatureVerificationInput};
use crate::{ConnectionTrafficSecrets, verify};

mod client_hello {
    use super::*;
    use crate::common_state::KxState;
    use crate::crypto::kx::SupportedKxGroup;
    use crate::crypto::{SelectedCredential, Signer};
    use crate::msgs::enums::{ClientCertificateType, Compression};
    use crate::msgs::handshake::{
        CertificateRequestPayload, CertificateStatus, ClientHelloPayload, ClientSessionTicket,
        Random, ServerExtensionsInput, ServerHelloPayload, ServerKeyExchange,
        ServerKeyExchangeParams, ServerKeyExchangePayload,
    };
    use crate::sealed::Sealed;
    use crate::server::hs::{ClientHelloInput, ExpectClientHello, ServerHandler};
    use crate::verify::DigitallySignedStruct;

    pub(crate) static TLS12_HANDLER: &dyn ServerHandler<Tls12CipherSuite> = &Handler;

    #[derive(Debug)]
    struct Handler;

    impl ServerHandler<Tls12CipherSuite> for Handler {
        fn handle_client_hello(
            &self,
            suite: &'static Tls12CipherSuite,
            kx_group: &'static dyn SupportedKxGroup,
            credentials: SelectedCredential,
            input: ClientHelloInput<'_>,
            mut st: ExpectClientHello,
            cx: &mut ServerContext<'_>,
        ) -> hs::NextStateOrError {
            let mut randoms = st.randoms(&input)?;
            let mut transcript = st
                .transcript
                .start(suite.common.hash_provider)?;

            // -- TLS1.2 only from hereon in --
            transcript.add_message(input.message);

            if input
                .client_hello
                .extended_master_secret_request
                .is_some()
            {
                st.using_ems = true;
            } else if st.config.require_ems {
                return Err(PeerIncompatible::ExtendedMasterSecretExtensionRequired.into());
            }

            // "RFC 4492 specified that if this extension is missing,
            // it means that only the uncompressed point format is
            // supported"
            // - <https://datatracker.ietf.org/doc/html/rfc8422#section-5.1.2>
            let supported_ec_point_formats = input
                .client_hello
                .ec_point_formats
                .unwrap_or_default();

            trace!("ecpoints {supported_ec_point_formats:?}");

            if !supported_ec_point_formats.uncompressed {
                return Err(PeerIncompatible::UncompressedEcPointsRequired.into());
            }

            // -- If TLS1.3 is enabled, signal the downgrade in the server random
            if !st
                .config
                .provider
                .tls13_cipher_suites
                .is_empty()
            {
                randoms.server[24..].copy_from_slice(&tls12::DOWNGRADE_SENTINEL);
            }

            // -- Check for resumption --
            // We can do this either by (in order of preference):
            // 1. receiving a ticket that decrypts
            // 2. receiving a sessionid that is in our cache
            //
            // If we receive a ticket, the sessionid won't be in our
            // cache, so don't check.
            //
            // If either works, we end up with a ServerConnectionValue
            // which is passed to start_resumption and concludes
            // our handling of the ClientHello.
            //
            let mut ticket_received = false;
            let resume_data = input
                .client_hello
                .session_ticket
                .as_ref()
                .and_then(|ticket_ext| match ticket_ext {
                    ClientSessionTicket::Offer(ticket) => Some(ticket),
                    _ => None,
                })
                .and_then(|ticket| {
                    ticket_received = true;
                    debug!("Ticket received");
                    let data = st
                        .config
                        .ticketer
                        .as_ref()
                        .and_then(|ticketer| ticketer.decrypt(ticket.bytes()));
                    if data.is_none() {
                        debug!("Ticket didn't decrypt");
                    }
                    data
                })
                .or_else(|| {
                    // Perhaps resume?  If we received a ticket, the sessionid
                    // does not correspond to a real session.
                    if input.client_hello.session_id.is_empty() || ticket_received {
                        return None;
                    }

                    st.config
                        .session_storage
                        .get(input.client_hello.session_id.as_ref())
                })
                .and_then(|x| persist::ServerSessionValue::read_bytes(&x).ok())
                .and_then(|resumedata| match resumedata {
                    persist::ServerSessionValue::Tls12(tls12) => Some(tls12),
                    _ => None,
                })
                .filter(|resumedata| {
                    resumedata
                        .common
                        .can_resume(suite.common.suite, &cx.data.sni)
                        && (resumedata.extended_ms == st.using_ems
                            || (resumedata.extended_ms && !st.using_ems))
                });

            if let Some(data) = resume_data {
                let proof = input.proof;
                return start_resumption(
                    suite,
                    st.using_ems,
                    cx,
                    input,
                    transcript,
                    randoms,
                    st.extra_exts,
                    st.config,
                    data,
                    proof,
                );
            }

            let mut ocsp_response = credentials.ocsp.as_deref();

            // If we're not offered a ticket or a potential session ID, allocate a session ID.
            if !st.config.session_storage.can_cache() {
                st.session_id = SessionId::empty();
            } else if st.session_id.is_empty() && !ticket_received {
                st.session_id = SessionId::random(st.config.provider.secure_random)?;
            }

            cx.common.kx_state = KxState::Start(kx_group);
            cx.common.handshake_kind = Some(HandshakeKind::Full);

            let mut flight = HandshakeFlightTls12::new(&mut transcript);

            let send_ticket = emit_server_hello(
                &mut flight,
                &st.config,
                cx,
                st.session_id,
                suite,
                st.using_ems,
                &mut ocsp_response,
                input.client_hello,
                None,
                &randoms,
                st.extra_exts,
            )?;
            emit_certificate(&mut flight, &credentials);
            match ocsp_response {
                None | Some([]) => {}
                Some(response) => emit_cert_status(&mut flight, response),
            }
            let server_kx = emit_server_kx(&mut flight, kx_group, credentials.signer, &randoms)?;
            let doing_client_auth = emit_certificate_req(&mut flight, &st.config)?;
            emit_server_hello_done(&mut flight);

            flight.finish(cx.common);

            if doing_client_auth {
                Ok(Box::new(ExpectCertificate {
                    config: st.config,
                    transcript,
                    randoms,
                    session_id: st.session_id,
                    suite,
                    using_ems: st.using_ems,
                    server_kx,
                    send_ticket,
                }))
            } else {
                Ok(Box::new(ExpectClientKx {
                    config: st.config,
                    transcript,
                    randoms,
                    session_id: st.session_id,
                    suite,
                    using_ems: st.using_ems,
                    server_kx,
                    peer_identity: None,
                    send_ticket,
                }))
            }
        }
    }

    impl Sealed for Handler {}

    fn start_resumption(
        suite: &'static Tls12CipherSuite,
        using_ems: bool,
        cx: &mut ServerContext<'_>,
        input: ClientHelloInput<'_>,
        mut transcript: HandshakeHash,
        randoms: ConnectionRandoms,
        extra_exts: ServerExtensionsInput<'static>,
        config: Arc<ServerConfig>,
        resumedata: persist::Tls12ServerSessionValue,
        proof: HandshakeAlignedProof,
    ) -> hs::NextStateOrError {
        debug!("Resuming connection");

        if resumedata.extended_ms && !using_ems {
            return Err(PeerMisbehaved::ResumptionAttemptedWithVariedEms.into());
        }

        let session_id = input.client_hello.session_id;
        let mut flight = HandshakeFlightTls12::new(&mut transcript);
        let send_ticket = emit_server_hello(
            &mut flight,
            &config,
            cx,
            session_id,
            suite,
            using_ems,
            &mut None,
            input.client_hello,
            Some(&resumedata),
            &randoms,
            extra_exts,
        )?;
        flight.finish(cx.common);

        let secrets = ConnectionSecrets::new_resume(randoms, suite, &resumedata.master_secret);
        config.key_log.log(
            "CLIENT_RANDOM",
            &secrets.randoms.client,
            secrets.master_secret(),
        );
        cx.common
            .start_encryption_tls12(&secrets, Side::Server);
        cx.common.peer_identity = resumedata.common.peer_identity;
        cx.common.handshake_kind = Some(HandshakeKind::Resumed);

        if send_ticket {
            let now = config.current_time()?;

            if let Some(ticketer) = config.ticketer.as_deref() {
                emit_ticket(&secrets, &mut transcript, using_ems, cx, ticketer, now)?;
            }
        }
        emit_ccs(cx.common);
        cx.common
            .record_layer
            .start_encrypting();
        emit_finished(&secrets, &mut transcript, cx.common, &proof);

        Ok(Box::new(ExpectCcs {
            config,
            secrets,
            transcript,
            session_id,
            using_ems,
            resuming: true,
            send_ticket,
        }))
    }

    fn emit_server_hello(
        flight: &mut HandshakeFlightTls12<'_>,
        config: &ServerConfig,
        cx: &mut ServerContext<'_>,
        session_id: SessionId,
        suite: &'static Tls12CipherSuite,
        using_ems: bool,
        ocsp_response: &mut Option<&[u8]>,
        hello: &ClientHelloPayload,
        resumedata: Option<&persist::Tls12ServerSessionValue>,
        randoms: &ConnectionRandoms,
        extra_exts: ServerExtensionsInput<'static>,
    ) -> Result<bool, Error> {
        let mut ep = hs::ExtensionProcessing::new(extra_exts, hello, config);
        ep.process_common(cx, ocsp_response, resumedata.map(|r| &r.common))?;
        ep.process_tls12(ocsp_response, using_ems);

        let sh = HandshakeMessagePayload(HandshakePayload::ServerHello(ServerHelloPayload {
            legacy_version: ProtocolVersion::TLSv1_2,
            random: Random::from(randoms.server),
            session_id,
            cipher_suite: suite.common.suite,
            compression_method: Compression::Null,
            extensions: ep.extensions,
        }));
        trace!("sending server hello {sh:?}");
        flight.add(sh);

        Ok(ep.send_ticket)
    }

    fn emit_certificate(flight: &mut HandshakeFlightTls12<'_>, credentials: &SelectedCredential) {
        flight.add(HandshakeMessagePayload(HandshakePayload::Certificate(
            CertificateChain::from_signer(credentials),
        )));
    }

    fn emit_cert_status(flight: &mut HandshakeFlightTls12<'_>, ocsp: &[u8]) {
        flight.add(HandshakeMessagePayload(
            HandshakePayload::CertificateStatus(CertificateStatus::new(ocsp)),
        ));
    }

    fn emit_server_kx(
        flight: &mut HandshakeFlightTls12<'_>,
        selected_group: &'static dyn SupportedKxGroup,
        credentials: Box<dyn Signer>,
        randoms: &ConnectionRandoms,
    ) -> Result<Box<dyn ActiveKeyExchange>, Error> {
        let kx = selected_group.start()?.into_single();
        let kx_params = ServerKeyExchangeParams::new(&*kx);

        let mut msg = Vec::new();
        msg.extend(randoms.client);
        msg.extend(randoms.server);
        kx_params.encode(&mut msg);

        let sigscheme = credentials.scheme();
        let sig = credentials.sign(&msg)?;

        let skx = ServerKeyExchangePayload::from(ServerKeyExchange {
            params: kx_params,
            dss: DigitallySignedStruct::new(sigscheme, sig),
        });

        flight.add(HandshakeMessagePayload(
            HandshakePayload::ServerKeyExchange(skx),
        ));
        Ok(kx)
    }

    fn emit_certificate_req(
        flight: &mut HandshakeFlightTls12<'_>,
        config: &ServerConfig,
    ) -> Result<bool, Error> {
        let client_auth = &config.verifier;

        if !client_auth.offer_client_auth() {
            return Ok(false);
        }

        let verify_schemes = client_auth.supported_verify_schemes();

        let names = config
            .verifier
            .root_hint_subjects()
            .to_vec();

        let cr = CertificateRequestPayload {
            certtypes: vec![
                ClientCertificateType::RSASign,
                ClientCertificateType::ECDSASign,
            ],
            sigschemes: verify_schemes,
            canames: names,
        };

        let creq = HandshakeMessagePayload(HandshakePayload::CertificateRequest(cr));

        trace!("Sending CertificateRequest {creq:?}");
        flight.add(creq);
        Ok(true)
    }

    fn emit_server_hello_done(flight: &mut HandshakeFlightTls12<'_>) {
        flight.add(HandshakeMessagePayload(HandshakePayload::ServerHelloDone));
    }
}

// --- Process client's Certificate for client auth ---
struct ExpectCertificate {
    config: Arc<ServerConfig>,
    transcript: HandshakeHash,
    randoms: ConnectionRandoms,
    session_id: SessionId,
    suite: &'static Tls12CipherSuite,
    using_ems: bool,
    server_kx: Box<dyn ActiveKeyExchange>,
    send_ticket: bool,
}

impl State<ServerConnectionData> for ExpectCertificate {
    fn handle(
        mut self: Box<Self>,
        _cx: &mut ServerContext<'_>,
        m: Message<'_>,
    ) -> hs::NextStateOrError {
        self.transcript.add_message(&m);
        let cert_chain = require_handshake_msg_move!(
            m,
            HandshakeType::Certificate,
            HandshakePayload::Certificate
        )?;

        // If we can't determine if the auth is mandatory, abort
        let mandatory = self
            .config
            .verifier
            .client_auth_mandatory();

        trace!("certs {cert_chain:?}");

        let peer_identity = match Identity::from_peer(cert_chain.0, CertificateType::X509)? {
            None if mandatory => {
                return Err(PeerMisbehaved::NoCertificatesPresented.into());
            }
            None => {
                debug!("client auth requested but no certificate supplied");
                self.transcript.abandon_client_auth();
                None
            }
            Some(identity) => {
                self.config
                    .verifier
                    .verify_identity(&ClientIdentity {
                        identity: &identity,
                        now: self.config.current_time()?,
                    })?;
                Some(identity.into_owned())
            }
        };

        Ok(Box::new(ExpectClientKx {
            config: self.config,
            transcript: self.transcript,
            randoms: self.randoms,
            session_id: self.session_id,
            suite: self.suite,
            using_ems: self.using_ems,
            server_kx: self.server_kx,
            peer_identity,
            send_ticket: self.send_ticket,
        }))
    }
}

// --- Process client's KeyExchange ---
struct ExpectClientKx {
    config: Arc<ServerConfig>,
    transcript: HandshakeHash,
    randoms: ConnectionRandoms,
    session_id: SessionId,
    suite: &'static Tls12CipherSuite,
    using_ems: bool,
    server_kx: Box<dyn ActiveKeyExchange>,
    peer_identity: Option<Identity<'static>>,
    send_ticket: bool,
}

impl State<ServerConnectionData> for ExpectClientKx {
    fn handle(
        mut self: Box<Self>,
        cx: &mut ServerContext<'_>,
        m: Message<'_>,
    ) -> hs::NextStateOrError {
        let client_kx = require_handshake_msg!(
            m,
            HandshakeType::ClientKeyExchange,
            HandshakePayload::ClientKeyExchange
        )?;
        self.transcript.add_message(&m);
        let ems_seed = self
            .using_ems
            .then(|| self.transcript.current_hash());

        // Complete key agreement, and set up encryption with the
        // resulting premaster secret.
        let peer_kx_params =
            tls12::decode_kx_params::<ClientKeyExchangeParams>(self.suite.kx, client_kx.bytes())?;
        let secrets = ConnectionSecrets::from_key_exchange(
            self.server_kx,
            peer_kx_params.pub_key(),
            ems_seed,
            self.randoms,
            self.suite,
        )?;
        cx.common.kx_state.complete();

        self.config.key_log.log(
            "CLIENT_RANDOM",
            &secrets.randoms.client,
            secrets.master_secret(),
        );
        cx.common
            .start_encryption_tls12(&secrets, Side::Server);

        match self.peer_identity {
            Some(peer_identity) => Ok(Box::new(ExpectCertificateVerify {
                config: self.config,
                secrets,
                transcript: self.transcript,
                session_id: self.session_id,
                using_ems: self.using_ems,
                peer_identity,
                send_ticket: self.send_ticket,
            })),
            _ => Ok(Box::new(ExpectCcs {
                config: self.config,
                secrets,
                transcript: self.transcript,
                session_id: self.session_id,
                using_ems: self.using_ems,
                resuming: false,
                send_ticket: self.send_ticket,
            })),
        }
    }
}

// --- Process client's certificate proof ---
struct ExpectCertificateVerify {
    config: Arc<ServerConfig>,
    secrets: ConnectionSecrets,
    transcript: HandshakeHash,
    session_id: SessionId,
    using_ems: bool,
    peer_identity: Identity<'static>,
    send_ticket: bool,
}

impl State<ServerConnectionData> for ExpectCertificateVerify {
    fn handle(
        mut self: Box<Self>,
        cx: &mut ServerContext<'_>,
        m: Message<'_>,
    ) -> hs::NextStateOrError {
        let signature = require_handshake_msg!(
            m,
            HandshakeType::CertificateVerify,
            HandshakePayload::CertificateVerify
        )?;

        match self.transcript.take_handshake_buf() {
            Some(msgs) => {
                self.config
                    .verifier
                    .verify_tls12_signature(&SignatureVerificationInput {
                        message: &msgs,
                        signer: &self.peer_identity.as_signer(),
                        signature,
                    })?;
            }
            None => {
                // This should be unreachable; the handshake buffer was initialized with
                // client authentication if the verifier wants to offer it.
                // `transcript.abandon_client_auth()` can extract it, but its only caller in
                // this flow will also set `ExpectClientKx::client_cert` to `None`, making it
                // impossible to reach this state.
                return Err(Error::Unreachable("client authentication not set up"));
            }
        }

        trace!("client CertificateVerify OK");
        cx.common.peer_identity = Some(self.peer_identity);

        self.transcript.add_message(&m);
        Ok(Box::new(ExpectCcs {
            config: self.config,
            secrets: self.secrets,
            transcript: self.transcript,
            session_id: self.session_id,
            using_ems: self.using_ems,
            resuming: false,
            send_ticket: self.send_ticket,
        }))
    }
}

// --- Process client's ChangeCipherSpec ---
struct ExpectCcs {
    config: Arc<ServerConfig>,
    secrets: ConnectionSecrets,
    transcript: HandshakeHash,
    session_id: SessionId,
    using_ems: bool,
    resuming: bool,
    send_ticket: bool,
}

impl State<ServerConnectionData> for ExpectCcs {
    fn handle(self: Box<Self>, cx: &mut ServerContext<'_>, m: Message<'_>) -> hs::NextStateOrError {
        match m.payload {
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
        let proof = cx.common.check_aligned_handshake()?;

        cx.common
            .record_layer
            .start_decrypting(&proof);
        Ok(Box::new(ExpectFinished {
            config: self.config,
            secrets: self.secrets,
            transcript: self.transcript,
            session_id: self.session_id,
            using_ems: self.using_ems,
            resuming: self.resuming,
            send_ticket: self.send_ticket,
        }))
    }
}

// --- Process client's Finished ---
fn get_server_connection_value_tls12(
    secrets: &ConnectionSecrets,
    using_ems: bool,
    cx: &ServerContext<'_>,
    time_now: UnixTime,
) -> persist::ServerSessionValue {
    persist::Tls12ServerSessionValue::new(
        persist::CommonServerSessionValue::new(
            cx.data.sni.as_ref(),
            secrets.suite().common.suite,
            cx.common.peer_identity.clone(),
            cx.common.alpn_protocol.clone(),
            cx.data.resumption_data.clone(),
            time_now,
        ),
        secrets.master_secret(),
        using_ems,
    )
    .into()
}

fn emit_ticket(
    secrets: &ConnectionSecrets,
    transcript: &mut HandshakeHash,
    using_ems: bool,
    cx: &mut ServerContext<'_>,
    ticketer: &dyn TicketProducer,
    now: UnixTime,
) -> Result<(), Error> {
    let plain = get_server_connection_value_tls12(secrets, using_ems, cx, now).get_encoding();

    // If we can't produce a ticket for some reason, we can't
    // report an error. Send an empty one.
    let ticket = ticketer
        .encrypt(&plain)
        .unwrap_or_default();
    let ticket_lifetime = ticketer.lifetime();

    let m = Message {
        version: ProtocolVersion::TLSv1_2,
        payload: MessagePayload::handshake(HandshakeMessagePayload(
            HandshakePayload::NewSessionTicket(NewSessionTicketPayload::new(
                ticket_lifetime,
                ticket,
            )),
        )),
    };

    transcript.add_message(&m);
    cx.common.send_msg(m, false);
    Ok(())
}

fn emit_ccs(common: &mut CommonState) {
    let m = Message {
        version: ProtocolVersion::TLSv1_2,
        payload: MessagePayload::ChangeCipherSpec(ChangeCipherSpecPayload {}),
    };

    common.send_msg(m, false);
}

fn emit_finished(
    secrets: &ConnectionSecrets,
    transcript: &mut HandshakeHash,
    common: &mut CommonState,
    proof: &HandshakeAlignedProof,
) {
    let vh = transcript.current_hash();
    let verify_data = secrets.server_verify_data(&vh, proof);
    let verify_data_payload = Payload::Borrowed(&verify_data);

    let f = Message {
        version: ProtocolVersion::TLSv1_2,
        payload: MessagePayload::handshake(HandshakeMessagePayload(HandshakePayload::Finished(
            verify_data_payload,
        ))),
    };

    transcript.add_message(&f);
    common.send_msg(f, true);
}

struct ExpectFinished {
    config: Arc<ServerConfig>,
    secrets: ConnectionSecrets,
    transcript: HandshakeHash,
    session_id: SessionId,
    using_ems: bool,
    resuming: bool,
    send_ticket: bool,
}

impl State<ServerConnectionData> for ExpectFinished {
    fn handle(
        mut self: Box<Self>,
        cx: &mut ServerContext<'_>,
        m: Message<'_>,
    ) -> hs::NextStateOrError {
        let finished =
            require_handshake_msg!(m, HandshakeType::Finished, HandshakePayload::Finished)?;

        let proof = cx.common.check_aligned_handshake()?;

        let vh = self.transcript.current_hash();
        let expect_verify_data = self
            .secrets
            .client_verify_data(&vh, &proof);

        let fin_verified =
            match ConstantTimeEq::ct_eq(&expect_verify_data[..], finished.bytes()).into() {
                true => verify::FinishedMessageVerified::assertion(),
                false => {
                    return Err(PeerMisbehaved::IncorrectFinished.into());
                }
            };

        // Save connection, perhaps
        if !self.resuming && !self.session_id.is_empty() {
            let now = self.config.current_time()?;

            let value = get_server_connection_value_tls12(&self.secrets, self.using_ems, cx, now);

            let worked = self
                .config
                .session_storage
                .put(self.session_id.as_ref().to_vec(), value.get_encoding());
            if worked {
                debug!("Session saved");
            } else {
                debug!("Session not saved");
            }
        }

        // Send our CCS and Finished.
        self.transcript.add_message(&m);
        if !self.resuming {
            if self.send_ticket {
                let now = self.config.current_time()?;
                if let Some(ticketer) = self.config.ticketer.as_deref() {
                    emit_ticket(
                        &self.secrets,
                        &mut self.transcript,
                        self.using_ems,
                        cx,
                        ticketer,
                        now,
                    )?;
                }
            }
            emit_ccs(cx.common);
            cx.common
                .record_layer
                .start_encrypting();
            emit_finished(&self.secrets, &mut self.transcript, cx.common, &proof);
        }

        cx.common
            .start_traffic(&mut cx.sendable_plaintext);

        let extracted_secrets = self
            .config
            .enable_secret_extraction
            .then(|| {
                self.secrets
                    .extract_secrets(Side::Server)
            });

        cx.common.exporter = Some(self.secrets.into_exporter());

        Ok(Box::new(ExpectTraffic {
            extracted_secrets,
            _fin_verified: fin_verified,
        }))
    }
}

// --- Process traffic ---
struct ExpectTraffic {
    // only `Some` if `config.enable_secret_extraction` is true
    extracted_secrets: Option<Result<PartiallyExtractedSecrets, Error>>,
    _fin_verified: verify::FinishedMessageVerified,
}

impl ExpectTraffic {}

impl State<ServerConnectionData> for ExpectTraffic {
    fn handle(self: Box<Self>, cx: &mut ServerContext<'_>, m: Message<'_>) -> hs::NextStateOrError {
        match m.payload {
            MessagePayload::ApplicationData(payload) => cx.receive_plaintext(payload),
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
    ) -> Result<(PartiallyExtractedSecrets, Box<dyn KernelState + 'static>), Error> {
        match self.extracted_secrets.take() {
            Some(extracted_secrets) => Ok((extracted_secrets?, self)),
            None => Err(Error::Unreachable(
                "call of into_external_state() only allowed with enable_secret_extraction",
            )),
        }
    }
}

impl KernelState for ExpectTraffic {
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn update_secrets(&mut self, _: Direction) -> Result<ConnectionTrafficSecrets, Error> {
        Err(Error::Unreachable(
            "TLS 1.2 connections do not support traffic secret updates",
        ))
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn handle_new_session_ticket(
        &mut self,
        _cx: &mut KernelContext<'_>,
        _message: &NewSessionTicketPayloadTls13,
    ) -> Result<(), Error> {
        unreachable!(
            "server connections should never have handle_new_session_ticket called on them"
        )
    }
}
