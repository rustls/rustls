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
use crate::common_state::{Event, HandshakeFlightTls12, HandshakeKind, Input, Output, Side, State};
use crate::conn::ConnectionRandoms;
use crate::conn::kernel::{Direction, KernelState};
use crate::crypto::cipher::{MessageDecrypter, MessageEncrypter, Payload};
use crate::crypto::kx::{ActiveKeyExchange, SupportedKxGroup};
use crate::crypto::{Identity, TicketProducer};
use crate::enums::{
    ApplicationProtocol, CertificateType, ContentType, HandshakeType, ProtocolVersion,
};
use crate::error::{ApiMisuse, Error, PeerIncompatible, PeerMisbehaved};
use crate::hash_hs::HandshakeHash;
use crate::log::{debug, trace};
use crate::msgs::deframer::HandshakeAlignedProof;
use crate::msgs::handshake::{
    CertificateChain, ClientKeyExchangeParams, HandshakeMessagePayload, HandshakePayload,
    NewSessionTicketPayload, NewSessionTicketPayloadTls13, SessionId,
};
use crate::msgs::message::{Message, MessagePayload};
use crate::msgs::{ChangeCipherSpecPayload, Codec, persist};
use crate::suites::PartiallyExtractedSecrets;
use crate::sync::Arc;
use crate::tls12::{self, ConnectionSecrets, Tls12CipherSuite};
use crate::verify::{ClientIdentity, SignatureVerificationInput};
use crate::{ConnectionTrafficSecrets, verify};

mod client_hello {
    use super::*;
    use crate::common_state::Protocol;
    use crate::crypto::kx::SupportedKxGroup;
    use crate::crypto::{SelectedCredential, Signer};
    use crate::enums::ApplicationProtocol;
    use crate::msgs::handshake::{
        CertificateRequestPayload, CertificateStatus, ClientHelloPayload, ClientSessionTicket,
        Random, ServerExtensionsInput, ServerHelloPayload, ServerKeyExchange,
        ServerKeyExchangeParams, ServerKeyExchangePayload,
    };
    use crate::msgs::{ClientCertificateType, Compression};
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
                        .can_resume(suite.common.suite, cx.data.sni.as_ref())
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

            cx.emit(Event::HandshakeKind(HandshakeKind::Full));

            let mut flight = HandshakeFlightTls12::new(&mut transcript);

            let (send_ticket, alpn_protocol) = emit_server_hello(
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

            flight.finish(cx);

            if doing_client_auth {
                Ok(Box::new(ExpectCertificate {
                    config: st.config,
                    transcript,
                    randoms,
                    session_id: st.session_id,
                    suite,
                    using_ems: st.using_ems,
                    server_kx,
                    alpn_protocol,
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
                    alpn_protocol,
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
        extra_exts: ServerExtensionsInput,
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
        let (send_ticket, alpn_protocol) = emit_server_hello(
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
        flight.finish(cx);

        let secrets = ConnectionSecrets::new_resume(randoms, suite, &resumedata.master_secret);
        config.key_log.log(
            "CLIENT_RANDOM",
            &secrets.randoms.client,
            secrets.master_secret(),
        );

        cx.emit(Event::HandshakeKind(HandshakeKind::Resumed));
        cx.data.received_resumption_data = Some(
            resumedata
                .common
                .application_data
                .bytes()
                .to_vec(),
        );

        if send_ticket {
            let now = config.current_time()?;

            if let Some(ticketer) = config.ticketer.as_deref() {
                emit_ticket(
                    &secrets,
                    &mut transcript,
                    using_ems,
                    resumedata.common.peer_identity.as_ref(),
                    alpn_protocol.as_ref(),
                    cx,
                    ticketer,
                    now,
                )?;
            }
        }
        emit_ccs(cx);

        let (dec, encrypter) = secrets.make_cipher_pair(Side::Server);
        cx.emit(Event::MessageEncrypter {
            encrypter,
            limit: secrets
                .suite()
                .common
                .confidentiality_limit,
        });
        emit_finished(&secrets, &mut transcript, cx, &proof);

        Ok(Box::new(ExpectCcs {
            config,
            secrets,
            transcript,
            session_id,
            alpn_protocol,
            peer_identity: resumedata.common.peer_identity,
            using_ems,
            resuming_decrypter: Some(dec),
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
        extra_exts: ServerExtensionsInput,
    ) -> Result<(bool, Option<ApplicationProtocol<'static>>), Error> {
        let mut ep = hs::ExtensionProcessing::new(extra_exts, Protocol::Tcp, hello, config);
        let (_, alpn_protocol) =
            ep.process_common(cx, ocsp_response, resumedata.map(|r| &r.common))?;
        ep.process_tls12(ocsp_response.as_deref(), using_ems);

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

        Ok((ep.send_ticket, alpn_protocol))
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
    ) -> Result<GroupAndKeyExchange, Error> {
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
        Ok(GroupAndKeyExchange {
            kx,
            group: selected_group,
        })
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
    server_kx: GroupAndKeyExchange,
    alpn_protocol: Option<ApplicationProtocol<'static>>,
    send_ticket: bool,
}

impl State<ServerConnectionData> for ExpectCertificate {
    fn handle(
        mut self: Box<Self>,
        _cx: &mut ServerContext<'_>,
        Input { message, .. }: Input<'_>,
    ) -> hs::NextStateOrError {
        self.transcript.add_message(&message);
        let cert_chain = require_handshake_msg_move!(
            message,
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
            alpn_protocol: self.alpn_protocol,
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
    server_kx: GroupAndKeyExchange,
    alpn_protocol: Option<ApplicationProtocol<'static>>,
    peer_identity: Option<Identity<'static>>,
    send_ticket: bool,
}

impl State<ServerConnectionData> for ExpectClientKx {
    fn handle(
        mut self: Box<Self>,
        cx: &mut ServerContext<'_>,
        Input { message, .. }: Input<'_>,
    ) -> hs::NextStateOrError {
        let client_kx = require_handshake_msg!(
            message,
            HandshakeType::ClientKeyExchange,
            HandshakePayload::ClientKeyExchange
        )?;
        self.transcript.add_message(&message);
        let ems_seed = self
            .using_ems
            .then(|| self.transcript.current_hash());

        // Complete key agreement, and set up encryption with the
        // resulting premaster secret.
        let peer_kx_params =
            tls12::decode_kx_params::<ClientKeyExchangeParams>(self.suite.kx, client_kx.bytes())?;

        let secrets = ConnectionSecrets::from_key_exchange(
            self.server_kx.kx,
            peer_kx_params.pub_key(),
            ems_seed,
            self.randoms,
            self.suite,
        )?;
        cx.emit(Event::KeyExchangeGroup(self.server_kx.group));

        self.config.key_log.log(
            "CLIENT_RANDOM",
            &secrets.randoms.client,
            secrets.master_secret(),
        );

        match self.peer_identity {
            Some(peer_identity) => Ok(Box::new(ExpectCertificateVerify {
                config: self.config,
                secrets,
                transcript: self.transcript,
                session_id: self.session_id,
                using_ems: self.using_ems,
                alpn_protocol: self.alpn_protocol,
                peer_identity,
                send_ticket: self.send_ticket,
            })),
            _ => Ok(Box::new(ExpectCcs {
                config: self.config,
                secrets,
                transcript: self.transcript,
                session_id: self.session_id,
                alpn_protocol: self.alpn_protocol,
                peer_identity: None,
                using_ems: self.using_ems,
                resuming_decrypter: None,
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
    alpn_protocol: Option<ApplicationProtocol<'static>>,
    peer_identity: Identity<'static>,
    send_ticket: bool,
}

impl State<ServerConnectionData> for ExpectCertificateVerify {
    fn handle(
        mut self: Box<Self>,
        _cx: &mut ServerContext<'_>,
        Input { message, .. }: Input<'_>,
    ) -> hs::NextStateOrError {
        let signature = require_handshake_msg!(
            message,
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

        self.transcript.add_message(&message);
        Ok(Box::new(ExpectCcs {
            config: self.config,
            secrets: self.secrets,
            transcript: self.transcript,
            session_id: self.session_id,
            alpn_protocol: self.alpn_protocol,
            peer_identity: Some(self.peer_identity),
            using_ems: self.using_ems,
            resuming_decrypter: None,
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
    alpn_protocol: Option<ApplicationProtocol<'static>>,
    peer_identity: Option<Identity<'static>>,
    using_ems: bool,
    resuming_decrypter: Option<Box<dyn MessageDecrypter>>,
    send_ticket: bool,
}

impl State<ServerConnectionData> for ExpectCcs {
    fn handle(
        self: Box<Self>,
        cx: &mut ServerContext<'_>,
        input: Input<'_>,
    ) -> hs::NextStateOrError {
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

        let (decrypter, pending_encrypter) = match self.resuming_decrypter {
            Some(dec) => (dec, None),
            None => {
                let (dec, enc) = self
                    .secrets
                    .make_cipher_pair(Side::Server);
                (dec, Some(enc))
            }
        };

        cx.emit(Event::MessageDecrypter { decrypter, proof });

        Ok(Box::new(ExpectFinished {
            config: self.config,
            secrets: self.secrets,
            transcript: self.transcript,
            session_id: self.session_id,
            alpn_protocol: self.alpn_protocol,
            peer_identity: self.peer_identity,
            using_ems: self.using_ems,
            resuming: pending_encrypter.is_none(),
            send_ticket: self.send_ticket,
            pending_encrypter,
        }))
    }
}

// --- Process client's Finished ---
fn get_server_connection_value_tls12(
    secrets: &ConnectionSecrets,
    using_ems: bool,
    peer_identity: Option<&Identity<'static>>,
    alpn_protocol: Option<&ApplicationProtocol<'_>>,
    cx: &ServerContext<'_>,
    time_now: UnixTime,
) -> persist::ServerSessionValue {
    persist::Tls12ServerSessionValue::new(
        persist::CommonServerSessionValue::new(
            cx.data.sni.as_ref(),
            secrets.suite().common.suite,
            peer_identity.cloned(),
            alpn_protocol.map(|p| p.to_owned()),
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
    peer_identity: Option<&Identity<'static>>,
    alpn_protocol: Option<&ApplicationProtocol<'_>>,
    cx: &mut ServerContext<'_>,
    ticketer: &dyn TicketProducer,
    now: UnixTime,
) -> Result<(), Error> {
    let plain = get_server_connection_value_tls12(
        secrets,
        using_ems,
        peer_identity,
        alpn_protocol,
        cx,
        now,
    )
    .get_encoding();

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
    cx.emit(Event::PlainMessage(m));
    Ok(())
}

fn emit_ccs(output: &mut dyn Output) {
    output.emit(Event::PlainMessage(Message {
        version: ProtocolVersion::TLSv1_2,
        payload: MessagePayload::ChangeCipherSpec(ChangeCipherSpecPayload {}),
    }));
}

fn emit_finished(
    secrets: &ConnectionSecrets,
    transcript: &mut HandshakeHash,
    output: &mut dyn Output,
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
    output.emit(Event::EncryptMessage(f));
}

struct ExpectFinished {
    config: Arc<ServerConfig>,
    secrets: ConnectionSecrets,
    transcript: HandshakeHash,
    session_id: SessionId,
    alpn_protocol: Option<ApplicationProtocol<'static>>,
    peer_identity: Option<Identity<'static>>,
    using_ems: bool,
    resuming: bool,
    send_ticket: bool,
    pending_encrypter: Option<Box<dyn MessageEncrypter>>,
}

impl State<ServerConnectionData> for ExpectFinished {
    fn handle(
        mut self: Box<Self>,
        cx: &mut ServerContext<'_>,
        input: Input<'_>,
    ) -> hs::NextStateOrError {
        let finished = require_handshake_msg!(
            input.message,
            HandshakeType::Finished,
            HandshakePayload::Finished
        )?;

        let proof = input.check_aligned_handshake()?;

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

            let value = get_server_connection_value_tls12(
                &self.secrets,
                self.using_ems,
                self.peer_identity.as_ref(),
                self.alpn_protocol.as_ref(),
                cx,
                now,
            );

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
        self.transcript
            .add_message(&input.message);
        if let Some(encrypter) = self.pending_encrypter {
            assert!(!self.resuming);
            if self.send_ticket {
                let now = self.config.current_time()?;
                if let Some(ticketer) = self.config.ticketer.as_deref() {
                    emit_ticket(
                        &self.secrets,
                        &mut self.transcript,
                        self.using_ems,
                        self.peer_identity.as_ref(),
                        self.alpn_protocol.as_ref(),
                        cx,
                        ticketer,
                        now,
                    )?;
                }
            }
            emit_ccs(cx);
            cx.emit(Event::MessageEncrypter {
                encrypter,
                limit: self
                    .secrets
                    .suite()
                    .common
                    .confidentiality_limit,
            });
            emit_finished(&self.secrets, &mut self.transcript, cx, &proof);
        }

        if let Some(identity) = self.peer_identity {
            cx.emit(Event::PeerIdentity(identity));
        }

        let extracted_secrets = self
            .config
            .enable_secret_extraction
            .then(|| {
                self.secrets
                    .extract_secrets(Side::Server)
            });

        cx.emit(Event::Exporter(self.secrets.into_exporter()));
        cx.emit(Event::StartTraffic);

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
    fn handle(
        self: Box<Self>,
        cx: &mut ServerContext<'_>,
        Input { message, .. }: Input<'_>,
    ) -> hs::NextStateOrError {
        match message.payload {
            MessagePayload::ApplicationData(payload) => cx.emit(Event::ApplicationData(payload)),
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
            None => Err(ApiMisuse::SecretExtractionRequiresPriorOptIn.into()),
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
        &self,
        _message: &NewSessionTicketPayloadTls13,
    ) -> Result<(), Error> {
        unreachable!(
            "server connections should never have handle_new_session_ticket called on them"
        )
    }
}

struct GroupAndKeyExchange {
    group: &'static dyn SupportedKxGroup,
    kx: Box<dyn ActiveKeyExchange>,
}
