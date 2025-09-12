use alloc::boxed::Box;
use alloc::string::ToString;
use alloc::vec;
use alloc::vec::Vec;

pub(super) use client_hello::CompleteClientHelloHandling;
pub(crate) use client_hello::{TLS12_HANDLER, Tls12Handler};
use pki_types::UnixTime;
use subtle::ConstantTimeEq;

use super::hs::{self, ServerContext};
use super::server_conn::{ProducesTickets, ServerConfig, ServerConnectionData};
use crate::check::inappropriate_message;
use crate::common_state::{CommonState, HandshakeFlightTls12, HandshakeKind, Side, State};
use crate::conn::ConnectionRandoms;
use crate::conn::kernel::{Direction, KernelContext, KernelState};
use crate::crypto::ActiveKeyExchange;
use crate::enums::{
    AlertDescription, CertificateType, ContentType, HandshakeType, ProtocolVersion,
};
use crate::error::{Error, PeerIncompatible, PeerMisbehaved};
use crate::hash_hs::HandshakeHash;
use crate::log::{debug, trace};
use crate::msgs::base::Payload;
use crate::msgs::ccs::ChangeCipherSpecPayload;
use crate::msgs::codec::Codec;
use crate::msgs::handshake::{
    CertificateChain, ClientKeyExchangeParams, HandshakeMessagePayload, HandshakePayload,
    NewSessionTicketPayload, NewSessionTicketPayloadTls13, SessionId,
};
use crate::msgs::message::{Message, MessagePayload};
use crate::msgs::persist;
use crate::suites::PartiallyExtractedSecrets;
use crate::sync::Arc;
use crate::tls12::{self, ConnectionSecrets, Tls12CipherSuite};
use crate::verify::{ClientIdentity, PeerIdentity, SignatureVerificationInput};
use crate::{ConnectionTrafficSecrets, verify};

mod client_hello {
    use core::fmt;

    use pki_types::CertificateDer;

    use super::*;
    use crate::common_state::KxState;
    use crate::crypto::SupportedKxGroup;
    use crate::enums::SignatureScheme;
    use crate::msgs::enums::{ClientCertificateType, Compression};
    use crate::msgs::handshake::{
        CertificateRequestPayload, CertificateStatus, ClientHelloPayload, ClientSessionTicket,
        Random, ServerExtensionsInput, ServerHelloPayload, ServerKeyExchange,
        ServerKeyExchangeParams, ServerKeyExchangePayload,
    };
    use crate::sealed::Sealed;
    use crate::server::hs::ClientHelloState;
    use crate::sign::SigningKey;
    use crate::verify::DigitallySignedStruct;

    pub(crate) static TLS12_HANDLER: &dyn Tls12Handler = &Handler;

    #[derive(Debug)]
    struct Handler;

    impl Tls12Handler for Handler {
        fn handle_client_hello(
            &self,
            mut cch: CompleteClientHelloHandling,
            mut st: ClientHelloState<'_>,
            tls13_enabled: bool,
            cx: &mut ServerContext<'_>,
        ) -> hs::NextStateOrError<'static> {
            // -- TLS1.2 only from hereon in --
            st.transcript.add_message(st.message);

            if st
                .client_hello
                .extended_master_secret_request
                .is_some()
            {
                cch.using_ems = true;
            } else if st.config.require_ems {
                return Err(cx.common.send_fatal_alert(
                    AlertDescription::HandshakeFailure,
                    PeerIncompatible::ExtendedMasterSecretExtensionRequired,
                ));
            }

            // "RFC 4492 specified that if this extension is missing,
            // it means that only the uncompressed point format is
            // supported"
            // - <https://datatracker.ietf.org/doc/html/rfc8422#section-5.1.2>
            let supported_ec_point_formats = st
                .client_hello
                .ec_point_formats
                .unwrap_or_default();

            trace!("ecpoints {supported_ec_point_formats:?}");

            if !supported_ec_point_formats.uncompressed {
                return Err(cx.common.send_fatal_alert(
                    AlertDescription::IllegalParameter,
                    PeerIncompatible::UncompressedEcPointsRequired,
                ));
            }

            // -- If TLS1.3 is enabled, signal the downgrade in the server random
            if tls13_enabled {
                st.randoms.server[24..].copy_from_slice(&tls12::DOWNGRADE_SENTINEL);
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
            let resume_data = st
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
                        .decrypt(ticket.bytes());
                    if data.is_none() {
                        debug!("Ticket didn't decrypt");
                    }
                    data
                })
                .or_else(|| {
                    // Perhaps resume?  If we received a ticket, the sessionid
                    // does not correspond to a real session.
                    if st.client_hello.session_id.is_empty() || ticket_received {
                        return None;
                    }

                    st.config
                        .session_storage
                        .get(st.client_hello.session_id.as_ref())
                })
                .and_then(|x| persist::ServerSessionValue::read_bytes(&x).ok())
                .and_then(|resumedata| match resumedata {
                    persist::ServerSessionValue::Tls12(tls12) => Some(tls12),
                    _ => None,
                })
                .filter(|resumedata| {
                    hs::can_resume(cch.suite.into(), &cx.data.sni, &resumedata.common)
                        && (resumedata.extended_ms == cch.using_ems
                            || (resumedata.extended_ms && !cch.using_ems))
                });

            if let Some(data) = resume_data {
                return cch.start_resumption(cx, st, data);
            }

            // Now we have chosen a ciphersuite, we can make kx decisions.
            let sigschemes = cch
                .suite
                .resolve_sig_schemes(&st.sig_schemes);

            if sigschemes.is_empty() {
                return Err(cx.common.send_fatal_alert(
                    AlertDescription::HandshakeFailure,
                    PeerIncompatible::NoSignatureSchemesInCommon,
                ));
            }

            let mut ocsp_response = st.cert_key.ocsp.as_deref();

            // If we're not offered a ticket or a potential session ID, allocate a session ID.
            if !st.config.session_storage.can_cache() {
                cch.session_id = SessionId::empty();
            } else if cch.session_id.is_empty() && !ticket_received {
                cch.session_id = SessionId::random(st.config.provider.secure_random)?;
            }

            cx.common.kx_state = KxState::Start(st.kx_group);
            cx.common.handshake_kind = Some(HandshakeKind::Full);

            let mut flight = HandshakeFlightTls12::new(&mut st.transcript);

            cch.send_ticket = emit_server_hello(
                &mut flight,
                &st.config,
                cx,
                cch.session_id,
                cch.suite,
                cch.using_ems,
                &mut ocsp_response,
                st.client_hello,
                None,
                &st.randoms,
                st.extra_exts,
            )?;
            emit_certificate(&mut flight, &st.cert_key.cert_chain);
            if let Some(ocsp_response) = ocsp_response {
                emit_cert_status(&mut flight, ocsp_response);
            }
            let server_kx = emit_server_kx(
                &mut flight,
                sigschemes,
                st.kx_group,
                &*st.cert_key.key,
                &st.randoms,
            )?;
            let doing_client_auth = emit_certificate_req(&mut flight, &st.config)?;
            emit_server_hello_done(&mut flight);

            flight.finish(cx.common);

            if doing_client_auth {
                Ok(Box::new(ExpectCertificate {
                    config: st.config,
                    transcript: st.transcript,
                    randoms: st.randoms,
                    session_id: cch.session_id,
                    suite: cch.suite,
                    using_ems: cch.using_ems,
                    server_kx,
                    send_ticket: cch.send_ticket,
                }))
            } else {
                Ok(Box::new(ExpectClientKx {
                    config: st.config,
                    transcript: st.transcript,
                    randoms: st.randoms,
                    session_id: cch.session_id,
                    suite: cch.suite,
                    using_ems: cch.using_ems,
                    server_kx,
                    peer_identity: None,
                    send_ticket: cch.send_ticket,
                }))
            }
        }
    }

    impl Sealed for Handler {}

    pub(crate) trait Tls12Handler: fmt::Debug + Sealed + Send + Sync {
        fn handle_client_hello(
            &self,
            cch: CompleteClientHelloHandling,
            st: ClientHelloState<'_>,
            tls13_enabled: bool,
            cx: &mut ServerContext<'_>,
        ) -> hs::NextStateOrError<'static>;
    }

    pub(crate) struct CompleteClientHelloHandling {
        pub(in crate::server) session_id: SessionId,
        pub(in crate::server) suite: &'static Tls12CipherSuite,
        pub(in crate::server) using_ems: bool,
        pub(in crate::server) send_ticket: bool,
    }

    impl CompleteClientHelloHandling {
        fn start_resumption(
            mut self,
            cx: &mut ServerContext<'_>,
            mut state: ClientHelloState<'_>,
            resumedata: persist::Tls12ServerSessionValue,
        ) -> hs::NextStateOrError<'static> {
            debug!("Resuming connection");

            if resumedata.extended_ms && !self.using_ems {
                return Err(cx.common.send_fatal_alert(
                    AlertDescription::IllegalParameter,
                    PeerMisbehaved::ResumptionAttemptedWithVariedEms,
                ));
            }

            self.session_id = state.client_hello.session_id;
            let mut flight = HandshakeFlightTls12::new(&mut state.transcript);
            self.send_ticket = emit_server_hello(
                &mut flight,
                &state.config,
                cx,
                self.session_id,
                self.suite,
                self.using_ems,
                &mut None,
                state.client_hello,
                Some(&resumedata),
                &state.randoms,
                state.extra_exts,
            )?;
            flight.finish(cx.common);

            let secrets =
                ConnectionSecrets::new_resume(state.randoms, self.suite, &resumedata.master_secret);
            state.config.key_log.log(
                "CLIENT_RANDOM",
                &secrets.randoms.client,
                secrets.master_secret(),
            );
            cx.common
                .start_encryption_tls12(&secrets, Side::Server);
            cx.common.peer_identity = resumedata.common.peer_identity;
            cx.common.handshake_kind = Some(HandshakeKind::Resumed);

            if self.send_ticket {
                let now = state.config.current_time()?;

                emit_ticket(
                    &secrets,
                    &mut state.transcript,
                    self.using_ems,
                    cx,
                    &*state.config.ticketer,
                    now,
                )?;
            }
            emit_ccs(cx.common);
            cx.common
                .record_layer
                .start_encrypting();
            emit_finished(&secrets, &mut state.transcript, cx.common);

            Ok(Box::new(ExpectCcs {
                config: state.config,
                secrets,
                transcript: state.transcript,
                session_id: self.session_id,
                using_ems: self.using_ems,
                resuming: true,
                send_ticket: self.send_ticket,
            }))
        }
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
        let mut ep = hs::ExtensionProcessing::new(extra_exts);
        ep.process_common(
            config,
            cx,
            ocsp_response,
            hello,
            resumedata.map(|r| &r.common),
        )?;
        ep.process_tls12(config, hello, using_ems);

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

    fn emit_certificate(
        flight: &mut HandshakeFlightTls12<'_>,
        cert_chain: &[CertificateDer<'static>],
    ) {
        flight.add(HandshakeMessagePayload(HandshakePayload::Certificate(
            CertificateChain(cert_chain.to_vec()),
        )));
    }

    fn emit_cert_status(flight: &mut HandshakeFlightTls12<'_>, ocsp: &[u8]) {
        flight.add(HandshakeMessagePayload(
            HandshakePayload::CertificateStatus(CertificateStatus::new(ocsp)),
        ));
    }

    fn emit_server_kx(
        flight: &mut HandshakeFlightTls12<'_>,
        sigschemes: Vec<SignatureScheme>,
        selected_group: &'static dyn SupportedKxGroup,
        signing_key: &dyn SigningKey,
        randoms: &ConnectionRandoms,
    ) -> Result<Box<dyn ActiveKeyExchange>, Error> {
        let kx = selected_group.start()?;
        let kx_params = ServerKeyExchangeParams::new(&*kx);

        let mut msg = Vec::new();
        msg.extend(randoms.client);
        msg.extend(randoms.server);
        kx_params.encode(&mut msg);

        let signer = signing_key
            .choose_scheme(&sigschemes)
            .ok_or_else(|| Error::General("incompatible signing key".to_string()))?;
        let sigscheme = signer.scheme();
        let sig = signer.sign(&msg)?;

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
    fn handle<'m>(
        mut self: Box<Self>,
        cx: &mut ServerContext<'_>,
        m: Message<'m>,
    ) -> hs::NextStateOrError<'m>
    where
        Self: 'm,
    {
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

        let peer_identity =
            match PeerIdentity::from_cert_chain(cert_chain.0, CertificateType::X509, cx.common)? {
                None if mandatory => {
                    return Err(cx.common.send_fatal_alert(
                        AlertDescription::CertificateRequired,
                        Error::NoCertificatesPresented,
                    ));
                }
                None => {
                    debug!("client auth requested but no certificate supplied");
                    self.transcript.abandon_client_auth();
                    None
                }
                Some(identity) => {
                    self.config
                        .verifier
                        .verify_client_cert(&ClientIdentity {
                            identity: &identity,
                            now: self.config.current_time()?,
                        })
                        .map_err(|err| {
                            cx.common
                                .send_cert_verify_error_alert(err)
                        })?;
                    Some(identity)
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

    fn into_owned(self: Box<Self>) -> hs::NextState<'static> {
        self
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
    peer_identity: Option<PeerIdentity>,
    send_ticket: bool,
}

impl State<ServerConnectionData> for ExpectClientKx {
    fn handle<'m>(
        mut self: Box<Self>,
        cx: &mut ServerContext<'_>,
        m: Message<'m>,
    ) -> hs::NextStateOrError<'m>
    where
        Self: 'm,
    {
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
        let peer_kx_params = tls12::decode_kx_params::<ClientKeyExchangeParams>(
            self.suite.kx,
            cx.common,
            client_kx.bytes(),
        )?;
        let secrets = ConnectionSecrets::from_key_exchange(
            self.server_kx,
            peer_kx_params.pub_key(),
            ems_seed,
            self.randoms,
            self.suite,
        )
        .map_err(|err| {
            cx.common
                .send_fatal_alert(AlertDescription::IllegalParameter, err)
        })?;
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

    fn into_owned(self: Box<Self>) -> hs::NextState<'static> {
        Box::new(Self {
            config: self.config,
            transcript: self.transcript,
            randoms: self.randoms,
            session_id: self.session_id,
            suite: self.suite,
            using_ems: self.using_ems,
            server_kx: self.server_kx,
            peer_identity: self.peer_identity,
            send_ticket: self.send_ticket,
        })
    }
}

// --- Process client's certificate proof ---
struct ExpectCertificateVerify {
    config: Arc<ServerConfig>,
    secrets: ConnectionSecrets,
    transcript: HandshakeHash,
    session_id: SessionId,
    using_ems: bool,
    peer_identity: PeerIdentity,
    send_ticket: bool,
}

impl State<ServerConnectionData> for ExpectCertificateVerify {
    fn handle<'m>(
        mut self: Box<Self>,
        cx: &mut ServerContext<'_>,
        m: Message<'m>,
    ) -> hs::NextStateOrError<'m>
    where
        Self: 'm,
    {
        let rc = {
            let signature = require_handshake_msg!(
                m,
                HandshakeType::CertificateVerify,
                HandshakePayload::CertificateVerify
            )?;

            match self.transcript.take_handshake_buf() {
                Some(msgs) => self
                    .config
                    .verifier
                    .verify_tls12_signature(&SignatureVerificationInput {
                        message: &msgs,
                        signer: &self.peer_identity.as_signer(),
                        signature,
                    }),
                None => {
                    // This should be unreachable; the handshake buffer was initialized with
                    // client authentication if the verifier wants to offer it.
                    // `transcript.abandon_client_auth()` can extract it, but its only caller in
                    // this flow will also set `ExpectClientKx::client_cert` to `None`, making it
                    // impossible to reach this state.
                    return Err(cx.common.send_fatal_alert(
                        AlertDescription::AccessDenied,
                        Error::General("client authentication not set up".into()),
                    ));
                }
            }
        };

        if let Err(e) = rc {
            return Err(cx
                .common
                .send_cert_verify_error_alert(e));
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

    fn into_owned(self: Box<Self>) -> hs::NextState<'static> {
        Box::new(Self {
            config: self.config,
            secrets: self.secrets,
            transcript: self.transcript,
            session_id: self.session_id,
            using_ems: self.using_ems,
            peer_identity: self.peer_identity,
            send_ticket: self.send_ticket,
        })
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
    fn handle<'m>(
        self: Box<Self>,
        cx: &mut ServerContext<'_>,
        m: Message<'m>,
    ) -> hs::NextStateOrError<'m>
    where
        Self: 'm,
    {
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
        cx.common.check_aligned_handshake()?;

        cx.common
            .record_layer
            .start_decrypting();
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

    fn into_owned(self: Box<Self>) -> hs::NextState<'static> {
        self
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
    ticketer: &dyn ProducesTickets,
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
) {
    let vh = transcript.current_hash();
    let verify_data = secrets.server_verify_data(&vh);
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
    fn handle<'m>(
        mut self: Box<Self>,
        cx: &mut ServerContext<'_>,
        m: Message<'m>,
    ) -> hs::NextStateOrError<'m>
    where
        Self: 'm,
    {
        let finished =
            require_handshake_msg!(m, HandshakeType::Finished, HandshakePayload::Finished)?;

        cx.common.check_aligned_handshake()?;

        let vh = self.transcript.current_hash();
        let expect_verify_data = self.secrets.client_verify_data(&vh);

        let _fin_verified =
            match ConstantTimeEq::ct_eq(&expect_verify_data[..], finished.bytes()).into() {
                true => verify::FinishedMessageVerified::assertion(),
                false => {
                    return Err(cx
                        .common
                        .send_fatal_alert(AlertDescription::DecryptError, Error::DecryptError));
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
            #[cfg_attr(not(feature = "log"), allow(clippy::if_same_then_else))]
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
                emit_ticket(
                    &self.secrets,
                    &mut self.transcript,
                    self.using_ems,
                    cx,
                    &*self.config.ticketer,
                    now,
                )?;
            }
            emit_ccs(cx.common);
            cx.common
                .record_layer
                .start_encrypting();
            emit_finished(&self.secrets, &mut self.transcript, cx.common);
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
            _fin_verified,
        }))
    }

    fn into_owned(self: Box<Self>) -> hs::NextState<'static> {
        self
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
    fn handle<'m>(
        self: Box<Self>,
        cx: &mut ServerContext<'_>,
        m: Message<'m>,
    ) -> hs::NextStateOrError<'m>
    where
        Self: 'm,
    {
        match m.payload {
            MessagePayload::ApplicationData(payload) => cx
                .common
                .take_received_plaintext(payload),
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

    fn into_owned(self: Box<Self>) -> hs::NextState<'static> {
        self
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
