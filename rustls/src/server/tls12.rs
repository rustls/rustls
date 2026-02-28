use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;

pub(crate) use client_hello::TLS12_HANDLER;
use pki_types::{DnsName, UnixTime};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use super::config::ServerConfig;
use super::{CommonServerSessionValue, ServerSessionKey, ServerSessionValue};
use crate::check::inappropriate_message;
use crate::common_state::{Event, HandshakeFlightTls12, HandshakeKind, Input, Output, Side, State};
use crate::conn::ConnectionRandoms;
use crate::conn::kernel::KernelState;
use crate::crypto::cipher::{MessageDecrypter, MessageEncrypter, Payload};
use crate::crypto::kx::{ActiveKeyExchange, SupportedKxGroup};
use crate::crypto::{Identity, TicketProducer};
use crate::enums::{
    ApplicationProtocol, CertificateType, ContentType, HandshakeType, ProtocolVersion,
};
use crate::error::{ApiMisuse, Error, InvalidMessage, PeerIncompatible, PeerMisbehaved};
use crate::hash_hs::HandshakeHash;
use crate::log::{debug, trace};
use crate::msgs::{
    CertificateChain, ChangeCipherSpecPayload, ClientKeyExchangeParams, Codec,
    HandshakeAlignedProof, HandshakeMessagePayload, HandshakePayload, Message, MessagePayload,
    NewSessionTicketPayload, NewSessionTicketPayloadTls13, Reader, SessionId,
};
use crate::suites::PartiallyExtractedSecrets;
use crate::sync::Arc;
use crate::tls12::{self, ConnectionSecrets, Tls12CipherSuite};
use crate::tls13::key_schedule::KeyScheduleTrafficSend;
use crate::verify::{ClientIdentity, SignatureVerificationInput};
use crate::{ConnectionTrafficSecrets, verify};

mod client_hello {
    use super::*;
    use crate::crypto::kx::SupportedKxGroup;
    use crate::crypto::{SelectedCredential, Signer};
    use crate::msgs::{
        CertificateRequestPayload, CertificateStatus, ClientCertificateType, ClientHelloPayload,
        ClientSessionTicket, Compression, Random, ServerExtensionsInput, ServerHelloPayload,
        ServerKeyExchange, ServerKeyExchangeParams, ServerKeyExchangePayload,
    };
    use crate::sealed::Sealed;
    use crate::server::hs::{ClientHelloInput, ExpectClientHello, ServerHandler, Tls12Extensions};
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
            output: &mut dyn Output,
        ) -> Result<Box<dyn State>, Error> {
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

            let (ticket_received, resume_data) = check_session(
                input.client_hello,
                st.sni.as_ref(),
                st.using_ems,
                suite,
                &st.config,
            );

            if let Some(data) = resume_data {
                let proof = input.proof;
                return start_resumption(
                    suite,
                    st.using_ems,
                    output,
                    input,
                    st.sni,
                    st.resumption_data,
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

            output.emit(Event::HandshakeKind(HandshakeKind::Full));

            let mut flight = HandshakeFlightTls12::new(&mut transcript);

            let Tls12Extensions {
                alpn_protocol,
                send_ticket,
            } = emit_server_hello(
                &mut flight,
                &st.config,
                output,
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

            flight.finish(output);
            let hs = HandshakeState {
                config: st.config,
                transcript,
                session_id: st.session_id,
                alpn_protocol,
                sni: st.sni,
                resumption_data: st.resumption_data,
                using_ems: st.using_ems,
                send_ticket,
            };

            if doing_client_auth {
                Ok(Box::new(ExpectCertificate {
                    hs,
                    randoms,
                    suite,
                    server_kx,
                }))
            } else {
                Ok(Box::new(ExpectClientKx {
                    hs,
                    randoms,
                    suite,
                    server_kx,
                    peer_identity: None,
                }))
            }
        }
    }

    impl Sealed for Handler {}

    /// Check for resumption
    fn check_session(
        hello: &ClientHelloPayload,
        sni: Option<&DnsName<'_>>,
        using_ems: bool,
        suite: &'static Tls12CipherSuite,
        config: &ServerConfig,
    ) -> (bool, Option<Tls12ServerSessionValue<'static>>) {
        // First, check for a ticket that decrypts
        let (ticket, encoded) = match hello.session_ticket.as_ref() {
            Some(ClientSessionTicket::Offer(ticket)) => {
                debug!("Ticket received");
                let data = config
                    .ticketer
                    .as_ref()
                    .and_then(|ticketer| ticketer.decrypt(ticket.bytes()));
                match data {
                    Some(data) => (true, Some(data)),
                    None => {
                        debug!("Ticket didn't decrypt");
                        (true, None)
                    }
                }
            }
            Some(_) | None => (false, None),
        };

        let (ticket, encoded) = match (ticket, encoded) {
            (_, Some(data)) => (true, data),
            // If we've received a ticket, the session ID won't be in our cache, so skip checking
            (false, None) if !hello.session_id.is_empty() => {
                // Check for a session ID in our cache
                let store = &config.session_storage;
                match store.get(ServerSessionKey::from(&hello.session_id)) {
                    Some(data) => (false, data),
                    None => return (false, None),
                }
            }
            (ticket, None) => return (ticket, None),
        };

        // Try to parse the encoded session value
        let Ok(ServerSessionValue::Tls12(session)) = ServerSessionValue::read_bytes(&encoded)
        else {
            return (ticket, None);
        };

        // Check that the session is compatible with the current connection
        if !session
            .common
            .can_resume(suite.common.suite, sni)
        {
            return (ticket, None);
        }

        match session.extended_ms == using_ems || session.extended_ms && !using_ems {
            true => (ticket, Some(session.into_owned())),
            false => (ticket, None),
        }
    }

    fn start_resumption(
        suite: &'static Tls12CipherSuite,
        using_ems: bool,
        output: &mut dyn Output,
        input: ClientHelloInput<'_>,
        sni: Option<DnsName<'static>>,
        resumption_data: Vec<u8>,
        mut transcript: HandshakeHash,
        randoms: ConnectionRandoms,
        extra_exts: ServerExtensionsInput,
        config: Arc<ServerConfig>,
        resumedata: Tls12ServerSessionValue<'static>,
        proof: HandshakeAlignedProof,
    ) -> Result<Box<dyn State>, Error> {
        debug!("Resuming connection");

        if resumedata.extended_ms && !using_ems {
            return Err(PeerMisbehaved::ResumptionAttemptedWithVariedEms.into());
        }

        let session_id = input.client_hello.session_id;
        let mut flight = HandshakeFlightTls12::new(&mut transcript);
        let Tls12Extensions {
            alpn_protocol,
            send_ticket,
        } = emit_server_hello(
            &mut flight,
            &config,
            output,
            session_id,
            suite,
            using_ems,
            &mut None,
            input.client_hello,
            Some(&resumedata.common),
            &randoms,
            extra_exts,
        )?;
        flight.finish(output);

        let mut hs = HandshakeState {
            config,
            transcript,
            session_id,
            alpn_protocol,
            sni,
            resumption_data: resumption_data.to_vec(),
            using_ems,
            send_ticket,
        };

        let secrets =
            ConnectionSecrets::new_resume(randoms, suite, resumedata.master_secret.as_ref());
        hs.config.key_log.log(
            "CLIENT_RANDOM",
            &secrets.randoms.client,
            secrets.master_secret(),
        );

        output.emit(Event::HandshakeKind(HandshakeKind::Resumed));
        output.emit(Event::ResumptionData(
            resumedata
                .common
                .application_data
                .bytes()
                .to_vec(),
        ));

        if send_ticket {
            let now = hs.config.current_time()?;

            if let Some(ticketer) = hs.config.ticketer.as_deref() {
                emit_ticket(
                    &secrets,
                    &mut hs.transcript,
                    using_ems,
                    resumedata.common.peer_identity.as_ref(),
                    hs.alpn_protocol.as_ref(),
                    hs.sni.as_ref(),
                    resumption_data,
                    output,
                    ticketer,
                    now,
                )?;
            }
        }
        emit_ccs(output);

        let (dec, encrypter) = secrets.make_cipher_pair(Side::Server);
        output.emit(Event::MessageEncrypter {
            encrypter,
            limit: secrets
                .suite()
                .common
                .confidentiality_limit,
        });
        emit_finished(&secrets, &mut hs.transcript, output, &proof);

        Ok(Box::new(ExpectCcs {
            hs,
            secrets,
            peer_identity: resumedata.common.peer_identity,
            resuming_decrypter: Some(dec),
        }))
    }

    fn emit_server_hello(
        flight: &mut HandshakeFlightTls12<'_>,
        config: &ServerConfig,
        output: &mut dyn Output,
        session_id: SessionId,
        suite: &'static Tls12CipherSuite,
        using_ems: bool,
        ocsp_response: &mut Option<&[u8]>,
        hello: &ClientHelloPayload,
        resumedata: Option<&CommonServerSessionValue<'_>>,
        randoms: &ConnectionRandoms,
        extra_exts: ServerExtensionsInput,
    ) -> Result<Tls12Extensions, Error> {
        let (out, extensions) = Tls12Extensions::new(
            extra_exts,
            ocsp_response,
            resumedata,
            hello,
            output,
            using_ems,
            config,
        )?;

        let sh = HandshakeMessagePayload(HandshakePayload::ServerHello(ServerHelloPayload {
            legacy_version: ProtocolVersion::TLSv1_2,
            random: Random::from(randoms.server),
            session_id,
            cipher_suite: suite.common.suite,
            compression_method: Compression::Null,
            extensions,
        }));

        trace!("sending server hello {sh:?}");
        flight.add(sh);
        Ok(out)
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
    hs: HandshakeState,
    randoms: ConnectionRandoms,
    suite: &'static Tls12CipherSuite,
    server_kx: GroupAndKeyExchange,
}

impl State for ExpectCertificate {
    fn handle(
        mut self: Box<Self>,
        Input { message, .. }: Input<'_>,
        _output: &mut dyn Output,
    ) -> Result<Box<dyn State>, Error> {
        self.hs.transcript.add_message(&message);
        let cert_chain = require_handshake_msg_move!(
            message,
            HandshakeType::Certificate,
            HandshakePayload::Certificate
        )?;

        // If we can't determine if the auth is mandatory, abort
        let mandatory = self
            .hs
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
                self.hs.transcript.abandon_client_auth();
                None
            }
            Some(identity) => {
                self.hs
                    .config
                    .verifier
                    .verify_identity(&ClientIdentity {
                        identity: &identity,
                        now: self.hs.config.current_time()?,
                    })?;
                Some(identity.into_owned())
            }
        };

        Ok(Box::new(ExpectClientKx {
            hs: self.hs,
            randoms: self.randoms,
            suite: self.suite,
            server_kx: self.server_kx,
            peer_identity,
        }))
    }
}

// --- Process client's KeyExchange ---
struct ExpectClientKx {
    hs: HandshakeState,
    randoms: ConnectionRandoms,
    suite: &'static Tls12CipherSuite,
    server_kx: GroupAndKeyExchange,
    peer_identity: Option<Identity<'static>>,
}

impl State for ExpectClientKx {
    fn handle(
        mut self: Box<Self>,
        Input { message, .. }: Input<'_>,
        output: &mut dyn Output,
    ) -> Result<Box<dyn State>, Error> {
        let client_kx = require_handshake_msg!(
            message,
            HandshakeType::ClientKeyExchange,
            HandshakePayload::ClientKeyExchange
        )?;
        self.hs.transcript.add_message(&message);
        let ems_seed = self
            .hs
            .using_ems
            .then(|| self.hs.transcript.current_hash());

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
        output.emit(Event::KeyExchangeGroup(self.server_kx.group));

        self.hs.config.key_log.log(
            "CLIENT_RANDOM",
            &secrets.randoms.client,
            secrets.master_secret(),
        );

        match self.peer_identity {
            Some(peer_identity) => Ok(Box::new(ExpectCertificateVerify {
                hs: self.hs,
                secrets,
                peer_identity,
            })),
            _ => Ok(Box::new(ExpectCcs {
                hs: self.hs,
                secrets,
                peer_identity: None,
                resuming_decrypter: None,
            })),
        }
    }
}

// --- Process client's certificate proof ---
struct ExpectCertificateVerify {
    hs: HandshakeState,
    secrets: ConnectionSecrets,
    peer_identity: Identity<'static>,
}

impl State for ExpectCertificateVerify {
    fn handle(
        mut self: Box<Self>,
        Input { message, .. }: Input<'_>,
        _output: &mut dyn Output,
    ) -> Result<Box<dyn State>, Error> {
        let signature = require_handshake_msg!(
            message,
            HandshakeType::CertificateVerify,
            HandshakePayload::CertificateVerify
        )?;

        match self.hs.transcript.take_handshake_buf() {
            Some(msgs) => {
                self.hs
                    .config
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

        self.hs.transcript.add_message(&message);
        Ok(Box::new(ExpectCcs {
            hs: self.hs,
            secrets: self.secrets,
            peer_identity: Some(self.peer_identity),
            resuming_decrypter: None,
        }))
    }
}

// --- Process client's ChangeCipherSpec ---
struct ExpectCcs {
    hs: HandshakeState,
    secrets: ConnectionSecrets,
    peer_identity: Option<Identity<'static>>,
    resuming_decrypter: Option<Box<dyn MessageDecrypter>>,
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

        let (decrypter, pending_encrypter) = match self.resuming_decrypter {
            Some(dec) => (dec, None),
            None => {
                let (dec, enc) = self
                    .secrets
                    .make_cipher_pair(Side::Server);
                (dec, Some(enc))
            }
        };

        output.emit(Event::MessageDecrypter { decrypter, proof });

        Ok(Box::new(ExpectFinished {
            hs: self.hs,
            secrets: self.secrets,
            peer_identity: self.peer_identity,
            resuming: pending_encrypter.is_none(),
            pending_encrypter,
        }))
    }
}

#[derive(Debug)]
pub(crate) struct Tls12ServerSessionValue<'a> {
    common: CommonServerSessionValue<'a>,
    master_secret: ZeroizingCow<'a, 48>,
    extended_ms: bool,
}

impl<'a> Tls12ServerSessionValue<'a> {
    fn new(
        common: CommonServerSessionValue<'a>,
        master_secret: &'a [u8; 48],
        extended_ms: bool,
    ) -> Self {
        Self {
            common,
            master_secret: ZeroizingCow::Borrowed(master_secret),
            extended_ms,
        }
    }

    fn into_owned(self) -> Tls12ServerSessionValue<'static> {
        Tls12ServerSessionValue {
            common: self.common.into_owned(),
            master_secret: ZeroizingCow::Owned(match self.master_secret {
                ZeroizingCow::Borrowed(b) => *b,
                ZeroizingCow::Owned(o) => o,
            }),
            extended_ms: self.extended_ms,
        }
    }
}

impl Codec<'_> for Tls12ServerSessionValue<'_> {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.common.encode(bytes);
        bytes.extend_from_slice(self.master_secret.as_ref());
        (self.extended_ms as u8).encode(bytes);
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, InvalidMessage> {
        Ok(Self {
            common: CommonServerSessionValue::read(r)?,
            master_secret: ZeroizingCow::Owned(r.take_array("MasterSecret").copied()?),
            extended_ms: matches!(u8::read(r)?, 1),
        })
    }
}

impl<'a> From<Tls12ServerSessionValue<'a>> for ServerSessionValue<'a> {
    fn from(value: Tls12ServerSessionValue<'a>) -> Self {
        Self::Tls12(value)
    }
}

#[derive(Debug)]
enum ZeroizingCow<'a, const N: usize> {
    Borrowed(&'a [u8; N]),
    Owned([u8; N]),
}

impl<const N: usize> AsRef<[u8; N]> for ZeroizingCow<'_, N> {
    fn as_ref(&self) -> &[u8; N] {
        match self {
            ZeroizingCow::Borrowed(b) => b,
            ZeroizingCow::Owned(o) => o,
        }
    }
}

impl<const N: usize> Drop for ZeroizingCow<'_, N> {
    fn drop(&mut self) {
        if let ZeroizingCow::Owned(o) = self {
            o.zeroize();
        }
    }
}

fn emit_ticket(
    secrets: &ConnectionSecrets,
    transcript: &mut HandshakeHash,
    using_ems: bool,
    peer_identity: Option<&Identity<'static>>,
    alpn_protocol: Option<&ApplicationProtocol<'_>>,
    sni: Option<&DnsName<'static>>,
    resumption_data: Vec<u8>,
    output: &mut dyn Output,
    ticketer: &dyn TicketProducer,
    now: UnixTime,
) -> Result<(), Error> {
    let plain = ServerSessionValue::from(Tls12ServerSessionValue::new(
        CommonServerSessionValue::new(
            sni,
            secrets.suite().common.suite,
            peer_identity.cloned(),
            alpn_protocol.map(|p| p.to_owned()),
            resumption_data,
            now,
        ),
        secrets.master_secret(),
        using_ems,
    ))
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
    let verify_data = secrets.server_verify_data(&vh, proof);
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

struct ExpectFinished {
    hs: HandshakeState,
    secrets: ConnectionSecrets,
    peer_identity: Option<Identity<'static>>,
    resuming: bool,
    pending_encrypter: Option<Box<dyn MessageEncrypter>>,
}

impl State for ExpectFinished {
    fn handle(
        mut self: Box<Self>,
        input: Input<'_>,
        output: &mut dyn Output,
    ) -> Result<Box<dyn State>, Error> {
        let finished = require_handshake_msg!(
            input.message,
            HandshakeType::Finished,
            HandshakePayload::Finished
        )?;

        let proof = input.check_aligned_handshake()?;

        let vh = self.hs.transcript.current_hash();
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
        if !self.resuming && !self.hs.session_id.is_empty() {
            let value = ServerSessionValue::from(Tls12ServerSessionValue::new(
                CommonServerSessionValue::new(
                    self.hs.sni.as_ref(),
                    self.secrets.suite().common.suite,
                    self.peer_identity.clone(),
                    self.hs.alpn_protocol.clone(),
                    self.hs.resumption_data.to_vec(),
                    self.hs.config.current_time()?,
                ),
                self.secrets.master_secret(),
                self.hs.using_ems,
            ));

            let worked = self.hs.config.session_storage.put(
                ServerSessionKey::from(&self.hs.session_id),
                value.get_encoding(),
            );
            if worked {
                debug!("Session saved");
            } else {
                debug!("Session not saved");
            }
        }

        // Send our CCS and Finished.
        self.hs
            .transcript
            .add_message(&input.message);
        if let Some(encrypter) = self.pending_encrypter {
            assert!(!self.resuming);
            if self.hs.send_ticket {
                let now = self.hs.config.current_time()?;
                if let Some(ticketer) = self.hs.config.ticketer.as_deref() {
                    emit_ticket(
                        &self.secrets,
                        &mut self.hs.transcript,
                        self.hs.using_ems,
                        self.peer_identity.as_ref(),
                        self.hs.alpn_protocol.as_ref(),
                        self.hs.sni.as_ref(),
                        self.hs.resumption_data,
                        output,
                        ticketer,
                        now,
                    )?;
                }
            }
            emit_ccs(output);
            output.emit(Event::MessageEncrypter {
                encrypter,
                limit: self
                    .secrets
                    .suite()
                    .common
                    .confidentiality_limit,
            });
            emit_finished(&self.secrets, &mut self.hs.transcript, output, &proof);
        }

        if let Some(identity) = self.peer_identity {
            output.emit(Event::PeerIdentity(identity));
        }

        let extracted_secrets = self
            .hs
            .config
            .enable_secret_extraction
            .then(|| {
                self.secrets
                    .extract_secrets(Side::Server)
            });

        output.emit(Event::Exporter(self.secrets.into_exporter()));
        output.start_traffic();

        Ok(Box::new(ExpectTraffic {
            extracted_secrets,
            _fin_verified: fin_verified,
        }))
    }
}

struct HandshakeState {
    config: Arc<ServerConfig>,
    transcript: HandshakeHash,
    session_id: SessionId,
    alpn_protocol: Option<ApplicationProtocol<'static>>,
    sni: Option<DnsName<'static>>,
    resumption_data: Vec<u8>,
    using_ems: bool,
    send_ticket: bool,
}

// --- Process traffic ---
struct ExpectTraffic {
    // only `Some` if `config.enable_secret_extraction` is true
    extracted_secrets: Option<Result<PartiallyExtractedSecrets, Error>>,
    _fin_verified: verify::FinishedMessageVerified,
}

impl ExpectTraffic {}

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
        unreachable!(
            "server connections should never have handle_new_session_ticket called on them"
        )
    }
}

struct GroupAndKeyExchange {
    group: &'static dyn SupportedKxGroup,
    kx: Box<dyn ActiveKeyExchange>,
}
