#[cfg(feature = "quic")]
use crate::conn::Protocol;
use crate::conn::{ConnectionRandoms, ConnectionSecrets};
use crate::error::Error;
use crate::key::Certificate;
use crate::kx;
#[cfg(feature = "logging")]
use crate::log::{debug, trace};
use crate::msgs::codec::Codec;
use crate::msgs::enums::{AlertDescription, ExtensionType};
use crate::msgs::enums::{CipherSuite, Compression, ECPointFormat};
use crate::msgs::enums::{ClientCertificateType, SignatureScheme};
use crate::msgs::enums::{ContentType, HandshakeType, ProtocolVersion};
use crate::msgs::handshake::CertificateRequestPayload;
use crate::msgs::handshake::{CertificateStatus, ClientExtension, HandshakeMessagePayload};
use crate::msgs::handshake::{ClientHelloPayload, ServerExtension, SessionID};
use crate::msgs::handshake::{ConvertProtocolNameList, ConvertServerNameList};
use crate::msgs::handshake::{DigitallySignedStruct, ServerECDHParams};
use crate::msgs::handshake::{ECDHEServerKeyExchange, ServerKeyExchangePayload};
use crate::msgs::handshake::{ECPointFormatList, SupportedPointFormats};
use crate::msgs::handshake::{HandshakePayload, SupportedSignatureSchemes};
use crate::msgs::message::{Message, MessagePayload};
use crate::msgs::persist;
use crate::server::{ClientHello, ServerConfig, ServerConnection};
use crate::sign;
use crate::suites;
use crate::SupportedCipherSuite;

use crate::server::common::{HandshakeDetails, ServerKxDetails};
use crate::server::{tls12, tls13};

pub type NextState = Box<dyn State + Send + Sync>;
pub type NextStateOrError = Result<NextState, Error>;

pub trait State {
    fn handle(self: Box<Self>, conn: &mut ServerConnection, m: Message) -> NextStateOrError;

    fn export_keying_material(
        &self,
        _output: &mut [u8],
        _label: &[u8],
        _context: Option<&[u8]>,
    ) -> Result<(), Error> {
        Err(Error::HandshakeNotComplete)
    }

    fn perhaps_write_key_update(&mut self, _conn: &mut ServerConnection) {}
}

pub fn incompatible(conn: &mut ServerConnection, why: &str) -> Error {
    conn.common
        .send_fatal_alert(AlertDescription::HandshakeFailure);
    Error::PeerIncompatibleError(why.to_string())
}

fn bad_version(conn: &mut ServerConnection, why: &str) -> Error {
    conn.common
        .send_fatal_alert(AlertDescription::ProtocolVersion);
    Error::PeerIncompatibleError(why.to_string())
}

pub fn illegal_param(conn: &mut ServerConnection, why: &str) -> Error {
    conn.common
        .send_fatal_alert(AlertDescription::IllegalParameter);
    Error::PeerMisbehavedError(why.to_string())
}

pub fn decode_error(conn: &mut ServerConnection, why: &str) -> Error {
    conn.common
        .send_fatal_alert(AlertDescription::DecodeError);
    Error::PeerMisbehavedError(why.to_string())
}

pub fn can_resume(
    suite: &'static SupportedCipherSuite,
    sni: &Option<webpki::DnsName>,
    using_ems: bool,
    resumedata: persist::ServerSessionValue,
) -> Option<persist::ServerSessionValue> {
    // The RFCs underspecify what happens if we try to resume to
    // an unoffered/varying suite.  We merely don't resume in weird cases.
    //
    // RFC 6066 says "A server that implements this extension MUST NOT accept
    // the request to resume the session if the server_name extension contains
    // a different name. Instead, it proceeds with a full handshake to
    // establish a new session."

    if resumedata.cipher_suite == suite.suite
        && (resumedata.extended_ms == using_ems || (resumedata.extended_ms && !using_ems))
        && same_dns_name_or_both_none(resumedata.sni.as_ref(), sni.as_ref())
    {
        return Some(resumedata);
    }

    None
}

// Require an exact match for the purpose of comparing SNI DNS Names from two
// client hellos, even though a case-insensitive comparison might also be OK.
fn same_dns_name_or_both_none(a: Option<&webpki::DnsName>, b: Option<&webpki::DnsName>) -> bool {
    match (a, b) {
        (Some(a), Some(b)) => {
            let a: &str = a.as_ref().into();
            let b: &str = b.as_ref().into();
            a == b
        }
        (None, None) => true,
        _ => false,
    }
}

// Changing the keys must not span any fragmented handshake
// messages.  Otherwise the defragmented messages will have
// been protected with two different record layer protections,
// which is illegal.  Not mentioned in RFC.
pub fn check_aligned_handshake(conn: &mut ServerConnection) -> Result<(), Error> {
    if !conn.common.handshake_joiner.is_empty() {
        conn.common
            .send_fatal_alert(AlertDescription::UnexpectedMessage);
        Err(Error::PeerMisbehavedError(
            "key epoch or handshake flight with pending fragment".to_string(),
        ))
    } else {
        Ok(())
    }
}

pub fn save_sni(conn: &mut ServerConnection, sni: Option<webpki::DnsName>) {
    if let Some(sni) = sni {
        // Save the SNI into the session.
        conn.set_sni(sni);
    }
}

#[derive(Default)]
pub struct ExtensionProcessing {
    // extensions to reply with
    pub exts: Vec<ServerExtension>,

    pub send_ticket: bool,
}

impl ExtensionProcessing {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn process_common(
        &mut self,
        conn: &mut ServerConnection,
        #[allow(unused_variables)] // #[cfg(feature = "quic")] only
        suite: &'static SupportedCipherSuite,
        ocsp_response: &mut Option<&[u8]>,
        sct_list: &mut Option<&[u8]>,
        hello: &ClientHelloPayload,
        resumedata: Option<&persist::ServerSessionValue>,
        handshake: &HandshakeDetails,
    ) -> Result<(), Error> {
        // ALPN
        let our_protocols = &conn.config.alpn_protocols;
        let maybe_their_protocols = hello.get_alpn_extension();
        if let Some(their_protocols) = maybe_their_protocols {
            let their_protocols = their_protocols.to_slices();

            if their_protocols
                .iter()
                .any(|protocol| protocol.is_empty())
            {
                return Err(Error::PeerMisbehavedError(
                    "client offered empty ALPN protocol".to_string(),
                ));
            }

            conn.common.alpn_protocol = our_protocols
                .iter()
                .find(|protocol| their_protocols.contains(&protocol.as_slice()))
                .cloned();
            if let Some(ref selected_protocol) = conn.common.alpn_protocol {
                debug!("Chosen ALPN protocol {:?}", selected_protocol);
                self.exts
                    .push(ServerExtension::make_alpn(&[selected_protocol]));
            } else {
                // For compatibility, strict ALPN validation is not employed unless targeting QUIC
                #[cfg(feature = "quic")]
                {
                    if conn.common.protocol == Protocol::Quic && !our_protocols.is_empty() {
                        conn.common
                            .send_fatal_alert(AlertDescription::NoApplicationProtocol);
                        return Err(Error::NoApplicationProtocol);
                    }
                }
            }
        }

        #[cfg(feature = "quic")]
        {
            if conn.common.protocol == Protocol::Quic {
                if let Some(params) = hello.get_quic_params_extension() {
                    conn.common.quic.params = Some(params);
                }

                if let Some(resume) = resumedata {
                    if conn.config.max_early_data_size > 0
                        && hello.early_data_extension_offered()
                        && resume.version == conn.common.negotiated_version.unwrap()
                        && resume.cipher_suite == suite.suite
                        && resume.alpn.as_ref().map(|x| &x.0) == conn.common.alpn_protocol.as_ref()
                        && !conn.reject_early_data
                    {
                        self.exts
                            .push(ServerExtension::EarlyData);
                    } else {
                        // Clobber value set in tls13::emit_server_hello
                        conn.common.quic.early_secret = None;
                    }
                }
            }
        }

        let for_resume = resumedata.is_some();
        // SNI
        if !for_resume && hello.get_sni_extension().is_some() {
            self.exts
                .push(ServerExtension::ServerNameAck);
        }

        // Send status_request response if we have one.  This is not allowed
        // if we're resuming, and is only triggered if we have an OCSP response
        // to send.
        if !for_resume
            && hello
                .find_extension(ExtensionType::StatusRequest)
                .is_some()
        {
            if ocsp_response.is_some() && !conn.common.is_tls13() {
                // Only TLS1.2 sends confirmation in ServerHello
                self.exts
                    .push(ServerExtension::CertificateStatusAck);
            }
        } else {
            // Throw away any OCSP response so we don't try to send it later.
            ocsp_response.take();
        }

        if !for_resume
            && hello
                .find_extension(ExtensionType::SCT)
                .is_some()
        {
            if !conn.common.is_tls13() {
                // Take the SCT list, if any, so we don't send it later,
                // and put it in the legacy extension.
                if let Some(sct_list) = sct_list.take() {
                    self.exts
                        .push(ServerExtension::make_sct(sct_list.to_vec()));
                }
            }
        } else {
            // Throw away any SCT list so we don't send it later.
            sct_list.take();
        }

        self.exts
            .extend(handshake.extra_exts.iter().cloned());

        Ok(())
    }

    pub(super) fn process_tls12(
        &mut self,
        conn: &ServerConnection,
        hello: &ClientHelloPayload,
        using_ems: bool,
    ) {
        // Renegotiation.
        // (We don't do reneg at all, but would support the secure version if we did.)
        let secure_reneg_offered = hello
            .find_extension(ExtensionType::RenegotiationInfo)
            .is_some()
            || hello
                .cipher_suites
                .contains(&CipherSuite::TLS_EMPTY_RENEGOTIATION_INFO_SCSV);

        if secure_reneg_offered {
            self.exts
                .push(ServerExtension::make_empty_renegotiation_info());
        }

        // Tickets:
        // If we get any SessionTicket extension and have tickets enabled,
        // we send an ack.
        if hello
            .find_extension(ExtensionType::SessionTicket)
            .is_some()
            && conn.config.ticketer.enabled()
        {
            self.send_ticket = true;
            self.exts
                .push(ServerExtension::SessionTicketAck);
        }

        // Confirm use of EMS if offered.
        if using_ems {
            self.exts
                .push(ServerExtension::ExtendedMasterSecretAck);
        }
    }
}

pub struct ExpectClientHello {
    pub handshake: HandshakeDetails,
    pub using_ems: bool,
    pub done_retry: bool,
    pub send_ticket: bool,
}

impl ExpectClientHello {
    pub fn new(
        server_config: &ServerConfig,
        extra_exts: Vec<ServerExtension>,
    ) -> ExpectClientHello {
        let mut ech = ExpectClientHello {
            handshake: HandshakeDetails::new(extra_exts),
            using_ems: false,
            done_retry: false,
            send_ticket: false,
        };

        if server_config
            .verifier
            .offer_client_auth()
        {
            ech.handshake
                .transcript
                .set_client_auth_enabled();
        }

        ech
    }

    fn emit_certificate(&mut self, conn: &mut ServerConnection, cert_chain: &[Certificate]) {
        let c = Message {
            typ: ContentType::Handshake,
            version: ProtocolVersion::TLSv1_2,
            payload: MessagePayload::Handshake(HandshakeMessagePayload {
                typ: HandshakeType::Certificate,
                payload: HandshakePayload::Certificate(cert_chain.to_owned()),
            }),
        };

        self.handshake
            .transcript
            .add_message(&c);
        conn.common.send_msg(c, false);
    }

    fn emit_cert_status(&mut self, conn: &mut ServerConnection, ocsp: &[u8]) {
        let st = CertificateStatus::new(ocsp.to_owned());

        let c = Message {
            typ: ContentType::Handshake,
            version: ProtocolVersion::TLSv1_2,
            payload: MessagePayload::Handshake(HandshakeMessagePayload {
                typ: HandshakeType::CertificateStatus,
                payload: HandshakePayload::CertificateStatus(st),
            }),
        };

        self.handshake
            .transcript
            .add_message(&c);
        conn.common.send_msg(c, false);
    }

    fn emit_server_kx(
        &mut self,
        conn: &mut ServerConnection,
        sigschemes: Vec<SignatureScheme>,
        skxg: &'static kx::SupportedKxGroup,
        signing_key: &dyn sign::SigningKey,
        randoms: &ConnectionRandoms,
    ) -> Result<kx::KeyExchange, Error> {
        let kx = kx::KeyExchange::start(skxg)
            .ok_or_else(|| Error::PeerMisbehavedError("key exchange failed".to_string()))?;
        let secdh = ServerECDHParams::new(skxg.name, kx.pubkey.as_ref());

        let mut msg = Vec::new();
        msg.extend(&randoms.client);
        msg.extend(&randoms.server);
        secdh.encode(&mut msg);

        let signer = signing_key
            .choose_scheme(&sigschemes)
            .ok_or_else(|| Error::General("incompatible signing key".to_string()))?;
        let sigscheme = signer.get_scheme();
        let sig = signer.sign(&msg)?;

        let skx = ServerKeyExchangePayload::ECDHE(ECDHEServerKeyExchange {
            params: secdh,
            dss: DigitallySignedStruct::new(sigscheme, sig),
        });

        let m = Message {
            typ: ContentType::Handshake,
            version: ProtocolVersion::TLSv1_2,
            payload: MessagePayload::Handshake(HandshakeMessagePayload {
                typ: HandshakeType::ServerKeyExchange,
                payload: HandshakePayload::ServerKeyExchange(skx),
            }),
        };

        self.handshake
            .transcript
            .add_message(&m);
        conn.common.send_msg(m, false);
        Ok(kx)
    }

    fn emit_certificate_req(&mut self, conn: &mut ServerConnection) -> Result<bool, Error> {
        let client_auth = conn.config.get_verifier();

        if !client_auth.offer_client_auth() {
            return Ok(false);
        }

        let verify_schemes = client_auth.supported_verify_schemes();

        let names = client_auth
            .client_auth_root_subjects(conn.get_sni())
            .ok_or_else(|| {
                debug!("could not determine root subjects based on SNI");
                conn.common
                    .send_fatal_alert(AlertDescription::AccessDenied);
                Error::General("client rejected by client_auth_root_subjects".into())
            })?;

        let cr = CertificateRequestPayload {
            certtypes: vec![
                ClientCertificateType::RSASign,
                ClientCertificateType::ECDSASign,
            ],
            sigschemes: verify_schemes,
            canames: names,
        };

        let m = Message {
            typ: ContentType::Handshake,
            version: ProtocolVersion::TLSv1_2,
            payload: MessagePayload::Handshake(HandshakeMessagePayload {
                typ: HandshakeType::CertificateRequest,
                payload: HandshakePayload::CertificateRequest(cr),
            }),
        };

        trace!("Sending CertificateRequest {:?}", m);
        self.handshake
            .transcript
            .add_message(&m);
        conn.common.send_msg(m, false);
        Ok(true)
    }

    fn emit_server_hello_done(&mut self, conn: &mut ServerConnection) {
        let m = Message {
            typ: ContentType::Handshake,
            version: ProtocolVersion::TLSv1_2,
            payload: MessagePayload::Handshake(HandshakeMessagePayload {
                typ: HandshakeType::ServerHelloDone,
                payload: HandshakePayload::ServerHelloDone,
            }),
        };

        self.handshake
            .transcript
            .add_message(&m);
        conn.common.send_msg(m, false);
    }

    fn start_resumption(
        mut self,
        conn: &mut ServerConnection,
        client_hello: &ClientHelloPayload,
        suite: &'static SupportedCipherSuite,
        sni: Option<&webpki::DnsName>,
        id: &SessionID,
        resumedata: persist::ServerSessionValue,
        randoms: &ConnectionRandoms,
    ) -> NextStateOrError {
        debug!("Resuming session");

        if resumedata.extended_ms && !self.using_ems {
            return Err(illegal_param(conn, "refusing to resume without ems"));
        }

        self.handshake.session_id = *id;
        self.send_ticket = tls12::emit_server_hello(
            &mut self.handshake,
            conn,
            suite,
            self.using_ems,
            &mut None,
            &mut None,
            client_hello,
            Some(&resumedata),
            randoms,
        )?;

        let secrets = ConnectionSecrets::new_resume(&randoms, suite, &resumedata.master_secret.0);
        conn.config.key_log.log(
            "CLIENT_RANDOM",
            &secrets.randoms.client,
            &secrets.master_secret,
        );
        conn.common
            .start_encryption_tls12(&secrets);
        conn.client_cert_chain = resumedata.client_cert_chain;

        if self.send_ticket {
            tls12::emit_ticket(&secrets, &mut self.handshake, self.using_ems, conn);
        }
        tls12::emit_ccs(conn);
        conn.common
            .record_layer
            .start_encrypting();
        tls12::emit_finished(&secrets, &mut self.handshake, conn);

        assert!(same_dns_name_or_both_none(sni, conn.get_sni()));

        Ok(Box::new(tls12::ExpectCcs {
            secrets,
            handshake: self.handshake,
            using_ems: self.using_ems,
            resuming: true,
            send_ticket: self.send_ticket,
        }))
    }
}

impl State for ExpectClientHello {
    fn handle(mut self: Box<Self>, conn: &mut ServerConnection, m: Message) -> NextStateOrError {
        let client_hello =
            require_handshake_msg!(m, HandshakeType::ClientHello, HandshakePayload::ClientHello)?;
        let tls13_enabled = conn
            .config
            .supports_version(ProtocolVersion::TLSv1_3);
        let tls12_enabled = conn
            .config
            .supports_version(ProtocolVersion::TLSv1_2);
        trace!("we got a clienthello {:?}", client_hello);

        if !client_hello
            .compression_methods
            .contains(&Compression::Null)
        {
            conn.common
                .send_fatal_alert(AlertDescription::IllegalParameter);
            return Err(Error::PeerIncompatibleError(
                "client did not offer Null compression".to_string(),
            ));
        }

        if client_hello.has_duplicate_extension() {
            return Err(decode_error(conn, "client sent duplicate extensions"));
        }

        // No handshake messages should follow this one in this flight.
        check_aligned_handshake(conn)?;

        // Are we doing TLS1.3?
        let maybe_versions_ext = client_hello.get_versions_extension();
        let version = if let Some(versions) = maybe_versions_ext {
            if versions.contains(&ProtocolVersion::TLSv1_3) && tls13_enabled {
                ProtocolVersion::TLSv1_3
            } else if !versions.contains(&ProtocolVersion::TLSv1_2) || !tls12_enabled {
                return Err(bad_version(conn, "TLS1.2 not offered/enabled"));
            } else {
                ProtocolVersion::TLSv1_2
            }
        } else if client_hello.client_version.get_u16() < ProtocolVersion::TLSv1_2.get_u16() {
            return Err(bad_version(conn, "Client does not support TLSv1_2"));
        } else if !tls12_enabled && tls13_enabled {
            return Err(bad_version(
                conn,
                "Server requires TLS1.3, but client omitted versions ext",
            ));
        } else {
            ProtocolVersion::TLSv1_2
        };

        conn.common.negotiated_version = Some(version);

        // --- Common to TLS1.2 and TLS1.3: ciphersuite and certificate selection.

        // Extract and validate the SNI DNS name, if any, before giving it to
        // the cert resolver. In particular, if it is invalid then we should
        // send an Illegal Parameter alert instead of the Internal Error alert
        // (or whatever) that we'd send if this were checked later or in a
        // different way.
        let sni: Option<webpki::DnsName> = match client_hello.get_sni_extension() {
            Some(sni) => {
                if sni.has_duplicate_names_for_type() {
                    return Err(decode_error(
                        conn,
                        "ClientHello SNI contains duplicate name types",
                    ));
                }

                if let Some(hostname) = sni.get_single_hostname() {
                    Some(hostname.into())
                } else {
                    return Err(illegal_param(
                        conn,
                        "ClientHello SNI did not contain a hostname",
                    ));
                }
            }
            None => None,
        };

        if !self.done_retry {
            // save only the first SNI
            save_sni(conn, sni.clone());
        }

        // We communicate to the upper layer what kind of key they should choose
        // via the sigschemes value.  Clients tend to treat this extension
        // orthogonally to offered ciphersuites (even though, in TLS1.2 it is not).
        // So: reduce the offered sigschemes to those compatible with the
        // intersection of ciphersuites.
        let mut common_suites = conn.config.cipher_suites.clone();
        common_suites.retain(|scs| {
            client_hello
                .cipher_suites
                .contains(&scs.suite)
        });

        let mut sigschemes_ext = client_hello
            .get_sigalgs_extension()
            .cloned()
            .unwrap_or_else(SupportedSignatureSchemes::default);
        sigschemes_ext
            .retain(|scheme| suites::compatible_sigscheme_for_suites(*scheme, &common_suites));

        let alpn_protocols = client_hello
            .get_alpn_extension()
            .map(|protos| protos.to_slices());

        // Choose a certificate.
        let certkey = {
            let sni_ref = sni
                .as_ref()
                .map(webpki::DnsName::as_ref);
            trace!("sni {:?}", sni_ref);
            trace!("sig schemes {:?}", sigschemes_ext);
            trace!("alpn protocols {:?}", alpn_protocols);

            let alpn_slices = alpn_protocols.as_deref();
            let client_hello = ClientHello::new(sni_ref, &sigschemes_ext, alpn_slices);

            let certkey = conn
                .config
                .cert_resolver
                .resolve(client_hello);
            certkey.ok_or_else(|| {
                conn.common
                    .send_fatal_alert(AlertDescription::AccessDenied);
                Error::General("no server certificate chain resolved".to_string())
            })?
        };

        // Reduce our supported ciphersuites by the certificate.
        // (no-op for TLS1.3)
        let suitable_suites =
            suites::reduce_given_sigalg(&conn.config.cipher_suites, certkey.key.algorithm());

        // And version
        let suitable_suites = suites::reduce_given_version(&suitable_suites, version);

        let suite = if conn.config.ignore_client_order {
            suites::choose_ciphersuite_preferring_server(
                &client_hello.cipher_suites,
                &suitable_suites,
            )
        } else {
            suites::choose_ciphersuite_preferring_client(
                &client_hello.cipher_suites,
                &suitable_suites,
            )
        }
        .ok_or_else(|| incompatible(conn, "no ciphersuites in common"))?;

        debug!("decided upon suite {:?}", suite);
        conn.common.suite = Some(suite);

        // Start handshake hash.
        let starting_hash = suite.get_hash();
        if !self
            .handshake
            .transcript
            .start_hash(starting_hash)
        {
            conn.common
                .send_fatal_alert(AlertDescription::IllegalParameter);
            return Err(Error::PeerIncompatibleError(
                "hash differed on retry".to_string(),
            ));
        }

        // Save their Random.
        let mut randoms = ConnectionRandoms::for_server()?;
        client_hello
            .random
            .write_slice(&mut randoms.client);

        if conn.common.is_tls13() {
            return tls13::CompleteClientHelloHandling {
                handshake: self.handshake,
                suite,
                randoms,
                done_retry: self.done_retry,
                send_ticket: self.send_ticket,
            }
            .handle_client_hello(suite, conn, &certkey, &m);
        }

        // -- TLS1.2 only from hereon in --
        self.handshake
            .transcript
            .add_message(&m);

        if client_hello.ems_support_offered() {
            self.using_ems = true;
        }

        let groups_ext = client_hello
            .get_namedgroups_extension()
            .ok_or_else(|| incompatible(conn, "client didn't describe groups"))?;
        let ecpoints_ext = client_hello
            .get_ecpoints_extension()
            .ok_or_else(|| incompatible(conn, "client didn't describe ec points"))?;

        trace!("namedgroups {:?}", groups_ext);
        trace!("ecpoints {:?}", ecpoints_ext);

        if !ecpoints_ext.contains(&ECPointFormat::Uncompressed) {
            conn.common
                .send_fatal_alert(AlertDescription::IllegalParameter);
            return Err(Error::PeerIncompatibleError(
                "client didn't support uncompressed ec points".to_string(),
            ));
        }

        // -- If TLS1.3 is enabled, signal the downgrade in the server random
        if tls13_enabled {
            randoms.set_tls12_downgrade_marker();
        }

        // -- Check for resumption --
        // We can do this either by (in order of preference):
        // 1. receiving a ticket that decrypts
        // 2. receiving a sessionid that is in our cache
        //
        // If we receive a ticket, the sessionid won't be in our
        // cache, so don't check.
        //
        // If either works, we end up with a ServerSessionValue
        // which is passed to start_resumption and concludes
        // our handling of the ClientHello.
        //
        let mut ticket_received = false;

        if let Some(ClientExtension::SessionTicketOffer(ref ticket)) =
            client_hello.get_ticket_extension()
        {
            ticket_received = true;
            debug!("Ticket received");

            if let Some(resume) = conn
                .config
                .ticketer
                .decrypt(&ticket.0)
                .and_then(|plain| persist::ServerSessionValue::read_bytes(&plain))
                .and_then(|resumedata| can_resume(suite, &sni, self.using_ems, resumedata))
            {
                return self.start_resumption(
                    conn,
                    client_hello,
                    suite,
                    sni.as_ref(),
                    &client_hello.session_id,
                    resume,
                    &randoms,
                );
            } else {
                debug!("Ticket didn't decrypt");
            }
        }

        // If we're not offered a ticket or a potential session ID,
        // allocate a session ID.
        if self.handshake.session_id.is_empty() && !ticket_received {
            self.handshake.session_id = SessionID::random()?;
        }

        // Perhaps resume?  If we received a ticket, the sessionid
        // does not correspond to a real session.
        if !client_hello.session_id.is_empty() && !ticket_received {
            if let Some(resume) = conn
                .config
                .session_storage
                .get(&client_hello.session_id.get_encoding())
                .and_then(|x| persist::ServerSessionValue::read_bytes(&x))
                .and_then(|resumedata| can_resume(suite, &conn.sni, self.using_ems, resumedata))
            {
                return self.start_resumption(
                    conn,
                    client_hello,
                    suite,
                    sni.as_ref(),
                    &client_hello.session_id,
                    resume,
                    &randoms,
                );
            }
        }

        // Now we have chosen a ciphersuite, we can make kx decisions.
        let sigschemes = suite.resolve_sig_schemes(&sigschemes_ext);

        if sigschemes.is_empty() {
            return Err(incompatible(conn, "no supported sig scheme"));
        }

        let group = conn
            .config
            .kx_groups
            .iter()
            .find(|skxg| groups_ext.contains(&skxg.name))
            .cloned()
            .ok_or_else(|| incompatible(conn, "no supported group"))?;

        let ecpoint = ECPointFormatList::supported()
            .iter()
            .find(|format| ecpoints_ext.contains(format))
            .cloned()
            .ok_or_else(|| incompatible(conn, "no supported point format"))?;

        debug_assert_eq!(ecpoint, ECPointFormat::Uncompressed);

        let (mut ocsp_response, mut sct_list) =
            (certkey.ocsp.as_deref(), certkey.sct_list.as_deref());
        self.send_ticket = tls12::emit_server_hello(
            &mut self.handshake,
            conn,
            suite,
            self.using_ems,
            &mut ocsp_response,
            &mut sct_list,
            client_hello,
            None,
            &randoms,
        )?;
        self.emit_certificate(conn, &certkey.cert);
        if let Some(ocsp_response) = ocsp_response {
            self.emit_cert_status(conn, ocsp_response);
        }
        let kx = self.emit_server_kx(conn, sigschemes, group, &*certkey.key, &randoms)?;
        let doing_client_auth = self.emit_certificate_req(conn)?;
        self.emit_server_hello_done(conn);

        let server_kx = ServerKxDetails::new(kx);
        if doing_client_auth {
            Ok(Box::new(tls12::ExpectCertificate {
                handshake: self.handshake,
                randoms,
                suite,
                using_ems: self.using_ems,
                server_kx,
                send_ticket: self.send_ticket,
            }))
        } else {
            Ok(Box::new(tls12::ExpectClientKx {
                handshake: self.handshake,
                randoms,
                suite,
                using_ems: self.using_ems,
                server_kx,
                client_cert: None,
                send_ticket: self.send_ticket,
            }))
        }
    }
}
