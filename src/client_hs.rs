use msgs::enums::{ContentType, HandshakeType, ExtensionType, SignatureScheme};
use msgs::enums::{Compression, ProtocolVersion, AlertDescription, NamedGroup};
use msgs::message::{Message, MessagePayload};
use msgs::base::{Payload, PayloadU8};
use msgs::handshake::{HandshakePayload, HandshakeMessagePayload, ClientHelloPayload};
use msgs::handshake::{SessionID, Random, ServerHelloPayload};
use msgs::handshake::{ClientExtension, ServerExtension, HasServerExtensions};
use msgs::handshake::{SupportedSignatureSchemes, SupportedMandatedSignatureSchemes};
use msgs::handshake::DecomposedSignatureScheme;
use msgs::handshake::{NamedGroups, SupportedGroups, KeyShareEntry, EncryptedExtensions};
use msgs::handshake::{ECPointFormatList, SupportedPointFormats};
use msgs::handshake::{ProtocolNameList, ConvertProtocolNameList};
use msgs::handshake::{CertificatePayloadTLS13, CertificateEntry};
use msgs::handshake::ServerKeyExchangePayload;
use msgs::handshake::DigitallySignedStruct;
use msgs::handshake::{PresharedKeyIdentity, PresharedKeyOffer, HelloRetryRequest};
use msgs::enums::{ClientCertificateType, PSKKeyExchangeMode, ECPointFormat};
use msgs::codec::Codec;
use msgs::persist;
use msgs::ccs::ChangeCipherSpecPayload;
use client::ClientSessionImpl;
use session::SessionSecrets;
use key_schedule::{KeySchedule, SecretKind};
use cipher;
use suites;
use hash_hs;
use verify;
use rand;
use time;
use error::TLSError;
use handshake::Expectation;

use std::mem;

// draft-ietf-tls-tls13-18
const TLS13_DRAFT: u16 = 0x7f12;

macro_rules! extract_handshake(
  ( $m:expr, $t:path ) => (
    match $m.payload {
      MessagePayload::Handshake(ref hsp) => match hsp.payload {
        $t(ref hm) => Some(hm),
        _ => None
      },
      _ => None
    }
  )
);

// These are effectively operations on the ClientSessionImpl, variant on the
// connection state. They must not have state of their own -- so they're
// functions rather than a trait.
pub type HandleFunction = fn(&mut ClientSessionImpl, m: Message) -> StateResult;
type StateResult = Result<&'static State, TLSError>;

// This describes a single connection state.
pub struct State {
    pub expect: Expectation,
    pub handle: HandleFunction,
}

fn illegal_param(sess: &mut ClientSessionImpl, why: &str) -> TLSError {
    sess.common.send_fatal_alert(AlertDescription::IllegalParameter);
    TLSError::PeerMisbehavedError(why.to_string())
}

fn ticket_timebase() -> u64 {
    time::get_time().sec as u64
}

fn check_aligned_handshake(sess: &mut ClientSessionImpl) -> Result<(), TLSError> {
    if !sess.common.handshake_joiner.is_empty() {
        Err(illegal_param(sess, "keys changed with pending hs fragment"))
    } else {
        Ok(())
    }
}

fn find_session(sess: &mut ClientSessionImpl) -> Option<persist::ClientSessionValue> {
    let key = persist::ClientSessionKey::session_for_dns_name(&sess.handshake_data.dns_name);
    let key_buf = key.get_encoding();

    let mut persist = sess.config.session_persistence.lock().unwrap();
    let maybe_value = persist.get(&key_buf);

    if maybe_value.is_none() {
        info!("No cached session for {:?}", sess.handshake_data.dns_name);
        return None;
    }

    let value = maybe_value.unwrap();
    if let Some(result) = persist::ClientSessionValue::read_bytes(&value) {
        if result.has_expired(ticket_timebase()) {
            None
        } else {
            Some(result)
        }
    } else {
        None
    }
}

fn find_kx_hint(sess: &mut ClientSessionImpl) -> Option<NamedGroup> {
    let key = persist::ClientSessionKey::hint_for_dns_name(&sess.handshake_data.dns_name);
    let key_buf = key.get_encoding();

    let mut persist = sess.config.session_persistence.lock().unwrap();
    let maybe_value = persist.get(&key_buf);
    maybe_value.and_then(|enc| NamedGroup::read_bytes(&enc))
}

fn save_kx_hint(sess: &mut ClientSessionImpl, group: NamedGroup) {
    let key = persist::ClientSessionKey::hint_for_dns_name(&sess.handshake_data.dns_name);

    let mut persist = sess.config.session_persistence.lock().unwrap();
    persist.put(key.get_encoding(), group.get_encoding());
}

/// If we have a ticket, we use the sessionid as a signal that we're
/// doing an abbreviated handshake.  See section 3.4 in RFC5077.
fn randomise_sessionid_for_ticket(csv: &mut persist::ClientSessionValue) {
    if csv.ticket.len() > 0 {
        let mut random_id = [0u8; 32];
        rand::fill_random(&mut random_id);
        csv.session_id = SessionID::new(&random_id);
    }
}

/// This implements the horrifying TLS1.3 hack where PSK binders have a
/// data dependency on the message they are contained within.
pub fn fill_in_psk_binder(sess: &mut ClientSessionImpl, hmp: &mut HandshakeMessagePayload) {
    // We need to know the hash function of the suite we're trying to resume into.
    let resuming = sess.handshake_data.resuming_session.as_ref().unwrap();
    let suite_hash = sess.find_cipher_suite(resuming.cipher_suite).unwrap().get_hash();

    // The binder is calculated over the clienthello, but doesn't include itself or its
    // length, or the length of its container.
    let binder_plaintext = hmp.get_encoding_for_binder_signing();
    let handshake_hash =
        sess.handshake_data.transcript.get_hash_given(suite_hash, &binder_plaintext);

    let mut empty_hash_ctx = hash_hs::HandshakeHash::new();
    empty_hash_ctx.start_hash(suite_hash);
    let empty_hash = empty_hash_ctx.get_current_hash();

    // Run a fake key_schedule to simulate what the server will do if it choses
    // to resume.
    let mut key_schedule = KeySchedule::new(suite_hash);
    key_schedule.input_secret(&resuming.master_secret.0);
    let base_key = key_schedule.derive(SecretKind::ResumptionPSKBinderKey, &empty_hash);
    let real_binder = key_schedule.sign_verify_data(&base_key, &handshake_hash);

    if let HandshakePayload::ClientHello(ref mut ch) = hmp.payload {
        ch.set_psk_binder(real_binder);
    };
}

pub fn emit_client_hello(sess: &mut ClientSessionImpl) -> &'static State {
    emit_client_hello_for_retry(sess, None)
}

fn emit_client_hello_for_retry(sess: &mut ClientSessionImpl,
                               retryreq: Option<&HelloRetryRequest>)
                               -> &'static State {
    // Do we have a SessionID or ticket cached for this host?
    sess.handshake_data.resuming_session = find_session(sess);
    let (session_id, ticket, resume_version) = if sess.handshake_data.resuming_session.is_some() {
        let mut resuming = sess.handshake_data.resuming_session.as_mut().unwrap();
        if resuming.version == ProtocolVersion::TLSv1_2 {
            randomise_sessionid_for_ticket(resuming);
        }
        info!("Resuming session");
        (resuming.session_id, resuming.ticket.0.clone(), resuming.version)
    } else {
        info!("Not resuming any session");
        (SessionID::empty(), Vec::new(), ProtocolVersion::Unknown(0))
    };

    let support_tls12 = sess.config.versions.contains(&ProtocolVersion::TLSv1_2);
    let support_tls13 = sess.config.versions.contains(&ProtocolVersion::TLSv1_3);

    let mut supported_versions = Vec::new();
    if support_tls13 {
        supported_versions.push(ProtocolVersion::Unknown(TLS13_DRAFT));
    }

    if support_tls12 {
        supported_versions.push(ProtocolVersion::TLSv1_2);
    }

    let mut key_shares = vec![];

    if support_tls13 {
        // Choose our groups:
        // - if we've been asked via HelloRetryRequest for a specific
        //   one, do that.
        // - if not, we might have a hint of what the server supports
        // - if not, send just X25519.
        //
        let groups = retryreq.and_then(|req| req.get_requested_key_share_group())
            .or_else(|| find_kx_hint(sess))
            .or_else(|| Some(NamedGroup::X25519))
            .map(|grp| vec![ grp ])
            .unwrap();

        for group in groups {
            // in reply to HelloRetryRequest, we must not alter any existing key
            // shares
            if let Some(already_offered_share) = find_key_share(sess, group) {
                key_shares.push(KeyShareEntry::new(group, &already_offered_share.pubkey));
                sess.handshake_data.offered_key_shares.push(already_offered_share);
                continue;
            }

            if let Some(key_share) = suites::KeyExchange::start_ecdhe(group) {
                key_shares.push(KeyShareEntry::new(group, &key_share.pubkey));
                sess.handshake_data.offered_key_shares.push(key_share);
            }
        }
    }

    let mut exts = Vec::new();
    if !supported_versions.is_empty() {
        exts.push(ClientExtension::SupportedVersions(supported_versions));
    }
    exts.push(ClientExtension::make_sni(&sess.handshake_data.dns_name));
    exts.push(ClientExtension::ECPointFormats(ECPointFormatList::supported()));
    exts.push(ClientExtension::NamedGroups(NamedGroups::supported()));
    exts.push(ClientExtension::SignatureAlgorithms(SupportedSignatureSchemes::supported_verify()));
    exts.push(ClientExtension::ExtendedMasterSecretRequest);

    if support_tls13 {
        exts.push(ClientExtension::KeyShare(key_shares));
    }

    if let Some(cookie) = retryreq.and_then(|req| req.get_cookie()) {
        exts.push(ClientExtension::Cookie(cookie.clone()));
    }

    if support_tls13 && sess.config.enable_tickets {
        // We could support PSK_KE here too. Such connections don't
        // have forward secrecy, and are similar to TLS1.2 resumption.
        let psk_modes = vec![ PSKKeyExchangeMode::PSK_DHE_KE ];
        exts.push(ClientExtension::PresharedKeyModes(psk_modes));
    }

    if !sess.config.alpn_protocols.is_empty() {
        exts.push(ClientExtension::Protocols(ProtocolNameList::from_strings(&sess.config
            .alpn_protocols)));
    }

    let fill_in_binder = if support_tls13 && sess.config.enable_tickets &&
                            resume_version == ProtocolVersion::TLSv1_3 &&
                            !ticket.is_empty() {
        // Finally, and only for TLS1.3 with a ticket resumption, include a binder
        // for our ticket.  This must go last.
        //
        // Include an empty binder. It gets filled in below because it depends on
        // the message it's contained in (!!!).
        let (obfuscated_ticket_age, suite) = {
            let resuming = sess.handshake_data
                .resuming_session
                .as_ref()
                .unwrap();
            (resuming.get_obfuscated_ticket_age(ticket_timebase()), resuming.cipher_suite)
        };

        let binder_len = sess.find_cipher_suite(suite).unwrap().get_hash().output_len;
        let binder = vec![0u8; binder_len];

        let psk_identity = PresharedKeyIdentity::new(ticket, obfuscated_ticket_age);
        let psk_ext = PresharedKeyOffer::new(psk_identity, binder);
        exts.push(ClientExtension::PresharedKey(psk_ext));
        true
    } else if sess.config.enable_tickets {
        // If we have a ticket, include it.  Otherwise, request one.
        if ticket.is_empty() {
            exts.push(ClientExtension::SessionTicketRequest);
        } else {
            exts.push(ClientExtension::SessionTicketOffer(Payload::new(ticket)));
        }
        false
    } else {
        false
    };

    // Note what extensions we sent.
    sess.handshake_data.sent_extensions = exts.iter()
        .map(|ext| ext.get_type())
        .collect();

    let mut chp = HandshakeMessagePayload {
        typ: HandshakeType::ClientHello,
        payload: HandshakePayload::ClientHello(ClientHelloPayload {
            client_version: ProtocolVersion::TLSv1_2,
            random: Random::from_slice(&sess.handshake_data.randoms.client),
            session_id: session_id,
            cipher_suites: sess.get_cipher_suites(),
            compression_methods: vec![Compression::Null],
            extensions: exts,
        }),
    };

    if fill_in_binder {
        fill_in_psk_binder(sess, &mut chp);
    }

    let ch = Message {
        typ: ContentType::Handshake,
        version: ProtocolVersion::TLSv1_0,
        payload: MessagePayload::Handshake(chp),
    };

    debug!("Sending ClientHello {:#?}", ch);

    sess.handshake_data.transcript.add_message(&ch);
    sess.common.send_msg(ch, false);

    if support_tls13 && retryreq.is_none() {
        &EXPECT_TLS13_SERVER_HELLO_OR_RETRY
    } else {
        &EXPECT_SERVER_HELLO
    }
}

fn sent_unsolicited_extensions(sess: &ClientSessionImpl,
                               received_exts: &[ServerExtension],
                               allowed_unsolicited: &[ExtensionType]) -> bool {

    let sent = &sess.handshake_data.sent_extensions;
    for ext in received_exts {
        let ext_type = ext.get_type();
        if !sent.contains(&ext_type) && !allowed_unsolicited.contains(&ext_type) {
            debug!("Unsolicited extension {:?}", ext_type);
            return true;
        }
    }

    false
}

fn has_key_share(sess: &mut ClientSessionImpl,
                 group: NamedGroup) -> bool {
    sess.handshake_data.offered_key_shares
        .iter()
        .any(|share| share.group == group)
}

fn find_key_share(sess: &mut ClientSessionImpl,
                  group: NamedGroup)
                  -> Option<suites::KeyExchange> {
    let shares = &mut sess.handshake_data.offered_key_shares;
    shares.iter()
        .position(|s| s.group == group)
        .map(|idx| shares.remove(idx))
}

fn find_key_share_and_discard_others(sess: &mut ClientSessionImpl,
                                     group: NamedGroup)
                                     -> Result<suites::KeyExchange, TLSError> {
    let ret = find_key_share(sess, group)
        .ok_or_else(|| illegal_param(sess, "wrong group for key share"));
    sess.handshake_data.offered_key_shares.clear();
    ret
}

// Extensions we expect in plaintext in the ServerHello.
static ALLOWED_PLAINTEXT_EXTS: &'static [ExtensionType] = &[
    ExtensionType::KeyShare,
    ExtensionType::PreSharedKey
];

// Only the intersection of things we offer, and those disallowed
// in TLS1.3
static DISALLOWED_TLS13_EXTS: &'static [ExtensionType] = &[
    ExtensionType::ECPointFormats,
    ExtensionType::SessionTicket,
    ExtensionType::RenegotiationInfo,
    ExtensionType::ExtendedMasterSecret,
];

fn validate_server_hello_tls13(sess: &mut ClientSessionImpl,
                               server_hello: &ServerHelloPayload)
                               -> Result<(), TLSError> {
    for ext in &server_hello.extensions {
        if !ALLOWED_PLAINTEXT_EXTS.contains(&ext.get_type()) {
            sess.common.send_fatal_alert(AlertDescription::UnsupportedExtension);
            return Err(TLSError::PeerMisbehavedError("server sent unexpected cleartext ext"
                                                     .to_string()));
        }
    }

    Ok(())
}

fn start_handshake_traffic(sess: &mut ClientSessionImpl,
                           server_hello: &ServerHelloPayload)
                           -> Result<(), TLSError> {
    let suite = sess.common.get_suite();
    let hash = suite.get_hash();
    let mut key_schedule = KeySchedule::new(hash);

    if let Some(selected_psk) = server_hello.get_psk_index() {
        if let Some(ref resuming) = sess.handshake_data.resuming_session {
            let resume_from_suite = sess.find_cipher_suite(resuming.cipher_suite).unwrap();
            if !resume_from_suite.can_resume_to(suite) {
                return Err(TLSError::PeerMisbehavedError("server resuming incompatible suite"
                    .to_string()));
            }

            if selected_psk != 0 {
                return Err(TLSError::PeerMisbehavedError("server selected invalid psk"
                    .to_string()));
            }

            info!("Resuming using PSK");
            key_schedule.input_secret(&resuming.master_secret.0);
        } else {
            return Err(TLSError::PeerMisbehavedError("server selected unoffered psk".to_string()));
        }
    } else {
        info!("Not resuming");
        key_schedule.input_empty();
        sess.handshake_data.resuming_session.take();
    }

    let their_key_share = try! {
        server_hello.get_key_share()
            .ok_or_else(|| {
                sess.common.send_fatal_alert(AlertDescription::MissingExtension);
                TLSError::PeerMisbehavedError("missing key share".to_string())
                })
    };

    let our_key_share = try!(find_key_share_and_discard_others(sess,
                                                               their_key_share.group));
    let shared = try! {
        our_key_share.complete(&their_key_share.payload.0)
            .ok_or_else(|| TLSError::PeerMisbehavedError("key exchange failed"
                                                         .to_string()))
    };

    save_kx_hint(sess, their_key_share.group);
    key_schedule.input_secret(&shared.premaster_secret);

    try!(check_aligned_handshake(sess));

    let handshake_hash = sess.handshake_data.transcript.get_current_hash();
    let write_key = key_schedule.derive(SecretKind::ClientHandshakeTrafficSecret, &handshake_hash);
    let read_key = key_schedule.derive(SecretKind::ServerHandshakeTrafficSecret, &handshake_hash);
    sess.common.set_message_encrypter(cipher::new_tls13_write(suite, &write_key));
    sess.common.set_message_decrypter(cipher::new_tls13_read(suite, &read_key));
    key_schedule.current_client_traffic_secret = write_key;
    key_schedule.current_server_traffic_secret = read_key;
    sess.common.set_key_schedule(key_schedule);

    Ok(())
}

fn process_alpn_protocol(sess: &mut ClientSessionImpl,
                         proto: Option<String>)
                         -> Result<(), TLSError> {
    sess.alpn_protocol = proto;
    if sess.alpn_protocol.is_some() &&
        !sess.config.alpn_protocols.contains(sess.alpn_protocol.as_ref().unwrap()) {
        return Err(illegal_param(sess, "server sent non-offered ALPN protocol"));
    }
    info!("ALPN protocol is {:?}", sess.alpn_protocol);
    Ok(())
}

fn handle_server_hello(sess: &mut ClientSessionImpl, m: Message) -> StateResult {
    let server_hello = extract_handshake!(m, HandshakePayload::ServerHello).unwrap();
    debug!("We got ServerHello {:#?}", server_hello);

    match server_hello.server_version {
        ProtocolVersion::TLSv1_2 if sess.config.versions.contains(&ProtocolVersion::TLSv1_2) => {
            sess.common.negotiated_version = Some(ProtocolVersion::TLSv1_2);
        }
        ProtocolVersion::TLSv1_3 |
        ProtocolVersion::Unknown(TLS13_DRAFT) if sess.config
            .versions
            .contains(&ProtocolVersion::TLSv1_3) => {
            sess.common.negotiated_version = Some(ProtocolVersion::TLSv1_3);
        }
        _ => {
            sess.common.send_fatal_alert(AlertDescription::ProtocolVersion);
            return Err(TLSError::PeerIncompatibleError("server does not support TLS v1.2/v1.3"
                .to_string()));
        }
    };

    if server_hello.compression_method != Compression::Null {
        sess.common.send_fatal_alert(AlertDescription::HandshakeFailure);
        return Err(TLSError::PeerMisbehavedError("server chose non-Null compression".to_string()));
    }

    if server_hello.has_duplicate_extension() {
        sess.common.send_fatal_alert(AlertDescription::DecodeError);
        return Err(TLSError::PeerMisbehavedError("server sent duplicate extensions".to_string()));
    }

    let allowed_unsolicited = [ ExtensionType::RenegotiationInfo ];
    if sent_unsolicited_extensions(sess, &server_hello.extensions, &allowed_unsolicited) {
        sess.common.send_fatal_alert(AlertDescription::UnsupportedExtension);
        return Err(TLSError::PeerMisbehavedError("server sent unsolicited extension".to_string()));
    }

    // Extract ALPN protocol
    if !sess.common.is_tls13() {
        try!(process_alpn_protocol(sess, server_hello.get_alpn_protocol()));
    }

    // If ECPointFormats extension is supplied by the server, it must contain
    // Uncompressed.  But it's allowed to be omitted.
    if let Some(point_fmts) = server_hello.get_ecpoints_extension() {
        if !point_fmts.contains(&ECPointFormat::Uncompressed) {
            sess.common.send_fatal_alert(AlertDescription::HandshakeFailure);
            return Err(TLSError::PeerMisbehavedError("server does not support uncompressed points"
                                                     .to_string()));
        }
    }

    let scs = sess.find_cipher_suite(server_hello.cipher_suite);

    if scs.is_none() {
        sess.common.send_fatal_alert(AlertDescription::HandshakeFailure);
        return Err(TLSError::PeerMisbehavedError("server chose non-offered ciphersuite"
            .to_string()));
    }

    info!("Using ciphersuite {:?}", server_hello.cipher_suite);
    sess.common.set_suite(scs.unwrap());

    let version = sess.common.negotiated_version.unwrap();
    if !sess.common.get_suite().usable_for_version(version) {
        return Err(illegal_param(sess, "server chose unusable ciphersuite for version"));
    }

    // Start our handshake hash, and input the server-hello.
    sess.handshake_data.transcript.start_hash(sess.common.get_suite().get_hash());
    sess.handshake_data.transcript.add_message(&m);

    // For TLS1.3, start message encryption using
    // handshake_traffic_secret.
    if sess.common.is_tls13() {
        try!(validate_server_hello_tls13(sess, &server_hello));
        try!(start_handshake_traffic(sess, &server_hello));
        return Ok(&EXPECT_TLS13_ENCRYPTED_EXTENSIONS);
    }

    // TLS1.2 only from here-on

    // Save ServerRandom and SessionID
    server_hello.random.write_slice(&mut sess.handshake_data.randoms.server);
    sess.handshake_data.session_id = server_hello.session_id;

    // Doing EMS?
    if server_hello.ems_support_acked() {
        sess.handshake_data.using_ems = true;
    }

    // Might the server send a ticket?
    if server_hello.find_extension(ExtensionType::SessionTicket).is_some() {
        info!("Server supports tickets");
        sess.handshake_data.must_issue_new_ticket = true;
    }

    // See if we're successfully resuming.
    let mut abbreviated_handshake = false;
    if let Some(ref resuming) = sess.handshake_data.resuming_session {
        if resuming.session_id == sess.handshake_data.session_id {
            info!("Server agreed to resume");
            abbreviated_handshake = true;

            // Is the server telling lies about the ciphersuite?
            if resuming.cipher_suite != scs.unwrap().suite {
                let error_msg = "abbreviated handshake offered, but with varied cs".to_string();
                return Err(TLSError::PeerMisbehavedError(error_msg));
            }

            // And about EMS support?
            if resuming.extended_ms != sess.handshake_data.using_ems {
                let error_msg = "server varied ems support over resume".to_string();
                return Err(TLSError::PeerMisbehavedError(error_msg));
            }

            sess.secrets = Some(SessionSecrets::new_resume(&sess.handshake_data.randoms,
                                                           scs.unwrap().get_hash(),
                                                           &resuming.master_secret.0));
        }
    }

    if abbreviated_handshake {
        sess.start_encryption_tls12();

        if sess.handshake_data.must_issue_new_ticket {
            Ok(&EXPECT_TLS12_NEW_TICKET_RESUME)
        } else {
            Ok(&EXPECT_TLS12_CCS_RESUME)
        }
    } else {
        Ok(&EXPECT_TLS12_CERTIFICATE)
    }
}

pub static EXPECT_SERVER_HELLO: State = State {
    expect: Expectation {
        content_types: &[ContentType::Handshake],
        handshake_types: &[HandshakeType::ServerHello],
    },
    handle: handle_server_hello,
};

fn handle_hello_retry_request(sess: &mut ClientSessionImpl,
                              m: Message) -> StateResult {
    let hrr = extract_handshake!(m, HandshakePayload::HelloRetryRequest).unwrap();
    sess.handshake_data.transcript.add_message(&m);
    debug!("Got HRR {:?}", hrr);

    let has_cookie = hrr.get_cookie().is_some();
    let req_group = hrr.get_requested_key_share_group();

    // A retry request is illegal if it contains no cookie and asks for
    // retry of a group we already sent.
    if !has_cookie && req_group.map(|g| has_key_share(sess, g)).unwrap_or(false) {
        return Err(illegal_param(sess, "server requested hrr with our group"));
    }

    // Or asks for us to retry on an unsupported group.
    if let Some(group) = req_group {
        if !NamedGroups::supported().contains(&group) {
            return Err(illegal_param(sess, "server requested hrr with bad group"));
        }
    }

    // Or has an empty cookie.
    if has_cookie && hrr.get_cookie().unwrap().len() == 0 {
        return Err(illegal_param(sess, "server requested hrr with empty cookie"));
    }

    // Or has something unrecognised
    if hrr.has_unknown_extension() {
        sess.common.send_fatal_alert(AlertDescription::UnsupportedExtension);
        return Err(TLSError::PeerIncompatibleError("server sent hrr with unhandled extension"
                                                   .to_string()));
    }

    // Or has the same extensions more than once
    if hrr.has_duplicate_extension() {
        return Err(illegal_param(sess, "server send duplicate hrr extensions"));
    }

    // Or asks us to change nothing.
    if !has_cookie && req_group.is_none() {
        return Err(illegal_param(sess, "server requested hrr with no changes"));
    }

    // Or asks us to talk a protocol we didn't offer, or doesn't support HRR at all.
    match hrr.server_version {
        ProtocolVersion::TLSv1_3 | ProtocolVersion::Unknown(TLS13_DRAFT) => {
        }
        _ => {
            return Err(illegal_param(sess, "server requested unsupported version in hrr"));
        }
    }

    Ok(emit_client_hello_for_retry(sess, Some(hrr)))
}

fn handle_server_hello_or_retry(sess: &mut ClientSessionImpl,
                                m: Message)
                                -> StateResult {
    if m.is_handshake_type(HandshakeType::ServerHello) {
        handle_server_hello(sess, m)
    } else {
        handle_hello_retry_request(sess, m)
    }
}

static EXPECT_TLS13_SERVER_HELLO_OR_RETRY: State = State {
    expect: Expectation {
        content_types: &[ContentType::Handshake],
        handshake_types: &[HandshakeType::ServerHello, HandshakeType::HelloRetryRequest],
    },
    handle: handle_server_hello_or_retry,
};

fn validate_encrypted_extensions(sess: &mut ClientSessionImpl,
                                 exts: &EncryptedExtensions) -> Result<(), TLSError> {
    if exts.has_duplicate_extension() {
        sess.common.send_fatal_alert(AlertDescription::DecodeError);
        return Err(TLSError::PeerMisbehavedError("server sent duplicate encrypted extensions"
                                                 .to_string()));
    }

    if sent_unsolicited_extensions(sess, exts, &[]) {
        sess.common.send_fatal_alert(AlertDescription::UnsupportedExtension);
        let msg = "server sent unsolicited encrypted extension".to_string();
        return Err(TLSError::PeerMisbehavedError(msg));
    }

    for ext in exts {
        if ALLOWED_PLAINTEXT_EXTS.contains(&ext.get_type()) ||
           DISALLOWED_TLS13_EXTS.contains(&ext.get_type()) {
            sess.common.send_fatal_alert(AlertDescription::UnsupportedExtension);
            let msg = "server sent inappropriate encrypted extension".to_string();
            return Err(TLSError::PeerMisbehavedError(msg));
        }
    }

    Ok(())
}

fn handle_encrypted_extensions(sess: &mut ClientSessionImpl,
                               m: Message)
                               -> StateResult {
    let exts = extract_handshake!(m, HandshakePayload::EncryptedExtensions).unwrap();
    info!("TLS1.3 encrypted extensions: {:?}", exts);
    sess.handshake_data.transcript.add_message(&m);

    try!(validate_encrypted_extensions(sess, exts));
    try!(process_alpn_protocol(sess, exts.get_alpn_protocol()));

    if sess.handshake_data.resuming_session.is_some() {
        Ok(&EXPECT_TLS13_FINISHED)
    } else {
        Ok(&EXPECT_TLS13_CERTIFICATE_OR_CERTREQ)
    }
}

static EXPECT_TLS13_ENCRYPTED_EXTENSIONS: State = State {
    expect: Expectation {
        content_types: &[ContentType::Handshake],
        handshake_types: &[HandshakeType::EncryptedExtensions],
    },
    handle: handle_encrypted_extensions,
};

fn handle_certificate_tls13(sess: &mut ClientSessionImpl, m: Message) -> StateResult {
    let cert_chain = extract_handshake!(m, HandshakePayload::CertificateTLS13).unwrap();
    sess.handshake_data.transcript.add_message(&m);

    // This is only non-empty for client auth.
    if cert_chain.context.len() > 0 {
        warn!("certificate with non-empty context during handshake");
        sess.common.send_fatal_alert(AlertDescription::DecodeError);
        return Err(TLSError::CorruptMessagePayload(ContentType::Handshake));
    }

    if cert_chain.any_entry_has_duplicate_extension() ||
        cert_chain.any_entry_has_unknown_extension() {
        warn!("certificate chain contains unsolicited/unknown extension");
        sess.common.send_fatal_alert(AlertDescription::UnsupportedExtension);
        return Err(TLSError::PeerMisbehavedError("bad cert chain extensions".to_string()));
    }

    sess.handshake_data.server_cert_chain = cert_chain.convert();
    Ok(&EXPECT_TLS13_CERTIFICATE_VERIFY)
}

static EXPECT_TLS13_CERTIFICATE: State = State {
    expect: Expectation {
        content_types: &[ContentType::Handshake],
        handshake_types: &[HandshakeType::Certificate],
    },
    handle: handle_certificate_tls13,
};

fn handle_certificate_tls12(sess: &mut ClientSessionImpl, m: Message) -> StateResult {
    let cert_chain = extract_handshake!(m, HandshakePayload::Certificate).unwrap();
    sess.handshake_data.transcript.add_message(&m);

    sess.handshake_data.server_cert_chain = cert_chain.clone();
    Ok(&EXPECT_TLS12_SERVER_KX)
}

static EXPECT_TLS12_CERTIFICATE: State = State {
    expect: Expectation {
        content_types: &[ContentType::Handshake],
        handshake_types: &[HandshakeType::Certificate],
    },
    handle: handle_certificate_tls12,
};

fn handle_certificate_or_cert_req(sess: &mut ClientSessionImpl,
                                  m: Message) -> StateResult {
    if m.is_handshake_type(HandshakeType::Certificate) {
        handle_certificate_tls13(sess, m)
    } else {
        handle_certificate_req_tls13(sess, m)
    }
}

static EXPECT_TLS13_CERTIFICATE_OR_CERTREQ: State = State {
    expect: Expectation {
        content_types: &[ContentType::Handshake],
        handshake_types: &[HandshakeType::Certificate, HandshakeType::CertificateRequest],
    },
    handle: handle_certificate_or_cert_req,
};

fn handle_server_kx(sess: &mut ClientSessionImpl, m: Message) -> StateResult {
    let opaque_kx = extract_handshake!(m, HandshakePayload::ServerKeyExchange).unwrap();
    let maybe_decoded_kx = opaque_kx.unwrap_given_kxa(&sess.common.get_suite().kx);
    sess.handshake_data.transcript.add_message(&m);

    if maybe_decoded_kx.is_none() {
        sess.common.send_fatal_alert(AlertDescription::DecodeError);
        return Err(TLSError::CorruptMessagePayload(ContentType::Handshake));
    }

    let decoded_kx = maybe_decoded_kx.unwrap();

    // Save the signature and signed parameters for later verification.
    sess.handshake_data.server_kx_sig = decoded_kx.get_sig();
    decoded_kx.encode_params(&mut sess.handshake_data.server_kx_params);

    if let ServerKeyExchangePayload::ECDHE(ecdhe) = decoded_kx {
        info!("ECDHE curve is {:?}", ecdhe.params.curve_params);
    }

    Ok(&EXPECT_TLS12_SERVER_DONE_OR_CERTREQ)
}

static EXPECT_TLS12_SERVER_KX: State = State {
    expect: Expectation {
        content_types: &[ContentType::Handshake],
        handshake_types: &[HandshakeType::ServerKeyExchange],
    },
    handle: handle_server_kx,
};

// --- TLS1.3 CertificateVerify ---
fn handle_certificate_verify(sess: &mut ClientSessionImpl,
                             m: Message)
                             -> StateResult {
    let cert_verify = extract_handshake!(m, HandshakePayload::CertificateVerify).unwrap();

    info!("Server cert is {:?}", sess.handshake_data.server_cert_chain);

    // 1. Verify the certificate chain. (unless configured not to)
    // 2. Verify their signature on the handshake.
    try!(verify::verify_server_cert(&sess.config.root_store,
                                  &sess.handshake_data.server_cert_chain,
                                  &sess.handshake_data.dns_name,
                                  !sess.config.do_host_name_verification()));

    let handshake_hash = sess.handshake_data.transcript.get_current_hash();
    try!(verify::verify_tls13(&sess.handshake_data.server_cert_chain[0],
                            &cert_verify,
                            &handshake_hash,
                            b"TLS 1.3, server CertificateVerify\x00"));

    sess.handshake_data.transcript.add_message(&m);

    Ok(&EXPECT_TLS13_FINISHED)
}

static EXPECT_TLS13_CERTIFICATE_VERIFY: State = State {
    expect: Expectation {
        content_types: &[ContentType::Handshake],
        handshake_types: &[HandshakeType::CertificateVerify],
    },
    handle: handle_certificate_verify,
};

fn emit_certificate(sess: &mut ClientSessionImpl) {
    let chosen_cert = sess.handshake_data.client_auth_cert.take();

    let cert = Message {
        typ: ContentType::Handshake,
        version: ProtocolVersion::TLSv1_2,
        payload: MessagePayload::Handshake(HandshakeMessagePayload {
            typ: HandshakeType::Certificate,
            payload: HandshakePayload::Certificate(chosen_cert.unwrap_or_else(Vec::new)),
        }),
    };

    sess.handshake_data.transcript.add_message(&cert);
    sess.common.send_msg(cert, false);
}

fn emit_clientkx(sess: &mut ClientSessionImpl, kxd: &suites::KeyExchangeResult) {
    let mut buf = Vec::new();
    let ecpoint = PayloadU8::new(kxd.pubkey.clone());
    ecpoint.encode(&mut buf);
    let pubkey = Payload::new(buf);

    let ckx = Message {
        typ: ContentType::Handshake,
        version: ProtocolVersion::TLSv1_2,
        payload: MessagePayload::Handshake(HandshakeMessagePayload {
            typ: HandshakeType::ClientKeyExchange,
            payload: HandshakePayload::ClientKeyExchange(pubkey),
        }),
    };

    sess.handshake_data.transcript.add_message(&ckx);
    sess.common.send_msg(ckx, false);
}

fn emit_certverify(sess: &mut ClientSessionImpl) {
    if sess.handshake_data.client_auth_key.is_none() {
        debug!("Not sending CertificateVerify, no key");
        sess.handshake_data.transcript.abandon_client_auth();
        return;
    }

    let message = sess.handshake_data.transcript.take_handshake_buf();
    let key = sess.handshake_data.client_auth_key.take().unwrap();
    let sigscheme = sess.handshake_data
        .client_auth_sigscheme
        .unwrap();
    let sig = key.sign(sigscheme, &message)
        .expect("client auth signing failed unexpectedly");
    let body = DigitallySignedStruct::new(sigscheme, sig);

    let m = Message {
        typ: ContentType::Handshake,
        version: ProtocolVersion::TLSv1_2,
        payload: MessagePayload::Handshake(HandshakeMessagePayload {
            typ: HandshakeType::CertificateVerify,
            payload: HandshakePayload::CertificateVerify(body),
        }),
    };

    sess.handshake_data.transcript.add_message(&m);
    sess.common.send_msg(m, false);
}

fn emit_ccs(sess: &mut ClientSessionImpl) {
    let ccs = Message {
        typ: ContentType::ChangeCipherSpec,
        version: ProtocolVersion::TLSv1_2,
        payload: MessagePayload::ChangeCipherSpec(ChangeCipherSpecPayload {}),
    };

    sess.common.send_msg(ccs, false);
    sess.common.we_now_encrypting();
}

fn emit_finished(sess: &mut ClientSessionImpl) {
    let vh = sess.handshake_data.transcript.get_current_hash();
    let verify_data = sess.secrets.as_ref().unwrap().client_verify_data(&vh);
    let verify_data_payload = Payload::new(verify_data);

    let f = Message {
        typ: ContentType::Handshake,
        version: ProtocolVersion::TLSv1_2,
        payload: MessagePayload::Handshake(HandshakeMessagePayload {
            typ: HandshakeType::Finished,
            payload: HandshakePayload::Finished(verify_data_payload),
        }),
    };

    sess.handshake_data.transcript.add_message(&f);
    sess.common.send_msg(f, true);
}

// --- Either a CertificateRequest, or a ServerHelloDone. ---
// Existence of the CertificateRequest tells us the server is asking for
// client auth.  Otherwise we go straight to ServerHelloDone.
fn handle_certificate_req(sess: &mut ClientSessionImpl, m: Message) -> StateResult {
    let certreq = extract_handshake!(m, HandshakePayload::CertificateRequest).unwrap();
    sess.handshake_data.transcript.add_message(&m);
    sess.handshake_data.doing_client_auth = true;
    info!("Got CertificateRequest {:?}", certreq);

    // The RFC jovially describes the design here as 'somewhat complicated'
    // and 'somewhat underspecified'.  So thanks for that.

    // We only support RSA signing at the moment.  If you don't support that,
    // we're not doing client auth.
    if !certreq.certtypes.contains(&ClientCertificateType::RSASign) {
        warn!("Server asked for client auth but without RSASign");
        return Ok(&EXPECT_TLS12_SERVER_HELLO_DONE);
    }

    let canames = certreq.canames
        .iter()
        .map(|p| p.0.as_slice())
        .collect::<Vec<&[u8]>>();
    let maybe_certkey =
        sess.config.client_auth_cert_resolver.resolve(&canames, &certreq.sigschemes);

    let scs = sess.common.get_suite();
    let maybe_sigscheme = scs.resolve_sig_scheme(&certreq.sigschemes);

    if maybe_certkey.is_some() && maybe_sigscheme.is_some() {
        let (cert, key) = maybe_certkey.unwrap();
        info!("Attempting client auth, will use {:?}", maybe_sigscheme.as_ref().unwrap());
        sess.handshake_data.client_auth_cert = Some(cert);
        sess.handshake_data.client_auth_key = Some(key);
        sess.handshake_data.client_auth_sigscheme = maybe_sigscheme;
    } else {
        info!("Client auth requested but no cert/sigscheme available");
    }

    Ok(&EXPECT_TLS12_SERVER_HELLO_DONE)
}

// TLS1.3 version of the above.  We then move to expecting the server Certificate.
// Unfortunately the CertificateRequest type changed in an annoying way in TLS1.3.
fn handle_certificate_req_tls13(sess: &mut ClientSessionImpl,
                                m: Message) -> StateResult {
    let certreq = &extract_handshake!(m, HandshakePayload::CertificateRequestTLS13).unwrap();
    sess.handshake_data.transcript.add_message(&m);
    sess.handshake_data.doing_client_auth = true;
    info!("Got CertificateRequest {:?}", certreq);

    // Fortunately the problems here in TLS1.2 and prior are corrected in
    // TLS1.3.

    // Must be empty during handshake.
    if certreq.context.len() > 0 {
        warn!("Server sent non-empty certreq context");
        sess.common.send_fatal_alert(AlertDescription::DecodeError);
        return Err(TLSError::CorruptMessagePayload(ContentType::Handshake));
    }

    let tls13_sign_schemes = SupportedSignatureSchemes::supported_sign_tls13();
    let compat_sigschemes = certreq.sigschemes
        .iter()
        .cloned()
        .filter(|scheme| tls13_sign_schemes.contains(scheme))
        .collect::<Vec<SignatureScheme>>();

    if compat_sigschemes.is_empty() {
        sess.common.send_fatal_alert(AlertDescription::DecodeError);
        return Err(TLSError::PeerIncompatibleError("server sent bad certreq schemes".to_string()));
    }

    let canames = certreq.canames
        .iter()
        .map(|p| p.0.as_slice())
        .collect::<Vec<&[u8]>>();
    let maybe_certkey =
        sess.config.client_auth_cert_resolver.resolve(&canames, &compat_sigschemes);

    if maybe_certkey.is_some() {
        let (cert, key) = maybe_certkey.unwrap();
        let maybe_sigscheme = key.choose_scheme(&compat_sigschemes);
        info!("Attempting client auth, will use sigscheme {:?}", maybe_sigscheme);
        sess.handshake_data.client_auth_cert = Some(cert);
        sess.handshake_data.client_auth_key = Some(key);
        sess.handshake_data.client_auth_sigscheme = maybe_sigscheme;
        sess.handshake_data.client_auth_context = Some(certreq.context.0.clone());
    } else {
        info!("Client auth requested but no cert selected");
    }

    Ok(&EXPECT_TLS13_CERTIFICATE)
}

fn handle_server_done_or_certreq(sess: &mut ClientSessionImpl, m: Message) -> StateResult {
    if extract_handshake!(m, HandshakePayload::CertificateRequest).is_some() {
        handle_certificate_req(sess, m)
    } else {
        sess.handshake_data.transcript.abandon_client_auth();
        handle_server_hello_done(sess, m)
    }
}

static EXPECT_TLS12_SERVER_DONE_OR_CERTREQ: State = State {
    expect: Expectation {
        content_types: &[ContentType::Handshake],
        handshake_types: &[HandshakeType::CertificateRequest, HandshakeType::ServerHelloDone],
    },
    handle: handle_server_done_or_certreq,
};

fn handle_server_hello_done(sess: &mut ClientSessionImpl,
                            m: Message) -> StateResult {
    sess.handshake_data.transcript.add_message(&m);

    info!("Server cert is {:?}", sess.handshake_data.server_cert_chain);
    info!("Server DNS name is {:?}", sess.handshake_data.dns_name);

    // 1. Verify the cert chain. (unless configured not to)
    // 2. Verify that the top certificate signed their kx.
    // 3. If doing client auth, send our Certificate.
    // 4. Complete the key exchange:
    //    a) generate our kx pair
    //    b) emit a ClientKeyExchange containing it
    //    c) if doing client auth, emit a CertificateVerify
    //    d) emit a CCS
    //    e) derive the shared keys, and start encryption
    // 5. emit a Finished, our first encrypted message under the new keys.

    // 1.
    try!(verify::verify_server_cert(&sess.config.root_store,
                                  &sess.handshake_data.server_cert_chain,
                                  &sess.handshake_data.dns_name,
                                  !sess.config.do_host_name_verification()));

    // 2.
    // Build up the contents of the signed message.
    // It's ClientHello.random || ServerHello.random || ServerKeyExchange.params
    {
        let mut message = Vec::new();
        message.extend_from_slice(&sess.handshake_data.randoms.client);
        message.extend_from_slice(&sess.handshake_data.randoms.server);
        message.extend_from_slice(&sess.handshake_data.server_kx_params);

        // Check the signature is compatible with the ciphersuite.
        let sig = sess.handshake_data.server_kx_sig.as_ref().unwrap();
        let scs = sess.common.get_suite();
        if scs.sign != sig.scheme.sign() {
            let error_message =
                format!("peer signed kx with wrong algorithm (got {:?} expect {:?})",
                                  sig.scheme.sign(), scs.sign);
            return Err(TLSError::PeerMisbehavedError(error_message));
        }

        try!(verify::verify_signed_struct(&message,
                                      &sess.handshake_data.server_cert_chain[0],
                                      sig));
    }

    // 3.
    if sess.handshake_data.doing_client_auth {
        emit_certificate(sess);
    }

    // 4a.
    let kxd = try! {
        sess.common.get_suite()
        .do_client_kx(&sess.handshake_data.server_kx_params)
        .ok_or_else(|| TLSError::PeerMisbehavedError("key exchange failed".to_string()))
    };

    // 4b.
    emit_clientkx(sess, &kxd);
    // nb. EMS handshake hash only runs up to ClientKeyExchange.
    let handshake_hash = sess.handshake_data.transcript.get_current_hash();

    // 4c.
    if sess.handshake_data.doing_client_auth {
        emit_certverify(sess);
    }

    // 4d.
    emit_ccs(sess);

    // 4e. Now commit secrets.
    let hashalg = sess.common.get_suite().get_hash();
    if sess.handshake_data.using_ems {
        sess.secrets = Some(SessionSecrets::new_ems(&sess.handshake_data.randoms,
                                                    &handshake_hash,
                                                    hashalg,
                                                    &kxd.premaster_secret));
    } else {
        sess.secrets = Some(SessionSecrets::new(&sess.handshake_data.randoms,
                                                hashalg,
                                                &kxd.premaster_secret));
    }
    sess.start_encryption_tls12();

    // 5.
    emit_finished(sess);

    if sess.handshake_data.must_issue_new_ticket {
        Ok(&EXPECT_TLS12_NEW_TICKET)
    } else {
        Ok(&EXPECT_TLS12_CCS)
    }
}

static EXPECT_TLS12_SERVER_HELLO_DONE: State = State {
    expect: Expectation {
        content_types: &[ContentType::Handshake],
        handshake_types: &[HandshakeType::ServerHelloDone],
    },
    handle: handle_server_hello_done,
};

// -- Waiting for their CCS --
fn handle_ccs(sess: &mut ClientSessionImpl, _m: Message) -> StateResult {
    // CCS should not be received interleaved with fragmented handshake-level
    // message.
    if !sess.common.handshake_joiner.is_empty() {
        warn!("CCS received interleaved with fragmented handshake");
        return Err(TLSError::InappropriateMessage {
            expect_types: vec![ ContentType::Handshake ],
            got_type: ContentType::ChangeCipherSpec,
        });
    }

    // nb. msgs layer validates trivial contents of CCS
    sess.common.peer_now_encrypting();
    Ok(&EXPECT_TLS12_FINISHED)
}

static EXPECT_TLS12_CCS: State = State {
    expect: Expectation {
        content_types: &[ContentType::ChangeCipherSpec],
        handshake_types: &[],
    },
    handle: handle_ccs,
};

fn handle_new_ticket(sess: &mut ClientSessionImpl, m: Message) -> StateResult {
    let ticket = extract_handshake!(m, HandshakePayload::NewSessionTicket).unwrap();
    sess.handshake_data.transcript.add_message(&m);
    sess.handshake_data.new_ticket = ticket.ticket.0.clone();
    sess.handshake_data.new_ticket_lifetime = ticket.lifetime_hint;
    Ok(&EXPECT_TLS12_CCS)
}

static EXPECT_TLS12_NEW_TICKET: State = State {
    expect: Expectation {
        content_types: &[ContentType::Handshake],
        handshake_types: &[HandshakeType::NewSessionTicket],
    },
    handle: handle_new_ticket,
};

fn handle_ccs_resume(sess: &mut ClientSessionImpl, m: Message) -> StateResult {
    handle_ccs(sess, m).and(Ok(&EXPECT_TLS12_FINISHED_RESUME))
}

static EXPECT_TLS12_CCS_RESUME: State = State {
    expect: Expectation {
        content_types: &[ContentType::ChangeCipherSpec],
        handshake_types: &[],
    },
    handle: handle_ccs_resume,
};

fn handle_new_ticket_resume(sess: &mut ClientSessionImpl,
                            m: Message) -> StateResult {
    handle_new_ticket(sess, m).and(Ok(&EXPECT_TLS12_CCS_RESUME))
}

static EXPECT_TLS12_NEW_TICKET_RESUME: State = State {
    expect: Expectation {
        content_types: &[ContentType::Handshake],
        handshake_types: &[HandshakeType::NewSessionTicket],
    },
    handle: handle_new_ticket_resume,
};

// -- Waiting for their finished --
fn save_session(sess: &mut ClientSessionImpl) {
    // Save a ticket.  If we got a new ticket, save that.  Otherwise, save the
    // original ticket again.
    let mut ticket = mem::replace(&mut sess.handshake_data.new_ticket, Vec::new());
    if ticket.is_empty() && sess.handshake_data.resuming_session.is_some() {
        ticket = sess.handshake_data.resuming_session.as_mut().unwrap().take_ticket();
    }

    if sess.handshake_data.session_id.is_empty() && ticket.is_empty() {
        info!("Session not saved: server didn't allocate id or ticket");
        return;
    }

    let key = persist::ClientSessionKey::session_for_dns_name(&sess.handshake_data.dns_name);

    let scs = sess.common.get_suite();
    let master_secret = sess.secrets.as_ref().unwrap().get_master_secret();
    let version = sess.get_protocol_version().unwrap();
    let mut value = persist::ClientSessionValue::new(version,
                                                     scs.suite,
                                                     &sess.handshake_data.session_id,
                                                     ticket,
                                                     master_secret);
    value.set_times(ticket_timebase(),
                    sess.handshake_data.new_ticket_lifetime,
                    0);
    if sess.handshake_data.using_ems {
        value.set_extended_ms_used();
    }

    let mut persist = sess.config.session_persistence.lock().unwrap();
    let worked = persist.put(key.get_encoding(), value.get_encoding());

    if worked {
        info!("Session saved");
    } else {
        info!("Session not saved");
    }
}

fn emit_certificate_tls13(sess: &mut ClientSessionImpl) {
    let context = sess.handshake_data
        .client_auth_context
        .take()
        .unwrap_or_else(Vec::new);

    let mut cert_payload = CertificatePayloadTLS13 {
        context: PayloadU8::new(context),
        list: Vec::new(),
    };

    if let Some(cert_chain) = sess.handshake_data.client_auth_cert.take() {
        for cert in cert_chain {
            cert_payload.list.push(CertificateEntry::new(cert));
        }
    }

    let m = Message {
        typ: ContentType::Handshake,
        version: ProtocolVersion::TLSv1_3,
        payload: MessagePayload::Handshake(HandshakeMessagePayload {
            typ: HandshakeType::Certificate,
            payload: HandshakePayload::CertificateTLS13(cert_payload),
        }),
    };
    sess.handshake_data.transcript.add_message(&m);
    sess.common.send_msg(m, true);
}

fn emit_certverify_tls13(sess: &mut ClientSessionImpl) -> Result<(), TLSError> {
    if sess.handshake_data.client_auth_sigscheme.is_none() ||
       sess.handshake_data.client_auth_key.is_none() {
        info!("Skipping certverify message (no client scheme/key)");
        return Ok(());
    }

    let mut message = Vec::new();
    message.resize(64, 0x20u8);
    message.extend_from_slice(b"TLS 1.3, client CertificateVerify\x00");
    message.extend_from_slice(&sess.handshake_data.transcript.get_current_hash());

    let scheme = sess.handshake_data.client_auth_sigscheme.take().unwrap();
    let key = sess.handshake_data.client_auth_key.take().unwrap();
    let sig = try! {
        key.sign(scheme, &message)
            .map_err(|_| TLSError::General("cannot sign".to_string()))
    };
    let verf = DigitallySignedStruct::new(scheme, sig);

    let m = Message {
        typ: ContentType::Handshake,
        version: ProtocolVersion::TLSv1_3,
        payload: MessagePayload::Handshake(HandshakeMessagePayload {
            typ: HandshakeType::CertificateVerify,
            payload: HandshakePayload::CertificateVerify(verf),
        }),
    };

    sess.handshake_data.transcript.add_message(&m);
    sess.common.send_msg(m, true);
    Ok(())
}

fn emit_finished_tls13(sess: &mut ClientSessionImpl) {
    let handshake_hash = sess.handshake_data.transcript.get_current_hash();
    let verify_data = sess.common
        .get_key_schedule()
        .sign_finish(SecretKind::ClientHandshakeTrafficSecret, &handshake_hash);
    let verify_data_payload = Payload::new(verify_data);

    let m = Message {
        typ: ContentType::Handshake,
        version: ProtocolVersion::TLSv1_3,
        payload: MessagePayload::Handshake(HandshakeMessagePayload {
            typ: HandshakeType::Finished,
            payload: HandshakePayload::Finished(verify_data_payload),
        }),
    };

    sess.handshake_data.transcript.add_message(&m);
    sess.common.send_msg(m, true);
}

fn handle_finished_tls13(sess: &mut ClientSessionImpl, m: Message) -> StateResult {
    let finished = extract_handshake!(m, HandshakePayload::Finished).unwrap();

    let handshake_hash = sess.handshake_data.transcript.get_current_hash();
    let expect_verify_data = sess.common
        .get_key_schedule()
        .sign_finish(SecretKind::ServerHandshakeTrafficSecret, &handshake_hash);

    use ring;
    try! {
        ring::constant_time::verify_slices_are_equal(&expect_verify_data, &finished.0)
            .map_err(|_| {
                     sess.common.send_fatal_alert(AlertDescription::DecryptError);
                     TLSError::DecryptError
                     })
    };

    sess.handshake_data.transcript.add_message(&m);

    /* Transition to application data */
    sess.common.get_mut_key_schedule().input_empty();

    /* Traffic from server is now encrypted with application data keys. */
    let handshake_hash = sess.handshake_data.transcript.get_current_hash();
    let read_key = sess.common
        .get_key_schedule()
        .derive(SecretKind::ServerApplicationTrafficSecret, &handshake_hash);
    let suite = sess.common.get_suite();
    sess.common.set_message_decrypter(cipher::new_tls13_read(suite, &read_key));
    sess.common
        .get_mut_key_schedule()
        .current_server_traffic_secret = read_key;

    /* Send our authentication/finished messages.  These are still encrypted
     * with our handshake keys. */
    if sess.handshake_data.doing_client_auth {
        emit_certificate_tls13(sess);
        try!(emit_certverify_tls13(sess));
    }

    emit_finished_tls13(sess);

    /* Now move to our application traffic keys. */
    try!(check_aligned_handshake(sess));
    let write_key = sess.common
        .get_key_schedule()
        .derive(SecretKind::ClientApplicationTrafficSecret, &handshake_hash);
    sess.common.set_message_encrypter(cipher::new_tls13_write(suite, &write_key));
    sess.common
        .get_mut_key_schedule()
        .current_client_traffic_secret = write_key;

    sess.common.we_now_encrypting();
    sess.common.start_traffic();
    Ok(&EXPECT_TLS13_TRAFFIC)
}

static EXPECT_TLS13_FINISHED: State = State {
    expect: Expectation {
        content_types: &[ContentType::Handshake],
        handshake_types: &[HandshakeType::Finished],
    },
    handle: handle_finished_tls13,
};

fn _handle_finished_tls12(sess: &mut ClientSessionImpl, m: Message) -> StateResult {
    let finished = extract_handshake!(m, HandshakePayload::Finished).unwrap();

    // Work out what verify_data we expect.
    let vh = sess.handshake_data.transcript.get_current_hash();
    let expect_verify_data = sess.secrets.as_ref().unwrap().server_verify_data(&vh);

    // Constant-time verification of this is relatively unimportant: they only
    // get one chance.  But it can't hurt.
    use ring;
    try! {
        ring::constant_time::verify_slices_are_equal(&expect_verify_data, &finished.0)
            .map_err(|_| {
                     sess.common.send_fatal_alert(AlertDescription::DecryptError);
                     TLSError::DecryptError
                     })
    };

    // Hash this message too.
    sess.handshake_data.transcript.add_message(&m);

    save_session(sess);

    // caller must we_now_encrypting/start_traffic, because
    // resuming case cannot start traffic yet
    Ok(&EXPECT_TLS12_TRAFFIC)
}

fn handle_finished_tls12(sess: &mut ClientSessionImpl, m: Message) -> StateResult {
    let next_state = try!(_handle_finished_tls12(sess, m));
    sess.common.we_now_encrypting();
    sess.common.start_traffic();
    Ok(next_state)
}

static EXPECT_TLS12_FINISHED: State = State {
    expect: Expectation {
        content_types: &[ContentType::Handshake],
        handshake_types: &[HandshakeType::Finished],
    },
    handle: handle_finished_tls12,
};

fn handle_finished_resume(sess: &mut ClientSessionImpl, m: Message) -> StateResult {
    try!(_handle_finished_tls12(sess, m));

    emit_ccs(sess);
    emit_finished(sess);

    sess.common.we_now_encrypting();
    sess.common.start_traffic();
    Ok(&EXPECT_TLS12_TRAFFIC)
}

static EXPECT_TLS12_FINISHED_RESUME: State = State {
    expect: Expectation {
        content_types: &[ContentType::Handshake],
        handshake_types: &[],
    },
    handle: handle_finished_resume,
};

// -- Traffic transit state --
fn handle_traffic(sess: &mut ClientSessionImpl, mut m: Message) -> StateResult {
    sess.common.take_received_plaintext(m.take_opaque_payload().unwrap());
    Ok(&EXPECT_TLS12_TRAFFIC)
}

static EXPECT_TLS12_TRAFFIC: State = State {
    expect: Expectation {
        content_types: &[ContentType::ApplicationData],
        handshake_types: &[],
    },
    handle: handle_traffic,
};

// -- Traffic transit state (TLS1.3) --
// In this state we can be sent tickets, keyupdates,
// and application data.
fn handle_traffic_tls13(sess: &mut ClientSessionImpl, m: Message) -> StateResult {
    if m.is_content_type(ContentType::ApplicationData) {
        try!(handle_traffic(sess, m));
    } else if m.is_handshake_type(HandshakeType::NewSessionTicket) {
        try!(handle_new_ticket_tls13(sess, m));
    } else if m.is_handshake_type(HandshakeType::KeyUpdate) {
        try!(handle_key_update(sess, m));
    }

    Ok(&EXPECT_TLS13_TRAFFIC)
}

fn handle_new_ticket_tls13(sess: &mut ClientSessionImpl, m: Message) -> Result<(), TLSError> {
    let nst = extract_handshake!(m, HandshakePayload::NewSessionTicketTLS13).unwrap();
    let handshake_hash = sess.handshake_data.transcript.get_current_hash();
    let secret =
        sess.common.get_key_schedule().derive(SecretKind::ResumptionMasterSecret, &handshake_hash);
    let mut value = persist::ClientSessionValue::new(ProtocolVersion::TLSv1_3,
                                                     sess.common.get_suite().suite,
                                                     &SessionID::empty(),
                                                     nst.ticket.0.clone(),
                                                     secret);
    value.set_times(ticket_timebase(),
                    nst.lifetime,
                    nst.age_add);

    let key = persist::ClientSessionKey::session_for_dns_name(&sess.handshake_data.dns_name);

    let mut persist = sess.config.session_persistence.lock().unwrap();
    let worked = persist.put(key.get_encoding(), value.get_encoding());

    if worked {
        info!("Ticket saved");
    } else {
        info!("Ticket not saved");
    }
    Ok(())
}

fn handle_key_update(sess: &mut ClientSessionImpl, m: Message) -> Result<(), TLSError> {
    let kur = extract_handshake!(m, HandshakePayload::KeyUpdate).unwrap();
    sess.common.process_key_update(kur, SecretKind::ServerApplicationTrafficSecret)
}

static EXPECT_TLS13_TRAFFIC: State = State {
    expect: Expectation {
        content_types: &[ContentType::ApplicationData, ContentType::Handshake],
        handshake_types: &[HandshakeType::NewSessionTicket, HandshakeType::KeyUpdate],
    },
    handle: handle_traffic_tls13,
};
